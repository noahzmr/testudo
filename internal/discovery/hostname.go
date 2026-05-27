package discovery

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Hostname resolution for the device inventory. The active collectors
// (mDNS/LLDP/SNMP) already contribute authoritative names for the hosts that
// speak those protocols; this fills in the long tail of plain hosts that don't,
// using three fallbacks in priority order:
//
//  1. DHCP leases  - when Testudo runs on the gateway, the lease file already
//     maps IP => client hostname. Free, instant, no probe traffic.
//  2. Reverse DNS  - PTR lookup, the most broadly useful method on networks
//     with a populated reverse zone (DHCP-registered names, AD, etc.).
//  3. NetBIOS      - NBSTAT node-status query for Windows/SMB hosts that
//     commonly have no PTR record.
//
// Resolution mirrors the bounded-concurrency + negative-cache pattern used by
// the flow DNS cache (internal/flows/correlate.go): a miss is remembered for
// hostnameNegativeTTL so we don't re-hammer silent hosts every pass.

const (
	hostnameConcurrency = 32
	hostnameNegativeTTL = 5 * time.Minute
	leaseRefreshTTL     = 30 * time.Second
)

// dhcpLeaseFiles are the well-known lease databases written by DHCP servers.
// All are read best-effort; absent/unreadable files are skipped silently.
var dhcpLeaseFiles = []string{
	"/var/lib/misc/dnsmasq.leases",
	"/var/lib/dnsmasq/dnsmasq.leases",
	"/var/lib/dhcp/dhcpd.leases",
	"/var/lib/dhcpd/dhcpd.leases",
}

// hostnameMethods toggles which fallbacks run for a given pass. Driven by the
// scanner's intensity setting.
type hostnameMethods struct {
	DHCP    bool
	RDNS    bool
	NetBIOS bool
}

// hostnameResolver resolves names for inventory entries that don't have one.
// Safe for concurrent use; one instance is held per Scanner.
type hostnameResolver struct {
	timeout    time.Duration
	lookupAddr func(ctx context.Context, addr string) ([]string, error)
	sem        chan struct{}

	mu        sync.Mutex
	attempted map[string]time.Time // ip => last rdns/netbios attempt (negative cache)
	leases    map[string]string    // ip => hostname (from DHCP lease files)
	leasesAt  time.Time
}

func newHostnameResolver() *hostnameResolver {
	return &hostnameResolver{
		timeout:    1500 * time.Millisecond,
		lookupAddr: net.DefaultResolver.LookupAddr,
		sem:        make(chan struct{}, hostnameConcurrency),
		attempted:  make(map[string]time.Time),
		leases:     make(map[string]string),
	}
}

// resolve fills in hostnames for every inventory device that lacks one, using
// the enabled methods. Each discovered name is written back via Observe, which
// preserves existing non-empty hostnames - so authoritative mDNS/LLDP names are
// never clobbered by a weaker PTR/NetBIOS result.
func (r *hostnameResolver) resolve(ctx context.Context, inv *Inventory, m hostnameMethods) {
	if inv == nil {
		return
	}
	if m.DHCP {
		r.refreshLeases()
	}
	var wg sync.WaitGroup
	for _, d := range inv.Snapshot() {
		if d.Hostname != "" {
			continue
		}
		ip := d.IP
		// Skip LLDP-only pseudo keys ("lldp:...") and anything that isn't a
		// real address.
		if ip == "" || net.ParseIP(ip) == nil {
			continue
		}
		if m.DHCP {
			if name := r.leaseName(ip); name != "" {
				inv.SetHostname(ip, name)
				continue
			}
		}
		if !m.RDNS && !m.NetBIOS {
			continue
		}
		if !r.shouldAttempt(ip) {
			continue
		}
		wg.Add(1)
		r.sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-r.sem }()
			if ctx.Err() != nil {
				return
			}
			if m.RDNS {
				if name := r.reverse(ctx, ip); name != "" {
					inv.SetHostname(ip, name)
					return
				}
			}
			if m.NetBIOS {
				if name := r.netbios(ctx, ip); name != "" {
					inv.SetHostname(ip, name)
				}
			}
		}(ip)
	}
	wg.Wait()
}

// shouldAttempt enforces the negative cache: returns true (and records the
// attempt) only if ip hasn't been tried within hostnameNegativeTTL.
func (r *hostnameResolver) shouldAttempt(ip string) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if last, seen := r.attempted[ip]; seen && now.Sub(last) < hostnameNegativeTTL {
		return false
	}
	r.attempted[ip] = now
	return true
}

// reverse performs a single PTR lookup with a bounded timeout.
func (r *hostnameResolver) reverse(ctx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	names, err := r.lookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return cleanHostname(names[0])
}

// cleanHostname trims the trailing root dot and surrounding whitespace from a
// resolved name. The full FQDN is kept (callers can shorten for display).
func cleanHostname(s string) string {
	return strings.TrimSuffix(strings.TrimSpace(s), ".")
}

// --- DHCP lease parsing -----------------------------------------------------

// refreshLeases re-reads the lease files at most once per leaseRefreshTTL and
// rebuilds the ip => hostname map.
func (r *hostnameResolver) refreshLeases() {
	r.mu.Lock()
	stale := time.Since(r.leasesAt) >= leaseRefreshTTL
	r.mu.Unlock()
	if !stale {
		return
	}
	merged := make(map[string]string)
	for _, path := range dhcpLeaseFiles {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		var parsed map[string]string
		if strings.Contains(path, "dnsmasq") {
			parsed = parseDnsmasqLeases(f)
		} else {
			parsed = parseISCLeases(f)
		}
		f.Close()
		for ip, name := range parsed {
			merged[ip] = name
		}
	}
	r.mu.Lock()
	r.leases = merged
	r.leasesAt = time.Now()
	r.mu.Unlock()
}

func (r *hostnameResolver) leaseName(ip string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.leases[ip]
}

// parseDnsmasqLeases parses the dnsmasq lease format, one lease per line:
//
//	<expiry-epoch> <mac> <ip> <hostname> <client-id>
//
// A hostname of "*" means the client supplied none; such rows are skipped.
func parseDnsmasqLeases(r io.Reader) map[string]string {
	out := make(map[string]string)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		ip, host := fields[2], fields[3]
		if host == "" || host == "*" || net.ParseIP(ip) == nil {
			continue
		}
		out[ip] = host
	}
	return out
}

// parseISCLeases parses the ISC dhcpd.leases format:
//
//	lease 192.168.1.50 {
//	  ...
//	  client-hostname "foo";
//	}
//
// The last lease block wins for a given IP (most recent in the file).
func parseISCLeases(r io.Reader) map[string]string {
	out := make(map[string]string)
	sc := bufio.NewScanner(r)
	var curIP, curHost string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "lease "):
			curIP, curHost = "", ""
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				curIP = parts[1]
			}
		case strings.HasPrefix(line, "client-hostname "):
			curHost = trimISCValue(strings.TrimPrefix(line, "client-hostname "))
		case strings.HasPrefix(line, "}"):
			if curIP != "" && curHost != "" && net.ParseIP(curIP) != nil {
				out[curIP] = curHost
			}
			curIP, curHost = "", ""
		}
	}
	return out
}

// trimISCValue strips the trailing ';' and surrounding double quotes from an
// ISC lease statement value.
func trimISCValue(s string) string {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), ";"))
	return strings.Trim(s, `"`)
}

// --- NetBIOS (NBSTAT) -------------------------------------------------------

// netbios sends a NetBIOS node-status (NBSTAT) query to UDP/137 and returns the
// first unique workstation name (<00> suffix) from the reply.
func (r *hostnameResolver) netbios(ctx context.Context, ip string) string {
	addr := &net.UDPAddr{IP: net.ParseIP(ip), Port: 137}
	if addr.IP == nil {
		return ""
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	deadline := time.Now().Add(r.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(buildNBStatQuery()); err != nil {
		return ""
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}
	return parseNBStatResponse(buf[:n])
}

// buildNBStatQuery builds a NetBIOS node-status request for the wildcard name
// "*". The single-label name is encoded with first-level NetBIOS encoding
// (each nibble + 'A'), giving "CKAAAA...".
func buildNBStatQuery() []byte {
	b := make([]byte, 0, 50)
	b = append(b, 0x00, 0x00) // transaction id
	b = append(b, 0x00, 0x00) // flags: standard query
	b = append(b, 0x00, 0x01) // qdcount
	b = append(b, 0x00, 0x00) // ancount
	b = append(b, 0x00, 0x00) // nscount
	b = append(b, 0x00, 0x00) // arcount
	// Encoded wildcard name: length 0x20, then 32 encoded bytes, then root.
	b = append(b, 0x20)
	name := make([]byte, 16)
	name[0] = '*' // rest stay 0x00
	for _, c := range name {
		b = append(b, 'A'+(c>>4), 'A'+(c&0x0F))
	}
	b = append(b, 0x00)       // name terminator
	b = append(b, 0x00, 0x21) // qtype NBSTAT
	b = append(b, 0x00, 0x01) // qclass IN
	return b
}

// parseNBStatResponse extracts the first unique (non-group) workstation name
// (<00> suffix) from an NBSTAT response. Returns "" if the packet is malformed
// or carries no usable name.
func parseNBStatResponse(buf []byte) string {
	if len(buf) < 12 {
		return ""
	}
	if ancount := binary.BigEndian.Uint16(buf[6:8]); ancount == 0 {
		return ""
	}
	off := 12
	// Skip the answer's encoded name (label-length prefixed, root-terminated).
	for off < len(buf) {
		l := int(buf[off])
		if l == 0 {
			off++
			break
		}
		off += 1 + l
	}
	// type(2) class(2) ttl(4) rdlength(2)
	off += 10
	if off >= len(buf) {
		return ""
	}
	numNames := int(buf[off])
	off++
	for i := 0; i < numNames; i++ {
		if off+18 > len(buf) {
			return ""
		}
		raw := buf[off : off+15]
		suffix := buf[off+15]
		flags := binary.BigEndian.Uint16(buf[off+16 : off+18])
		off += 18
		group := flags&0x8000 != 0
		if suffix == 0x00 && !group {
			if name := strings.TrimRight(string(raw), " \x00"); name != "" {
				return name
			}
		}
	}
	return ""
}
