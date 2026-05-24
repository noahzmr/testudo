package flows

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/noahzmr/testudo/internal/services"
)

// DNSCache maps a destination IP to the most recently seen DNS name that
// resolved to it. Populated by the engine from KindDNSResult events; queried
// during flow rendering.
type DNSCache struct {
	mu  sync.RWMutex
	ips map[string]string
}

func NewDNSCache() *DNSCache { return &DNSCache{ips: make(map[string]string)} }

// Record adds (name → resolved IP) mappings. We index by IP because that's
// what a packet carries.
func (c *DNSCache) Record(name string, ips []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ip := range ips {
		c.ips[ip] = name
	}
}

// RecordHostByIP allows recording when we've only resolved one address.
func (c *DNSCache) RecordHostByIP(name, ip string) {
	c.mu.Lock()
	c.ips[ip] = name
	c.mu.Unlock()
}

// Lookup returns the most-recent DNS name observed for ip, or "".
func (c *DNSCache) Lookup(ip string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ips[ip]
}

// ProcMatcher reads /proc/net/{tcp,tcp6,udp,udp6} and /proc/*/fd to map
// (proto, local-ip, local-port) → process name. Refresh() is cheap enough
// to call once per render tick; the cost is bounded by the number of
// established sockets, not by total processes.
type ProcMatcher struct {
	mu    sync.RWMutex
	table map[string]string // key = "proto|ip:port"
}

func NewProcMatcher() *ProcMatcher { return &ProcMatcher{table: make(map[string]string)} }

// Refresh rebuilds the in-memory mapping. Best-effort: I/O errors are
// silently absorbed because /proc visibility depends on the caller's uid
// and may legitimately partially fail.
func (p *ProcMatcher) Refresh() {
	inodeToPid := buildInodeIndex()
	table := make(map[string]string, 64)
	for _, src := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp"},
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp"},
	} {
		rows := parseProcNet(src.path)
		for _, r := range rows {
			pid, ok := inodeToPid[r.inode]
			if !ok {
				continue
			}
			name := procName(pid)
			if name == "" {
				continue
			}
			key := src.proto + "|" + net.JoinHostPort(r.localIP, fmt.Sprintf("%d", r.localPort))
			table[key] = name
		}
	}
	p.mu.Lock()
	p.table = table
	p.mu.Unlock()
}

// Lookup returns a process name for a 5-tuple endpoint, or "".
func (p *ProcMatcher) Lookup(proto, ip string, port uint16) string {
	key := proto + "|" + net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.table[key]
}

// Decorate fills Process + DNSName + Service on every flow that has a
// matching record. Returns a fresh slice; input is not mutated.
func Decorate(stats []FlowStats, dns *DNSCache, proc *ProcMatcher) []FlowStats {
	out := make([]FlowStats, len(stats))
	for i, f := range stats {
		out[i] = f
		// DNS reverse-correlate either endpoint.
		if name := dns.Lookup(f.Key.B.IP); name != "" {
			out[i].DNSName = name
		} else if name := dns.Lookup(f.Key.A.IP); name != "" {
			out[i].DNSName = name
		}
		// Process correlation: try both endpoints as "local".
		if n := proc.Lookup(f.Key.Proto, f.Key.A.IP, f.Key.A.Port); n != "" {
			out[i].Process = n
			out[i].ProcessName = n
		} else if n := proc.Lookup(f.Key.Proto, f.Key.B.IP, f.Key.B.Port); n != "" {
			out[i].Process = n
			out[i].ProcessName = n
		}
		// Service correlation: prefer the lower port (typical "server" side).
		out[i].Service = serviceFor(f.Key.Proto, f.Key.A.Port, f.Key.B.Port)
	}
	return out
}

// Tagger applies cross-subsystem correlation labels. Callers populate it
// once per snapshot tick from authoritative state (conntrack, route table,
// firewall counters) and pass it to Tag(). Unmatched flows are left
// untagged — empty strings — so callers can distinguish "no data" from "no
// match".
type Tagger struct {
	// FirewallByFlow maps a canonical "proto|srcIP:srcPort→dstIP:dstPort"
	// key to a chain/verdict label, e.g. "INPUT/ACCEPT".
	FirewallByFlow map[string]string
	// NATByEndpoint maps a "proto|ip:port" key to a NAT mapping label.
	NATByEndpoint map[string]string
	// RouteByDestIP maps a destination IP to a route descriptor
	// ("via 10.0.0.1 dev eth0").
	RouteByDestIP map[string]string
}

// NewTagger returns an empty tagger that no-ops on Tag.
func NewTagger() *Tagger {
	return &Tagger{
		FirewallByFlow: map[string]string{},
		NATByEndpoint:  map[string]string{},
		RouteByDestIP:  map[string]string{},
	}
}

// Tag fills FirewallChain / NATMapping / RouteVia on each flow it has data
// for. Returns a new slice; input is not mutated.
func (t *Tagger) Tag(stats []FlowStats) []FlowStats {
	if t == nil {
		return stats
	}
	out := make([]FlowStats, len(stats))
	for i, f := range stats {
		out[i] = f
		key := f.Key.Proto + "|" + f.Key.A.String() + "→" + f.Key.B.String()
		if v := t.FirewallByFlow[key]; v != "" {
			out[i].FirewallChain = v
		}
		if v := t.NATByEndpoint[f.Key.Proto+"|"+f.Key.B.String()]; v != "" {
			out[i].NATMapping = v
		} else if v := t.NATByEndpoint[f.Key.Proto+"|"+f.Key.A.String()]; v != "" {
			out[i].NATMapping = v
		}
		if v := t.RouteByDestIP[f.Key.B.IP]; v != "" {
			out[i].RouteVia = v
		}
	}
	return out
}

// serviceFor returns the well-known service name for a flow's port pair.
// The "server" side typically owns the well-known port — we try the lower
// port first and fall back to the higher.
func serviceFor(proto string, portA, portB uint16) string {
	lo, hi := portA, portB
	if hi < lo {
		lo, hi = hi, lo
	}
	if name := services.Name(proto, lo); name != "" {
		return name
	}
	return services.Name(proto, hi)
}

// --- /proc parsers (pure stdlib) ---

type procNetRow struct {
	localIP   string
	localPort uint16
	inode     uint64
}

func parseProcNet(path string) []procNetRow {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	scanner.Scan() // skip header
	var rows []procNetRow
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// sl local_addr rem_addr st tx_queue:rx_queue tr:tm_when retrnsmt uid timeout inode ...
		if len(fields) < 10 {
			continue
		}
		ip, port, ok := parseHexEndpoint(fields[1])
		if !ok {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		rows = append(rows, procNetRow{localIP: ip, localPort: port, inode: inode})
	}
	return rows
}

// parseHexEndpoint converts /proc/net's "0100007F:1F90" into ("127.0.0.1", 8080).
// Handles both 4-byte and 16-byte (IPv6) hex forms.
func parseHexEndpoint(s string) (string, uint16, bool) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0, false
	}
	port64, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, false
	}
	port := uint16(port64)

	hex := parts[0]
	switch len(hex) {
	case 8: // IPv4 little-endian
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
			if err != nil {
				return "", 0, false
			}
			b[3-i] = byte(v)
		}
		return net.IP(b).String(), port, true
	case 32: // IPv6 — groups of 4 bytes, each group little-endian
		b := make([]byte, 16)
		for g := 0; g < 4; g++ {
			for i := 0; i < 4; i++ {
				v, err := strconv.ParseUint(hex[g*8+i*2:g*8+i*2+2], 16, 8)
				if err != nil {
					return "", 0, false
				}
				b[g*4+3-i] = byte(v)
			}
		}
		return net.IP(b).String(), port, true
	}
	return "", 0, false
}

// buildInodeIndex scans /proc/*/fd/* and returns a map from socket inode to
// owning pid. Only readable entries are returned; permission errors are
// ignored.
func buildInodeIndex() map[uint64]int {
	out := make(map[uint64]int)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", ent.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			// e.g. "socket:[123456]"
			if !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inodeStr := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			inode, err := strconv.ParseUint(inodeStr, 10, 64)
			if err != nil {
				continue
			}
			out[inode] = pid
		}
	}
	return out
}

func procName(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
