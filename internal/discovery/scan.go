package discovery

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/noahzmr/testudo/internal/events"
)

// Scanner runs periodic active + passive discovery against the local subnets.
type Scanner struct {
	Inventory *Inventory
	Interval  time.Duration // sweep cadence
	Active    bool          // when true, also runs ICMP/ARP/mDNS/SNMP probes

	// MaxSubnetBits caps the prefix expansion for active sweeps. Default
	// 10 = /22 (1024 hosts). Set to 8 to keep behaviour pinned to /24,
	// raise to 12 for /20 networks. Anything wider is silently skipped
	// to avoid burying the local NIC.
	MaxSubnetBits int

	// SNMPCommunity is the read community used by the SNMPv2c probe.
	// Empty disables SNMP probing entirely.
	SNMPCommunity string

	// SNMPTimeout is the per-host UDP/161 deadline. Default 1s.
	SNMPTimeout time.Duration

	// Intensity controls scan breadth: "fast", "balanced" (default), or
	// "aggressive". It tunes port lists, probe timeouts, the subnet cap, and
	// which hostname-resolution fallbacks run. See profile.
	Intensity string

	hres     *hostnameResolver
	hresOnce sync.Once
}

// hostnames returns the lazily-initialized hostname resolver. Safe for
// concurrent first use.
func (s *Scanner) hostnames() *hostnameResolver {
	s.hresOnce.Do(func() { s.hres = newHostnameResolver() })
	return s.hres
}

// scanProfile is the resolved set of per-pass knobs for an intensity level.
type scanProfile struct {
	doICMP     bool
	doMDNS     bool
	doUDP      bool
	tcpPorts   []uint16
	tcpTimeout time.Duration
	udpTimeout time.Duration
	subnetCap  int // 0 = use the scanner's MaxSubnetBits unchanged
	hostnames  hostnameMethods
}

// profile maps the configured Intensity to its knobs. Unknown/empty values
// fall back to "balanced", which preserves the historical behaviour.
func (s *Scanner) profile() scanProfile {
	switch strings.ToLower(s.Intensity) {
	case "fast":
		// ARP-centric, tight timeouts, cheap hostname fills only. No ICMP/mDNS
		// flood, no NetBIOS probe.
		return scanProfile{
			doICMP:     false,
			doMDNS:     false,
			doUDP:      false,
			tcpPorts:   ConnectionPorts,
			tcpTimeout: 200 * time.Millisecond,
			subnetCap:  8, // /24
			hostnames:  hostnameMethods{DHCP: true, RDNS: true},
		}
	case "aggressive":
		return scanProfile{
			doICMP:     true,
			doMDNS:     true,
			doUDP:      true,
			tcpPorts:   DefaultProbePorts,
			tcpTimeout: 500 * time.Millisecond,
			udpTimeout: 600 * time.Millisecond,
			subnetCap:  0,
			hostnames:  hostnameMethods{DHCP: true, RDNS: true, NetBIOS: true},
		}
	default: // "balanced"
		return scanProfile{
			doICMP:     true,
			doMDNS:     true,
			doUDP:      true,
			tcpPorts:   DefaultProbePorts,
			tcpTimeout: 300 * time.Millisecond,
			udpTimeout: 400 * time.Millisecond,
			subnetCap:  0,
			hostnames:  hostnameMethods{DHCP: true, RDNS: true, NetBIOS: true},
		}
	}
}

func (s *Scanner) Name() string { return "discovery" }

func (s *Scanner) Run(ctx context.Context, bus *events.Bus) error {
	if s.Interval <= 0 {
		s.Interval = 60 * time.Second
	}
	s.pass(ctx, bus)
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.pass(ctx, bus)
		}
	}
}

// pass runs one round of discovery work. Passive observation (ARP cache
// read) runs every tick; when Active is true the round also fires an ARP
// broadcast sweep (the biggest single coverage win - catches hosts that
// drop ICMP), an ICMP sweep, mDNS, the TCP/UDP service probe against
// every known host, and an SNMPv2c GET against UDP/161 responders.
//
// The TCP/UDP probes no longer cap at 32 hosts; each probe bounds its
// own concurrency, and the per-pass interval (default 60s) keeps even
// large inventories from saturating the link. The ICMP sweep still
// skips anything wider than MaxSubnetBits.
func (s *Scanner) pass(ctx context.Context, bus *events.Bus) {
	s.scanARPCache()
	prof := s.profile()
	if !s.Active {
		// Passive mode still benefits from the cheap, no-probe hostname fills
		// (DHCP leases + reverse DNS) and from classification.
		s.hostnames().resolve(ctx, s.Inventory, hostnameMethods{DHCP: true, RDNS: true})
		s.enrich()
		return
	}
	maxBits := s.MaxSubnetBits
	if maxBits == 0 {
		maxBits = 10 // /22 - 1024 hosts
	}
	if prof.subnetCap > 0 && prof.subnetCap < maxBits {
		maxBits = prof.subnetCap
	}
	// ARP sweep first: the kernel populates /proc/net/arp from replies,
	// so the next scanARPCache() on the next tick picks up the long tail
	// of devices that ignored ICMP.
	s.arpSweepAll(ctx, maxBits)
	if prof.doICMP {
		for _, sub := range localIPv4Subnets() {
			s.icmpSweep(ctx, sub, maxBits)
		}
	}
	if prof.doMDNS {
		s.mdnsProbe(ctx)
	}
	// Refresh hosts after the ARP/ICMP sweeps so the port probes see
	// everything we just discovered.
	hosts := make([]string, 0)
	for _, d := range s.Inventory.Snapshot() {
		// Skip pseudo-IPs (LLDP-only neighbours under "lldp:..." keys).
		if d.IP != "" && d.IP[0] != 'l' {
			hosts = append(hosts, d.IP)
		}
	}
	if len(hosts) > 0 {
		s.TCPProbe(ctx, hosts, prof.tcpPorts, prof.tcpTimeout)
		if prof.doUDP {
			s.UDPProbe(ctx, hosts, nil, prof.udpTimeout)
		}
	}
	if s.SNMPCommunity != "" {
		timeout := s.SNMPTimeout
		if timeout <= 0 {
			timeout = time.Second
		}
		s.snmpProbeAll(ctx, s.SNMPCommunity, timeout)
	}
	// Hostname fallbacks + classification run last, over everything the
	// probes just discovered. Neither bumps LastSeen (see Inventory.SetHostname
	// / Enrich), so resolving a name for an offline host can't keep it alive.
	s.hostnames().resolve(ctx, s.Inventory, prof.hostnames)
	s.enrich()
}

// enrich derives DeviceType and MACType for every inventory entry that's still
// missing them, from the signals accumulated so far. It uses the non-liveness
// Inventory.Enrich mutator so repeated passes don't refresh LastSeen.
func (s *Scanner) enrich() {
	for _, d := range s.Inventory.Snapshot() {
		macType := ""
		if d.MACType == "" && d.MAC != "" {
			macType = classifyMAC(d.MAC)
		}
		deviceType := ""
		if d.DeviceType == "" {
			deviceType = classifyDevice(d)
		}
		if macType != "" || deviceType != "" {
			s.Inventory.Enrich(d.IP, deviceType, macType)
		}
	}
}

// scanARPCache reads /proc/net/arp and records every (IP, MAC, iface) tuple.
// Cheap, low-noise, runs every interval. Stale entries decay via MarkStale.
func (s *Scanner) scanARPCache() {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Scan() // header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// IP HW-Type Flags HW-Addr Mask Device
		if len(fields) < 6 {
			continue
		}
		ip := fields[0]
		mac := fields[3]
		iface := fields[5]
		if mac == "00:00:00:00:00:00" {
			continue
		}
		d := Device{
			IP: ip, MAC: mac, Iface: iface, Source: "arp",
			Vendor: vendorFor(mac), MACType: classifyMAC(mac),
		}
		s.Inventory.Observe(d)
	}
}

// icmpSweep pings every host in subnet (capped to maxBits-sized ranges
// to bound network noise) and records responders. Reuses the same
// unprivileged-ICMP fallback dance as the collector.
func (s *Scanner) icmpSweep(ctx context.Context, subnet *net.IPNet, maxBits int) {
	ones, bits := subnet.Mask.Size()
	if bits-ones > maxBits {
		// Wider than the configured cap - skip. Avoid blasting tens of
		// thousands of ICMP echoes against a misconfigured /16.
		return
	}
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		conn, err = icmp.ListenPacket("udp4", "0.0.0.0")
		if err != nil {
			return
		}
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Send echoes to every host in the subnet, except network/broadcast.
	base := subnet.IP.Mask(subnet.Mask).To4()
	if base == nil {
		return
	}
	count := 1 << (bits - ones)
	var wg sync.WaitGroup
	wg.Add(1)
	// Reader: collects responses.
	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}
			msg, err := icmp.ParseMessage(int(ipv4.ICMPTypeEchoReply.Protocol()), buf[:n])
			if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			ip := stripPort(peer.String())
			s.Inventory.Observe(Device{IP: ip, Source: "icmp"})
		}
	}()

	for i := 1; i < count-1; i++ {
		target := dupIP(base)
		incIP(target, i)
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{ID: 1, Seq: i & 0xffff, Data: []byte("testudo-disc")},
		}
		b, err := msg.Marshal(nil)
		if err != nil {
			continue
		}
		_, _ = conn.WriteTo(b, &net.IPAddr{IP: target})
		// Tiny stagger so we don't burst into upstream rate-limits.
		time.Sleep(2 * time.Millisecond)
		if ctx.Err() != nil {
			return
		}
	}
	wg.Wait()
}

func stripPort(addr string) string {
	if i := strings.LastIndex(addr, ":"); i > 0 && i < len(addr)-1 && !strings.Contains(addr[:i], "]") {
		return addr[:i]
	}
	return addr
}

func dupIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

// incIP adds offset to the IP in place (big-endian, IPv4 only).
func incIP(ip net.IP, offset int) {
	v := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	v += uint32(offset)
	ip[0] = byte(v >> 24)
	ip[1] = byte(v >> 16)
	ip[2] = byte(v >> 8)
	ip[3] = byte(v)
}

// mdnsProbe sends a single ANY query to 224.0.0.251:5353 and listens for
// responses for a few seconds. Responders advertise hostnames in their
// answer records - we extract the first .local name as a hostname hint.
func (s *Scanner) mdnsProbe(ctx context.Context) {
	mdnsAddr := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return
	}
	defer conn.Close()
	// Minimal mDNS query: standard query, 1 question for "_services._dns-sd._udp.local" PTR
	query := buildMDNSQuery("_services._dns-sd._udp.local")
	_, _ = conn.WriteToUDP(query, mdnsAddr)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	for {
		if ctx.Err() != nil {
			return
		}
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		host := extractFirstMDNSName(buf[:n])
		if host == "" {
			continue
		}
		s.Inventory.Observe(Device{
			IP: from.IP.String(), Hostname: host, Source: "mdns",
		})
	}
}

// buildMDNSQuery hand-rolls a minimal DNS query for name (type PTR, class IN).
// Returns wire-format bytes. Sufficient for "anyone there?" probes.
func buildMDNSQuery(name string) []byte {
	var b []byte
	// Header: id=0, flags=0x0000 (standard query), qdcount=1
	b = append(b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// QNAME: length-prefixed labels + null terminator
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		b = append(b, byte(len(label)))
		b = append(b, []byte(label)...)
	}
	b = append(b, 0x00)
	// QTYPE=PTR(12), QCLASS=IN(1)
	b = append(b, 0x00, 0x0c, 0x00, 0x01)
	return b
}

// extractFirstMDNSName parses a tiny subset of DNS to find the first ANSWER
// record's RDATA when it points at a name. Returns the parsed name or "".
// Not a full DNS parser; just enough to recover hostnames from mDNS replies.
func extractFirstMDNSName(packet []byte) string {
	if len(packet) < 12 {
		return ""
	}
	qdcount := int(packet[4])<<8 | int(packet[5])
	ancount := int(packet[6])<<8 | int(packet[7])
	if ancount == 0 {
		return ""
	}
	off := 12
	// Skip question section.
	for i := 0; i < qdcount; i++ {
		n, ok := skipName(packet, off)
		if !ok {
			return ""
		}
		off = n + 4
	}
	// First answer: NAME(skipped) TYPE(2) CLASS(2) TTL(4) RDLEN(2) RDATA
	n, ok := skipName(packet, off)
	if !ok {
		return ""
	}
	if n+10 > len(packet) {
		return ""
	}
	rdLen := int(packet[n+8])<<8 | int(packet[n+9])
	rdStart := n + 10
	if rdStart+rdLen > len(packet) {
		return ""
	}
	name, _ := readName(packet, rdStart)
	return name
}

// skipName walks DNS-encoded labels and returns the byte offset just past
// the terminator (or first pointer). Pointers are followed for one hop.
func skipName(packet []byte, off int) (int, bool) {
	for off < len(packet) {
		b := packet[off]
		if b == 0 {
			return off + 1, true
		}
		if b&0xC0 == 0xC0 {
			return off + 2, true
		}
		off += int(b) + 1
	}
	return 0, false
}

// readName resolves a DNS-encoded name including one level of pointer chasing.
func readName(packet []byte, off int) (string, int) {
	var labels []string
	for i := 0; i < 32 && off < len(packet); i++ {
		b := packet[off]
		if b == 0 {
			return strings.Join(labels, "."), off + 1
		}
		if b&0xC0 == 0xC0 {
			if off+1 >= len(packet) {
				return "", off
			}
			ptr := int(b&0x3F)<<8 | int(packet[off+1])
			name, _ := readName(packet, ptr)
			if name != "" {
				labels = append(labels, name)
			}
			return strings.Join(labels, "."), off + 2
		}
		llen := int(b)
		if off+1+llen > len(packet) {
			return "", off
		}
		labels = append(labels, string(packet[off+1:off+1+llen]))
		off += 1 + llen
	}
	return strings.Join(labels, "."), off
}

// localIPv4Subnets returns CIDRs assigned to up, non-loopback interfaces.
func localIPv4Subnets() []*net.IPNet {
	var out []*net.IPNet
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			out = append(out, ipn)
		}
	}
	return out
}
