package discovery

import (
	"context"
	"net"
	"sync"
	"time"
)

// DefaultProbePorts is the curated short list of TCP ports tried during an
// active port sweep. Kept tiny so a /24 sweep finishes in seconds — wider
// scans belong to a manual `testudo discover --ports=...` invocation.
var DefaultProbePorts = []uint16{
	22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 631, 993, 995,
	1433, 1883, 2049, 2375, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9100,
}

// DefaultUDPProbePorts is the matching UDP shortlist. UDP is famously
// noisy/unanswered; only ports that typically reply (DNS, NTP, SNMP) are
// worth probing without specialised payloads.
var DefaultUDPProbePorts = []uint16{53, 67, 123, 161, 500, 1900, 5353}

// TCPProbe runs a TCP-connect probe (not a raw SYN — that would need raw
// sockets and root-only privileges; CAP_NET_RAW won't cover SOCK_RAW IPv4
// on all kernels). A successful connect is recorded; refused/timeout is
// silently dropped.
//
// timeout is per-port. Concurrency is bounded so a /24 × 25-port sweep
// doesn't open 6,400 sockets at once.
func (s *Scanner) TCPProbe(ctx context.Context, hosts []string, ports []uint16, timeout time.Duration) {
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	if len(ports) == 0 {
		ports = DefaultProbePorts
	}
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	for _, ip := range hosts {
		ip := ip
		for _, p := range ports {
			p := p
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				if probeTCPOnce(ctx, ip, p, timeout) {
					s.Inventory.Observe(Device{
						IP:        ip,
						OpenPorts: []uint16{p},
						Source:    "tcp-probe",
						LastSeen:  time.Now(),
					})
				}
			}()
		}
	}
	wg.Wait()
}

// UDPProbe sends a one-byte UDP datagram and waits briefly for an answer.
// Useful for the ports in DefaultUDPProbePorts; on others it reliably
// produces nothing.
func (s *Scanner) UDPProbe(ctx context.Context, hosts []string, ports []uint16, timeout time.Duration) {
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}
	if len(ports) == 0 {
		ports = DefaultUDPProbePorts
	}
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for _, ip := range hosts {
		ip := ip
		for _, p := range ports {
			p := p
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				if probeUDPOnce(ctx, ip, p, timeout) {
					s.Inventory.Observe(Device{
						IP:        ip,
						OpenPorts: []uint16{p},
						Source:    "udp-probe",
						LastSeen:  time.Now(),
					})
				}
			}()
		}
	}
	wg.Wait()
}

func probeTCPOnce(ctx context.Context, ip string, port uint16, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, portStr(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func probeUDPOnce(ctx context.Context, ip string, port uint16, timeout time.Duration) bool {
	addr := &net.UDPAddr{IP: net.ParseIP(ip), Port: int(port)}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{0}); err != nil {
		return false
	}
	buf := make([]byte, 1024)
	if _, err := conn.Read(buf); err != nil {
		// ICMP unreachable surfaces as a read error too — treat as closed.
		return false
	}
	_ = ctx // signature parity with TCP variant
	return true
}

func portStr(p uint16) string {
	const digits = "0123456789"
	if p == 0 {
		return "0"
	}
	var buf [6]byte
	i := len(buf)
	for p > 0 {
		i--
		buf[i] = digits[p%10]
		p /= 10
	}
	return string(buf[i:])
}
