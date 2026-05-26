package collectors

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/flows"
)

// InternalDNSCollector queries the LAN's DNS resolvers directly (not via
// the stub) so the operator can tell whether the internal resolver is
// healthy independently of any caching layer. The DNSResultPayload's
// Server field carries the resolver that answered, so a single name
// resolving fast on 192.168.1.1 but slow on 192.168.1.2 is visible.
type InternalDNSCollector struct {
	// Servers is the explicit list of resolvers. When empty,
	// /etc/resolv.conf is re-parsed every tick and non-loopback LAN
	// nameservers are picked up automatically (catches DHCP changes).
	Servers  []string
	Names    []string
	Interval time.Duration
	Timeout  time.Duration
}

func (c *InternalDNSCollector) Name() string { return "internal-dns" }

func (c *InternalDNSCollector) Run(ctx context.Context, bus *events.Bus) error {
	if len(c.Names) == 0 || c.Interval <= 0 {
		return nil
	}
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	c.probeAll(ctx, bus)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.probeAll(ctx, bus)
		}
	}
}

func (c *InternalDNSCollector) probeAll(ctx context.Context, bus *events.Bus) {
	servers := c.Servers
	if len(servers) == 0 {
		servers = lanResolversFromResolvConf()
	}
	if len(servers) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, srv := range servers {
		for _, name := range c.Names {
			wg.Add(1)
			go func(srv, name string) {
				defer wg.Done()
				c.probeOne(ctx, bus, srv, name)
			}(srv, name)
		}
	}
	wg.Wait()
}

func (c *InternalDNSCollector) probeOne(ctx context.Context, bus *events.Bus, server, name string) {
	qctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: c.Timeout}
			return d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		},
	}
	start := time.Now()
	addrs, err := resolver.LookupHost(qctx, name)
	dur := time.Since(start)
	if err != nil {
		bus.Publish(events.Event{
			Kind: events.KindDNSFailure, Source: c.Name(),
			Payload: events.DNSFailurePayload{
				Name: name, Server: server, Duration: dur, Err: err.Error(),
			},
		})
		return
	}
	bus.Publish(events.Event{
		Kind: events.KindDNSResult, Source: c.Name(),
		Payload: events.DNSResultPayload{
			Name: name, Server: server, Duration: dur,
			Answers: len(addrs), IPs: append([]string{}, addrs...),
		},
	})
}

// lanResolversFromResolvConf returns the nameserver IPs configured on
// the host that are reachable LAN addresses. Loopback is skipped -
// 127.0.0.53 is the systemd-resolved stub, which is what we're trying
// to look *behind*. On systemd-resolved hosts the real upstream
// resolvers live in /run/systemd/resolve/resolv.conf, so we read that
// path too and de-duplicate. Order: /etc first, then systemd-resolved
// upstream list.
func lanResolversFromResolvConf() []string {
	paths := []string{
		"/etc/resolv.conf",
		"/run/systemd/resolve/resolv.conf",
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		for _, ip := range parseResolvConf(p) {
			if seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

func parseResolvConf(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[1]
		parsed := net.ParseIP(ip)
		if parsed == nil || parsed.IsLoopback() {
			continue
		}
		if !flows.IsLAN(ip) {
			continue
		}
		out = append(out, ip)
	}
	return out
}
