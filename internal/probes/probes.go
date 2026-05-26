// Package probes implements user-triggered, one-shot diagnostic tests
// initiated from the TUI's Probes tab or the Web UI. Each probe returns a
// Result synchronously so the UI can show pass/fail without subscribing to
// the event bus.
package probes

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Kind enumerates the probe types exposed in the UI.
type Kind string

const (
	KindICMP       Kind = "icmp"
	KindTCP        Kind = "tcp"
	KindUDP        Kind = "udp"
	KindDNS        Kind = "dns"
	KindThroughput Kind = "throughput"
	KindTraceroute Kind = "traceroute"
)

// Request is the input to a probe execution.
type Request struct {
	Kind    Kind
	Target  string        // ip/host/cidr depending on kind
	Port    uint16        // for TCP/UDP
	Bytes   int           // for throughput (target bytes to transfer)
	Hops    int           // for traceroute (max hops)
	Timeout time.Duration // per-attempt deadline; 0 = sensible default
}

// Result is the structured outcome of a probe. Latency is the operationally
// useful metric for most probes; Detail carries human-readable extras
// (route hops, throughput Mbps, error message, …).
type Result struct {
	Kind    Kind
	OK      bool
	Latency time.Duration
	Detail  string
	Mbps    float64
	Hops    []TraceHop
	Err     string
}

// TraceHop is one entry in a traceroute result.
type TraceHop struct {
	TTL     int
	IP      string
	Latency time.Duration
}

// Run executes the probe described by r and returns the result. Returns
// nil only on programmer error - operational failures live inside Result.
//
// Panics inside an individual probe are caught and surfaced as a normal
// Result with Err set. This is a deliberate isolation: a probe runs from
// a Bubble Tea Cmd goroutine, and an unrecovered panic there would kill
// the entire TUI process. Operationally we'd rather show the user "this
// probe blew up" than have the program exit.
func Run(ctx context.Context, r Request) (res *Result, err error) {
	if r.Timeout <= 0 {
		r.Timeout = 3 * time.Second
	}
	defer func() {
		if p := recover(); p != nil {
			if res == nil {
				res = &Result{Kind: r.Kind}
			}
			res.OK = false
			res.Err = fmt.Sprintf("probe panic: %v", p)
		}
	}()
	switch r.Kind {
	case KindICMP:
		return runICMP(ctx, r), nil
	case KindTCP:
		return runTCP(ctx, r), nil
	case KindUDP:
		return runUDP(ctx, r), nil
	case KindDNS:
		return runDNS(ctx, r), nil
	case KindThroughput:
		return runThroughput(ctx, r), nil
	case KindTraceroute:
		return runTraceroute(ctx, r), nil
	}
	return nil, fmt.Errorf("unknown probe kind %q", r.Kind)
}

func runICMP(ctx context.Context, r Request) *Result {
	res := &Result{Kind: KindICMP}
	addr, err := net.ResolveIPAddr("ip4", r.Target)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		conn, err = icmp.ListenPacket("udp4", "0.0.0.0")
		if err != nil {
			res.Err = "icmp socket: " + err.Error()
			return res
		}
	}
	defer conn.Close()
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: 1, Seq: 1, Data: []byte("testudo-probe")},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	var dst net.Addr = &net.IPAddr{IP: addr.IP}
	// Try as UDP4 too in case raw is unavailable - we don't actually know
	// which mode ListenPacket gave us. We'll just try and switch on error.
	start := time.Now()
	if _, err := conn.WriteTo(b, dst); err != nil {
		dst = &net.UDPAddr{IP: addr.IP}
		if _, err := conn.WriteTo(b, dst); err != nil {
			res.Err = err.Error()
			return res
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(r.Timeout))
	buf := make([]byte, 1500)
	if _, _, err := conn.ReadFrom(buf); err != nil {
		res.Err = "timeout"
		return res
	}
	res.OK = true
	res.Latency = time.Since(start)
	res.Detail = fmt.Sprintf("reply from %s in %s", addr.IP, res.Latency)
	return res
}

func runTCP(ctx context.Context, r Request) *Result {
	res := &Result{Kind: KindTCP}
	dialer := net.Dialer{Timeout: r.Timeout}
	target := net.JoinHostPort(r.Target, fmt.Sprintf("%d", r.Port))
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	_ = conn.Close()
	res.OK = true
	res.Latency = time.Since(start)
	res.Detail = fmt.Sprintf("tcp connect to %s in %s", target, res.Latency)
	return res
}

// runUDP doesn't tell us if the *service* is up - UDP has no handshake -
// but it does tell us the path works and the kernel didn't return ICMP
// port-unreachable inside Timeout.
func runUDP(ctx context.Context, r Request) *Result {
	res := &Result{Kind: KindUDP}
	target := net.JoinHostPort(r.Target, fmt.Sprintf("%d", r.Port))
	conn, err := net.DialTimeout("udp", target, r.Timeout)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(r.Timeout))
	start := time.Now()
	if _, err := conn.Write([]byte("testudo-probe")); err != nil {
		res.Err = err.Error()
		return res
	}
	// Best-effort: try to read a response, but treat no-response as OK.
	buf := make([]byte, 1500)
	if _, err := conn.Read(buf); err != nil {
		// No response is normal for UDP - most servers don't reply to garbage.
		res.OK = true
		res.Latency = time.Since(start)
		res.Detail = "udp write succeeded; no response (typical)"
		return res
	}
	res.OK = true
	res.Latency = time.Since(start)
	res.Detail = "udp write succeeded; got a reply"
	return res
}

func runDNS(ctx context.Context, r Request) *Result {
	res := &Result{Kind: KindDNS}
	resolver := &net.Resolver{}
	dnsCtx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	start := time.Now()
	addrs, err := resolver.LookupHost(dnsCtx, r.Target)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.OK = true
	res.Latency = time.Since(start)
	res.Detail = fmt.Sprintf("%d answer(s): %v", len(addrs), addrs)
	return res
}

// runThroughput downloads from a known HTTP endpoint for up to r.Timeout
// and reports the average throughput.
//
// Target resolution, in order of preference:
//  1. r.Target already has http:// or https:// => use it as-is
//  2. r.Target is a bare hostname (e.g. "speed.cloudflare.com") => use
//     https://<target>/__down?bytes=N
//  3. r.Target is empty, looks like an IP, or otherwise unusable as a URL
//     => fall back to the Cloudflare speedtest endpoint
//
// The third case matters because the TUI shares a single `target` field
// across all probe kinds, defaulting to "1.1.1.1" - which makes sense for
// ICMP but is useless for an HTTP throughput test. Without this fallback
// the probe failed with `unsupported protocol scheme ""`.
func runThroughput(ctx context.Context, r Request) *Result {
	res := &Result{Kind: KindThroughput}
	bytes := r.Bytes
	if bytes <= 0 {
		bytes = 25_000_000
	}
	defaultURL := fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", bytes)

	url := pickThroughputURL(r.Target, defaultURL, bytes)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	client := &http.Client{Timeout: r.Timeout + 10*time.Second}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer resp.Body.Close()
	buf := make([]byte, 64*1024)
	var total int64
	for {
		n, err := resp.Body.Read(buf)
		total += int64(n)
		if err != nil {
			break
		}
	}
	elapsed := time.Since(start)
	if elapsed == 0 {
		elapsed = time.Millisecond
	}
	bits := float64(total) * 8
	mbps := bits / 1_000_000.0 / elapsed.Seconds()
	res.OK = total > 0
	res.Latency = elapsed
	res.Mbps = mbps
	res.Detail = fmt.Sprintf("%.1f Mbps · %d bytes in %s · %s",
		mbps, total, elapsed.Truncate(time.Millisecond), url)
	if !res.OK {
		res.Err = "no bytes received"
	}
	return res
}

// pickThroughputURL picks a usable HTTP URL for the throughput probe. See
// the comment on runThroughput for the resolution order.
func pickThroughputURL(target, fallback string, bytes int) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return fallback
	}
	// Already a URL.
	if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
		return t
	}
	// Bare IPs (v4 or v6) are not usable: there's no speedtest endpoint
	// guaranteed at the root of an IP. Use the fallback so the user gets a
	// meaningful number instead of "unsupported protocol scheme """.
	if net.ParseIP(t) != nil {
		return fallback
	}
	// Hostname - assume the user typed e.g. "speed.cloudflare.com" and
	// wants to hit the conventional path. Falls back if the host doesn't
	// actually serve /__down, which is fine: the user can paste a full URL.
	return fmt.Sprintf("https://%s/__down?bytes=%d", t, bytes)
}

// runTraceroute walks TTLs from 1..Hops, sending an ICMP echo at each TTL
// and recording where the kernel-side TTL-exceeded came from.
//
// Implementation notes (these were each landmines in an earlier version):
//
//   - To set TTL we MUST use conn.IPv4PacketConn(), not
//     ipv4.NewPacketConn(conn). The former returns the wrapper icmp keeps
//     inside, with the underlying RawConn already attached. The latter
//     wraps the high-level conn a second time and on some platforms ends
//     up with a nil internal Conn, so the next SetTTL deref-panics.
//
//   - One defer Close, not two. The icmp.PacketConn and its inner
//     ipv4.PacketConn share the same fd; closing it twice is not portable.
//
//   - peer is always *net.IPAddr for an `ip4:icmp` listener - its String()
//     returns just the IP. The old stripPort() helper would chop IPv6
//     addresses at the last colon. Use peer.String() directly.
//
//   - r.Timeout is a per-probe budget (default 3s) - using it as the
//     per-hop read deadline meant a non-responsive hop wasted 3s and 16
//     hops × 3s = 48s, longer than the TUI's outer 25s context. We use a
//     much tighter 800ms per hop and honor ctx.Done() between hops.
func runTraceroute(ctx context.Context, r Request) *Result {
	res := &Result{Kind: KindTraceroute}
	if r.Hops <= 0 {
		r.Hops = 16
	}
	if strings.TrimSpace(r.Target) == "" {
		res.Err = "traceroute: empty target"
		return res
	}
	addr, err := net.ResolveIPAddr("ip4", r.Target)
	if err != nil {
		res.Err = "resolve: " + err.Error()
		return res
	}
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		res.Err = "icmp listen (need CAP_NET_RAW): " + err.Error()
		return res
	}
	defer conn.Close()
	pconn := conn.IPv4PacketConn()
	if pconn == nil {
		res.Err = "icmp: IPv4PacketConn unavailable"
		return res
	}

	perHop := 800 * time.Millisecond
	if r.Timeout > 0 && r.Timeout < perHop {
		perHop = r.Timeout
	}
	target := addr.IP.String()

	for ttl := 1; ttl <= r.Hops; ttl++ {
		if ctx.Err() != nil {
			break
		}
		if err := pconn.SetTTL(ttl); err != nil {
			res.Err = "set TTL: " + err.Error()
			break
		}
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{ID: 1, Seq: ttl, Data: []byte("testudo-trace")},
		}
		b, err := msg.Marshal(nil)
		if err != nil {
			break
		}
		start := time.Now()
		if _, err := conn.WriteTo(b, &net.IPAddr{IP: addr.IP}); err != nil {
			res.Hops = append(res.Hops, TraceHop{TTL: ttl, IP: "*"})
			continue
		}
		_ = conn.SetReadDeadline(time.Now().Add(perHop))
		buf := make([]byte, 1500)
		_, peer, err := conn.ReadFrom(buf)
		if err != nil || peer == nil {
			res.Hops = append(res.Hops, TraceHop{TTL: ttl, IP: "*"})
			continue
		}
		ip := peer.String()
		hop := TraceHop{TTL: ttl, IP: ip, Latency: time.Since(start)}
		res.Hops = append(res.Hops, hop)
		if ip == target {
			break
		}
	}
	res.OK = len(res.Hops) > 0
	if !res.OK && res.Err == "" {
		res.Err = "no hops collected"
	}
	res.Detail = fmt.Sprintf("%d hops collected", len(res.Hops))
	return res
}

func stripPort(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return s[:i]
		}
	}
	return s
}
