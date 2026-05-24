package collectors

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/noahzmr/testudo/internal/events"
)

// ICMPCollector probes targets at a fixed interval. It prefers raw ICMP
// (`ip4:icmp`, requires CAP_NET_RAW) and falls back to datagram ICMP
// (`udp4`, requires `net.ipv4.ping_group_range` to cover the user's gid).
// A non-response within Timeout is reported as packet loss.
type ICMPCollector struct {
	Targets  []string
	Interval time.Duration
	Timeout  time.Duration
}

func (c *ICMPCollector) Name() string { return "icmp" }

func (c *ICMPCollector) Run(ctx context.Context, bus *events.Bus) error {
	if len(c.Targets) == 0 {
		return nil
	}
	conn, network, err := listenICMP()
	if err != nil {
		return err
	}
	defer conn.Close()

	pending := newPendingMap()
	go readLoop(ctx, conn, pending)

	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()

	var seq uint32
	probe := func() {
		for _, target := range c.Targets {
			addr, err := net.ResolveIPAddr("ip4", target)
			if err != nil {
				bus.Publish(events.Event{
					Kind: events.KindPacketLoss, Source: c.Name(),
					Payload: events.PacketLossPayload{Target: target, Sent: 1, Lost: 1, LossPct: 100},
				})
				continue
			}
			seq++
			seqKey := strconv.Itoa(int(seq & 0xffff))
			start := time.Now()
			pending.add(seqKey)

			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho, Code: 0,
				Body: &icmp.Echo{
					// In udp4 mode the kernel rewrites ID to the socket's
					// source port; in raw mode it's preserved. Either way
					// the receiver matches by sequence, so ID is cosmetic.
					ID:   1,
					Seq:  int(seq & 0xffff),
					Data: []byte("testudo"),
				},
			}
			b, err := msg.Marshal(nil)
			if err != nil {
				pending.remove(seqKey)
				continue
			}
			var dst net.Addr = &net.IPAddr{IP: addr.IP}
			if network == "udp4" {
				dst = &net.UDPAddr{IP: addr.IP}
			}
			if _, err := conn.WriteTo(b, dst); err != nil {
				pending.remove(seqKey)
				bus.Publish(events.Event{
					Kind: events.KindPacketLoss, Source: c.Name(),
					Payload: events.PacketLossPayload{Target: target, Sent: 1, Lost: 1, LossPct: 100},
				})
				continue
			}

			go func(seqKey, target string, start time.Time) {
				timer := time.NewTimer(c.Timeout)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return
				case reply := <-pending.wait(seqKey):
					bus.Publish(events.Event{
						Kind: events.KindLatency, Source: c.Name(),
						Payload: events.LatencyPayload{Target: target, RTT: reply.Sub(start)},
					})
				case <-timer.C:
					pending.remove(seqKey)
					bus.Publish(events.Event{
						Kind: events.KindPacketLoss, Source: c.Name(),
						Payload: events.PacketLossPayload{Target: target, Sent: 1, Lost: 1, LossPct: 100},
					})
				}
			}(seqKey, target, start)
		}
	}

	probe()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			probe()
		}
	}
}

// listenICMP opens a SOCK_RAW ICMP socket if permitted, otherwise tries
// SOCK_DGRAM (the "unprivileged ping" path). Returns the selected network
// so callers know which destination address type to use.
func listenICMP() (*icmp.PacketConn, string, error) {
	if c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
		return c, "ip4:icmp", nil
	}
	if c, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
		return c, "udp4", nil
	}
	return nil, "", errors.New(
		"icmp socket unavailable — grant CAP_NET_RAW with `sudo setcap cap_net_raw=+ep ./testudo` " +
			"or enable datagram mode with `sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'`",
	)
}

func readLoop(ctx context.Context, conn *icmp.PacketConn, pending *pendingMap) {
	buf := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return
		}
		msg, err := icmp.ParseMessage(int(ipv4.ICMPTypeEchoReply.Protocol()), buf[:n])
		if err != nil {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		pending.deliver(strconv.Itoa(echo.Seq), time.Now())
	}
}

// pendingMap tracks in-flight probes keyed by sequence number.
type pendingMap struct {
	mu sync.Mutex
	m  map[string]chan time.Time
}

func newPendingMap() *pendingMap {
	return &pendingMap{m: make(map[string]chan time.Time)}
}

func (p *pendingMap) add(key string) {
	p.mu.Lock()
	p.m[key] = make(chan time.Time, 1)
	p.mu.Unlock()
}

func (p *pendingMap) wait(key string) <-chan time.Time {
	p.mu.Lock()
	ch, ok := p.m[key]
	p.mu.Unlock()
	if !ok {
		c := make(chan time.Time)
		close(c)
		return c
	}
	return ch
}

func (p *pendingMap) deliver(key string, ts time.Time) {
	p.mu.Lock()
	ch, ok := p.m[key]
	if ok {
		delete(p.m, key)
	}
	p.mu.Unlock()
	if ok {
		select {
		case ch <- ts:
		default:
		}
	}
}

func (p *pendingMap) remove(key string) {
	p.mu.Lock()
	delete(p.m, key)
	p.mu.Unlock()
}
