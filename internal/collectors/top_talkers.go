package collectors

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/flows"
)

// ephemeralPortFloor is the start of the Linux ephemeral range. Ports at
// or above this are assumed to be client-side (caller) and ignored when
// guessing a remote host's listening service port.
const ephemeralPortFloor uint16 = 49152

// TopTalkersCollector picks the busiest internal (RFC1918 / link-local)
// hosts from the live flow table and pings them so the operator gets
// latency/loss numbers for the hosts they actually care about, without
// having to list them in ICMPTargets manually. The probe set is capped
// at MaxHosts to keep this from amplifying load on already-busy peers.
//
// Targets are re-selected on every tick - if traffic shifts, the prober
// follows it. Hosts whose traffic stops appearing in the flow table
// simply drop out of the rotation.
type TopTalkersCollector struct {
	Flows    *flows.Aggregator
	Interval time.Duration
	Timeout  time.Duration
	MaxHosts int
}

func (c *TopTalkersCollector) Name() string { return "top-talkers" }

func (c *TopTalkersCollector) Run(ctx context.Context, bus *events.Bus) error {
	if c.Flows == nil || c.MaxHosts <= 0 || c.Interval <= 0 {
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
		snap := c.Flows.Snapshot()
		if len(snap) == 0 {
			return
		}
		// Ask TopHosts for headroom so we can skip non-LAN entries and
		// still fill MaxHosts when the talkers list mixes internal and
		// external peers.
		ranked := flows.TopHosts(snap, c.MaxHosts*4)
		picked := 0
		for _, h := range ranked {
			if picked >= c.MaxHosts {
				break
			}
			if !h.IsLAN {
				continue
			}
			// h.Host can be a DNS name (when a reverse lookup landed) -
			// resolve so we send to the IP and report the friendly name.
			target := h.Host
			addr, err := net.ResolveIPAddr("ip4", target)
			if err != nil {
				continue
			}
			picked++

			s := atomic.AddUint32(&seq, 1)
			seqKey := strconv.Itoa(int(s & 0xffff))
			start := time.Now()
			pending.add(seqKey)

			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho, Code: 0,
				Body: &icmp.Echo{
					ID:   2,
					Seq:  int(s & 0xffff),
					Data: []byte("testudo-tt"),
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

			// TCP service probe alongside ICMP: a host that pings but
			// won't accept its busiest service port is the failure mode
			// ICMP alone misses.
			if port := hostServicePort(snap, addr.IP.String()); port != 0 {
				go c.tcpProbe(ctx, bus, target, addr.IP.String(), port)
			}
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

// tcpProbe runs a single TCP connect to ip:port with the collector's
// timeout and publishes a latency event (success) or a packet-loss event
// (failure). The connection is closed immediately - we measure the
// handshake, not throughput, so a successful dial proves the service is
// accepting connections right now.
func (c *TopTalkersCollector) tcpProbe(ctx context.Context, bus *events.Bus, target, ip string, port uint16) {
	addr := net.JoinHostPort(ip, strconv.Itoa(int(port)))
	label := net.JoinHostPort(target, strconv.Itoa(int(port)))
	dialer := net.Dialer{Timeout: c.Timeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	rtt := time.Since(start)
	if err != nil {
		bus.Publish(events.Event{
			Kind: events.KindPacketLoss, Source: c.Name(),
			Payload: events.PacketLossPayload{Target: label, Sent: 1, Lost: 1, LossPct: 100},
		})
		return
	}
	_ = conn.Close()
	bus.Publish(events.Event{
		Kind: events.KindLatency, Source: c.Name(),
		Payload: events.LatencyPayload{Target: label, RTT: rtt},
	})
}

// hostServicePort picks the busiest non-ephemeral port observed on
// hostIP in snap, treating that as the host's listening service. Ports
// >= ephemeralPortFloor are assumed to be client-side and ignored.
// Returns 0 when no candidate is found.
func hostServicePort(snap []flows.FlowStats, hostIP string) uint16 {
	candidates := map[uint16]uint64{}
	for _, f := range snap {
		var port uint16
		switch hostIP {
		case f.Key.A.IP:
			port = f.Key.A.Port
		case f.Key.B.IP:
			port = f.Key.B.Port
		default:
			continue
		}
		if port == 0 || port >= ephemeralPortFloor {
			continue
		}
		candidates[port] += f.Bytes
	}
	var bestPort uint16
	var bestBytes uint64
	for p, b := range candidates {
		if b > bestBytes {
			bestPort = p
			bestBytes = b
		}
	}
	return bestPort
}
