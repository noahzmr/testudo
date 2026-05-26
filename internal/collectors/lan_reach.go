package collectors

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/noahzmr/testudo/internal/discovery"
	"github.com/noahzmr/testudo/internal/events"
)

// LANReachabilityCollector pings every device in the discovery
// inventory on a slow cadence. Unlike TopTalkersCollector (which
// requires capture and only probes the busiest hosts), this collector
// works off the inventory alone - so the operator gets reachability
// data for the whole known LAN even without flow capture running.
// One ICMP per device per Interval; with the default 60s and a typical
// home LAN this is well under 1 pps.
type LANReachabilityCollector struct {
	Inventory *discovery.Inventory
	Interval  time.Duration
	Timeout   time.Duration
}

func (c *LANReachabilityCollector) Name() string { return "lan-reach" }

func (c *LANReachabilityCollector) Run(ctx context.Context, bus *events.Bus) error {
	if c.Inventory == nil || c.Interval <= 0 {
		return nil
	}
	if c.Timeout <= 0 {
		c.Timeout = 2 * time.Second
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
		devices := c.Inventory.Snapshot()
		for _, d := range devices {
			if d.IP == "" {
				continue
			}
			addr, err := net.ResolveIPAddr("ip4", d.IP)
			if err != nil {
				continue
			}
			s := atomic.AddUint32(&seq, 1)
			seqKey := strconv.Itoa(int(s & 0xffff))
			start := time.Now()
			pending.add(seqKey)
			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho, Code: 0,
				Body: &icmp.Echo{ID: 4, Seq: int(s & 0xffff), Data: []byte("testudo-lan")},
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
			target := d.IP
			if d.Hostname != "" {
				target = d.Hostname
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
