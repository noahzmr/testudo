package collectors

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/netops"
)

// IfaceHealthCollector polls every interface on Interval and emits an
// anomaly when:
//   - link state transitions (UP<->DOWN, RUNNING<->NOT)
//   - RX/TX error counters grow between samples
//   - RX/TX drop counters grow between samples
//   - the collision counter grows between samples
//
// The first sample seeds the baseline; no events are fired for the
// initial read. Loopback is skipped since its counters aren't useful
// indicators of stability.
type IfaceHealthCollector struct {
	Netops   *netops.Writer
	Interval time.Duration
	// ErrorThreshold is the per-tick delta below which counter growth is
	// ignored. 0 means alert on any non-zero delta.
	ErrorThreshold uint64
}

func (c *IfaceHealthCollector) Name() string { return "iface-health" }

type ifaceHealthSnap struct {
	up         bool
	running    bool
	rxErrors   uint64
	txErrors   uint64
	rxDropped  uint64
	txDropped  uint64
	collisions uint64
}

func (c *IfaceHealthCollector) Run(ctx context.Context, bus *events.Bus) error {
	if c.Netops == nil || c.Interval <= 0 {
		return nil
	}
	prev := map[string]ifaceHealthSnap{}
	sample := func() map[string]ifaceHealthSnap {
		out := map[string]ifaceHealthSnap{}
		ifs, err := c.Netops.ListIfaces()
		if err != nil {
			return out
		}
		for _, ifi := range ifs {
			if strings.EqualFold(ifi.Name, "lo") {
				continue
			}
			out[ifi.Name] = ifaceHealthSnap{
				up: ifi.Up, running: ifi.Running,
				rxErrors: ifi.RxErrors, txErrors: ifi.TxErrors,
				rxDropped: ifi.RxDropped, txDropped: ifi.TxDropped,
				collisions: ifi.Collisions,
			}
		}
		return out
	}
	prev = sample()

	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			cur := sample()
			for name, c2 := range cur {
				p, seen := prev[name]
				if !seen {
					// Newly-appeared interface (hotplug, VPN up). Skip
					// alerting this tick and let it baseline.
					continue
				}
				c.compare(bus, name, p, c2)
			}
			prev = cur
		}
	}
}

func (c *IfaceHealthCollector) compare(bus *events.Bus, name string, prev, cur ifaceHealthSnap) {
	if prev.up != cur.up || prev.running != cur.running {
		sev := events.SevWarn
		if !cur.up || !cur.running {
			sev = events.SevError
		}
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(sev),
				Message: fmt.Sprintf("%s link changed: up=%t running=%t",
					name, cur.up, cur.running),
			},
		})
	}
	dErr := delta(cur.rxErrors, prev.rxErrors) + delta(cur.txErrors, prev.txErrors)
	if dErr > c.ErrorThreshold {
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevWarn),
				Message: fmt.Sprintf("%s errors growing: +%d rx, +%d tx",
					name, delta(cur.rxErrors, prev.rxErrors), delta(cur.txErrors, prev.txErrors)),
			},
		})
	}
	dDrop := delta(cur.rxDropped, prev.rxDropped) + delta(cur.txDropped, prev.txDropped)
	if dDrop > c.ErrorThreshold {
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevWarn),
				Message: fmt.Sprintf("%s drops growing: +%d rx, +%d tx",
					name, delta(cur.rxDropped, prev.rxDropped), delta(cur.txDropped, prev.txDropped)),
			},
		})
	}
	if dColl := delta(cur.collisions, prev.collisions); dColl > c.ErrorThreshold {
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevInfo),
				Message:  fmt.Sprintf("%s collisions growing: +%d", name, dColl),
			},
		})
	}
}

// delta returns cur-prev, clamped to 0 so a counter reset (link bounce,
// driver reload) doesn't produce a spurious massive delta.
func delta(cur, prev uint64) uint64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}
