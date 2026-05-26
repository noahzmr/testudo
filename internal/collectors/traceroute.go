package collectors

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/probes"
)

// TracerouteCollector traces each target on a slow cadence and emits:
//   - KindLatency per hop (Target = "trace:<dest>:hop<N>:<ip>")
//   - KindLatency end-to-end (Target = "trace:<dest>")
//   - KindAnomaly when the hop set changes (route flap) or a previously
//     responsive hop goes silent.
//
// Requires CAP_NET_RAW (the underlying probes.RunTraceroute opens a raw
// ICMP socket). On systems without it, Run returns early with a logged
// error from the probe layer.
type TracerouteCollector struct {
	Targets  []string
	Interval time.Duration
	MaxHops  int

	mu      sync.Mutex
	history map[string][]string // target -> last-known per-TTL hop IPs
}

func (c *TracerouteCollector) Name() string { return "traceroute" }

func (c *TracerouteCollector) Run(ctx context.Context, bus *events.Bus) error {
	if len(c.Targets) == 0 || c.Interval <= 0 {
		return nil
	}
	if c.MaxHops <= 0 {
		c.MaxHops = 16
	}
	c.history = map[string][]string{}
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	c.traceAll(ctx, bus)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.traceAll(ctx, bus)
		}
	}
}

func (c *TracerouteCollector) traceAll(ctx context.Context, bus *events.Bus) {
	var wg sync.WaitGroup
	for _, t := range c.Targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			c.traceOne(ctx, bus, t)
		}(t)
	}
	wg.Wait()
}

func (c *TracerouteCollector) traceOne(ctx context.Context, bus *events.Bus, target string) {
	res, err := probes.Run(ctx, probes.Request{
		Kind:    probes.KindTraceroute,
		Target:  target,
		Hops:    c.MaxHops,
		Timeout: 800 * time.Millisecond,
	})
	if err != nil || res == nil {
		return
	}
	if !res.OK {
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevWarn),
				Message:  fmt.Sprintf("traceroute %s failed: %s", target, res.Err),
			},
		})
		return
	}

	cur := make([]string, 0, len(res.Hops))
	for _, h := range res.Hops {
		cur = append(cur, h.IP)
		if h.IP != "" && h.IP != "*" && h.Latency > 0 {
			bus.Publish(events.Event{
				Kind: events.KindLatency, Source: c.Name(),
				Payload: events.LatencyPayload{
					Target: fmt.Sprintf("trace:%s:hop%d:%s", target, h.TTL, h.IP),
					RTT:    h.Latency,
				},
			})
		}
	}
	// End-to-end RTT = the final hop's RTT (when we reached the target).
	if last := lastValidHop(res.Hops); last != nil {
		bus.Publish(events.Event{
			Kind: events.KindLatency, Source: c.Name(),
			Payload: events.LatencyPayload{
				Target: "trace:" + target,
				RTT:    last.Latency,
			},
		})
	}

	c.mu.Lock()
	prev, seen := c.history[target]
	c.history[target] = cur
	c.mu.Unlock()
	if !seen {
		return
	}
	if diff := compareHops(prev, cur); diff != "" {
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevWarn),
				Message:  fmt.Sprintf("traceroute to %s changed: %s", target, diff),
			},
		})
	}
}

func lastValidHop(hops []probes.TraceHop) *probes.TraceHop {
	for i := len(hops) - 1; i >= 0; i-- {
		h := hops[i]
		if h.IP != "" && h.IP != "*" && h.Latency > 0 {
			return &h
		}
	}
	return nil
}

// compareHops returns a short human-readable summary of how cur differs
// from prev, or "" when they match. Mismatched-length paths are reported
// with a length delta so a short trace (failure to reach target) is
// flagged distinctly from a per-hop change.
func compareHops(prev, cur []string) string {
	if len(prev) != len(cur) {
		return fmt.Sprintf("path length %d -> %d", len(prev), len(cur))
	}
	var diffs []string
	for i := range prev {
		if prev[i] != cur[i] {
			diffs = append(diffs, fmt.Sprintf("hop%d %s -> %s", i+1, prev[i], cur[i]))
		}
	}
	return strings.Join(diffs, "; ")
}
