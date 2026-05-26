package collectors

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/probes"
)

// BufferbloatCollector measures the RTT delta between idle and saturated
// states - the classic flent/dslreports test, condensed. It pings the
// target for a few seconds idle, takes a baseline median RTT, then runs
// an HTTP throughput download while pinging the same target, and
// computes loaded - idle.
//
// This is invasive (it saturates the link for Duration) and so the
// default is disabled. Cadence is hours, not seconds.
//
// Severity:
//   < 30 ms   silent
//   30-100ms  INFO  ("mild bufferbloat")
//   100-300ms WARN  ("significant bufferbloat")
//   >= 300ms  ERROR ("severe bufferbloat - VoIP/gaming will suffer")
type BufferbloatCollector struct {
	Target   string        // ping target (during both phases)
	LoadURL  string        // download URL; empty = cloudflare default
	Interval time.Duration // gap between runs (hours)
	Duration time.Duration // length of the loaded phase
	Timeout  time.Duration // per-ping deadline
}

func (c *BufferbloatCollector) Name() string { return "bufferbloat" }

func (c *BufferbloatCollector) Run(ctx context.Context, bus *events.Bus) error {
	if c.Target == "" || c.Interval <= 0 {
		return nil
	}
	if c.Duration <= 0 {
		c.Duration = 10 * time.Second
	}
	if c.Timeout <= 0 {
		c.Timeout = 2 * time.Second
	}
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	c.runOnce(ctx, bus)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.runOnce(ctx, bus)
		}
	}
}

func (c *BufferbloatCollector) runOnce(ctx context.Context, bus *events.Bus) {
	idleSamples := c.pingFor(ctx, 3*time.Second)
	if len(idleSamples) == 0 {
		return
	}
	idleMed := median(idleSamples)

	// Saturate + measure concurrently.
	loadCtx, cancel := context.WithTimeout(ctx, c.Duration)
	defer cancel()
	var wg sync.WaitGroup
	var loadedSamples []time.Duration
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Discard the throughput Result - we only care about the side
		// effect (link saturation). probes.Run uses a sane default URL
		// when c.LoadURL is empty.
		_, _ = probes.Run(loadCtx, probes.Request{
			Kind:    probes.KindThroughput,
			Target:  c.LoadURL,
			Bytes:   100_000_000,
			Timeout: c.Duration,
		})
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		loadedSamples = c.pingFor(loadCtx, c.Duration)
	}()
	wg.Wait()

	if len(loadedSamples) == 0 {
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(),
			Payload: events.AnomalyPayload{
				Severity: string(events.SevWarn),
				Message:  fmt.Sprintf("bufferbloat: no loaded samples to %s", c.Target),
			},
		})
		return
	}
	loadedMed := median(loadedSamples)
	delta := loadedMed - idleMed

	bus.Publish(events.Event{
		Kind: events.KindLatency, Source: c.Name(),
		Payload: events.LatencyPayload{
			Target: "bufferbloat:idle:" + c.Target,
			RTT:    idleMed,
		},
	})
	bus.Publish(events.Event{
		Kind: events.KindLatency, Source: c.Name(),
		Payload: events.LatencyPayload{
			Target: "bufferbloat:loaded:" + c.Target,
			RTT:    loadedMed,
		},
	})

	var sev events.Severity
	switch {
	case delta >= 300*time.Millisecond:
		sev = events.SevError
	case delta >= 100*time.Millisecond:
		sev = events.SevWarn
	case delta >= 30*time.Millisecond:
		sev = events.SevInfo
	default:
		return // no bufferbloat worth flagging
	}
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: c.Name(),
		Payload: events.AnomalyPayload{
			Severity: string(sev),
			Message: fmt.Sprintf("bufferbloat: idle=%s loaded=%s delta=%s (target=%s)",
				idleMed.Truncate(time.Millisecond),
				loadedMed.Truncate(time.Millisecond),
				delta.Truncate(time.Millisecond),
				c.Target),
		},
	})
}

// pingFor sends back-to-back ICMP echoes to c.Target for `dur` and
// returns the collected RTTs. Stops early on ctx cancel.
func (c *BufferbloatCollector) pingFor(ctx context.Context, dur time.Duration) []time.Duration {
	deadline := time.Now().Add(dur)
	conn, network, err := listenICMP()
	if err != nil {
		return nil
	}
	defer conn.Close()
	pending := newPendingMap()
	go readLoop(ctx, conn, pending)

	addr, err := net.ResolveIPAddr("ip4", c.Target)
	if err != nil {
		return nil
	}
	var dst net.Addr = &net.IPAddr{IP: addr.IP}
	if network == "udp4" {
		dst = &net.UDPAddr{IP: addr.IP}
	}
	var (
		samples []time.Duration
		seq     uint32
	)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			break
		}
		seq++
		seqKey := strconv.Itoa(int(seq & 0xffff))
		start := time.Now()
		pending.add(seqKey)
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{ID: 3, Seq: int(seq & 0xffff), Data: []byte("testudo-bb")},
		}
		b, err := msg.Marshal(nil)
		if err != nil {
			pending.remove(seqKey)
			continue
		}
		if _, err := conn.WriteTo(b, dst); err != nil {
			pending.remove(seqKey)
			continue
		}
		select {
		case reply := <-pending.wait(seqKey):
			samples = append(samples, reply.Sub(start))
		case <-time.After(c.Timeout):
			pending.remove(seqKey)
		case <-ctx.Done():
			pending.remove(seqKey)
			return samples
		}
		// Roughly 5pps - enough to characterise RTT without being its own
		// load source.
		time.Sleep(200 * time.Millisecond)
	}
	return samples
}

func median(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	cp := make([]time.Duration, len(d))
	copy(cp, d)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return cp[len(cp)/2]
}
