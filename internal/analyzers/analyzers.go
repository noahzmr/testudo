// Package analyzers consumes events and emits AnomalyEvents on the bus.
// Detectors come in two flavours:
//
//   - threshold detectors fire on a single metric crossing a configured
//     ceiling (default thresholds from CLAUDE.md);
//   - pattern detectors fire on rolling-window aggregates that catch
//     degradations a single sample wouldn't.
//
// All detectors read their thresholds live from config.SettingsStore so
// the Settings TUI can tune them without restart.
package analyzers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/events"
)

// Analyzer is the unit of correlation. Run blocks until ctx ends.
type Analyzer interface {
	Name() string
	Run(ctx context.Context, in <-chan events.Event, bus *events.Bus) error
}

// escalate maps a value vs threshold to a 4-level severity. Multipliers of
// 1×/2×/4× are conservative defaults that give operators headroom before
// pages escalate to CRITICAL.
func escalate(value, threshold float64) events.Severity {
	switch {
	case value >= 4*threshold:
		return events.SevCritical
	case value >= 2*threshold:
		return events.SevError
	case value >= threshold:
		return events.SevWarn
	default:
		return events.SevInfo
	}
}

// HighRTTDetector - threshold detector: any single RTT > Thresholds.RTTMs.
type HighRTTDetector struct {
	Settings *config.SettingsStore
	CoolDown time.Duration

	mu        sync.Mutex
	lastFired map[string]time.Time
}

func (d *HighRTTDetector) Name() string { return "high_rtt" }

func (d *HighRTTDetector) Run(ctx context.Context, in <-chan events.Event, bus *events.Bus) error {
	d.lastFired = make(map[string]time.Time)
	if d.CoolDown <= 0 {
		d.CoolDown = 20 * time.Second
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-in:
			if !ok {
				return nil
			}
			if ev.Kind != events.KindLatency {
				continue
			}
			p, ok := ev.Payload.(events.LatencyPayload)
			if !ok {
				continue
			}
			thresh := d.Settings.Snapshot().RTTMs
			rttMs := float64(p.RTT.Microseconds()) / 1000.0
			if rttMs < thresh {
				continue
			}
			d.mu.Lock()
			last := d.lastFired[p.Target]
			if !last.IsZero() && time.Since(last) < d.CoolDown {
				d.mu.Unlock()
				continue
			}
			d.lastFired[p.Target] = time.Now()
			d.mu.Unlock()
			bus.Publish(events.Event{
				Kind: events.KindAnomaly, Source: d.Name(),
				Payload: events.AnomalyPayload{
					Severity: string(escalate(rttMs, thresh)),
					Message: fmt.Sprintf(
						"high RTT on %s: %.1fms (threshold %.0fms)",
						p.Target, rttMs, thresh,
					),
				},
			})
		}
	}
}

// HighDNSLatencyDetector fires when a single DNS query exceeds the
// configured threshold. Matches CLAUDE.md "DNS Latency 120ms" default.
type HighDNSLatencyDetector struct {
	Settings *config.SettingsStore
	CoolDown time.Duration

	mu        sync.Mutex
	lastFired map[string]time.Time
}

func (d *HighDNSLatencyDetector) Name() string { return "high_dns_latency" }

func (d *HighDNSLatencyDetector) Run(ctx context.Context, in <-chan events.Event, bus *events.Bus) error {
	d.lastFired = make(map[string]time.Time)
	if d.CoolDown <= 0 {
		d.CoolDown = 20 * time.Second
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-in:
			if !ok {
				return nil
			}
			var name string
			var ms float64
			switch p := ev.Payload.(type) {
			case events.DNSResultPayload:
				name, ms = p.Name, float64(p.Duration.Microseconds())/1000.0
			case events.DNSFailurePayload:
				name, ms = p.Name, float64(p.Duration.Microseconds())/1000.0
			default:
				continue
			}
			thresh := d.Settings.Snapshot().DNSLatencyMs
			if ms < thresh {
				continue
			}
			d.mu.Lock()
			last := d.lastFired[name]
			if !last.IsZero() && time.Since(last) < d.CoolDown {
				d.mu.Unlock()
				continue
			}
			d.lastFired[name] = time.Now()
			d.mu.Unlock()
			bus.Publish(events.Event{
				Kind: events.KindAnomaly, Source: d.Name(),
				Payload: events.AnomalyPayload{
					Severity: string(escalate(ms, thresh)),
					Message: fmt.Sprintf(
						"slow DNS for %s: %.1fms (threshold %.0fms)",
						name, ms, thresh,
					),
				},
			})
		}
	}
}

// PacketLossDetector emits when rolling loss exceeds Settings.PacketLossPct.
// Window is fixed at 20 - small enough to react quickly, large enough that
// a single missed probe doesn't fire on a 5% threshold.
type PacketLossDetector struct {
	Settings *config.SettingsStore
	Window   int
	CoolDown time.Duration

	mu        sync.Mutex
	rings     map[string]*lossRing
	lastFired map[string]time.Time
	init      bool
}

func (d *PacketLossDetector) Name() string { return "packet_loss" }

func (d *PacketLossDetector) lazyInit() {
	if d.init {
		return
	}
	if d.Window <= 0 {
		d.Window = 20
	}
	if d.CoolDown <= 0 {
		d.CoolDown = 30 * time.Second
	}
	d.rings = make(map[string]*lossRing)
	d.lastFired = make(map[string]time.Time)
	d.init = true
}

func (d *PacketLossDetector) Run(ctx context.Context, in <-chan events.Event, bus *events.Bus) error {
	d.lazyInit()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-in:
			if !ok {
				return nil
			}
			switch ev.Kind {
			case events.KindLatency:
				if p, ok := ev.Payload.(events.LatencyPayload); ok {
					d.record(p.Target, false, bus)
				}
			case events.KindPacketLoss:
				if p, ok := ev.Payload.(events.PacketLossPayload); ok {
					d.record(p.Target, true, bus)
				}
			}
		}
	}
}

func (d *PacketLossDetector) record(target string, lost bool, bus *events.Bus) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.rings[target]
	if !ok {
		r = newLossRing(d.Window)
		d.rings[target] = r
	}
	r.push(lost)
	if r.count < d.Window {
		return
	}
	lossPct := r.lossRate() * 100
	thresh := d.Settings.Snapshot().PacketLossPct
	if lossPct < thresh {
		return
	}
	last := d.lastFired[target]
	if !last.IsZero() && time.Since(last) < d.CoolDown {
		return
	}
	d.lastFired[target] = time.Now()
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: d.Name(),
		Payload: events.AnomalyPayload{
			Severity: string(escalate(lossPct, thresh)),
			Message: fmt.Sprintf(
				"packet loss on %s: %.1f%% over last %d probes (threshold %.1f%%)",
				target, lossPct, d.Window, thresh,
			),
		},
	})
}

// LatencySpikeDetector fires when current RTT >> rolling baseline. This is
// the "burst" complement to the absolute-threshold HighRTTDetector - useful
// on low-latency links where 30ms is already a big deal even if it never
// crosses the 150ms ceiling.
type LatencySpikeDetector struct {
	Settings *config.SettingsStore
	Window   int
	Factor   float64
	CoolDown time.Duration

	mu        sync.Mutex
	samples   map[string][]time.Duration
	lastFired map[string]time.Time
	init      bool
}

func (d *LatencySpikeDetector) Name() string { return "latency_spike" }

func (d *LatencySpikeDetector) lazyInit() {
	if d.init {
		return
	}
	if d.Window <= 0 {
		d.Window = 30
	}
	if d.Factor <= 0 {
		d.Factor = 3.0
	}
	if d.CoolDown <= 0 {
		d.CoolDown = 20 * time.Second
	}
	d.samples = make(map[string][]time.Duration)
	d.lastFired = make(map[string]time.Time)
	d.init = true
}

func (d *LatencySpikeDetector) Run(ctx context.Context, in <-chan events.Event, bus *events.Bus) error {
	d.lazyInit()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-in:
			if !ok {
				return nil
			}
			if ev.Kind != events.KindLatency {
				continue
			}
			p, ok := ev.Payload.(events.LatencyPayload)
			if !ok {
				continue
			}
			d.record(p.Target, p.RTT, bus)
		}
	}
}

func (d *LatencySpikeDetector) record(target string, rtt time.Duration, bus *events.Bus) {
	d.mu.Lock()
	defer d.mu.Unlock()
	buf := d.samples[target]
	if len(buf) >= d.Window {
		var sum time.Duration
		for _, v := range buf {
			sum += v
		}
		avg := sum / time.Duration(len(buf))
		if avg > 0 && float64(rtt) > d.Factor*float64(avg) {
			last := d.lastFired[target]
			if last.IsZero() || time.Since(last) >= d.CoolDown {
				d.lastFired[target] = time.Now()
				bus.Publish(events.Event{
					Kind: events.KindAnomaly, Source: d.Name(),
					Payload: events.AnomalyPayload{
						Severity: string(events.SevWarn),
						Message: fmt.Sprintf(
							"latency spike on %s: %.1fms (baseline %.1fms, %.1f× factor)",
							target,
							float64(rtt.Microseconds())/1000.0,
							float64(avg.Microseconds())/1000.0,
							d.Factor,
						),
					},
				})
			}
		}
	}
	buf = append(buf, rtt)
	if len(buf) > d.Window {
		buf = buf[1:]
	}
	d.samples[target] = buf
}

// JitterSpikeDetector flags sustained high RTT variance against Settings.JitterMs.
type JitterSpikeDetector struct {
	Settings *config.SettingsStore
	Window   int
	CoolDown time.Duration

	mu        sync.Mutex
	samples   map[string][]time.Duration
	lastFired map[string]time.Time
	init      bool
}

func (d *JitterSpikeDetector) Name() string { return "jitter_spike" }

func (d *JitterSpikeDetector) lazyInit() {
	if d.init {
		return
	}
	if d.Window <= 0 {
		d.Window = 20
	}
	if d.CoolDown <= 0 {
		d.CoolDown = 60 * time.Second
	}
	d.samples = make(map[string][]time.Duration)
	d.lastFired = make(map[string]time.Time)
	d.init = true
}

func (d *JitterSpikeDetector) Run(ctx context.Context, in <-chan events.Event, bus *events.Bus) error {
	d.lazyInit()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-in:
			if !ok {
				return nil
			}
			if ev.Kind != events.KindLatency {
				continue
			}
			p, ok := ev.Payload.(events.LatencyPayload)
			if !ok {
				continue
			}
			d.record(p.Target, p.RTT, bus)
		}
	}
}

func (d *JitterSpikeDetector) record(target string, rtt time.Duration, bus *events.Bus) {
	d.mu.Lock()
	defer d.mu.Unlock()
	buf := append(d.samples[target], rtt)
	if len(buf) > d.Window {
		buf = buf[1:]
	}
	d.samples[target] = buf
	if len(buf) < d.Window {
		return
	}
	var sumDiffMs float64
	for i := 1; i < len(buf); i++ {
		diff := buf[i] - buf[i-1]
		if diff < 0 {
			diff = -diff
		}
		sumDiffMs += float64(diff.Microseconds()) / 1000.0
	}
	avgJitter := sumDiffMs / float64(len(buf)-1)
	thresh := d.Settings.Snapshot().JitterMs
	if avgJitter < thresh {
		return
	}
	last := d.lastFired[target]
	if !last.IsZero() && time.Since(last) < d.CoolDown {
		return
	}
	d.lastFired[target] = time.Now()
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: d.Name(),
		Payload: events.AnomalyPayload{
			Severity: string(escalate(avgJitter, thresh)),
			Message: fmt.Sprintf(
				"jitter spike on %s: %.1fms avg over last %d probes (threshold %.0fms)",
				target, avgJitter, d.Window, thresh,
			),
		},
	})
}

// DNSBurstDetector - DNS failure rate complement to the latency detector.
// Kept at a fixed 30% threshold because failure-rate isn't in the settings
// table; the spec lists latency, not error-rate, as the DNS gauge.
type DNSBurstDetector struct {
	Window    int
	Threshold float64
	CoolDown  time.Duration

	mu        sync.Mutex
	rings     map[string]*lossRing
	lastFired map[string]time.Time
	init      bool
}

func (d *DNSBurstDetector) Name() string { return "dns_burst" }

func (d *DNSBurstDetector) lazyInit() {
	if d.init {
		return
	}
	if d.Window <= 0 {
		d.Window = 10
	}
	if d.Threshold <= 0 {
		d.Threshold = 0.30
	}
	if d.CoolDown <= 0 {
		d.CoolDown = 30 * time.Second
	}
	d.rings = make(map[string]*lossRing)
	d.lastFired = make(map[string]time.Time)
	d.init = true
}

func (d *DNSBurstDetector) Run(ctx context.Context, in <-chan events.Event, bus *events.Bus) error {
	d.lazyInit()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-in:
			if !ok {
				return nil
			}
			switch ev.Kind {
			case events.KindDNSResult:
				if p, ok := ev.Payload.(events.DNSResultPayload); ok {
					d.record(p.Name, false, bus)
				}
			case events.KindDNSFailure:
				if p, ok := ev.Payload.(events.DNSFailurePayload); ok {
					d.record(p.Name, true, bus)
				}
			}
		}
	}
}

func (d *DNSBurstDetector) record(name string, failed bool, bus *events.Bus) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.rings[name]
	if !ok {
		r = newLossRing(d.Window)
		d.rings[name] = r
	}
	r.push(failed)
	if r.count < d.Window {
		return
	}
	rate := r.lossRate()
	if rate < d.Threshold {
		return
	}
	last := d.lastFired[name]
	if !last.IsZero() && time.Since(last) < d.CoolDown {
		return
	}
	d.lastFired[name] = time.Now()
	sev := events.SevWarn
	if rate >= 0.7 {
		sev = events.SevError
	}
	if rate >= 0.95 {
		sev = events.SevCritical
	}
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: d.Name(),
		Payload: events.AnomalyPayload{
			Severity: string(sev),
			Message: fmt.Sprintf(
				"DNS failure burst for %s: %.0f%% over last %d queries",
				name, rate*100, d.Window,
			),
		},
	})
}

// lossRing is a fixed-size circular buffer of bool loss markers.
type lossRing struct {
	buf   []bool
	head  int
	count int
}

func newLossRing(size int) *lossRing {
	return &lossRing{buf: make([]bool, size)}
}

func (r *lossRing) push(lost bool) {
	r.buf[r.head] = lost
	r.head = (r.head + 1) % len(r.buf)
	if r.count < len(r.buf) {
		r.count++
	}
}

func (r *lossRing) lossRate() float64 {
	if r.count == 0 {
		return 0
	}
	lost := 0
	for i := 0; i < r.count; i++ {
		if r.buf[i] {
			lost++
		}
	}
	return float64(lost) / float64(r.count)
}
