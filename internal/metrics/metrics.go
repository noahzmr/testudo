// Package metrics maintains rolling per-target counters consumed by the TUI
// and persisted by the storage engine. Operations are safe for concurrent use.
package metrics

import (
	"math"
	"sort"
	"sync"
	"time"
)

// TargetStats summarises latency and loss for a single probe target.
type TargetStats struct {
	Target     string
	Sent       int
	Lost       int
	LossPct    float64
	LastRTT    time.Duration
	MinRTT     time.Duration
	MaxRTT     time.Duration
	AvgRTT     time.Duration
	P50RTT     time.Duration
	P95RTT     time.Duration
	P99RTT     time.Duration
	JitterMs   float64
	UpdatedAt  time.Time
	rttSamples []time.Duration // bounded ring; newest at the end
}

// DNSStats summarises resolver health for a single name.
type DNSStats struct {
	Name        string
	Queries     int
	Failures    int
	LastLatency time.Duration
	AvgLatency  time.Duration
	UpdatedAt   time.Time
	durations   []time.Duration
}

// Aggregator is the in-memory mirror of recent measurements. The TUI reads
// snapshots; storage flushes raw samples. Aggregator does not persist.
type Aggregator struct {
	mu      sync.RWMutex
	targets map[string]*TargetStats
	dns     map[string]*DNSStats
	maxKeep int // per-key sample cap, bounds memory
}

func NewAggregator() *Aggregator {
	return &Aggregator{
		targets: make(map[string]*TargetStats),
		dns:     make(map[string]*DNSStats),
		maxKeep: 256,
	}
}

// RecordLatency stores a successful RTT sample for target.
func (a *Aggregator) RecordLatency(target string, rtt time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	t := a.touchTarget(target)
	t.Sent++
	t.LastRTT = rtt
	t.rttSamples = appendBounded(t.rttSamples, rtt, a.maxKeep)
	t.recompute()
	t.UpdatedAt = time.Now()
}

// RecordLoss increments the loss counter for target.
func (a *Aggregator) RecordLoss(target string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	t := a.touchTarget(target)
	t.Sent++
	t.Lost++
	t.LossPct = percent(t.Lost, t.Sent)
	t.UpdatedAt = time.Now()
}

// RecordDNS stores a resolver outcome for name.
func (a *Aggregator) RecordDNS(name string, d time.Duration, failed bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.dns[name]
	if !ok {
		s = &DNSStats{Name: name}
		a.dns[name] = s
	}
	s.Queries++
	s.LastLatency = d
	s.UpdatedAt = time.Now()
	if failed {
		s.Failures++
		return
	}
	s.durations = appendBounded(s.durations, d, a.maxKeep)
	if len(s.durations) > 0 {
		var total time.Duration
		for _, v := range s.durations {
			total += v
		}
		s.AvgLatency = total / time.Duration(len(s.durations))
	}
}

// SnapshotTargets returns a sorted, defensively-copied view safe to render.
func (a *Aggregator) SnapshotTargets() []TargetStats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]TargetStats, 0, len(a.targets))
	for _, t := range a.targets {
		// Copy without the sample slice; rendering doesn't need it.
		c := *t
		c.rttSamples = nil
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

// SnapshotDNS returns a sorted, defensively-copied view safe to render.
func (a *Aggregator) SnapshotDNS() []DNSStats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]DNSStats, 0, len(a.dns))
	for _, s := range a.dns {
		c := *s
		c.durations = nil
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LatencySamples returns a defensive copy of the rolling RTT samples for
// the named target, oldest-first. Empty slice when the target is unknown.
// Used by the dashboard sparkline.
func (a *Aggregator) LatencySamples(target string) []time.Duration {
	a.mu.RLock()
	defer a.mu.RUnlock()
	t, ok := a.targets[target]
	if !ok {
		return nil
	}
	out := make([]time.Duration, len(t.rttSamples))
	copy(out, t.rttSamples)
	return out
}

// DNSSamples returns a defensive copy of the rolling DNS resolution-time
// samples for the named query, oldest-first.
func (a *Aggregator) DNSSamples(name string) []time.Duration {
	a.mu.RLock()
	defer a.mu.RUnlock()
	s, ok := a.dns[name]
	if !ok {
		return nil
	}
	out := make([]time.Duration, len(s.durations))
	copy(out, s.durations)
	return out
}

func (a *Aggregator) touchTarget(target string) *TargetStats {
	t, ok := a.targets[target]
	if !ok {
		t = &TargetStats{Target: target}
		a.targets[target] = t
	}
	return t
}

func (t *TargetStats) recompute() {
	if len(t.rttSamples) == 0 {
		return
	}
	t.MinRTT = t.rttSamples[0]
	t.MaxRTT = t.rttSamples[0]
	var sum time.Duration
	for _, v := range t.rttSamples {
		if v < t.MinRTT {
			t.MinRTT = v
		}
		if v > t.MaxRTT {
			t.MaxRTT = v
		}
		sum += v
	}
	t.AvgRTT = sum / time.Duration(len(t.rttSamples))
	t.LossPct = percent(t.Lost, t.Sent)
	t.P50RTT = percentile(t.rttSamples, 0.50)
	t.P95RTT = percentile(t.rttSamples, 0.95)
	t.P99RTT = percentile(t.rttSamples, 0.99)
	t.JitterMs = jitterMs(t.rttSamples)
}

func percent(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return (float64(part) / float64(total)) * 100
}

func appendBounded[T any](buf []T, v T, max int) []T {
	if max <= 0 {
		return append(buf, v)
	}
	if len(buf) >= max {
		buf = buf[1:]
	}
	return append(buf, v)
}

func percentile(samples []time.Duration, p float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

// jitterMs returns mean absolute RTT deviation between consecutive samples.
func jitterMs(samples []time.Duration) float64 {
	if len(samples) < 2 {
		return 0
	}
	var sum float64
	for i := 1; i < len(samples); i++ {
		diff := samples[i] - samples[i-1]
		if diff < 0 {
			diff = -diff
		}
		sum += float64(diff.Microseconds()) / 1000.0
	}
	return sum / float64(len(samples)-1)
}
