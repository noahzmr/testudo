package collectors

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/telemetry"
)

// TCPInfoCollector samples per-flow TCP quality (smoothed RTT, retransmit rate,
// cwnd) the userspace flow path can't cheaply get, and joins it onto the flow
// table by 5-tuple. It is the Stage-A, pure-Go backend (INET_DIAG / tcp_info);
// when the binary is built with -tags ebpf and the kernel supports it, the
// source tag flips to "ebpf" and the same join happens - no parallel table.
//
// Besides enrichment it raises two anomaly classes:
//   - a per-flow RTX-rate WARN when a single connection's retransmission rate
//     crosses the configured threshold (the "which connection is suffering"
//     signal), and
//   - a frag-needed / PMTU black-hole anomaly when a flow retransmits heavily
//     while making no forward progress - the classic "some sites won't load"
//     fault, raised here as a conservative pure-Go heuristic and authoritatively
//     by the eBPF drop-path tracepoint when that backend is active.
type TCPInfoCollector struct {
	Interval time.Duration
	Flows    *flows.Aggregator
	Settings *config.SettingsStore

	ebpf telemetry.EBPFInfo

	mu     sync.RWMutex
	status TCPInfoStatus

	prev     map[string]flowCounters // 5-tuple -> last cumulative counters
	cooldown map[string]time.Time    // 5-tuple -> next time an anomaly may fire
}

// flowCounters is the per-flow cumulative state kept between ticks to derive
// per-interval rates and forward-progress.
type flowCounters struct {
	totalRetrans uint32
	segsOut      uint32
	seen         time.Time
}

// TCPInfoStatus is the Health-tab status card for the telemetry source.
type TCPInfoStatus struct {
	Source        string             // active backend: inet_diag | ebpf
	EBPF          telemetry.EBPFInfo // build/runtime eBPF detection result
	Flows         int                // flows carrying TCP stats at the last sample
	WorstRTX      float64            // highest per-flow RTX rate observed (percent)
	WorstRTT      float64            // highest per-flow smoothed RTT (ms)
	PMTUBlackhole bool               // a flow shows the frag-needed / black-hole shape now
	LastErr       string             // last sample error, empty when healthy
	Updated       time.Time
}

func (c *TCPInfoCollector) Name() string { return "tcpinfo" }

// Status returns the current telemetry-source status for rendering.
func (c *TCPInfoCollector) Status() TCPInfoStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *TCPInfoCollector) Run(ctx context.Context, bus *events.Bus) error {
	if c.Interval <= 0 {
		c.Interval = 10 * time.Second
	}
	c.ebpf = telemetry.EBPFStatus()
	c.prev = map[string]flowCounters{}
	c.cooldown = map[string]time.Time{}

	c.sample(bus) // prime immediately so the first render has data
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.sample(bus)
		}
	}
}

// sample runs one collection pass: query the source, derive per-flow rates,
// join onto the flow table, and raise anomalies. Errors are recorded in the
// status card rather than returned - the collector is optional and degraded,
// never fatal.
func (c *TCPInfoCollector) sample(bus *events.Bus) {
	th := config.DefaultThresholds()
	if c.Settings != nil {
		th = c.Settings.Snapshot()
	}
	source := telemetry.SourceInetDiag
	if th.EBPFEnabled && c.ebpf.Available {
		source = telemetry.SourceEBPF
	}

	samples, err := telemetry.Query()
	now := time.Now()
	st := TCPInfoStatus{Source: source, EBPF: c.ebpf, Updated: now}
	if err != nil {
		st.LastErr = err.Error()
		c.mu.Lock()
		c.status = st
		c.mu.Unlock()
		return
	}

	live := make(map[string]struct{}, len(samples))
	for _, s := range samples {
		key := flowTupleKey(s)
		live[key] = struct{}{}

		prev := c.prev[key]
		rate := telemetry.RetransRate(
			uint64(prev.totalRetrans), uint64(prev.segsOut),
			uint64(s.TotalRetrans), uint64(s.SegsOut),
		)

		if c.Flows != nil {
			c.Flows.ApplyTCPStats(
				"", s.SrcIP, s.SrcPort, s.DstIP, s.DstPort, "tcp",
				flows.FlowTCPStats{
					RTTus:       s.RTTus,
					RTTVarus:    s.RTTVarus,
					Retrans:     s.TotalRetrans,
					RetransRate: rate,
					Cwnd:        s.Cwnd,
					Source:      source,
				},
			)
		}

		st.Flows++
		if rate > st.WorstRTX {
			st.WorstRTX = rate
		}
		if rttMs := float64(s.RTTus) / 1000.0; rttMs > st.WorstRTT {
			st.WorstRTT = rttMs
		}

		if c.detectAnomalies(bus, s, prev, rate, th, now) {
			st.PMTUBlackhole = true
		}
		c.prev[key] = flowCounters{totalRetrans: s.TotalRetrans, segsOut: s.SegsOut, seen: now}
	}

	// Drop prev state for flows that have gone away, bounding memory.
	for key := range c.prev {
		if _, ok := live[key]; !ok {
			delete(c.prev, key)
			delete(c.cooldown, key)
		}
	}

	c.mu.Lock()
	c.status = st
	c.mu.Unlock()
}

// detectAnomalies raises the per-flow RTX-rate WARN and the frag-needed / PMTU
// black-hole signal, each behind a per-flow cooldown so a persistent condition
// doesn't spam the Alerts tab. It returns true when this flow currently shows
// the PMTU black-hole shape (independent of the publish cooldown), so the
// status card and grade reflect the live condition.
func (c *TCPInfoCollector) detectAnomalies(bus *events.Bus, s telemetry.Sample, prev flowCounters, rate float64, th config.Thresholds, now time.Time) bool {
	thresh := th.FlowRetransPct
	if thresh <= 0 {
		thresh = 5
	}

	// PMTU black-hole heuristic: heavy retransmits with ~no new data segments
	// over the window means the connection is wedged - the frag-needed shape.
	dRetrans := int64(s.TotalRetrans) - int64(prev.totalRetrans)
	dSegs := int64(s.SegsOut) - int64(prev.segsOut)
	pmtu := !prev.seen.IsZero() && dRetrans >= 4 && dSegs <= dRetrans

	if bus == nil {
		return pmtu
	}
	key := flowTupleKey(s)
	if t, ok := c.cooldown[key]; ok && now.Before(t) {
		return pmtu
	}

	if pmtu {
		bus.Publish(events.Event{
			Kind: events.KindFragNeeded, Source: c.Name(), Time: now,
			Payload: events.FragNeededPayload{
				SrcIP: s.SrcIP, DstIP: s.DstIP, DstPort: s.DstPort, Suspect: true,
			},
		})
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(), Time: now,
			Payload: events.AnomalyPayload{
				Severity: string(events.SevWarn),
				Message: fmt.Sprintf("suspected PMTU black-hole: %s -> %s:%d retransmitting without progress (%d retx, no new data)",
					s.SrcIP, s.DstIP, s.DstPort, dRetrans),
			},
		})
		c.cooldown[key] = now.Add(5 * time.Minute)
		return true
	}

	if rate >= thresh {
		bus.Publish(events.Event{
			Kind: events.KindAnomaly, Source: c.Name(), Time: now,
			Payload: events.AnomalyPayload{
				Severity: string(events.SevWarn),
				Message: fmt.Sprintf("flow %s -> %s:%d RTX rate %.1f%% (>= %.1f%%), RTT %.0fms",
					s.SrcIP, s.DstIP, s.DstPort, rate, thresh, float64(s.RTTus)/1000.0),
			},
		})
		c.cooldown[key] = now.Add(2 * time.Minute)
	}
	return false
}

// flowTupleKey is the directional 5-tuple identity used to track per-flow
// cumulative counters between ticks.
func flowTupleKey(s telemetry.Sample) string {
	return fmt.Sprintf("%s:%d>%s:%d", s.SrcIP, s.SrcPort, s.DstIP, s.DstPort)
}
