package engine

import (
	"context"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/probes"
	"github.com/noahzmr/testudo/internal/quality"
	"github.com/noahzmr/testudo/internal/storage"
)

// rollupAlpha is the EMA weight of each fresh observation folded into a baseline
// bucket: small enough that a single bad night barely moves the learned normal,
// but recent weeks still dominate over months-old data.
const rollupAlpha = 0.15

// rollupInterval is how often the live window is folded into the (dow, hour)
// baseline. Several merges per hour keep the bucket fresh without thrashing.
const rollupInterval = 5 * time.Minute

// flowSnapshotInterval controls the timestamped flow_snapshots cadence.
const flowSnapshotInterval = 60 * time.Second

// QualitySnapshot bundles the baseline-relative context the dashboards render
// and the grade consumes. It is cheap to build (cached baselines + a scan of
// the live aggregator) so both UIs can request it on every refresh.
type QualitySnapshot struct {
	// Baselines is the current (dow, hour) baseline row per real target. Absent
	// targets simply have no learned normal yet → neutral.
	Baselines map[string]quality.Rollup
	// Bufferbloat: idle-vs-loaded RTT delta and its A–F letter. HasBufferbloat
	// is false until the collector has produced an idle/loaded pair.
	BufferbloatDelta time.Duration
	BufferbloatGrade string
	HasBufferbloat   bool
	// Fault isolation verdict over the primary traceroute path.
	FaultLayer   quality.FaultLayer
	FaultVerdict string
	HasFault     bool
}

// QualitySnapshot returns the live baseline-relative context. Safe for the
// render path: reads the in-memory baseline cache and a single aggregator scan.
func (e *Engine) QualitySnapshot() QualitySnapshot {
	out := QualitySnapshot{Baselines: e.baselineCacheCopy(), FaultLayer: quality.FaultNone}

	if delta, ok := e.bufferbloatDelta(); ok {
		out.BufferbloatDelta = delta
		out.BufferbloatGrade = quality.BufferbloatGrade(delta)
		out.HasBufferbloat = true
	}

	if hops, gw, wan, ok := e.tracePath(); ok {
		layer, verdict := quality.IsolateFault(hops, gw, wan)
		out.FaultLayer = layer
		out.FaultVerdict = verdict
		out.HasFault = true
	}
	return out
}

// GradeContext projects the snapshot into the pure grade-context the TUI and
// Web grade computations both consume, keeping the modifier identical.
func (q QualitySnapshot) GradeContext() quality.GradeContext {
	return quality.GradeContext{
		Baselines:        q.Baselines,
		BufferbloatGrade: q.BufferbloatGrade,
		HasBufferbloat:   q.HasBufferbloat,
		FaultLayer:       q.FaultLayer,
		FaultVerdict:     q.FaultVerdict,
		HasFault:         q.HasFault,
	}
}

// Baseline returns the learned baseline for target at the current hour bucket.
func (e *Engine) Baseline(target string) (quality.Rollup, bool) {
	e.baselinesMu.RLock()
	defer e.baselinesMu.RUnlock()
	r, ok := e.baselines[target]
	return r, ok
}

func (e *Engine) baselineCacheCopy() map[string]quality.Rollup {
	e.baselinesMu.RLock()
	defer e.baselinesMu.RUnlock()
	out := make(map[string]quality.Rollup, len(e.baselines))
	for k, v := range e.baselines {
		out[k] = v
	}
	return out
}

// ResetBaseline clears the persisted baseline for target and drops it from the
// live cache. Backs the "reset baseline for <target>" action in both UIs.
func (e *Engine) ResetBaseline(ctx context.Context, target string) error {
	if err := e.store.ResetBaseline(ctx, target); err != nil {
		return err
	}
	e.baselinesMu.Lock()
	delete(e.baselines, target)
	e.baselinesMu.Unlock()
	return nil
}

// startRollupAggregator folds the live per-target window into the persisted
// (target, dow, hour) baseline on a timer using an exponential moving merge.
// Runs on a worker off the render path; writes are one row per real target.
func (e *Engine) startRollupAggregator(ctx context.Context) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		t := time.NewTicker(rollupInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				e.mergeRollupsOnce(ctx, time.Now())
			}
		}
	}()
}

func (e *Engine) mergeRollupsOnce(ctx context.Context, now time.Time) {
	dow, hour := quality.Bucket(now)
	updated := make(map[string]quality.Rollup)
	for _, ts := range e.agg.SnapshotTargets() {
		if !isRealTarget(ts.Target) || ts.AvgRTT <= 0 {
			continue // skip synthetic trace:/bufferbloat: targets and empty stats
		}
		obs := quality.Rollup{
			Target:   ts.Target,
			DOW:      dow,
			Hour:     hour,
			P50RTT:   msf(ts.P50RTT),
			P95RTT:   msf(ts.P95RTT),
			P99RTT:   msf(ts.P99RTT),
			LossPct:  ts.LossPct,
			JitterMs: ts.JitterMs,
			Samples:  1,
			Updated:  now,
		}
		old, _, err := e.store.GetRollup(ctx, ts.Target, dow, hour)
		if err != nil {
			continue
		}
		merged := quality.MergeEMA(quality.Rollup{
			Target: old.Target, DOW: old.DOW, Hour: old.Hour,
			P50RTT: old.P50RTT, P95RTT: old.P95RTT, P99RTT: old.P99RTT,
			LossPct: old.LossPct, JitterMs: old.JitterMs, Samples: old.Samples, Updated: old.Updated,
		}, obs, rollupAlpha)
		merged.Updated = now
		if err := e.store.PutRollup(ctx, storage.RollupRow{
			Target: merged.Target, DOW: merged.DOW, Hour: merged.Hour,
			P50RTT: merged.P50RTT, P95RTT: merged.P95RTT, P99RTT: merged.P99RTT,
			LossPct: merged.LossPct, JitterMs: merged.JitterMs,
			Samples: merged.Samples, Updated: merged.Updated,
		}); err != nil {
			continue
		}
		updated[ts.Target] = merged
	}
	if len(updated) == 0 {
		return
	}
	e.baselinesMu.Lock()
	for k, v := range updated {
		e.baselines[k] = v
	}
	e.baselinesMu.Unlock()
}

// startFlowSnapshotter writes a timestamped set of the current flows on a timer,
// so "what was talking at 02:00?" is answerable independently of the cumulative
// flows table.
func (e *Engine) startFlowSnapshotter(ctx context.Context) {
	if e.flowAgg == nil {
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		t := time.NewTicker(flowSnapshotInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				e.snapshotFlows(ctx, now)
			}
		}
	}()
}

func (e *Engine) snapshotFlows(ctx context.Context, now time.Time) {
	snap := e.flowAgg.Snapshot()
	if len(snap) == 0 {
		return
	}
	decorated := flows.Decorate(snap, e.dnsCache, e.procMatch)
	tagged := e.tagger.Tag(decorated)
	rows := make([]storage.FlowSnapshotRow, 0, len(tagged))
	for _, f := range tagged {
		sum := f.Summarize()
		row := storage.FlowSnapshotRow{
			Iface:    f.Key.Iface,
			Src:      f.Key.A.IP,
			Dst:      f.Key.B.IP,
			Proto:    sum.Protocol,
			BytesIn:  int64(sum.BytesIn),
			BytesOut: int64(sum.BytesOut),
			Process:  sum.ProcessName,
			DNSName:  sum.DNSName,
		}
		if f.HasTCP() {
			row.TCPRTTus = int64(f.TCP.RTTus)
			row.TCPRetransRate = f.TCP.RetransRate
			row.TCPCwnd = int64(f.TCP.Cwnd)
			row.TCPSource = f.TCP.Source
		}
		rows = append(rows, row)
	}
	_ = e.store.InsertFlowSnapshots(ctx, e.sessionID, now, rows)
}

// bufferbloatDelta derives the idle-vs-loaded RTT delta from the synthetic
// bufferbloat targets the collector publishes (bufferbloat:idle:* / :loaded:*).
func (e *Engine) bufferbloatDelta() (time.Duration, bool) {
	var idle, loaded time.Duration
	var haveIdle, haveLoaded bool
	for _, ts := range e.agg.SnapshotTargets() {
		switch {
		case strings.HasPrefix(ts.Target, "bufferbloat:idle:"):
			idle, haveIdle = ts.P50RTT, true
		case strings.HasPrefix(ts.Target, "bufferbloat:loaded:"):
			loaded, haveLoaded = ts.P50RTT, true
		}
	}
	if !haveIdle || !haveLoaded {
		return 0, false
	}
	delta := loaded - idle
	if delta < 0 {
		delta = 0
	}
	return delta, true
}

// tracePath reconstructs the primary traceroute path from the synthetic trace
// targets (trace:<dest>:hop<N>:<ip>) and derives gateway / WAN reference RTTs:
// the gateway is the first hop, the WAN entry is the first public hop. Returns
// ok=false until at least two valid hops exist.
func (e *Engine) tracePath() ([]probes.TraceHop, float64, float64, bool) {
	dest := e.primaryTraceTarget()
	if dest == "" {
		return nil, 0, 0, false
	}
	prefix := "trace:" + dest + ":hop"
	var hops []probes.TraceHop
	for _, ts := range e.agg.SnapshotTargets() {
		if !strings.HasPrefix(ts.Target, prefix) {
			continue
		}
		ttl, ip := parseHopTarget(ts.Target, prefix)
		if ttl == 0 {
			continue
		}
		hops = append(hops, probes.TraceHop{TTL: ttl, IP: ip, Latency: ts.AvgRTT})
	}
	if len(hops) < 2 {
		return nil, 0, 0, false
	}
	sort.Slice(hops, func(i, j int) bool { return hops[i].TTL < hops[j].TTL })

	gwRTT := msf(hops[0].Latency)
	wanRTT := gwRTT
	for _, h := range hops {
		if isPublicIP(h.IP) {
			wanRTT = msf(h.Latency)
			break
		}
	}
	return hops, gwRTT, wanRTT, true
}

func (e *Engine) primaryTraceTarget() string {
	if len(e.cfg.TracerouteTargets) > 0 {
		return e.cfg.TracerouteTargets[0]
	}
	if len(e.cfg.ICMPTargets) > 0 {
		return e.cfg.ICMPTargets[0]
	}
	return ""
}

// parseHopTarget extracts TTL and IP from "trace:<dest>:hopN:<ip>" given the
// "trace:<dest>:hop" prefix. Returns ttl=0 on a malformed target.
func parseHopTarget(target, prefix string) (int, string) {
	rest := strings.TrimPrefix(target, prefix) // "N:<ip>"
	idx := strings.IndexByte(rest, ':')
	if idx <= 0 {
		return 0, ""
	}
	ttl, err := strconv.Atoi(rest[:idx])
	if err != nil {
		return 0, ""
	}
	return ttl, rest[idx+1:]
}

func isRealTarget(target string) bool {
	return !strings.Contains(target, ":")
}

func isPublicIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}

func msf(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}
