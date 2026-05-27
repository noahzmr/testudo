// Package quality holds the pure baseline-quality logic: the persisted
// per-(target, day-of-week, hour) rollup model, baseline-relative comparison,
// the bufferbloat letter grade, and ISP-degradation isolation. Everything here
// is allocation-light and free of I/O so it is trivially table-testable and can
// run off the render path (see the storage rollup aggregator and grade modifier).
package quality

import (
	"fmt"
	"time"

	"github.com/noahzmr/testudo/internal/probes"
)

// Rollup is one persisted baseline row keyed (Target, DOW, Hour). RTT/jitter are
// stored in milliseconds, loss as a percentage. It is the per-target,
// per-hour-of-day "normal" the live metrics are compared against.
type Rollup struct {
	Target   string
	DOW      int // 0..6, time.Weekday
	Hour     int // 0..23
	P50RTT   float64
	P95RTT   float64
	P99RTT   float64
	LossPct  float64
	JitterMs float64
	Samples  int64
	Updated  time.Time
}

// Bucket returns the (dow, hour) baseline bucket for t in its own location.
func Bucket(t time.Time) (dow, hour int) {
	return int(t.Weekday()), t.Hour()
}

// MergeEMA folds a freshly-observed bucket aggregate (obs) into the stored
// baseline (old) using an exponential moving merge: recent weeks dominate while
// old data decays. alpha in (0,1] is the weight of the new observation. When the
// stored row has no samples yet the observation is adopted wholesale so the
// baseline bootstraps on first run. Target/DOW/Hour come from obs.
func MergeEMA(old, obs Rollup, alpha float64) Rollup {
	if alpha <= 0 {
		alpha = 0.1
	}
	if alpha > 1 {
		alpha = 1
	}
	out := obs
	out.Samples = old.Samples + obs.Samples
	if old.Samples == 0 {
		// First observation for this bucket: adopt as-is.
		return out
	}
	out.P50RTT = ema(old.P50RTT, obs.P50RTT, alpha)
	out.P95RTT = ema(old.P95RTT, obs.P95RTT, alpha)
	out.P99RTT = ema(old.P99RTT, obs.P99RTT, alpha)
	out.LossPct = ema(old.LossPct, obs.LossPct, alpha)
	out.JitterMs = ema(old.JitterMs, obs.JitterMs, alpha)
	return out
}

func ema(old, obs, alpha float64) float64 {
	return old*(1-alpha) + obs*alpha
}

// Sample is the live measurement compared against a baseline row. RTT/jitter in
// milliseconds, loss as a percentage.
type Sample struct {
	RTTms    float64
	LossPct  float64
	JitterMs float64
}

// BaselineRatio returns current RTT ÷ baseline median RTT for the bucket and
// ok=true when a usable baseline exists. ok=false (ratio 1.0) means "no opinion"
// - an empty baseline (first run / new target) or a non-positive median - and
// per the Network Quality contract must be treated as neutral, never a penalty.
func BaselineRatio(b Rollup, now Sample) (ratio float64, ok bool) {
	if b.Samples <= 0 || b.P50RTT <= 0 || now.RTTms <= 0 {
		return 1.0, false
	}
	return now.RTTms / b.P50RTT, true
}

// BaselineDescr renders the operator-facing baseline badge suffix for an RTT
// value, e.g. "≈ normal" or "3.1× normal ▲". Returns "" when there is no
// baseline opinion so callers can omit the badge entirely.
func BaselineDescr(b Rollup, now Sample) string {
	ratio, ok := BaselineRatio(b, now)
	if !ok {
		return ""
	}
	switch {
	case ratio >= 1.5:
		return fmt.Sprintf("%.1f× normal ▲", ratio)
	case ratio <= 0.66:
		return fmt.Sprintf("%.1f× normal ▼", ratio)
	default:
		return "≈ normal"
	}
}

// BufferbloatGrade maps the measured idle-vs-loaded RTT delta to an A–F letter.
// Bands follow the collector's severity boundaries (30/100/300 ms): under 30 ms
// is imperceptible (A); 300 ms or more wrecks VoIP and gaming (F).
func BufferbloatGrade(delta time.Duration) string {
	ms := float64(delta) / float64(time.Millisecond)
	switch {
	case ms < 30:
		return "A"
	case ms < 100:
		return "B"
	case ms < 200:
		return "C"
	case ms < 300:
		return "D"
	default:
		return "F"
	}
}

// GradeContext carries the baseline-relative, bufferbloat, and ISP-isolation
// signals into the Network Quality grade. The zero value is fully neutral, so a
// host with no learned baseline and no bufferbloat/trace data is never penalised.
type GradeContext struct {
	// Baselines is the current-bucket baseline per target.
	Baselines map[string]Rollup
	// BufferbloatGrade is the A–F letter; HasBufferbloat gates its display.
	BufferbloatGrade string
	HasBufferbloat   bool
	// Fault isolation verdict over the primary path.
	FaultLayer   FaultLayer
	FaultVerdict string
	HasFault     bool
}

// baselineModifierStart is the ratio above which baseline-relative degradation
// starts nudging the grade down; below it, tonight looks normal.
const baselineModifierStart = 1.5

// maxBaselinePenalty caps the baseline-relative grade nudge so an early warning
// can drop a letter or two without tanking an otherwise-healthy score.
const maxBaselinePenalty = 25

// WorstBaselineRatio returns the largest current÷baseline RTT ratio across the
// targets that have a usable baseline, and ok=true when at least one did. The
// worst offender drives the early-warning modifier.
func WorstBaselineRatio(baselines map[string]Rollup, currentRTTms map[string]float64) (float64, bool) {
	worst := 0.0
	ok := false
	for target, cur := range currentRTTms {
		b, has := baselines[target]
		if !has {
			continue
		}
		if r, good := BaselineRatio(b, Sample{RTTms: cur}); good && r > worst {
			worst, ok = r, true
		}
	}
	return worst, ok
}

// GradeModifier maps a baseline ratio to a score penalty (0..maxBaselinePenalty):
// when tonight's RTT is far worse than the learned normal the grade is nudged
// down even if absolute thresholds aren't breached yet (early warning). Returns
// 0 when there is no baseline opinion or the ratio is within the normal envelope.
func GradeModifier(ratio float64, ok bool) int {
	if !ok || ratio <= baselineModifierStart {
		return 0
	}
	penalty := int((ratio-baselineModifierStart)*20 + 0.5)
	if penalty > maxBaselinePenalty {
		penalty = maxBaselinePenalty
	}
	return penalty
}

// FaultLayer names the path segment responsible for degradation.
type FaultLayer string

const (
	FaultNone     FaultLayer = "none"
	FaultFirstHop FaultLayer = "first-hop"
	FaultGateway  FaultLayer = "gateway"
	FaultWAN      FaultLayer = "WAN"
	FaultTarget   FaultLayer = "target"
)

// isolateFloorMs is the smallest incremental segment delay worth blaming; below
// it the path is considered healthy regardless of which segment is largest.
const isolateFloorMs = 25.0

// IsolateFault decomposes the path into first-hop / gateway / WAN / target
// segments and names the one contributing the dominant incremental delay, with a
// human verdict. hops are traceroute hops in TTL order; gwRTT and wanRTT are
// reference RTTs (ms) for the gateway and a WAN anchor (e.g. 1.1.1.1). Returns
// FaultNone when no segment's incremental delay clears the floor - the answer to
// "where's the problem?" when there isn't one.
func IsolateFault(hops []probes.TraceHop, gwRTT, wanRTT float64) (FaultLayer, string) {
	firstHop, targetRTT := hopBounds(hops)

	// Incremental delay attributed to each segment, clamped at zero so a faster
	// downstream measurement never produces a negative "delay".
	firstHopDelay := firstHop
	gatewayDelay := nonNeg(gwRTT - firstHop)
	wanDelay := nonNeg(wanRTT - gwRTT)
	targetDelay := nonNeg(targetRTT - wanRTT)

	type seg struct {
		layer FaultLayer
		delay float64
		label string
	}
	segs := []seg{
		{FaultFirstHop, firstHopDelay, "first hop / LAN"},
		{FaultGateway, gatewayDelay, "gateway"},
		{FaultWAN, wanDelay, "WAN"},
		{FaultTarget, targetDelay, "target"},
	}

	worst := seg{layer: FaultNone}
	for _, s := range segs {
		if s.delay > worst.delay {
			worst = s
		}
	}
	if worst.layer == FaultNone || worst.delay < isolateFloorMs {
		return FaultNone, "path healthy (no segment dominates)"
	}

	// Name a healthy reference segment for context in the verdict.
	healthy := "downstream"
	switch worst.layer {
	case FaultWAN, FaultTarget:
		if gatewayDelay < isolateFloorMs && firstHopDelay < isolateFloorMs {
			healthy = "gateway healthy"
		}
	case FaultGateway, FaultFirstHop:
		if wanDelay < isolateFloorMs {
			healthy = "WAN healthy"
		}
	}
	return worst.layer, fmt.Sprintf("Degradation isolated to: %s (%s)", worst.label, healthy)
}

// hopBounds returns the first valid hop's RTT (≈ the first router) and the final
// valid hop's RTT (≈ end-to-end), in milliseconds. Invalid hops ("*", zero
// latency) are skipped.
func hopBounds(hops []probes.TraceHop) (firstHop, target float64) {
	for _, h := range hops {
		if h.IP == "" || h.IP == "*" || h.Latency <= 0 {
			continue
		}
		ms := float64(h.Latency) / float64(time.Millisecond)
		if firstHop == 0 {
			firstHop = ms
		}
		target = ms
	}
	return firstHop, target
}

func nonNeg(v float64) float64 {
	if v < 0 {
		return 0
	}
	return v
}
