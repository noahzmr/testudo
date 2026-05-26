package web

import (
	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/metrics"
)

// computeGradeView mirrors the TUI's ComputeGrade so the dashboard's
// "Network Quality" badge looks identical in both UIs. Weights and the
// 0-100 sub-score mapping are kept in lockstep with internal/tui/grade.go.
func computeGradeView(targets []metrics.TargetStats, dns []metrics.DNSStats, th config.Thresholds) gradeView {
	const (
		wLoss   = 0.40
		wRTT    = 0.30
		wJitter = 0.15
		wDNS    = 0.15
	)
	lossScore := subScore(avgLoss(targets), th.PacketLossPct)
	rttScore := subScore(avgRTT(targets), th.RTTMs)
	jitScore := subScore(avgJit(targets), th.JitterMs)
	dnsScore := subScore(avgDNS(dns), th.DNSLatencyMs)
	total := wLoss*float64(lossScore) + wRTT*float64(rttScore) +
		wJitter*float64(jitScore) + wDNS*float64(dnsScore)
	score := int(total + 0.5)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	letter, verdict := letterVerdict(score)
	return gradeView{
		Score: score, Letter: letter, Verdict: verdict,
		Loss: lossScore, RTT: rttScore, Jitter: jitScore, DNS: dnsScore,
	}
}

// subScore maps a measurement => 0..100 against a comfort threshold.
// See tui/grade.go for the same logic.
func subScore(value, threshold float64) int {
	if threshold <= 0 {
		threshold = 1
	}
	if value <= 0 {
		return 100
	}
	ratio := value / threshold
	switch {
	case ratio <= 1:
		return int(100 - 50*ratio + 0.5)
	case ratio <= 2:
		return int(50 - 50*(ratio-1) + 0.5)
	default:
		return 0
	}
}

func letterVerdict(score int) (string, string) {
	switch {
	case score >= 95:
		return "A+", "Excellent"
	case score >= 90:
		return "A", "Very good"
	case score >= 85:
		return "A-", "Good"
	case score >= 80:
		return "B+", "OK"
	case score >= 70:
		return "B", "Acceptable"
	case score >= 60:
		return "C", "Degraded"
	case score >= 50:
		return "D", "Poor"
	default:
		return "F", "Failing"
	}
}

func avgLoss(ts []metrics.TargetStats) float64 {
	if len(ts) == 0 {
		return 0
	}
	var sum float64
	for _, t := range ts {
		sum += t.LossPct
	}
	return sum / float64(len(ts))
}

func avgRTT(ts []metrics.TargetStats) float64 {
	var sum float64
	var n int
	for _, t := range ts {
		if t.AvgRTT > 0 {
			sum += float64(t.AvgRTT.Microseconds()) / 1000.0
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

func avgJit(ts []metrics.TargetStats) float64 {
	var sum float64
	var n int
	for _, t := range ts {
		if t.JitterMs > 0 {
			sum += t.JitterMs
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

func avgDNS(ds []metrics.DNSStats) float64 {
	var sum float64
	var n int
	for _, d := range ds {
		if d.AvgLatency > 0 {
			sum += float64(d.AvgLatency.Microseconds()) / 1000.0
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}
