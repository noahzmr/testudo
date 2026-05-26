package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/metrics"
)

// NetworkGrade is the dashboard's at-a-glance summary of overall network
// health. A 0-100 score is computed from four sub-scores (loss, RTT,
// jitter, DNS), each scaled against the operator's configured thresholds.
type NetworkGrade struct {
	Score   int    // 0..100
	Letter  string // "A+" .. "F"
	Verdict string // human-readable summary ("Excellent", "Degraded", …)
	Loss    subScore
	RTT     subScore
	Jitter  subScore
	DNS     subScore
}

type subScore struct {
	Name  string
	Score int     // 0..100
	Value float64 // raw measurement (units depend on name)
	Unit  string
	OK    bool // false = below the comfort threshold
}

// ComputeGrade combines the live aggregator snapshots with the operator's
// configured thresholds into a single quality score. Empty inputs yield a
// neutral 100 ("nothing measured == nothing wrong yet").
func ComputeGrade(targets []metrics.TargetStats, dns []metrics.DNSStats, th config.Thresholds) NetworkGrade {
	// Per-sub-score weights. Loss is the most visceral degradation;
	// jitter least.
	const (
		weightLoss   = 0.40
		weightRTT    = 0.30
		weightJitter = 0.15
		weightDNS    = 0.15
	)

	loss := scoreFromMetric(
		"loss", avgLossPct(targets), th.PacketLossPct, "%",
	)
	rtt := scoreFromMetric(
		"rtt", avgRTTms(targets), th.RTTMs, "ms",
	)
	jit := scoreFromMetric(
		"jitter", avgJitterMs(targets), th.JitterMs, "ms",
	)
	dnsLat := scoreFromMetric(
		"dns", avgDNSms(dns), th.DNSLatencyMs, "ms",
	)

	total := weightLoss*float64(loss.Score) +
		weightRTT*float64(rtt.Score) +
		weightJitter*float64(jit.Score) +
		weightDNS*float64(dnsLat.Score)
	score := int(total + 0.5)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	letter, verdict := letterAndVerdict(score)
	return NetworkGrade{
		Score: score, Letter: letter, Verdict: verdict,
		Loss: loss, RTT: rtt, Jitter: jit, DNS: dnsLat,
	}
}

// scoreFromMetric maps a measurement => 0..100 where:
//
//	value = 0          => 100 (perfect)
//	value = threshold  => 50  (operator comfort line)
//	value ≥ 2×threshold => 0  (worst case for the score)
//
// Returns a neutral 100 when no data has been collected yet so the dashboard
// doesn't open red on first paint.
func scoreFromMetric(name string, value, threshold float64, unit string) subScore {
	if threshold <= 0 {
		threshold = 1
	}
	score := 100
	ok := true
	if value > 0 {
		// 50 points spans 0..threshold; the next 50 spans threshold..2×threshold.
		ratio := value / threshold
		switch {
		case ratio <= 1:
			score = int(100 - 50*ratio + 0.5)
		case ratio <= 2:
			score = int(50 - 50*(ratio-1) + 0.5)
			ok = false
		default:
			score = 0
			ok = false
		}
	}
	return subScore{Name: name, Score: score, Value: value, Unit: unit, OK: ok}
}

func letterAndVerdict(score int) (string, string) {
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

// ---- helpers that average across targets ----

func avgLossPct(ts []metrics.TargetStats) float64 {
	if len(ts) == 0 {
		return 0
	}
	var sum float64
	for _, t := range ts {
		sum += t.LossPct
	}
	return sum / float64(len(ts))
}

func avgRTTms(ts []metrics.TargetStats) float64 {
	if len(ts) == 0 {
		return 0
	}
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

func avgJitterMs(ts []metrics.TargetStats) float64 {
	if len(ts) == 0 {
		return 0
	}
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

func avgDNSms(ds []metrics.DNSStats) float64 {
	if len(ds) == 0 {
		return 0
	}
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

// gradeColor picks the foreground colour for the letter badge.
func gradeColor(score int) lipgloss.Color {
	switch {
	case score >= 85:
		return lipgloss.Color("42") // green
	case score >= 70:
		return lipgloss.Color("220") // yellow
	case score >= 60:
		return lipgloss.Color("214") // orange
	default:
		return lipgloss.Color("196") // red
	}
}

// renderGradeBadge produces a 3-line block that frames the letter grade,
// score, and verdict. Width-adaptive: stays inside the supplied width.
func renderGradeBadge(g NetworkGrade, width int) string {
	if width < 30 {
		width = 30
	}
	col := gradeColor(g.Score)
	letterBox := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("231")).
		Background(col).
		Padding(0, 2).
		Margin(0, 1).
		Render(" " + g.Letter + " ")
	scoreLine := lipgloss.NewStyle().
		Bold(true).
		Foreground(col).
		Render(fmt.Sprintf("%d / 100", g.Score))
	verdict := lipgloss.NewStyle().
		Foreground(col).
		Render(g.Verdict)
	right := scoreLine + "  " + dimStyle.Render("·  ") + verdict
	return lipgloss.JoinHorizontal(lipgloss.Center, letterBox, "  ", right)
}

// renderSubScoreBar produces "LABEL  ▓▓▓▓░░░  value" - a 0..100 horizontal
// gauge of one sub-score, with the unit appended.
func renderSubScoreBar(s subScore, width int) string {
	if width < 30 {
		width = 30
	}
	const barW = 16
	filled := s.Score * barW / 100
	if filled < 0 {
		filled = 0
	}
	if filled > barW {
		filled = barW
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barW-filled)
	col := gradeColor(s.Score)
	label := fmt.Sprintf("%-7s", strings.ToUpper(s.Name))
	value := fmt.Sprintf("%.1f%s", s.Value, s.Unit)
	if s.Value == 0 {
		value = "-"
	}
	return fmt.Sprintf("  %s %s %s",
		dimStyle.Render(label),
		lipgloss.NewStyle().Foreground(col).Render(bar),
		dimStyle.Render(value),
	)
}

// renderSparklineWithLabel pairs a target name with a sparkline of its
// rolling samples. Empty samples render as a flat dash line.
func renderSparklineWithLabel(label string, samples []time.Duration, width int) string {
	values := make([]float64, len(samples))
	for i, s := range samples {
		values[i] = float64(s.Microseconds()) / 1000.0
	}
	const labelW = 14
	if width < 40 {
		width = 40
	}
	plotW := width - labelW - 4
	if plotW < 8 {
		plotW = 8
	}
	lbl := label
	if len(lbl) > labelW {
		lbl = lbl[:labelW]
	}
	spark := sparkline(values, plotW)
	last := "-"
	if n := len(samples); n > 0 {
		last = fmtRTT(samples[n-1])
	}
	return fmt.Sprintf("  %-*s %s  %s",
		labelW, lbl,
		rowStyle.Render(spark),
		dimStyle.Render(last),
	)
}
