package tui

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/noahzmr/testudo/internal/collectors"
	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/metrics"
	"github.com/noahzmr/testudo/internal/netops"
)

// NetworkGrade is the dashboard's at-a-glance summary of overall network
// health. A 0-100 score is computed from eight sub-scores spanning WAN,
// LAN, service, and stability dimensions. Each sub-score is mapped
// against an operator-configured threshold (or a sensible default when
// the metric doesn't have an explicit Threshold entry).
type NetworkGrade struct {
	Score   int    // 0..100
	Letter  string // "A+" .. "F"
	Verdict string // human-readable summary

	// HasData is false when every sub-score is "no data" - the grade is a
	// placeholder rather than a real measurement. Used by renderers to
	// switch the badge into a violet "awaiting probes" state.
	HasData bool

	// WAN-side reachability (ICMP to external + WAN top-talkers).
	Loss   subScore
	RTT    subScore
	Jitter subScore

	// DNS - external resolvers + internal LAN resolvers (both go through
	// the metrics aggregator with the same DNS payload).
	DNS subScore

	// LAN - reachability to LAN-side hosts (top-talkers, lan-reach,
	// internal discovery probes).
	LAN subScore

	// HTTP - service health: TTFB and failure rate of configured /
	// auto-derived HTTP endpoints.
	HTTP subScore

	// Stab - interface stability: per-iface error/drop ratio vs total
	// packets. Bad NIC, congested switch port, dirty cable.
	Stab subScore

	// WiFi - average signal level across associated wireless
	// interfaces. Neutral 100 when no wireless NICs are present.
	WiFi subScore
}

type subScore struct {
	Name  string
	Score int     // 0..100
	Value float64 // raw measurement (units depend on name)
	Unit  string
	OK    bool // false = below the comfort threshold
	// HasData is true when the sub-score is derived from at least one
	// real probe. When false, the sub-score is excluded from the overall
	// grade calculation and rendered in violet to signal "no results".
	HasData bool
}

// ComputeGrade combines live aggregator snapshots, kernel interface
// counters, and the operator's configured thresholds into a single
// quality score. Empty inputs yield a neutral 100 ("nothing measured ==
// nothing wrong yet").
//
// Targets are filtered by source so a slow HTTP TTFB doesn't pollute
// the ICMP RTT sub-score, and an offline LAN host doesn't drag the WAN
// loss number. The classification is by target-string prefix and the
// IsLAN heuristic.
func ComputeGrade(
	targets []metrics.TargetStats,
	dns []metrics.DNSStats,
	ifaces []netops.IfaceInfo,
	wifi []collectors.WiFiSnapshot,
	th config.Thresholds,
) NetworkGrade {
	// Weights sum to 1.0. WAN reachability remains the spine of the
	// grade; new dimensions slot in around it.
	const (
		wLoss   = 0.20
		wRTT    = 0.15
		wJitter = 0.10
		wDNS    = 0.10
		wLAN    = 0.15
		wHTTP   = 0.10
		wStab   = 0.10
		wWiFi   = 0.10
	)

	wan := filterTargets(targets, isWANTarget)
	lan := filterTargets(targets, isLANTarget)
	httpT := filterTargets(targets, isHTTPTarget)

	loss := scoreLossSub(wan, th.PacketLossPct)
	rtt := scoreRTTSub(wan, th.RTTMs)
	jit := scoreJitterSub(wan, th.JitterMs)
	dnsLat := scoreDNSSub(dns, th.DNSLatencyMs)
	lanScore := scoreLAN(lan, th)
	httpScore := scoreHTTP(httpT)
	stabScore := scoreStability(ifaces)
	wifiScore := scoreWiFi(wifi)

	// Renormalize over sub-scores that actually have data. A sub-score
	// with HasData=false drops out of both the numerator and the
	// denominator so "we haven't measured X yet" never inflates (or
	// deflates) the grade.
	parts := []struct {
		w float64
		s subScore
	}{
		{wLoss, loss}, {wRTT, rtt}, {wJitter, jit}, {wDNS, dnsLat},
		{wLAN, lanScore}, {wHTTP, httpScore}, {wStab, stabScore}, {wWiFi, wifiScore},
	}
	var weighted, totalW float64
	for _, p := range parts {
		if !p.s.HasData {
			continue
		}
		weighted += p.w * float64(p.s.Score)
		totalW += p.w
	}
	if totalW == 0 {
		return NetworkGrade{
			Score: 0, Letter: "?", Verdict: "Awaiting probes",
			HasData: false,
			Loss:    loss, RTT: rtt, Jitter: jit, DNS: dnsLat,
			LAN: lanScore, HTTP: httpScore, Stab: stabScore, WiFi: wifiScore,
		}
	}
	score := int(weighted/totalW + 0.5)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	letter, verdict := letterAndVerdict(score)
	return NetworkGrade{
		Score: score, Letter: letter, Verdict: verdict, HasData: true,
		Loss: loss, RTT: rtt, Jitter: jit, DNS: dnsLat,
		LAN: lanScore, HTTP: httpScore, Stab: stabScore, WiFi: wifiScore,
	}
}

// scoreFromMetric maps a measurement => 0..100 where:
//
//	value = 0          => 100 (perfect)
//	value = threshold  => 50  (operator comfort line)
//	value ≥ 2×threshold => 0  (worst case for the score)
//
// The returned sub-score always has HasData=true; callers must short-circuit
// before invoking this helper when no measurements exist.
func scoreFromMetric(name string, value, threshold float64, unit string) subScore {
	if threshold <= 0 {
		threshold = 1
	}
	score := 100
	ok := true
	if value > 0 {
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
	return subScore{Name: name, Score: score, Value: value, Unit: unit, OK: ok, HasData: true}
}

// scoreLossSub computes the WAN packet-loss sub-score. Empty WAN target
// set => HasData=false (the sub-score is excluded from the grade and
// rendered violet by the dashboard).
func scoreLossSub(ts []metrics.TargetStats, threshold float64) subScore {
	if len(ts) == 0 {
		return subScore{Name: "loss", Unit: "%", OK: true}
	}
	return scoreFromMetric("loss", avgLossPct(ts), threshold, "%")
}

// scoreRTTSub computes the WAN RTT sub-score. HasData=false when no
// target has been probed successfully yet.
func scoreRTTSub(ts []metrics.TargetStats, threshold float64) subScore {
	if !hasRTTData(ts) {
		return subScore{Name: "rtt", Unit: "ms", OK: true}
	}
	return scoreFromMetric("rtt", avgRTTms(ts), threshold, "ms")
}

// scoreJitterSub computes the WAN jitter sub-score. Jitter piggybacks on
// the same probe stream as RTT, so absence of RTT data implies absence
// of jitter data.
func scoreJitterSub(ts []metrics.TargetStats, threshold float64) subScore {
	if !hasRTTData(ts) {
		return subScore{Name: "jitter", Unit: "ms", OK: true}
	}
	return scoreFromMetric("jitter", avgJitterMs(ts), threshold, "ms")
}

// scoreDNSSub computes the DNS latency sub-score. HasData=false when no
// resolver has answered a query yet.
func scoreDNSSub(ds []metrics.DNSStats, threshold float64) subScore {
	if !hasDNSData(ds) {
		return subScore{Name: "dns", Unit: "ms", OK: true}
	}
	return scoreFromMetric("dns", avgDNSms(ds), threshold, "ms")
}

// scoreLAN blends LAN loss and LAN RTT into a single sub-score. LAN
// RTT comfort line is tighter than WAN (typical LAN ping is <5ms).
// HasData=false when no LAN targets exist.
func scoreLAN(ts []metrics.TargetStats, th config.Thresholds) subScore {
	if len(ts) == 0 {
		return subScore{Name: "lan", Unit: "ms", OK: true}
	}
	lossPart := scoreFromMetric("lan-loss", avgLossPct(ts), th.PacketLossPct, "%")
	// LAN RTT threshold: 50ms is already concerning on a switched LAN.
	rttPart := scoreFromMetric("lan-rtt", avgRTTms(ts), 50, "ms")
	score := (lossPart.Score + rttPart.Score) / 2
	return subScore{
		Name: "lan", Score: score, Value: rttPart.Value, Unit: "ms",
		OK: lossPart.OK && rttPart.OK, HasData: true,
	}
}

// scoreHTTP blends HTTP failure rate and TTFB. Comfort line for TTFB
// is 500ms; for failure rate, 2% (same as packet loss). HasData=false
// when no HTTP endpoints are configured.
func scoreHTTP(ts []metrics.TargetStats) subScore {
	if len(ts) == 0 {
		return subScore{Name: "http", Unit: "ms", OK: true}
	}
	lossPart := scoreFromMetric("http-fail", avgLossPct(ts), 2.0, "%")
	ttfbPart := scoreFromMetric("ttfb", avgRTTms(ts), 500, "ms")
	score := (lossPart.Score + ttfbPart.Score) / 2
	return subScore{
		Name: "http", Score: score, Value: ttfbPart.Value, Unit: "ms",
		OK: lossPart.OK && ttfbPart.OK, HasData: true,
	}
}

// scoreStability reads kernel error / drop counters and reports the
// ratio of errored packets to total packets across non-loopback
// interfaces. Comfort line: 0.1% (one bad packet in a thousand).
// HasData=false when the kernel hasn't reported any packets yet.
func scoreStability(ifs []netops.IfaceInfo) subScore {
	var totalErrors, totalPackets uint64
	for _, ifi := range ifs {
		if ifi.Name == "lo" {
			continue
		}
		totalErrors += ifi.RxErrors + ifi.TxErrors + ifi.RxDropped + ifi.TxDropped
		totalPackets += ifi.RxPackets + ifi.TxPackets
	}
	if totalPackets == 0 {
		return subScore{Name: "stab", Unit: "%", OK: true}
	}
	pct := float64(totalErrors) / float64(totalPackets) * 100
	return scoreFromMetric("stab", pct, 0.1, "%")
}

// scoreWiFi averages the signal level (dBm) across associated wireless
// interfaces using the WiFiCollector's snapshot. The collector fuses
// nl80211 (via `iw`) and /proc/net/wireless data, so this scorer
// surfaces real signal numbers even on drivers that don't populate the
// legacy wireless-extensions API. Linear -60dBm => 100, -90dBm => 0.
// HasData=false when no wireless NICs exist or none are associated.
func scoreWiFi(snaps []collectors.WiFiSnapshot) subScore {
	if len(snaps) == 0 {
		return subScore{Name: "wifi", Unit: "dBm", OK: true}
	}
	var sum float64
	var n int
	for _, s := range snaps {
		if s.Associated && s.Signal != 0 {
			sum += s.Signal
			n++
		}
	}
	if n == 0 {
		return subScore{Name: "wifi", Unit: "dBm", OK: true}
	}
	avg := sum / float64(n)
	// Map dBm to 0..100. -60 = excellent (100), -90 = unusable (0).
	score := int((avg+90)/30*100 + 0.5)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return subScore{Name: "wifi", Score: score, Value: avg, Unit: "dBm", OK: avg > -75, HasData: true}
}

// hasRTTData reports whether any target has produced a non-zero RTT
// sample. Used by the WAN RTT / jitter sub-scores to distinguish
// "perfectly stable network" from "we haven't measured anything yet".
func hasRTTData(ts []metrics.TargetStats) bool {
	for _, t := range ts {
		if t.AvgRTT > 0 {
			return true
		}
	}
	return false
}

// hasDNSData reports whether any DNS resolver has answered a probe.
func hasDNSData(ds []metrics.DNSStats) bool {
	for _, d := range ds {
		if d.AvgLatency > 0 {
			return true
		}
	}
	return false
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

// ---- target classification ----

func filterTargets(ts []metrics.TargetStats, pred func(string) bool) []metrics.TargetStats {
	out := make([]metrics.TargetStats, 0, len(ts))
	for _, t := range ts {
		if pred(t.Target) {
			out = append(out, t)
		}
	}
	return out
}

func isHTTPTarget(t string) bool {
	return strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://")
}

// isLANTarget reports whether the target should be treated as a LAN
// host for grading. IP literals: IsLAN heuristic. Hostnames: the
// .lan/.local/.home suffixes commonly used for LAN-only mDNS / DNS.
func isLANTarget(t string) bool {
	host := t
	if h, _, err := net.SplitHostPort(t); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		return flows.IsLAN(host)
	}
	for _, suf := range []string{".lan", ".local", ".home", ".internal"} {
		if strings.HasSuffix(strings.ToLower(host), suf) {
			return true
		}
	}
	return false
}

// isWANTarget excludes everything we score separately. Anything left is
// treated as the WAN-side ICMP/TCP probe set the original grade was
// designed around.
func isWANTarget(t string) bool {
	if isHTTPTarget(t) {
		return false
	}
	if isSyntheticTarget(t) {
		return false
	}
	if isLANTarget(t) {
		return false
	}
	return true
}

// isSyntheticTarget reports whether the target is one of the encoded
// names other collectors (traceroute, wifi, bufferbloat) write into the
// aggregator. Those have dedicated Health-tab renderers and would
// otherwise pollute the ICMP latency panels on the Dashboard.
func isSyntheticTarget(t string) bool {
	for _, p := range []string{"trace:", "wifi:", "bufferbloat:"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// filterICMPTargets keeps only real ICMP/TCP probe targets - LAN and WAN
// hosts the user configured for icmp probing. Synthetic entries and
// HTTP endpoints are dropped.
func filterICMPTargets(in []metrics.TargetStats) []metrics.TargetStats {
	out := in[:0:0]
	for _, t := range in {
		if isSyntheticTarget(t.Target) || isHTTPTarget(t.Target) {
			continue
		}
		out = append(out, t)
	}
	return out
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
		return lipgloss.Color("42")
	case score >= 70:
		return lipgloss.Color("220")
	case score >= 60:
		return lipgloss.Color("214")
	default:
		return lipgloss.Color("196")
	}
}

// noDataColor is the violet hue used wherever a sub-score (or the whole
// grade) is rendered because no measurements have been collected yet.
const noDataColor = lipgloss.Color("141")

// renderGradeBadge produces a 3-line block that frames the letter grade,
// score, and verdict. When the grade itself has no data, the badge
// turns violet and the letter becomes "?".
func renderGradeBadge(g NetworkGrade, width int) string {
	if width < 30 {
		width = 30
	}
	col := gradeColor(g.Score)
	letter := g.Letter
	scoreText := fmt.Sprintf("%d / 100", g.Score)
	if !g.HasData {
		col = noDataColor
		if letter == "" {
			letter = "?"
		}
		scoreText = "no data"
	}
	letterBox := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("231")).
		Background(col).
		Padding(0, 2).
		Margin(0, 1).
		Render(" " + letter + " ")
	scoreLine := lipgloss.NewStyle().
		Bold(true).
		Foreground(col).
		Render(scoreText)
	verdict := lipgloss.NewStyle().
		Foreground(col).
		Render(g.Verdict)
	right := scoreLine + "  " + dimStyle.Render("·  ") + verdict
	return lipgloss.JoinHorizontal(lipgloss.Center, letterBox, "  ", right)
}

// renderSubScoreBar produces "LABEL  ▓▓▓▓░░░  value" - a 0..100
// horizontal gauge of one sub-score, with the unit appended. When the
// sub-score has no data, the bar is fully empty and rendered violet
// with a "no data" trailing label so the operator can immediately see
// which dimensions have not yet been measured.
func renderSubScoreBar(s subScore, width int) string {
	if width < 30 {
		width = 30
	}
	const barW = 16
	label := fmt.Sprintf("%-7s", strings.ToUpper(s.Name))
	if !s.HasData {
		bar := strings.Repeat("░", barW)
		violet := lipgloss.NewStyle().Foreground(noDataColor)
		return fmt.Sprintf("  %s %s %s",
			dimStyle.Render(label),
			violet.Render(bar),
			violet.Render("no data"),
		)
	}
	filled := s.Score * barW / 100
	if filled < 0 {
		filled = 0
	}
	if filled > barW {
		filled = barW
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barW-filled)
	col := gradeColor(s.Score)
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
// rolling samples.
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
