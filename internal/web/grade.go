package web

import (
	"net"
	"strings"

	"github.com/noahzmr/testudo/internal/collectors"
	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/metrics"
	"github.com/noahzmr/testudo/internal/netops"
)

// computeGradeView mirrors the TUI's ComputeGrade so the dashboard's
// "Network Quality" badge looks identical in both UIs. Weights, sub-score
// mapping, and target classification stay in lockstep with
// internal/tui/grade.go.
func computeGradeView(
	targets []metrics.TargetStats,
	dns []metrics.DNSStats,
	ifaces []netops.IfaceInfo,
	wifi []collectors.WiFiSnapshot,
	fwDropRate float64,
	fwHasDropRules bool,
	th config.Thresholds,
) gradeView {
	const (
		wLoss     = 0.20
		wRTT      = 0.15
		wJitter   = 0.10
		wDNS      = 0.10
		wLAN      = 0.15
		wHTTP     = 0.05
		wStab     = 0.10
		wWiFi     = 0.10
		wFirewall = 0.05
	)

	wan := filterT(targets, isWANTargetW)
	lan := filterT(targets, isLANTargetW)
	httpT := filterT(targets, isHTTPTargetW)

	hasLoss := len(wan) > 0
	hasRTT := hasRTTDataW(wan)
	hasJit := hasRTTDataW(wan)
	hasDNS := hasDNSDataW(dns)
	hasLAN := len(lan) > 0
	hasHTTP := len(httpT) > 0
	hasStab := hasStabDataW(ifaces)
	hasWiFi := hasWiFiDataW(wifi)

	lossScore := subScore(avgLoss(wan), th.PacketLossPct)
	rttScore := subScore(avgRTT(wan), th.RTTMs)
	jitScore := subScore(avgJit(wan), th.JitterMs)
	dnsScore := subScore(avgDNS(dns), th.DNSLatencyMs)
	lanScore := scoreLANW(lan, th)
	httpScore := scoreHTTPW(httpT)
	stabScore := scoreStabilityW(ifaces)
	wifiScore := scoreWiFiW(wifi)
	fwScore := scoreFirewallW(fwDropRate, fwHasDropRules)

	// Renormalize over sub-scores that have data so "no measurement yet"
	// doesn't inflate the overall grade. Mirrors internal/tui/grade.go.
	parts := []struct {
		w  float64
		s  int
		ok bool
		nm string
	}{
		{wLoss, lossScore, hasLoss, "Loss"},
		{wRTT, rttScore, hasRTT, "RTT"},
		{wJitter, jitScore, hasJit, "Jitter"},
		{wDNS, dnsScore, hasDNS, "DNS"},
		{wLAN, lanScore, hasLAN, "LAN"},
		{wHTTP, httpScore, hasHTTP, "HTTP"},
		{wStab, stabScore, hasStab, "Stab"},
		{wWiFi, wifiScore, hasWiFi, "WiFi"},
		{wFirewall, fwScore, fwHasDropRules, "Firewall"},
	}
	var weighted, totalW float64
	noData := []string{}
	for _, p := range parts {
		if !p.ok {
			noData = append(noData, p.nm)
			continue
		}
		weighted += p.w * float64(p.s)
		totalW += p.w
	}
	if totalW == 0 {
		return gradeView{
			Score: 0, Letter: "?", Verdict: "Awaiting probes",
			HasData: false,
			Loss:    lossScore, RTT: rttScore, Jitter: jitScore, DNS: dnsScore,
			LAN: lanScore, HTTP: httpScore, Stab: stabScore, WiFi: wifiScore,
			Firewall: fwScore,
			NoData:   noData,
		}
	}
	score := int(weighted/totalW + 0.5)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	letter, verdict := letterVerdict(score)
	return gradeView{
		Score: score, Letter: letter, Verdict: verdict, HasData: true,
		Loss: lossScore, RTT: rttScore, Jitter: jitScore, DNS: dnsScore,
		LAN: lanScore, HTTP: httpScore, Stab: stabScore, WiFi: wifiScore,
		Firewall: fwScore,
		NoData:   noData,
	}
}

// scoreFirewallW mirrors tui/grade.go scoreFirewallSub: managed DROP/REJECT
// velocity vs a 10 drops/sec comfort line. Returns a neutral 100 when no
// managed blocking rule carries a counter (the caller marks it as no-data so
// it's excluded from the weighted total).
func scoreFirewallW(dropRate float64, hasDropRules bool) int {
	if !hasDropRules {
		return 100
	}
	return subScore(dropRate, 10)
}

func hasRTTDataW(ts []metrics.TargetStats) bool {
	for _, t := range ts {
		if t.AvgRTT > 0 {
			return true
		}
	}
	return false
}

func hasDNSDataW(ds []metrics.DNSStats) bool {
	for _, d := range ds {
		if d.AvgLatency > 0 {
			return true
		}
	}
	return false
}

func hasStabDataW(ifs []netops.IfaceInfo) bool {
	for _, ifi := range ifs {
		if ifi.Name == "lo" {
			continue
		}
		if ifi.RxPackets+ifi.TxPackets > 0 {
			return true
		}
	}
	return false
}

func hasWiFiDataW(snaps []collectors.WiFiSnapshot) bool {
	for _, s := range snaps {
		if s.Associated && s.Signal != 0 {
			return true
		}
	}
	return false
}

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

func scoreLANW(ts []metrics.TargetStats, th config.Thresholds) int {
	if len(ts) == 0 {
		return 100
	}
	loss := subScore(avgLoss(ts), th.PacketLossPct)
	rtt := subScore(avgRTT(ts), 50) // LAN comfort line tighter than WAN
	return (loss + rtt) / 2
}

func scoreHTTPW(ts []metrics.TargetStats) int {
	if len(ts) == 0 {
		return 100
	}
	fail := subScore(avgLoss(ts), 2.0)
	ttfb := subScore(avgRTT(ts), 500)
	return (fail + ttfb) / 2
}

func scoreStabilityW(ifs []netops.IfaceInfo) int {
	var totalErrors, totalPackets uint64
	for _, ifi := range ifs {
		if ifi.Name == "lo" {
			continue
		}
		totalErrors += ifi.RxErrors + ifi.TxErrors + ifi.RxDropped + ifi.TxDropped
		totalPackets += ifi.RxPackets + ifi.TxPackets
	}
	if totalPackets == 0 {
		return 100
	}
	pct := float64(totalErrors) / float64(totalPackets) * 100
	return subScore(pct, 0.1)
}

func scoreWiFiW(snaps []collectors.WiFiSnapshot) int {
	if len(snaps) == 0 {
		return 100
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
		return 100
	}
	avg := sum / float64(n)
	score := int((avg+90)/30*100 + 0.5)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
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

// ---- target classification (mirrors tui/grade.go) ----

func filterT(ts []metrics.TargetStats, pred func(string) bool) []metrics.TargetStats {
	out := make([]metrics.TargetStats, 0, len(ts))
	for _, t := range ts {
		if pred(t.Target) {
			out = append(out, t)
		}
	}
	return out
}

func isHTTPTargetW(t string) bool {
	return strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://")
}

func isLANTargetW(t string) bool {
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

func isWANTargetW(t string) bool {
	if isHTTPTargetW(t) {
		return false
	}
	for _, p := range []string{"trace:", "wifi:", "bufferbloat:"} {
		if strings.HasPrefix(t, p) {
			return false
		}
	}
	if isLANTargetW(t) {
		return false
	}
	return true
}

// ---- averages ----

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
