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
	"github.com/noahzmr/testudo/internal/quality"
	"github.com/noahzmr/testudo/internal/telemetry"
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

	// Firewall - DROP/REJECT velocity across managed blocking rules. A
	// sudden spike of drops against an active flow is connectivity the user
	// feels ("only some services work"). Neutral 100 when no managed DROP
	// rules carry counters.
	Firewall subScore

	// NAT - conntrack table utilisation (live entries / nf_conntrack_max).
	// Near-saturation means new connections start failing host-wide.
	// Neutral 100 when nf_conntrack_max is unknown.
	NAT subScore

	// Congestion - flow-weighted per-flow retransmission rate from tcp_info
	// (INET_DIAG / eBPF). A far better congestion signal than the system-wide
	// /proc/net/snmp number: busy flows dominate the weighting. Neutral 100
	// when no active TCP flows carry telemetry.
	Congestion subScore

	// Throughput - best recently-observed download/upload vs the operator's
	// configured expected link speed. Neutral 100 (no data) when expected speeds
	// aren't set or the link has been idle, so it never penalises an unused link.
	Throughput subScore

	// WireGuard - tunnel health: fraction of peers with a fresh handshake.
	// Neutral 100 (no data) when no WG device exists or its state is unreadable.
	WireGuard subScore

	// Loss breakdown: the Loss sub-score follows the worse of ICMP/probe loss and
	// the TCP retransmission rate. These carry the components (plus the live
	// connection-failure rate) so the dashboard can explain why loss is high even
	// when ping looks clean. LossHasTCP gates whether the TCP figures are real.
	LossICMPPct      float64
	LossTCPPct       float64
	LossConnFailRate float64
	LossHasTCP       bool

	// PMTU black-hole: a frag-needed condition (a flow retransmitting without
	// forward progress) is a real "some sites won't load" fault. When set, the
	// grade takes a fixed penalty and the letter reflects it. PMTUPenalty is
	// the points shaved off so renderers can explain the drop.
	PMTUBlackhole bool
	PMTUPenalty   int

	// ConnectStall: one or more sockets are wedged in the TCP handshake
	// (SYN_SENT across ticks) - connections that can't establish, the
	// "waiting for connection" timeout users feel. Like PMTU it takes a fixed
	// penalty so the letter reflects it even when established-flow averages look
	// fine. StalledConnects is the live count for the operator-facing note.
	ConnectStall    bool
	ConnectPenalty  int
	StalledConnects int

	// ConnResetSpike: failed-connect + reset rate is abnormally high (connections
	// keep dropping). SendStall: a connection is frozen with data wedged in its
	// send queue (peer zero-window / path block). EphemeralExhaustion: local
	// ephemeral ports are near-exhausted (new outbound connections start failing).
	// Each takes a fixed penalty; the *Rate/*Util values back the operator note.
	ConnResetSpike bool
	ConnResetRate  float64
	ResetPenalty   int

	SendStall    bool
	SendStalls   int
	StallPenalty int

	EphemeralExhaustion bool
	EphemeralUtil       float64
	EphemeralPenalty    int

	// Baseline-relative early warning: the worst current÷normal RTT ratio
	// across WAN targets that have a learned baseline. BaselinePenalty is the
	// points the modifier shaved off the absolute score. HasBaseline is false
	// on first run / new targets → no modifier was applied.
	BaselineRatio   float64
	BaselinePenalty int
	HasBaseline     bool

	// Bufferbloat A–F letter from the idle-vs-loaded delta. HasBufferbloat is
	// false until the collector has produced an idle/loaded pair.
	BufferbloatGrade string
	HasBufferbloat   bool

	// ISP-degradation isolation: which path segment owns the problem, plus a
	// human verdict. HasFault is false when the trace path is unavailable.
	FaultLayer   string
	FaultVerdict string
	HasFault     bool
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
	fwDropRate float64,
	fwHasDropRules bool,
	l3 L3GradeInput,
	tcp TCPGradeInput,
	tp ThroughputGradeInput,
	th config.Thresholds,
	qc quality.GradeContext,
) NetworkGrade {
	// Weights sum to 1.0 and are tuned so the dimensions that actually describe
	// connection quality dominate: end-to-end reachability (loss/RTT/jitter),
	// achievable throughput, and per-flow congestion together are ~60% of the
	// grade. DNS/LAN/HTTP/stability/WiFi fill in the experience. Conntrack
	// exhaustion stays small (it only bites at saturation). Firewall DROP
	// velocity is deliberately NOT weighted: a blocked packet is a policy
	// decision, not a statement about the network's quality - it remains
	// visible as an alert and on the Firewall tab, but never moves the grade.
	const (
		wLoss       = 0.18
		wRTT        = 0.15
		wThroughput = 0.12
		wCongestion = 0.10
		wDNS        = 0.10
		wLAN        = 0.10
		wStab       = 0.08
		wJitter     = 0.05
		wHTTP       = 0.05
		wWiFi       = 0.05
		wNAT        = 0.02
		// WireGuard tunnel health. Small weight (~5%) and neutral (excluded) when
		// no WG device exists, so it only bites when a configured tunnel degrades.
		// Renormalised at runtime alongside the others, so the totals need not be
		// exactly 1.0.
		wWireGuard = 0.05
	)

	wan := filterTargets(targets, isWANTarget)
	lan := filterTargets(targets, isLANTarget)
	httpT := filterTargets(targets, isHTTPTarget)

	// Loss blends ICMP/probe loss with TCP-layer loss: a retransmission is a
	// lost segment, and TCP connections fail far more often than ICMP echo
	// survives a lossy/middlebox path. The sub-score follows the worse of the
	// two so a clean ping can't hide failing connections; the components are
	// kept for the detailed breakdown.
	loss := scoreLossSub(wan, th.PacketLossPct, tcp)
	rtt := scoreRTTSub(wan, th.RTTMs)
	// On a busy host the connection the user actually cares about may be worse
	// than the probe target; let the worst active-flow RTT sharpen the RTT
	// sub-score downward (never upward - probes still set the floor).
	if tcp.HasWorstRTT {
		wf := scoreFromMetric("rtt", tcp.WorstFlowRTTms, th.RTTMs, "ms")
		if !rtt.HasData || wf.Score < rtt.Score {
			rtt = wf
		}
	}
	jit := scoreJitterSub(wan, th.JitterMs)
	dnsLat := scoreDNSSub(dns, th.DNSLatencyMs)
	lanScore := scoreLAN(lan, l3.DuplicateIPs, th)
	httpScore := scoreHTTP(httpT)
	stabScore := scoreStability(ifaces, l3.NeighStaleRatio, l3.HasNeigh,
		l3.FlapRate, l3.RouteChurn, l3.HasNetlinkWatch)
	wifiScore := scoreWiFi(wifi)
	fwScore := scoreFirewallSub(fwDropRate, fwHasDropRules)
	natScore := scoreNATSub(l3.ConntrackUtil, l3.HasConntrack)
	congScore := scoreCongestionSub(tcp.FlowRTXRate, tcp.HasFlowRTX, th.RetransmissionsPct)
	tpScore := scoreThroughputSub(tp.PeakDownMbps, tp.PeakUpMbps, th.ExpectedDownMbps, th.ExpectedUpMbps)
	wgScore := scoreWireGuardSub(qc)

	// Renormalize over sub-scores that actually have data. A sub-score
	// with HasData=false drops out of both the numerator and the
	// denominator so "we haven't measured X yet" never inflates (or
	// deflates) the grade. Firewall is intentionally absent: drops are policy,
	// not network quality, so the sub-score is computed for display only.
	parts := []struct {
		w float64
		s subScore
	}{
		{wLoss, loss}, {wRTT, rtt}, {wThroughput, tpScore}, {wCongestion, congScore},
		{wDNS, dnsLat}, {wLAN, lanScore}, {wStab, stabScore}, {wJitter, jit},
		{wHTTP, httpScore}, {wWiFi, wifiScore}, {wNAT, natScore}, {wWireGuard, wgScore},
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
		g := NetworkGrade{
			Score: 0, Letter: "?", Verdict: "Awaiting probes",
			HasData: false,
			Loss:    loss, RTT: rtt, Jitter: jit, DNS: dnsLat,
			LAN: lanScore, HTTP: httpScore, Stab: stabScore, WiFi: wifiScore,
			Firewall: fwScore, NAT: natScore, Congestion: congScore, Throughput: tpScore,
			WireGuard:     wgScore,
			PMTUBlackhole: tcp.PMTUBlackhole,
			ConnectStall:  tcp.ConnectStall, StalledConnects: tcp.StalledConn,
			ConnResetSpike: tcp.ConnResetSpike, ConnResetRate: tcp.ConnFailRate,
			SendStall: tcp.SendStall, SendStalls: tcp.SendStalls,
			EphemeralExhaustion: tcp.EphemeralExhaust, EphemeralUtil: tcp.EphemeralUtil,
		}
		attachQualityContext(&g, wan, qc)
		attachLossDetail(&g, wan, tcp)
		return g
	}
	score := int(weighted/totalW + 0.5)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	g := NetworkGrade{
		Score: score, HasData: true,
		Loss: loss, RTT: rtt, Jitter: jit, DNS: dnsLat,
		LAN: lanScore, HTTP: httpScore, Stab: stabScore, WiFi: wifiScore,
		Firewall: fwScore, NAT: natScore, Congestion: congScore, Throughput: tpScore,
		WireGuard:     wgScore,
		PMTUBlackhole: tcp.PMTUBlackhole,
		ConnectStall:  tcp.ConnectStall, StalledConnects: tcp.StalledConn,
		ConnResetSpike: tcp.ConnResetSpike, ConnResetRate: tcp.ConnFailRate,
		SendStall: tcp.SendStall, SendStalls: tcp.SendStalls,
		EphemeralExhaustion: tcp.EphemeralExhaust, EphemeralUtil: tcp.EphemeralUtil,
	}
	// Baseline-relative early warning: nudge the absolute score down when tonight
	// is far worse than the learned normal, then derive the letter from the
	// modified score (so the operator sees the warning in the letter, not just a
	// badge). Empty baseline → zero penalty, grade unchanged.
	attachQualityContext(&g, wan, qc)
	attachLossDetail(&g, wan, tcp)
	g.Score -= g.BaselinePenalty
	// PMTU black-hole is a real "some sites won't load" fault: a fixed penalty
	// on top of the weighted score so the letter reflects it even when the
	// averages look fine.
	if g.PMTUBlackhole {
		g.PMTUPenalty = pmtuBlackholePenalty
		g.Score -= g.PMTUPenalty
	}
	// Connections that can't even establish are a hard, user-visible fault:
	// a fixed penalty on top of the weighted score so the letter drops even
	// when the established-flow averages still look healthy.
	if g.ConnectStall {
		g.ConnectPenalty = connectStallPenalty
		g.Score -= g.ConnectPenalty
	}
	// Connections actively dropping, frozen, or unable to start are each their
	// own user-visible fault; like PMTU/connect-stall they apply on top of the
	// weighted score and stack, clamped at zero.
	if g.ConnResetSpike {
		g.ResetPenalty = connResetPenalty
		g.Score -= g.ResetPenalty
	}
	if g.SendStall {
		g.StallPenalty = sendStallPenalty
		g.Score -= g.StallPenalty
	}
	if g.EphemeralExhaustion {
		g.EphemeralPenalty = ephemeralExhaustPenalty
		g.Score -= g.EphemeralPenalty
	}
	if g.Score < 0 {
		g.Score = 0
	}
	g.Letter, g.Verdict = letterAndVerdict(g.Score)
	return g
}

// pmtuBlackholePenalty is the fixed score reduction applied when a frag-needed
// / PMTU black-hole condition is active.
const pmtuBlackholePenalty = 15

// connectStallPenalty is the fixed score reduction applied when one or more
// sockets are wedged in the TCP handshake (connections failing to establish).
const connectStallPenalty = 20

// Fixed penalties for the active-traffic connection faults, mirrored in the web
// grade. Resets (connections dropping) and ephemeral exhaustion (new ones can't
// start) bite harder than a transient send-stall.
const (
	connResetPenalty        = 15
	sendStallPenalty        = 10
	ephemeralExhaustPenalty = 15
)

// attachQualityContext folds the baseline ratio, bufferbloat letter, and ISP
// isolation verdict onto the grade. It computes (but does not apply) the
// baseline penalty; the caller subtracts it so the "awaiting probes" path can
// surface context without a misleading penalty.
// attachLossDetail records the loss breakdown (ICMP vs TCP retransmits, plus
// the live connection-failure rate) onto the grade so the dashboards can show
// why loss is high even when ping is clean.
func attachLossDetail(g *NetworkGrade, wan []metrics.TargetStats, tcp TCPGradeInput) {
	_, icmp, tcpLoss, _ := lossComponents(wan, tcp)
	g.LossICMPPct = icmp
	g.LossTCPPct = tcpLoss
	g.LossHasTCP = tcp.HasFlowRTX
	g.LossConnFailRate = tcp.ConnFailRate
}

func attachQualityContext(g *NetworkGrade, wan []metrics.TargetStats, qc quality.GradeContext) {
	current := make(map[string]float64, len(wan))
	for _, t := range wan {
		if t.AvgRTT > 0 {
			current[t.Target] = float64(t.AvgRTT) / float64(time.Millisecond)
		}
	}
	if ratio, ok := quality.WorstBaselineRatio(qc.Baselines, current); ok {
		g.BaselineRatio = ratio
		g.HasBaseline = true
		if g.HasData {
			g.BaselinePenalty = quality.GradeModifier(ratio, ok)
		}
	}
	g.BufferbloatGrade = qc.BufferbloatGrade
	g.HasBufferbloat = qc.HasBufferbloat
	g.FaultLayer = string(qc.FaultLayer)
	g.FaultVerdict = qc.FaultVerdict
	g.HasFault = qc.HasFault
}

// L3GradeInput carries the conntrack/neighbour signals into the grade. The
// zero value is the neutral case (no conflicts, no neighbours, no conntrack),
// so a host lacking the signal maps to neutral 100.
type L3GradeInput struct {
	DuplicateIPs    int     // active IP conflicts -> hard LAN penalty
	NeighStaleRatio float64 // (FAILED+INCOMPLETE)/total neighbours -> Stability
	HasNeigh        bool
	ConntrackUtil   float64 // live entries / nf_conntrack_max -> NAT sub-score
	HasConntrack    bool

	// Push-derived stability inputs from the RTNETLINK watcher. FlapRate is
	// link transitions per minute (a flapping NIC / cable); RouteChurn is
	// default-route changes per minute (uplink / ISP instability). Both feed
	// the Stab sub-score. HasNetlinkWatch=false maps them to neutral.
	FlapRate        float64
	RouteChurn      float64
	HasNetlinkWatch bool
}

// l3InputFrom adapts the neighbour/conntrack and netlink-watch collectors'
// signals into the grade input. Returns the neutral zero value when both
// collectors are absent.
func l3InputFrom(nc *collectors.NeighConntrackCollector, nw *collectors.NetlinkWatchCollector) L3GradeInput {
	var in L3GradeInput
	if nc != nil {
		s := nc.Signal()
		in.DuplicateIPs = s.DuplicateIPs
		in.NeighStaleRatio = s.StaleRatio
		in.HasNeigh = s.HasNeigh
		in.ConntrackUtil = s.ConntrackUtil
		in.HasConntrack = s.HasConntrack
	}
	if nw != nil {
		s := nw.Signal()
		in.FlapRate = s.FlapRate
		in.RouteChurn = s.RouteChurn
		in.HasNetlinkWatch = s.HasData
	}
	return in
}

// TCPGradeInput carries the per-flow TCP telemetry signals into the grade. The
// zero value is the neutral case (no active TCP flows), mapping to neutral-100
// for congestion and leaving the RTT sub-score on the probe target.
type TCPGradeInput struct {
	FlowRTXRate    float64 // flow-weighted retransmission rate, percent
	HasFlowRTX     bool    // false when no active TCP flows -> neutral
	WorstFlowRTTms float64 // worst active-flow smoothed RTT, ms
	HasWorstRTT    bool
	PMTUBlackhole  bool // a flow currently shows the frag-needed shape
	ConnectStall   bool // a socket is wedged in the TCP handshake right now
	StalledConn    int  // count of sockets stuck mid-handshake

	ConnResetSpike   bool    // failed-connect + reset rate past comfort line
	ConnFailRate     float64 // failed/refused connects + resets per second
	SendStall        bool    // a connection is send-stalled (zero-window) right now
	SendStalls       int     // count of send-stalled connections
	EphemeralExhaust bool    // ephemeral local ports near-exhausted
	EphemeralUtil    float64 // ephemeral-port utilisation (0..1)
}

// tcpInputFrom adapts the per-flow TCP telemetry collector and the flow table
// into the grade input: the byte-weighted RTX rate across flows carrying
// telemetry, the worst flow RTT, and the live PMTU black-hole flag. Returns the
// neutral zero value when telemetry is absent.
func tcpInputFrom(ti *collectors.TCPInfoCollector, fl *flows.Aggregator) TCPGradeInput {
	var in TCPGradeInput
	if ti == nil || fl == nil {
		return in
	}
	stat := ti.Status()
	in.PMTUBlackhole = stat.PMTUBlackhole
	in.ConnectStall = stat.ConnectStall
	in.StalledConn = stat.StalledConn
	in.ConnResetSpike = stat.ConnResetSpike
	in.ConnFailRate = stat.ConnFailRate
	in.SendStall = stat.SendStall
	in.SendStalls = stat.SendStalls
	in.EphemeralExhaust = stat.EphemeralExhaust
	in.EphemeralUtil = stat.EphemeralUtil

	var samples []telemetry.RTXSample
	var rtts []float64
	for _, f := range fl.Snapshot() {
		if !f.HasTCP() {
			continue
		}
		samples = append(samples, telemetry.RTXSample{Rate: f.TCP.RetransRate, Bytes: f.Bytes})
		rtts = append(rtts, f.TCP.RTTms())
	}
	if rate, ok := telemetry.FlowWeightedRTX(samples); ok {
		in.FlowRTXRate = rate
		in.HasFlowRTX = true
	}
	if worst, ok := telemetry.WorstFlowRTT(rtts); ok {
		in.WorstFlowRTTms = worst
		in.HasWorstRTT = true
	}
	return in
}

// ThroughputGradeInput carries the best recently-observed download/upload
// throughput (Mbit/s) into the grade. The zero value is neutral: with no
// observed throughput the Throughput sub-score reports no data and is excluded.
type ThroughputGradeInput struct {
	PeakDownMbps float64
	PeakUpMbps   float64
}

// throughputInputFrom reads the recent peak download/upload throughput from the
// bandwidth history. Returns the neutral zero value when history is absent.
func throughputInputFrom(bw *metrics.BandwidthHistory) ThroughputGradeInput {
	var in ThroughputGradeInput
	if bw == nil {
		return in
	}
	in.PeakDownMbps, in.PeakUpMbps = bw.RecentPeakMbps()
	return in
}

// throughputActivityFloor is the fraction of the expected speed a direction
// must recently have reached for it to be judged at all. Below it the link is
// treated as idle in that direction (no demand observed) and excluded, so a
// quiet link is never scored as "slow".
const throughputActivityFloor = 0.10

// throughputGoodFraction is the share of the rated speed treated as "full
// speed": real links rarely hit 100% of their provisioned rate (protocol
// overhead, ISP shaping), so reaching 90% scores 100.
const throughputGoodFraction = 0.90

// scoreThroughputSub scores the best recently-observed throughput against the
// configured expected link speed, per direction, and returns the worse of the
// two directions that have both an expected speed and recent activity. Reports
// no data when nothing is configured or the link has been idle.
func scoreThroughputSub(peakDown, peakUp, expDown, expUp float64) subScore {
	worst := -1
	var worstVal float64
	consider := func(peak, exp float64) {
		if exp <= 0 || peak < exp*throughputActivityFloor {
			return // unconfigured, or no meaningful transfer to judge
		}
		ratio := peak / (exp * throughputGoodFraction)
		s := int(ratio*100 + 0.5)
		if s > 100 {
			s = 100
		}
		if s < 0 {
			s = 0
		}
		if worst == -1 || s < worst {
			worst, worstVal = s, peak
		}
	}
	consider(peakDown, expDown)
	consider(peakUp, expUp)
	if worst == -1 {
		return subScore{Name: "tput", Unit: "Mbps", OK: true}
	}
	return subScore{Name: "tput", Score: worst, Value: worstVal, Unit: "Mbps", OK: worst >= 50, HasData: true}
}

// scoreCongestionSub maps the flow-weighted retransmission rate against the
// retransmission threshold. Neutral-100 with HasData=false when no active TCP
// flows carry telemetry, so a quiet host isn't graded on a fabricated zero.
func scoreCongestionSub(rate float64, has bool, threshold float64) subScore {
	if !has {
		return subScore{Name: "cong", Unit: "%", OK: true}
	}
	if threshold <= 0 {
		threshold = 5
	}
	return scoreFromMetric("cong", rate, threshold, "%")
}

// scoreNATSub maps conntrack utilisation to the NAT sub-score. Comfort line
// 70%: a half-full table is fine, near-saturation (where new connections
// start failing) drags the grade and lines up with the NAT-exhaustion
// anomaly. Neutral 100 when nf_conntrack_max is unknown.
func scoreNATSub(conntrackUtil float64, hasConntrack bool) subScore {
	if !hasConntrack {
		return subScore{Name: "nat", Unit: "%", OK: true}
	}
	return scoreFromMetric("nat", conntrackUtil*100, 70, "%")
}

// scoreWireGuardSub maps the WireGuard tunnel health carried in the grade
// context to a sub-score. Neutral 100 with HasData=false when no WG device
// exists or its state couldn't be read, so a host without WireGuard is never
// penalised (the sub-score drops out of the weighted grade entirely).
func scoreWireGuardSub(qc quality.GradeContext) subScore {
	if !qc.WGHasData {
		return subScore{Name: "wg", Unit: "peers", OK: true}
	}
	return subScore{
		Name: "wg", Score: qc.WGScore, Value: float64(qc.WGScore),
		Unit: "%", OK: qc.WGScore >= 80, HasData: true,
	}
}

// scoreFirewallSub maps the managed DROP/REJECT velocity to a sub-score.
// Comfort line: 10 drops/sec - a steady trickle is normal background noise;
// a sustained burst against an active flow is the connectivity fault the
// operator feels. HasData=false (neutral 100, excluded from the grade) when
// no managed blocking rule carries a counter.
func scoreFirewallSub(dropRate float64, hasDropRules bool) subScore {
	if !hasDropRules {
		return subScore{Name: "fw", Unit: "d/s", OK: true}
	}
	return scoreFromMetric("fw", dropRate, 10, "d/s")
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

// scoreLossSub computes the loss sub-score from the worse of ICMP/probe loss
// and the TCP retransmission rate (a retransmit is a lost segment). ICMP echo
// frequently survives a path that drops or resets TCP, so probe loss alone is
// optimistic - folding in TCP loss makes the figure reflect what connections
// actually experience. HasData=false (excluded) only when neither source has
// reported anything yet.
func scoreLossSub(ts []metrics.TargetStats, threshold float64, tcp TCPGradeInput) subScore {
	worst, _, _, has := lossComponents(ts, tcp)
	if !has {
		return subScore{Name: "loss", Unit: "%", OK: true}
	}
	return scoreFromMetric("loss", worst, threshold, "%")
}

// lossComponents returns the ICMP/probe loss %, the TCP retransmission loss %,
// their worst, and whether any source had data. Shared by the sub-score and the
// detailed breakdown so they never disagree.
func lossComponents(ts []metrics.TargetStats, tcp TCPGradeInput) (worst, icmp, tcpLoss float64, has bool) {
	if len(ts) > 0 {
		icmp = avgLossPct(ts)
		has = true
	}
	if tcp.HasFlowRTX {
		tcpLoss = tcp.FlowRTXRate
		has = true
	}
	worst = icmp
	if tcpLoss > worst {
		worst = tcpLoss
	}
	return worst, icmp, tcpLoss, has
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

// scoreDNSSub computes the DNS sub-score from both latency and failure rate.
//
// A DNS timeout ("context deadline exceeded") is recorded as a failure with no
// latency sample (see metrics.RecordDNS), so a latency-only score is blind to
// failing resolvers - if every query times out, AvgLatency stays 0 and the
// whole dimension would silently drop out of the grade. We therefore blend the
// failure rate (5% comfort line) with latency, and treat any query activity -
// success or failure - as data so timeouts always count.
func scoreDNSSub(ds []metrics.DNSStats, threshold float64) subScore {
	if !hasDNSActivity(ds) {
		return subScore{Name: "dns", Unit: "ms", OK: true}
	}
	fail := scoreFromMetric("dns", avgDNSFailPct(ds), 5, "%")
	if !hasDNSData(ds) {
		// Queries happened but none succeeded: score on the failure rate alone,
		// surfaced as a percentage so the bar reads "100.0%" rather than "-".
		return fail
	}
	lat := scoreFromMetric("dns", avgDNSms(ds), threshold, "ms")
	return subScore{
		Name: "dns", Score: (lat.Score + fail.Score) / 2,
		Value: lat.Value, Unit: "ms", OK: lat.OK && fail.OK, HasData: true,
	}
}

// scoreLAN blends LAN loss and LAN RTT into a single sub-score. LAN
// RTT comfort line is tighter than WAN (typical LAN ping is <5ms).
// HasData=false when no LAN targets exist.
// scoreLAN blends LAN loss and LAN RTT, then applies a hard penalty for any
// active duplicate-IP conflict - a conflict is its own measured LAN fault, so
// it forces HasData=true even with no LAN ping targets.
func scoreLAN(ts []metrics.TargetStats, dupIPs int, th config.Thresholds) subScore {
	if len(ts) == 0 && dupIPs == 0 {
		return subScore{Name: "lan", Unit: "ms", OK: true}
	}
	score := 100
	value := 0.0
	ok := true
	if len(ts) > 0 {
		lossPart := scoreFromMetric("lan-loss", avgLossPct(ts), th.PacketLossPct, "%")
		// LAN RTT threshold: 50ms is already concerning on a switched LAN.
		rttPart := scoreFromMetric("lan-rtt", avgRTTms(ts), 50, "ms")
		score = (lossPart.Score + rttPart.Score) / 2
		value = rttPart.Value
		ok = lossPart.OK && rttPart.OK
	}
	if dupIPs > 0 {
		// Two hosts fighting over an address = intermittent connectivity.
		// One conflict drops the LAN score hard; multiple, harder.
		penalty := 60
		if dupIPs > 1 {
			penalty = 80
		}
		if score -= penalty; score < 20 {
			score = 20
		}
		ok = false
	}
	if score < 0 {
		score = 0
	}
	return subScore{Name: "lan", Score: score, Value: value, Unit: "ms", OK: ok, HasData: true}
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
// scoreStability blends the kernel interface error/drop ratio with the
// neighbour unreachable ratio (FAILED+INCOMPLETE neighbours). A failed
// gateway neighbour is imminent connectivity loss, so it belongs in the same
// stability dimension as a flaky NIC. Either component may be absent; the
// score averages whatever has data, and is neutral (no data) when none does.
//
// The RTNETLINK push watcher adds two more components: link flap-rate
// (transitions/min) and default-route churn (changes/min). A 300ms flap that a
// 5s poll missed entirely now correctly drags the grade. Both use a 2/min
// comfort line - sustained flapping or an uplink that keeps re-electing its
// default route is a real instability the operator feels.
func scoreStability(ifs []netops.IfaceInfo, neighStaleRatio float64, hasNeigh bool,
	flapRate, routeChurn float64, hasNetlinkWatch bool) subScore {
	var totalErrors, totalPackets uint64
	for _, ifi := range ifs {
		if ifi.Name == "lo" {
			continue
		}
		totalErrors += ifi.RxErrors + ifi.TxErrors + ifi.RxDropped + ifi.TxDropped
		totalPackets += ifi.RxPackets + ifi.TxPackets
	}
	ifaceHasData := totalPackets > 0
	if !ifaceHasData && !hasNeigh && !hasNetlinkWatch {
		return subScore{Name: "stab", Unit: "%", OK: true}
	}

	sum, n := 0, 0
	value := 0.0
	ok := true
	if ifaceHasData {
		pct := float64(totalErrors) / float64(totalPackets) * 100
		s := scoreFromMetric("stab", pct, 0.1, "%")
		sum += s.Score
		n++
		value = pct
		ok = ok && s.OK
	}
	if hasNeigh {
		// Comfort line: 10% of neighbours unreachable.
		s := scoreFromMetric("neigh", neighStaleRatio*100, 10, "%")
		sum += s.Score
		n++
		if !ifaceHasData {
			value = neighStaleRatio * 100
		}
		ok = ok && s.OK
	}
	if hasNetlinkWatch {
		// Comfort line: 2 link flaps / minute.
		flap := scoreFromMetric("flap", flapRate, 2, "/min")
		// Comfort line: 2 default-route changes / minute (uplink churn).
		churn := scoreFromMetric("churn", routeChurn, 2, "/min")
		sum += flap.Score + churn.Score
		n += 2
		ok = ok && flap.OK && churn.OK
	}
	return subScore{Name: "stab", Score: sum / n, Value: value, Unit: "%", OK: ok, HasData: true}
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
	var blendSum, sigSum float64
	var nIface, nSig int
	for _, s := range snaps {
		if !s.Associated || s.Signal == 0 {
			continue
		}
		// Per-interface blend of every available quality signal, not just RSSI:
		// a strong signal with a high retry/failure rate or a collapsed SNR is
		// still a bad link, and signal alone would hide that.
		comps := []int{wifiSignalScore(s.Signal)}
		sigSum += s.Signal
		nSig++
		if s.Noise != 0 {
			comps = append(comps, wifiSNRScore(s.Signal-s.Noise))
		}
		if tot := s.TxPackets + s.TxFailed; tot >= 100 {
			failPct := float64(s.TxFailed) / float64(tot) * 100
			comps = append(comps, scoreFromMetric("wifi-fail", failPct, 5, "%").Score)
		}
		sum := 0
		for _, c := range comps {
			sum += c
		}
		blendSum += float64(sum) / float64(len(comps))
		nIface++
	}
	if nIface == 0 {
		return subScore{Name: "wifi", Unit: "dBm", OK: true}
	}
	score := int(blendSum/float64(nIface) + 0.5)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return subScore{Name: "wifi", Score: score, Value: sigSum / float64(nSig), Unit: "dBm", OK: score >= 50, HasData: true}
}

// wifiSignalScore maps RSSI (dBm) to 0..100: -60 excellent (100), -90 unusable (0).
func wifiSignalScore(dBm float64) int {
	return clampScore(int((dBm+90)/30*100 + 0.5))
}

// wifiSNRScore maps signal-to-noise margin (dB) to 0..100: >=30dB excellent,
// <=10dB unusable. SNR is a better "will this link actually carry data" signal
// than raw RSSI when the driver reports a noise floor.
func wifiSNRScore(snr float64) int {
	return clampScore(int((snr-10)/20*100 + 0.5))
}

func clampScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
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

// hasDNSActivity reports whether any DNS query has been attempted, successful
// or not. Unlike hasDNSData it counts pure-failure resolvers, so a totally
// failing resolver still registers as a measured (bad) dimension.
func hasDNSActivity(ds []metrics.DNSStats) bool {
	for _, d := range ds {
		if d.Queries > 0 {
			return true
		}
	}
	return false
}

// avgDNSFailPct is the mean failure percentage across resolvers that have been
// queried. A query that timed out ("context deadline exceeded") is a failure.
func avgDNSFailPct(ds []metrics.DNSStats) float64 {
	var sum float64
	var n int
	for _, d := range ds {
		if d.Queries > 0 {
			sum += float64(d.Failures) / float64(d.Queries) * 100
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
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

// avgLossPct averages the *live-window* loss across targets (not the
// cumulative-since-startup LossPct), so a current outage moves the grade
// instead of being diluted by hours of prior good history.
func avgLossPct(ts []metrics.TargetStats) float64 {
	if len(ts) == 0 {
		return 0
	}
	var sum float64
	for _, t := range ts {
		sum += t.WindowLossPct
	}
	return sum / float64(len(ts))
}

// avgRTTms averages the recent-window RTT across targets (RecentRTT, the mean
// of the last liveWindow successes), falling back to the 256-sample AvgRTT only
// when no recent sample exists. This keeps the RTT sub-score live rather than
// smoothing a current spike into minutes of history.
func avgRTTms(ts []metrics.TargetStats) float64 {
	if len(ts) == 0 {
		return 0
	}
	var sum float64
	var n int
	for _, t := range ts {
		rtt := t.RecentRTT
		if rtt <= 0 {
			rtt = t.AvgRTT
		}
		if rtt > 0 {
			sum += float64(rtt.Microseconds()) / 1000.0
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

// renderQualityContext renders the baseline-relative early warning, the
// bufferbloat letter, and the ISP-isolation verdict beneath the sub-score bars.
// Returns nil when none of the three signals have data, so the card stays quiet
// on a fresh / unmeasured host.
func renderQualityContext(g NetworkGrade) []string {
	var rows []string
	if g.HasBaseline {
		switch {
		case g.BaselinePenalty > 0:
			rows = append(rows, "  "+warnStyle.Render(
				fmt.Sprintf("Baseline: %.1f× normal ▲ (grade −%d, early warning)", g.BaselineRatio, g.BaselinePenalty)))
		case g.BaselineRatio <= 0.66:
			rows = append(rows, "  "+okStyle.Render(
				fmt.Sprintf("Baseline: %.1f× normal ▼ (better than usual)", g.BaselineRatio)))
		default:
			rows = append(rows, "  "+dimStyle.Render(
				fmt.Sprintf("Baseline: %.1f× normal (≈ usual for this hour)", g.BaselineRatio)))
		}
	}
	if g.HasBufferbloat {
		col := gradeColorForLetter(g.BufferbloatGrade)
		letter := lipgloss.NewStyle().Bold(true).Foreground(col).Render(g.BufferbloatGrade)
		rows = append(rows, "  "+dimStyle.Render("Bufferbloat: ")+letter+
			dimStyle.Render(" (idle-vs-loaded latency)"))
	}
	if g.HasFault {
		style := okStyle
		if g.FaultLayer != "" && g.FaultLayer != "none" {
			style = warnStyle
		}
		rows = append(rows, "  "+style.Render(g.FaultVerdict))
	}
	return rows
}

// gradeColorForLetter maps a bufferbloat A–F letter to its badge colour.
func gradeColorForLetter(letter string) lipgloss.Color {
	switch letter {
	case "A", "A+", "A-":
		return lipgloss.Color("42")
	case "B", "B+":
		return lipgloss.Color("220")
	case "C":
		return lipgloss.Color("214")
	default:
		return lipgloss.Color("196")
	}
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
