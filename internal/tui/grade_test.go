package tui

import (
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/collectors"
	"github.com/noahzmr/testudo/internal/config"
	"github.com/noahzmr/testudo/internal/metrics"
	"github.com/noahzmr/testudo/internal/quality"
)

// healthyWAN is one good WAN target so the grade has a spine to start from.
func healthyWAN() []metrics.TargetStats {
	return []metrics.TargetStats{{Target: "1.1.1.1", AvgRTT: 10 * time.Millisecond, LossPct: 0}}
}

// TestDNSFailureCountsInGrade locks in the fix for the blind spot where DNS
// timeouts ("context deadline exceeded"), recorded as failures with no latency
// sample, were invisible to a latency-only DNS sub-score.
func TestDNSFailureCountsInGrade(t *testing.T) {
	th := config.DefaultThresholds()
	qc := quality.GradeContext{}

	// A resolver that answers every query fast -> DNS dimension is healthy.
	good := []metrics.DNSStats{{Name: "example.com", Queries: 10, Failures: 0, AvgLatency: 15 * time.Millisecond}}
	gGood := ComputeGrade(healthyWAN(), good, nil, nil, 0, false, L3GradeInput{}, TCPGradeInput{}, ThroughputGradeInput{}, th, qc)
	if !gGood.DNS.HasData || gGood.DNS.Score < 90 {
		t.Fatalf("healthy DNS: want HasData with high score, got HasData=%v score=%d", gGood.DNS.HasData, gGood.DNS.Score)
	}

	// A resolver where every query times out: Failures>0, AvgLatency==0. The
	// dimension must still register as data and score near zero - previously it
	// dropped out entirely and the grade looked fine.
	failing := []metrics.DNSStats{{Name: "example.com", Queries: 10, Failures: 10, AvgLatency: 0}}
	gFail := ComputeGrade(healthyWAN(), failing, nil, nil, 0, false, L3GradeInput{}, TCPGradeInput{}, ThroughputGradeInput{}, th, qc)
	if !gFail.DNS.HasData {
		t.Fatalf("all-failing DNS must count as measured data, got HasData=false")
	}
	if gFail.DNS.Score > 10 {
		t.Errorf("all-failing DNS should score ~0, got %d", gFail.DNS.Score)
	}
	if gFail.Score >= gGood.Score {
		t.Errorf("failing DNS should lower the overall grade: fail=%d good=%d", gFail.Score, gGood.Score)
	}
}

// TestConnectStallPenalty locks in that sockets wedged in the TCP handshake
// (connections failing to establish) drop the grade even when the established-
// flow averages look fine.
func TestConnectStallPenalty(t *testing.T) {
	th := config.DefaultThresholds()
	qc := quality.GradeContext{}
	dns := []metrics.DNSStats{{Name: "example.com", Queries: 5, AvgLatency: 15 * time.Millisecond}}

	base := ComputeGrade(healthyWAN(), dns, nil, nil, 0, false, L3GradeInput{}, TCPGradeInput{}, ThroughputGradeInput{}, th, qc)
	stalled := ComputeGrade(healthyWAN(), dns, nil, nil, 0, false, L3GradeInput{},
		TCPGradeInput{ConnectStall: true, StalledConn: 3}, ThroughputGradeInput{}, th, qc)

	if !stalled.ConnectStall || stalled.ConnectPenalty != connectStallPenalty {
		t.Fatalf("expected ConnectStall with penalty %d, got stall=%v penalty=%d",
			connectStallPenalty, stalled.ConnectStall, stalled.ConnectPenalty)
	}
	if stalled.Score != base.Score-connectStallPenalty {
		t.Errorf("connect stall should subtract %d: base=%d stalled=%d",
			connectStallPenalty, base.Score, stalled.Score)
	}
	if stalled.StalledConnects != 3 {
		t.Errorf("StalledConnects not propagated: got %d", stalled.StalledConnects)
	}
}

// TestActiveTrafficFaultPenalties locks in that connection resets, send-stalls,
// and ephemeral-port exhaustion each drop the grade by their fixed penalty and
// stack.
func TestActiveTrafficFaultPenalties(t *testing.T) {
	th := config.DefaultThresholds()
	qc := quality.GradeContext{}
	dns := []metrics.DNSStats{{Name: "example.com", Queries: 5, AvgLatency: 15 * time.Millisecond}}
	base := ComputeGrade(healthyWAN(), dns, nil, nil, 0, false, L3GradeInput{}, TCPGradeInput{}, ThroughputGradeInput{}, th, qc)

	cases := []struct {
		name    string
		in      TCPGradeInput
		penalty int
		check   func(NetworkGrade) bool
	}{
		{"reset", TCPGradeInput{ConnResetSpike: true, ConnFailRate: 9}, connResetPenalty, func(g NetworkGrade) bool { return g.ConnResetSpike && g.ResetPenalty == connResetPenalty }},
		{"send-stall", TCPGradeInput{SendStall: true, SendStalls: 2}, sendStallPenalty, func(g NetworkGrade) bool { return g.SendStall && g.StallPenalty == sendStallPenalty }},
		{"ephemeral", TCPGradeInput{EphemeralExhaust: true, EphemeralUtil: 0.9}, ephemeralExhaustPenalty, func(g NetworkGrade) bool {
			return g.EphemeralExhaustion && g.EphemeralPenalty == ephemeralExhaustPenalty
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := ComputeGrade(healthyWAN(), dns, nil, nil, 0, false, L3GradeInput{}, tc.in, ThroughputGradeInput{}, th, qc)
			if !tc.check(g) {
				t.Fatalf("%s: flag/penalty not set as expected: %+v", tc.name, g)
			}
			if g.Score != base.Score-tc.penalty {
				t.Errorf("%s: want score %d, got %d", tc.name, base.Score-tc.penalty, g.Score)
			}
		})
	}

	// All three at once stack.
	all := ComputeGrade(healthyWAN(), dns, nil, nil, 0, false, L3GradeInput{},
		TCPGradeInput{ConnResetSpike: true, SendStall: true, EphemeralExhaust: true}, ThroughputGradeInput{}, th, qc)
	want := base.Score - connResetPenalty - sendStallPenalty - ephemeralExhaustPenalty
	if want < 0 {
		want = 0
	}
	if all.Score != want {
		t.Errorf("stacked penalties: want %d, got %d", want, all.Score)
	}
}

// TestWiFiBlendCatchesFailingLink locks in that a strong-signal link with a
// high TX-failure rate scores worse than a clean strong-signal link - i.e. the
// grade looks beyond raw RSSI.
func TestWiFiBlendCatchesFailingLink(t *testing.T) {
	clean := collectors.WiFiSnapshot{
		Iface: "wlan0", Associated: true, Signal: -55, Noise: -95,
		TxPackets: 10000, TxFailed: 0,
	}
	failing := clean
	failing.TxFailed = 4000 // ~29% TX failure despite the same strong signal

	cs := scoreWiFi([]collectors.WiFiSnapshot{clean})
	fs := scoreWiFi([]collectors.WiFiSnapshot{failing})
	if !cs.HasData || !fs.HasData {
		t.Fatal("expected wifi sub-score to have data")
	}
	if fs.Score >= cs.Score {
		t.Errorf("failing link should score lower than clean: clean=%d failing=%d", cs.Score, fs.Score)
	}
}

// TestThroughputScoring covers the achievable-vs-expected speed sub-score:
// unconfigured or idle links report no data; an idle link is never penalised;
// a link that can't reach its rated speed scores low; the worse direction wins.
func TestThroughputScoring(t *testing.T) {
	cases := []struct {
		name                     string
		down, up, expDown, expUp float64
		wantData                 bool
		wantMin, wantMax         int
	}{
		{"unconfigured", 50, 10, 0, 0, false, 0, 0},
		{"idle below floor", 5, 0, 100, 0, false, 0, 0},        // 5 < 10% of 100 -> no demand seen
		{"full speed", 92, 0, 100, 0, true, 100, 100},          // >=90% rated -> 100
		{"half speed", 45, 0, 100, 0, true, 45, 55},            // ~50
		{"worst direction wins", 92, 9, 100, 20, true, 45, 55}, // up at 9/18 ~50 drives it
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := scoreThroughputSub(c.down, c.up, c.expDown, c.expUp)
			if s.HasData != c.wantData {
				t.Fatalf("HasData = %v, want %v (%+v)", s.HasData, c.wantData, s)
			}
			if c.wantData && (s.Score < c.wantMin || s.Score > c.wantMax) {
				t.Errorf("score %d outside [%d,%d]", s.Score, c.wantMin, c.wantMax)
			}
		})
	}
}

// TestFirewallNotWeighted confirms firewall DROP velocity no longer moves the
// Network Quality grade (it is policy, not network quality).
func TestFirewallNotWeighted(t *testing.T) {
	th := config.DefaultThresholds()
	qc := quality.GradeContext{}
	dns := []metrics.DNSStats{{Name: "example.com", Queries: 5, AvgLatency: 15 * time.Millisecond}}

	noFw := ComputeGrade(healthyWAN(), dns, nil, nil, 0, false, L3GradeInput{}, TCPGradeInput{}, ThroughputGradeInput{}, th, qc)
	heavyFw := ComputeGrade(healthyWAN(), dns, nil, nil, 5000, true, L3GradeInput{}, TCPGradeInput{}, ThroughputGradeInput{}, th, qc)
	if noFw.Score != heavyFw.Score {
		t.Errorf("firewall drops must not change the grade: no-fw=%d heavy-fw=%d", noFw.Score, heavyFw.Score)
	}
}

// TestLossReflectsTCP confirms the Loss sub-score follows TCP retransmissions
// when ICMP probes look clean - ping surviving a path that drops TCP must not
// hide the loss real connections experience.
func TestLossReflectsTCP(t *testing.T) {
	th := config.DefaultThresholds()
	qc := quality.GradeContext{}
	dns := []metrics.DNSStats{{Name: "example.com", Queries: 5, AvgLatency: 15 * time.Millisecond}}

	// Clean ICMP target (0% loss) but 12% TCP retransmissions.
	clean := ComputeGrade(healthyWAN(), dns, nil, nil, 0, false, L3GradeInput{}, TCPGradeInput{}, ThroughputGradeInput{}, th, qc)
	lossy := ComputeGrade(healthyWAN(), dns, nil, nil, 0, false, L3GradeInput{},
		TCPGradeInput{FlowRTXRate: 12, HasFlowRTX: true}, ThroughputGradeInput{}, th, qc)

	if !lossy.LossHasTCP || lossy.LossTCPPct != 12 {
		t.Fatalf("expected TCP loss component 12%%, got hasTCP=%v tcp=%.1f", lossy.LossHasTCP, lossy.LossTCPPct)
	}
	if lossy.Loss.Score >= clean.Loss.Score {
		t.Errorf("TCP retransmissions must drag the Loss sub-score: clean=%d lossy=%d", clean.Loss.Score, lossy.Loss.Score)
	}
	if lossy.Loss.Value < 12 {
		t.Errorf("loss value should reflect the 12%% TCP loss, got %.1f", lossy.Loss.Value)
	}
}
