package quality

import (
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/probes"
)

func TestBaselineRatio(t *testing.T) {
	tests := []struct {
		name      string
		b         Rollup
		now       Sample
		wantRatio float64
		wantOK    bool
	}{
		{"empty baseline neutral", Rollup{Samples: 0, P50RTT: 0}, Sample{RTTms: 50}, 1.0, false},
		{"zero median neutral", Rollup{Samples: 10, P50RTT: 0}, Sample{RTTms: 50}, 1.0, false},
		{"no current neutral", Rollup{Samples: 10, P50RTT: 20}, Sample{RTTms: 0}, 1.0, false},
		{"3.1x worse", Rollup{Samples: 10, P50RTT: 18}, Sample{RTTms: 55.8}, 3.1, true},
		{"normal", Rollup{Samples: 10, P50RTT: 20}, Sample{RTTms: 21}, 1.05, true},
		{"better than normal", Rollup{Samples: 10, P50RTT: 40}, Sample{RTTms: 20}, 0.5, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ratio, ok := BaselineRatio(tt.b, tt.now)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if diff := ratio - tt.wantRatio; diff > 0.001 || diff < -0.001 {
				t.Errorf("ratio = %v, want %v", ratio, tt.wantRatio)
			}
		})
	}
}

func TestBaselineDescr(t *testing.T) {
	tests := []struct {
		name string
		b    Rollup
		now  Sample
		want string
	}{
		{"no baseline", Rollup{Samples: 0}, Sample{RTTms: 50}, ""},
		{"normal", Rollup{Samples: 5, P50RTT: 20}, Sample{RTTms: 22}, "≈ normal"},
		{"worse", Rollup{Samples: 5, P50RTT: 18}, Sample{RTTms: 55.8}, "3.1× normal ▲"},
		{"better", Rollup{Samples: 5, P50RTT: 40}, Sample{RTTms: 20}, "0.5× normal ▼"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BaselineDescr(tt.b, tt.now); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBufferbloatGrade(t *testing.T) {
	tests := []struct {
		delta time.Duration
		want  string
	}{
		{0, "A"},
		{29 * time.Millisecond, "A"},
		{30 * time.Millisecond, "B"},
		{99 * time.Millisecond, "B"},
		{100 * time.Millisecond, "C"},
		{199 * time.Millisecond, "C"},
		{200 * time.Millisecond, "D"},
		{299 * time.Millisecond, "D"},
		{300 * time.Millisecond, "F"},
		{2 * time.Second, "F"},
	}
	for _, tt := range tests {
		if got := BufferbloatGrade(tt.delta); got != tt.want {
			t.Errorf("BufferbloatGrade(%v) = %q, want %q", tt.delta, got, tt.want)
		}
	}
}

func TestMergeEMA(t *testing.T) {
	// First observation bootstraps wholesale.
	first := MergeEMA(Rollup{}, Rollup{Target: "x", P50RTT: 20, Samples: 5}, 0.2)
	if first.P50RTT != 20 || first.Samples != 5 {
		t.Fatalf("bootstrap: got p50=%v samples=%d", first.P50RTT, first.Samples)
	}

	// Feeding a steady stream of higher observations converges upward toward it.
	cur := Rollup{Target: "x", P50RTT: 20, Samples: 5}
	for i := 0; i < 200; i++ {
		cur = MergeEMA(cur, Rollup{Target: "x", P50RTT: 50, Samples: 1}, 0.2)
	}
	if cur.P50RTT < 49 || cur.P50RTT > 50.01 {
		t.Errorf("converged p50 = %v, want ~50", cur.P50RTT)
	}
	if cur.Samples != 205 {
		t.Errorf("samples = %d, want 205", cur.Samples)
	}

	// alpha clamps.
	hi := MergeEMA(Rollup{P50RTT: 10, Samples: 1}, Rollup{P50RTT: 30, Samples: 1}, 5)
	if hi.P50RTT != 30 {
		t.Errorf("alpha>1 clamp: got %v want 30 (full adopt)", hi.P50RTT)
	}
}

func TestWorstBaselineRatioAndModifier(t *testing.T) {
	baselines := map[string]Rollup{
		"1.1.1.1": {Samples: 10, P50RTT: 18},
		"8.8.8.8": {Samples: 10, P50RTT: 20},
		"new":     {Samples: 0}, // no baseline -> ignored
	}
	current := map[string]float64{
		"1.1.1.1": 55.8, // 3.1x
		"8.8.8.8": 22,   // 1.1x
		"new":     200,  // ignored
		"unknown": 999,  // no baseline -> ignored
	}
	ratio, ok := WorstBaselineRatio(baselines, current)
	if !ok {
		t.Fatal("expected ok")
	}
	if diff := ratio - 3.1; diff > 0.01 || diff < -0.01 {
		t.Errorf("worst ratio = %v, want ~3.1", ratio)
	}

	tests := []struct {
		name  string
		ratio float64
		ok    bool
		want  int
	}{
		{"no baseline neutral", 5, false, 0},
		{"within envelope", 1.2, true, 0},
		{"at start neutral", 1.5, true, 0},
		{"mild nudge", 2.0, true, 10},
		{"capped", 10, true, maxBaselinePenalty},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GradeModifier(tt.ratio, tt.ok); got != tt.want {
				t.Errorf("GradeModifier(%v,%v) = %d, want %d", tt.ratio, tt.ok, got, tt.want)
			}
		})
	}
}

func TestWorstBaselineRatioEmpty(t *testing.T) {
	if _, ok := WorstBaselineRatio(nil, map[string]float64{"x": 10}); ok {
		t.Error("no baselines should yield ok=false")
	}
}

func hop(ttl int, ip string, ms int) probes.TraceHop {
	return probes.TraceHop{TTL: ttl, IP: ip, Latency: time.Duration(ms) * time.Millisecond}
}

func TestIsolateFault(t *testing.T) {
	tests := []struct {
		name      string
		hops      []probes.TraceHop
		gw, wan   float64
		wantLayer FaultLayer
	}{
		{
			name: "healthy path",
			hops: []probes.TraceHop{hop(1, "192.168.1.1", 2), hop(2, "10.0.0.1", 12), hop(3, "1.1.1.1", 18)},
			gw:   2, wan: 18,
			wantLayer: FaultNone,
		},
		{
			name: "WAN degraded gateway healthy",
			hops: []probes.TraceHop{hop(1, "192.168.1.1", 2), hop(2, "10.0.0.1", 120), hop(3, "1.1.1.1", 140)},
			gw:   2, wan: 140,
			wantLayer: FaultWAN,
		},
		{
			name: "gateway slow",
			hops: []probes.TraceHop{hop(1, "192.168.1.1", 5), hop(2, "1.1.1.1", 60)},
			gw:   80, wan: 90,
			wantLayer: FaultGateway,
		},
		{
			name: "first hop / LAN slow",
			hops: []probes.TraceHop{hop(1, "192.168.1.1", 90), hop(2, "1.1.1.1", 100)},
			gw:   92, wan: 105,
			wantLayer: FaultFirstHop,
		},
		{
			name: "target slow beyond WAN",
			hops: []probes.TraceHop{hop(1, "192.168.1.1", 2), hop(2, "1.1.1.1", 18), hop(3, "8.8.8.8", 200)},
			gw:   2, wan: 18,
			wantLayer: FaultTarget,
		},
		{
			name: "empty hops healthy",
			hops: nil,
			gw:   0, wan: 0,
			wantLayer: FaultNone,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			layer, verdict := IsolateFault(tt.hops, tt.gw, tt.wan)
			if layer != tt.wantLayer {
				t.Errorf("layer = %q, want %q (verdict=%q)", layer, tt.wantLayer, verdict)
			}
			if verdict == "" {
				t.Error("verdict should never be empty")
			}
		})
	}
}
