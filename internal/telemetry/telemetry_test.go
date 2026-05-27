package telemetry

import (
	"math"
	"testing"
)

func TestRetransRate(t *testing.T) {
	tests := []struct {
		name                                       string
		prevRetrans, prevSegs, curRetrans, curSegs uint64
		want                                       float64
	}{
		{"two percent", 10, 1000, 30, 2000, 2.0},       // 20 retrans over 1000 new segs
		{"no new segments", 10, 1000, 10, 1000, 0},     // window empty -> neutral
		{"segs went backwards", 10, 2000, 10, 1000, 0}, // counter reset
		{"retrans went backwards", 50, 1000, 10, 2000, 0},
		{"clean window", 0, 0, 5, 500, 1.0},
		{"clamped to 100", 0, 100, 500, 200, 100}, // pathological: more retrans than new segs
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RetransRate(tt.prevRetrans, tt.prevSegs, tt.curRetrans, tt.curSegs)
			if math.Abs(got-tt.want) > 1e-9 {
				t.Errorf("RetransRate(%d,%d,%d,%d) = %v, want %v",
					tt.prevRetrans, tt.prevSegs, tt.curRetrans, tt.curSegs, got, tt.want)
			}
		})
	}
}

func TestFlowWeightedRTX(t *testing.T) {
	t.Run("no flows is neutral", func(t *testing.T) {
		if _, ok := FlowWeightedRTX(nil); ok {
			t.Error("empty input should report ok=false (neutral)")
		}
	})

	t.Run("busy flow dominates", func(t *testing.T) {
		// A tiny flow at 50% RTX and a huge flow at 1% should weight toward 1%.
		samples := []RTXSample{
			{Rate: 50, Bytes: 1_000},
			{Rate: 1, Bytes: 1_000_000},
		}
		got, ok := FlowWeightedRTX(samples)
		if !ok {
			t.Fatal("ok=false on non-empty input")
		}
		// weighted = (50*1000 + 1*1e6) / (1001000) ~= 1.049
		if got > 2.0 {
			t.Errorf("busy flow should pull rate near 1%%, got %v", got)
		}
	})

	t.Run("stalled flow still counts", func(t *testing.T) {
		// A zero-byte but heavily-retransmitting flow (PMTU black-hole shape)
		// must not be silently dropped to a 0 weight.
		got, ok := FlowWeightedRTX([]RTXSample{{Rate: 80, Bytes: 0}})
		if !ok || got != 80 {
			t.Errorf("stalled flow: got rate=%v ok=%v, want 80 true", got, ok)
		}
	})
}

func TestWorstFlowRTT(t *testing.T) {
	if _, ok := WorstFlowRTT(nil); ok {
		t.Error("empty input should report ok=false")
	}
	got, ok := WorstFlowRTT([]float64{12, 250, 40})
	if !ok || got != 250 {
		t.Errorf("got %v ok=%v, want 250 true", got, ok)
	}
}
