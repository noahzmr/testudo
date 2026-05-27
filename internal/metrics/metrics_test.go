package metrics

import (
	"testing"
	"time"
)

func TestPercentileP50P95P99(t *testing.T) {
	// 100 samples: 1ms .. 100ms.
	samples := make([]time.Duration, 0, 100)
	for i := 1; i <= 100; i++ {
		samples = append(samples, time.Duration(i)*time.Millisecond)
	}
	tests := []struct {
		name string
		p    float64
		want time.Duration
	}{
		{"p50", 0.50, 50 * time.Millisecond},
		{"p95", 0.95, 95 * time.Millisecond},
		{"p99", 0.99, 99 * time.Millisecond},
		{"p100", 1.0, 100 * time.Millisecond},
	}
	for _, tt := range tests {
		if got := percentile(samples, tt.p); got != tt.want {
			t.Errorf("%s: got %v want %v", tt.name, got, tt.want)
		}
	}
}

func TestPercentileEmpty(t *testing.T) {
	if got := percentile(nil, 0.5); got != 0 {
		t.Errorf("empty: got %v want 0", got)
	}
}

func TestRecomputePopulatesPercentiles(t *testing.T) {
	a := NewAggregator()
	for i := 1; i <= 100; i++ {
		a.RecordLatency("t", time.Duration(i)*time.Millisecond)
	}
	got := a.SnapshotTargets()
	if len(got) != 1 {
		t.Fatalf("want 1 target, got %d", len(got))
	}
	ts := got[0]
	if ts.P50RTT != 50*time.Millisecond {
		t.Errorf("P50RTT = %v, want 50ms", ts.P50RTT)
	}
	if ts.P95RTT != 95*time.Millisecond {
		t.Errorf("P95RTT = %v, want 95ms", ts.P95RTT)
	}
	if ts.P99RTT != 99*time.Millisecond {
		t.Errorf("P99RTT = %v, want 99ms", ts.P99RTT)
	}
}
