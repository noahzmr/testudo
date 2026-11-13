package metrics

import (
	"strconv"
	"testing"
	"time"
)

// BenchmarkRecordLatency measures one probe result landing on a target whose
// rolling window is full (the steady state).
func BenchmarkRecordLatency(b *testing.B) {
	a := NewAggregator()
	for i := 0; i < 256; i++ {
		a.RecordLatency("1.1.1.1", time.Duration(10+i%7)*time.Millisecond)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.RecordLatency("1.1.1.1", time.Duration(10+i%13)*time.Millisecond)
	}
}

// BenchmarkSnapshotTargets is the per-poll read of 30 targets.
func BenchmarkSnapshotTargets(b *testing.B) {
	a := NewAggregator()
	for t := 0; t < 30; t++ {
		for i := 0; i < 256; i++ {
			a.RecordLatency("10.0.0."+strconv.Itoa(t), time.Duration(10+i%7)*time.Millisecond)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = a.SnapshotTargets()
	}
}
