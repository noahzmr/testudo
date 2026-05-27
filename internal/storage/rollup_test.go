package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestRollupRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)

	if _, ok, err := st.GetRollup(ctx, "1.1.1.1", 2, 21); err != nil || ok {
		t.Fatalf("empty baseline: ok=%v err=%v, want ok=false err=nil", ok, err)
	}

	r := RollupRow{Target: "1.1.1.1", DOW: 2, Hour: 21, P50RTT: 18, P95RTT: 30, P99RTT: 40, Samples: 100, Updated: time.Now()}
	if err := st.PutRollup(ctx, r); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, ok, err := st.GetRollup(ctx, "1.1.1.1", 2, 21)
	if err != nil || !ok {
		t.Fatalf("get after put: ok=%v err=%v", ok, err)
	}
	if got.P50RTT != 18 || got.Samples != 100 {
		t.Errorf("got %+v", got)
	}

	// Upsert overwrites the same (target,dow,hour) key.
	r.P50RTT = 25
	r.Samples = 150
	if err := st.PutRollup(ctx, r); err != nil {
		t.Fatalf("re-put: %v", err)
	}
	got, _, _ = st.GetRollup(ctx, "1.1.1.1", 2, 21)
	if got.P50RTT != 25 || got.Samples != 150 {
		t.Errorf("after upsert got %+v", got)
	}

	if err := st.ResetBaseline(ctx, "1.1.1.1"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, ok, _ := st.GetRollup(ctx, "1.1.1.1", 2, 21); ok {
		t.Error("baseline should be gone after reset")
	}
}

// TestRetentionSeparation proves rollups outlive raw samples: an old rollup
// survives the 30-day raw cutoff but an old raw sample does not.
func TestRetentionSeparation(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)

	now := time.Now()
	sid := "s1"
	if err := st.StartSession(ctx, sid, []string{"1.1.1.1"}, ""); err != nil {
		t.Fatal(err)
	}

	// Raw sample 40 days old (beyond 30d raw retention, within 1y rollup retention).
	old := now.Add(-40 * 24 * time.Hour)
	if err := st.InsertSample(ctx, sid, Sample{Kind: "rtt", Value: 10, TS: old}); err != nil {
		t.Fatal(err)
	}
	// Rollup updated 40 days ago — should survive (rollup retention is 1y).
	if err := st.PutRollup(ctx, RollupRow{Target: "1.1.1.1", DOW: 1, Hour: 2, P50RTT: 12, Samples: 5, Updated: old}); err != nil {
		t.Fatal(err)
	}

	if err := st.Retain(ctx, now); err != nil {
		t.Fatalf("retain: %v", err)
	}

	samples, err := st.SamplesBySession(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 0 {
		t.Errorf("raw sample should be pruned at 40d, got %d", len(samples))
	}
	if _, ok, _ := st.GetRollup(ctx, "1.1.1.1", 1, 2); !ok {
		t.Error("rollup should survive at 40d (1y retention)")
	}

	// A rollup older than a year is pruned.
	ancient := now.Add(-400 * 24 * time.Hour)
	if err := st.PutRollup(ctx, RollupRow{Target: "old", DOW: 0, Hour: 0, P50RTT: 1, Samples: 1, Updated: ancient}); err != nil {
		t.Fatal(err)
	}
	if err := st.Retain(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.GetRollup(ctx, "old", 0, 0); ok {
		t.Error("rollup older than 1y should be pruned")
	}
}

func TestFlowSnapshots(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	sid := "s1"
	if err := st.StartSession(ctx, sid, nil, ""); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Add(-time.Hour)
	rows := []FlowSnapshotRow{
		{Iface: "eth0", Src: "10.0.0.2", Dst: "1.1.1.1", Proto: "tcp", BytesIn: 100, BytesOut: 200, Process: "curl"},
	}
	if err := st.InsertFlowSnapshots(ctx, sid, t0, rows); err != nil {
		t.Fatal(err)
	}
	got, err := st.FlowSnapshotsAround(ctx, sid, time.Now(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Process != "curl" {
		t.Fatalf("got %+v", got)
	}
	// A query before the snapshot time returns nothing.
	none, _ := st.FlowSnapshotsAround(ctx, sid, t0.Add(-time.Minute), 10)
	if len(none) != 0 {
		t.Errorf("expected no rows before snapshot, got %d", len(none))
	}
}

func TestCapIncidents(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	sid := "s1"
	if err := st.StartSession(ctx, sid, nil, ""); err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	for i := 0; i < 10; i++ {
		if err := st.InsertIncident(ctx, sid, IncidentRow{
			ID: string(rune('a' + i)), TS: base.Add(time.Duration(i) * time.Minute), Trigger: "x", Summary: "y",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.CapIncidents(ctx, sid, 3); err != nil {
		t.Fatal(err)
	}
	got, err := st.IncidentsBySession(ctx, sid)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 newest incidents, got %d", len(got))
	}
	// Newest-first: the last three inserted (h, i, j -> 'a'+9,'a'+8,'a'+7).
	if got[0].ID != string(rune('a'+9)) {
		t.Errorf("newest id = %q, want %q", got[0].ID, string(rune('a'+9)))
	}
}
