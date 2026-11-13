package engine

import (
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/storage"
)

func TestL3PersistNeighboursWritesOnChangeAndKeyframe(t *testing.T) {
	var p l3Persist
	t0 := time.Unix(1_700_000_000, 0)
	a := []storage.NeighbourSample{
		{IP: "192.168.1.1", MAC: "aa", Dev: "eth0", Family: "inet", State: "REACHABLE"},
		{IP: "192.168.1.9", MAC: "bb", Dev: "eth0", Family: "inet", State: "STALE"},
	}
	reordered := []storage.NeighbourSample{a[1], a[0]}

	if !p.neighbours(a, t0) {
		t.Fatal("first table must be written")
	}
	if p.neighbours(reordered, t0.Add(30*time.Second)) {
		t.Fatal("same table in another order must be skipped")
	}
	churn := append([]storage.NeighbourSample{}, a...)
	churn[0].State, churn[1].State = "DELAY", "REACHABLE" // normal NUD cycling
	if p.neighbours(churn, t0.Add(40*time.Second)) {
		t.Fatal("NUD churn between healthy states must be skipped")
	}
	failed := append([]storage.NeighbourSample{}, a...)
	failed[1].State = "FAILED"
	if !p.neighbours(failed, t0.Add(50*time.Second)) {
		t.Fatal("an entry going FAILED must be written")
	}
	changed := append([]storage.NeighbourSample{}, a...)
	changed[1].MAC = "cc" // duplicate-IP / MAC change is exactly what replay needs
	if !p.neighbours(changed, t0.Add(60*time.Second)) {
		t.Fatal("a MAC change must be written")
	}
	if !p.neighbours(changed[:1], t0.Add(90*time.Second)) {
		t.Fatal("a removed entry must be written")
	}
	if !p.neighbours(changed[:1], t0.Add(90*time.Second+l3KeyframeEvery)) {
		t.Fatal("an unchanged table must still be written once per keyframe interval")
	}
}

func TestL3PersistConntrackWritesNewAndChangedFlows(t *testing.T) {
	var p l3Persist
	t0 := time.Unix(1_700_000_000, 0)
	f1 := storage.ConntrackSample{Proto: "tcp", OrigSrc: "10.0.0.2", OrigSport: 5000, OrigDst: "1.1.1.1", OrigDport: 443, State: "ESTABLISHED", Packets: 10}
	f2 := storage.ConntrackSample{Proto: "udp", OrigSrc: "10.0.0.2", OrigSport: 5353, OrigDst: "224.0.0.251", OrigDport: 5353}

	if got := p.conntrack([]storage.ConntrackSample{f1, f2}, t0); len(got) != 2 {
		t.Fatalf("first tick is a keyframe: wrote %d, want 2", len(got))
	}
	f1.Packets = 50 // counters alone do not justify a row
	if got := p.conntrack([]storage.ConntrackSample{f1, f2}, t0.Add(30*time.Second)); len(got) != 0 {
		t.Fatalf("unchanged flows: wrote %d, want 0", len(got))
	}
	f1.State = "TIME_WAIT"
	f3 := storage.ConntrackSample{Proto: "tcp", OrigSrc: "10.0.0.3", OrigSport: 6000, OrigDst: "8.8.8.8", OrigDport: 53}
	got := p.conntrack([]storage.ConntrackSample{f1, f2, f3}, t0.Add(60*time.Second))
	if len(got) != 2 || got[0].State != "TIME_WAIT" || got[1].OrigSrc != "10.0.0.3" {
		t.Fatalf("want the state change and the new flow, got %+v", got)
	}
	if got := p.conntrack([]storage.ConntrackSample{f1, f2, f3}, t0.Add(60*time.Second+l3KeyframeEvery)); len(got) != 3 {
		t.Fatalf("keyframe: wrote %d, want 3", len(got))
	}
}

func TestSeriesPersistWritesChangesAndHeartbeat(t *testing.T) {
	var p seriesPersist
	t0 := time.Unix(1_700_000_000, 0)
	steps := []struct {
		v    float64
		at   time.Duration
		want bool
	}{
		{5180, 0, true},                                // first value
		{5180, 5 * time.Second, false},                 // repeat
		{5180, 30 * time.Second, false},                // repeat
		{5200, 35 * time.Second, true},                 // change
		{5200, 35*time.Second + seriesHeartbeat, true}, // heartbeat
	}
	for i, s := range steps {
		if got := p.due("wifi:freq:wlan0", s.v, t0.Add(s.at)); got != s.want {
			t.Errorf("step %d: due=%v, want %v", i, got, s.want)
		}
	}
	if !p.due("wifi:signal:wlan0", -60, t0) {
		t.Error("series are tracked independently")
	}
}
