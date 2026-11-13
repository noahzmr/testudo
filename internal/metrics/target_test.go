package metrics

import (
	"testing"
	"time"
)

func TestClassifyTarget(t *testing.T) {
	cases := map[string]TargetKind{
		"1.1.1.1":                     TargetICMP,
		"192.168.178.1":               TargetICMP,
		"router.lan":                  TargetICMP,
		"2001:4860:4860::8888":        TargetICMP, // bare IPv6: colons, no port
		"fe80::1":                     TargetICMP,
		"10.0.0.5:22":                 TargetTCP,
		"nas.local:445":               TargetTCP,
		"[2001:db8::1]:443":           TargetTCP,
		"https://example.org/":        TargetHTTP,
		"http://10.0.0.1:8080/health": TargetHTTP,
		"wifi:freq:wlp194s0":          TargetWiFi,
		"wifi:signal:wlan0":           TargetWiFi,
		"trace:1.1.1.1":               TargetTrace,
		"trace:1.1.1.1:hop3":          TargetTrace,
		"bufferbloat:idle:1.1.1.1":    TargetBufferbloat,
		"bufferbloat:loaded:8.8.8.8":  TargetBufferbloat,
	}
	for in, want := range cases {
		if got := ClassifyTarget(in); got != want {
			t.Errorf("ClassifyTarget(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestTargetKindPredicates(t *testing.T) {
	for k, want := range map[TargetKind][2]bool{ // {IsHostRTT, IsProbe}
		TargetICMP:        {true, true},
		TargetTCP:         {true, true},
		TargetHTTP:        {false, true},
		TargetWiFi:        {false, false},
		TargetTrace:       {false, false},
		TargetBufferbloat: {false, false},
	} {
		if k.IsHostRTT() != want[0] || k.IsProbe() != want[1] {
			t.Errorf("%v: IsHostRTT=%v IsProbe=%v, want %v", k, k.IsHostRTT(), k.IsProbe(), want)
		}
	}
}

func TestAggregatorEvictsStaleTargets(t *testing.T) {
	a := NewAggregator()
	a.RecordLatency("10.0.0.5:22", time.Millisecond)              // top-talker TCP probe
	a.RecordLatency("1.1.1.1", time.Millisecond)                  // configured probe
	a.RecordLatency("bufferbloat:idle:1.1.1.1", time.Millisecond) // hourly series
	old := time.Now().Add(-time.Hour)
	a.mu.Lock()
	for _, t := range a.targets {
		t.UpdatedAt = old
	}
	a.targets["1.1.1.1"].UpdatedAt = time.Now()
	a.maybePrune(time.Now().Add(2 * pruneEvery))
	a.mu.Unlock()

	got := map[string]bool{}
	for _, t := range a.SnapshotTargets() {
		got[t.Target] = true
	}
	if got["10.0.0.5:22"] {
		t.Error("idle TCP probe should be evicted after 15 min")
	}
	if !got["1.1.1.1"] || !got["bufferbloat:idle:1.1.1.1"] {
		t.Errorf("live probe and hourly series must survive an hour: %v", got)
	}
}
