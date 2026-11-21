package pathmon

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fake answers per peer address with a fixed delay, or not at all.
type fake map[string]time.Duration

func (f fake) probe(_ context.Context, addr string) (time.Duration, error) {
	d, ok := f[addr]
	if !ok || d < 0 {
		return 0, errors.New("lost")
	}
	return d, nil
}

func TestHysteresisAndFailover(t *testing.T) {
	ms := time.Millisecond
	net := fake{"inet": 40 * ms, "mpls": 30 * ms, "lab": 5 * ms}
	m := &Monitor{Probe: net.probe, Margin: 10 * ms, Hold: 10 * time.Second}
	targets := []Target{
		{Device: "tm01c0s0", Peer: "inet", PeerNode: "hq", Color: "inet"},
		{Device: "tm01c1s0", Peer: "mpls", PeerNode: "hq", Color: "mpls"},
		{Device: "tm09c0s0", Peer: "lab", PeerNode: "lab", Color: "inet"},
	}
	now := time.Unix(0, 0)
	step := func(n int) (changed bool) {
		for i := 0; i < n; i++ {
			now = now.Add(time.Second)
			changed = m.Check(context.Background(), targets, now) || changed
		}
		return changed
	}
	// Until enough probes are in, nothing is chosen.
	step(2)
	if m.Preferred("hq", 0, LowestLatency) != "" {
		t.Fatal("chose after two probes")
	}
	step(1)
	if got := m.Preferred("hq", 0, LowestLatency); got != "mpls" {
		t.Fatalf("first choice %q, want mpls (30 ms against 40)", got)
	}
	// The internet gets faster by 5 ms: not enough to move.
	net["inet"] = 25 * ms
	step(30)
	if got := m.Preferred("hq", 0, LowestLatency); got != "mpls" {
		t.Errorf("moved for a 5 ms difference: %q", got)
	}
	// Then much faster: it has to stay so for the hold time first.
	net["inet"] = 5 * ms
	step(20) // the average of the window catches up
	before := m.Preferred("hq", 0, LowestLatency)
	step(12)
	if got := m.Preferred("hq", 0, LowestLatency); got != "inet" {
		t.Errorf("did not move to a path 25 ms faster: %q (was %q)", got, before)
	}
	// One bad probe on the internet does not move traffic back.
	net["inet"] = 200 * ms
	step(1)
	net["inet"] = 5 * ms
	step(5)
	if got := m.Preferred("hq", 0, LowestLatency); got != "inet" {
		t.Errorf("one slow probe moved traffic: %q", got)
	}
	// The internet stops answering: away at once, no hold time.
	net["inet"] = -1
	if !step(3) || !m.Down("tm01c0s0") {
		t.Fatal("a dead path was not noticed")
	}
	if got := m.Preferred("hq", 0, LowestLatency); got != "mpls" {
		t.Errorf("after the internet path died: %q", got)
	}
	// By loss: mpls loses every fourth probe, the internet is back and
	// clean; the loss criterion prefers it, latency does not care yet.
	net["inet"] = 50 * ms
	lossy := 0
	m.Probe = func(ctx context.Context, addr string) (time.Duration, error) {
		if addr == "mpls" {
			lossy++
			if lossy%4 == 0 {
				return 0, errors.New("lost")
			}
		}
		return net.probe(ctx, addr)
	}
	step(40)
	if got := m.Preferred("hq", 0, LowestLoss); got != "inet" {
		t.Errorf("lowest loss chose %q", got)
	}
	if got := m.Preferred("hq", 0, LowestLatency); got != "mpls" {
		t.Errorf("lowest latency chose %q", got)
	}
	// Numbers for people.
	st := m.Status()
	if len(st) != 3 {
		t.Fatalf("status of %d paths", len(st))
	}
	for _, s := range st {
		if s.Device == "tm01c1s0" && (s.Loss < 0.2 || s.Loss > 0.3 || !s.Preferred) {
			t.Errorf("mpls numbers: %+v", s)
		}
		if s.Device == "tm09c0s0" && (s.LatencyMs != 5 || s.JitterMs != 0 || s.Down) {
			t.Errorf("lab numbers: %+v", s)
		}
	}
	// A tunnel that leaves the plan is forgotten.
	m.Check(context.Background(), targets[:2], now)
	if len(m.Status()) != 2 {
		t.Error("a removed tunnel is still measured")
	}
}
