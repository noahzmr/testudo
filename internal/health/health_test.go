package health

import (
	"testing"
	"time"
)

func TestRegistryTransitions(t *testing.T) {
	clk := time.Unix(1000, 0)
	r := newRegistryClock(func() time.Time { return clk })

	r.Register("icmp", true)
	st, ok := r.Get("icmp")
	if !ok {
		t.Fatal("icmp not registered")
	}
	if st.State != StateOK {
		t.Fatalf("fresh subsystem state = %q, want ok", st.State)
	}
	if !st.Core {
		t.Fatal("icmp should be core")
	}

	// Re-register preserves state but updates core flag.
	r.MarkDegraded("icmp", "boom")
	r.Register("icmp", false)
	st, _ = r.Get("icmp")
	if st.State != StateDegraded {
		t.Fatalf("re-register clobbered state: %q", st.State)
	}
	if st.Core {
		t.Fatal("re-register should have cleared core flag")
	}
}

func TestSinceOnlyBumpsOnChange(t *testing.T) {
	clk := time.Unix(2000, 0)
	r := newRegistryClock(func() time.Time { return clk })
	r.MarkDegraded("dns", "err1")
	first, _ := r.Get("dns")

	clk = clk.Add(5 * time.Second)
	r.MarkDegraded("dns", "err2") // same state, different error
	second, _ := r.Get("dns")

	if !second.Since.Equal(first.Since) {
		t.Fatalf("Since moved on a same-state report: %v -> %v", first.Since, second.Since)
	}
	if !second.Updated.After(first.Updated) {
		t.Fatal("Updated should advance on every report")
	}
	if second.LastErr != "err2" {
		t.Fatalf("LastErr = %q, want err2", second.LastErr)
	}

	clk = clk.Add(time.Second)
	r.MarkOK("dns")
	third, _ := r.Get("dns")
	if !third.Since.After(second.Since) {
		t.Fatal("Since should move on a real state change")
	}
}

func TestIncRestart(t *testing.T) {
	r := NewRegistry()
	r.Register("capture", true)
	r.IncRestart("capture")
	r.IncRestart("capture")
	st, _ := r.Get("capture")
	if st.Restarts != 2 {
		t.Fatalf("Restarts = %d, want 2", st.Restarts)
	}
	// IncRestart on an unknown subsystem auto-creates it.
	r.IncRestart("ghost")
	if st, ok := r.Get("ghost"); !ok || st.Restarts != 1 {
		t.Fatalf("ghost restart = %+v", st)
	}
}

func TestUnprivilegedCarriesHint(t *testing.T) {
	r := NewRegistry()
	r.MarkUnprivileged("capture", "operation not permitted",
		"sudo setcap cap_net_raw+ep ./testudo")
	st, _ := r.Get("capture")
	if st.State != StateUnprivileged {
		t.Fatalf("state = %q", st.State)
	}
	if st.Hint == "" {
		t.Fatal("unprivileged status must carry a hint")
	}
}

func TestWorstAndCoreDegraded(t *testing.T) {
	r := NewRegistry()
	r.Register("icmp", true)
	r.Register("dns", true)
	r.Register("nat", false)

	if w, core := r.Worst(); w != StateOK || core {
		t.Fatalf("all-ok worst=%q core=%v", w, core)
	}

	r.MarkUnprivileged("nat", "no caps", "setcap")
	if w, core := r.Worst(); w != StateUnprivileged {
		t.Fatalf("worst=%q, want unprivileged", w)
	} else if core {
		t.Fatal("non-core unprivileged must not set coreDegraded")
	}

	r.MarkDegraded("icmp", "flap")
	w, core := r.Worst()
	if w != StateDegraded {
		t.Fatalf("worst=%q, want degraded", w)
	}
	if !core {
		t.Fatal("degraded core collector must set coreDegraded")
	}

	r.MarkFailed("dns", "dead")
	if w, _ := r.Worst(); w != StateFailed {
		t.Fatalf("worst=%q, want failed", w)
	}
	if r.Healthy() {
		t.Fatal("Healthy() should be false with a failed subsystem")
	}
}

func TestSnapshotOrdersWorstFirst(t *testing.T) {
	r := NewRegistry()
	r.Register("aaa", false) // ok
	r.MarkFailed("zzz", "dead")
	r.MarkDegraded("mmm", "flap")

	snap := r.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("snapshot len = %d", len(snap))
	}
	if snap[0].Name != "zzz" || snap[0].State != StateFailed {
		t.Fatalf("worst-first ordering broken: %+v", snap[0])
	}
	if snap[2].Name != "aaa" {
		t.Fatalf("ok subsystem should sort last: %+v", snap[2])
	}
}
