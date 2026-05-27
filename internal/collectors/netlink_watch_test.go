package collectors

import (
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/events"
)

// fakeClock is a manually-advanced clock for the coalescer's timing logic.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }

func TestFlapCoalescer_BurstCoalescesIntoOneSummary(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	fc := &flapCoalescer{window: 250 * time.Millisecond, now: clk.now}

	// Six transitions on eth0, each 50ms apart - well inside the 250ms window.
	for i := 0; i < 6; i++ {
		fc.add("eth0", i%2 == 0)
		clk.add(50 * time.Millisecond)
	}

	// Only 50ms of quiet so far: nothing should flush yet.
	if got := fc.flushReady(); len(got) != 0 {
		t.Fatalf("expected no flush while still flapping, got %d bursts", len(got))
	}

	// Go quiet past the window.
	clk.add(300 * time.Millisecond)
	got := fc.flushReady()
	if len(got) != 1 {
		t.Fatalf("expected 1 coalesced burst, got %d", len(got))
	}
	b := got[0]
	if b.Iface != "eth0" {
		t.Errorf("iface = %q, want eth0", b.Iface)
	}
	if b.Count != 6 {
		t.Errorf("count = %d, want 6", b.Count)
	}
	// Last transition was i=5 (odd) -> running=false.
	if b.LastRunning {
		t.Errorf("LastRunning = true, want false")
	}
	if b.Duration() != 250*time.Millisecond {
		t.Errorf("duration = %s, want 250ms", b.Duration())
	}

	// Nothing left after flush.
	if got := fc.flushAll(); len(got) != 0 {
		t.Errorf("expected empty after flush, got %d", len(got))
	}
}

func TestFlapCoalescer_SeparateIfacesSeparateBursts(t *testing.T) {
	clk := &fakeClock{t: time.Unix(100, 0)}
	fc := &flapCoalescer{window: 100 * time.Millisecond, now: clk.now}

	fc.add("eth0", false)
	fc.add("wlan0", true)
	fc.add("eth0", true)

	// Not yet quiet.
	if got := fc.flushReady(); len(got) != 0 {
		t.Fatalf("premature flush: %d", len(got))
	}
	clk.add(150 * time.Millisecond)

	got := fc.flushReady()
	if len(got) != 2 {
		t.Fatalf("expected 2 bursts (one per iface), got %d", len(got))
	}
	// collectLocked sorts by iface name.
	if got[0].Iface != "eth0" || got[1].Iface != "wlan0" {
		t.Errorf("unexpected ordering: %q, %q", got[0].Iface, got[1].Iface)
	}
	if got[0].Count != 2 {
		t.Errorf("eth0 count = %d, want 2", got[0].Count)
	}
	if got[1].Count != 1 {
		t.Errorf("wlan0 count = %d, want 1", got[1].Count)
	}
}

func TestFlapCoalescer_NewTransitionExtendsWindow(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	fc := &flapCoalescer{window: 200 * time.Millisecond, now: clk.now}

	fc.add("eth0", false)
	clk.add(150 * time.Millisecond) // within window
	if got := fc.flushReady(); len(got) != 0 {
		t.Fatal("flushed before window elapsed")
	}
	fc.add("eth0", true) // resets quiet timer
	clk.add(150 * time.Millisecond)
	if got := fc.flushReady(); len(got) != 0 {
		t.Fatal("flushed though last transition was only 150ms ago")
	}
	clk.add(100 * time.Millisecond) // now 250ms since last transition
	got := fc.flushReady()
	if len(got) != 1 || got[0].Count != 2 {
		t.Fatalf("expected one burst of 2, got %#v", got)
	}
}

func TestDiffNetState_DetectsMissedChanges(t *testing.T) {
	old := netState{
		links:  map[string]bool{"eth0": true, "wlan0": false},
		addrs:  map[string]bool{"eth0/192.168.1.2/24": true},
		routes: map[string]bool{"ipv4|default|192.168.1.1|eth0": true},
	}
	fresh := netState{
		links: map[string]bool{"eth0": false /* went down */, "tun0": true /* appeared */},
		// wlan0 removed entirely.
		addrs: map[string]bool{"eth0/192.168.1.2/24": true, "tun0/10.0.0.2/32": true},
		// default route changed gateway.
		routes: map[string]bool{"ipv4|default|192.168.1.254|eth0": true},
	}

	got := diffNetState(old, fresh)

	// Index the changes for assertion regardless of order within a category.
	type lk struct {
		iface            string
		running, removed bool
	}
	links := map[lk]bool{}
	var addrAdds, addrDels []string
	var routeAdds, routeDels []string
	for _, ch := range got {
		switch p := ch.payload.(type) {
		case events.LinkChangePayload:
			links[lk{p.Iface, p.Running, p.Removed}] = true
		case events.AddrChangePayload:
			if p.Added {
				addrAdds = append(addrAdds, p.Iface+"/"+p.Addr)
			} else {
				addrDels = append(addrDels, p.Iface+"/"+p.Addr)
			}
		case events.RouteChangePayload:
			if p.Added {
				routeAdds = append(routeAdds, p.Gateway)
			} else {
				routeDels = append(routeDels, p.Gateway)
			}
		}
	}

	if !links[lk{"eth0", false, false}] {
		t.Error("missing eth0 down transition")
	}
	if !links[lk{"tun0", true, false}] {
		t.Error("missing tun0 appearance")
	}
	if !links[lk{"wlan0", false, true}] {
		t.Error("missing wlan0 removal")
	}
	if len(addrAdds) != 1 || addrAdds[0] != "tun0/10.0.0.2/32" {
		t.Errorf("addr adds = %v, want [tun0/10.0.0.2/32]", addrAdds)
	}
	if len(addrDels) != 0 {
		t.Errorf("addr dels = %v, want none", addrDels)
	}
	if len(routeAdds) != 1 || routeAdds[0] != "192.168.1.254" {
		t.Errorf("route adds = %v, want new gateway", routeAdds)
	}
	if len(routeDels) != 1 || routeDels[0] != "192.168.1.1" {
		t.Errorf("route dels = %v, want old gateway", routeDels)
	}
}

func TestDiffNetState_NoChangeIsEmpty(t *testing.T) {
	s := netState{
		links:  map[string]bool{"eth0": true},
		addrs:  map[string]bool{"eth0/192.168.1.2/24": true},
		routes: map[string]bool{"ipv4|default|192.168.1.1|eth0": true},
	}
	// Compare an identical snapshot (fresh copy with same contents).
	fresh := netState{
		links:  map[string]bool{"eth0": true},
		addrs:  map[string]bool{"eth0/192.168.1.2/24": true},
		routes: map[string]bool{"ipv4|default|192.168.1.1|eth0": true},
	}
	if got := diffNetState(s, fresh); len(got) != 0 {
		t.Errorf("expected no changes for identical state, got %d", len(got))
	}
}

func TestPruneAppend_SlidingWindow(t *testing.T) {
	base := time.Unix(1000, 0)
	var ts []time.Time
	// Three events spaced 30s apart.
	ts = pruneAppend(ts, base, time.Minute)
	ts = pruneAppend(ts, base.Add(30*time.Second), time.Minute)
	ts = pruneAppend(ts, base.Add(60*time.Second), time.Minute)
	// At t=60s, the t=0 event is exactly at the window edge (cut = 0s,
	// Before(cut) is false) so it's retained; count is 3.
	if got := countWithin(ts, base.Add(60*time.Second), time.Minute); got != 3 {
		t.Errorf("count = %v, want 3", got)
	}
	// Append one well past the window; the oldest should be pruned.
	ts = pruneAppend(ts, base.Add(95*time.Second), time.Minute)
	// Window now [35s, 95s]: retains 60s and 95s only -> 2.
	if got := countWithin(ts, base.Add(95*time.Second), time.Minute); got != 2 {
		t.Errorf("count after slide = %v, want 2", got)
	}
}
