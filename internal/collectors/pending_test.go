package collectors

import (
	"testing"
	"time"
)

// A reply that arrives before the prober reaches wait() must still be
// received with its real timestamp. Before the fix, deliver() deleted the
// entry and wait() returned a closed channel, so the prober read a zero
// time.Time and recorded reply.Sub(start) as a saturated negative RTT.
func TestPendingMapDeliverBeforeWait(t *testing.T) {
	p := newPendingMap()
	start := time.Now()
	p.add("7")
	replyAt := start.Add(3 * time.Millisecond)
	p.deliver("7", replyAt)

	select {
	case got := <-p.wait("7"):
		if !got.Equal(replyAt) {
			t.Fatalf("reply time = %v, want %v", got, replyAt)
		}
		if rtt := got.Sub(start); rtt <= 0 {
			t.Fatalf("rtt = %v, want positive", rtt)
		}
	case <-time.After(time.Second):
		t.Fatal("early reply was lost")
	}
	p.remove("7")
	if len(p.m) != 0 {
		t.Fatalf("entry not removed: %d left", len(p.m))
	}
}

// An unknown key (already timed out and removed) must never produce a reply:
// the prober's timer reports loss instead.
func TestPendingMapUnknownKeyNeverFires(t *testing.T) {
	p := newPendingMap()
	select {
	case got := <-p.wait("missing"):
		t.Fatalf("unknown key fired with %v", got)
	case <-time.After(20 * time.Millisecond):
	}
}

// A duplicate reply must not block the receive loop.
func TestPendingMapDuplicateDeliverDoesNotBlock(t *testing.T) {
	p := newPendingMap()
	p.add("1")
	done := make(chan struct{})
	go func() {
		p.deliver("1", time.Now())
		p.deliver("1", time.Now())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("duplicate deliver blocked")
	}
}
