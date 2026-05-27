package engine

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/health"
)

func TestSuperviseRestartsThenRecovers(t *testing.T) {
	s := newSupervisor(events.NewBus(64))
	s.wait = func(ctx context.Context, _ /*d*/ time.Duration) bool { return ctx.Err() == nil }

	var mu sync.Mutex
	calls := 0
	fn := func(ctx context.Context) error {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n <= 3 {
			panic("boom")
		}
		// 4th call exits cleanly.
		return nil
	}

	s.run(context.Background(), "flaky", true, fn)

	st, _ := s.reg.Get("flaky")
	if st.State != health.StateOK {
		t.Fatalf("final state = %q, want ok (recovered)", st.State)
	}
	if st.Restarts != 3 {
		t.Fatalf("restarts = %d, want 3", st.Restarts)
	}
	if calls != 4 {
		t.Fatalf("fn called %d times, want 4", calls)
	}
}

func TestSupervisePermanentlyFails(t *testing.T) {
	s := newSupervisor(events.NewBus(64))
	s.maxRestarts = 3
	s.wait = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }

	calls := 0
	fn := func(ctx context.Context) error {
		calls++
		return errors.New("still broken")
	}
	s.run(context.Background(), "dead", false, fn)

	st, _ := s.reg.Get("dead")
	if st.State != health.StateFailed {
		t.Fatalf("state = %q, want failed", st.State)
	}
	// Initial attempt + maxRestarts retries = 4 calls, then give up.
	if calls != s.maxRestarts+1 {
		t.Fatalf("fn called %d times, want %d", calls, s.maxRestarts+1)
	}
}

func TestSuperviseUnprivilegedStopsRetrying(t *testing.T) {
	s := newSupervisor(events.NewBus(64))
	s.wait = func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil }

	calls := 0
	fn := func(ctx context.Context) error {
		calls++
		return errors.New("socket: operation not permitted")
	}
	s.run(context.Background(), "capture", true, fn)

	st, _ := s.reg.Get("capture")
	if st.State != health.StateUnprivileged {
		t.Fatalf("state = %q, want unprivileged", st.State)
	}
	if st.Hint == "" {
		t.Fatal("unprivileged status must carry a setcap hint")
	}
	if calls != 1 {
		t.Fatalf("unprivileged soft-fail retried %d times, want 1", calls)
	}
}

func TestSuperviseCancelEndsCleanly(t *testing.T) {
	s := newSupervisor(events.NewBus(64))
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	calls := 0
	fn := func(ctx context.Context) error {
		calls++
		<-ctx.Done()
		return ctx.Err()
	}
	s.run(ctx, "x", false, fn)
	if calls != 1 {
		t.Fatalf("fn called %d times on cancelled ctx, want 1", calls)
	}
}

func TestBackoffCaps(t *testing.T) {
	s := newSupervisor(events.NewBus(64))
	if got := s.backoff(1); got != s.baseBackoff {
		t.Fatalf("backoff(1) = %v, want %v", got, s.baseBackoff)
	}
	if got := s.backoff(100); got != s.maxBackoff {
		t.Fatalf("backoff(100) = %v, want cap %v", got, s.maxBackoff)
	}
}
