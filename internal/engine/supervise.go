package engine

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/health"
)

// supervisor wraps every collector goroutine so one panic degrades one
// subsystem instead of crashing the shared engine. It owns the health.Registry
// and is the single place subsystem state transitions are decided and
// published onto the bus (KindSubsystemDegraded).
type supervisor struct {
	reg *health.Registry
	bus *events.Bus

	// Tunables (fields so tests can shrink them).
	maxRestarts int
	baseBackoff time.Duration
	maxBackoff  time.Duration

	// wait blocks for d or until ctx is cancelled, returning false if cancelled.
	// Injectable so tests run without real sleeps.
	wait func(ctx context.Context, d time.Duration) bool
}

func newSupervisor(bus *events.Bus) *supervisor {
	return &supervisor{
		reg:         health.NewRegistry(),
		bus:         bus,
		maxRestarts: 8,
		baseBackoff: time.Second,
		maxBackoff:  30 * time.Second,
		wait:        waitOrCancel,
	}
}

func waitOrCancel(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Registry exposes the health registry for the UIs.
func (s *supervisor) Registry() *health.Registry { return s.reg }

// run executes fn under recover() with bounded exponential-backoff restart. A
// clean return (fn returns nil, typically because ctx was cancelled) ends
// supervision in StateOK. A returned error or a panic degrades the subsystem
// and schedules a restart; once the restart budget is exhausted the subsystem
// is marked permanently failed and no longer retried (no crash-loop). An error
// that looks like a missing-capability soft-fail moves the subsystem straight
// to StateUnprivileged with an actionable hint and stops retrying.
func (s *supervisor) run(ctx context.Context, name string, core bool, fn func(context.Context) error) {
	s.reg.Register(name, core)
	s.publish(name)

	restarts := 0
	for {
		err := s.callOnce(ctx, fn)

		if ctx.Err() != nil {
			return // engine shutting down; leave last state as-is
		}
		if err == nil {
			// Collector exited cleanly on its own (rare). Treat as healthy and
			// stop supervising.
			s.reg.MarkOK(name)
			s.publish(name)
			return
		}

		// Missing-capability soft-fail: retrying won't help. Park the subsystem
		// in the unprivileged state with a concrete remediation.
		if hint, ok := privilegeHint(name, err); ok {
			s.reg.MarkUnprivileged(name, err.Error(), hint)
			s.publish(name)
			log.Printf("supervise: %s unprivileged: %v", name, err)
			return
		}

		restarts++
		if restarts > s.maxRestarts {
			s.reg.MarkFailed(name, err.Error())
			s.publish(name)
			log.Printf("supervise: %s permanently failed after %d restarts: %v", name, restarts-1, err)
			return
		}

		s.reg.MarkDegraded(name, err.Error())
		s.reg.IncRestart(name)
		s.publish(name)
		log.Printf("supervise: %s degraded (restart %d/%d): %v", name, restarts, s.maxRestarts, err)

		if !s.wait(ctx, s.backoff(restarts)) {
			return // cancelled during backoff
		}
	}
}

// callOnce invokes fn, converting a panic into an error so the loop can treat
// panics and returned errors uniformly.
func (s *supervisor) callOnce(ctx context.Context, fn func(context.Context) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return fn(ctx)
}

// backoff returns the capped exponential delay for the n-th restart (n >= 1).
func (s *supervisor) backoff(n int) time.Duration {
	d := s.baseBackoff << (n - 1)
	if d <= 0 || d > s.maxBackoff {
		d = s.maxBackoff
	}
	return d
}

// publish mirrors the current registry state for name onto the bus so both UIs
// and the storage timeline see the transition.
func (s *supervisor) publish(name string) {
	st, ok := s.reg.Get(name)
	if !ok {
		return
	}
	s.bus.Publish(events.Event{
		Kind:   events.KindSubsystemDegraded,
		Source: name,
		Payload: events.SubsystemStatePayload{
			Name:     st.Name,
			State:    string(st.State),
			LastErr:  st.LastErr,
			Hint:     st.Hint,
			Restarts: st.Restarts,
		},
	})
}

// privilegeHint detects a missing-capability soft-fail from an error and
// returns the actionable setcap hint to show in the status table. Returns
// ok=false for ordinary failures that warrant a retry.
func privilegeHint(name string, err error) (string, bool) {
	low := strings.ToLower(err.Error())
	if strings.Contains(low, "not permitted") ||
		strings.Contains(low, "permission denied") ||
		strings.Contains(low, "eperm") ||
		strings.Contains(low, "eacces") {
		return "needs CAP_NET_RAW/CAP_NET_ADMIN — run via the privileged helper, " +
			"or: sudo setcap cap_net_raw,cap_net_admin=eip ./testudo", true
	}
	return "", false
}
