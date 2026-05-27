// Package health tracks the runtime state of each Testudo subsystem so the
// TUI, Web UI, and Network Quality grade can show a first-class "which
// subsystems soft-failed" surface instead of letting collectors no-op
// silently.
//
// The Registry is the single source of truth: every supervised collector and
// every privileged capability reports its state here. A subsystem moves
// through a small state machine:
//
//	ok           - running and producing data
//	degraded     - transient failure; being restarted with backoff
//	failed       - permanently degraded; retries exhausted, no longer running
//	unprivileged - a soft-fail caused by missing capabilities (e.g. capture
//	               without CAP_NET_RAW). Carries an actionable Hint (the exact
//	               setcap command) rather than a raw kernel error.
//
// The Registry is safe for concurrent use.
package health

import (
	"sort"
	"sync"
	"time"
)

// State is one of the four subsystem states. The zero value is StateOK so a
// freshly-registered subsystem reads as healthy until something says otherwise.
type State string

const (
	StateOK           State = "ok"
	StateDegraded     State = "degraded"
	StateFailed       State = "failed"
	StateUnprivileged State = "unprivileged"
)

// rank orders states by severity so the worst subsystem can drive an
// aggregate badge. Higher = worse.
func (s State) rank() int {
	switch s {
	case StateOK:
		return 0
	case StateUnprivileged:
		return 1
	case StateDegraded:
		return 2
	case StateFailed:
		return 3
	}
	return 0
}

// Status is an immutable snapshot of one subsystem's health.
type Status struct {
	Name     string
	State    State
	LastErr  string
	Hint     string // actionable remediation, e.g. a setcap command
	Restarts int
	Since    time.Time // when the current state was entered
	Updated  time.Time // last time anything was reported
	// Core marks signal-bearing collectors (ICMP, DNS, capture) whose
	// degradation should flag the Network Quality grade as "reduced coverage".
	Core bool
}

// Registry holds the live state of every known subsystem.
type Registry struct {
	mu  sync.RWMutex
	now func() time.Time
	m   map[string]*Status
}

// NewRegistry returns an empty registry using the real clock.
func NewRegistry() *Registry {
	return &Registry{now: time.Now, m: make(map[string]*Status)}
}

// newRegistryClock is the test seam for a deterministic clock.
func newRegistryClock(now func() time.Time) *Registry {
	return &Registry{now: now, m: make(map[string]*Status)}
}

// Register declares a subsystem so it appears in the status table before it
// has reported anything. Idempotent; re-registering preserves existing state
// but updates the Core flag. core marks signal-bearing collectors.
func (r *Registry) Register(name string, core bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if st, ok := r.m[name]; ok {
		st.Core = core
		return
	}
	r.m[name] = &Status{
		Name: name, State: StateOK, Core: core,
		Since: now, Updated: now,
	}
}

// set is the internal transition primitive. It records the new state, bumps
// Since only on an actual state change, and always refreshes Updated.
func (r *Registry) set(name string, state State, lastErr, hint string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	st := r.m[name]
	if st == nil {
		st = &Status{Name: name, Since: now}
		r.m[name] = st
	}
	if st.State != state {
		st.Since = now
	}
	st.State = state
	st.LastErr = lastErr
	st.Hint = hint
	st.Updated = now
}

// MarkOK transitions a subsystem to healthy and clears its error.
func (r *Registry) MarkOK(name string) { r.set(name, StateOK, "", "") }

// MarkDegraded records a transient failure (a recovered panic or a returned
// error that will be retried). It does not bump the restart count - call
// IncRestart when an actual restart is scheduled.
func (r *Registry) MarkDegraded(name, lastErr string) {
	r.set(name, StateDegraded, lastErr, "")
}

// MarkFailed records a permanent failure: retries exhausted, subsystem stopped.
func (r *Registry) MarkFailed(name, lastErr string) {
	r.set(name, StateFailed, lastErr, "")
}

// MarkUnprivileged records a soft-fail caused by a missing capability, with an
// actionable hint (typically a setcap command) shown verbatim in the UIs.
func (r *Registry) MarkUnprivileged(name, lastErr, hint string) {
	r.set(name, StateUnprivileged, lastErr, hint)
}

// IncRestart bumps the restart counter for a subsystem.
func (r *Registry) IncRestart(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.m[name]
	if st == nil {
		st = &Status{Name: name, State: StateOK, Since: r.now()}
		r.m[name] = st
	}
	st.Restarts++
	st.Updated = r.now()
}

// Get returns the status of one subsystem.
func (r *Registry) Get(name string) (Status, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	st, ok := r.m[name]
	if !ok {
		return Status{}, false
	}
	return *st, true
}

// Snapshot returns every subsystem's status, worst-state first then by name so
// the operator's eye lands on problems. The returned slice is a copy.
func (r *Registry) Snapshot() []Status {
	r.mu.RLock()
	out := make([]Status, 0, len(r.m))
	for _, st := range r.m {
		out = append(out, *st)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		ri, rj := out[i].State.rank(), out[j].State.rank()
		if ri != rj {
			return ri > rj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Worst returns the most-severe state across all subsystems, and whether any
// degraded/failed/unprivileged subsystem is a Core signal collector. The grade
// card uses CoreDegraded to decide whether to show a "reduced coverage" badge.
func (r *Registry) Worst() (worst State, coreDegraded bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	worst = StateOK
	for _, st := range r.m {
		if st.State.rank() > worst.rank() {
			worst = st.State
		}
		if st.Core && st.State != StateOK {
			coreDegraded = true
		}
	}
	return worst, coreDegraded
}

// Healthy reports whether every subsystem is in StateOK.
func (r *Registry) Healthy() bool {
	w, _ := r.Worst()
	return w == StateOK
}
