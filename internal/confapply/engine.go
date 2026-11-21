// Package confapply turns a change to the configuration model into a change
// of the running system, and takes it back unless the operator confirms.
//
//	validate -> render -> dry run -> commit -> apply -> health check
//	         -> wait for confirmation -> keep, or roll back automatically
//
// Nothing touches the system before every stage has rendered and passed its
// dry run. The pending confirmation is written to disk before the first
// stage is applied, so a crash or reboot inside the window rolls back on the
// next start instead of leaving an unconfirmed change in place.
package confapply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
)

// Stage renders one part of the system (packet filter, routing daemon, VPN,
// proxy) from the model and applies it. Render must be pure: the same state
// always gives the same bytes, which is what golden-file tests pin down.
type Stage interface {
	Name() string
	Render(s *confstore.State) ([]byte, error)
	// Check is the dry run: it must not change the running system.
	Check(ctx context.Context, artifact []byte) error
	// Apply replaces the running configuration atomically.
	Apply(ctx context.Context, artifact []byte) error
	// Healthy reports whether the stage works after an apply.
	Healthy(ctx context.Context) error
}

// Redactor is implemented by stages whose artifact can contain secrets. Its
// result is what a person is shown instead of the artifact.
type Redactor interface {
	Redact(artifact []byte) []byte
}

// Display returns the artifacts in the form a person may see.
func (e *Engine) Display(arts map[string][]byte) map[string]string {
	out := make(map[string]string, len(arts))
	for _, st := range e.stages {
		a, ok := arts[st.Name()]
		if !ok {
			continue
		}
		if r, ok := st.(Redactor); ok {
			a = r.Redact(a)
		}
		out[st.Name()] = string(a)
	}
	return out
}

// DefaultWindow is how long an applied change waits for confirmation.
const DefaultWindow = 60 * time.Second

// SystemActor is recorded as the author of automatic rollbacks.
const SystemActor = "system:rollback"

var (
	// ErrPending is returned while an applied change awaits confirmation.
	// No further change is accepted until it is confirmed or rolled back.
	ErrPending = errors.New("confapply: a change is waiting for confirmation")
	// ErrNothingPending is returned by Confirm and Rollback when no change
	// is waiting.
	ErrNothingPending = errors.New("confapply: no change is waiting for confirmation")
)

// StageError says which stage failed in which phase.
type StageError struct {
	Stage string
	Phase string // "render", "check", "apply", "health", "rollback"
	Err   error
	// RolledBack is set when the failure happened after the commit and the
	// previous configuration was restored.
	RolledBack bool
}

func (e *StageError) Error() string {
	s := fmt.Sprintf("%s failed in stage %s: %v", e.Phase, e.Stage, e.Err)
	if e.RolledBack {
		s += " (previous configuration restored)"
	}
	return s
}
func (e *StageError) Unwrap() error { return e.Err }

// Pending describes the change that awaits confirmation.
type Pending struct {
	Index    int64     `json:"index"`
	Actor    string    `json:"actor"`
	Note     string    `json:"note,omitempty"`
	Deadline time.Time `json:"deadline"`
}

// Notice is emitted for every outcome so the caller can audit and display it.
type Notice struct {
	Event  string // "applied", "confirmed", "rolled_back", "rollback_failed"
	Index  int64
	Actor  string
	Reason string
	Err    error
}

// Engine serialises applies for one node.
type Engine struct {
	store  *confstore.Store
	stages []Stage
	window time.Duration
	file   string
	notify func(Notice)

	mu      sync.Mutex
	pending *Pending
	prev    map[string][]byte // artifacts in force before the pending change
	// touched lists the stages the pending change gave other artifacts;
	// nil after a restart, when it is not known.
	touched map[string]bool
	// applied holds, per stage, the artifact it last applied successfully.
	// A stage's rendering may depend on more than the model (run-time
	// alias contents, backend health), so this, not a fresh render of the
	// current model, is what a change is compared with.
	appliedArt map[string][]byte
	timer      *time.Timer

	// Cluster membership (see cluster.go). applied is the model index this
	// member last put into effect, failed the one it last failed at.
	cluster   Cluster
	maxFailed int
	applied   int64
	failed    int64
	override  *LocalOverride
	overFile  string
	// overrideTold is when the cluster was last told about the override.
	overrideTold time.Time
}

// stateT and Op keep cluster.go readable.
type (
	stateT = *confstore.State
	Op     = confstore.Op
)

// LocalOverride is a change that is in force on one member only, made
// while that member was cut off from the cluster.
type LocalOverride struct {
	Actor  string    `json:"actor"`
	Reason string    `json:"reason"`
	Base   int64     `json:"base"` // the model index it was made on
	At     time.Time `json:"at"`
	Ops    []Op      `json:"ops"`
}

func (e *Engine) writeOverride(o *LocalOverride) error {
	if o == nil {
		if err := os.Remove(e.overFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := json.Marshal(o)
	if err != nil {
		return err
	}
	tmp := e.overFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.overFile)
}

// Options configures an Engine.
type Options struct {
	// Dir holds the pending-confirmation marker (created 0700).
	Dir string
	// Window overrides DefaultWindow.
	Window time.Duration
	// Notify receives every outcome. It is called with the engine locked
	// and must not call back into it.
	Notify func(Notice)
}

// New builds an engine. Stages are applied in the given order and rolled
// back in reverse.
func New(store *confstore.Store, opts Options, stages ...Stage) (*Engine, error) {
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, err
	}
	e := &Engine{store: store, stages: stages, window: opts.Window, notify: opts.Notify,
		file: filepath.Join(opts.Dir, "pending-apply.json"), overFile: filepath.Join(opts.Dir, "local-override.json")}
	if e.window <= 0 {
		e.window = DefaultWindow
	}
	if e.notify == nil {
		e.notify = func(Notice) {}
	}
	return e, nil
}

// Pending returns the change that awaits confirmation, if any.
func (e *Engine) Pending() (Pending, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cluster != nil {
		// The same answer on every member.
		if p := e.cluster.View().Pending; p != nil {
			return *p, true
		}
		return Pending{}, false
	}
	if e.pending == nil {
		return Pending{}, false
	}
	return *e.pending, true
}

// Start brings the running system in line with the model. If the process
// stopped while a change was unconfirmed, that change is rolled back first.
// Call it once before serving requests.
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if data, err := os.ReadFile(e.overFile); err == nil {
		// A local override survives a restart: it is in force until
		// someone resolves it.
		var o LocalOverride
		if json.Unmarshal(data, &o) == nil {
			if cand, _, perr := e.store.Current().Prepare(o.Actor, o.Ops); perr == nil {
				e.override = &o
				return e.convergeLocked(ctx, cand)
			}
		}
	}
	if e.cluster != nil {
		// Fail-static: the member starts with the last model it has, and
		// follows the cluster from there. Whether a change is pending is
		// the cluster's knowledge, not a file's.
		head := e.store.Current()
		if err := e.convergeLocked(ctx, head); err != nil {
			return err
		}
		e.applied = head.Index()
		return nil
	}
	if data, err := os.ReadFile(e.file); err == nil {
		var p Pending
		if err := json.Unmarshal(data, &p); err != nil {
			return fmt.Errorf("confapply: unreadable %s: %w", e.file, err)
		}
		e.pending = &p
		return e.rollbackLocked(ctx, SystemActor, "restart before the change was confirmed")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	arts, err := e.render(e.store.Current())
	if err != nil {
		return err
	}
	for _, st := range e.stages {
		if err := st.Apply(ctx, arts[st.Name()]); err != nil {
			return &StageError{Stage: st.Name(), Phase: "apply", Err: err}
		}
		e.recordApplied(st.Name(), arts[st.Name()])
	}
	return nil
}

// recordApplied remembers what a stage runs now.
func (e *Engine) recordApplied(stage string, art []byte) {
	if e.appliedArt == nil {
		e.appliedArt = map[string][]byte{}
	}
	e.appliedArt[stage] = art
}

// changes reports whether a stage has to apply art: it differs from what
// the stage last applied, or, for a stage that never applied anything
// successfully, from what the current model renders to.
func (e *Engine) changes(stage string, prev, art []byte) bool {
	if last, ok := e.appliedArt[stage]; ok {
		return !bytes.Equal(last, art)
	}
	return !bytes.Equal(prev, art)
}

func (e *Engine) render(s *confstore.State) (map[string][]byte, error) {
	out := make(map[string][]byte, len(e.stages))
	for _, st := range e.stages {
		a, err := st.Render(s)
		if err != nil {
			return nil, &StageError{Stage: st.Name(), Phase: "render", Err: err}
		}
		out[st.Name()] = a
	}
	return out, nil
}

// Plan validates ops and renders every stage without committing or changing
// anything. It returns the artifacts the change would produce.
func (e *Engine) Plan(ctx context.Context, actor string, ops []confstore.Op) (map[string][]byte, []confstore.Change, error) {
	cand, changes, err := e.store.Preview(actor, ops)
	if err != nil {
		return nil, nil, err
	}
	arts, err := e.render(cand)
	if err != nil {
		return nil, nil, err
	}
	for _, st := range e.stages {
		if err := st.Check(ctx, arts[st.Name()]); err != nil {
			return nil, nil, &StageError{Stage: st.Name(), Phase: "check", Err: err}
		}
	}
	return arts, changes, nil
}

// Apply runs the whole pipeline for ops as one transaction. changeSets are
// consumed by the commit. On success the change is live and waits for
// Confirm until the returned deadline; without it the previous configuration
// comes back.
func (e *Engine) Apply(ctx context.Context, actor, note string, ops []confstore.Op, changeSets ...string) (Pending, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.override != nil {
		return Pending{}, ErrOverride
	}
	if c := e.cluster; c != nil {
		if !c.IsLeader() {
			return Pending{}, ErrNotLeader
		}
		if c.View().Pending != nil {
			return Pending{}, ErrPending
		}
	}
	if e.pending != nil {
		return Pending{}, ErrPending
	}
	prev, err := e.render(e.store.Current())
	if err != nil {
		return Pending{}, err
	}
	arts, _, err := e.Plan(ctx, actor, ops)
	if err != nil {
		return Pending{}, err
	}

	deadline := time.Now().Add(e.window).UTC()
	if e.cluster != nil {
		// The deadline goes into the same log entry as the record.
		e.cluster.AttachPending(Pending{Actor: actor, Note: note, Deadline: deadline})
	}
	rec, err := e.store.Commit(ctx, actor, note, ops, changeSets...)
	if err != nil {
		return Pending{}, err
	}
	p := Pending{Index: rec.Index, Actor: actor, Note: note, Deadline: deadline}
	if e.cluster != nil {
		// No marker file: the cluster holds the pending change.
	} else if err := e.writeMarker(p); err != nil {
		// Without a durable marker a crash could leave the change
		// unconfirmed forever, so do not start applying.
		_, rerr := e.store.Revert(ctx, SystemActor, rec.Index, "could not record the pending confirmation")
		return Pending{}, errors.Join(fmt.Errorf("confapply: write marker: %w", err), rerr)
	}
	// A stage the change does not touch is left alone: its artifacts are
	// what it runs already, and a stage that cannot be applied here (no
	// privileges, a daemon missing) does not block unrelated changes.
	touched := map[string]bool{}
	for _, st := range e.stages {
		touched[st.Name()] = e.changes(st.Name(), prev[st.Name()], arts[st.Name()])
	}
	e.pending, e.prev, e.touched = &p, prev, touched

	fail := func(stage, phase string, cause error) (Pending, error) {
		rbErr := e.rollbackLocked(ctx, SystemActor, fmt.Sprintf("%s failed in stage %s: %v", phase, stage, cause))
		return Pending{}, errors.Join(&StageError{Stage: stage, Phase: phase, Err: cause, RolledBack: rbErr == nil}, rbErr)
	}
	for _, st := range e.stages {
		if !touched[st.Name()] {
			continue
		}
		if err := st.Apply(ctx, arts[st.Name()]); err != nil {
			return fail(st.Name(), "apply", err)
		}
		e.recordApplied(st.Name(), arts[st.Name()])
	}
	for _, st := range e.stages {
		if !touched[st.Name()] {
			continue
		}
		if err := st.Healthy(ctx); err != nil {
			return fail(st.Name(), "health", err)
		}
	}

	if c := e.cluster; c != nil {
		// This member was the canary and is healthy: the others follow.
		e.applied, e.failed = p.Index, 0
		c.Report(p.Index, nil, "")
		if err := c.OpenRollout(p.Index); err != nil {
			rbErr := e.rollbackLocked(ctx, SystemActor, fmt.Sprintf("the rollout could not be opened: %v", err))
			return Pending{}, errors.Join(err, rbErr)
		}
	}
	e.timer = time.AfterFunc(time.Until(deadline), func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		// The timer may fire while Confirm holds the lock.
		if e.pending != nil && e.pending.Index == p.Index && (e.cluster == nil || e.cluster.IsLeader()) {
			_ = e.rollbackLocked(context.Background(), SystemActor, "not confirmed in time")
		}
	})
	e.notify(Notice{Event: "applied", Index: p.Index, Actor: actor})
	return p, nil
}

// Confirm keeps the pending change.
func (e *Engine) Confirm(actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c := e.cluster; c != nil {
		p := c.View().Pending
		if p == nil {
			return ErrNothingPending
		}
		if !c.IsLeader() {
			return ErrNotLeader
		}
		if err := c.ClearPending(); err != nil {
			return err
		}
		if e.timer != nil {
			e.timer.Stop()
		}
		e.pending, e.prev, e.timer, e.touched = nil, nil, nil, nil
		e.notify(Notice{Event: "confirmed", Index: p.Index, Actor: actor})
		return nil
	}
	if e.pending == nil {
		return ErrNothingPending
	}
	if e.timer != nil {
		e.timer.Stop()
	}
	if err := os.Remove(e.file); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	idx := e.pending.Index
	e.pending, e.prev, e.timer, e.touched = nil, nil, nil, nil
	e.notify(Notice{Event: "confirmed", Index: idx, Actor: actor})
	return nil
}

// Rollback takes the pending change back now.
func (e *Engine) Rollback(ctx context.Context, actor, reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c := e.cluster; c != nil {
		if !c.IsLeader() {
			return ErrNotLeader
		}
		if p := c.View().Pending; p != nil && e.pending == nil {
			q := *p
			e.pending = &q
		}
	}
	if e.pending == nil {
		return ErrNothingPending
	}
	return e.rollbackLocked(ctx, actor, reason)
}

// rollbackLocked reverts the pending record in the model and re-applies the
// previous artifacts to every stage, in reverse order. It keeps going after
// a failing stage so one broken stage cannot keep the others on the new
// configuration.
func (e *Engine) rollbackLocked(ctx context.Context, actor, reason string) error {
	p := *e.pending
	if e.timer != nil {
		e.timer.Stop()
	}
	var errs []error
	if e.cluster != nil {
		// The revert ends the confirmation window and the rollout in the
		// same log entry.
		e.cluster.AttachClear()
	}
	rev, err := e.store.Revert(ctx, actor, p.Index, reason)
	if err != nil {
		errs = append(errs, fmt.Errorf("revert record %d: %w", p.Index, err))
	} else if e.cluster != nil {
		e.applied, e.failed = rev.Index, 0
		defer func() { e.cluster.Report(rev.Index, nil, "") }()
	}
	prev := e.prev
	if prev == nil {
		// After a restart the previous artifacts are gone; the reverted
		// model renders to the same thing.
		var err error
		if prev, err = e.render(e.store.Current()); err != nil {
			errs = append(errs, err)
		}
	}
	for i := len(e.stages) - 1; i >= 0 && prev != nil; i-- {
		st := e.stages[i]
		if e.touched != nil && !e.touched[st.Name()] {
			continue
		}
		if err := st.Apply(ctx, prev[st.Name()]); err != nil {
			errs = append(errs, &StageError{Stage: st.Name(), Phase: "rollback", Err: err})
		} else {
			e.recordApplied(st.Name(), prev[st.Name()])
		}
	}
	if err := os.Remove(e.file); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	e.pending, e.prev, e.timer, e.touched = nil, nil, nil, nil
	if err := errors.Join(errs...); err != nil {
		e.notify(Notice{Event: "rollback_failed", Index: p.Index, Actor: actor, Reason: reason, Err: err})
		return fmt.Errorf("confapply: rollback of record %d incomplete: %w", p.Index, err)
	}
	e.notify(Notice{Event: "rolled_back", Index: p.Index, Actor: actor, Reason: reason})
	return nil
}

func (e *Engine) writeMarker(p Pending) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tmp := e.file + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, e.file)
}
