package confapply

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// In a cluster a change is committed once, by the leader, and applied by
// every member itself. The engine keeps doing what it does on a single
// node, with these differences:
//
//   - The pending confirmation is cluster state, not a file: it travels in
//     the same log entry as the record, so whoever leads when the deadline
//     passes can roll back, and a record without a deadline cannot exist.
//   - The member that leads when the change is made is its canary. Only it
//     applies at first. When its stages report healthy the rollout is
//     opened and the others follow, each through Sync.
//   - Every member reports how applying went. More failures than allowed
//     roll the change back for everyone.

// Cluster is what the engine needs from the group.
type Cluster interface {
	NodeID() string
	IsLeader() bool
	// AttachPending makes the next commit carry p and a rollout that
	// starts with this member as the canary. AttachClear makes it clear
	// both (the commit is a rollback).
	AttachPending(p Pending)
	AttachClear()
	// ClearPending ends the confirmation window and the rollout.
	ClearPending() error
	// OpenRollout lets every member apply the record at index.
	OpenRollout(index int64) error
	// View returns the cluster's side of the current rollout.
	View() ClusterView
	// Report publishes how applying the model at index went here.
	Report(index int64, applyErr error, drift string)
}

// ClusterView is the replicated state the engine acts on.
type ClusterView struct {
	Pending *Pending
	// MayApply reports whether this member may apply the model at index.
	MayApply func(index int64) bool
	// Failed lists the members that reported a failure for index or later.
	Failed func(index int64) []string
}

var (
	// ErrNotLeader means the change has to be made on the leader. The API
	// layer forwards it there.
	ErrNotLeader = errors.New("confapply: this member does not lead the cluster")
	// ErrOverride means a local override is in force; resolve it first.
	ErrOverride = errors.New("confapply: a local override is in force on this member")
)

// SetCluster makes the engine a cluster member (nil: a single node again).
// maxFailed is how many members may fail to apply a change before it is
// rolled back for everyone.
func (e *Engine) SetCluster(c Cluster, maxFailed int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cluster, e.maxFailed = c, maxFailed
}

// Sync brings this member in line with the cluster. It applies the model
// when the rollout lets this member apply, reports the result, and does
// the leader's part: watching the deadline and the other members' reports.
// It is called whenever the replicated state changed, and periodically.
func (e *Engine) Sync(ctx context.Context) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.cluster
	if c == nil {
		return
	}
	view := c.View()
	e.leadLocked(ctx, c, view)
	if o := e.override; o != nil {
		// The local override stays until someone resolves it. The cluster
		// is told again and again: the first report was made while this
		// member could not reach anyone.
		if time.Since(e.overrideTold) > 10*time.Second {
			e.overrideTold = time.Now()
			c.Report(e.store.Current().Index(), nil, "local override by "+o.Actor+": "+o.Reason)
		}
		return
	}
	head := e.store.Current()
	idx := head.Index()
	if idx == e.applied || idx == e.failed || !view.MayApply(idx) {
		return
	}
	err := e.convergeLocked(ctx, head)
	if err != nil {
		e.failed = idx
		e.notify(Notice{Event: "apply_failed", Index: idx, Actor: SystemActor, Err: err})
	} else {
		e.applied, e.failed = idx, 0
	}
	c.Report(idx, err, "")
}

// convergeLocked renders the given state and puts it into effect.
func (e *Engine) convergeLocked(ctx context.Context, st stateT) error {
	arts, err := e.render(st)
	if err != nil {
		return err
	}
	for _, s := range e.stages {
		if err := s.Check(ctx, arts[s.Name()]); err != nil {
			return &StageError{Stage: s.Name(), Phase: "check", Err: err}
		}
	}
	for _, s := range e.stages {
		if err := s.Apply(ctx, arts[s.Name()]); err != nil {
			return &StageError{Stage: s.Name(), Phase: "apply", Err: err}
		}
	}
	for _, s := range e.stages {
		if err := s.Healthy(ctx); err != nil {
			return &StageError{Stage: s.Name(), Phase: "health", Err: err}
		}
	}
	return nil
}

// leadLocked is the leader's part of a rollout.
func (e *Engine) leadLocked(ctx context.Context, c Cluster, view ClusterView) {
	if !c.IsLeader() {
		// Whoever leads now watches the deadline.
		if e.timer != nil {
			e.timer.Stop()
		}
		e.pending, e.prev, e.timer, e.touched = nil, nil, nil, nil
		return
	}
	switch {
	case view.Pending == nil:
		// Confirmed or rolled back, here or by a previous leader.
		if e.timer != nil {
			e.timer.Stop()
		}
		e.pending, e.prev, e.timer, e.touched = nil, nil, nil, nil
		return
	case e.pending == nil || e.pending.Index != view.Pending.Index:
		// This member became leader while a change was pending, or the
		// change is one whose proposal looked failed and was agreed on
		// after all. Either way it now has to be confirmed in time or go.
		p := *view.Pending
		e.pending, e.prev = &p, nil
		if e.timer != nil {
			e.timer.Stop()
		}
		left := time.Until(p.Deadline)
		if left <= 0 {
			_ = e.rollbackLocked(ctx, SystemActor, "not confirmed in time")
			return
		}
		e.timer = time.AfterFunc(left, func() {
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.pending != nil && e.pending.Index == p.Index && e.cluster != nil && e.cluster.IsLeader() {
				_ = e.rollbackLocked(context.Background(), SystemActor, "not confirmed in time")
			}
		})
	}
	if failed := view.Failed(e.pending.Index); len(failed) > e.maxFailed {
		_ = e.rollbackLocked(ctx, SystemActor, "applying failed on "+strings.Join(failed, ", "))
	}
}

// Override puts ops into effect on this member only, without the cluster.
// It exists for one situation: the member is cut off from the majority,
// the cluster cannot accept a change, and something has to be changed here
// now. Nothing is written to the model. The override stays in force, and
// keeps the member from following the cluster, until it is resolved.
func (e *Engine) Override(ctx context.Context, actor, reason string, ops []Op) (LocalOverride, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cluster == nil {
		return LocalOverride{}, errors.New("confapply: not a cluster member; make the change normally")
	}
	if e.cluster.IsLeader() {
		return LocalOverride{}, errors.New("confapply: this member leads a working cluster; make the change normally")
	}
	base := e.store.Current()
	all := ops
	if e.override != nil {
		all = append(append([]Op(nil), e.override.Ops...), ops...)
	}
	cand, _, err := base.Prepare(actor, all)
	if err != nil {
		return LocalOverride{}, err
	}
	if err := e.convergeLocked(ctx, cand); err != nil {
		// Put back what was running: the model, or the earlier override.
		back := stateT(base)
		if e.override != nil {
			if prev, _, perr := base.Prepare(actor, e.override.Ops); perr == nil {
				back = prev
			}
		}
		rbErr := e.convergeLocked(ctx, back)
		return LocalOverride{}, errors.Join(err, rbErr)
	}
	o := LocalOverride{Actor: actor, Reason: reason, Base: base.Index(), At: time.Now().UTC(), Ops: all}
	if err := e.writeOverride(&o); err != nil {
		return LocalOverride{}, fmt.Errorf("confapply: the override is in force but could not be recorded: %w", err)
	}
	e.override = &o
	e.notify(Notice{Event: "override", Index: o.Base, Actor: actor, Reason: reason})
	e.cluster.Report(o.Base, nil, "local override by "+actor+": "+reason)
	return o, nil
}

// CurrentOverride returns the local override in force, if any.
func (e *Engine) CurrentOverride() (LocalOverride, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.override == nil {
		return LocalOverride{}, false
	}
	return *e.override, true
}

// ResolveOverride ends a local override. The member goes back to the
// cluster's model. The override's changes are returned so that whoever
// reviews them can make them again as an ordinary change; they are never
// merged by themselves.
func (e *Engine) ResolveOverride(ctx context.Context, actor string) (LocalOverride, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.override == nil {
		return LocalOverride{}, ErrNothingPending
	}
	o := *e.override
	if err := e.writeOverride(nil); err != nil {
		return LocalOverride{}, err
	}
	e.override, e.applied, e.failed = nil, 0, 0
	e.notify(Notice{Event: "override_resolved", Index: o.Base, Actor: actor})
	return o, nil
}

// Repair compares the running system with the model: every stage is asked
// whether it still runs what was applied. A member that drifted is brought
// back by applying the model again; the drift and the outcome are reported
// to the cluster either way. It returns what differed, or "".
func (e *Engine) Repair(ctx context.Context) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var drift []string
	for _, s := range e.stages {
		if err := s.Healthy(ctx); err != nil {
			drift = append(drift, s.Name()+": "+err.Error())
		}
	}
	if len(drift) == 0 || e.override != nil || e.pending != nil {
		return ""
	}
	what := strings.Join(drift, "; ")
	head := e.store.Current()
	err := e.convergeLocked(ctx, head)
	if e.cluster != nil {
		note := "repaired: " + what
		if err != nil {
			note = "not repaired: " + what
		}
		e.cluster.Report(head.Index(), err, note)
	}
	e.notify(Notice{Event: "drift", Index: head.Index(), Actor: SystemActor, Reason: what, Err: err})
	return what
}

// Applied returns the model index this member last put into effect.
func (e *Engine) Applied() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.applied
}
