package cluster

import (
	"context"
	"sort"
	"time"

	"github.com/noahzmr/testudo/internal/confapply"
)

// Applier connects a member's apply engine to the cluster: it is the
// confapply.Cluster of this member.
type Applier struct {
	Node *Node
	// Send delivers a report to the leader when this member does not
	// lead. Nil drops reports of followers.
	Send func(Result) error
	Now  func() time.Time
}

var _ confapply.Cluster = (*Applier)(nil)

func (a *Applier) NodeID() string { return a.Node.ID() }
func (a *Applier) IsLeader() bool { return a.Node.IsLeader() }

func (a *Applier) AttachPending(p confapply.Pending) {
	a.Node.Attach(&Pending{Actor: p.Actor, Note: p.Note, Deadline: p.Deadline}, true,
		&Rollout{Canary: a.Node.ID(), Phase: PhaseCanary}, true)
}

func (a *Applier) AttachClear() { a.Node.Attach(nil, true, nil, true) }

func (a *Applier) ClearPending() error {
	c, err := command(CmdPending, "", (*Pending)(nil))
	if err != nil {
		return err
	}
	return a.Node.Propose(context.Background(), c)
}

func (a *Applier) OpenRollout(index int64) error {
	c, err := command(CmdRollout, "", &Rollout{Index: index, Canary: a.Node.ID(), Phase: PhaseAll})
	if err != nil {
		return err
	}
	return a.Node.Propose(context.Background(), c)
}

func (a *Applier) View() confapply.ClusterView {
	st := a.Node.State()
	v := confapply.ClusterView{
		MayApply: func(index int64) bool { return st.MayApply(a.Node.ID(), index) },
		Failed: func(index int64) []string {
			var out []string
			for id, r := range st.Results {
				if r.Index >= index && !r.OK {
					out = append(out, id)
				}
			}
			sort.Strings(out)
			return out
		},
	}
	if p := st.Pending; p != nil {
		v.Pending = &confapply.Pending{Index: p.Index, Actor: p.Actor, Note: p.Note, Deadline: p.Deadline}
	}
	return v
}

// Report publishes the result without holding the caller up: the leader
// may be unreachable, and applying must not wait for it.
func (a *Applier) Report(index int64, applyErr error, drift string) {
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	r := Result{Node: a.Node.ID(), Index: index, OK: applyErr == nil, At: now().UTC(), Drift: drift}
	if applyErr != nil {
		r.Error = applyErr.Error()
	}
	go func() {
		if a.Node.IsLeader() {
			if c, err := command(CmdResult, "", r); err == nil {
				_ = a.Node.Propose(context.Background(), c)
			}
			return
		}
		if a.Send != nil {
			_ = a.Send(r)
		}
	}()
}
