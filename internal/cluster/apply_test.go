package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

// stage is a member's running system: it remembers every configuration it
// was told to run, and can be made to fail.
type stage struct {
	mu        sync.Mutex
	running   string
	history   []string
	failApply string // an artifact containing this is refused
	unhealthy string // an artifact containing this applies and is unhealthy
}

func (s *stage) Name() string { return "test" }
func (s *stage) Render(st *confstore.State) ([]byte, error) {
	var names []string
	for _, e := range st.List(model.KindAlias) {
		names = append(names, e.GetMeta().Name)
	}
	return []byte(strings.Join(names, ",")), nil
}
func (s *stage) Check(context.Context, []byte) error { return nil }
func (s *stage) Apply(_ context.Context, art []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failApply != "" && strings.Contains(string(art), s.failApply) {
		return errors.New("the kernel refused it")
	}
	s.running = string(art)
	s.history = append(s.history, string(art))
	return nil
}
func (s *stage) Healthy(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unhealthy != "" && strings.Contains(s.running, s.unhealthy) {
		return errors.New("no traffic passes")
	}
	return nil
}
func (s *stage) now() string { s.mu.Lock(); defer s.mu.Unlock(); return s.running }
func (s *stage) ran(part string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.history {
		if strings.Contains(h, part) {
			return true
		}
	}
	return false
}

// site is a member with its apply engine and its running system.
type site struct {
	*member
	eng   *confapply.Engine
	stage *stage
	wake  chan struct{}
}

type fleet struct {
	*cluster
	sites  map[string]*site
	window time.Duration
}

// newFleet forms a cluster whose members each run an apply engine.
func newFleet(t *testing.T, window time.Duration, ids ...string) *fleet {
	f := &fleet{cluster: newCluster(t), sites: map[string]*site{}, window: window}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	f.opts = func(id string, o *Options) {
		s := f.sites[id]
		if s == nil {
			s = &site{stage: &stage{}, wake: make(chan struct{}, 1)}
			f.sites[id] = s
		}
		o.Changed = func() {
			select {
			case s.wake <- struct{}{}:
			default:
			}
		}
	}
	f.form(ids...)
	for _, id := range ids {
		f.engine(id, stop)
	}
	return f
}

// engine gives a started member its apply engine and the loop that keeps
// it in step with the cluster.
func (f *fleet) engine(id string, stop chan struct{}) {
	f.t.Helper()
	s := f.sites[id]
	f.mu.Lock()
	s.member = f.members[id]
	f.mu.Unlock()
	eng, err := confapply.New(s.store, confapply.Options{Dir: filepath.Join(s.dir, "apply"), Window: f.window}, s.stage)
	if err != nil {
		f.t.Fatal(err)
	}
	s.eng = eng
	node := s.node
	eng.SetCluster(&Applier{Node: node, Send: func(r Result) error {
		// What the member API does in the daemon: hand the report to
		// whoever leads.
		for _, m := range f.running() {
			if m.node.IsLeader() {
				c, _ := command(CmdResult, "", r)
				return m.node.Propose(ctx, c)
			}
		}
		return ErrNoQuorum
	}}, 0)
	if err := eng.Start(ctx); err != nil {
		f.t.Fatal(err)
	}
	go func() {
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-s.wake:
			case <-tick.C:
			}
			eng.Sync(ctx)
		}
	}()
}

func (f *fleet) lead() *site { return f.sites[f.leader().id] }

func create(name string) []confstore.Op {
	obj, _ := json.Marshal(alias(name))
	return []confstore.Op{{Type: confstore.OpCreate, Kind: model.KindAlias, Object: obj}}
}

// eventually waits for cond; what describes it for the failure message.
func (f *fleet) eventually(what string, cond func() bool) {
	f.t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
	}
	var state []string
	for id, s := range f.sites {
		state = append(state, fmt.Sprintf("%s runs %q", id, s.stage.now()))
	}
	f.t.Fatalf("never: %s (%s)", what, strings.Join(state, "; "))
}

func (f *fleet) allRun(want string) func() bool {
	return func() bool {
		for _, s := range f.sites {
			if s.stage.now() != want {
				return false
			}
		}
		return true
	}
}

func TestChangeRollsOutCanaryFirst(t *testing.T) {
	f := newFleet(t, time.Minute, "a", "b", "c")
	l := f.lead()
	// A member that does not lead refuses; the API layer forwards.
	for _, s := range f.sites {
		if s != l {
			if _, err := s.eng.Apply(ctx, "alice", "", create("x")); !errors.Is(err, confapply.ErrNotLeader) {
				t.Fatalf("apply on a follower: %v", err)
			}
		}
	}
	p, err := l.eng.Apply(ctx, "alice", "first", create("one"))
	if err != nil {
		t.Fatal(err)
	}
	if l.stage.now() != "one" {
		t.Fatalf("the canary runs %q", l.stage.now())
	}
	f.eventually("every member runs the change", f.allRun("one"))
	// Every member knows the change is pending, and who made it.
	for id, s := range f.sites {
		f.eventually(id+" sees the pending change", func() bool {
			got, ok := s.eng.Pending()
			return ok && got.Index == p.Index && got.Actor == "alice"
		})
	}
	// Every member reported.
	f.eventually("three reports", func() bool {
		st := l.node.State()
		n := 0
		for _, r := range st.Results {
			if r.Index == p.Index && r.OK {
				n++
			}
		}
		return n == 3
	})
	// A second change has to wait.
	if _, err := l.eng.Apply(ctx, "bob", "", create("two")); !errors.Is(err, confapply.ErrPending) {
		t.Errorf("second change while one is pending: %v", err)
	}
	if err := l.eng.Confirm("alice"); err != nil {
		t.Fatal(err)
	}
	for id, s := range f.sites {
		f.eventually(id+" sees the confirmation", func() bool { _, ok := s.eng.Pending(); return !ok })
	}
	if _, err := l.eng.Apply(ctx, "bob", "", create("two")); err != nil {
		t.Fatalf("change after the confirmation: %v", err)
	}
	f.eventually("every member runs both", f.allRun("one,two"))
}

func TestUnhealthyCanaryStopsTheRollout(t *testing.T) {
	f := newFleet(t, time.Minute, "a", "b", "c")
	l := f.lead()
	if _, err := l.eng.Apply(ctx, "alice", "", create("good")); err != nil {
		t.Fatal(err)
	}
	if err := l.eng.Confirm("alice"); err != nil {
		t.Fatal(err)
	}
	f.eventually("every member runs the first change", f.allRun("good"))

	l.stage.unhealthy = "bad"
	_, err := l.eng.Apply(ctx, "alice", "", create("bad"))
	var se *confapply.StageError
	if !errors.As(err, &se) || se.Phase != "health" || !se.RolledBack {
		t.Fatalf("apply with an unhealthy canary: %v", err)
	}
	// The canary is back on what it ran, the model is back, and nobody
	// else ever ran the change.
	f.eventually("the model is reverted everywhere", func() bool {
		for _, s := range f.sites {
			if s.names()["bad"] {
				return false
			}
		}
		return true
	})
	time.Sleep(500 * time.Millisecond)
	for id, s := range f.sites {
		if s.stage.now() != "good" {
			t.Errorf("%s runs %q", id, s.stage.now())
		}
		if s != l && s.stage.ran("bad") {
			t.Errorf("%s ran the change the canary rejected", id)
		}
		if _, pending := s.eng.Pending(); pending {
			t.Errorf("%s still sees a pending change", id)
		}
	}
}

func TestFailureOnAnotherMemberRollsEveryoneBack(t *testing.T) {
	f := newFleet(t, time.Minute, "a", "b", "c")
	l := f.lead()
	if _, err := l.eng.Apply(ctx, "alice", "", create("good")); err != nil {
		t.Fatal(err)
	}
	l.eng.Confirm("alice")
	f.eventually("every member runs the first change", f.allRun("good"))
	var weak *site
	for _, s := range f.sites {
		if s != l {
			weak = s
			break
		}
	}
	weak.stage.failApply = "bad"
	// The canary is fine, so the apply itself succeeds.
	if _, err := l.eng.Apply(ctx, "alice", "", create("bad")); err != nil {
		t.Fatal(err)
	}
	// Then one member cannot apply it, and the change goes for everyone.
	f.eventually("everyone is back on the first change", func() bool {
		for _, s := range f.sites {
			if s.stage.now() != "good" || s.names()["bad"] {
				return false
			}
			if _, pending := s.eng.Pending(); pending {
				return false
			}
		}
		return true
	})
	if !l.stage.ran("bad") {
		t.Error("the canary never ran the change; the test proves nothing")
	}
	// The history says why.
	recs, _ := l.store.History(0, 1)
	if len(recs) != 1 || recs[0].Type != "revert" || !strings.Contains(recs[0].Note, weak.id) {
		t.Errorf("last record: %+v", recs)
	}
}

func TestUnconfirmedChangeGoesAwayEverywhere(t *testing.T) {
	f := newFleet(t, 700*time.Millisecond, "a", "b", "c")
	l := f.lead()
	if _, err := l.eng.Apply(ctx, "alice", "", create("unconfirmed")); err != nil {
		t.Fatal(err)
	}
	f.eventually("every member runs the change", f.allRun("unconfirmed"))
	f.eventually("every member is back without it", func() bool {
		for _, s := range f.sites {
			if s.stage.now() != "" || len(s.names()) != 0 {
				return false
			}
		}
		return true
	})
}

func TestNewLeaderWatchesThePendingChange(t *testing.T) {
	f := newFleet(t, 2*time.Second, "a", "b", "c")
	old := f.lead()
	if _, err := old.eng.Apply(ctx, "alice", "", create("orphan")); err != nil {
		t.Fatal(err)
	}
	f.eventually("every member runs the change", f.allRun("orphan"))
	// The leader goes away before anyone confirmed.
	f.stop(old.id)
	var rest []*site
	for _, s := range f.sites {
		if s != old {
			rest = append(rest, s)
		}
	}
	// Whoever leads now rolls it back when the deadline passes.
	f.eventually("the remaining members are back without the change", func() bool {
		for _, s := range rest {
			if s.stage.now() != "" || len(s.names()) != 0 {
				return false
			}
			if _, pending := s.eng.Pending(); pending {
				return false
			}
		}
		return true
	})
}

func TestNewLeaderCanConfirm(t *testing.T) {
	f := newFleet(t, time.Minute, "a", "b", "c")
	old := f.lead()
	if _, err := old.eng.Apply(ctx, "alice", "", create("kept")); err != nil {
		t.Fatal(err)
	}
	f.eventually("every member runs the change", f.allRun("kept"))
	if err := old.node.TransferLeadership(); err != nil {
		t.Fatal(err)
	}
	var next *site
	f.eventually("another member leads", func() bool {
		for _, s := range f.sites {
			if s != old && s.node.IsLeader() {
				next = s
				return true
			}
		}
		return false
	})
	if err := next.eng.Confirm("alice"); err != nil {
		t.Fatalf("confirm on the new leader: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if !f.allRun("kept")() {
		t.Error("the confirmed change did not stay")
	}
}

func TestCutOffMemberKeepsRunningAndCanBeOverridden(t *testing.T) {
	f := newFleet(t, time.Minute, "a", "b", "c")
	l := f.lead()
	if _, err := l.eng.Apply(ctx, "alice", "", create("base")); err != nil {
		t.Fatal(err)
	}
	l.eng.Confirm("alice")
	f.eventually("every member runs the base", f.allRun("base"))
	var cut *site
	var majority []string
	for id, s := range f.sites {
		if s != l && cut == nil {
			cut = s
		} else {
			majority = append(majority, id)
		}
	}
	// With a working cluster nobody overrides anything.
	if _, err := l.eng.Override(ctx, "root", "no reason", create("x")); err == nil {
		t.Error("an override on the leader of a working cluster")
	}
	f.net.partition([]string{cut.id}, majority)
	// The majority goes on.
	l = f.sites[f.leader(majority...).id]
	if _, err := l.eng.Apply(ctx, "alice", "", create("majority")); err != nil {
		t.Fatal(err)
	}
	l.eng.Confirm("alice")
	// The cut-off member keeps what it had, and cannot change the model.
	time.Sleep(500 * time.Millisecond)
	if cut.stage.now() != "base" {
		t.Fatalf("the cut-off member runs %q", cut.stage.now())
	}
	if _, err := cut.eng.Apply(ctx, "root", "", create("local")); !errors.Is(err, confapply.ErrNotLeader) {
		t.Fatalf("ordinary change on the cut-off member: %v", err)
	}
	// An explicit override changes what runs there, and nothing else.
	o, err := cut.eng.Override(ctx, "root", "uplink moved", create("emergency"))
	if err != nil {
		t.Fatal(err)
	}
	if cut.stage.now() != "base,emergency" || cut.names()["emergency"] || o.Base != 1 {
		t.Fatalf("after the override: runs %q, model has it: %v, base %d", cut.stage.now(), cut.names()["emergency"], o.Base)
	}
	// An override the system refuses leaves what was running.
	cut.stage.failApply = "broken"
	if _, err := cut.eng.Override(ctx, "root", "", create("broken")); err == nil || cut.stage.now() != "base,emergency" {
		t.Errorf("refused override: %v, runs %q", err, cut.stage.now())
	}

	f.net.heal()
	// The member gets the cluster's model again, and keeps running the
	// override: it is not overwritten behind anyone's back.
	f.converge(l.store.Current().Index(), cut.id)
	time.Sleep(500 * time.Millisecond)
	if cut.stage.now() != "base,emergency" {
		t.Fatalf("after the partition healed the member runs %q", cut.stage.now())
	}
	// The cluster sees that it differs, and why.
	f.eventually("the override shows up as drift", func() bool {
		return strings.Contains(l.node.State().Results[cut.id].Drift, "uplink moved")
	})
	if _, err := cut.eng.Apply(ctx, "root", "", create("y")); err == nil {
		t.Error("an ordinary change while the override is unresolved")
	}
	// Someone looks at it and resolves it; the changes are handed back to
	// be made properly or dropped.
	got, err := cut.eng.ResolveOverride(ctx, "alice")
	if err != nil || len(got.Ops) != 1 {
		t.Fatalf("resolve: %+v %v", got, err)
	}
	f.eventually("the member runs the cluster's model", func() bool { return cut.stage.now() == "base,majority" })
	if _, ok := cut.eng.CurrentOverride(); ok {
		t.Error("the override is still there")
	}
}

func TestChangeThatSurfacesLateIsRolledBack(t *testing.T) {
	f := newFleet(t, 600*time.Millisecond, "a", "b", "c")
	old := f.lead()
	var others []string
	for id, s := range f.sites {
		if s != old {
			others = append(others, id)
		}
	}
	// The leader is cut off in the middle of making a change: the change
	// is in its log, nobody else has it, and the operator is told it
	// failed.
	f.net.partition([]string{old.id}, []string{others[0]}, []string{others[1]})
	if _, err := old.eng.Apply(ctx, "alice", "", create("limbo")); err == nil {
		t.Fatal("a change was accepted without a majority")
	}
	time.Sleep(time.Second) // the confirmation deadline passes
	f.net.heal()
	// Whether or not the entry is agreed on after all, nobody ends up
	// running it and it is not left pending.
	f.eventually("nobody runs the change and nothing is pending", func() bool {
		if _, err := f.leaderErr(); err != nil {
			return false
		}
		for _, s := range f.sites {
			if s.names()["limbo"] || s.stage.now() != "" {
				return false
			}
			if _, pending := s.eng.Pending(); pending {
				return false
			}
		}
		return true
	})
	// And the cluster takes changes again.
	l := f.lead()
	if _, err := l.eng.Apply(ctx, "alice", "", create("after")); err != nil {
		t.Fatalf("change after the partition: %v", err)
	}
	f.eventually("every member runs it", f.allRun("after"))
}
