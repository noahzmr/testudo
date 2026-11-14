package confapply

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

var ctx = context.Background()

// fakeStage renders the sorted alias names and records what is "running".
type fakeStage struct {
	name string
	log  *[]string

	mu                           sync.Mutex
	running                      string
	failCheck, failApply, failHP string // artifact substring that triggers a failure
}

func (f *fakeStage) Name() string { return f.name }
func (f *fakeStage) Render(s *confstore.State) ([]byte, error) {
	var names []string
	for _, e := range s.List(model.KindAlias) {
		names = append(names, e.GetMeta().Name)
	}
	sort.Strings(names)
	return []byte(strings.Join(names, ",")), nil
}
func (f *fakeStage) Check(_ context.Context, a []byte) error {
	*f.log = append(*f.log, f.name+":check")
	if f.failCheck != "" && strings.Contains(string(a), f.failCheck) {
		return errors.New("syntax error")
	}
	return nil
}
func (f *fakeStage) Apply(_ context.Context, a []byte) error {
	*f.log = append(*f.log, f.name+":apply("+string(a)+")")
	if f.failApply != "" && strings.Contains(string(a), f.failApply) {
		return errors.New("kernel said no")
	}
	f.mu.Lock()
	f.running = string(a)
	f.mu.Unlock()
	return nil
}
func (f *fakeStage) Healthy(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failHP != "" && strings.Contains(f.running, f.failHP) {
		return errors.New("management unreachable")
	}
	return nil
}
func (f *fakeStage) now() string { f.mu.Lock(); defer f.mu.Unlock(); return f.running }

type rig struct {
	dir     string
	store   *confstore.Store
	eng     *Engine
	a, b    *fakeStage
	log     []string
	mu      sync.Mutex
	notices []Notice
}

func newRig(t *testing.T, window time.Duration) *rig {
	t.Helper()
	r := &rig{dir: t.TempDir()}
	r.a, r.b = &fakeStage{name: "filter", log: &r.log}, &fakeStage{name: "routing", log: &r.log}
	r.open(t, window)
	return r
}

func (r *rig) open(t *testing.T, window time.Duration) {
	t.Helper()
	var err error
	if r.store, err = confstore.Open(r.dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.store.Close() })
	r.eng, err = New(r.store, Options{Dir: r.dir, Window: window, Notify: func(n Notice) {
		r.mu.Lock()
		r.notices = append(r.notices, n)
		r.mu.Unlock()
	}}, r.a, r.b)
	if err != nil {
		t.Fatal(err)
	}
}

func (r *rig) events() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, n := range r.notices {
		out = append(out, n.Event)
	}
	return strings.Join(out, ",")
}

func addAlias(name string) []confstore.Op {
	obj, _ := json.Marshal(&model.Alias{Meta: model.Meta{Name: name}, Type: "host"})
	return []confstore.Op{{Type: confstore.OpCreate, Kind: model.KindAlias, Object: obj}}
}

func (r *rig) aliases() string {
	a, _ := r.a.Render(r.store.Current())
	return string(a)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestApplyThenConfirm(t *testing.T) {
	r := newRig(t, time.Hour)
	p, err := r.eng.Apply(ctx, "alice", "first", addAlias("web"))
	if err != nil {
		t.Fatal(err)
	}
	// Every dry run happens before anything is applied.
	want := "filter:check routing:check filter:apply(web) routing:apply(web)"
	if got := strings.Join(r.log, " "); got != want {
		t.Errorf("order:\n got %s\nwant %s", got, want)
	}
	if p.Index != 1 || time.Until(p.Deadline) < 59*time.Minute || r.a.now() != "web" {
		t.Errorf("pending %+v running %q", p, r.a.now())
	}
	if _, err := os.Stat(filepath.Join(r.dir, "pending-apply.json")); err != nil {
		t.Errorf("no durable pending marker: %v", err)
	}

	// A second change is refused until the first is settled.
	if _, err := r.eng.Apply(ctx, "bob", "", addAlias("db")); !errors.Is(err, ErrPending) {
		t.Errorf("apply during confirmation window: %v", err)
	}

	if err := r.eng.Confirm("alice"); err != nil {
		t.Fatal(err)
	}
	if _, pending := r.eng.Pending(); pending || r.aliases() != "web" {
		t.Errorf("after confirm: pending=%v model=%q", pending, r.aliases())
	}
	if _, err := os.Stat(filepath.Join(r.dir, "pending-apply.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("marker survived confirm: %v", err)
	}
	if err := r.eng.Confirm("alice"); !errors.Is(err, ErrNothingPending) {
		t.Errorf("double confirm: %v", err)
	}
	if r.events() != "applied,confirmed" {
		t.Errorf("notices: %s", r.events())
	}
}

func TestUnconfirmedChangeRollsBackAutomatically(t *testing.T) {
	r := newRig(t, time.Hour)
	if _, err := r.eng.Apply(ctx, "alice", "", addAlias("web")); err != nil {
		t.Fatal(err)
	}
	r.eng.Confirm("alice")

	r.eng.window = 500 * time.Millisecond
	if _, err := r.eng.Apply(ctx, "alice", "risky", addAlias("lockout")); err != nil {
		t.Fatal(err)
	}
	if r.a.now() != "lockout,web" {
		t.Fatalf("change not live: %q", r.a.now())
	}
	waitFor(t, "automatic rollback", func() bool { _, p := r.eng.Pending(); return !p })

	if r.a.now() != "web" || r.b.now() != "web" || r.aliases() != "web" {
		t.Errorf("after timeout: filter=%q routing=%q model=%q", r.a.now(), r.b.now(), r.aliases())
	}
	// The rollback is a new, attributed record; nothing is erased.
	hist, _ := r.store.History(0, 1)
	if hist[0].Type != "revert" || hist[0].Actor != SystemActor || hist[0].Reverts != 2 ||
		!strings.Contains(hist[0].Note, "not confirmed") {
		t.Errorf("rollback record: %+v", hist[0])
	}
	if r.events() != "applied,confirmed,applied,rolled_back" {
		t.Errorf("notices: %s", r.events())
	}
	// The system accepts changes again.
	if _, err := r.eng.Apply(ctx, "alice", "", addAlias("db")); err != nil {
		t.Errorf("apply after rollback: %v", err)
	}
}

func TestFailedDryRunChangesNothing(t *testing.T) {
	r := newRig(t, time.Hour)
	r.b.failCheck = "bad"
	_, err := r.eng.Apply(ctx, "alice", "", addAlias("bad"))
	var se *StageError
	if !errors.As(err, &se) || se.Stage != "routing" || se.Phase != "check" || se.RolledBack {
		t.Fatalf("err = %v", err)
	}
	if r.store.Current().Index() != 0 || strings.Contains(strings.Join(r.log, " "), "apply") {
		t.Errorf("a failed dry run committed or applied: index=%d log=%v", r.store.Current().Index(), r.log)
	}
	if _, pending := r.eng.Pending(); pending {
		t.Error("pending after a failed dry run")
	}

	// An invalid model never reaches a stage.
	r.log = nil
	if _, err := r.eng.Apply(ctx, "alice", "", addAlias("not valid")); err == nil || len(r.log) != 0 {
		t.Errorf("invalid object: err=%v log=%v", err, r.log)
	}
}

func TestFailedApplyRestoresEveryStage(t *testing.T) {
	for _, phase := range []string{"apply", "health"} {
		t.Run(phase, func(t *testing.T) {
			r := newRig(t, time.Hour)
			r.eng.Apply(ctx, "alice", "", addAlias("web"))
			r.eng.Confirm("alice")
			if phase == "apply" {
				r.b.failApply = "boom" // second stage fails after the first applied
			} else {
				r.a.failHP = "boom"
			}
			_, err := r.eng.Apply(ctx, "alice", "", addAlias("boom"))
			var se *StageError
			if !errors.As(err, &se) || se.Phase != phase || !se.RolledBack {
				t.Fatalf("err = %v", err)
			}
			if r.a.now() != "web" || r.b.now() != "web" || r.aliases() != "web" {
				t.Errorf("not restored: filter=%q routing=%q model=%q", r.a.now(), r.b.now(), r.aliases())
			}
			if _, pending := r.eng.Pending(); pending {
				t.Error("still pending after a failed apply")
			}
			if !strings.HasSuffix(r.events(), "rolled_back") {
				t.Errorf("notices: %s", r.events())
			}
		})
	}
}

func TestRestartInsideTheWindowRollsBack(t *testing.T) {
	r := newRig(t, time.Hour)
	r.eng.Apply(ctx, "alice", "", addAlias("web"))
	r.eng.Confirm("alice")
	if _, err := r.eng.Apply(ctx, "alice", "", addAlias("unconfirmed")); err != nil {
		t.Fatal(err)
	}
	// Crash: the process dies, the timer with it. Stages lose their state.
	r.eng.timer.Stop()
	r.store.Close()
	r.a.running, r.b.running, r.log = "", "", nil

	r.open(t, time.Hour)
	if err := r.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if r.a.now() != "web" || r.b.now() != "web" || r.aliases() != "web" {
		t.Errorf("after restart: filter=%q routing=%q model=%q", r.a.now(), r.b.now(), r.aliases())
	}
	if _, pending := r.eng.Pending(); pending {
		t.Error("still pending after restart")
	}
	hist, _ := r.store.History(0, 1)
	if hist[0].Type != "revert" || !strings.Contains(hist[0].Note, "restart") {
		t.Errorf("restart rollback record: %+v", hist[0])
	}
}

func TestStartAppliesTheModel(t *testing.T) {
	r := newRig(t, time.Hour)
	r.eng.Apply(ctx, "alice", "", addAlias("web"))
	r.eng.Confirm("alice")
	r.store.Close()
	r.a.running, r.b.running = "", "" // reboot: the kernel forgot everything

	r.open(t, time.Hour)
	if err := r.eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if r.a.now() != "web" || r.b.now() != "web" {
		t.Errorf("after boot: filter=%q routing=%q", r.a.now(), r.b.now())
	}
}

func TestManualRollbackAndPlan(t *testing.T) {
	r := newRig(t, time.Hour)
	arts, changes, err := r.eng.Plan(ctx, "alice", addAlias("web"))
	if err != nil || string(arts["filter"]) != "web" || len(changes) != 1 || r.store.Current().Index() != 0 {
		t.Fatalf("plan: %v %q %d index=%d", err, arts["filter"], len(changes), r.store.Current().Index())
	}
	if err := r.eng.Rollback(ctx, "alice", ""); !errors.Is(err, ErrNothingPending) {
		t.Errorf("rollback with nothing pending: %v", err)
	}
	r.eng.Apply(ctx, "alice", "", addAlias("web"))
	if err := r.eng.Rollback(ctx, "alice", "changed my mind"); err != nil {
		t.Fatal(err)
	}
	if r.a.now() != "" || r.aliases() != "" {
		t.Errorf("after manual rollback: %q / %q", r.a.now(), r.aliases())
	}
	hist, _ := r.store.History(0, 1)
	if hist[0].Actor != "alice" || hist[0].Note != "changed my mind" {
		t.Errorf("record: %+v", hist[0])
	}
}

func TestRollbackContinuesPastABrokenStage(t *testing.T) {
	r := newRig(t, time.Hour)
	r.eng.Apply(ctx, "alice", "", addAlias("web"))
	r.eng.Confirm("alice")
	r.eng.Apply(ctx, "alice", "", addAlias("zzz"))
	r.b.failApply = "web" // routing refuses the previous configuration
	err := r.eng.Rollback(ctx, "alice", "undo")
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("err = %v", err)
	}
	// The other stage is still restored and the engine is usable again.
	if r.a.now() != "web" || r.aliases() != "web" {
		t.Errorf("filter=%q model=%q", r.a.now(), r.aliases())
	}
	if _, pending := r.eng.Pending(); pending {
		t.Error("engine stuck in pending")
	}
	if !strings.HasSuffix(r.events(), "rollback_failed") {
		t.Errorf("notices: %s", r.events())
	}
}
