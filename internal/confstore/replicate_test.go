package confstore

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/noahzmr/testudo/internal/model"
)

// group is the simplest thing that agrees on records: an ordered list that
// every member applies. It can be told to refuse, or to let another record
// win the race for an index.
type group struct {
	mu      sync.Mutex
	members []*Store
	log     []Record
	refuse  error
	steal   *Record // applied ahead of the next proposal
}

func (g *group) Replicate(_ context.Context, r Record) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.refuse != nil {
		return g.refuse
	}
	if g.steal != nil {
		other := *g.steal
		g.steal = nil
		g.log = append(g.log, other)
		for _, m := range g.members {
			m.ApplyReplicated(other)
		}
	}
	g.log = append(g.log, r)
	var first error
	for i, m := range g.members {
		if err := m.ApplyReplicated(r); err != nil && i == 0 {
			first = err
		}
	}
	return first
}

func TestReplicatedStoresStayIdentical(t *testing.T) {
	a, b := open(t), open(t)
	g := &group{members: []*Store{a, b}}
	a.SetReplicator(g)
	b.SetReplicator(g)

	one := mustCreate(t, a, "alice", alias("one", "10.0.0.1"))
	// A write on the other member goes through the same group.
	mustCreate(t, b, "bob", alias("two", "10.0.0.2"))
	one.Entries = []string{"10.0.0.9"}
	if _, err := a.Update(ctx, "alice", one, one.Version); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*Store{a, b} {
		st := s.Current()
		got, _ := st.Get(model.KindAlias, one.ID)
		if st.Index() != 3 || len(st.List(model.KindAlias)) != 2 || got.(*model.Alias).Entries[0] != "10.0.0.9" || got.GetMeta().Version != 3 {
			t.Fatalf("member state: index %d, %d aliases, %+v", st.Index(), len(st.List(model.KindAlias)), got)
		}
	}
	// Both logs replay to the same thing after a restart.
	ra, _ := ReadState(a.dir)
	rb, _ := ReadState(b.dir)
	if ra.Index() != 3 || rb.Index() != 3 {
		t.Errorf("replayed indexes %d and %d", ra.Index(), rb.Index())
	}

	// Validation happens before anything is proposed.
	if _, err := a.Create(ctx, "alice", alias("one")); err == nil || len(g.log) != 3 {
		t.Errorf("a duplicate name was proposed: %v, %d records", err, len(g.log))
	}
	// A refusal by the group changes nothing anywhere.
	g.refuse = errors.New("not the leader")
	if _, err := a.Create(ctx, "alice", alias("three")); err == nil || !strings.Contains(err.Error(), "not the leader") {
		t.Errorf("refused write: %v", err)
	}
	g.refuse = nil
	if a.Current().Index() != 3 || b.Current().Index() != 3 {
		t.Error("a refused write moved a store")
	}

	// Replaying the group's log is harmless.
	for _, r := range g.log {
		if err := b.ApplyReplicated(r); !errors.Is(err, ErrDuplicate) {
			t.Errorf("replay of record %d: %v", r.Index, err)
		}
	}
	// A gap is refused instead of applied out of order.
	if err := b.ApplyReplicated(Record{Index: 9}); !errors.Is(err, ErrAhead) {
		t.Errorf("record after a gap: %v", err)
	}
	// So is a record from a newer build.
	if err := b.ApplyReplicated(Record{Index: 4, Schema: model.SchemaVersion + 1}); err == nil || !strings.Contains(err.Error(), "newer version") {
		t.Errorf("record with a newer schema: %v", err)
	}
}

func TestLosingTheRaceForAnIndexIsReported(t *testing.T) {
	a, b := open(t), open(t)
	g := &group{members: []*Store{a, b}}
	a.SetReplicator(g)
	// Another leader's record takes index 1 while ours is on its way.
	other := open(t)
	rec, err := other.Commit(ctx, "carol", "", []Op{{Type: OpCreate, Kind: model.KindAlias, Object: mustJSON(alias("theirs", "10.9.9.9"))}})
	if err != nil {
		t.Fatal(err)
	}
	g.steal = &rec
	if _, err := a.Create(ctx, "alice", alias("ours", "10.0.0.1")); !errors.Is(err, ErrStale) {
		t.Fatalf("losing the race: %v", err)
	}
	for _, s := range []*Store{a, b} {
		list := s.Current().List(model.KindAlias)
		if len(list) != 1 || list[0].GetMeta().Name != "theirs" {
			t.Errorf("after the race a member holds %v", list)
		}
	}
	// Trying again works and lands on the next index.
	if got := mustCreate(t, a, "alice", alias("ours", "10.0.0.1")); got.Version != 2 {
		t.Errorf("second attempt has version %d", got.Version)
	}
}

func TestRestoreSnapshot(t *testing.T) {
	a, b := open(t), open(t)
	for _, n := range []string{"one", "two", "three"} {
		mustCreate(t, a, "alice", alias(n, "10.0.0.1"))
	}
	mustCreate(t, b, "bob", alias("stale", "10.1.1.1"))
	if err := b.RestoreSnapshot(a.Snapshot()); err != nil {
		t.Fatal(err)
	}
	st := b.Current()
	if st.Index() != 3 || len(st.List(model.KindAlias)) != 3 {
		t.Fatalf("after restore: index %d, %d aliases", st.Index(), len(st.List(model.KindAlias)))
	}
	// The member continues from there, and a restart finds the same.
	next, err := a.Commit(ctx, "alice", "", []Op{{Type: OpCreate, Kind: model.KindAlias, Object: mustJSON(alias("four", "10.0.0.4"))}})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.ApplyReplicated(next); err != nil {
		t.Fatal(err)
	}
	re, err := ReadState(b.dir)
	if err != nil || re.Index() != 4 || len(re.List(model.KindAlias)) != 4 {
		t.Fatalf("replay after restore: %v", err)
	}
	// An older snapshot does not take a member back.
	old := a.Snapshot()
	old.Index = 2
	if err := b.RestoreSnapshot(old); err != nil || b.Current().Index() != 4 {
		t.Errorf("older snapshot: %v, index %d", err, b.Current().Index())
	}
}
