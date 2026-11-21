package engine

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/storage"
)

type memKV struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (k *memKV) Get(n string) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if b, ok := k.m[n]; ok {
		return b, nil
	}
	return nil, errors.New("missing")
}
func (k *memKV) Put(n string, b []byte) error { k.mu.Lock(); k.m[n] = b; k.mu.Unlock(); return nil }
func (k *memKV) Delete(n string) error        { k.mu.Lock(); delete(k.m, n); k.mu.Unlock(); return nil }
func (k *memKV) List() ([]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []string
	for n := range k.m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// TestRequestsAreSharedAndLogsMerged: two members share one store of
// requests; a request one makes, the other reads and decides. Requests
// from before the store was shared are still listed. Each member's log
// stays its own, and the view shows both, newest first.
func TestRequestsAreSharedAndLogsMerged(t *testing.T) {
	ctx := context.Background()
	open := func(name string) *storage.Store {
		s, err := storage.Open(filepath.Join(t.TempDir(), name+".db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	db1, db2 := open("fw1"), open("fw2")
	shared := &memKV{m: map[string][]byte{}}
	now := time.Now()
	if err := db1.UpsertPAMGrant(ctx, storage.PAMGrant{ID: "grant-old", User: "bob", State: "expired", RequestedAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	fw1 := sharedAccess{local: db1, kv: shared, member: "fw1"}
	fw2 := sharedAccess{local: db2, kv: shared, member: "fw2"}
	fw1.remote = func(context.Context) []storage.AccessEvent {
		evs, _ := db2.ListAccessEvents(ctx, 10)
		for i := range evs {
			evs[i].Member = "fw2"
		}
		return evs
	}

	g := storage.PAMGrant{ID: "grant-1", User: "alice", State: "pending", RequestedAt: now}
	if err := fw1.UpsertPAMGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	fw1.AppendAccessEvent(ctx, storage.AccessEvent{TS: now, Actor: "alice", Action: "requested", GrantID: g.ID})

	got, err := fw2.GetPAMGrant(ctx, "grant-1")
	if err != nil || got.User != "alice" {
		t.Fatalf("the other member does not see the request: %+v %v", got, err)
	}
	got.State, got.ApprovedBy = "active", "carol"
	if err := fw2.UpsertPAMGrant(ctx, got); err != nil {
		t.Fatal(err)
	}
	fw2.AppendAccessEvent(ctx, storage.AccessEvent{TS: now.Add(time.Second), Actor: "carol", Action: "approved", GrantID: g.ID})

	list, err := fw1.ListPAMGrants(ctx, nil, 10)
	if err != nil || len(list) != 2 || list[0].ID != "grant-1" || list[0].State != "active" || list[1].ID != "grant-old" {
		t.Fatalf("requests on fw1: %+v %v", list, err)
	}
	if active, _ := fw1.ListPAMGrants(ctx, []string{"active"}, 10); len(active) != 1 {
		t.Errorf("active requests: %+v", active)
	}
	evs, err := fw1.ListAccessEvents(ctx, 10)
	if err != nil || len(evs) != 2 || evs[0].Member != "fw2" || evs[0].Action != "approved" || evs[1].Member != "fw1" {
		t.Fatalf("merged log: %+v %v", evs, err)
	}
	// Each member's chain is intact and its own.
	if n, broken, _ := fw1.VerifyAccessEvents(ctx); n != 1 || broken != 0 {
		t.Errorf("fw1's chain: %d rows, broken at %d", n, broken)
	}

	// Ended long ago: the shared store lets it go.
	got.State, got.EndedAt = "expired", now.Add(-31*24*time.Hour)
	fw1.UpsertPAMGrant(ctx, got)
	if n := pruneRequests(shared, now); n != 1 {
		t.Errorf("pruned %d", n)
	}
}
