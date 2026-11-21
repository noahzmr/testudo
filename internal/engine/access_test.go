package engine

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/storage"
)

// TestActiveGrantsMoveIntoTheModel: a grant that was active when the access
// manager still wrote firewall rules becomes a model grant on the resource
// that moved into the model in the same change, and lasts until its end.
// Ended grants and grants that are already in the model are left alone.
func TestActiveGrantsMoveIntoTheModel(t *testing.T) {
	store, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if _, err := store.Create(ctx, "a", &model.User{Meta: model.Meta{Name: "alice"}, Username: "alice", Source: "local"}); err != nil {
		t.Fatal(err)
	}
	// The resource arrives in the same change as the grant.
	res := &model.AccessResource{Meta: model.Meta{ID: confstore.NewID(), Name: "db"}, Type: "network", Target: "10.0.0.5", Protocol: "any"}
	raw, _ := json.Marshal(res)
	ops := []confstore.Op{{Type: confstore.OpCreate, Kind: model.KindAccessResource, ID: res.ID, Object: raw}}

	now := time.Now()
	active := []storage.PAMGrant{
		{ID: "g1", User: "alice", ResourceID: "old-res", State: "active", EndsAt: now.Add(time.Hour), Justification: "incident"},
		{ID: "g2", User: "alice", ResourceID: "old-res", State: "active", EndsAt: now.Add(-time.Minute)},
		{ID: "g3", User: "nobody", ResourceID: "old-res", State: "active", EndsAt: now.Add(time.Hour)},
	}
	resID := map[string]string{"old-res": res.ID}
	ops = append(ops, activeGrantOps(store.Current(), active, resID, nil, now)...)
	if _, err := store.Commit(ctx, "system", "migration", ops); err != nil {
		t.Fatalf("the store rejects the grants: %v", err)
	}
	grants := store.Current().List(model.KindAccessGrant)
	if len(grants) != 1 {
		t.Fatalf("%d grants, want 1", len(grants))
	}
	g := grants[0].(*model.AccessGrant)
	if g.Request != "g1" || g.Resource.ID != res.ID || g.Reason != "incident" || !g.Ends.Equal(active[0].EndsAt.UTC()) {
		t.Errorf("grant: %+v", g)
	}
	// A second start finds it there.
	if again := activeGrantOps(store.Current(), active, resID, nil, now); len(again) != 0 {
		t.Errorf("the grant is made again: %d ops", len(again))
	}
}
