package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAuditLogRoundTrip(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()
	ctx := context.Background()

	base := time.Now().Add(-time.Hour)
	entries := []AuditEntry{
		{TS: base, Op: "route_add", Args: `{"cidr":"10.0.0.0/24"}`, PeerUID: 1000, Result: "ok"},
		{TS: base.Add(time.Minute), Op: "iface_down", Args: `{"name":"eth0"}`, PeerUID: 1000, Result: "operation not permitted"},
		{TS: base.Add(2 * time.Minute), Op: "nat_add", Args: `{"wan":443}`, PeerUID: 0, Result: "ok"},
	}
	for _, e := range entries {
		if err := store.InsertAudit(ctx, e); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	got, err := store.RecentAudit(ctx, 10)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}
	// Newest first.
	if got[0].Op != "nat_add" {
		t.Fatalf("newest-first broken: %q", got[0].Op)
	}
	if got[1].Result != "operation not permitted" {
		t.Fatalf("result lost: %q", got[1].Result)
	}
	if got[2].Op != "route_add" || got[2].PeerUID != 1000 {
		t.Fatalf("oldest row wrong: %+v", got[2])
	}
}

func TestInsertAuditDefaults(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()
	ctx := context.Background()

	// Zero TS and empty result default to now / "ok".
	if err := store.InsertAudit(ctx, AuditEntry{Op: "ping"}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, _ := store.RecentAudit(ctx, 1)
	if len(got) != 1 || got[0].Result != "ok" {
		t.Fatalf("default result not applied: %+v", got)
	}
	if got[0].TS.IsZero() {
		t.Fatal("default TS not applied")
	}
}

func TestCapAuditLog(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()
	ctx := context.Background()

	base := time.Now()
	for i := 0; i < 10; i++ {
		_ = store.InsertAudit(ctx, AuditEntry{TS: base.Add(time.Duration(i) * time.Second), Op: "op", Args: "{}", Result: "ok"})
	}
	if err := store.CapAuditLog(ctx, 4); err != nil {
		t.Fatalf("cap: %v", err)
	}
	got, _ := store.RecentAudit(ctx, 100)
	if len(got) != 4 {
		t.Fatalf("after cap got %d rows, want 4", len(got))
	}
}
