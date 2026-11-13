package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAccessEventChainDetectsTampering(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	var ids []int64
	for i, a := range []string{"requested", "approved", "activated", "expired"} {
		ev, err := st.AppendAccessEvent(ctx, AccessEvent{
			TS: time.Unix(1700000000+int64(i), 0), Actor: "alice", Action: a, GrantID: "grant-1", Detail: "d" + a,
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, ev.ID)
		if ev.Hash == "" || (i > 0 && ev.PrevHash == "") || (i == 0 && ev.PrevHash != "") {
			t.Fatalf("event %d chain fields: %+v", i, ev)
		}
	}
	checked, broken, err := st.VerifyAccessEvents(ctx)
	if err != nil || broken != 0 || checked != 4 {
		t.Fatalf("intact chain: checked=%d broken=%d err=%v", checked, broken, err)
	}
	// Rewriting history is detected at the rewritten row.
	if _, err := st.db.Exec(`UPDATE access_events SET detail = 'tampered' WHERE id = ?`, ids[1]); err != nil {
		t.Fatal(err)
	}
	checked, broken, err = st.VerifyAccessEvents(ctx)
	if err != nil || broken != ids[1] || checked != 1 {
		t.Fatalf("tampered chain: checked=%d broken=%d err=%v", checked, broken, err)
	}
	// Deleting a row is detected at the following row.
	if _, err := st.db.Exec(`UPDATE access_events SET detail = 'dapproved' WHERE id = ?`, ids[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`DELETE FROM access_events WHERE id = ?`, ids[2]); err != nil {
		t.Fatal(err)
	}
	_, broken, _ = st.VerifyAccessEvents(ctx)
	if broken != ids[3] {
		t.Fatalf("deleted row not detected: broken=%d want %d", broken, ids[3])
	}
	evs, err := st.ListAccessEvents(ctx, 10)
	if err != nil || len(evs) != 3 || evs[0].Action != "expired" {
		t.Fatalf("list: %+v %v", evs, err)
	}
}

func TestPAMGrantRoundTrip(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	g := PAMGrant{
		ID: "grant-1", User: "alice", ResourceID: "res-1", PolicyID: "pol-1", State: "active",
		Justification: "why", Ticket: "CHG-1", TTL: 3600, RequestedAt: time.UnixMilli(1700000000000),
		ApprovedBy: "carol", DecidedAt: time.UnixMilli(1700000001000), StartsAt: time.UnixMilli(1700000001000),
		EndsAt: time.UnixMilli(1700003601000), PeerIPs: []string{"10.8.0.2/32", "10.8.0.3/32"}, CaptureID: "cap-1",
		ObservedFlows: 3, ObservedBytes: 999, BreakGlass: true,
	}
	if err := st.UpsertPAMGrant(ctx, g); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetPAMGrant(ctx, "grant-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.User != "alice" || got.State != "active" || len(got.PeerIPs) != 2 || got.PeerIPs[1] != "10.8.0.3/32" ||
		!got.EndsAt.Equal(g.EndsAt) || got.ObservedBytes != 999 || !got.BreakGlass || !got.EndedAt.IsZero() {
		t.Fatalf("roundtrip: %+v", got)
	}
	active, _ := st.ListPAMGrants(ctx, []string{"active"}, 10)
	expired, _ := st.ListPAMGrants(ctx, []string{"expired"}, 10)
	if len(active) != 1 || len(expired) != 0 {
		t.Fatalf("filters: active=%d expired=%d", len(active), len(expired))
	}
	if _, err := st.GetPAMGrant(ctx, "nope"); err != ErrPAMNotFound {
		t.Fatalf("missing grant err = %v", err)
	}
	// Peer binding survives name upserts and reads back.
	if err := st.SetWGPeerUser(ctx, "pk1", "alice"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertWGPeerMeta(ctx, "pk1", "alice-phone", ""); err != nil {
		t.Fatal(err)
	}
	users, err := st.WGPeerUsers(ctx)
	if err != nil || users["pk1"] != "alice" {
		t.Fatalf("peer users after name upsert: %v %v", users, err)
	}
}
