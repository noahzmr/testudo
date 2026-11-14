package confstore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahzmr/testudo/internal/model"
)

var ctx = context.Background()

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func alias(name string, entries ...string) *model.Alias {
	return &model.Alias{Meta: model.Meta{Name: name}, Type: "host", Entries: entries}
}

func mustCreate[T model.Entity](t *testing.T, s *Store, actor string, e T) T {
	t.Helper()
	out, err := s.Create(ctx, actor, e)
	if err != nil {
		t.Fatalf("create %s: %v", e.Kind(), err)
	}
	return out.(T)
}

func TestCreateSetsMetaAndVersionIsLogIndex(t *testing.T) {
	s := open(t)
	a := mustCreate(t, s, "alice", alias("web", "192.0.2.1"))
	if a.ID == "" || a.Version != 1 || a.CreatedBy != "alice" || a.UpdatedBy != "alice" ||
		a.CreatedAt.IsZero() || a.Scope != model.ScopeGlobal {
		t.Fatalf("meta = %+v", a.Meta)
	}
	b := mustCreate(t, s, "bob", alias("db", "192.0.2.2"))
	if b.Version != 2 || s.Current().Index() != 2 {
		t.Fatalf("second object version %d, index %d", b.Version, s.Current().Index())
	}
}

func TestStaleWriteGetsConflictWithFieldDiff(t *testing.T) {
	s := open(t)
	a := mustCreate(t, s, "alice", alias("web", "192.0.2.1"))

	// Alice and Bob both load version 1. Alice saves first.
	alices, bobs := model.Clone(a).(*model.Alias), model.Clone(a).(*model.Alias)
	alices.Entries = []string{"192.0.2.9"}
	if _, err := s.Update(ctx, "alice", alices, a.Version); err != nil {
		t.Fatal(err)
	}

	bobs.Description = "bob was here"
	_, err := s.Update(ctx, "bob", bobs, a.Version)
	var c *ConflictError
	if !errors.As(err, &c) {
		t.Fatalf("want ConflictError, got %v", err)
	}
	if c.YourVersion != 1 || c.CurrentVersion != 2 || c.CurrentBy != "alice" {
		t.Errorf("conflict = %+v", c)
	}
	fields := map[string]bool{}
	for _, d := range c.Diff {
		fields[d.Field] = true
	}
	if len(fields) != 2 || !fields["entries"] || !fields["description"] {
		t.Errorf("diff = %+v, want exactly entries and description", c.Diff)
	}
	// Nothing of Bob's write reached the store.
	cur, _ := s.Current().Get(model.KindAlias, a.ID)
	if cur.(*model.Alias).Description != "" || cur.GetMeta().Version != 2 {
		t.Errorf("stale write leaked: %+v", cur)
	}

	// Missing version is refused outright.
	if _, err := s.Update(ctx, "bob", bobs, 0); !errors.Is(err, ErrIfMatchNeeded) {
		t.Errorf("update without version: %v", err)
	}
	if err := s.Delete(ctx, "bob", model.KindAlias, a.ID, 1); !errors.As(err, &c) {
		t.Errorf("stale delete: %v", err)
	}
}

func TestRenameKeepsReferencesAndDeleteIsBlocked(t *testing.T) {
	s := open(t)
	a := mustCreate(t, s, "alice", alias("web", "192.0.2.1"))
	rule := mustCreate(t, s, "alice", &model.FilterRule{Meta: model.Meta{Name: "allow-web"}, Enabled: true,
		Action: "accept", Direction: "forward", Protocol: "tcp", Destination: []model.Ref[model.Alias]{{ID: a.ID}}})

	a.Name = "web-servers"
	if _, err := s.Update(ctx, "alice", a, a.Version); err != nil {
		t.Fatalf("rename: %v", err)
	}
	got, _ := s.Current().Get(model.KindFilterRule, rule.ID)
	if got.(*model.FilterRule).Destination[0].ID != a.ID {
		t.Fatal("reference changed by a rename")
	}

	use := s.Current().UsedBy(model.KindAlias, a.ID)
	want := []Use{{Kind: model.KindFilterRule, ID: rule.ID, Name: "allow-web", Field: "destination[0]"}}
	if len(use) != 1 || use[0] != want[0] {
		t.Fatalf("UsedBy = %+v", use)
	}

	cur, _ := s.Current().Get(model.KindAlias, a.ID)
	err := s.Delete(ctx, "alice", model.KindAlias, a.ID, cur.GetMeta().Version)
	var ref *ReferencedError
	if !errors.As(err, &ref) || len(ref.UsedBy) != 1 || ref.UsedBy[0] != want[0] {
		t.Fatalf("delete of a referenced alias: %v", err)
	}
	if !strings.Contains(err.Error(), `filter_rule "allow-web" (destination[0])`) {
		t.Errorf("error does not name the user: %v", err)
	}

	// Deleting the referrer and the target in one transaction is allowed.
	if _, err := s.Commit(ctx, "alice", "cleanup", []Op{
		{Type: OpDelete, Kind: model.KindAlias, ID: a.ID, IfMatch: cur.GetMeta().Version},
		{Type: OpDelete, Kind: model.KindFilterRule, ID: rule.ID, IfMatch: rule.Version},
	}); err != nil {
		t.Fatalf("combined delete: %v", err)
	}
}

func TestIntegrityAndValidation(t *testing.T) {
	s := open(t)
	ghost := "99999999-9999-4999-8999-999999999999"

	_, err := s.Create(ctx, "a", &model.FilterRule{Meta: model.Meta{Name: "r"}, Action: "accept",
		Direction: "in", Protocol: "tcp", SourceZone: model.Ref[model.Zone]{ID: ghost}})
	var ie *IntegrityError
	if !errors.As(err, &ie) || ie.Problems[0].Field != "source_zone" {
		t.Fatalf("dangling reference: %v", err)
	}

	_, err = s.Create(ctx, "a", alias("bad name"))
	var ve *model.ValidationError
	if !errors.As(err, &ve) || ve.Fields[0].Field != "name" {
		t.Fatalf("invalid object: %v", err)
	}

	mustCreate(t, s, "a", alias("dup"))
	if _, err = s.Create(ctx, "a", alias("dup")); !errors.As(err, &ve) || ve.Fields[0].Rule != "unique" {
		t.Fatalf("duplicate name: %v", err)
	}

	// Scope targets are references too.
	a := alias("scoped")
	a.Scope = model.SiteScope(ghost)
	if _, err = s.Create(ctx, "a", a); !errors.As(err, &ie) || ie.Problems[0].Field != "scope" {
		t.Fatalf("scope to a missing site: %v", err)
	}
	if s.Current().Index() != 1 {
		t.Errorf("rejected writes advanced the log to %d", s.Current().Index())
	}
}

func TestSemanticChecks(t *testing.T) {
	s := open(t)
	site := mustCreate(t, s, "a", &model.Site{Meta: model.Meta{Name: "hq"}})
	node := mustCreate(t, s, "a", &model.ClusterNode{Meta: model.Meta{Name: "fw1"},
		Site: model.Ref[model.Site]{ID: site.ID}, Hostname: "fw1", Address: "10.0.0.1"})
	ifc := &model.Interface{Meta: model.Meta{Name: "wan", Scope: model.NodeScope(node.ID)}, Device: "eth0", Enabled: true}
	ifc = mustCreate(t, s, "a", ifc)
	vrf := mustCreate(t, s, "a", &model.VRF{Meta: model.Meta{Name: "blue"}, Table: 100})
	gw := &model.Gateway{Meta: model.Meta{Name: "isp", Scope: model.SiteScope(site.ID)},
		Interface: model.Ref[model.Interface]{ID: ifc.ID}, Address: "198.51.100.1", Enabled: true}
	gw = mustCreate(t, s, "a", gw)

	problem := func(err error) string {
		t.Helper()
		var ie *IntegrityError
		if !errors.As(err, &ie) || len(ie.Problems) != 1 {
			t.Fatalf("want one integrity problem, got %v", err)
		}
		return ie.Problems[0].Field + ": " + ie.Problems[0].Message
	}

	// Route in VRF blue through a gateway in the default VRF.
	_, err := s.Create(ctx, "a", &model.Route{Meta: model.Meta{Name: "r1"}, Enabled: true,
		Destination: "10.9.0.0/16", Gateway: model.Ref[model.Gateway]{ID: gw.ID}, VRF: model.Ref[model.VRF]{ID: vrf.ID}})
	if got := problem(err); !strings.Contains(got, "gateway") || !strings.Contains(got, "another VRF") {
		t.Errorf("route/gateway VRF: %s", got)
	}

	// SNI router pointing to an empty pool.
	zone := mustCreate(t, s, "a", &model.Zone{Meta: model.Meta{Name: "dmz"}, DefaultAction: "drop"})
	pool := mustCreate(t, s, "a", &model.LBBackendPool{Meta: model.Meta{Name: "empty"},
		Algorithm: "weighted_round_robin", HealthCheck: model.LBHealthCheck{Type: "tcp"}})
	svc := mustCreate(t, s, "a", &model.LBService{Meta: model.Meta{Name: "tls"}, Enabled: true,
		Zone: model.Ref[model.Zone]{ID: zone.ID}, Port: 443, Protocol: "tcp", Mode: "proxy"})
	router := &model.LBRouter{Meta: model.Meta{Name: "sni"}, Enabled: true, Service: model.Ref[model.LBService]{ID: svc.ID},
		SNI: []string{"app.example.com"}, TLS: "passthrough", Pool: model.Ref[model.LBBackendPool]{ID: pool.ID}}
	if got := problem(func() error { _, err := s.Create(ctx, "a", router); return err }()); !strings.Contains(got, "no backend") {
		t.Errorf("empty pool: %s", got)
	}
	router.Enabled = false
	mustCreate(t, s, "a", router) // a disabled router may point anywhere

	// Rule referencing a disabled tunnel.
	tun := mustCreate(t, s, "a", &model.WGTunnel{Meta: model.Meta{Name: "wg0", Scope: model.SiteScope(site.ID)},
		Device: "wg0", Mode: "road_warrior", ListenPort: 51820, Addresses: []string{"10.8.0.1/24"},
		PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Zone: model.Ref[model.Zone]{ID: zone.ID}})
	_, err = s.Create(ctx, "a", &model.FilterRule{Meta: model.Meta{Name: "vpn"}, Enabled: true, Action: "accept",
		Direction: "forward", Protocol: "any", Tunnel: model.Ref[model.WGTunnel]{ID: tun.ID}})
	if got := problem(err); !strings.Contains(got, "disabled") {
		t.Errorf("disabled tunnel: %s", got)
	}

	// Alias cycle.
	a := mustCreate(t, s, "a", alias("a"))
	b := alias("b")
	b.Members = []model.Ref[model.Alias]{{ID: a.ID}}
	b = mustCreate(t, s, "a", b)
	a.Members = []model.Ref[model.Alias]{{ID: b.ID}}
	_, err = s.Update(ctx, "a", a, a.Version)
	var ie *IntegrityError
	if !errors.As(err, &ie) || !strings.Contains(err.Error(), "cycle") {
		t.Errorf("alias cycle: %v", err)
	}

	// A site's voter must be one of its nodes.
	other := mustCreate(t, s, "a", &model.Site{Meta: model.Meta{Name: "branch"}})
	other.Voter = model.Ref[model.ClusterNode]{ID: node.ID}
	if _, err = s.Update(ctx, "a", other, other.Version); !errors.As(err, &ie) || !strings.Contains(err.Error(), "another site") {
		t.Errorf("foreign voter: %v", err)
	}
}

func TestChangeSetsCombineIntoOneTransaction(t *testing.T) {
	s := open(t)
	base := mustCreate(t, s, "root", alias("web", "192.0.2.1"))

	// Alice adds an alias, Bob edits the existing one, each in a draft.
	draftA, err := s.PutChangeSet(ctx, "alice", ChangeSet{Name: "add-db",
		Ops: []Op{{Type: OpCreate, Kind: model.KindAlias, Object: mustJSON(alias("db", "192.0.2.2"))}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	edited := model.Clone(base).(*model.Alias)
	edited.Entries = []string{"192.0.2.1", "192.0.2.3"}
	draftB, err := s.PutChangeSet(ctx, "bob", ChangeSet{Name: "grow-web",
		Ops: []Op{{Type: OpUpdate, Kind: model.KindAlias, ID: base.ID, Object: mustJSON(edited), IfMatch: base.Version}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if draftA.Owner != "alice" || draftB.Owner != "bob" || len(s.Current().ChangeSets()) != 2 {
		t.Fatalf("drafts: %+v %+v", draftA, draftB)
	}
	// Drafts do not touch the live model.
	if len(s.Current().List(model.KindAlias)) != 1 {
		t.Fatal("a draft changed the live model")
	}

	// Editing a draft needs its current version.
	if _, err := s.PutChangeSet(ctx, "bob", ChangeSet{ID: draftB.ID, Name: "x"}, draftB.Version+7); err == nil {
		t.Error("stale change-set edit accepted")
	}

	ops, err := s.Combine(draftA.ID, draftB.ID)
	if err != nil {
		t.Fatal(err)
	}
	cand, changes, err := s.Preview("carol", ops)
	if err != nil || len(changes) != 2 || len(cand.List(model.KindAlias)) != 2 {
		t.Fatalf("preview: %v changes=%d", err, len(changes))
	}
	before := s.Current().Index()
	rec, err := s.Commit(ctx, "carol", "apply both", ops, draftA.ID, draftB.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Index != before+1 || len(rec.Changes) != 2 || len(s.Current().ChangeSets()) != 0 {
		t.Errorf("record %+v, %d drafts left", rec.Index, len(s.Current().ChangeSets()))
	}
	for _, e := range s.Current().List(model.KindAlias) {
		if e.GetMeta().Version != rec.Index || e.GetMeta().UpdatedBy != "carol" {
			t.Errorf("%s: version %d by %s", e.GetMeta().Name, e.GetMeta().Version, e.GetMeta().UpdatedBy)
		}
	}

	// Two drafts changing the same object cannot be combined silently.
	cur, _ := s.Current().Get(model.KindAlias, base.ID)
	op := Op{Type: OpUpdate, Kind: model.KindAlias, ID: base.ID, Object: mustJSON(cur), IfMatch: cur.GetMeta().Version}
	var c *ConflictError
	if _, _, err := s.Preview("x", []Op{op, op}); !errors.As(err, &c) {
		t.Errorf("overlapping drafts: %v", err)
	}
}

func TestStaleChangeSetConflictsAtApply(t *testing.T) {
	s := open(t)
	base := mustCreate(t, s, "root", alias("web", "192.0.2.1"))
	edited := model.Clone(base).(*model.Alias)
	edited.Description = "from the draft"
	draft, _ := s.PutChangeSet(ctx, "alice", ChangeSet{Name: "d",
		Ops: []Op{{Type: OpUpdate, Kind: model.KindAlias, ID: base.ID, Object: mustJSON(edited), IfMatch: base.Version}}}, 0)

	direct := model.Clone(base).(*model.Alias)
	direct.Entries = []string{"192.0.2.50"}
	if _, err := s.Update(ctx, "bob", direct, base.Version); err != nil {
		t.Fatal(err)
	}
	ops, _ := s.Combine(draft.ID)
	_, err := s.Commit(ctx, "alice", "", ops, draft.ID)
	var c *ConflictError
	if !errors.As(err, &c) || c.CurrentBy != "bob" {
		t.Fatalf("stale draft applied: %v", err)
	}
	if _, ok := s.Current().ChangeSet(draft.ID); !ok {
		t.Error("the draft was consumed by a failed apply")
	}
}

func TestHistoryRevertAndReplay(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := mustCreate(t, s, "alice", alias("web", "192.0.2.1"))
	a.Entries = []string{"192.0.2.2"}
	a2, _ := s.Update(ctx, "bob", a, a.Version)
	b := mustCreate(t, s, "bob", alias("db"))

	hist, err := s.History(0, 10)
	if err != nil || len(hist) != 3 || hist[0].Index != 3 || hist[2].Actor != "alice" {
		t.Fatalf("history: %v %+v", err, hist)
	}
	upd := hist[1].Changes[0]
	if upd.Type != OpUpdate || !strings.Contains(string(upd.Before), "192.0.2.1") || !strings.Contains(string(upd.After), "192.0.2.2") {
		t.Errorf("update record lacks before/after: %+v", upd)
	}

	// Revert the update: content returns, version moves forward.
	rec, err := s.Revert(ctx, "carol", a2.GetMeta().Version, "undo")
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := s.Current().Get(model.KindAlias, a.ID)
	if got := cur.(*model.Alias); got.Entries[0] != "192.0.2.1" || got.Version != rec.Index || rec.Reverts != 2 {
		t.Errorf("after revert: %+v, record %+v", got, rec)
	}
	// Reverting a create deletes; reverting again is refused once changed.
	if _, err := s.Revert(ctx, "carol", b.Version, ""); err != nil {
		t.Fatalf("revert create: %v", err)
	}
	if _, ok := s.Current().Get(model.KindAlias, b.ID); ok {
		t.Error("reverted create still present")
	}
	var c *ConflictError
	if _, err := s.Revert(ctx, "carol", 1, ""); !errors.As(err, &c) {
		t.Errorf("revert of a record whose object changed since: %v", err)
	}
	want := mustJSON(cur)
	wantIndex := s.Current().Index()
	s.Close()

	// The log is private and replays to the same state.
	if fi, _ := os.Stat(filepath.Join(dir, "config.log")); fi.Mode().Perm() != 0o600 {
		t.Errorf("log mode %v", fi.Mode().Perm())
	}
	// A torn final record (crash mid-write) is dropped on open.
	f, _ := os.OpenFile(filepath.Join(dir, "config.log"), os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"index":99,"changes":[{"ty`)
	f.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, _ := s2.Current().Get(model.KindAlias, a.ID)
	if s2.Current().Index() != wantIndex || string(mustJSON(got)) != string(want) {
		t.Errorf("replay: index %d want %d\n got %s\nwant %s", s2.Current().Index(), wantIndex, mustJSON(got), want)
	}
	mustCreate(t, s2, "alice", alias("after-reopen"))
}

func TestCorruptLogIsRefused(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	mustCreate(t, s, "a", alias("one"))
	mustCreate(t, s, "a", alias("two"))
	s.Close()
	path := filepath.Join(dir, "config.log")
	data, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(data), "\n")
	os.WriteFile(path, []byte("garbage\n"+lines[1]), 0o600)
	if _, err := Open(dir); err == nil {
		t.Fatal("corrupt log was accepted")
	}
}

func TestSecretRoundTrip(t *testing.T) {
	s := open(t)
	site := mustCreate(t, s, "a", &model.Site{Meta: model.Meta{Name: "hq"}})
	n := mustCreate(t, s, "a", &model.BGPNeighbor{Meta: model.Meta{Name: "peer", Scope: model.SiteScope(site.ID)},
		LocalAS: 65001, RemoteAS: 65002, Address: "192.0.2.1", SessionSecret: "hunter2"})

	masked := model.Mask(n).(*model.BGPNeighbor)
	masked.BFD = true
	if _, err := s.Update(ctx, "a", masked, n.Version); err != nil {
		t.Fatal(err)
	}
	cur, _ := s.Current().Get(model.KindBGPNeighbor, n.ID)
	if got := cur.(*model.BGPNeighbor); got.SessionSecret != "hunter2" || !got.BFD {
		t.Errorf("after masked round trip: %+v", got)
	}

	hist, _ := s.History(0, 1)
	out, _ := json.Marshal(hist[0].Changes[0].Masked())
	if strings.Contains(string(out), "hunter2") || !strings.Contains(string(out), model.SecretMask) {
		t.Errorf("masked change leaks: %s", out)
	}

	// A conflict diff never shows the secret either.
	stale := model.Clone(n).(*model.BGPNeighbor)
	stale.SessionSecret = "other"
	_, err := s.Update(ctx, "b", stale, n.Version)
	if js, _ := json.Marshal(err); strings.Contains(string(js), "hunter2") || strings.Contains(string(js), "other") {
		t.Errorf("conflict leaks a secret: %s", js)
	}
}

func TestSubscribe(t *testing.T) {
	s := open(t)
	ch, cancel := s.Subscribe(1)
	defer cancel()
	a := mustCreate(t, s, "alice", alias("web"))
	ev := <-ch
	if ev.Index != 1 || ev.Actor != "alice" || len(ev.Changes) != 1 || ev.Changes[0].ID != a.ID ||
		ev.Changes[0].After != nil || ev.Resync {
		t.Fatalf("event = %+v", ev)
	}
	// Fall behind: buffer of one, three commits.
	mustCreate(t, s, "alice", alias("b"))
	mustCreate(t, s, "alice", alias("c"))
	mustCreate(t, s, "alice", alias("d"))
	if ev := <-ch; ev.Index != 2 {
		t.Fatalf("buffered event index %d", ev.Index)
	}
	mustCreate(t, s, "alice", alias("e"))
	if ev := <-ch; !ev.Resync || ev.Index != 5 {
		t.Fatalf("event after a drop = %+v, want Resync at index 5", ev)
	}
}
