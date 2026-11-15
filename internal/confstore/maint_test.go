package confstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahzmr/testudo/internal/model"
)

func TestEveryOldSchemaVersionHasAMigration(t *testing.T) {
	for v := 1; v < model.SchemaVersion; v++ {
		if migrations[v] == nil {
			t.Errorf("no migration registered from schema %d to %d", v, v+1)
		}
	}
}

func TestMigrateChainsSteps(t *testing.T) {
	// Pretend the build is two versions ahead of the stored object.
	saved := migrations
	defer func() { migrations = saved }()
	migrations = map[int]Migration{
		model.SchemaVersion - 2: func(_ model.Kind, o json.RawMessage) (json.RawMessage, error) {
			return json.RawMessage(strings.Replace(string(o), `"old"`, `"mid"`, 1)), nil
		},
		model.SchemaVersion - 1: func(_ model.Kind, o json.RawMessage) (json.RawMessage, error) {
			return json.RawMessage(strings.Replace(string(o), `"mid"`, `"new"`, 1)), nil
		},
	}
	got, err := migrate(model.SchemaVersion-2, model.KindAlias, json.RawMessage(`{"name":"old"}`))
	if model.SchemaVersion-2 >= 1 && (err != nil || string(got) != `{"name":"new"}`) {
		t.Errorf("got %s, %v", got, err)
	}
	// Current-version objects pass through untouched.
	if got, err := migrate(model.SchemaVersion, model.KindAlias, json.RawMessage(`{"name":"old"}`)); err != nil || string(got) != `{"name":"old"}` {
		t.Errorf("current version changed: %s, %v", got, err)
	}
}

func TestNewerSchemaIsRefused(t *testing.T) {
	dir := t.TempDir()
	rec := `{"index":1,"schema":` + "999" + `,"time":"2026-01-01T00:00:00Z","actor":"x","type":"commit"}` + "\n"
	os.WriteFile(filepath.Join(dir, "config.log"), []byte(rec), 0o600)
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "newer version") {
		t.Fatalf("err = %v", err)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	src := open(t)
	a := mustCreate(t, src, "a", alias("web", "192.0.2.1"))
	mustCreate(t, src, "a", &model.FilterRule{Meta: model.Meta{Name: "r"}, Action: "accept", Direction: "in",
		Protocol: "tcp", Source: []model.Ref[model.Alias]{{ID: a.ID}}})
	snap := src.Current().Export()

	dst := open(t)
	stale := mustCreate(t, dst, "b", alias("leftover"))
	ops, err := dst.Current().ImportOps(snap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dst.Commit(ctx, "restore", "import", ops); err != nil {
		t.Fatalf("import: %v", err)
	}
	if _, ok := dst.Current().Get(model.KindAlias, stale.ID); ok {
		t.Error("object absent from the snapshot survived the import")
	}
	got, _ := json.Marshal(dst.Current().Export().Objects)
	want, _ := json.Marshal(snap.Objects)
	// Versions and authorship differ by design; compare the content.
	strip := func(b []byte) string {
		var m map[string][]map[string]any
		json.Unmarshal(b, &m)
		for _, objs := range m {
			for _, o := range objs {
				for _, k := range bookkeeping {
					delete(o, k)
				}
			}
		}
		out, _ := json.Marshal(m)
		return string(out)
	}
	if strip(got) != strip(want) {
		t.Errorf("after import:\n got %s\nwant %s", strip(got), strip(want))
	}
	// Importing the same snapshot again is a no-op.
	if ops, _ := dst.Current().ImportOps(snap); len(ops) != 0 {
		t.Errorf("second import wants %d ops", len(ops))
	}
}

func TestCompactKeepsStateAndRecentHistory(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		mustCreate(t, s, "x", alias(n))
	}
	before, _ := json.Marshal(s.Current().Export())
	if err := s.Compact(2); err != nil {
		t.Fatal(err)
	}
	hist, _ := s.History(0, 0)
	if len(hist) != 2 || hist[0].Index != 5 || hist[1].Index != 4 {
		t.Fatalf("history after compaction: %d records", len(hist))
	}
	f := mustCreate(t, s, "x", alias("f")) // the store keeps working
	if f.Version != 6 {
		t.Errorf("version after compaction: %d", f.Version)
	}
	s.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.Current().Index() != 6 || len(s2.Current().List(model.KindAlias)) != 6 {
		t.Errorf("reopen: index %d, %d aliases", s2.Current().Index(), len(s2.Current().List(model.KindAlias)))
	}
	_ = before

	// An interrupted compaction (snapshot written, log not yet trimmed)
	// must not replay records twice.
	dir2 := t.TempDir()
	s3, _ := Open(dir2)
	for _, n := range []string{"a", "b", "c"} {
		mustCreate(t, s3, "x", alias(n))
	}
	full, _ := os.ReadFile(filepath.Join(dir2, "config.log"))
	s3.Compact(1)
	s3.Close()
	os.WriteFile(filepath.Join(dir2, "config.log"), full, 0o600)
	s4, err := Open(dir2)
	if err != nil {
		t.Fatalf("open after interrupted compaction: %v", err)
	}
	defer s4.Close()
	if s4.Current().Index() != 3 || len(s4.Current().List(model.KindAlias)) != 3 {
		t.Errorf("interrupted compaction: index %d, %d aliases", s4.Current().Index(), len(s4.Current().List(model.KindAlias)))
	}
	mustCreate(t, s4, "x", alias("after"))
}

func TestOneFirewallPolicyPerScope(t *testing.T) {
	s := open(t)
	mustCreate(t, s, "a", &model.FirewallPolicy{Meta: model.Meta{Name: "default"}, AllowEstablished: true})
	if _, err := s.Create(ctx, "a", &model.FirewallPolicy{Meta: model.Meta{Name: "second"}}); err == nil ||
		!strings.Contains(err.Error(), "already covers") {
		t.Errorf("second global firewall policy: %v", err)
	}
}

func TestSecondWriterIsRefusedButReadersWork(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	defer s.Close()
	mustCreate(t, s, "a", alias("one"))
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("second writer: %v", err)
	}
	st, err := ReadState(dir)
	if err != nil || st.Index() != 1 || len(st.List(model.KindAlias)) != 1 {
		t.Fatalf("ReadState: %v", err)
	}
}

func TestGatewayGroupMustHaveMembers(t *testing.T) {
	s := open(t)
	_, err := s.Create(ctx, "a", &model.Route{Meta: model.Meta{Name: "r"}, Enabled: true, Destination: "10.0.0.0/8", GatewayGroup: "wan"})
	if err == nil || !strings.Contains(err.Error(), `no gateway belongs to group "wan"`) {
		t.Errorf("route to an empty group: %v", err)
	}
	// One of gateway and group is required, and not both.
	_, err = s.Create(ctx, "a", &model.Route{Meta: model.Meta{Name: "r"}, Enabled: true, Destination: "10.0.0.0/8"})
	if err == nil || !strings.Contains(err.Error(), "required_without") {
		t.Errorf("route without a next hop: %v", err)
	}
}
