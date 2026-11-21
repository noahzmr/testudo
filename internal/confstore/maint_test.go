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

func TestKernelModeServiceBalancesConnectionsOnly(t *testing.T) {
	s := open(t)
	zone := mustCreate(t, s, "a", &model.Zone{Meta: model.Meta{Name: "wan"}, DefaultAction: "drop"})
	pool := mustCreate(t, s, "a", &model.LBBackendPool{Meta: model.Meta{Name: "web"}, Algorithm: "weighted_round_robin",
		Backends: []model.LBBackend{{Address: "10.0.0.2:80"}}, HealthCheck: model.LBHealthCheck{Type: "tcp"}})
	svc := func(name, proto string, port int, withPool bool) *model.LBService {
		l := &model.LBService{Meta: model.Meta{Name: name}, Enabled: true, Zone: model.Ref[model.Zone]{ID: zone.ID},
			Port: port, Protocol: proto, Mode: "kernel"}
		if withPool {
			l.DefaultPool = model.Ref[model.LBBackendPool]{ID: pool.ID}
		}
		return l
	}
	if _, err := s.Create(ctx, "a", svc("l7", "http", 80, true)); err == nil || !strings.Contains(err.Error(), "needs proxy mode") {
		t.Errorf("http in kernel mode: %v", err)
	}
	if _, err := s.Create(ctx, "a", svc("nopool", "tcp", 81, false)); err == nil || !strings.Contains(err.Error(), "fallback pool") {
		t.Errorf("kernel mode without a pool: %v", err)
	}
	ok := mustCreate(t, s, "a", svc("l4", "tcp", 82, true))
	_, err := s.Create(ctx, "a", &model.LBRouter{Meta: model.Meta{Name: "r"}, Enabled: true, Service: model.Ref[model.LBService]{ID: ok.ID},
		TLS: "none", Pool: model.Ref[model.LBBackendPool]{ID: pool.ID}})
	if err == nil || !strings.Contains(err.Error(), "sees no host names") {
		t.Errorf("router on a kernel-mode service: %v", err)
	}
}

func TestFabricChecks(t *testing.T) {
	s := open(t)
	zone := mustCreate(t, s, "a", &model.Zone{Meta: model.Meta{Name: "fabric"}, DefaultAction: "drop"})
	fab := func(name, pool string) *model.Fabric {
		return &model.Fabric{Meta: model.Meta{Name: name}, Enabled: true, Topology: "full_mesh", Pool: pool, PortBase: 52000, ASN: 65000,
			Colors: []string{"inet", "mpls"}, Zone: model.Ref[model.Zone]{ID: zone.ID}}
	}
	if _, err := s.Create(ctx, "a", fab("f", "10.255.0.0/24")); err == nil || !strings.Contains(err.Error(), "/16") {
		t.Errorf("a /24 pool: %v", err)
	}
	if _, err := s.Create(ctx, "a", fab("f", "2001:db8::/16")); err == nil || !strings.Contains(err.Error(), "IPv4") {
		t.Errorf("an IPv6 pool: %v", err)
	}
	mustCreate(t, s, "a", fab("f", "10.255.0.0/16"))
	if _, err := s.Create(ctx, "a", fab("g", "10.254.0.0/16")); err == nil || !strings.Contains(err.Error(), "one fabric") {
		t.Errorf("second fabric: %v", err)
	}
	site := mustCreate(t, s, "a", &model.Site{Meta: model.Meta{Name: "hq"}})
	node := func(name string, index int, colors ...string) *model.ClusterNode {
		n := &model.ClusterNode{Meta: model.Meta{Name: name}, Site: model.Ref[model.Site]{ID: site.ID}, Hostname: name, Address: "192.0.2.1", MeshIndex: index}
		for _, c := range colors {
			n.Uplinks = append(n.Uplinks, model.Uplink{Color: c, Endpoint: "198.51.100.1"})
		}
		return n
	}
	mustCreate(t, s, "a", node("fw1", 1, "inet"))
	for want, n := range map[string]*model.ClusterNode{
		"fabric index 1 already":  node("fw2", 1),
		"not one of the fabric's": node("fw3", 3, "lte"),
		"two uplinks of color":    node("fw4", 4, "inet", "inet"),
	} {
		if _, err := s.Create(ctx, "a", n); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", want, err)
		}
	}
	if _, err := s.Create(ctx, "a", &model.WGTunnel{Meta: model.Meta{Name: "wg", Scope: model.SiteScope(site.ID)}, Enabled: true, Device: "wg9", Mode: "road_warrior",
		ListenPort: 52100, Addresses: []string{"10.8.0.1/24"}, PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Zone: model.Ref[model.Zone]{ID: zone.ID}}); err == nil || !strings.Contains(err.Error(), "range the fabric uses") {
		t.Errorf("a tunnel in the fabric's ports: %v", err)
	}
	mustCreate(t, s, "a", &model.VRF{Meta: model.Meta{Name: "red"}, Table: 100, MeshSlot: 1})
	if _, err := s.Create(ctx, "a", &model.VRF{Meta: model.Meta{Name: "blue"}, Table: 101, MeshSlot: 1}); err == nil || !strings.Contains(err.Error(), "slot 1 already") {
		t.Errorf("two VRFs in one slot: %v", err)
	}
	if _, err := s.Create(ctx, "a", &model.PathPolicy{Meta: model.Meta{Name: "voice"}, Enabled: true, Mark: 9, Prefer: "carrier-pigeon"}); err == nil || !strings.Contains(err.Error(), "neither") {
		t.Errorf("unknown preference: %v", err)
	}
	mustCreate(t, s, "a", &model.PathPolicy{Meta: model.Meta{Name: "voice"}, Enabled: true, Mark: 9, Prefer: "mpls"})
	if _, err := s.Create(ctx, "a", &model.PathPolicy{Meta: model.Meta{Name: "bulk"}, Enabled: true, Mark: 9, Prefer: "lowest_loss"}); err == nil || !strings.Contains(err.Error(), "already routed") {
		t.Errorf("two policies on one mark: %v", err)
	}
}

func TestHAPairChecks(t *testing.T) {
	s := open(t)
	hq := mustCreate(t, s, "a", &model.Site{Meta: model.Meta{Name: "hq"}})
	branch := mustCreate(t, s, "a", &model.Site{Meta: model.Meta{Name: "branch"}})
	node := func(name, site, sync string) model.Entity {
		return mustCreate(t, s, "a", &model.ClusterNode{Meta: model.Meta{Name: name}, Site: model.Ref[model.Site]{ID: site},
			Hostname: name, Address: "192.0.2.1", SyncAddress: sync})
	}
	fw1, fw2 := node("fw1", hq.GetMeta().ID, "10.9.9.1"), node("fw2", hq.GetMeta().ID, "10.9.9.2")
	nosync := node("fw3", hq.GetMeta().ID, "")
	away := node("br1", branch.GetMeta().ID, "10.9.9.3")
	pair := func(name string, a, b model.Entity, in ...model.VRRPInstance) *model.HAPair {
		p := &model.HAPair{Meta: model.Meta{Name: name}, Enabled: true, SyncInterface: "sync0",
			Nodes: []model.Ref[model.ClusterNode]{{ID: a.GetMeta().ID}, {ID: b.GetMeta().ID}}, Instances: in}
		p.Scope = model.SiteScope(hq.GetMeta().ID)
		return p
	}
	lan := model.VRRPInstance{Interface: "lan", VRID: 51, VirtualIPs: []string{"10.0.0.1/24"}}
	for _, tc := range []struct {
		p    *model.HAPair
		want string
	}{
		{pair("same", fw1, fw1, lan), "two different nodes"},
		{pair("away", fw1, away, lan), "not at the pair's site"},
		{pair("nosync", fw1, nosync, lan), "no address on the sync link"},
		{pair("mixed", fw1, fw2, model.VRRPInstance{Interface: "lan", VRID: 9, VirtualIPs: []string{"10.0.0.1/24", "2001:db8::1/64"}}), "mixes IPv4 and IPv6"},
	} {
		if _, err := s.Create(ctx, "a", tc.p); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.p.Name, err, tc.want)
		}
	}
	mustCreate(t, s, "a", pair("edge", fw1, fw2, lan))
	if _, err := s.Create(ctx, "a", pair("edge2", fw1, fw2, lan)); err == nil || !strings.Contains(err.Error(), "virtual router id 51") {
		t.Errorf("a second pair with the same VRID on the same interface: %v", err)
	}
}
