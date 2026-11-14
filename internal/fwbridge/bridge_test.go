package fwbridge

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/firewall"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/testutil/golden"
)

var ctx = context.Background()

func id(n int) string                    { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func meta(n int, name string) model.Meta { return model.Meta{ID: id(n), Name: name} }
func zone(n int) model.Ref[model.Zone]   { return model.Ref[model.Zone]{ID: id(n)} }
func alias(n int) model.Ref[model.Alias] { return model.Ref[model.Alias]{ID: id(n)} }

// fakeManager records what the stage asks for.
type fakeManager struct {
	current firewall.OwnedSet
	applies int
	failOn  string // substring of a rule comment that makes the apply fail
	drift   firewall.Drift
}

func (f *fakeManager) ReplaceOwned(owner string, set firewall.OwnedSet, dryRun bool) error {
	if owner != firewall.OwnerModel {
		return fmt.Errorf("unexpected owner %q", owner)
	}
	for _, r := range set.Rules {
		if f.failOn != "" && strings.Contains(r.Comment, f.failOn) {
			return fmt.Errorf("kernel refused %s", r.Comment)
		}
	}
	if !dryRun {
		f.current = set
		f.applies++
	}
	return nil
}
func (f *fakeManager) Reconcile() firewall.Drift { return f.drift }

const (
	siteN, nodeN = 1, 2
	lan, wan     = 10, 11
)

func open(t *testing.T) *confstore.Store {
	t.Helper()
	s, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	add(t, s,
		&model.Site{Meta: meta(siteN, "hq")},
		&model.ClusterNode{Meta: meta(nodeN, "fw1"), Site: model.Ref[model.Site]{ID: id(siteN)}, Hostname: "fw1", Address: "10.0.0.1"},
		&model.Zone{Meta: meta(lan, "lan"), DefaultAction: "drop", IntraZone: true},
		&model.Zone{Meta: meta(wan, "wan"), DefaultAction: "drop"},
	)
	for i, dev := range []string{"lan0", "lan1", "wan0"} {
		m := meta(20+i, dev)
		m.Scope = model.NodeScope(id(nodeN))
		z := zone(lan)
		if dev == "wan0" {
			z = zone(wan)
		}
		add(t, s, &model.Interface{Meta: m, Device: dev, Zone: z, Enabled: true})
	}
	add(t, s,
		&model.Alias{Meta: meta(30, "web-servers"), Type: "host", Entries: []string{"192.0.2.10", "2001:db8::10"}},
		&model.Alias{Meta: meta(31, "web-ports"), Type: "port", Entries: []string{"443", "8000-8099"}},
		&model.Alias{Meta: meta(32, "blocklist"), Type: "url_table", URL: "https://example.net/l.txt"},
	)
	return s
}

func add(t *testing.T, s *confstore.Store, objs ...model.Entity) {
	t.Helper()
	for _, e := range objs {
		if _, err := s.Create(ctx, "test", e); err != nil {
			t.Fatalf("create %s %q: %v", e.Kind(), e.GetMeta().Name, err)
		}
	}
}

func stage(m Manager) *Stage { return &Stage{Manager: m, SiteID: id(siteN), NodeID: id(nodeN)} }

func TestRenderGolden(t *testing.T) {
	s := open(t)
	add(t, s,
		&model.FirewallPolicy{Meta: meta(40, "default"), DefaultDeny: true, AllowEstablished: true, DropInvalid: true,
			AllowLoopback: true, AllowICMP: true, AllowTCPPorts: []string{"22", "8080"}, LogDrops: true},
		&model.FilterRule{Meta: meta(51, "lan-to-web"), Sequence: 20, Enabled: true, Action: "accept", Direction: "forward",
			Protocol: "tcp", SourceZone: zone(lan), DestinationZone: zone(wan), Destination: []model.Ref[model.Alias]{alias(30)},
			PortAliases: []model.Ref[model.Alias]{alias(31)}, States: []string{"new"}},
		&model.FilterRule{Meta: meta(50, "dns"), Sequence: 10, Enabled: true, Action: "accept", Direction: "in",
			Protocol: "any", SourceZone: zone(lan), Ports: []string{"53"}, RateLimit: "100/second", Log: true},
		&model.FilterRule{Meta: meta(52, "off"), Sequence: 30, Enabled: false, Action: "accept", Direction: "forward", Protocol: "any"},
		&model.NATRule{Meta: meta(60, "publish"), Enabled: true, Type: "dnat", Zone: zone(wan), Protocol: "tcp", Port: "443",
			TranslateTo: "192.0.2.10", TranslatePort: "8443"},
		&model.NATRule{Meta: meta(61, "outbound"), Enabled: true, Type: "masquerade", Zone: zone(wan), Protocol: "any",
			SourceNets: []string{"10.0.0.0/8"}},
	)
	out, err := stage(nil).Render(s.Current())
	if err != nil {
		t.Fatal(err)
	}
	golden.Assert(t, "policy.json", append(out, '\n'))

	var set firewall.OwnedSet
	json.Unmarshal(out, &set)
	// 4 intra-zone rules, dns on two interfaces for tcp and udp,
	// lan-to-web: 2 interfaces x 2 port ranges x (1 IPv4 + 1 IPv6 address),
	// and the accept that belongs to the port forward.
	if len(set.Rules) != 4+4+8+1 || len(set.Forwards) != 1 || len(set.Masquerades) != 1 || set.Enforce == nil || !*set.Enforce {
		t.Errorf("%d rules, %d forwards, %d masquerades", len(set.Rules), len(set.Forwards), len(set.Masquerades))
	}
	// Rules come in sequence order whatever the creation order was.
	var order []string
	for _, r := range set.Rules {
		name := r.Comment[strings.LastIndex(r.Comment, " ")+1:]
		if len(order) == 0 || order[len(order)-1] != name {
			order = append(order, name)
		}
	}
	if got := strings.Join(order, ","); got != "lan,dns,lan-to-web,publish" {
		t.Errorf("order: %s", got)
	}
}

func TestWhatCannotBeEnforcedIsRefusedByName(t *testing.T) {
	cases := map[string]model.Entity{
		"run time":         &model.FilterRule{Meta: meta(50, "blocked"), Enabled: true, Action: "drop", Direction: "forward", Protocol: "any", Source: []model.Ref[model.Alias]{alias(32)}},
		"firewall mark":    &model.FilterRule{Meta: meta(50, "marked"), Enabled: true, Action: "accept", Direction: "forward", Protocol: "any", Mark: 7},
		"snat is not":      &model.NATRule{Meta: meta(60, "src"), Enabled: true, Type: "snat", Zone: zone(wan), Protocol: "any", TranslateTo: "203.0.113.6"},
		"one-to-one":       &model.NATRule{Meta: meta(60, "pair"), Enabled: true, Type: "one_to_one", Protocol: "any", Destination: "203.0.113.7", TranslateTo: "10.0.0.7"},
		"reflection":       &model.NATRule{Meta: meta(60, "hairpin"), Enabled: true, Type: "dnat", Zone: zone(wan), Protocol: "tcp", Port: "443", TranslateTo: "192.0.2.10", Reflection: true},
		"single IPv4":      &model.NATRule{Meta: meta(60, "v6fwd"), Enabled: true, Type: "dnat", Zone: zone(wan), Protocol: "tcp", Port: "443", TranslateTo: "2001:db8::10"},
		"SYN flood":        &model.FirewallPolicy{Meta: meta(40, "p"), SynFloodGuard: true},
		"limit 256":        &model.FilterRule{Meta: meta(50, "huge"), Enabled: true, Action: "accept", Direction: "forward", Protocol: "any", SourceZone: zone(lan), DestinationZone: zone(lan), Ports: manyPorts(200)},
		"ports need proto": &model.FilterRule{Meta: meta(50, "icmp-port"), Enabled: true, Action: "accept", Direction: "in", Protocol: "icmp", Ports: []string{"80"}},
	}
	for want, obj := range cases {
		s := open(t)
		add(t, s, obj)
		_, err := stage(nil).Render(s.Current())
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), obj.GetMeta().Name) {
			t.Errorf("%s: err = %v", obj.GetMeta().Name, err)
		}
	}
	// A disabled object of an unsupported kind is no obstacle.
	s := open(t)
	add(t, s, &model.NATRule{Meta: meta(60, "later"), Enabled: false, Type: "snat", Zone: zone(wan), Protocol: "any", TranslateTo: "203.0.113.6"})
	if _, err := stage(nil).Render(s.Current()); err != nil {
		t.Errorf("disabled unsupported rule: %v", err)
	}
}

func manyPorts(n int) []string {
	out := make([]string, 0, 64)
	for i := 0; i < 64 && i < n; i++ {
		out = append(out, fmt.Sprint(1000+i))
	}
	return out
}

func TestAnotherNodeDoesNotGetThisNodesInterfaces(t *testing.T) {
	s := open(t)
	add(t, s, &model.FilterRule{Meta: meta(50, "in"), Enabled: true, Action: "accept", Direction: "in", Protocol: "tcp",
		SourceZone: zone(lan), Ports: []string{"22"}})
	other := &Stage{SiteID: id(siteN), NodeID: id(99)}
	if _, err := other.Render(s.Current()); err == nil || !strings.Contains(err.Error(), "no interface on this node") {
		t.Errorf("node without interfaces in the zone: %v", err)
	}
}

func TestThroughTheApplyEngine(t *testing.T) {
	s := open(t)
	fm := &fakeManager{drift: firewall.Drift{InSync: true}}
	eng, err := confapply.New(s, confapply.Options{Dir: t.TempDir(), Window: 60 * time.Millisecond}, stage(fm))
	if err != nil {
		t.Fatal(err)
	}
	rule := func(n int, name string) []confstore.Op {
		obj, _ := json.Marshal(&model.FilterRule{Meta: meta(n, name), Enabled: true, Action: "accept", Direction: "in",
			Protocol: "tcp", Ports: []string{"9090"}})
		return []confstore.Op{{Type: confstore.OpCreate, Kind: model.KindFilterRule, ID: id(n), Object: obj}}
	}
	// An empty model on a node without privileges is fine.
	if err := stage(nil).Apply(ctx, []byte(`{}`)); err != nil {
		t.Errorf("empty artifact without a manager: %v", err)
	}

	if _, err := eng.Apply(ctx, "alice", "", rule(50, "mgmt")); err != nil {
		t.Fatal(err)
	}
	if len(fm.current.Rules) != 4+1 { // intra-zone rules plus the new one
		t.Fatalf("applied %d rules", len(fm.current.Rules))
	}
	eng.Confirm("alice")

	// The kernel refusing a rule in the dry run leaves model and kernel alone.
	fm.failOn = "broken"
	before := fm.applies
	if _, err := eng.Apply(ctx, "alice", "", rule(51, "broken")); err == nil {
		t.Fatal("refused rule was accepted")
	}
	if fm.applies != before || len(s.Current().List(model.KindFilterRule)) != 1 {
		t.Errorf("a refused change left traces: applies %d->%d", before, fm.applies)
	}
	fm.failOn = ""

	// Unconfirmed: the previous rules come back by themselves.
	if _, err := eng.Apply(ctx, "alice", "", rule(52, "risky")); err != nil {
		t.Fatal(err)
	}
	if len(fm.current.Rules) != 6 {
		t.Fatalf("change not live: %d rules", len(fm.current.Rules))
	}
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, pending := eng.Pending(); !pending {
			break
		}
	}
	if len(fm.current.Rules) != 5 || len(s.Current().List(model.KindFilterRule)) != 1 {
		t.Errorf("after the window: %d kernel rules, %d model rules", len(fm.current.Rules), len(s.Current().List(model.KindFilterRule)))
	}

	// A kernel that does not match after the apply fails the health check.
	fm.drift = firewall.Drift{Error: "table vanished"}
	if _, err := eng.Apply(ctx, "alice", "", rule(53, "unhealthy")); err == nil || !strings.Contains(err.Error(), "table vanished") {
		t.Errorf("health failure: %v", err)
	}
}
