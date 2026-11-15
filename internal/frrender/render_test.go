package frrender

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/testutil/golden"
)

func id(n int) string                    { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func meta(n int, name string) model.Meta { return model.Meta{ID: id(n), Name: name} }
func gw(n int) model.Ref[model.Gateway]  { return model.Ref[model.Gateway]{ID: id(n)} }
func ifc(n int) model.Ref[model.Interface] {
	return model.Ref[model.Interface]{ID: id(n)}
}

const siteN, nodeN = 1, 2

func opts() Options { return Options{SiteID: id(siteN), NodeID: id(nodeN)} }

func build(t *testing.T, objs ...model.Entity) *confstore.State {
	t.Helper()
	s, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	nodeScope := func(n int, name string) model.Meta {
		m := meta(n, name)
		m.Scope = model.NodeScope(id(nodeN))
		return m
	}
	base := []model.Entity{
		&model.Site{Meta: meta(siteN, "hq")},
		&model.ClusterNode{Meta: meta(nodeN, "fw1"), Site: model.Ref[model.Site]{ID: id(siteN)}, Hostname: "fw1", Address: "10.0.0.1"},
		&model.VRF{Meta: meta(5, "blue"), Table: 100},
		&model.Interface{Meta: nodeScope(10, "wan0"), Device: "wan0", Enabled: true},
		&model.Interface{Meta: nodeScope(11, "wan1"), Device: "wan1", Enabled: true},
		&model.Interface{Meta: nodeScope(12, "lan0"), Device: "lan0", Enabled: true},
		&model.Interface{Meta: nodeScope(13, "tenant0"), Device: "tenant0", Enabled: true, VRF: model.Ref[model.VRF]{ID: id(5)}},
		&model.Gateway{Meta: nodeScope(20, "isp-a"), Enabled: true, Interface: ifc(10), Address: "198.51.100.1", Group: "wan", Priority: 1, Monitor: "198.51.100.1"},
		&model.Gateway{Meta: nodeScope(21, "isp-b"), Enabled: true, Interface: ifc(11), Address: "203.0.113.1", Group: "wan", Priority: 1},
		&model.Gateway{Meta: nodeScope(22, "lte"), Enabled: true, Interface: ifc(11), Address: "203.0.113.254", Group: "wan", Priority: 2},
		&model.Gateway{Meta: nodeScope(23, "isp-a-v6"), Enabled: true, Interface: ifc(10), Address: "2001:db8:a::1", Group: "wan", Priority: 1},
		&model.Gateway{Meta: nodeScope(24, "core"), Enabled: true, Interface: ifc(12), Address: "10.0.0.254"},
		&model.Gateway{Meta: nodeScope(25, "tenant-gw"), Enabled: true, Interface: ifc(13), Address: "10.50.0.1", VRF: model.Ref[model.VRF]{ID: id(5)}},
	}
	for _, e := range append(base, objs...) {
		if _, err := s.Create(context.Background(), "test", e); err != nil {
			t.Fatalf("create %s %q: %v", e.Kind(), e.GetMeta().Name, err)
		}
	}
	return s.Current()
}

// full is every routing feature at once: the fixture behind the golden file.
func full(t *testing.T) *confstore.State {
	site := func(n int, name string) model.Meta {
		m := meta(n, name)
		m.Scope = model.SiteScope(id(siteN))
		return m
	}
	return build(t,
		&model.Route{Meta: meta(30, "default"), Enabled: true, Destination: "0.0.0.0/0", GatewayGroup: "wan"},
		&model.Route{Meta: meta(31, "default-v6"), Enabled: true, Destination: "::/0", GatewayGroup: "wan"},
		&model.Route{Meta: meta(32, "dc"), Enabled: true, Destination: "10.20.0.0/16", Gateway: gw(24), Metric: 20},
		&model.Route{Meta: meta(33, "tenant"), Enabled: true, Destination: "10.60.0.0/16", Gateway: gw(25), VRF: model.Ref[model.VRF]{ID: id(5)}},
		&model.Route{Meta: meta(34, "off"), Enabled: false, Destination: "10.99.0.0/16", Gateway: gw(24)},
		&model.PolicyRoute{Meta: meta(40, "voip-via-b"), Enabled: true, Mark: 0x10, Gateway: gw(21)},
		&model.PolicyRoute{Meta: meta(41, "backup-via-lte"), Enabled: true, Mark: 0x20, Gateway: gw(22), Table: 300},
		&model.BGPNeighbor{Meta: site(50, "transit"), Enabled: true, LocalAS: 65001, RemoteAS: 64500, Address: "198.51.100.1",
			UpdateSource: ifc(10), BFD: true, SessionSecret: "s3cret", HoldTimeSecond: 90,
			PrefixListIn: []string{"0.0.0.0/0"}, Announce: []string{"192.0.2.0/24", "2001:db8:100::/48"},
			Communities: []string{"65001:100", "65001:1:2", "no-export"}},
		&model.BGPNeighbor{Meta: site(51, "rr-client"), Enabled: true, LocalAS: 65001, RemoteAS: 65001, Address: "2001:db8:ffff::2", RRClient: true},
		&model.OSPFArea{Meta: site(60, "backbone"), Enabled: true, Area: "0.0.0.0", Interfaces: []model.Ref[model.Interface]{ifc(12)}},
		&model.OSPFArea{Meta: site(61, "edge"), Enabled: true, Area: "51", Interfaces: []model.Ref[model.Interface]{ifc(11)}, Stub: true},
		&model.OSPFArea{Meta: site(62, "backbone-v6"), Enabled: true, Area: "0.0.0.0", Interfaces: []model.Ref[model.Interface]{ifc(12)}, IPv6: true},
	)
}

func TestRenderGolden(t *testing.T) {
	res, err := Render(full(t), opts())
	if err != nil {
		t.Fatal(err)
	}
	golden.Assert(t, "frr.conf", []byte(res.Conf))
	if got := strings.Join(res.Daemons, ","); got != "bfdd,bgpd,ospf6d,ospfd" {
		t.Errorf("daemons: %s", got)
	}
	if len(res.Rules) != 2 || res.Rules[0] != (PolicyRule{Priority: RulePriorityBase, Mark: 0x10, Table: autoTableBase + 0x10}) ||
		res.Rules[1].Table != 300 {
		t.Errorf("policy rules: %+v", res.Rules)
	}
	if len(res.VRFs) != 1 || res.VRFs[0].Name != "blue" || res.VRFs[0].Table != 100 || strings.Join(res.VRFs[0].Members, ",") != "tenant0" {
		t.Errorf("vrf devices: %+v", res.VRFs)
	}
	if strings.Contains(res.Conf, "10.99.0.0") {
		t.Error("a disabled route was rendered")
	}
}

func defaults(conf string) []string {
	var out []string
	for _, l := range strings.Split(conf, "\n") {
		if strings.HasPrefix(l, "ip route 0.0.0.0/0") && !strings.Contains(l, "table") {
			out = append(out, strings.TrimPrefix(l, "ip route 0.0.0.0/0 "))
		}
	}
	return out
}

func TestGatewayGroupFailover(t *testing.T) {
	st := build(t, &model.Route{Meta: meta(30, "default"), Enabled: true, Destination: "0.0.0.0/0", GatewayGroup: "wan"})
	render := func(down ...int) Result {
		o := opts()
		o.Down = map[string]bool{}
		for _, n := range down {
			o.Down[id(n)] = true
		}
		res, err := Render(st, o)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	// Both tier-1 gateways up: traffic is shared between them.
	if got := strings.Join(defaults(render().Conf), " | "); got != "198.51.100.1 wan0 | 203.0.113.1 wan1" {
		t.Errorf("all up: %s", got)
	}
	// One down: the other carries everything; the backup tier stays idle.
	if got := strings.Join(defaults(render(20).Conf), " | "); got != "203.0.113.1 wan1" {
		t.Errorf("isp-a down: %s", got)
	}
	// The whole tier down: the backup takes over.
	if got := strings.Join(defaults(render(20, 21).Conf), " | "); got != "203.0.113.254 wan1" {
		t.Errorf("tier 1 down: %s", got)
	}
	// Everything down: the route stays on the preferred tier and the group
	// is reported, instead of the default route disappearing.
	res := render(20, 21, 22)
	if got := strings.Join(defaults(res.Conf), " | "); got != "198.51.100.1 wan0 | 203.0.113.1 wan1" || strings.Join(res.Degraded, ",") != "wan" {
		t.Errorf("all down: %s, degraded %v", got, res.Degraded)
	}
}

func TestProblemsAreNamed(t *testing.T) {
	cases := map[string]model.Entity{
		"different address families": &model.Route{Meta: meta(30, "mixed"), Enabled: true, Destination: "2001:db8::/32", Gateway: gw(24)},
		"at most 15 characters":      &model.VRF{Meta: meta(6, "a-very-long-vrf-name"), Table: 200},
	}
	for want, obj := range cases {
		_, err := Render(build(t, obj), opts())
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), obj.GetMeta().Name) {
			t.Errorf("%s: err = %v", obj.GetMeta().Name, err)
		}
	}
	// A group without a gateway of the route's address family on this node.
	gm := meta(26, "v6-uplink")
	gm.Scope = model.NodeScope(id(nodeN))
	_, err := Render(build(t,
		&model.Gateway{Meta: gm, Enabled: true, Interface: ifc(10), Address: "2001:db8:b::1", Group: "v6only"},
		&model.Route{Meta: meta(30, "nogroup"), Enabled: true, Destination: "10.1.0.0/16", GatewayGroup: "v6only"}), opts())
	if err == nil || !strings.Contains(err.Error(), "has no enabled gateway") || !strings.Contains(err.Error(), "nogroup") {
		t.Errorf("group without a usable gateway: %v", err)
	}
	dup := build(t,
		&model.PolicyRoute{Meta: meta(40, "a"), Enabled: true, Mark: 7, Gateway: gw(20)},
		&model.PolicyRoute{Meta: meta(41, "b"), Enabled: true, Mark: 7, Gateway: gw(21)})
	if _, err := Render(dup, opts()); err == nil || !strings.Contains(err.Error(), "already routed") {
		t.Errorf("duplicate mark: %v", err)
	}
}

func TestEmptyModelAsksNothing(t *testing.T) {
	s, _ := confstore.Open(t.TempDir())
	defer s.Close()
	res, err := Render(s.Current(), Options{})
	if err != nil || !res.Empty {
		t.Errorf("empty model: %+v, %v", res, err)
	}
	if res, _ := Render(full(t), opts()); res.Empty {
		t.Error("a full model was reported as empty")
	}
}

// TestGoldenConfigPassesFRRCheck has FRR's own parser read the configuration
// behind the golden file. It runs where vtysh is installed (the test image).
func TestGoldenConfigPassesFRRCheck(t *testing.T) {
	if _, err := exec.LookPath("vtysh"); err != nil {
		t.Skip("vtysh is not installed")
	}
	res, err := Render(full(t), opts())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(path, []byte(res.Conf), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("vtysh", "-C", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("vtysh refuses the configuration: %v\n%s", err, out)
	}
}
