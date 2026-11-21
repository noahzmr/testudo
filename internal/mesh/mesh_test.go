package mesh

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

var ctx = context.Background()

func id(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

func key(n int) string {
	k := make([]byte, 32)
	k[0] = byte(n)
	return fmt.Sprintf("%-43s=", strings.Repeat("A", 42)+string("ABCDEFGHIJKLMNOPQRSTUVWXYZ"[n%26]))[:44]
}

type fixture struct {
	t *testing.T
	s *confstore.Store
}

func newFixture(t *testing.T) *fixture {
	s, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return &fixture{t, s}
}

func (f *fixture) add(objs ...model.Entity) {
	f.t.Helper()
	for _, e := range objs {
		if _, err := f.s.Create(ctx, "test", e); err != nil {
			f.t.Fatalf("create %s %q: %v", e.Kind(), e.GetMeta().Name, err)
		}
	}
}

func meta(n int, name string) model.Meta { return model.Meta{ID: id(n), Name: name} }

// three sites: hq (hub, AS 65001) with two nodes, branch (AS 65002) and
// lab (no AS of its own: the fabric's, 65000), plus a witness.
func sites(t *testing.T, topology string) *fixture {
	f := newFixture(t)
	f.add(
		&model.Zone{Meta: meta(1, "fabric"), DefaultAction: "drop"},
		&model.Site{Meta: meta(10, "hq"), ASN: 65001, Hub: true, Networks: []string{"10.1.0.0/16"}},
		&model.Site{Meta: meta(11, "branch"), ASN: 65002, Networks: []string{"10.2.0.0/16"}},
		&model.Site{Meta: meta(12, "lab"), Networks: []string{"10.3.0.0/24"}},
		&model.Site{Meta: meta(13, "witness"), Witness: true},
	)
	node := func(n int, name string, site, index int, colors ...string) *model.ClusterNode {
		c := &model.ClusterNode{Meta: meta(n, name), Site: model.Ref[model.Site]{ID: id(site)}, Hostname: name,
			Address: fmt.Sprintf("192.0.2.%d", n), MeshIndex: index, MeshPublicKey: key(n)}
		for _, color := range colors {
			c.Uplinks = append(c.Uplinks, model.Uplink{Color: color, Endpoint: fmt.Sprintf("%s.%s.example.net", color, name)})
		}
		return c
	}
	f.add(
		node(20, "hq1", 10, 1, "inet", "mpls"),
		node(21, "hq2", 10, 2, "inet"),
		node(22, "br1", 11, 5, "inet", "mpls"),
		node(23, "lab1", 12, 9, "inet"),
		node(24, "wit1", 13, 31, "inet"),
		&model.Fabric{Meta: meta(30, "fabric"), Enabled: true, Topology: topology, Pool: "10.255.0.0/16", PortBase: 52000,
			ASN: 65000, Colors: []string{"inet", "mpls"}, Zone: model.Ref[model.Zone]{ID: id(1)}, BFD: true},
	)
	return f
}

func (f *fixture) plan(node, site int) Plan {
	f.t.Helper()
	p, err := Build(f.s.Current(), id(site), id(node))
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

func TestFullMesh(t *testing.T) {
	f := sites(t, "full_mesh")
	br := f.plan(22, 11)
	// br1 meets hq1 on both colors, hq2 and lab1 on the internet only; no
	// tunnel to the witness.
	var got []string
	for _, tu := range br.Tunnels {
		got = append(got, fmt.Sprintf("%s %s %d %s %s %s", tu.Device, tu.Color, tu.ListenPort, tu.Local, tu.Peer, tu.Endpoint))
	}
	want := []string{
		"tm01c0s0 inet 52001 10.255.0.75/31 10.255.0.74 inet.hq1.example.net:52005",
		"tm01c1s0 mpls 52033 10.255.8.75/31 10.255.8.74 mpls.hq1.example.net:52037",
		"tm02c0s0 inet 52002 10.255.0.139/31 10.255.0.138 inet.hq2.example.net:52005",
		"tm09c0s0 inet 52009 10.255.1.82/31 10.255.1.83 inet.lab1.example.net:52005",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("tunnels of br1:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The other end of each link agrees.
	hq1 := f.plan(20, 10)
	for _, tu := range hq1.Tunnels {
		if tu.PeerNode == id(22) && tu.Color == "inet" {
			if tu.Local != "10.255.0.74/31" || tu.Peer != "10.255.0.75" || tu.ListenPort != 52005 || tu.Endpoint != "inet.br1.example.net:52001" {
				t.Errorf("hq1 towards br1: %+v", tu)
			}
		}
		if tu.PeerNode == id(21) {
			t.Error("hq1 has a tunnel to hq2 at its own site")
		}
	}
	// eBGP between hq and branch; the lab uses the fabric's AS.
	for _, tu := range br.Tunnels {
		if tu.IBGP || tu.LocalAS != 65002 {
			t.Errorf("br1 session %s: %+v", tu.Device, tu)
		}
	}
	if lab := f.plan(23, 12); lab.ASN != 65000 || lab.Loopback != "10.255.255.9" {
		t.Errorf("lab: AS %d loopback %s", lab.ASN, lab.Loopback)
	}
	// Announced: its loopback and its networks; accepted: everyone else's.
	if fmt.Sprint(br.Announce[0]) != "[10.2.0.0/16 10.255.255.5/32]" {
		t.Errorf("br1 announces %v", br.Announce[0])
	}
	if fmt.Sprint(br.Accept[0]) != "[10.1.0.0/16 10.255.255.1/32 10.255.255.2/32 10.255.255.9/32 10.3.0.0/24]" {
		t.Errorf("br1 accepts %v", br.Accept[0])
	}
	// A witness and a node without an index or key are not in it.
	if w := f.plan(24, 13); w.Enabled || len(w.Tunnels) != 0 {
		t.Errorf("witness plan: %+v", w)
	}
}

func TestHubAndSpoke(t *testing.T) {
	f := sites(t, "hub_spoke")
	br := f.plan(22, 11)
	for _, tu := range br.Tunnels {
		if tu.PeerSite != id(10) {
			t.Errorf("spoke br1 has a tunnel to a spoke: %s", tu.Device)
		}
	}
	if len(br.Tunnels) != 3 {
		t.Errorf("spoke br1 has %d tunnels, want 3 (hq1 twice, hq2 once)", len(br.Tunnels))
	}
	hq := f.plan(20, 10)
	if !hq.Reflect || len(hq.Tunnels) != 3 {
		t.Errorf("hub hq1: reflect %v, %d tunnels", hq.Reflect, len(hq.Tunnels))
	}
}

func TestSameASIsIBGPWithReflection(t *testing.T) {
	f := sites(t, "hub_spoke")
	st := f.s.Current()
	br, _ := st.Get(model.KindSite, id(11))
	b := *br.(*model.Site)
	b.ASN = 65001
	if _, err := f.s.Update(ctx, "test", &b, b.Version); err != nil {
		t.Fatal(err)
	}
	for _, tu := range f.plan(20, 10).Tunnels {
		if tu.PeerSite == id(11) && (!tu.IBGP || !tu.ReflectorClient) {
			t.Errorf("hub towards a spoke of its own AS: %+v", tu)
		}
	}
	for _, tu := range f.plan(22, 11).Tunnels {
		if !tu.IBGP || tu.ReflectorClient {
			t.Errorf("spoke towards its hub: %+v", tu)
		}
	}
}

func TestStretchedVRF(t *testing.T) {
	f := sites(t, "full_mesh")
	// The tenant VRF exists at hq and at branch, not in the lab.
	v := &model.VRF{Meta: meta(40, "tenant"), Table: 100, MeshSlot: 2, Networks: []string{"172.16.1.0/24"}}
	v.Overrides = []model.Override{{Scope: model.SiteScope(id(11)), Values: map[string]any{"networks": []string{"172.16.2.0/24"}}}}
	v.Scope = model.ScopeGlobal
	f.add(v)
	br := f.plan(22, 11)
	var vrf []string
	for _, tu := range br.Tunnels {
		if tu.Slot == 2 {
			vrf = append(vrf, tu.Device+" "+tu.VRF)
		}
	}
	// hq1 twice, hq2 once, and the lab too: the VRF is global here.
	if len(vrf) != 4 || !strings.Contains(strings.Join(vrf, ","), "tm01c0s2 tenant") {
		t.Errorf("VRF tunnels: %v", vrf)
	}
	if fmt.Sprint(br.Announce[2]) != "[172.16.2.0/24]" {
		t.Errorf("br1 announces in the VRF %v", br.Announce[2])
	}
	if fmt.Sprint(br.Remote[2][id(20)]) != "[172.16.1.0/24]" {
		t.Errorf("hq1 stands for %v in the VRF", br.Remote[2][id(20)])
	}
	for _, tu := range br.Tunnels {
		if tu.Slot == 2 && tu.ListenPort != 52000+(2*4+tu.ColorIndex)*32+map[string]int{id(20): 1, id(21): 2, id(23): 9}[tu.PeerNode] {
			t.Errorf("port of %s: %d", tu.Device, tu.ListenPort)
		}
	}
}

func TestNumbersStayPutWhenSitesComeAndGo(t *testing.T) {
	f := sites(t, "full_mesh")
	before := f.plan(22, 11)
	// A new site joins with a node between the existing indexes.
	f.add(&model.Site{Meta: meta(14, "new"), ASN: 65004},
		&model.ClusterNode{Meta: meta(25, "new1"), Site: model.Ref[model.Site]{ID: id(14)}, Hostname: "new1", Address: "192.0.2.25",
			MeshIndex: 3, MeshPublicKey: key(25), Uplinks: []model.Uplink{{Color: "inet", Endpoint: "203.0.113.25"}}})
	after := f.plan(22, 11)
	old := map[string]Tunnel{}
	for _, tu := range before.Tunnels {
		old[tu.Device] = tu
	}
	added := 0
	for _, tu := range after.Tunnels {
		o, ok := old[tu.Device]
		if !ok {
			added++
			if tu.Device != "tm03c0s0" || tu.Endpoint != "203.0.113.25:52005" {
				t.Errorf("new tunnel: %+v", tu)
			}
			continue
		}
		if o.ListenPort != tu.ListenPort || o.Local != tu.Local || o.Peer != tu.Peer {
			t.Errorf("tunnel %s changed: %+v -> %+v", tu.Device, o, tu)
		}
	}
	if added != 1 {
		t.Errorf("%d tunnels added", added)
	}
}

func TestLayoutLimits(t *testing.T) {
	// The highest link offset stays below the loopbacks, and ports within
	// the 512 the fabric reserves.
	a, b, err := LinkAddrs("10.255.0.0/16", 30, 31, MaxColors-1, MaxSlots-1)
	if err != nil || a != "10.255.127.190" || b != "10.255.127.191" {
		t.Errorf("highest link: %s %s %v", a, b, err)
	}
	if p := Port(52000, 31, MaxColors-1, MaxSlots-1); p != 52511 {
		t.Errorf("highest port %d", p)
	}
	if lb, _ := Loopback("10.255.0.0/16", 31); lb != "10.255.255.31" {
		t.Errorf("loopback %s", lb)
	}
	for _, bad := range []string{"10.255.0.0/24", "2001:db8::/16", "nonsense"} {
		if _, _, err := LinkAddrs(bad, 1, 2, 0, 0); err == nil {
			t.Errorf("pool %s accepted", bad)
		}
	}
	if len(Device(31, 3, 3)) > 15 {
		t.Error("device names exceed the kernel's limit")
	}
}
