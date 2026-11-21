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
)

const fabricKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// fabricModel: this node (index 1) at a hub site with two colors, a spoke
// with both colors, and a stretched VRF.
func fabricModel(t *testing.T, topology string, spokeAS uint32, extra ...model.Entity) (*confstore.State, Options) {
	t.Helper()
	objs := []model.Entity{
		&model.Zone{Meta: meta(90, "fabric"), DefaultAction: "drop"},
		&model.Site{Meta: meta(siteN, "hq"), ASN: 65001, Hub: true, Networks: []string{"10.1.0.0/16"}},
		&model.Site{Meta: meta(80, "branch"), ASN: spokeAS, Networks: []string{"10.2.0.0/16"}},
		&model.ClusterNode{Meta: meta(nodeN, "fw1"), Site: model.Ref[model.Site]{ID: id(siteN)}, Hostname: "fw1", Address: "192.0.2.1",
			MeshIndex: 1, MeshPublicKey: fabricKey, Uplinks: []model.Uplink{{Color: "inet", Endpoint: "198.51.100.1"}, {Color: "mpls", Endpoint: "10.200.0.1"}}},
		&model.ClusterNode{Meta: meta(81, "br1"), Site: model.Ref[model.Site]{ID: id(80)}, Hostname: "br1", Address: "192.0.2.2",
			MeshIndex: 2, MeshPublicKey: fabricKey, Uplinks: []model.Uplink{{Color: "inet", Endpoint: "198.51.100.2"}, {Color: "mpls", Endpoint: "10.200.0.2"}}},
		&model.Fabric{Meta: meta(91, "fabric"), Enabled: true, Topology: topology, Pool: "10.255.0.0/16", PortBase: 52000, ASN: 65000,
			Colors: []string{"inet", "mpls"}, Zone: model.Ref[model.Zone]{ID: id(90)}, BFD: true},
	}
	store, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	for _, e := range append(objs, extra...) {
		if _, err := store.Create(context.Background(), "test", e); err != nil {
			t.Fatalf("create %s %q: %v", e.Kind(), e.GetMeta().Name, err)
		}
	}
	o := opts()
	o.Paths = prefer{"mpls"}
	return store.Current(), o
}

type prefer struct{ color string }

func (p prefer) Preferred(string, int, string) string { return p.color }
func (prefer) Down(string) bool                       { return false }

func TestFabricSessions(t *testing.T) {
	st, o := fabricModel(t, "full_mesh", 65002)
	res, err := Render(st, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"interface lo\n ip address 10.255.255.1/32\nexit",
		"bgp router-id 192.0.2.1",
		// One eBGP session per tunnel, over its link addresses, with BFD.
		" neighbor 10.255.0.69 remote-as 65002\n neighbor 10.255.0.69 description fabric-tm02c0s0\n neighbor 10.255.0.69 bfd\n neighbor 10.255.0.69 timers 10 30",
		" neighbor 10.255.8.69 remote-as 65002",
		// Originates its own networks and loopback, accepts the spoke's.
		" network 10.1.0.0/16\n  network 10.255.255.1/32",
		"ip prefix-list fabric-tm02c0s0-in seq 5 permit 10.2.0.0/16\nip prefix-list fabric-tm02c0s0-in seq 10 permit 10.255.255.2/32",
		// The measured best color gets the higher preference.
		"route-map fabric-tm02c1s0-in permit 10\n match ip address prefix-list fabric-tm02c1s0-in\n set local-preference 200",
		"route-map fabric-tm02c0s0-in permit 10\n match ip address prefix-list fabric-tm02c0s0-in\n set local-preference 100",
		"maximum-paths 8",
	} {
		if !strings.Contains(res.Conf, want) {
			t.Errorf("configuration lacks:\n%s\n--- in ---\n%s", want, res.Conf)
			break
		}
	}
	if fmt.Sprint(res.Daemons) != "[bfdd bgpd]" {
		t.Errorf("daemons %v", res.Daemons)
	}
}

func TestFabricHubReflectsToSpokesOfItsAS(t *testing.T) {
	st, o := fabricModel(t, "hub_spoke", 65001)
	res, err := Render(st, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		" neighbor 10.255.0.69 remote-as 65001",
		"  neighbor 10.255.0.69 route-reflector-client\n  neighbor 10.255.0.69 next-hop-self force",
		// A hub passes on what it learns.
		"ip prefix-list fabric-tm02c0s0-out seq 15 permit 10.2.0.0/16",
	} {
		if !strings.Contains(res.Conf, want) {
			t.Errorf("configuration lacks:\n%s\n--- in ---\n%s", want, res.Conf)
		}
	}
}

func TestFabricStretchedVRFAndPathPolicy(t *testing.T) {
	v := &model.VRF{Meta: meta(92, "tenant"), Table: 100, MeshSlot: 1, Networks: []string{"172.16.1.0/24"}}
	pp := &model.PathPolicy{Meta: meta(93, "voice"), Enabled: true, Mark: 0x20, Prefer: "inet"}
	pl := &model.PathPolicy{Meta: meta(94, "bulk"), Enabled: true, Mark: 0x21, Prefer: "lowest_loss"}
	st, o := fabricModel(t, "full_mesh", 65002, v, pp, pl)
	res, err := Render(st, o)
	if err != nil {
		t.Fatal(err)
	}
	var tenant *VRFDevice
	for i := range res.VRFs {
		if res.VRFs[i].Name == "tenant" {
			tenant = &res.VRFs[i]
		}
	}
	if tenant == nil || fmt.Sprint(tenant.Members) != "[tm02c0s1 tm02c1s1]" {
		t.Errorf("VRF devices: %+v", res.VRFs)
	}
	for _, want := range []string{
		"router bgp 65001 vrf tenant",
		" neighbor 10.255.32.69 remote-as 65002",
		// Voice goes over the internet tunnel, bulk over the path with the
		// least loss (mpls, says the chooser), each in its own table.
		"ip route 10.2.0.0/16 tm02c0s0 table 20032",
		"ip route 10.255.255.2/32 tm02c0s0 table 20032",
		"ip route 10.2.0.0/16 tm02c1s0 table 20033",
	} {
		if !strings.Contains(res.Conf, want) {
			t.Errorf("configuration lacks:\n%s\n--- in ---\n%s", want, res.Conf)
		}
	}
	rules := fmt.Sprint(res.Rules)
	if !strings.Contains(rules, "{10500 32 20032}") || !strings.Contains(rules, "{10501 33 20033}") {
		t.Errorf("rules %s", rules)
	}
	// A policy whose color is down falls back to the best path.
	o.Paths = downColor{"inet"}
	res, _ = Render(st, o)
	if !strings.Contains(res.Conf, "ip route 10.2.0.0/16 tm02c1s0 table 20032") {
		t.Errorf("voice with the internet tunnel down:\n%s", res.Conf)
	}
}

type downColor struct{ color string }

func (d downColor) Preferred(string, int, string) string { return "mpls" }
func (d downColor) Down(dev string) bool                 { return strings.Contains(dev, "c0") }

func TestFabricConfigPassesFRRCheck(t *testing.T) {
	if _, err := exec.LookPath("vtysh"); err != nil {
		t.Skip("vtysh is not installed")
	}
	v := &model.VRF{Meta: meta(92, "tenant"), Table: 100, MeshSlot: 1, Networks: []string{"172.16.1.0/24"}}
	pp := &model.PathPolicy{Meta: meta(93, "voice"), Enabled: true, Mark: 0x20, Prefer: "inet"}
	for _, topo := range []struct {
		t  string
		as uint32
	}{{"full_mesh", 65002}, {"hub_spoke", 65001}} {
		st, o := fabricModel(t, topo.t, topo.as, v, pp)
		res, err := Render(st, o)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "frr.conf")
		os.WriteFile(path, []byte(res.Conf), 0o644)
		if out, err := exec.Command("vtysh", "-C", "-f", path).CombinedOutput(); err != nil {
			t.Fatalf("vtysh refuses the %s configuration: %v\n%s\n%s", topo.t, err, out, res.Conf)
		}
	}
}
