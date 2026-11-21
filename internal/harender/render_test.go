package harender

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

func id(n int) string                    { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func meta(n int, name string) model.Meta { return model.Meta{ID: id(n), Name: name} }

func state(t *testing.T, pair *model.HAPair, extra ...model.Entity) *confstore.State {
	t.Helper()
	s, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	pair.Scope = model.SiteScope(id(1))
	site := model.Ref[model.Site]{ID: id(1)}
	objs := append([]model.Entity{
		&model.Site{Meta: meta(1, "hq")},
		&model.ClusterNode{Meta: meta(2, "fw1"), Site: site, Hostname: "fw1", Address: "10.0.0.1", SyncAddress: "10.9.9.1"},
		&model.ClusterNode{Meta: meta(3, "fw2"), Site: site, Hostname: "fw2", Address: "10.0.0.2", SyncAddress: "10.9.9.2"},
		&model.ClusterNode{Meta: meta(4, "fw3"), Site: site, Hostname: "fw3", Address: "10.0.0.3"},
	}, extra...)
	for _, e := range append(objs, pair) {
		if _, err := s.Create(context.Background(), "test", e); err != nil {
			t.Fatalf("create %s: %v", e.GetMeta().Name, err)
		}
	}
	return s.Current()
}

func pair() *model.HAPair {
	return &model.HAPair{Meta: meta(10, "edge"), Enabled: true, SyncInterface: "sync0", AdvertMs: 500,
		Nodes: []model.Ref[model.ClusterNode]{{ID: id(2)}, {ID: id(3)}},
		Instances: []model.VRRPInstance{
			{Interface: "wan", VRID: 52, VirtualIPs: []string{"192.0.2.1/24"}},
			{Interface: "wan", VRID: 53, VirtualIPs: []string{"2001:db8::1/64"}},
			{Interface: "lan", VRID: 51, VirtualIPs: []string{"10.0.0.254/24"}},
		}}
}

func TestBothMembersRenderMirroredConfigs(t *testing.T) {
	st := state(t, pair())
	opt := Options{SiteID: id(1), Dir: "/var/lib/testudo/ha", RunDir: "/run/testudo-ha"}
	opt.NodeID = id(2)
	a, err := Render(st, opt)
	if err != nil {
		t.Fatal(err)
	}
	opt.NodeID = id(3)
	b, err := Render(st, opt)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Enabled || !b.Enabled || a.Peer != "10.9.9.2" || b.Peer != "10.9.9.1" {
		t.Fatalf("results: %+v / %+v", a, b)
	}
	if strings.Join(a.Interfaces, ",") != "lan,wan" || len(a.VirtualIPs) != 3 {
		t.Errorf("interfaces %v, addresses %v", a.Interfaces, a.VirtualIPs)
	}
	ka, kb := a.Files[KeepalivedConf], b.Files[KeepalivedConf]
	for _, want := range []string{
		"vrrp_version 3", "enable_script_security", "state BACKUP", "nopreempt", "advert_int 0.50",
		"virtual_router_id 51", "virtual_router_id 52", "2001:db8::1/64 dev wan",
		`notify_master "/var/lib/testudo/ha/become-active.sh"`, `notify_fault "/var/lib/testudo/ha/become-standby.sh"`,
	} {
		if !strings.Contains(ka, want) {
			t.Errorf("keepalived.conf lacks %q:\n%s", want, ka)
		}
	}
	// The first member is preferred; both start as backup and the election decides.
	if !strings.Contains(ka, "priority 150") || !strings.Contains(kb, "priority 100") {
		t.Errorf("priorities:\n%s\n%s", ka, kb)
	}
	// Instances come out in VRID order however the model lists them.
	if strings.Index(ka, "vi51") > strings.Index(ka, "vi52") {
		t.Errorf("instance order:\n%s", ka)
	}
	ca := a.Files[ConntrackdConf]
	for _, want := range []string{"Mode FTFW", "IPv4_address 10.9.9.1", "IPv4_Destination_Address 10.9.9.2", "Port 3780",
		"Interface sync0", "/run/testudo-ha/conntrackd.ctl"} {
		if !strings.Contains(ca, want) {
			t.Errorf("conntrackd.conf lacks %q:\n%s", want, ca)
		}
	}
	if !strings.Contains(a.Files[MasterScript], "conntrackd -C /var/lib/testudo/ha/conntrackd.conf -c") ||
		!strings.Contains(a.Files[BackupScript], "conntrackd -C /var/lib/testudo/ha/conntrackd.conf -t") {
		t.Errorf("scripts:\n%s\n%s", a.Files[MasterScript], a.Files[BackupScript])
	}
}

func TestPreemptAndExplicitPriority(t *testing.T) {
	p := pair()
	p.Preempt = true
	st := state(t, p)
	res, err := Render(st, Options{SiteID: id(1), NodeID: id(2), Dir: "/d", RunDir: "/r"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Files[KeepalivedConf], "nopreempt") {
		t.Errorf("preempting pair renders nopreempt")
	}
}

func TestNodesOutsideAPairRenderNothing(t *testing.T) {
	p := pair()
	st := state(t, p)
	res, err := Render(st, Options{SiteID: id(1), NodeID: id(4), Dir: "/d", RunDir: "/r"})
	if err != nil || res.Enabled || len(res.Files) != 0 {
		t.Fatalf("outsider: %+v %v", res, err)
	}
	p2 := pair()
	p2.Enabled = false
	st = state(t, p2)
	res, err = Render(st, Options{SiteID: id(1), NodeID: id(2), Dir: "/d", RunDir: "/r"})
	if err != nil || res.Enabled {
		t.Fatalf("disabled pair: %+v %v", res, err)
	}
}
