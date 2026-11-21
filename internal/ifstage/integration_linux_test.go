package ifstage

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/testnet"
)

// TestInterfacesOnARealKernel: the model configures a dummy device
// (addresses, MTU, link state) and a veth that gets its address from a
// Kea server in another namespace through the DHCP client the stage starts.
// Then it changes and switches them off, and the devices are as before,
// with what Testudo did not do left alone.
//
//	[node] lan ── eth0 dhcp (Kea, 192.168.50.1/24)
//	[node] dum0
func TestInterfacesOnARealKernel(t *testing.T) {
	for _, bin := range []string{"kea-dhcp4", "dhclient"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " is not installed")
		}
	}
	if testnet.Isolate(t) {
		return
	}
	dir := t.TempDir()
	srv := testnet.NewNS(t, "dhcp")
	testnet.Veth(t, "lan", srv, "eth0")
	testnet.Must(t, srv.Do(func() error { return testnet.Addr("eth0", "192.168.50.1/24") }))
	testnet.Must(t, netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "dum0"}}))
	// An address the node had before Testudo; it is never the stage's.
	testnet.Must(t, testnet.Addr("dum0", "10.9.0.99/24"))
	testnet.Must(t, setDown("dum0"))

	keaConf := filepath.Join(dir, "kea-dhcp4.conf")
	testnet.Must(t, os.WriteFile(keaConf, []byte(`{"Dhcp4": {
		"interfaces-config": {"interfaces": ["eth0"]},
		"lease-database": {"type": "memfile", "persist": false},
		"valid-lifetime": 600,
		"subnet4": [{"id": 1, "subnet": "192.168.50.0/24", "pools": [{"pool": "192.168.50.100-192.168.50.150"}],
			"option-data": [{"name": "routers", "data": "192.168.50.1"}]}]}}`), 0o600))
	var kea *exec.Cmd
	testnet.Must(t, srv.Do(func() error {
		kea = exec.Command("kea-dhcp4", "-c", keaConf)
		kea.Env = append(os.Environ(), "KEA_PIDFILE_DIR="+dir, "KEA_LOCKFILE_DIR="+dir)
		log, err := os.Create(filepath.Join(dir, "kea.log"))
		if err != nil {
			return err
		}
		kea.Stdout, kea.Stderr = log, log
		return kea.Start()
	}))
	t.Cleanup(func() { _ = kea.Process.Kill(); _ = kea.Wait() })

	store, err := confstore.Open(filepath.Join(dir, "config"))
	testnet.Must(t, err)
	defer store.Close()
	ctx := context.Background()
	site, err := store.Create(ctx, "t", &model.Site{Meta: model.Meta{Name: "hq"}})
	testnet.Must(t, err)
	node, err := store.Create(ctx, "t", &model.ClusterNode{Meta: model.Meta{Name: "fw1"},
		Site: model.Ref[model.Site]{ID: site.GetMeta().ID}, Hostname: "fw1", Address: "10.255.0.1"})
	testnet.Must(t, err)
	nodeID, siteID := node.GetMeta().ID, site.GetMeta().ID
	set := func(e *model.Interface) {
		t.Helper()
		e.Scope = model.NodeScope(nodeID)
		for _, o := range store.Current().List(model.KindInterface) {
			if o.GetMeta().Name == e.Name {
				e.ID = o.GetMeta().ID
				_, err := store.Update(ctx, "t", e, o.GetMeta().Version)
				testnet.Must(t, err)
				return
			}
		}
		_, err := store.Create(ctx, "t", e)
		testnet.Must(t, err)
	}

	nw := &netops.Writer{AllowWrites: true}
	runDir := "/run/tif-" + fmt.Sprint(os.Getpid())
	stage := func() *Stage {
		return &Stage{Runner: nw, Dir: filepath.Join(dir, "interfaces"), RunDir: runDir,
			Locate: func(*confstore.State) (string, string) { return siteID, nodeID }}
	}
	s := stage()
	t.Cleanup(func() {
		for _, c := range netops.DHCPClients {
			_ = nw.DaemonControl(netops.DaemonRequest{Name: c, Mode: netops.DaemonStop, RunDir: runDir, Interface: "lan"})
		}
	})
	apply := func() {
		t.Helper()
		raw, err := s.Render(store.Current())
		testnet.Must(t, err)
		testnet.Must(t, s.Check(ctx, raw))
		testnet.Must(t, s.Apply(ctx, raw))
		if err := s.Healthy(ctx); err != nil {
			b, _ := os.ReadFile(filepath.Join(dir, "kea.log"))
			t.Fatalf("health: %v\nkea:\n%s", err, b)
		}
	}
	link := func(name string) Link {
		t.Helper()
		l, ok, err := netlinkLinks(name)
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", name, ok, err)
		}
		return l
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			if cond() {
				return
			}
		}
		b, _ := os.ReadFile(filepath.Join(dir, "kea.log"))
		t.Fatalf("%s did not happen\nkea:\n%s", what, b)
	}
	lease := func() string {
		for _, a := range link("lan").Dynamic {
			if strings.HasPrefix(a, "192.168.50.") {
				return a
			}
		}
		return ""
	}

	// Configure.
	set(&model.Interface{Meta: model.Meta{Name: "dum0"}, Device: "dum0", Enabled: true,
		Addresses: []string{"10.9.0.1/24", "2001:db8:9::1/64"}, MTU: 1400})
	set(&model.Interface{Meta: model.Meta{Name: "lan"}, Device: "lan", Enabled: true, DHCP: true})
	apply()
	d := link("dum0")
	if !d.Up || d.MTU != 1400 || !slices.Contains(d.Addresses, "10.9.0.1/24") || !slices.Contains(d.Addresses, "2001:db8:9::1/64") {
		t.Fatalf("dum0 after the apply: %+v", d)
	}
	waitFor("a lease on lan", func() bool { return lease() != "" })

	// Change: another address, the MTU back to the device's, the link down,
	// no DHCP client.
	set(&model.Interface{Meta: model.Meta{Name: "dum0"}, Device: "dum0", Enabled: true,
		Addresses: []string{"10.9.0.2/24"}, Down: true})
	set(&model.Interface{Meta: model.Meta{Name: "lan"}, Device: "lan", Enabled: true, Addresses: []string{"192.168.50.9/24"}})
	apply()
	d = link("dum0")
	if d.Up || d.MTU != 1500 || slices.Contains(d.Addresses, "10.9.0.1/24") || slices.Contains(d.Addresses, "2001:db8:9::1/64") ||
		!slices.Contains(d.Addresses, "10.9.0.2/24") || !slices.Contains(d.Addresses, "10.9.0.99/24") {
		t.Fatalf("dum0 after the change: %+v", d)
	}
	if l := lease(); l != "" {
		t.Errorf("the lease %s stayed after the DHCP client was switched off", l)
	}
	if st, _ := nw.DaemonStateOf(netops.DaemonRequest{Name: "dhclient", RunDir: runDir, Interface: "lan"}); st == "running" {
		t.Error("the DHCP client still runs")
	}
	if !slices.Contains(link("lan").Addresses, "192.168.50.9/24") {
		t.Errorf("lan lacks its static address: %+v", link("lan"))
	}

	// After a restart, switching the interfaces off undoes what the stage
	// did, and only that.
	s = stage()
	set(&model.Interface{Meta: model.Meta{Name: "dum0"}, Device: "dum0", Enabled: false, Addresses: []string{"10.9.0.2/24"}, Down: true})
	set(&model.Interface{Meta: model.Meta{Name: "lan"}, Device: "lan", Enabled: false, Addresses: []string{"192.168.50.9/24"}})
	apply()
	d = link("dum0")
	if !d.Up || slices.Contains(d.Addresses, "10.9.0.2/24") || !slices.Contains(d.Addresses, "10.9.0.99/24") {
		t.Fatalf("dum0 after switching it off: %+v", d)
	}
	if slices.Contains(link("lan").Addresses, "192.168.50.9/24") {
		t.Errorf("lan kept the address the stage gave it: %+v", link("lan"))
	}
}

func setDown(name string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetDown(l)
}

// TestLinksOnARealKernel: bonds, bridges and VLANs of the model on a real
// kernel. A bond of two devices with a VLAN on it that carries an address,
// a bridge with a port; a change of bond mode recreates the bond; a device
// of the same name that Testudo did not make is refused and left alone;
// when the model drops them, the stage's devices go and the members are
// free again.
func TestLinksOnARealKernel(t *testing.T) {
	if testnet.Isolate(t) {
		return
	}
	for _, d := range []string{"m1", "m2", "p1", "busy0"} {
		testnet.Must(t, netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: d}}))
	}
	dir := t.TempDir()
	store, err := confstore.Open(filepath.Join(dir, "config"))
	testnet.Must(t, err)
	defer store.Close()
	ctx := context.Background()
	site, err := store.Create(ctx, "t", &model.Site{Meta: model.Meta{Name: "hq"}})
	testnet.Must(t, err)
	node, err := store.Create(ctx, "t", &model.ClusterNode{Meta: model.Meta{Name: "fw1"},
		Site: model.Ref[model.Site]{ID: site.GetMeta().ID}, Hostname: "fw1", Address: "10.255.0.1"})
	testnet.Must(t, err)
	at := func(name string) model.Meta {
		return model.Meta{Name: name, Scope: model.NodeScope(node.GetMeta().ID)}
	}
	s := &Stage{Runner: &netops.Writer{AllowWrites: true}, Dir: filepath.Join(dir, "interfaces"), RunDir: filepath.Join(dir, "run"),
		Locate: func(*confstore.State) (string, string) { return site.GetMeta().ID, node.GetMeta().ID }}
	apply := func() error {
		t.Helper()
		raw, err := s.Render(store.Current())
		testnet.Must(t, err)
		if err := s.Check(ctx, raw); err != nil {
			return err
		}
		if err := s.Apply(ctx, raw); err != nil {
			return err
		}
		return s.Healthy(ctx)
	}
	kind := func(name string) string {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return ""
		}
		return l.Type()
	}
	master := func(name string) string {
		l, _, _ := netlinkLinks(name)
		return l.Master
	}

	bond, err := store.Create(ctx, "t", &model.Bond{Meta: at("uplink"), Enabled: true, Device: "bond0", Members: []string{"m1", "m2"}, Mode: "active-backup", Primary: "m1"})
	testnet.Must(t, err)
	_, err = store.Create(ctx, "t", &model.VLAN{Meta: at("office"), Enabled: true, Device: "bond0.30", Parent: "bond0", VID: 30})
	testnet.Must(t, err)
	_, err = store.Create(ctx, "t", &model.Bridge{Meta: at("lan"), Enabled: true, Device: "br0", Ports: []string{"p1"}, STP: true})
	testnet.Must(t, err)
	_, err = store.Create(ctx, "t", &model.Interface{Meta: at("office"), Enabled: true, Device: "bond0.30", Addresses: []string{"10.30.0.1/24"}})
	testnet.Must(t, err)
	testnet.Must(t, apply())
	if kind("bond0") != "bond" || kind("bond0.30") != "vlan" || kind("br0") != "bridge" {
		t.Fatalf("devices: bond0=%q bond0.30=%q br0=%q", kind("bond0"), kind("bond0.30"), kind("br0"))
	}
	if master("m1") != "bond0" || master("m2") != "bond0" || master("p1") != "br0" {
		t.Errorf("members: m1=%q m2=%q p1=%q", master("m1"), master("m2"), master("p1"))
	}
	if l, _, _ := netlinkLinks("bond0.30"); !slices.Contains(l.Addresses, "10.30.0.1/24") || !l.Up {
		t.Errorf("bond0.30: %+v", l)
	}
	if stp, err := netops.BridgeSTP("br0"); err != nil || !stp {
		t.Errorf("br0 runs no spanning tree: %v", err)
	}

	// Another mode cannot be set in place: the bond is made anew, with
	// its members and the VLAN on it.
	b := bond.(*model.Bond)
	b.Mode = "balance-xor"
	_, err = store.Update(ctx, "t", b, b.Version)
	testnet.Must(t, err)
	testnet.Must(t, apply())
	if l, _ := netlink.LinkByName("bond0"); l == nil || l.(*netlink.Bond).Mode != netlink.BOND_MODE_BALANCE_XOR {
		t.Errorf("bond0 mode: %v", l)
	}
	if master("m1") != "bond0" || kind("bond0.30") != "vlan" {
		t.Errorf("after the mode change: m1 in %q, bond0.30 %q", master("m1"), kind("bond0.30"))
	}

	// A device the node had before is not Testudo's to take.
	_, err = store.Create(ctx, "t", &model.Bond{Meta: at("taken"), Enabled: true, Device: "busy0", Members: []string{"m3"}, Mode: "active-backup"})
	testnet.Must(t, err)
	if err := apply(); err == nil || !strings.Contains(err.Error(), "not made by Testudo") {
		t.Errorf("a foreign device was taken: %v", err)
	}
	if kind("busy0") != "dummy" {
		t.Errorf("busy0 was changed: %q", kind("busy0"))
	}

	// All of it leaves the model.
	for _, k := range []model.Kind{model.KindInterface, model.KindVLAN, model.KindBridge, model.KindBond} {
		for _, o := range store.Current().List(k) {
			testnet.Must(t, store.Delete(ctx, "t", k, o.GetMeta().ID, o.GetMeta().Version))
		}
	}
	testnet.Must(t, apply())
	for _, d := range []string{"bond0", "bond0.30", "br0"} {
		if kind(d) != "" {
			t.Errorf("%s stayed", d)
		}
	}
	for _, d := range []string{"m1", "m2", "p1", "busy0"} {
		if kind(d) != "dummy" || master(d) != "" {
			t.Errorf("%s: kind %q, master %q", d, kind(d), master(d))
		}
	}
}
