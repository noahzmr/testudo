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

// TestPPPoEOnARealKernel: a PPPoE link of the model dials a PPPoE server in
// another namespace: ppp0 comes up with the address the server hands out,
// and goes when the link leaves the model.
//
//	[node] wan ── eth0 isp (pppoe-server, 10.64.0.1)
func TestPPPoEOnARealKernel(t *testing.T) {
	for _, bin := range []string{"pppd", "pppoe-server"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " is not installed")
		}
	}
	if testnet.Isolate(t) {
		return
	}
	isp := testnet.NewNS(t, "isp")
	testnet.Veth(t, "wan", isp, "eth0")
	testnet.Must(t, os.MkdirAll("/etc/ppp", 0o755))
	testnet.Must(t, os.WriteFile("/etc/ppp/pap-secrets", []byte("\"alice\" * \"s3cret\" *\n"), 0o600))
	testnet.Must(t, os.WriteFile("/etc/ppp/pppoe-server-options", []byte("require-pap\nlcp-echo-interval 5\nlcp-echo-failure 3\n"), 0o644))
	var srv *exec.Cmd
	testnet.Must(t, isp.Do(func() error {
		srv = exec.Command("pppoe-server", "-F", "-I", "eth0", "-L", "10.64.0.1", "-R", "10.64.0.100", "-N", "4")
		return srv.Start()
	}))
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })

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
	link, err := store.Create(ctx, "t", &model.PPPoE{Meta: model.Meta{Name: "isp", Scope: model.NodeScope(node.GetMeta().ID)},
		Enabled: true, Device: "ppp0", Parent: "wan", Username: "alice", Password: "s3cret"})
	testnet.Must(t, err)
	nw := &netops.Writer{AllowWrites: true}
	s := &Stage{Runner: nw, Dir: filepath.Join(dir, "interfaces"), RunDir: filepath.Join(dir, "run"),
		Locate: func(*confstore.State) (string, string) { return site.GetMeta().ID, node.GetMeta().ID }}
	t.Cleanup(func() { _ = nw.DaemonControl(s.pppRequest("ppp0", netops.DaemonStop)) })
	apply := func() {
		t.Helper()
		raw, err := s.Render(store.Current())
		testnet.Must(t, err)
		testnet.Must(t, s.Check(ctx, raw))
		testnet.Must(t, s.Apply(ctx, raw))
		testnet.Must(t, s.Healthy(ctx))
	}
	apply()
	var l Link
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if l, _, _ = netlinkLinks("ppp0"); slices.Contains(l.Addresses, "10.64.0.100/32") {
			break
		}
	}
	if !slices.Contains(l.Addresses, "10.64.0.100/32") {
		t.Fatalf("ppp0 did not come up with the server's address: %+v", l)
	}

	testnet.Must(t, store.Delete(ctx, "t", model.KindPPPoE, link.GetMeta().ID, link.GetMeta().Version))
	apply()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if _, ok, _ := netlinkLinks("ppp0"); !ok {
			return
		}
	}
	t.Error("ppp0 stayed after the link left the model")
}

// TestPrefixDelegationOnARealKernel: the provider (Kea and radvd in
// another namespace) delegates a /56; the node's DHCPv6 client gets an
// address on the upstream interface and gives the LAN devices the /64s
// the model names, and takes them back when the client leaves the model.
//
//	[node] wan ── eth0 isp (Kea DHCPv6, radvd)
//	[node] lan0, lan1
func TestPrefixDelegationOnARealKernel(t *testing.T) {
	for _, bin := range []string{"dhcpcd", "kea-dhcp6", "radvd"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " is not installed")
		}
	}
	if testnet.Isolate(t) {
		return
	}
	run := func(script string) {
		t.Helper()
		if out, err := exec.Command("sh", "-ec", script).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", script, err, out)
		}
	}
	isp := testnet.NewNS(t, "isp")
	run("ip link set lo up && sysctl -qw net.ipv6.conf.default.accept_dad=0 net.ipv6.conf.all.accept_dad=0")
	testnet.Veth(t, "wan", isp, "eth0")
	run("ip link add lan0 type dummy && ip link add lan1 type dummy && ip link set lan0 up && ip link set lan1 up")
	dir := t.TempDir()
	keaConf := filepath.Join(dir, "kea-dhcp6.conf")
	// The link-local address of eth0 is still tentative when Kea starts;
	// Kea waits for it, as the one Testudo renders does.
	testnet.Must(t, os.WriteFile(keaConf, []byte(`{"Dhcp6": {
		"interfaces-config": {"interfaces": ["eth0"], "service-sockets-max-retries": 30, "service-sockets-retry-wait-time": 500},
		"lease-database": {"type": "memfile", "persist": false},
		"server-id": {"type": "LL", "persist": false},
		"subnet6": [{"id": 1, "subnet": "2001:db8:1::/64", "interface": "eth0",
			"pools": [{"pool": "2001:db8:1::100-2001:db8:1::1ff"}],
			"pd-pools": [{"prefix": "2001:db8:100::", "prefix-len": 48, "delegated-len": 56}]}]}}`), 0o600))
	radvdConf := filepath.Join(dir, "radvd.conf")
	testnet.Must(t, os.WriteFile(radvdConf, []byte("interface eth0 {\n AdvSendAdvert on;\n MinRtrAdvInterval 3;\n MaxRtrAdvInterval 5;\n AdvManagedFlag on;\n AdvOtherConfigFlag on;\n prefix 2001:db8:1::/64 { AdvAutonomous off; };\n};\n"), 0o644))
	var procs []*exec.Cmd
	testnet.Must(t, isp.Do(func() error {
		if out, err := exec.Command("sh", "-ec", "sysctl -qw net.ipv6.conf.all.forwarding=1 net.ipv6.conf.eth0.accept_dad=0; ip addr add 2001:db8:1::1/64 dev eth0 nodad").CombinedOutput(); err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		kea := exec.Command("kea-dhcp6", "-c", keaConf)
		kea.Env = append(os.Environ(), "KEA_PIDFILE_DIR="+dir, "KEA_LOCKFILE_DIR="+dir)
		klog, err := os.Create(filepath.Join(dir, "kea6.log"))
		if err != nil {
			return err
		}
		kea.Stdout, kea.Stderr = klog, klog
		radvd := exec.Command("radvd", "-n", "-m", "stderr", "-u", "root", "-p", filepath.Join(dir, "radvd.pid"), "-C", radvdConf)
		for _, c := range []*exec.Cmd{kea, radvd} {
			if err := c.Start(); err != nil {
				return err
			}
			procs = append(procs, c)
		}
		return nil
	}))
	t.Cleanup(func() {
		for _, c := range procs {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
	})

	store, err := confstore.Open(filepath.Join(dir, "config"))
	testnet.Must(t, err)
	defer store.Close()
	ctx := context.Background()
	site, err := store.Create(ctx, "t", &model.Site{Meta: model.Meta{Name: "hq"}})
	testnet.Must(t, err)
	node, err := store.Create(ctx, "t", &model.ClusterNode{Meta: model.Meta{Name: "fw1"},
		Site: model.Ref[model.Site]{ID: site.GetMeta().ID}, Hostname: "fw1", Address: "10.255.0.1"})
	testnet.Must(t, err)
	client, err := store.Create(ctx, "t", &model.DHCPv6Client{Meta: model.Meta{Name: "isp", Scope: model.NodeScope(node.GetMeta().ID)},
		Enabled: true, Interface: "wan", Address: true, PrefixLength: 56,
		Delegate: []model.PrefixAssignment{{Interface: "lan0", SubnetID: 1}, {Interface: "lan1", SubnetID: 2}}})
	testnet.Must(t, err)
	nw := &netops.Writer{AllowWrites: true}
	s := &Stage{Runner: nw, Dir: filepath.Join(dir, "interfaces"), RunDir: filepath.Join(dir, "run"),
		Locate: func(*confstore.State) (string, string) { return site.GetMeta().ID, node.GetMeta().ID }}
	t.Cleanup(func() { _ = nw.DaemonControl(s.request(dhcpcd6, "wan", netops.DaemonStop)) })
	apply := func() {
		t.Helper()
		raw, err := s.Render(store.Current())
		testnet.Must(t, err)
		testnet.Must(t, s.Check(ctx, raw))
		testnet.Must(t, s.Apply(ctx, raw))
		testnet.Must(t, s.Healthy(ctx))
	}
	global := func(dev, within string) string {
		l, _, _ := netlinkLinks(dev)
		for _, a := range l.Addresses {
			if strings.HasPrefix(a, within) {
				return a
			}
		}
		return ""
	}
	apply()
	var lan0, lan1, wan string
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		lan0, lan1, wan = global("lan0", "2001:db8:100:"), global("lan1", "2001:db8:100:"), global("wan", "2001:db8:1::")
		if lan0 != "" && lan1 != "" && wan != "" {
			break
		}
	}
	if lan0 == "" || lan1 == "" || wan == "" {
		klog, _ := os.ReadFile(filepath.Join(dir, "kea6.log"))
		t.Fatalf("after the delegation: wan %q, lan0 %q, lan1 %q\nkea:\n%s", wan, lan0, lan1, klog)
	}
	if !strings.HasSuffix(lan0, "/64") || !strings.HasSuffix(lan1, "/64") || lan0[:17] == lan1[:17] {
		t.Errorf("lan0 %s and lan1 %s should be two /64s of the prefix", lan0, lan1)
	}

	testnet.Must(t, store.Delete(ctx, "t", model.KindDHCPv6Client, client.GetMeta().ID, client.GetMeta().Version))
	apply()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(250 * time.Millisecond) {
		if global("lan0", "2001:db8:100:") == "" {
			return
		}
	}
	t.Errorf("lan0 kept %s after the client left the model", global("lan0", "2001:db8:100:"))
}
