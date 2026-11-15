//go:build linux

package frrstage

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/frrender"
	"github.com/noahzmr/testudo/internal/gwmon"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/testnet"
)

var (
	_ confapply.Stage    = (*Stage)(nil)
	_ confapply.Redactor = (*Stage)(nil)
	_ Runner             = (*netops.Writer)(nil)
)

var ctx = context.Background()

func id(n int) string                    { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func meta(n int, name string) model.Meta { return model.Meta{ID: id(n), Name: name} }

const siteN, nodeN = 1, 2

func sh(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// eventually waits for cond; routing daemons install routes asynchronously.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Errorf("timed out waiting for: %s", what)
}

// TestRoutingOnARealKernel runs FRR in a private namespace and checks what
// ends up in the kernel: static and policy routes, VRF devices, gateway
// failover driven by the monitor, and a BGP session with a second router.
//
//	ispA 10.1.0.1 --- wan0 [router] wan1 --- ispB 10.2.0.1
func TestRoutingOnARealKernel(t *testing.T) {
	if _, err := exec.LookPath("vtysh"); err != nil {
		t.Skip("FRR is not installed")
	}
	if testnet.Isolate(t) {
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root to run the routing daemons")
	}
	ispA, ispB := testnet.NewNS(t, "ispA"), testnet.NewNS(t, "ispB")
	testnet.Veth(t, "wan0", ispA, "eth0")
	testnet.Veth(t, "wan1", ispB, "eth0")
	testnet.Must(t, testnet.Addr("wan0", "10.1.0.2/24"))
	testnet.Must(t, testnet.Addr("wan1", "10.2.0.2/24"))
	testnet.Must(t, ispA.Do(func() error { return testnet.Addr("eth0", "10.1.0.1/24") }))
	testnet.Must(t, ispB.Do(func() error { return testnet.Addr("eth0", "10.2.0.1/24") }))
	// The gateway monitor pings without privileges, which a fresh network
	// namespace does not allow until this range is opened (a normal system
	// has it open).
	testnet.Must(t, testnet.Sysctl("net/ipv4/ping_group_range", "0 2147483647"))
	sh(t, "ip", "link", "add", "tenant0", "type", "dummy")
	sh(t, "ip", "link", "set", "tenant0", "up")

	// The router's FRR, with the daemons this test needs. The daemons must
	// not inherit this process's output, or whoever waits for it would wait
	// for them too.
	quiet := func(name string, args ...string) {
		t.Helper()
		c, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := exec.CommandContext(c, name, args...).Run(); err != nil {
			t.Fatalf("%s %s: %v", name, strings.Join(args, " "), err)
		}
	}
	daemons, _ := os.ReadFile("/etc/frr/daemons")
	conf := strings.NewReplacer("bgpd=no", "bgpd=yes", "bfdd=no", "bfdd=yes").Replace(string(daemons))
	testnet.Must(t, os.WriteFile("/etc/frr/daemons", []byte(conf), 0o640))
	quiet("/usr/lib/frr/frrinit.sh", "start")
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		exec.CommandContext(c, "/usr/lib/frr/frrinit.sh", "stop").Run()
	})

	// A second router in ispA: AS 64500, announcing 203.0.113.0/24.
	peer := &bgpPeer{as: 64500, routerID: net.ParseIP("10.1.0.1"), nextHop: net.ParseIP("10.1.0.1"),
		announce: &net.IPNet{IP: net.ParseIP("203.0.113.0"), Mask: net.CIDRMask(24, 32)}}
	var ln net.Listener
	testnet.Must(t, ispA.Do(func() error {
		var err error
		ln, err = net.Listen("tcp", "10.1.0.1:179")
		return err
	}))
	t.Cleanup(func() { ln.Close() })
	go peer.listen(ln)

	dir := t.TempDir()
	nw := &netops.Writer{AllowWrites: true}
	if !nw.FrrAvailable() {
		t.Fatal("FRR is not reachable")
	}
	mon := &gwmon.Monitor{}
	locate := func(*confstore.State) (string, string) { return id(siteN), id(nodeN) }
	stage := &Stage{Runner: nw, Locate: locate, Down: mon.Down, StateDir: dir}
	store, err := confstore.Open(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	eng, err := confapply.New(store, confapply.Options{Dir: dir, Window: time.Minute}, stage)
	if err != nil {
		t.Fatal(err)
	}
	// An empty model must not touch a routing daemon it does not manage.
	before := sh(t, "vtysh", "-c", "show running-config")
	if err := eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if after := sh(t, "vtysh", "-c", "show running-config"); after != before {
		t.Fatalf("an empty model changed the routing daemon's configuration:\n%s", after)
	}

	nodeMeta := func(n int, name string) model.Meta {
		m := meta(n, name)
		m.Scope = model.NodeScope(id(nodeN))
		return m
	}
	ifc := func(n int) model.Ref[model.Interface] { return model.Ref[model.Interface]{ID: id(n)} }
	objs := []model.Entity{
		&model.Site{Meta: meta(siteN, "hq")},
		&model.ClusterNode{Meta: meta(nodeN, "fw1"), Site: model.Ref[model.Site]{ID: id(siteN)}, Hostname: "fw1", Address: "10.1.0.2"},
		&model.VRF{Meta: meta(5, "blue"), Table: 100},
		&model.Interface{Meta: nodeMeta(10, "wan0"), Device: "wan0", Enabled: true},
		&model.Interface{Meta: nodeMeta(11, "wan1"), Device: "wan1", Enabled: true},
		&model.Interface{Meta: nodeMeta(12, "tenant0"), Device: "tenant0", Enabled: true, VRF: model.Ref[model.VRF]{ID: id(5)}},
		&model.Gateway{Meta: nodeMeta(20, "isp-a"), Enabled: true, Interface: ifc(10), Address: "10.1.0.1", Group: "wan", Priority: 1, Monitor: "10.1.0.1"},
		&model.Gateway{Meta: nodeMeta(21, "isp-b"), Enabled: true, Interface: ifc(11), Address: "10.2.0.1", Group: "wan", Priority: 2, Monitor: "10.2.0.1"},
		&model.Route{Meta: meta(30, "default"), Enabled: true, Destination: "0.0.0.0/0", GatewayGroup: "wan"},
		&model.Route{Meta: meta(31, "dc"), Enabled: true, Destination: "10.20.0.0/16", Gateway: model.Ref[model.Gateway]{ID: id(21)}},
		&model.PolicyRoute{Meta: meta(40, "voip-via-b"), Enabled: true, Mark: 0x10, Gateway: model.Ref[model.Gateway]{ID: id(21)}},
		&model.BGPNeighbor{Meta: func() model.Meta { m := meta(50, "transit"); m.Scope = model.SiteScope(id(siteN)); return m }(),
			Enabled: true, LocalAS: 65001, RemoteAS: 64500, Address: "10.1.0.1", SessionSecret: "",
			PrefixListIn: []string{"203.0.113.0/24"}, Announce: []string{"10.20.0.0/16"}},
	}
	var ops []confstore.Op
	for _, e := range objs {
		obj, _ := json.Marshal(e)
		ops = append(ops, confstore.Op{Type: confstore.OpCreate, Kind: e.Kind(), ID: e.GetMeta().ID, Object: obj})
	}
	if _, err := eng.Apply(ctx, "test", "routing", ops); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := eng.Confirm("test"); err != nil {
		t.Fatal(err)
	}
	route := func(args ...string) string {
		out, _ := exec.Command("ip", append([]string{"route", "show"}, args...)...).CombinedOutput()
		return string(out)
	}

	// Static routes, the policy table and its rule, and the VRF device.
	eventually(t, "default route via the preferred gateway", func() bool { return strings.Contains(route("default"), "via 10.1.0.1 dev wan0") })
	eventually(t, "static route", func() bool { return strings.Contains(route("10.20.0.0/16"), "via 10.2.0.1 dev wan1") })
	table := fmt.Sprint(20000 + 0x10)
	eventually(t, "default route in the policy table", func() bool { return strings.Contains(route("table", table), "via 10.2.0.1 dev wan1") })
	if rules := sh(t, "ip", "rule", "show"); !strings.Contains(rules, "fwmark 0x10 lookup "+table) {
		t.Errorf("policy rule missing:\n%s", rules)
	}
	if link := sh(t, "ip", "-d", "link", "show", "tenant0"); !strings.Contains(link, "master blue") {
		t.Errorf("tenant0 is not in VRF blue:\n%s", link)
	}
	if link := sh(t, "ip", "-d", "link", "show", "blue"); !strings.Contains(link, "vrf table 100") {
		t.Errorf("VRF device:\n%s", link)
	}

	// BGP: the session comes up, the announced prefix is installed, and the
	// peer receives ours.
	eventually(t, "BGP route from the peer in the kernel", func() bool { return strings.Contains(route("203.0.113.0/24"), "via 10.1.0.1") })
	if out, err := nw.FrrShow("bgp"); err != nil || !strings.Contains(out, `"state":"Established"`) {
		t.Errorf("BGP session state: %v\n%s", err, out)
	}
	eventually(t, "our prefix at the peer", func() bool { return peer.got("10.20.0.0/16") })
	if err := stage.Healthy(ctx); err != nil {
		t.Errorf("healthy: %v", err)
	}

	// Failover: the preferred uplink stops answering. After three failed
	// probes the default route moves; after three good ones it moves back.
	gateways := func() []*model.Gateway {
		return frrender.Gateways(store.Current(), frrender.Options{SiteID: id(siteN), NodeID: id(nodeN)})
	}
	rounds := func(n int) bool {
		changed := false
		for i := 0; i < n; i++ {
			changed = mon.Check(ctx, gateways(), time.Now()) || changed
		}
		return changed
	}
	if rounds(gwmon.Threshold) {
		t.Errorf("healthy gateways changed state: %+v", mon.Status())
	}
	testnet.Must(t, ispA.Do(func() error { return exec.Command("ip", "link", "set", "eth0", "down").Run() }))
	if !rounds(gwmon.Threshold) || !mon.Down()[id(20)] {
		t.Fatalf("the monitor did not notice the dead uplink: %+v", mon.Status())
	}
	if err := stage.Refresh(ctx, store.Current()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "default route via the backup gateway", func() bool {
		r := route("default")
		return strings.Contains(r, "via 10.2.0.1 dev wan1") && !strings.Contains(r, "10.1.0.1")
	})
	testnet.Must(t, ispA.Do(func() error { return exec.Command("ip", "link", "set", "eth0", "up").Run() }))
	eventually(t, "the uplink answering again", func() bool { ok, _ := gwmon.Ping(ctx, "10.1.0.1"); return ok })
	if !rounds(gwmon.Threshold) || mon.Down()[id(20)] {
		t.Fatalf("the monitor did not notice the recovery: %+v", mon.Status())
	}
	if err := stage.Refresh(ctx, store.Current()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "default route back on the preferred gateway", func() bool { return strings.Contains(route("default"), "via 10.1.0.1 dev wan0") })

	// Removing the routing objects removes what was installed.
	var del []confstore.Op
	for _, n := range []int{30, 31, 40, 50} {
		for _, kind := range []model.Kind{model.KindRoute, model.KindPolicyRoute, model.KindBGPNeighbor} {
			if e, ok := store.Current().Get(kind, id(n)); ok {
				del = append(del, confstore.Op{Type: confstore.OpDelete, Kind: kind, ID: id(n), IfMatch: e.GetMeta().Version})
			}
		}
	}
	if _, err := eng.Apply(ctx, "test", "remove", del); err != nil {
		t.Fatalf("remove: %v", err)
	}
	eng.Confirm("test")
	eventually(t, "routes gone", func() bool {
		return !strings.Contains(route("default"), "10.1.0.1") && route("10.20.0.0/16") == "" && route("203.0.113.0/24") == ""
	})
	if rules := sh(t, "ip", "rule", "show"); strings.Contains(rules, "fwmark 0x10") {
		t.Errorf("policy rule left behind:\n%s", rules)
	}
	if t.Failed() {
		t.Logf("running-config:\n%s", sh(t, "vtysh", "-c", "show running-config"))
	}
}
