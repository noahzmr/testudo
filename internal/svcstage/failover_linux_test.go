//go:build linux

package svcstage

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/svcrender"
	"github.com/noahzmr/testudo/internal/testnet"
)

// TestDHCPFailoverOnARealKernel: the two nodes of an HA pair run their
// DHCP servers hot-standby over the sync link. A client leases from the
// primary; the standby learns the lease. The primary's server dies; the
// standby takes over and the client keeps its address.
//
//	client --br-lan-- r1 lan 192.168.1.2 | r2 lan 192.168.1.3
//	                  r1 sync0 10.9.9.1 --br-sync-- 10.9.9.2 r2 sync0
func TestDHCPFailoverOnARealKernel(t *testing.T) {
	for _, bin := range []string{"kea-dhcp4", "dhclient"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " is not installed")
		}
	}
	hooks := hooksDir(t)
	if testnet.Isolate(t) {
		return
	}
	sh := func(script string) {
		t.Helper()
		if out, err := exec.Command("sh", "-ec", script).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", script, err, out)
		}
	}
	in := func(ns *testnet.NS, script string) (string, error) {
		var out []byte
		err := ns.Do(func() error {
			var err error
			out, err = exec.Command("sh", "-c", script).CombinedOutput()
			return err
		})
		return string(out), err
	}
	client, r1, r2 := testnet.NewNS(t, "client"), testnet.NewNS(t, "r1"), testnet.NewNS(t, "r2")
	sh("ip link add br-lan type bridge && ip link add br-sync type bridge && ip link set br-lan up && ip link set br-sync up")
	t.Cleanup(func() { exec.Command("sh", "-c", "ip link del br-lan; ip link del br-sync").Run() })
	attach := func(root string, ns *testnet.NS, name, bridge string) {
		testnet.Veth(t, root, ns, name)
		sh("ip link set " + root + " master " + bridge)
	}
	attach("hc", client, "eth0", "br-lan")
	attach("h1l", r1, "lan", "br-lan")
	attach("h2l", r2, "lan", "br-lan")
	attach("h1s", r1, "sync0", "br-sync")
	attach("h2s", r2, "sync0", "br-sync")
	for i, r := range []*testnet.NS{r1, r2} {
		if out, err := in(r, fmt.Sprintf(`set -e; ip link set lo up; ip link set lan up; ip link set sync0 up
			ip addr add 192.168.1.%d/24 dev lan; ip addr add 10.9.9.%d/24 dev sync0`, i+2, i+1)); err != nil {
			t.Fatal(out)
		}
	}
	if out, err := in(client, "ip link set lo up; ip link set eth0 up"); err != nil {
		t.Fatal(out)
	}

	dir := t.TempDir()
	store, err := confstore.Open(filepath.Join(dir, "config"))
	testnet.Must(t, err)
	defer store.Close()
	atSite := func(m model.Meta) model.Meta { m.Scope = model.SiteScope(id(1)); return m }
	site := model.Ref[model.Site]{ID: id(1)}
	for _, e := range []model.Entity{
		&model.Site{Meta: meta(1, "hq")},
		&model.ClusterNode{Meta: meta(2, "r1"), Site: site, Hostname: "r1", Address: "192.168.1.2", SyncAddress: "10.9.9.1"},
		&model.ClusterNode{Meta: meta(3, "r2"), Site: site, Hostname: "r2", Address: "192.168.1.3", SyncAddress: "10.9.9.2"},
		&model.HAPair{Meta: atSite(meta(4, "edge")), Enabled: true, SyncInterface: "sync0",
			Nodes:     []model.Ref[model.ClusterNode]{{ID: id(2)}, {ID: id(3)}},
			Instances: []model.VRRPInstance{{Interface: "lan", VRID: 7, VirtualIPs: []string{"192.168.1.1/24"}}}},
		&model.DHCPScope{Meta: atSite(meta(30, "lan4")), Enabled: true, Interface: "lan", Subnet: "192.168.1.0/24",
			Pools: []string{"192.168.1.100-192.168.1.150"}, LeaseSeconds: 600},
	} {
		if _, err := store.Create(context.Background(), "test", e); err != nil {
			t.Fatalf("create %s: %v", e.GetMeta().Name, err)
		}
	}
	nw := &netops.Writer{AllowWrites: true}
	ctx := context.Background()
	stages := map[*testnet.NS]*Stage{}
	for i, r := range []*testnet.NS{r1, r2} {
		node := id(i + 2)
		s := &Stage{Runner: nw, Dir: filepath.Join(dir, fmt.Sprintf("svc-r%d", i+1)), RunDir: fmt.Sprintf("/run/tsvc-r%d", i+1), HooksDir: hooks,
			Locate: func(*confstore.State) (string, string) { return id(1), node }}
		stages[r] = s
		raw, err := s.Render(store.Current())
		testnet.Must(t, err)
		// Kea's check looks for the interfaces: it runs where they are.
		testnet.Must(t, r.Do(func() error { return s.Check(ctx, raw) }))
		testnet.Must(t, r.Do(func() error { return s.Apply(ctx, raw) }))
		t.Cleanup(func() {
			nw.DaemonControl(netops.DaemonRequest{Name: svcrender.DaemonKea4, Mode: netops.DaemonStop, RunDir: s.RunDir})
		})
	}
	logs := func() {
		for name, r := range map[string]*testnet.NS{"r1": r1, "r2": r2} {
			out, _ := exec.Command("tail", "-25", filepath.Join(stages[r].Dir, "kea-dhcp4.log")).CombinedOutput()
			t.Logf("%s kea-dhcp4.log:\n%s", name, out)
		}
	}
	for _, r := range []*testnet.NS{r1, r2} {
		if err := stages[r].Healthy(ctx); err != nil {
			logs()
			t.Fatal(err)
		}
	}
	// The partners find each other.
	time.Sleep(5 * time.Second)

	testnet.Must(t, writeFile("/etc/dhcp/dhclient.conf", "send host-name \"laptop\";\n"))
	lease := func(what string) (addr, server string) {
		t.Helper()
		out, err := in(client, "timeout 40 dhclient -4 -1 -v -cf /etc/dhcp/dhclient.conf -lf /var/lib/dhcp/dhclient-fo.leases -pf /run/dhclient-fo.pid eth0 2>&1; dhclient -x -pf /run/dhclient-fo.pid >/dev/null 2>&1")
		m := regexp.MustCompile(`DHCPACK of (\S+) from (\S+)`).FindAllStringSubmatch(out, -1)
		if err != nil || m == nil {
			logs()
			t.Fatalf("%s: no lease: %v\n%s", what, err, out)
		}
		return m[len(m)-1][1], m[len(m)-1][2]
	}
	addr, server := lease("first lease")
	if server != "192.168.1.2" {
		t.Errorf("the first lease came from %s, not the primary", server)
	}
	// The standby knows the lease.
	var known bool
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline) && !known; time.Sleep(300 * time.Millisecond) {
		leases, _ := Leases(ctx, stages[r2].RunDir, false)
		for _, l := range leases {
			known = known || (l.Address == addr && l.Hostname == "laptop")
		}
	}
	if !known {
		logs()
		t.Fatalf("the standby never learned the lease of %s", addr)
	}

	// The primary's server dies; the standby waits out the delay and takes over.
	testnet.Must(t, r1.Do(func() error {
		return nw.DaemonControl(netops.DaemonRequest{Name: svcrender.DaemonKea4, Mode: netops.DaemonStop, RunDir: stages[r1].RunDir})
	}))
	time.Sleep(9 * time.Second)
	again, server := lease("after the failover")
	if again != addr || server != "192.168.1.3" {
		logs()
		t.Fatalf("after the failover: %s from %s, want %s from the standby", again, server, addr)
	}
	if !strings.Contains(addr, "192.168.1.") {
		t.Fatal(addr)
	}
}

func writeFile(path, body string) error {
	return exec.Command("sh", "-c", "mkdir -p /etc/dhcp && cat > "+path+" <<'EOF'\n"+body+"EOF").Run()
}
