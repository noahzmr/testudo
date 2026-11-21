//go:build linux

package hastage

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/testnet"
)

var _ confapply.Stage = (*Stage)(nil)

func id(n int) string                    { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func meta(n int, name string) model.Meta { return model.Meta{ID: id(n), Name: name} }

// TestPairOnARealKernel: two routers in front of a LAN, both with a strict
// stateful firewall (only established connections or new SYNs pass). The
// pair is applied from the model. A connection runs through the active
// router; the active router fails. The standby takes the addresses over
// and, because conntrackd gave it the connection, the connection goes on.
//
//	client 10.0.0.10 --br-lan-- r1 / r2 (VIP 10.0.0.1 | 192.0.2.1) --br-wan-- server 192.0.2.10
//	                             r1 sync0 10.9.9.1 ---- 10.9.9.2 r2 sync0
func TestPairOnARealKernel(t *testing.T) {
	for _, bin := range []string{"keepalived", "conntrackd", "nft"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip(bin + " is not installed")
		}
	}
	if testnet.Isolate(t) {
		return
	}
	sh := func(script string) {
		t.Helper()
		if out, err := exec.Command("sh", "-ec", script).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", script, err, out)
		}
	}
	in := func(ns *testnet.NS, script string) {
		t.Helper()
		testnet.Must(t, ns.Do(func() error {
			if out, err := exec.Command("sh", "-ec", script).CombinedOutput(); err != nil {
				return fmt.Errorf("%s: %v %s", script, err, out)
			}
			return nil
		}))
	}
	client, server := testnet.NewNS(t, "client"), testnet.NewNS(t, "server")
	r1, r2 := testnet.NewNS(t, "r1"), testnet.NewNS(t, "r2")
	sh("ip link add br-lan type bridge && ip link add br-wan type bridge && ip link set br-lan up && ip link set br-wan up")
	t.Cleanup(func() { exec.Command("sh", "-c", "ip link del br-lan; ip link del br-wan").Run() })
	attach := func(root string, ns *testnet.NS, name, bridge string) {
		testnet.Veth(t, root, ns, name)
		sh("ip link set " + root + " master " + bridge)
	}
	attach("hc", client, "eth0", "br-lan")
	attach("hs", server, "eth0", "br-wan")
	attach("h1l", r1, "lan", "br-lan")
	attach("h1w", r1, "wan", "br-wan")
	attach("h2l", r2, "lan", "br-lan")
	attach("h2w", r2, "wan", "br-wan")
	// The sync link is a bridge of its own between the two routers.
	sh("ip link add br-sync type bridge && ip link set br-sync up")
	t.Cleanup(func() { exec.Command("ip", "link", "del", "br-sync").Run() })
	attach("h1s", r1, "sync0", "br-sync")
	attach("h2s", r2, "sync0", "br-sync")
	in(client, "ip addr add 10.0.0.10/24 dev eth0 && ip route add default via 10.0.0.1")
	in(server, "ip addr add 192.0.2.10/24 dev eth0 && ip route add default via 192.0.2.1")
	for i, r := range []*testnet.NS{r1, r2} {
		in(r, fmt.Sprintf(`ip addr add 10.0.0.%d/24 dev lan && ip addr add 192.0.2.%d/24 dev wan && ip addr add 10.9.9.%d/30 dev sync0
			ip link set sync0 up
			sysctl -qw net.ipv4.ip_forward=1 net.netfilter.nf_conntrack_tcp_loose=0
			nft add table inet strict
			nft 'add chain inet strict pass { type filter hook forward priority 0; policy drop; }'
			nft add rule inet strict pass ct state established,related accept
			nft add rule inet strict pass ct state new tcp flags syn accept`, i+2, i+2, i+1))
	}

	// The pair, in the model.
	dir := t.TempDir()
	store, err := confstore.Open(filepath.Join(dir, "config"))
	testnet.Must(t, err)
	defer store.Close()
	site := model.Meta{ID: id(1), Name: "hq"}
	pair := &model.HAPair{Meta: meta(10, "edge"), Enabled: true, SyncInterface: "sync0", AdvertMs: 500,
		Nodes: []model.Ref[model.ClusterNode]{{ID: id(2)}, {ID: id(3)}},
		Instances: []model.VRRPInstance{{Interface: "lan", VRID: 51, VirtualIPs: []string{"10.0.0.1/24"}},
			{Interface: "wan", VRID: 52, VirtualIPs: []string{"192.0.2.1/24"}}}}
	pair.Scope = model.SiteScope(id(1))
	for _, e := range []model.Entity{
		&model.Site{Meta: site},
		&model.ClusterNode{Meta: meta(2, "r1"), Site: model.Ref[model.Site]{ID: id(1)}, Hostname: "r1", Address: "10.0.0.2", SyncAddress: "10.9.9.1"},
		&model.ClusterNode{Meta: meta(3, "r2"), Site: model.Ref[model.Site]{ID: id(1)}, Hostname: "r2", Address: "10.0.0.3", SyncAddress: "10.9.9.2"},
		pair,
	} {
		if _, err := store.Create(context.Background(), "test", e); err != nil {
			t.Fatal(err)
		}
	}
	nw := &netops.Writer{AllowWrites: true}
	stages := map[*testnet.NS]*Stage{}
	for i, r := range []*testnet.NS{r1, r2} {
		node := id(i + 2)
		s := &Stage{Runner: nw, Dir: filepath.Join(dir, fmt.Sprintf("ha-r%d", i+1)), RunDir: fmt.Sprintf("/run/tha-r%d", i+1),
			Locate: func(*confstore.State) (string, string) { return id(1), node }}
		stages[r] = s
		raw, err := s.Render(store.Current())
		testnet.Must(t, err)
		testnet.Must(t, s.Check(context.Background(), raw))
		// The daemons start inside the router's namespace.
		testnet.Must(t, r.Do(func() error { return s.Apply(context.Background(), raw) }))
		testnet.Must(t, s.Healthy(context.Background()))
		t.Cleanup(func() {
			r.Do(func() error {
				for _, d := range []string{"keepalived", "conntrackd"} {
					nw.DaemonControl(netops.DaemonRequest{Name: d, Mode: netops.DaemonStop, RunDir: s.RunDir})
				}
				return nil
			})
		})
	}
	active := func(r *testnet.NS) bool {
		var ok bool
		r.Do(func() error { ok, _ = Active([]string{"10.0.0.1/24", "192.0.2.1/24"}); return nil })
		return ok
	}
	eventually := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			if cond() {
				return
			}
		}
		t.Fatalf("never: %s", what)
	}
	eventually("r1 is active and r2 is not", func() bool { return active(r1) && !active(r2) })

	// A connection through the pair: the server sends a byte every 50 ms
	// for ten seconds.
	var ln net.Listener
	testnet.Must(t, server.Do(func() error {
		var err error
		ln, err = net.Listen("tcp", "192.0.2.10:5000")
		return err
	}))
	defer ln.Close()
	const total = 200
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		for i := 0; i < total; i++ {
			if _, err := c.Write([]byte{'x'}); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	var conn net.Conn
	testnet.Must(t, client.Do(func() error {
		var err error
		conn, err = net.DialTimeout("tcp", "192.0.2.10:5000", 3*time.Second)
		return err
	}))
	got := make(chan int, 1)
	go func() {
		n, buf := 0, make([]byte, 64)
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		for n < total {
			k, err := conn.Read(buf)
			n += k
			if err != nil {
				break
			}
		}
		got <- n
	}()
	time.Sleep(2 * time.Second)
	// The standby knows the connection before anything happens.
	var synced string
	r2.Do(func() error {
		out, _ := exec.Command("conntrackd", "-C", filepath.Join(stages[r2].Dir, "conntrackd.conf"), "-e").CombinedOutput()
		synced = string(out)
		return nil
	})
	if !strings.Contains(synced, "dport=5000") {
		t.Errorf("the standby's external cache does not hold the connection:\n%s", synced)
	}
	// r1 fails: both its links go down.
	in(r1, "ip link set lan down && ip link set wan down")
	eventually("r2 takes the addresses over", func() bool { return active(r2) })
	if n := <-got; n != total {
		t.Fatalf("the connection broke at the failover: %d of %d bytes", n, total)
	}
	conn.Close()
	// r2's kernel holds the connection now, committed from the cache.
	r2.Do(func() error {
		out, _ := exec.Command("conntrack", "-L", "-p", "tcp", "--dport", "5000").CombinedOutput()
		if !strings.Contains(string(out), "dport=5000") {
			t.Errorf("r2's connection table:\n%s", out)
		}
		return nil
	})
}
