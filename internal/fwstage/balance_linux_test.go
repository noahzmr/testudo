//go:build linux

package fwstage

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/testnet"
)

// TestKernelBalancingOnARealKernel checks services balanced in the packet
// filter with real connections: weights, sticky clients, draining, and
// leaving out a backend that failed its health check.
//
//	client 192.0.2.2 --- wan0 [router] lan0 --- backends 10.50.0.2 (a), 10.50.0.3 (b)
func TestKernelBalancingOnARealKernel(t *testing.T) {
	if testnet.Isolate(t) {
		return
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not installed")
	}
	client, back := testnet.NewNS(t, "client"), testnet.NewNS(t, "backends")
	testnet.Veth(t, "wan0", client, "eth0")
	testnet.Veth(t, "lan0", back, "eth0")
	testnet.Must(t, testnet.Addr("wan0", "192.0.2.1/24"))
	testnet.Must(t, testnet.Addr("lan0", "10.50.0.1/24"))
	testnet.Must(t, testnet.Sysctl("net/ipv4/ip_forward", "1"))
	testnet.Must(t, client.Do(func() error { return testnet.Addr("eth0", "192.0.2.2/24") }))
	// The client's address is preserved, so the backends route back
	// through the firewall.
	testnet.Must(t, back.Do(func() error {
		for _, f := range []func() error{
			func() error { return testnet.Addr("eth0", "10.50.0.2/24") },
			func() error { return testnet.Addr("eth0", "10.50.0.3/24") },
			func() error { return testnet.DefaultRoute("10.50.0.1") },
		} {
			if err := f(); err != nil {
				return err
			}
		}
		return nil
	}))
	for name, addr := range map[string]string{"a": "10.50.0.2:8080", "b": "10.50.0.3:8080"} {
		var ln net.Listener
		testnet.Must(t, back.Do(func() error {
			var err error
			ln, err = net.Listen("tcp", addr)
			return err
		}))
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				fmt.Fprintf(c, "%s %s", name, c.RemoteAddr().(*net.TCPAddr).IP)
				c.Close()
			}
		}()
	}
	// spread opens n connections and counts which backend answered.
	spread := func(port, n int) map[string]int {
		count := map[string]int{}
		for i := 0; i < n; i++ {
			var conn net.Conn
			err := client.Do(func() error {
				var err error
				conn, err = net.DialTimeout("tcp", fmt.Sprintf("192.0.2.1:%d", port), 500*time.Millisecond)
				return err
			})
			if err != nil {
				count["no connection"]++
				continue
			}
			conn.SetDeadline(time.Now().Add(time.Second))
			b, _ := io.ReadAll(conn)
			conn.Close()
			count[string(b)]++
		}
		return count
	}

	dir := t.TempDir()
	nw := &netops.Writer{AllowWrites: true}
	down := map[string]bool{}
	stage := &Stage{Runner: nw, ProtectedTCPPorts: []int{22}, Locate: func(*confstore.State) (string, string) { return id(siteN), id(nodeN) },
		BackendDown: func() map[string]bool { return down }}
	store, err := confstore.Open(filepath.Join(dir, "config"))
	testnet.Must(t, err)
	defer store.Close()
	eng, err := confapply.New(store, confapply.Options{Dir: dir, Window: time.Minute}, stage)
	testnet.Must(t, err)
	testnet.Must(t, eng.Start(ctx))
	apply := func(note string, ops ...confstore.Op) {
		t.Helper()
		if _, err := eng.Apply(ctx, "test", note, ops); err != nil {
			out, _ := exec.Command("nft", "list", "ruleset").CombinedOutput()
			t.Fatalf("%s: %v\n%s", note, err, out)
		}
		testnet.Must(t, eng.Confirm("test"))
	}
	op := func(typ confstore.OpType, e model.Entity) confstore.Op {
		o := confstore.Op{Type: typ, Kind: e.Kind(), ID: e.GetMeta().ID}
		if typ == confstore.OpUpdate {
			cur, _ := store.Current().Get(e.Kind(), e.GetMeta().ID)
			o.IfMatch = cur.GetMeta().Version
			e.GetMeta().Scope = cur.GetMeta().Scope
		}
		o.Object, _ = json.Marshal(e)
		return o
	}
	nodeMeta := func(n int, name string) model.Meta {
		m := meta(n, name)
		m.Scope = model.NodeScope(id(nodeN))
		return m
	}
	pool := func(n int, name string, sticky bool, backends ...model.LBBackend) *model.LBBackendPool {
		return &model.LBBackendPool{Meta: meta(n, name), Algorithm: "weighted_round_robin", Sticky: sticky,
			Backends: backends, HealthCheck: model.LBHealthCheck{Type: "tcp"}}
	}
	a, b := model.LBBackend{Address: "10.50.0.2:8080", Weight: 3}, model.LBBackend{Address: "10.50.0.3:8080", Weight: 1}
	service := func(n int, name string, port, poolN int) *model.LBService {
		return &model.LBService{Meta: meta(n, name), Enabled: true, Zone: zone(wan), Port: port, Protocol: "tcp", Mode: "kernel",
			DefaultPool: model.Ref[model.LBBackendPool]{ID: id(poolN)}}
	}
	apply("balancing",
		op(confstore.OpCreate, &model.Site{Meta: meta(siteN, "hq")}),
		op(confstore.OpCreate, &model.ClusterNode{Meta: meta(nodeN, "fw1"), Site: model.Ref[model.Site]{ID: id(siteN)}, Hostname: "fw1", Address: "192.0.2.1"}),
		op(confstore.OpCreate, &model.Zone{Meta: meta(lan, "lan"), DefaultAction: "drop"}),
		op(confstore.OpCreate, &model.Zone{Meta: meta(wan, "wan"), DefaultAction: "drop"}),
		op(confstore.OpCreate, &model.Interface{Meta: nodeMeta(20, "lan0"), Device: "lan0", Zone: zone(lan), Enabled: true}),
		op(confstore.OpCreate, &model.Interface{Meta: nodeMeta(21, "wan0"), Device: "wan0", Zone: zone(wan), Enabled: true}),
		op(confstore.OpCreate, &model.FirewallPolicy{Meta: meta(40, "default"), DefaultDeny: true, AllowEstablished: true, DropInvalid: true, AllowLoopback: true, AllowICMP: true}),
		op(confstore.OpCreate, pool(70, "web", false, a, b)),
		op(confstore.OpCreate, pool(71, "sticky", true, model.LBBackend{Address: a.Address}, model.LBBackend{Address: b.Address})),
		op(confstore.OpCreate, service(80, "web", 9000, 70)),
		op(confstore.OpCreate, service(81, "sticky", 9001, 71)),
	)

	// 1. Weights 3 to 1, and the backend sees the client's own address.
	//    Default deny is in force: only the translated connections pass.
	if got := spread(9000, 40); got["a 192.0.2.2"] != 30 || got["b 192.0.2.2"] != 10 {
		t.Errorf("weights 3:1 over 40 connections: %v", got)
	}
	if got := spread(8080, 1); got["no connection"] != 1 {
		t.Errorf("a port nothing balances is reachable: %v", got)
	}
	// 2. A sticky pool keeps one client on one backend.
	if got := spread(9001, 20); len(got) != 1 || got["no connection"] != 0 {
		t.Errorf("sticky pool spread one client over backends: %v", got)
	}
	// 3. A draining backend gets no new connections.
	drained := a
	drained.Drain = true
	apply("drain a", op(confstore.OpUpdate, pool(70, "web", false, drained, b)))
	if got := spread(9000, 12); got["b 192.0.2.2"] != 12 {
		t.Errorf("with a draining: %v", got)
	}
	apply("a back", op(confstore.OpUpdate, pool(70, "web", false, a, b)))
	// 4. A backend that failed its health check is left out by a refresh,
	//    without a change to the model, and comes back the same way.
	down[b.Address] = true
	testnet.Must(t, stage.Refresh(store.Current()))
	if got := spread(9000, 12); got["a 192.0.2.2"] != 12 {
		t.Errorf("with b down: %v", got)
	}
	delete(down, b.Address)
	testnet.Must(t, stage.Refresh(store.Current()))
	if got := spread(9000, 40); got["a 192.0.2.2"] != 30 || got["b 192.0.2.2"] != 10 {
		t.Errorf("after b came back: %v", got)
	}
	// 5. The service has a counter under its own id.
	counters, err := stage.Counters()
	if err != nil || counters[id(80)].Packets == 0 {
		t.Errorf("counter of the service: %+v, %v", counters[id(80)], err)
	}
	// 6. Every backend down: the service refuses instead of sending
	//    connections nowhere.
	down[a.Address], down[b.Address] = true, true
	testnet.Must(t, stage.Refresh(store.Current()))
	if got := spread(9000, 2); got["no connection"] != 2 {
		t.Errorf("with every backend down: %v", got)
	}
}
