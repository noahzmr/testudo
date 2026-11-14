//go:build linux

package fwbridge

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confapply"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/firewall"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/testnet"
)

// TestModelDrivesTheKernel proves the whole path with real packets: a change
// to the model goes through the apply engine and the bridge into the firewall
// manager and nftables, and connections through a router behave accordingly.
//
//	client 10.77.1.2 --- lan0 [router] wan0 --- server 10.77.2.2
func TestModelDrivesTheKernel(t *testing.T) {
	if testnet.Isolate(t) {
		return
	}
	client, server := testnet.NewNS(t, "client"), testnet.NewNS(t, "server")
	testnet.Veth(t, "lan0", client, "eth0")
	testnet.Veth(t, "wan0", server, "eth0")
	testnet.Must(t, testnet.Addr("lan0", "10.77.1.1/24"))
	testnet.Must(t, testnet.Addr("wan0", "10.77.2.1/24"))
	testnet.Must(t, testnet.Sysctl("net/ipv4/ip_forward", "1"))
	testnet.Must(t, client.Do(func() error {
		if err := testnet.Addr("eth0", "10.77.1.2/24"); err != nil {
			return err
		}
		return testnet.DefaultRoute("10.77.1.1")
	}))
	// The server has no route back to the client network, so only
	// masqueraded traffic can be answered. That makes NAT observable.
	testnet.Must(t, server.Do(func() error { return testnet.Addr("eth0", "10.77.2.2/24") }))

	serve := func(port int) {
		var ln net.Listener
		testnet.Must(t, server.Do(func() error {
			var err error
			ln, err = net.Listen("tcp", fmt.Sprintf("10.77.2.2:%d", port))
			return err
		}))
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				fmt.Fprint(c, c.RemoteAddr().(*net.TCPAddr).IP.String())
				c.Close()
			}
		}()
	}
	serve(8443)
	serve(8444)
	// dial returns what the server saw as the peer address, or "" when the
	// connection did not come about.
	dial := func(addr string) string {
		var conn net.Conn
		err := client.Do(func() error {
			var err error
			conn, err = net.DialTimeout("tcp", addr, 400*time.Millisecond)
			return err
		})
		if err != nil {
			return ""
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second))
		b, _ := io.ReadAll(conn)
		return string(b)
	}

	dir := t.TempDir()
	mgr, err := firewall.Open(firewall.Options{Path: filepath.Join(dir, "firewall.json"), ProtectedTCPPorts: []uint16{22}},
		&netops.Writer{AllowWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	// A rule the operator made outside the model must survive everything.
	if err := mgr.AddRule(netops.FilterRule{Chain: "input", Action: "accept", Proto: "tcp", Port: 9999, Comment: "legacy"}); err != nil {
		t.Fatal(err)
	}
	store, err := confstore.Open(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	eng, err := confapply.New(store, confapply.Options{Dir: dir, Window: 600 * time.Millisecond},
		&Stage{Manager: mgr, SiteID: id(siteN), NodeID: id(nodeN)})
	if err != nil {
		t.Fatal(err)
	}
	create := func(objs ...model.Entity) []confstore.Op {
		var ops []confstore.Op
		for _, e := range objs {
			obj, _ := json.Marshal(e)
			ops = append(ops, confstore.Op{Type: confstore.OpCreate, Kind: e.Kind(), ID: e.GetMeta().ID, Object: obj})
		}
		return ops
	}
	apply := func(note string, ops []confstore.Op) {
		t.Helper()
		if _, err := eng.Apply(ctx, "test", note, ops); err != nil {
			t.Fatalf("%s: %v", note, err)
		}
		if err := eng.Confirm("test"); err != nil {
			t.Fatalf("%s: confirm: %v", note, err)
		}
	}
	nodeMeta := func(n int, name string) model.Meta {
		m := meta(n, name)
		m.Scope = model.NodeScope(id(nodeN))
		return m
	}

	// 1. Topology and a default-deny policy with one allowed service.
	apply("base", create(
		&model.Site{Meta: meta(siteN, "hq")},
		&model.ClusterNode{Meta: meta(nodeN, "fw1"), Site: model.Ref[model.Site]{ID: id(siteN)}, Hostname: "fw1", Address: "10.77.1.1"},
		&model.Zone{Meta: meta(lan, "lan"), DefaultAction: "drop"},
		&model.Zone{Meta: meta(wan, "wan"), DefaultAction: "drop"},
		&model.Interface{Meta: nodeMeta(20, "lan0"), Device: "lan0", Zone: zone(lan), Enabled: true},
		&model.Interface{Meta: nodeMeta(21, "wan0"), Device: "wan0", Zone: zone(wan), Enabled: true},
		&model.Alias{Meta: meta(30, "servers"), Type: "host", Entries: []string{"10.77.2.2"}},
		&model.FirewallPolicy{Meta: meta(40, "default"), DefaultDeny: true, AllowEstablished: true, DropInvalid: true,
			AllowLoopback: true, AllowICMP: true},
		&model.FilterRule{Meta: meta(50, "lan-to-servers"), Sequence: 10, Enabled: true, Action: "accept", Direction: "forward",
			Protocol: "tcp", SourceZone: zone(lan), DestinationZone: zone(wan),
			Destination: []model.Ref[model.Alias]{alias(30)}, Ports: []string{"8443"}},
		&model.NATRule{Meta: meta(60, "outbound"), Enabled: true, Type: "masquerade", Zone: zone(wan), Protocol: "any",
			SourceNets: []string{"10.77.1.0/24"}},
	))
	if got := dial("10.77.2.2:8443"); got != "10.77.2.1" {
		t.Fatalf("allowed service: server saw %q, want the router's address 10.77.2.1 (masquerade)", got)
	}
	if got := dial("10.77.2.2:8444"); got != "" {
		t.Fatalf("a port no rule allows was reachable (server saw %q)", got)
	}

	// 2. A port forward: the router's own address leads to the server.
	apply("forward", create(&model.NATRule{Meta: meta(61, "publish"), Enabled: true, Type: "dnat", Zone: zone(lan),
		Protocol: "tcp", Port: "8080", TranslateTo: "10.77.2.2", TranslatePort: "8444"}))
	if got := dial("10.77.1.1:8080"); got != "10.77.2.1" {
		t.Errorf("port forward: server saw %q", got)
	}

	// 3. Removing the allow rule without confirming: it comes back.
	rule, _ := store.Current().Get(model.KindFilterRule, id(50))
	del := []confstore.Op{{Type: confstore.OpDelete, Kind: model.KindFilterRule, ID: id(50), IfMatch: rule.GetMeta().Version}}
	if _, err := eng.Apply(ctx, "test", "cut the service off", del); err != nil {
		t.Fatal(err)
	}
	if got := dial("10.77.2.2:8443"); got != "" {
		t.Errorf("the rule is gone from the model but the kernel still lets traffic through (%q)", got)
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, pending := eng.Pending(); !pending {
			break
		}
	}
	if got := dial("10.77.2.2:8443"); got != "10.77.2.1" {
		t.Errorf("after the automatic rollback the service is still cut off (server saw %q)", got)
	}
	if _, ok := store.Current().Get(model.KindFilterRule, id(50)); !ok {
		t.Error("the model did not get its rule back")
	}

	// 4. The operator's own rule and the kernel's sync state are intact.
	if r, _, _ := mgr.CountOwned(netops.OwnerUser); r != 1 {
		t.Errorf("rules owned by the operator: %d, want 1", r)
	}
	if d := mgr.Reconcile(); !d.InSync || d.Error != "" {
		t.Errorf("kernel drifted from the policy: %+v", d)
	}
}
