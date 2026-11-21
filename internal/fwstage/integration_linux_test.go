//go:build linux

package fwstage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// Compile-time proof that the pieces fit.
var (
	_ confapply.Stage = (*Stage)(nil)
	_ Runner          = (*netops.Writer)(nil)
)

var ctx = context.Background()

func id(n int) string                    { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func meta(n int, name string) model.Meta { return model.Meta{ID: id(n), Name: name} }
func zone(n int) model.Ref[model.Zone]   { return model.Ref[model.Zone]{ID: id(n)} }
func alias(n int) model.Ref[model.Alias] { return model.Ref[model.Alias]{ID: id(n)} }

const (
	siteN, nodeN = 1, 2
	lan, wan     = 10, 11
)

// TestRulesetOnARealKernel loads the rendered ruleset with nft and checks
// with real connections that it does what the model says.
//
//	client 10.77.1.2 / fd77:1::2 --- lan0 [router] wan0 --- server 10.77.2.2 / fd77:2::2
func TestRulesetOnARealKernel(t *testing.T) {
	if testnet.Isolate(t) {
		return
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not installed")
	}
	client, server := testnet.NewNS(t, "client"), testnet.NewNS(t, "server")
	testnet.Veth(t, "lan0", client, "eth0")
	testnet.Veth(t, "wan0", server, "eth0")
	for _, a := range [][2]string{{"lan0", "10.77.1.1/24"}, {"lan0", "fd77:1::1/64"}, {"wan0", "10.77.2.1/24"}, {"wan0", "fd77:2::1/64"}} {
		testnet.Must(t, testnet.Addr(a[0], a[1]))
	}
	testnet.Must(t, testnet.Sysctl("net/ipv4/ip_forward", "1"))
	testnet.Must(t, testnet.Sysctl("net/ipv6/conf/all/forwarding", "1"))
	testnet.Must(t, client.Do(func() error {
		for _, f := range []func() error{
			func() error { return testnet.Addr("eth0", "10.77.1.2/24") },
			func() error { return testnet.Addr("eth0", "fd77:1::2/64") },
			func() error { return testnet.DefaultRoute("10.77.1.1") },
			func() error { return testnet.DefaultRoute("fd77:1::1") },
		} {
			if err := f(); err != nil {
				return err
			}
		}
		return nil
	}))
	// The server has an IPv6 route back but no IPv4 route: IPv4 replies only
	// arrive when the router translates the source.
	testnet.Must(t, server.Do(func() error {
		for _, f := range []func() error{
			func() error { return testnet.Addr("eth0", "10.77.2.2/24") },
			func() error { return testnet.Addr("eth0", "fd77:2::2/64") },
			func() error { return testnet.DefaultRoute("fd77:2::1") },
		} {
			if err := f(); err != nil {
				return err
			}
		}
		return nil
	}))

	serve := func(addr string) {
		var ln net.Listener
		testnet.Must(t, server.Do(func() error {
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
				fmt.Fprint(c, c.RemoteAddr().(*net.TCPAddr).IP.String())
				c.Close()
			}
		}()
	}
	for _, a := range []string{"10.77.2.2:8443", "10.77.2.2:8444", "[fd77:2::2]:8443", "[fd77:2::2]:8444"} {
		serve(a)
	}
	// dial returns the peer address the server saw, or "" without a connection.
	dial := func(addr string) string {
		var conn net.Conn
		if err := client.Do(func() error {
			var err error
			conn, err = net.DialTimeout("tcp", addr, 400*time.Millisecond)
			return err
		}); err != nil {
			return ""
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second))
		b, _ := io.ReadAll(conn)
		return string(b)
	}
	nft := func(args ...string) string {
		out, _ := exec.Command("nft", args...).CombinedOutput()
		return string(out)
	}

	dir := t.TempDir()
	nw := &netops.Writer{AllowWrites: true}
	if !nw.NftAvailable() {
		t.Fatal("nft cannot load rulesets here")
	}

	// A host that used the netlink path has its two tables; the switch has to
	// remove them in the same transaction that installs the new one.
	if err := nw.NftApply("add table inet testudo_filter\nadd table ip testudo_nat\n"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nft("list", "tables"), "testudo_filter") {
		t.Fatal("precondition: the netlink table was not created")
	}

	stage := &Stage{Runner: nw, ProtectedTCPPorts: []int{22}, Locate: func(*confstore.State) (string, string) { return id(siteN), id(nodeN) }}
	blocklist := []string{}
	stage.Elements = func() map[string][]string { return map[string][]string{id(33): blocklist} }
	store, err := confstore.Open(filepath.Join(dir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	eng, err := confapply.New(store, confapply.Options{Dir: dir, Window: 700 * time.Millisecond}, stage)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// The old manager's tables are gone; a model without a policy has no
	// table of its own either.
	tables := nft("list", "tables")
	if strings.Contains(tables, "testudo_filter") || strings.Contains(tables, "testudo_nat") {
		t.Fatalf("after the switch the tables are:\n%s", tables)
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
			t.Fatalf("%s: %v\n%s", note, err, nft("list", "ruleset"))
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

	// 1. Default deny, one service allowed by alias for both families,
	//    outbound masquerade for IPv4.
	apply("base", create(
		&model.Site{Meta: meta(siteN, "hq")},
		&model.ClusterNode{Meta: meta(nodeN, "fw1"), Site: model.Ref[model.Site]{ID: id(siteN)}, Hostname: "fw1", Address: "10.77.1.1"},
		&model.Zone{Meta: meta(lan, "lan"), DefaultAction: "drop", AntiSpoof: true},
		&model.Zone{Meta: meta(wan, "wan"), DefaultAction: "drop"},
		&model.Interface{Meta: nodeMeta(20, "lan0"), Device: "lan0", Zone: zone(lan), Enabled: true},
		&model.Interface{Meta: nodeMeta(21, "wan0"), Device: "wan0", Zone: zone(wan), Enabled: true},
		&model.Alias{Meta: meta(30, "servers"), Type: "host", Entries: []string{"10.77.2.2", "fd77:2::2"}},
		&model.Alias{Meta: meta(31, "web-ports"), Type: "port", Entries: []string{"8443"}},
		&model.Alias{Meta: meta(33, "blocklist"), Type: "url_table", URL: "https://example.net/list.txt"},
		&model.FirewallPolicy{Meta: meta(40, "default"), DefaultDeny: true, AllowEstablished: true, DropInvalid: true,
			AllowLoopback: true, AllowICMP: true, SynFloodGuard: true, LogDrops: true, TCPEstablished: "2h", UDPTimeout: "90s"},
		&model.FilterRule{Meta: meta(49, "blocked-sources"), Sequence: 5, Enabled: true, Action: "drop", Direction: "forward",
			Protocol: "any", Source: []model.Ref[model.Alias]{alias(33)}},
		&model.FilterRule{Meta: meta(50, "lan-to-servers"), Sequence: 10, Enabled: true, Action: "accept", Direction: "forward",
			Protocol: "tcp", SourceZone: zone(lan), DestinationZone: zone(wan),
			Destination: []model.Ref[model.Alias]{alias(30)}, PortAliases: []model.Ref[model.Alias]{alias(31)}},
		&model.NATRule{Meta: meta(60, "outbound"), Enabled: true, Sequence: 100, Type: "masquerade", Zone: zone(wan), Protocol: "any",
			SourceNets: []string{"10.77.1.0/24"}},
	))
	// Fresh interfaces need a moment before IPv6 neighbour discovery works
	// (their link-local addresses are still being verified), so what must
	// succeed is retried; what must fail is checked once things work.
	eventually := func(addr, want string) {
		t.Helper()
		var got string
		for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			if got = dial(addr); got == want {
				return
			}
		}
		t.Errorf("%s: server saw %q, want %q", addr, got, want)
	}
	eventually("10.77.2.2:8443", "10.77.2.1")   // allowed, masqueraded
	eventually("[fd77:2::2]:8443", "fd77:1::2") // allowed, IPv6 is routed
	for _, addr := range []string{"10.77.2.2:8444", "[fd77:2::2]:8444"} {
		if got := dial(addr); got != "" {
			t.Errorf("%s: no rule allows it, yet the server saw %q", addr, got)
		}
	}
	if t.Failed() {
		t.Fatalf("ruleset:\n%s", nft("list", "table", "inet", "testudo"))
	}

	if l := nft("list", "table", "inet", "testudo"); !strings.Contains(l, "ct timeout tcp_established_ipv4") || !strings.Contains(l, `ct timeout set "udp_stream_ipv6"`) {
		t.Errorf("connection-tracking timeouts are not in the loaded ruleset:\n%s", l)
	}

	// 2. Counters come back by model object.
	counters, err := stage.Counters()
	if err != nil || counters[id(50)].Packets == 0 {
		t.Errorf("counters for the allow rule: %+v, %v", counters[id(50)], err)
	}

	// 3. A run-time alias: once the client is on the block list, it is cut off.
	blocklist = []string{"10.77.1.0/24", "fd77:1::/64"}
	a33, _ := store.Current().Get(model.KindAlias, id(33))
	a33.GetMeta().Description = "refreshed"
	obj, _ := json.Marshal(a33)
	apply("refresh block list", []confstore.Op{{Type: confstore.OpUpdate, Kind: model.KindAlias, ID: id(33), Object: obj, IfMatch: a33.GetMeta().Version}})
	if got := dial("10.77.2.2:8443"); got != "" {
		t.Errorf("a blocked source still gets through (%q)", got)
	}
	blocklist = nil
	a33, _ = store.Current().Get(model.KindAlias, id(33))
	a33.GetMeta().Description = ""
	obj, _ = json.Marshal(a33)
	apply("empty block list", []confstore.Op{{Type: confstore.OpUpdate, Kind: model.KindAlias, ID: id(33), Object: obj, IfMatch: a33.GetMeta().Version}})

	// 4. Source NAT to a second address, a port forward with reflection and
	//    its translated connection, for IPv4.
	testnet.Must(t, testnet.Addr("wan0", "10.77.2.9/24"))
	apply("nat", create(
		&model.NATRule{Meta: meta(61, "mail-out"), Enabled: true, Sequence: 1, Type: "snat", Zone: zone(wan), Protocol: "tcp",
			SourceNets: []string{"10.77.1.2"}, Port: "8443", TranslateTo: "10.77.2.9"},
		&model.NATRule{Meta: meta(62, "publish"), Enabled: true, Sequence: 2, Type: "dnat", Zone: zone(lan), Protocol: "tcp",
			Destination: "10.77.1.1", Port: "8080", TranslateTo: "10.77.2.2", TranslatePort: "8444"},
	))
	if got := dial("10.77.2.2:8443"); got != "10.77.2.9" {
		t.Errorf("source NAT: server saw %q, want 10.77.2.9", got)
	}
	if got := dial("10.77.1.1:8080"); got != "10.77.2.1" {
		t.Errorf("port forward: server saw %q, want 10.77.2.1", got)
	}

	// 6. An unconfirmed change comes back by itself.
	rule, _ := store.Current().Get(model.KindFilterRule, id(50))
	if _, err := eng.Apply(ctx, "test", "cut off", []confstore.Op{{Type: confstore.OpDelete, Kind: model.KindFilterRule, ID: id(50), IfMatch: rule.GetMeta().Version}}); err != nil {
		t.Fatal(err)
	}
	if got := dial("[fd77:2::2]:8443"); got != "" {
		t.Errorf("removed rule still lets traffic through (%q)", got)
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, pending := eng.Pending(); !pending {
			break
		}
	}
	if got := dial("[fd77:2::2]:8443"); got != "fd77:1::2" {
		t.Errorf("service still cut off after the automatic rollback (%q)", got)
	}

	// 7. Someone flushes the table: the drift check notices and reloads.
	nft("delete", "table", "inet", "testudo")
	if got := dial("[fd77:2::2]:8444"); got == "" {
		t.Error("precondition: without the table everything should be forwarded")
	}
	if d := stage.Reconcile(); d.Error != "" || !d.Reloaded || !d.InSync {
		t.Errorf("drift after a flushed table: %+v", d)
	}
	if d := stage.Reconcile(); d.Reloaded || !d.InSync {
		t.Errorf("a second check reloaded again: %+v", d)
	}
	if got := dial("[fd77:2::2]:8443"); got != "fd77:1::2" {
		t.Errorf("after the reload the service is unreachable (%q)", got)
	}
	if got := dial("10.77.2.2:8444"); got != "" {
		t.Errorf("after the reload a closed port is open (%q)", got)
	}
	if err := stage.Healthy(ctx); err != nil {
		t.Errorf("healthy: %v", err)
	}
}
