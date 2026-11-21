//go:build linux

package flowattr

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/capture"
	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/testnet"
)

// TestNATAttributionOnARealKernel forwards a port with nftables and checks
// that the flow the capture sees outside and the one it sees inside are
// told apart and joined: both carry the connection before and after the
// translation and one conversation id.
//
//	client 192.0.2.2 --- wan0 [router 192.0.2.1:8443 -> 10.50.0.2:443] lan0 --- server 10.50.0.2
func TestNATAttributionOnARealKernel(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not installed")
	}
	if testnet.Isolate(t) {
		return
	}
	client, server := testnet.NewNS(t, "client"), testnet.NewNS(t, "server")
	testnet.Veth(t, "wan0", client, "eth0")
	testnet.Veth(t, "lan0", server, "eth0")
	testnet.Must(t, testnet.Addr("wan0", "192.0.2.1/24"))
	testnet.Must(t, testnet.Addr("lan0", "10.50.0.1/24"))
	testnet.Must(t, testnet.Sysctl("net/ipv4/ip_forward", "1"))
	testnet.Must(t, client.Do(func() error { return testnet.Addr("eth0", "192.0.2.2/24") }))
	testnet.Must(t, server.Do(func() error {
		if err := testnet.Addr("eth0", "10.50.0.2/24"); err != nil {
			return err
		}
		return testnet.DefaultRoute("10.50.0.1")
	}))
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader("table ip portfwd {\n chain pre {\n  type nat hook prerouting priority dstnat; policy accept;\n  tcp dport 8443 dnat to 10.50.0.2:443\n }\n}\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft: %v %s", err, out)
	}

	var ln net.Listener
	testnet.Must(t, server.Do(func() error {
		var err error
		ln, err = net.Listen("tcp", "10.50.0.2:443")
		return err
	}))
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fmt.Fprint(c, strings.Repeat("x", 4096))
			c.Close()
		}
	}()

	agg := flows.NewAggregator()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go (&capture.Multi{Ifaces: []string{"wan0", "lan0"}, Flows: agg}).Run(ctx, events.NewBus(16))
	time.Sleep(500 * time.Millisecond) // the capture sockets are open

	var conn net.Conn
	testnet.Must(t, client.Do(func() error {
		var err error
		conn, err = (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 40555}, Timeout: 2 * time.Second}).Dial("tcp", "192.0.2.1:8443")
		return err
	}))
	body, _ := io.ReadAll(conn)
	if len(body) != 4096 {
		t.Fatalf("through the forward: %d bytes", len(body))
	}
	// conntrack still holds the entry (TIME_WAIT) while the flows are read.
	ct, err := (&netops.Writer{}).ListConntrackQuery(netops.ConntrackQuery{NATOnly: true})
	if err != nil || len(ct.Flows) == 0 {
		t.Fatalf("conntrack: %d entries, %v", len(ct.Flows), err)
	}
	conn.Close()

	// The model knows which zone each interface is in.
	store, err := confstore.Open(t.TempDir())
	testnet.Must(t, err)
	defer store.Close()
	nodeScope := func(n int, name string) model.Meta {
		m := meta(n, name)
		m.Scope = model.NodeScope(id(2))
		return m
	}
	for _, e := range []model.Entity{
		&model.Site{Meta: meta(1, "hq")},
		&model.ClusterNode{Meta: meta(2, "fw1"), Site: model.Ref[model.Site]{ID: id(1)}, Hostname: "fw1", Address: "192.0.2.1"},
		&model.Zone{Meta: meta(10, "wan"), DefaultAction: "drop"},
		&model.Zone{Meta: meta(11, "lan"), DefaultAction: "drop"},
		&model.Interface{Meta: nodeScope(20, "wan0"), Device: "wan0", Zone: model.Ref[model.Zone]{ID: id(10)}, Enabled: true},
		&model.Interface{Meta: nodeScope(21, "lan0"), Device: "lan0", Zone: model.Ref[model.Zone]{ID: id(11)}, Enabled: true},
	} {
		if _, err := store.Create(ctx, "t", e); err != nil {
			t.Fatal(err)
		}
	}
	var outside, inside flows.FlowStats
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		for _, f := range agg.Snapshot() {
			if f.Key.Iface == "wan0" && f.Key.Proto == "tcp" && (f.Key.A.Port == 8443 || f.Key.B.Port == 8443) {
				outside = f
			}
			if f.Key.Iface == "lan0" && f.Key.Proto == "tcp" && (f.Key.A.Port == 443 || f.Key.B.Port == 443) {
				inside = f
			}
		}
		if outside.Bytes > 4096 && inside.Bytes > 4096 {
			break
		}
	}
	if outside.Packets == 0 || inside.Packets == 0 {
		t.Fatalf("the capture did not see both sides: %+v / %+v", outside.Key, inside.Key)
	}
	got := Build(Input{State: store.Current(), SiteID: id(1), NodeID: id(2), Conntrack: ct.Flows,
		LocalIPs: []string{"192.0.2.1", "10.50.0.1"}}).Apply([]flows.FlowStats{outside, inside})
	o, i := got[0].Attrs, got[1].Attrs
	want := "tcp 192.0.2.2:40555 > 192.0.2.1:8443"
	if o.PreNAT != want || i.PreNAT != want || o.PostNAT != "tcp 192.0.2.2:40555 > 10.50.0.2:443" || o.PostNAT != i.PostNAT {
		t.Errorf("translation: outside %q / %q, inside %q / %q", o.PreNAT, o.PostNAT, i.PreNAT, i.PostNAT)
	}
	if o.Conversation == "" || o.Conversation != i.Conversation {
		t.Errorf("conversation: %q / %q", o.Conversation, i.Conversation)
	}
	if o.Zone != "wan" || i.Zone != "lan" || o.Site != "hq" {
		t.Errorf("zones: %+v / %+v", o, i)
	}
}
