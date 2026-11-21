package flowattr

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
)

func id(n int) string                    { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func meta(n int, name string) model.Meta { return model.Meta{ID: id(n), Name: name} }

const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func fixture(t *testing.T) *confstore.State {
	t.Helper()
	s, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	node := func(n int, name string, site int) model.Meta {
		m := meta(n, name)
		m.Scope = model.NodeScope(id(2))
		return m
	}
	pool := func(n int) model.Ref[model.LBBackendPool] { return model.Ref[model.LBBackendPool]{ID: id(n)} }
	zone := func(n int) model.Ref[model.Zone] { return model.Ref[model.Zone]{ID: id(n)} }
	for _, e := range []model.Entity{
		&model.Site{Meta: meta(1, "hq"), ASN: 65001, Networks: []string{"10.1.0.0/24"}},
		&model.Site{Meta: meta(3, "branch"), ASN: 65002, Networks: []string{"10.2.0.0/24"}},
		&model.ClusterNode{Meta: meta(2, "fw1"), Site: model.Ref[model.Site]{ID: id(1)}, Hostname: "fw1", Address: "192.0.2.1",
			MeshIndex: 1, MeshPublicKey: key, Uplinks: []model.Uplink{{Color: "inet", Endpoint: "198.51.100.1"}}},
		&model.ClusterNode{Meta: meta(4, "br1"), Site: model.Ref[model.Site]{ID: id(3)}, Hostname: "br1", Address: "192.0.2.2",
			MeshIndex: 2, MeshPublicKey: key, Uplinks: []model.Uplink{{Color: "inet", Endpoint: "198.51.100.2"}}},
		&model.Zone{Meta: meta(10, "wan"), DefaultAction: "drop"},
		&model.Zone{Meta: meta(11, "lan"), DefaultAction: "drop"},
		&model.Zone{Meta: meta(12, "vpn"), DefaultAction: "drop"},
		&model.Zone{Meta: meta(13, "fabric"), DefaultAction: "accept"},
		&model.Interface{Meta: node(20, "wan0", 1), Device: "wan0", Zone: zone(10), Enabled: true},
		&model.Interface{Meta: node(21, "lan0", 1), Device: "lan0", Zone: zone(11), Enabled: true},
		&model.Fabric{Meta: meta(30, "fabric"), Enabled: true, Topology: "full_mesh", Pool: "10.255.0.0/16", PortBase: 52000, ASN: 65000,
			Colors: []string{"inet"}, Zone: zone(13)},
		&model.User{Meta: meta(40, "alice"), Username: "alice", Source: "oidc"},
		&model.WGTunnel{Meta: node(41, "roadwarriors", 1), Enabled: true, Device: "wg0", Mode: "road_warrior", ListenPort: 51820,
			Addresses: []string{"10.8.0.1/24"}, PublicKey: key, Zone: zone(12)},
		&model.WGPeer{Meta: meta(42, "alice-laptop"), Enabled: true, Tunnel: model.Ref[model.WGTunnel]{ID: id(41)}, PublicKey: key,
			AllowedIPs: []string{"10.8.0.2/32"}, User: model.Ref[model.User]{ID: id(40)}},
		&model.LBBackendPool{Meta: meta(50, "app"), Algorithm: "weighted_round_robin", HealthCheck: model.LBHealthCheck{Type: "none"},
			Backends: []model.LBBackend{{Address: "10.1.0.20:8080"}, {Address: "10.1.0.21:8080"}}},
		&model.LBBackendPool{Meta: meta(51, "dns"), Algorithm: "weighted_round_robin", HealthCheck: model.LBHealthCheck{Type: "none"},
			Backends: []model.LBBackend{{Address: "10.1.0.53:53"}}},
		&model.LBService{Meta: meta(52, "web"), Enabled: true, Zone: zone(10), Port: 443, Protocol: "https", Mode: "proxy"},
		&model.LBService{Meta: meta(53, "resolver"), Enabled: true, Zone: zone(10), Address: "203.0.113.1", Port: 53, Protocol: "udp",
			Mode: "kernel", DefaultPool: pool(51)},
	} {
		if _, err := s.Create(context.Background(), "t", e); err != nil {
			t.Fatalf("create %s %q: %v", e.Kind(), e.GetMeta().Name, err)
		}
	}
	if _, err := s.Create(context.Background(), "t", &model.LBRouter{Meta: meta(54, "app"), Enabled: true,
		Service: model.Ref[model.LBService]{ID: id(52)}, Hosts: []string{"app.example.com"}, TLS: "none", Pool: pool(50)}); err != nil {
		// TLS "none" on an https service may be refused; use termination.
		t.Logf("router: %v", err)
	}
	return s.Current()
}

func flow(iface, proto, a string, ap uint16, b string, bp uint16) flows.FlowStats {
	return flows.FlowStats{Key: flows.FlowKey{Iface: iface, Proto: proto, A: flows.Endpoint{IP: a, Port: ap}, B: flows.Endpoint{IP: b, Port: bp}}}
}

// A line as Traefik 3 writes it (fields it adds beyond these are ignored).
const sampleLine = `{"ClientAddr":"192.0.2.77:40001","ClientHost":"192.0.2.77","ClientPort":"40001","DownstreamStatus":200,` +
	`"RequestHost":"app.example.com","RouterName":"rt-app-000000@file","ServiceAddr":"10.1.0.21:8080",` +
	`"ServiceName":"pool-app-000000@file","ServiceURL":"http://10.1.0.21:8080","StartUTC":"2026-11-21T10:00:00.5Z"}`

func TestAttribution(t *testing.T) {
	st := fixture(t)
	acc, ok := ParseAccess([]byte(sampleLine))
	if !ok || acc.Router != "rt-app-000000" || acc.Backend != "10.1.0.21:8080" || acc.Client != "192.0.2.77:40001" {
		t.Fatalf("access line: %+v %v", acc, ok)
	}
	x := Build(Input{State: st, SiteID: id(1), NodeID: id(2), Access: []Access{acc}, Conntrack: []netops.ConntrackFlow{
		// A port forward: 192.0.2.9 -> 203.0.113.1:8443 becomes 10.1.0.30:443.
		{Proto: "tcp", OrigSrc: "192.0.2.9", OrigSport: 5555, OrigDst: "203.0.113.1", OrigDport: 8443,
			ReplySrc: "10.1.0.30", ReplySport: 443, ReplyDst: "192.0.2.9", ReplyDport: 5555, NATed: true},
		// The kernel's load balancer for the resolver.
		{Proto: "udp", OrigSrc: "192.0.2.10", OrigSport: 3000, OrigDst: "203.0.113.1", OrigDport: 53,
			ReplySrc: "10.1.0.53", ReplySport: 53, ReplyDst: "192.0.2.10", ReplyDport: 3000, NATed: true},
		// Not translated: ignored.
		{Proto: "tcp", OrigSrc: "10.1.0.5", OrigSport: 1, OrigDst: "10.1.0.6", OrigDport: 2, ReplySrc: "10.1.0.6", ReplySport: 2,
			ReplyDst: "10.1.0.5", ReplyDport: 1},
	}})
	got := x.Apply([]flows.FlowStats{
		flow("wg0", "tcp", "10.8.0.2", 50000, "10.1.0.5", 22),             // 0 alice over the VPN
		flow("wan0", "udp", "192.0.2.50", 41000, "198.51.100.1", 51820),   // 1 her tunnel's carrier
		flow("tm02c0s0", "tcp", "10.1.0.5", 33000, "10.2.0.9", 443),       // 2 to the branch over the fabric
		flow("wan0", "udp", "198.51.100.1", 52002, "198.51.100.2", 52001), // 3 the fabric tunnel's carrier
		flow("wan0", "tcp", "192.0.2.9", 5555, "203.0.113.1", 8443),       // 4 port forward, outside
		flow("lan0", "tcp", "10.1.0.30", 443, "192.0.2.9", 5555),          // 5 port forward, inside
		flow("wan0", "udp", "203.0.113.1", 53, "192.0.2.10", 3000),        // 6 kernel LB, client side
		flow("lan0", "udp", "10.1.0.53", 53, "192.0.2.10", 3000),          // 7 kernel LB, backend side
		flow("wan0", "tcp", "192.0.2.77", 40001, "203.0.113.1", 443),      // 8 proxy, client side
		flow("lan0", "tcp", "10.1.0.250", 61000, "10.1.0.21", 8080),       // 9 proxy, backend side
		flow("lan0", "tcp", "10.1.0.250", 61001, "10.1.0.20", 8080),       // 10 a pool backend not in the log
		flow("eth9", "tcp", "1.1.1.1", 1, "2.2.2.2", 2),                   // 11 unknown
	})
	want := []flows.Attrs{
		{Site: "hq", Zone: "vpn", Tunnel: "roadwarriors", Peer: "alice-laptop", User: "alice"},
		{Site: "hq", Zone: "wan", Tunnel: "roadwarriors", Carrier: true},
		{Site: "hq", Zone: "fabric", Tunnel: "fabric", Peer: "br1", PeerSite: "branch", Path: "inet"},
		{Site: "hq", Zone: "wan", Tunnel: "fabric", Peer: "br1", PeerSite: "branch", Path: "inet", Carrier: true},
		{Site: "hq", Zone: "wan", PreNAT: "tcp 192.0.2.9:5555 > 203.0.113.1:8443", PostNAT: "tcp 192.0.2.9:5555 > 10.1.0.30:443"},
		{Site: "hq", Zone: "lan", PreNAT: "tcp 192.0.2.9:5555 > 203.0.113.1:8443", PostNAT: "tcp 192.0.2.9:5555 > 10.1.0.30:443"},
		{Site: "hq", Zone: "wan", PreNAT: "udp 192.0.2.10:3000 > 203.0.113.1:53", PostNAT: "udp 192.0.2.10:3000 > 10.1.0.53:53",
			LBRole: "client", LBService: "resolver", LBBackend: "10.1.0.53:53"},
		{Site: "hq", Zone: "lan", PreNAT: "udp 192.0.2.10:3000 > 203.0.113.1:53", PostNAT: "udp 192.0.2.10:3000 > 10.1.0.53:53",
			LBRole: "backend", LBService: "resolver", LBBackend: "10.1.0.53:53"},
		{Site: "hq", Zone: "wan", LBRole: "client", LBService: "web", LBRouter: "app", LBHost: "app.example.com", LBBackend: "10.1.0.21:8080"},
		{Site: "hq", Zone: "lan", LBRole: "backend", LBService: "web", LBRouter: "app", LBHost: "app.example.com", LBBackend: "10.1.0.21:8080"},
		{Site: "hq", Zone: "lan", LBRole: "backend", LBService: "web", LBBackend: "10.1.0.20:8080"},
		{Site: "hq"},
	}
	for i, w := range want {
		g := got[i].Attrs
		c := g.Conversation
		g.Conversation = ""
		if g != w {
			t.Errorf("flow %d (%s %s %s):\n got %+v\nwant %+v", i, got[i].Key.Iface, got[i].Key.A, got[i].Key.B, g, w)
		}
		_ = c
	}
	// Both sides of a translation share a conversation, and so do a
	// client's connection and the backend connection it went to.
	same := func(i, j int) bool {
		return got[i].Attrs.Conversation != "" && got[i].Attrs.Conversation == got[j].Attrs.Conversation
	}
	if !same(4, 5) || !same(6, 7) || !same(8, 9) {
		t.Errorf("conversations: %q %q / %q %q / %q %q", got[4].Attrs.Conversation, got[5].Attrs.Conversation,
			got[6].Attrs.Conversation, got[7].Attrs.Conversation, got[8].Attrs.Conversation, got[9].Attrs.Conversation)
	}
	if same(4, 6) || same(8, 4) {
		t.Error("unrelated flows share a conversation")
	}
	// With the node's addresses known, a connection to port 443 of
	// another machine in the same zone is not the proxy's.
	x2 := Build(Input{State: st, SiteID: id(1), NodeID: id(2), LocalIPs: []string{"203.0.113.1"}})
	if a := x2.Apply([]flows.FlowStats{flow("wan0", "tcp", "192.0.2.77", 40002, "203.0.113.99", 443)})[0].Attrs; a.LBRole != "" {
		t.Errorf("a foreign port 443 was taken for the proxy: %+v", a)
	}
	if a := x2.Apply([]flows.FlowStats{flow("wan0", "tcp", "192.0.2.77", 40002, "203.0.113.1", 443)})[0].Attrs; a.LBRole != "client" {
		t.Errorf("the node's own port 443: %+v", a)
	}
	// Without a model or anything else, nothing is made up.
	if a := Build(Input{}).Apply([]flows.FlowStats{flow("wg0", "tcp", "10.8.0.2", 1, "10.1.0.5", 2)})[0].Attrs; !a.Empty() {
		t.Errorf("empty index attributed %+v", a)
	}
}

func TestAccessLogFollows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	l := &AccessLog{Path: path, Keep: time.Minute}
	now := time.Date(2026, 11, 21, 10, 0, 30, 0, time.UTC)
	if got := l.Read(now); len(got) != 0 {
		t.Fatalf("no file: %v", got)
	}
	f, _ := os.Create(path)
	f.WriteString(sampleLine + "\nnot json\n" + sampleLine[:40]) // the last line is still being written
	if got := l.Read(now); len(got) != 1 {
		t.Fatalf("first read: %d entries", len(got))
	}
	f.WriteString(sampleLine[40:] + "\n")
	if got := l.Read(now); len(got) != 2 {
		t.Fatalf("after the line was finished: %d entries", len(got))
	}
	f.Close()
	// The log is replaced (rotated): read from the start of the new one.
	os.Remove(path)
	os.WriteFile(path, []byte(sampleLine+"\n"), 0o600)
	if got := l.Read(now); len(got) != 3 {
		t.Fatalf("after rotation: %d entries", len(got))
	}
	// Old requests are forgotten.
	if got := l.Read(now.Add(2 * time.Minute)); len(got) != 0 {
		t.Errorf("after the keep time: %d entries", len(got))
	}
}
