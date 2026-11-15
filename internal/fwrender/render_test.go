package fwrender

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/testutil/golden"
)

func id(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

func meta(n int, name string) model.Meta { return model.Meta{ID: id(n), Name: name} }

type fixture struct {
	t     *testing.T
	store *confstore.Store
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	s, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return &fixture{t, s}
}

func (f *fixture) add(objs ...model.Entity) {
	f.t.Helper()
	for _, e := range objs {
		if _, err := f.store.Create(context.Background(), "test", e); err != nil {
			f.t.Fatalf("create %s %q: %v", e.Kind(), e.GetMeta().Name, err)
		}
	}
}

func (f *fixture) render(opt Options) string {
	f.t.Helper()
	out, err := Render(f.store.Current(), opt)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(out)
}

const (
	site, node, node2 = 1, 2, 3
	lan, wan, vpn     = 10, 11, 12
)

func zone(n int) model.Ref[model.Zone]   { return model.Ref[model.Zone]{ID: id(n)} }
func alias(n int) model.Ref[model.Alias] { return model.Ref[model.Alias]{ID: id(n)} }

// base is a two-zone router with a VPN: the shape of a small site.
func base(t *testing.T) *fixture {
	f := newFixture(t)
	nodeScope := func(n int, name string) model.Meta { m := meta(n, name); m.Scope = model.NodeScope(id(node)); return m }
	f.add(
		&model.Site{Meta: meta(site, "hq")},
		&model.ClusterNode{Meta: meta(node, "fw1"), Site: model.Ref[model.Site]{ID: id(site)}, Hostname: "fw1", Address: "10.0.0.1"},
		&model.ClusterNode{Meta: meta(node2, "fw2"), Site: model.Ref[model.Site]{ID: id(site)}, Hostname: "fw2", Address: "10.0.0.2"},
		&model.Zone{Meta: meta(lan, "lan"), DefaultAction: "drop", IntraZone: true},
		&model.Zone{Meta: meta(wan, "wan"), DefaultAction: "drop", AntiSpoof: true},
		&model.Zone{Meta: meta(vpn, "vpn"), DefaultAction: "reject"},
		&model.Interface{Meta: nodeScope(20, "lan0"), Device: "lan0", Zone: zone(lan), Enabled: true},
		&model.Interface{Meta: nodeScope(21, "lan1"), Device: "lan1", Zone: zone(lan), Enabled: true},
		&model.Interface{Meta: nodeScope(22, "wan0"), Device: "wan0", Zone: zone(wan), Enabled: true},
		&model.Interface{Meta: func() model.Meta { m := meta(23, "other-node"); m.Scope = model.NodeScope(id(node2)); return m }(),
			Device: "eth9", Zone: zone(wan), Enabled: true},
		&model.WGTunnel{Meta: nodeScope(24, "wg0"), Enabled: true, Device: "wg0", Mode: "road_warrior", ListenPort: 51820,
			Addresses: []string{"10.8.0.1/24"}, PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Zone: zone(vpn)},
		&model.Alias{Meta: meta(30, "web-servers"), Type: "host", Entries: []string{"192.0.2.10", "2001:db8::10"}},
		&model.Alias{Meta: meta(36, "branch-nets"), Type: "network", Entries: []string{"10.20.0.0/16", "2001:db8:20::/48"}},
		&model.Alias{Meta: meta(31, "internal"), Type: "network", Entries: []string{"10.0.0.0/8"}, Members: []model.Ref[model.Alias]{alias(36)}},
		&model.Alias{Meta: meta(32, "web-ports"), Type: "port", Entries: []string{"80", "443", "8000-8099"}},
		&model.Alias{Meta: meta(33, "blocklist"), Type: "url_table", URL: "https://example.net/list.txt", Refresh: "1h"},
		&model.Alias{Meta: meta(34, "v4-only"), Type: "host", Entries: []string{"198.51.100.7"}},
	)
	return f
}

func opts() Options {
	return Options{SiteID: id(site), NodeID: id(node), ProtectedTCPPorts: []int{22, 8080}}
}

// full is the fixture behind the golden file: every feature the renderer has.
func full(t *testing.T) *fixture {
	f := base(t)
	f.add(
		&model.FirewallPolicy{Meta: meta(40, "default"), DefaultDeny: true, AllowEstablished: true, DropInvalid: true,
			AllowLoopback: true, AllowICMP: true, AllowTCPPorts: []string{"443"}, AllowUDPPorts: []string{"51820"},
			SynFloodGuard: true, LogDrops: true, TCPEstablished: "2h", UDPTimeout: "90s"},
		&model.FilterRule{Meta: meta(50, "block-listed"), Sequence: 10, Enabled: true, Action: "drop", Direction: "forward",
			Protocol: "any", Source: []model.Ref[model.Alias]{alias(33)}, Log: true},
		&model.FilterRule{Meta: meta(51, "lan-to-web"), Sequence: 20, Enabled: true, Action: "accept", Direction: "forward",
			Protocol: "tcp", SourceZone: zone(lan), DestinationZone: zone(wan),
			Destination: []model.Ref[model.Alias]{alias(30)}, PortAliases: []model.Ref[model.Alias]{alias(32)}, States: []string{"new"}},
		&model.FilterRule{Meta: meta(52, "vpn-dns"), Sequence: 30, Enabled: true, Action: "accept", Direction: "forward",
			Protocol: "any", SourceZone: zone(vpn), SourceNets: []string{"10.8.0.0/24"}, DestinationNets: []string{"10.0.0.53"},
			Ports: []string{"53"}, RateLimit: "100/second"},
		&model.FilterRule{Meta: meta(53, "mixed-families"), Sequence: 40, Enabled: true, Action: "accept", Direction: "forward",
			Protocol: "tcp", Source: []model.Ref[model.Alias]{alias(34)}, Destination: []model.Ref[model.Alias]{alias(31)}, Ports: []string{"22"}},
		&model.FilterRule{Meta: meta(54, "mgmt-from-lan"), Sequence: 50, Enabled: true, Action: "accept", Direction: "in",
			Protocol: "tcp", SourceZone: zone(lan), Ports: []string{"9090"}, Mark: 0x10},
		&model.FilterRule{Meta: meta(55, "no-smtp-out"), Sequence: 60, Enabled: true, Action: "reject", Direction: "out",
			Protocol: "tcp", DestinationZone: zone(wan), Ports: []string{"25"}},
		&model.FilterRule{Meta: meta(56, "disabled"), Sequence: 70, Enabled: false, Action: "accept", Direction: "forward", Protocol: "any"},
		&model.NATRule{Meta: meta(60, "publish-web"), Enabled: true, Sequence: 10, Type: "dnat", Zone: zone(wan), Protocol: "tcp",
			Destination: "203.0.113.5", Port: "443", TranslateTo: "192.0.2.10", TranslatePort: "8443", Reflection: true},
		&model.NATRule{Meta: meta(61, "publish-v6"), Enabled: true, Sequence: 20, Type: "dnat", Zone: zone(wan), Protocol: "tcp",
			Port: "443", TranslateTo: "2001:db8::10", TranslatePort: "8443"},
		&model.NATRule{Meta: meta(62, "outbound"), Enabled: true, Sequence: 30, Type: "masquerade", Zone: zone(wan), Protocol: "any",
			SourceNets: []string{"10.0.0.0/8", "10.8.0.0/24"}},
		&model.NATRule{Meta: meta(63, "mail-out"), Enabled: true, Sequence: 40, Type: "snat", Zone: zone(wan), Protocol: "tcp",
			SourceNets: []string{"10.0.0.25"}, Port: "25", TranslateTo: "203.0.113.6"},
		&model.NATRule{Meta: meta(64, "one-to-one"), Enabled: true, Sequence: 50, Type: "one_to_one", Zone: zone(wan), Protocol: "any",
			Destination: "203.0.113.7", TranslateTo: "10.0.0.7"},
	)
	return f
}

func TestRenderGolden(t *testing.T) {
	f := full(t)
	out := f.render(opts())
	golden.Assert(t, "site.nft", []byte(out))

	// Things a reviewer should not have to find in the golden file.
	for _, want := range []string{
		"tcp dport { 22, 443, 8080 } accept", // protected ports merged with the policy's
		`elements = { "lan0", "lan1" }`,      // zone set from this node's interfaces
		"policy drop;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ruleset lacks %q", want)
		}
	}
	for _, not := range []string{"eth9", id(56)} { // another node's interface, a disabled rule
		if strings.Contains(out, not) {
			t.Errorf("ruleset contains %q", not)
		}
	}
	// A rule whose source is IPv4-only must not produce an IPv6 variant.
	if n := strings.Count(out, id(53)); n != 1 {
		t.Errorf("mixed-family rule rendered %d times, want 1 (IPv4 only)", n)
	}
	// A rule without address constraints is family-agnostic: one line.
	if n := strings.Count(out, id(54)); n != 1 {
		t.Errorf("unconstrained rule rendered %d times", n)
	}
}

func TestNoPolicyRendersAnInertRuleset(t *testing.T) {
	f := base(t)
	want := "table inet testudo\ndelete table inet testudo\n"
	if got := f.render(opts()); got != want {
		t.Errorf("without a firewall policy:\n%s", got)
	}
}

func TestProtectedPortsSurviveAnyPolicy(t *testing.T) {
	f := base(t)
	f.add(&model.FirewallPolicy{Meta: meta(40, "bare"), DefaultDeny: true})
	out := f.render(opts())
	if !strings.Contains(out, "tcp dport { 22, 8080 } accept") {
		t.Errorf("a policy without any baseline dropped the protected ports:\n%s", out)
	}
	if strings.Contains(out, "established") {
		t.Errorf("baseline options are not honoured:\n%s", out)
	}
}

func TestPolicyScopeAndOverrides(t *testing.T) {
	f := base(t)
	global := &model.FirewallPolicy{Meta: meta(40, "global"), DefaultDeny: false, AllowEstablished: true}
	nodePol := &model.FirewallPolicy{Meta: meta(41, "fw1"), DefaultDeny: true, AllowEstablished: true}
	nodePol.Scope = model.NodeScope(id(node))
	a := &model.Alias{Meta: meta(35, "dns"), Type: "host", Entries: []string{"192.0.2.53"}}
	a.Overrides = []model.Override{{Scope: model.NodeScope(id(node2)), Values: map[string]any{"entries": []any{"198.51.100.53"}}}}
	f.add(global, nodePol, a,
		&model.FilterRule{Meta: meta(50, "to-dns"), Enabled: true, Action: "accept", Direction: "forward", Protocol: "udp",
			Destination: []model.Ref[model.Alias]{alias(35)}, Ports: []string{"53"}})

	fw1 := f.render(opts())
	if !strings.Contains(fw1, "hook forward priority filter; policy drop;") || !strings.Contains(fw1, "ip daddr { 192.0.2.53 }") {
		t.Errorf("fw1 should use its node policy and the base alias:\n%s", fw1)
	}
	o2 := opts()
	o2.NodeID = id(node2)
	fw2 := f.render(o2)
	if !strings.Contains(fw2, "hook forward priority filter; policy accept;") || !strings.Contains(fw2, "ip daddr { 198.51.100.53 }") {
		t.Errorf("fw2 should use the global policy and its alias override:\n%s", fw2)
	}
	// Without default deny, a zone's own default action closes the zone.
	if !strings.Contains(fw2, "counter drop") || !strings.Contains(fw2, "counter reject") {
		t.Errorf("zone defaults missing on fw2:\n%s", fw2)
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	f := base(t)
	f.add(&model.FirewallPolicy{Meta: meta(40, "p"), DefaultDeny: true, AllowEstablished: true})
	first := f.render(opts())
	for i := 0; i < 20; i++ {
		if f.render(opts()) != first {
			t.Fatal("two renders of the same state differ")
		}
	}
}

func TestAccessPoliciesFollowIdentity(t *testing.T) {
	f := base(t)
	user := func(n int) model.Ref[model.User] { return model.Ref[model.User]{ID: id(n)} }
	group := func(n int) model.Ref[model.Group] { return model.Ref[model.Group]{ID: id(n)} }
	tun := model.Ref[model.WGTunnel]{ID: id(24)}
	key := func(c string) string { return strings.Repeat(c, 42) + "A=" }
	f.add(
		&model.FirewallPolicy{Meta: meta(40, "default"), DefaultDeny: true, AllowEstablished: true},
		&model.Group{Meta: meta(70, "engineers")},
		&model.User{Meta: meta(71, "alice"), Username: "alice", Source: "host"},
		&model.User{Meta: meta(72, "bob"), Username: "bob", Source: "host", Groups: []model.Ref[model.Group]{group(70)}},
		&model.User{Meta: meta(73, "carol"), Username: "carol", Source: "host", Disabled: true},
		&model.WGPeer{Meta: meta(80, "alice-laptop"), Enabled: true, Tunnel: tun, PublicKey: key("A"), AllowedIPs: []string{"10.8.0.2/32", "fd08::2/128"}, User: user(71)},
		&model.WGPeer{Meta: meta(81, "bob-phone"), Enabled: true, Tunnel: tun, PublicKey: key("B"), AllowedIPs: []string{"10.8.0.3/32"}, User: user(72)},
		&model.WGPeer{Meta: meta(82, "carol-pc"), Enabled: true, Tunnel: tun, PublicKey: key("C"), AllowedIPs: []string{"10.8.0.4/32"}, User: user(73)},
		&model.WGPeer{Meta: meta(83, "kiosk"), Enabled: true, Tunnel: tun, PublicKey: key("D"), AllowedIPs: []string{"10.8.0.5/32"}},
		&model.WGPeer{Meta: meta(84, "revoked"), Enabled: false, Tunnel: tun, PublicKey: key("E"), AllowedIPs: []string{"10.8.0.6/32"}, User: user(71)},
		&model.AccessResource{Meta: meta(90, "git"), Type: "network", Target: "10.50.0.10", Protocol: "tcp", Ports: "22"},
		&model.AccessResource{Meta: meta(91, "wiki"), Type: "network", Target: "10.50.0.0/24", Protocol: "any"},
		&model.AccessResource{Meta: meta(92, "vault"), Type: "ssh", Target: "10.50.0.99", Protocol: "tcp", Ports: "22"},
		&model.AccessResource{Meta: meta(93, "v6-app"), Type: "network", Target: "2001:db8::10", Protocol: "tcp", Ports: "443"},
		&model.AccessPolicy{Meta: meta(95, "git-for-alice"), Resource: model.Ref[model.AccessResource]{ID: id(90)}, Users: []model.Ref[model.User]{user(71)}, MaxDuration: "8h"},
		&model.AccessPolicy{Meta: meta(96, "wiki-for-engineers"), Resource: model.Ref[model.AccessResource]{ID: id(91)}, Groups: []model.Ref[model.Group]{group(70)}, MaxDuration: "8h"},
		&model.AccessPolicy{Meta: meta(97, "vault-needs-approval"), Resource: model.Ref[model.AccessResource]{ID: id(92)}, Everyone: true, MaxDuration: "1h", RequiresApproval: true},
		&model.AccessPolicy{Meta: meta(98, "v6-for-everyone"), Resource: model.Ref[model.AccessResource]{ID: id(93)}, Everyone: true, MaxDuration: "8h"},
	)
	out := f.render(opts())
	line := func(policy int) string {
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, id(policy)) {
				return strings.TrimSpace(l)
			}
		}
		return ""
	}
	want := map[int]string{
		// named user: only alice's enabled device
		95: `iifname "wg0" ip saddr { 10.8.0.2 } ip daddr 10.50.0.10 meta l4proto tcp th dport { 22 } counter accept comment "` + id(95) + `"`,
		// group through the user: bob
		96: `iifname "wg0" ip saddr { 10.8.0.3 } ip daddr 10.50.0.0/24 counter accept comment "` + id(96) + `"`,
		// everyone means everyone with an identity, and an IPv6 resource
		// matches IPv6 tunnel addresses only: alice has one
		98: `iifname "wg0" ip6 saddr { fd08::2 } ip6 daddr 2001:db8::10 meta l4proto tcp th dport { 443 } counter accept comment "` + id(98) + `"`,
	}
	for policy, w := range want {
		if got := line(policy); got != w {
			t.Errorf("policy %d:\n got %s\nwant %s", policy, got, w)
		}
	}
	// A policy that needs approval grants nothing by itself.
	if l := line(97); l != "" {
		t.Errorf("approval-gated policy rendered a standing rule: %s", l)
	}
	// Nobody without an identity, no disabled user, no revoked device.
	for _, addr := range []string{"10.8.0.4", "10.8.0.5", "10.8.0.6"} {
		if strings.Contains(out, addr) {
			t.Errorf("address %s got access", addr)
		}
	}
}
