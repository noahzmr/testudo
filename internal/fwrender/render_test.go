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

func TestKernelModeBalancing(t *testing.T) {
	f := base(t)
	f.add(
		&model.FirewallPolicy{Meta: meta(699, "default"), DefaultDeny: true, AllowEstablished: true},
		&model.LBBackendPool{Meta: meta(700, "web"), Algorithm: "weighted_round_robin", HealthCheck: model.LBHealthCheck{Type: "tcp"},
			Backends: []model.LBBackend{{Address: "10.0.0.2:8080", Weight: 2}, {Address: "10.0.0.3:8080"}, {Address: "10.0.0.4:8080", Drain: true},
				{Address: "10.0.0.5:8080"}, {Address: "[fd00::2]:8080"}}},
		&model.LBBackendPool{Meta: meta(701, "dns"), Algorithm: "weighted_round_robin", Sticky: true, HealthCheck: model.LBHealthCheck{Type: "none"},
			Backends: []model.LBBackend{{Address: "10.0.0.2:53"}, {Address: "10.0.0.3:53"}}},
		&model.LBService{Meta: meta(710, "web"), Enabled: true, Zone: zone(wan), Port: 443, Protocol: "tcp", Mode: "kernel",
			DefaultPool: model.Ref[model.LBBackendPool]{ID: id(700)}},
		&model.LBService{Meta: meta(711, "dns"), Enabled: true, Zone: zone(wan), Address: "192.0.2.1", Port: 53, Protocol: "udp", Mode: "kernel",
			DefaultPool: model.Ref[model.LBBackendPool]{ID: id(701)}},
		// Proxy-mode services are not the packet filter's business.
		&model.LBService{Meta: meta(712, "proxied"), Enabled: true, Zone: zone(wan), Port: 80, Protocol: "http", Mode: "proxy"},
	)
	o := opts()
	o.BackendDown = map[string]bool{"10.0.0.5:8080": true}
	out := f.render(o)
	for _, want := range []string{
		// Weights 2 and 1; the draining and the failed backend are left out.
		`meta nfproto ipv4 tcp dport 443 counter dnat ip addr . port to numgen inc mod 3 map { 0-1 : 10.0.0.2 . 8080, 2 : 10.0.0.3 . 8080 } comment "` + id(710) + `"`,
		`meta nfproto ipv6 tcp dport 443 counter dnat ip6 addr . port to numgen inc mod 1 map { 0 : fd00::2 . 8080 } comment "` + id(710) + `"`,
		// A listen address fixes the family; sticky hashes the client.
		`ip daddr 192.0.2.1 udp dport 53 counter dnat ip addr . port to jhash ip saddr mod 2 map { 0 : 10.0.0.2 . 53, 1 : 10.0.0.3 . 53 } comment "` + id(711) + `"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "dport 80 ") {
		t.Error("a proxy-mode service was rendered into the packet filter")
	}
	if len(KernelBackends(f.store.Current(), o)) != 2 {
		t.Errorf("pools to health-check: %v", KernelBackends(f.store.Current(), o))
	}
}

// TestHAPairOpensVRRPAndSync: a pair member lets the partner's VRRP adverts
// and state sync in ahead of any policy; a node outside the pair does not.
func TestHAPairOpensVRRPAndSync(t *testing.T) {
	f := newFixture(t)
	pair := &model.HAPair{Meta: meta(40, "edge"), Enabled: true, SyncInterface: "sync0",
		Nodes:     []model.Ref[model.ClusterNode]{{ID: id(node)}, {ID: id(node2)}},
		Instances: []model.VRRPInstance{{Interface: "lan0", VRID: 7, VirtualIPs: []string{"10.0.0.254/24"}}, {Interface: "wan0", VRID: 8, VirtualIPs: []string{"192.0.2.1/24"}}}}
	pair.Scope = model.SiteScope(id(site))
	f.add(
		&model.Site{Meta: meta(site, "hq")},
		&model.ClusterNode{Meta: meta(node, "fw1"), Site: model.Ref[model.Site]{ID: id(site)}, Hostname: "fw1", Address: "10.0.0.1", SyncAddress: "10.9.9.1"},
		&model.ClusterNode{Meta: meta(node2, "fw2"), Site: model.Ref[model.Site]{ID: id(site)}, Hostname: "fw2", Address: "10.0.0.2", SyncAddress: "10.9.9.2"},
		&model.ClusterNode{Meta: meta(4, "fw3"), Site: model.Ref[model.Site]{ID: id(site)}, Hostname: "fw3", Address: "10.0.0.3"},
		&model.FirewallPolicy{Meta: meta(41, "deny"), DefaultDeny: true},
		pair,
	)
	out := f.render(Options{SiteID: id(site), NodeID: id(node)})
	for _, want := range []string{
		`iifname { "lan0", "wan0" } meta l4proto 112 counter accept comment "ha: vrrp"`,
		`iifname "sync0" ip saddr 10.9.9.2 udp dport 3780 counter accept comment "ha: state sync"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if out := f.render(Options{SiteID: id(site), NodeID: id(4)}); strings.Contains(out, "ha: ") {
		t.Errorf("a node outside the pair opens HA traffic:\n%s", out)
	}
}

func siteMeta(n int, name string) model.Meta {
	m := meta(n, name)
	m.Scope = model.SiteScope(id(site))
	return m
}

// TestServicesOpenTheirInterfacesOnly: each service's port is let in on
// the interfaces it serves, and from the networks it names, ahead of any
// policy.
func TestServicesOpenTheirInterfacesOnly(t *testing.T) {
	f := base(t)
	f.add(
		&model.FirewallPolicy{Meta: meta(41, "deny"), DefaultDeny: true},
		&model.DHCPScope{Meta: siteMeta(60, "lan4"), Enabled: true, Interface: "lan0", Subnet: "192.168.1.0/24", Router: "192.168.1.1"},
		&model.DHCPScope{Meta: siteMeta(61, "lan6"), Enabled: true, Interface: "lan1", Subnet: "2001:db8:1::/64"},
		&model.RouterAdvert{Meta: siteMeta(62, "ra"), Enabled: true, Interface: "lan1", Mode: "stateless", Prefixes: []string{"2001:db8:1::/64"}},
		&model.DNSResolver{Meta: meta(63, "dns"), Enabled: true, Interfaces: []string{"lan0", "lan1"}, Mode: "recursive",
			AllowFrom: []string{"10.8.0.0/24", "fd00:8::/64"}},
		&model.NTPService{Meta: meta(64, "ntp"), Enabled: true, Interfaces: []string{"lan0"}, Pools: []string{"pool.ntp.org"},
			AllowFrom: []string{"10.8.0.0/24"}},
	)
	out := f.render(opts())
	for _, want := range []string{
		`iifname { "lan0" } udp dport 67 counter accept comment "service: dhcp"`,
		`iifname { "lan1" } udp dport 547 counter accept comment "service: dhcpv6"`,
		`iifname { "lan1" } icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } counter accept`,
		`iifname { "lan0", "lan1" } meta l4proto { tcp, udp } th dport 53 counter accept comment "service: dns"`,
		`ip saddr { 10.8.0.0/24 } meta l4proto { tcp, udp } th dport 53 counter accept`,
		`ip6 saddr { fd00:8::/64 } meta l4proto { tcp, udp } th dport 53 counter accept`,
		`iifname { "lan0" } udp dport 123 counter accept comment "service: ntp"`,
		`ip saddr { 10.8.0.0/24 } udp dport 123 counter accept comment "service: ntp"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, `"wan0" } meta l4proto { tcp, udp } th dport 53`) || strings.Contains(out, "dhcp failover") {
		t.Errorf("a service is open where it does not run:\n%s", out)
	}
	if t.Failed() {
		t.Log(out)
	}
}
