package svcrender

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

func id(n int) string                    { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func meta(n int, name string) model.Meta { return model.Meta{ID: id(n), Name: name} }

const site, fw1, fw2 = 1, 2, 3

func atSite(m model.Meta) model.Meta { m.Scope = model.SiteScope(id(site)); return m }
func atNode(m model.Meta, n int) model.Meta {
	m.Scope = model.NodeScope(id(n))
	return m
}

// lan is a site with two nodes, each with a LAN interface in the model,
// and every service on the LAN.
func lan(t *testing.T, extra ...model.Entity) *confstore.State {
	t.Helper()
	s, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	at := model.Ref[model.Site]{ID: id(site)}
	objs := []model.Entity{
		&model.Site{Meta: meta(site, "hq")},
		&model.ClusterNode{Meta: meta(fw1, "fw1"), Site: at, Hostname: "fw1", Address: "10.255.0.1", SyncAddress: "10.9.9.1"},
		&model.ClusterNode{Meta: meta(fw2, "fw2"), Site: at, Hostname: "fw2", Address: "10.255.0.2", SyncAddress: "10.9.9.2"},
		&model.Interface{Meta: atNode(meta(10, "fw1-lan"), fw1), Device: "lan", Enabled: true, Addresses: []string{"192.168.1.2/24", "2001:db8:1::2/64"}},
		&model.Interface{Meta: atNode(meta(11, "fw2-lan"), fw2), Device: "lan", Enabled: true, Addresses: []string{"192.168.1.3/24", "2001:db8:1::3/64"}},
		&model.DNSResolver{Meta: atSite(meta(20, "resolver")), Enabled: true, Interfaces: []string{"lan"}, Mode: "recursive", DNSSEC: true,
			DomainForwards: []model.DomainForward{{Domain: "corp.example", Servers: []string{"10.20.0.53"}}}},
		&model.NTPService{Meta: atSite(meta(21, "ntp")), Enabled: true, Interfaces: []string{"lan"}, Pools: []string{"2.debian.pool.ntp.org"}},
		&model.DHCPScope{Meta: atSite(meta(30, "lan4")), Enabled: true, Interface: "lan", Subnet: "192.168.1.0/24",
			Pools: []string{"192.168.1.100-192.168.1.199"}, RegisterDNS: true,
			Reservations: []model.DHCPReservation{{MAC: "52:54:00:AA:00:01", Address: "192.168.1.10", Hostname: "nas"}}},
		&model.DHCPScope{Meta: atSite(meta(31, "lan6")), Enabled: true, Interface: "lan", Subnet: "2001:db8:1::/64",
			Pools: []string{"2001:db8:1::1000-2001:db8:1::1fff"}},
		&model.RouterAdvert{Meta: atSite(meta(32, "lan-ra")), Enabled: true, Interface: "lan", Mode: "stateless"},
		&model.DNSRecord{Meta: meta(40, "printer"), Host: "printer.home.arpa", Type: "A", Value: "192.168.1.40"},
	}
	for _, e := range append(objs, extra...) {
		if _, err := s.Create(context.Background(), "test", e); err != nil {
			t.Fatalf("create %s: %v", e.GetMeta().Name, err)
		}
	}
	return s.Current()
}

func render(t *testing.T, st *confstore.State, node int) Result {
	t.Helper()
	res, err := Render(st, Options{SiteID: id(site), NodeID: id(node), Dir: "/var/lib/testudo/services", RunDir: "/run/testudo-svc",
		HooksDir: "/usr/lib/x86_64-linux-gnu/kea/hooks"})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func contains(t *testing.T, what, text string, want ...string) {
	t.Helper()
	flat := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	for _, w := range want {
		if !strings.Contains(text, w) && !strings.Contains(flat(text), flat(w)) {
			t.Errorf("%s lacks %q:\n%s", what, w, text)
		}
	}
}

func TestEveryServiceOnTheLAN(t *testing.T) {
	res := render(t, lan(t), fw1)
	if got := strings.Join(res.Daemons, ","); got != "unbound,chronyd,kea-dhcp4,kea-dhcp6,radvd" {
		t.Errorf("daemons: %s", got)
	}
	o := res.Open
	if fmt.Sprint(o.DHCP4, o.DHCP6, o.DNS, o.NTP) != "[lan] [lan] [lan] [lan]" || o.HA != nil {
		t.Errorf("openings: %+v", o)
	}

	var kea4 struct{ Dhcp4 map[string]any }
	if err := json.Unmarshal([]byte(res.Files[Kea4Conf]), &kea4); err != nil {
		t.Fatal(err)
	}
	k4 := res.Files[Kea4Conf]
	contains(t, "kea-dhcp4.conf", k4,
		`"pool": "192.168.1.100 - 192.168.1.199"`,
		// Defaults point at this node: gateway, resolver and NTP.
		`"data": "192.168.1.2", "name": "routers"`,
		`"name": "domain-name-servers"`, `"name": "ntp-servers"`, `"data": "home.arpa"`,
		`"hw-address": "52:54:00:aa:00:01"`, `"hostname": "nas.home.arpa"`,
		`"ddns-send-updates": true`, `"ddns-qualifying-suffix": "home.arpa."`, `"enable-updates": true`,
		`"dhcp-socket-type": "raw"`, `libdhcp_lease_cmds.so`, `/var/lib/testudo/services/kea-leases4.csv`, `/run/testudo-svc/kea4.sock`)
	if strings.Contains(k4, "libdhcp_ha.so") {
		t.Error("a single node renders HA")
	}
	contains(t, "kea-dhcp6.conf", res.Files[Kea6Conf], `"pool": "2001:db8:1::1000 - 2001:db8:1::1fff"`, `"name": "dns-servers"`,
		`"data": "2001:db8:1::2"`, `"type": "EN"`, `"preferred-lifetime": 2700`)

	u := res.Files[UnboundConf]
	contains(t, "unbound.conf", u, `interface: 192.168.1.2`, `interface-action: 2001:db8:1::2 allow`,
		`module-config: "validator iterator"`, `local-zone: "home.arpa." static`,
		`local-data: 'nas.home.arpa. 3600 IN A 192.168.1.10'`, `local-data: '10.1.168.192.in-addr.arpa. 3600 IN PTR nas.home.arpa.'`,
		`local-data: 'printer.home.arpa. 3600 IN A 192.168.1.40'`,
		`private-domain: "corp.example."`, `domain-insecure: "corp.example."`, "forward-zone:\n  name: \"corp.example.\"\n  forward-addr: 10.20.0.53",
		`include: "/run/testudo-svc/dns-leases.conf"`, `control-interface: "/run/testudo-svc/unbound.ctl"`)
	if strings.Contains(u, `name: "."`) {
		t.Error("a recursive resolver forwards everything")
	}

	contains(t, "chrony.conf", res.Files[ChronyConf], "pool 2.debian.pool.ntp.org iburst", "allow 192.168.1.0/24", "allow 2001:db8:1::/64", "rtcsync", "bindcmdaddress /")
	contains(t, "radvd.conf", res.Files[RadvdConf], "interface lan {", "AdvManagedFlag off;", "AdvOtherConfigFlag on;",
		"prefix 2001:db8:1::/64 {", "AdvAutonomous on;", "RDNSS 2001:db8:1::2 {", "DNSSL home.arpa {")
	if got := strings.Join(res.StaticNames, ","); got != "nas.home.arpa,printer.home.arpa" {
		t.Errorf("static names: %s", got)
	}
	if len(res.Scopes) != 2 || !res.Scopes[0].Register || res.Scopes[0].Domain != "home.arpa" || res.Scopes[1].Register {
		t.Errorf("scopes: %+v", res.Scopes)
	}
}

func TestForwardingOverTLS(t *testing.T) {
	st := lan(t)
	// Override the site's resolver on fw1 only.
	r := &model.DNSResolver{Meta: atNode(meta(22, "fw1-resolver"), fw1), Enabled: true, Interfaces: []string{"lan"}, Mode: "forward", TLS: true,
		Upstreams: []string{"9.9.9.9#dns.quad9.net", "149.112.112.112@853#dns.quad9.net"}}
	st2 := lan(t, r)
	_ = st
	u := render(t, st2, fw1).Files[UnboundConf]
	contains(t, "unbound.conf", u, "forward-zone:\n  name: \".\"", "forward-addr: 9.9.9.9@853#dns.quad9.net",
		"forward-addr: 149.112.112.112@853#dns.quad9.net", "forward-tls-upstream: yes", `module-config: "iterator"`, "tls-cert-bundle")
	// fw2 keeps the site's resolver.
	if strings.Contains(render(t, st2, fw2).Files[UnboundConf], "forward-tls-upstream") {
		t.Error("the node override reached the other node")
	}
}

// TestPairSharesLeases: on an HA pair both Kea servers run hot-standby over
// the sync link, and clients are pointed at the virtual address.
func TestPairSharesLeases(t *testing.T) {
	pair := &model.HAPair{Meta: atSite(meta(50, "edge")), Enabled: true, SyncInterface: "sync0",
		Nodes:     []model.Ref[model.ClusterNode]{{ID: id(fw1)}, {ID: id(fw2)}},
		Instances: []model.VRRPInstance{{Interface: "lan", VRID: 7, VirtualIPs: []string{"192.168.1.1/24"}}}}
	st := lan(t, pair)
	a, b := render(t, st, fw1), render(t, st, fw2)
	for name, res := range map[string]Result{"fw1": a, "fw2": b} {
		k4 := res.Files[Kea4Conf]
		contains(t, name+" kea-dhcp4.conf", k4, "libdhcp_ha.so", `"mode": "hot-standby"`, `"this-server-name": "`+name+`"`,
			`"url": "http://10.9.9.1:8000/"`, `"role": "primary"`, `"url": "http://10.9.9.2:8000/"`, `"role": "standby"`,
			`"http-dedicated-listener": true`, `"enable-multi-threading": true`,
			// The gateway and the resolver are the pair's virtual address.
			`"data": "192.168.1.1"`)
		if res.Open.HA == nil || res.Open.HA.Interface != "sync0" || fmt.Sprint(res.Open.HA.Ports) != "[8000 8001]" {
			t.Errorf("%s HA opening: %+v", name, res.Open.HA)
		}
		contains(t, name+" unbound.conf", res.Files[UnboundConf], "interface: 192.168.1.1\n", "ip-freebind: yes")
	}
	if a.Open.HA.Peer != "10.9.9.2" || b.Open.HA.Peer != "10.9.9.1" {
		t.Errorf("peers: %s %s", a.Open.HA.Peer, b.Open.HA.Peer)
	}
	// A scope on one node only cannot be half of a pair.
	solo := &model.DHCPScope{Meta: atNode(meta(33, "solo"), fw1), Enabled: true, Interface: "guest", Subnet: "192.168.9.0/24", Router: "192.168.9.1"}
	_, err := Render(lan(t, pair, solo), Options{SiteID: id(site), NodeID: id(fw1), Dir: "/d", RunDir: "/r", HooksDir: "/h"})
	if err == nil || !strings.Contains(err.Error(), "put the scope at the site") {
		t.Errorf("node-only scope on a pair: %v", err)
	}
}

func TestNothingConfiguredRunsNothing(t *testing.T) {
	s, err := confstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	res, err := Render(s.Current(), Options{SiteID: id(site), NodeID: id(fw1)})
	if err != nil || res.Enabled() || len(res.Files) != 0 {
		t.Fatalf("empty model: %+v %v", res, err)
	}
}

func TestReverseNames(t *testing.T) {
	if got := PTRName(net.ParseIP("192.168.1.10")); got != "10.1.168.192.in-addr.arpa." {
		t.Error(got)
	}
	if got := PTRName(net.ParseIP("2001:db8::1")); !strings.HasPrefix(got, "1.0.0.0.") || !strings.HasSuffix(got, "8.b.d.0.1.0.0.2.ip6.arpa.") {
		t.Error(got)
	}
}

// TestRelayToAnotherServer: a relayed interface passes requests from one
// of its own addresses to each server, for the server's family; the
// filter opens DHCP on it and the servers' answers. An interface that a
// scope of the same family serves cannot be relayed, nor one without an
// address of the server's family.
func TestRelayToAnotherServer(t *testing.T) {
	guest := &model.Interface{Meta: atNode(meta(12, "fw1-guest"), fw1), Device: "guest", Enabled: true, Addresses: []string{"10.50.0.1/24"}}
	relay := &model.DHCPRelay{Meta: atSite(meta(50, "to-corp")), Enabled: true, Interfaces: []string{"guest"}, Servers: []string{"10.20.0.67"}}
	res := render(t, lan(t, guest, relay), fw1)
	conf := res.Files[RelayConf]
	contains(t, "relay", conf, "port=0", "interface=guest", "dhcp-relay=10.50.0.1,10.20.0.67")
	if !strings.Contains(strings.Join(res.Daemons, " "), DaemonRelay) {
		t.Errorf("daemons: %v", res.Daemons)
	}
	if !strings.Contains(strings.Join(res.Open.DHCP4, " "), "guest") || strings.Join(res.Open.RelayFrom, " ") != "10.20.0.67" {
		t.Errorf("openings: %+v", res.Open)
	}

	// The LAN has its own DHCPv4 scope; an IPv6 server for it is fine, an
	// IPv4 one is not. The guest network has no IPv6 address.
	for _, tc := range []struct {
		ifaces, servers []string
		want            string
	}{
		{[]string{"lan"}, []string{"10.20.0.67"}, "served by a DHCP scope"},
		{[]string{"guest"}, []string{"2001:db8:20::67"}, "no address of the family"},
	} {
		bad := &model.DHCPRelay{Meta: atSite(meta(51, "bad")), Enabled: true, Interfaces: tc.ifaces, Servers: tc.servers}
		_, err := Render(lan(t, guest, bad), Options{SiteID: id(site), NodeID: id(fw1)})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v to %v: %v", tc.ifaces, tc.servers, err)
		}
	}
}
