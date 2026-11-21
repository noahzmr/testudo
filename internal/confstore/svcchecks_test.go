package confstore

import (
	"strings"
	"testing"

	"github.com/noahzmr/testudo/internal/model"
)

func TestServiceChecks(t *testing.T) {
	s := open(t)
	site := mustCreate(t, s, "a", &model.Site{Meta: model.Meta{Name: "hq"}})
	at := func(m model.Meta) model.Meta { m.Scope = model.SiteScope(site.GetMeta().ID); return m }
	scope := func(name, iface, subnet string) *model.DHCPScope {
		return &model.DHCPScope{Meta: at(model.Meta{Name: name}), Enabled: true, Interface: iface, Subnet: subnet}
	}
	refuse := func(e model.Entity, want string) {
		t.Helper()
		if _, err := s.Create(ctx, "a", e); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", e.GetMeta().Name, err, want)
		}
	}
	with := func(d *model.DHCPScope, f func(*model.DHCPScope)) *model.DHCPScope { f(d); return d }

	refuse(with(scope("pool-out", "lan", "192.168.1.0/24"), func(d *model.DHCPScope) { d.Pools = []string{"192.168.2.10-192.168.2.20"} }), "not inside")
	refuse(with(scope("router-out", "lan", "192.168.1.0/24"), func(d *model.DHCPScope) { d.Router = "10.0.0.1" }), "not inside")
	refuse(with(scope("v6-router", "lan", "2001:db8:1::/64"), func(d *model.DHCPScope) { d.Router = "2001:db8:1::1" }), "router advertisements")
	refuse(with(scope("dns-family", "lan", "192.168.1.0/24"), func(d *model.DHCPScope) { d.DNSServers = []string{"2001:db8::53"} }), "not an IPv4 address")
	refuse(with(scope("no-mac", "lan", "192.168.1.0/24"), func(d *model.DHCPScope) {
		d.Reservations = []model.DHCPReservation{{Address: "192.168.1.5"}}
	}), "needs a hardware address")
	refuse(with(scope("twice", "lan", "192.168.1.0/24"), func(d *model.DHCPScope) {
		d.Reservations = []model.DHCPReservation{{MAC: "52:54:00:00:00:01", Address: "192.168.1.5"}, {MAC: "52:54:00:00:00:01", Address: "192.168.1.6"}}
	}), "two reservations")
	mustCreate(t, s, "a", with(scope("lan4", "lan", "192.168.1.0/24"), func(d *model.DHCPScope) {
		d.Pools = []string{"192.168.1.100-192.168.1.199", "192.168.1.224/27"}
		d.Reservations = []model.DHCPReservation{{MAC: "52:54:00:00:00:01", Address: "192.168.1.5", Hostname: "nas"}}
	}))
	mustCreate(t, s, "a", scope("lan6", "lan", "2001:db8:1::/64"))
	refuse(scope("lan4-again", "lan", "192.168.7.0/24"), "already has a IPv4 scope")

	ra := func(name string, prefixes ...string) *model.RouterAdvert {
		return &model.RouterAdvert{Meta: at(model.Meta{Name: name}), Enabled: true, Interface: "lan", Mode: "slaac", Prefixes: prefixes}
	}
	refuse(ra("wide", "2001:db8:1::/56"), "/64")
	mustCreate(t, s, "a", ra("lan-ra", "2001:db8:1::/64"))
	refuse(ra("lan-ra-2"), "announced already")

	res := func(name string, f func(*model.DNSResolver)) *model.DNSResolver {
		r := &model.DNSResolver{Meta: at(model.Meta{Name: name}), Enabled: true, Interfaces: []string{"lan"}, Mode: "recursive", DNSSEC: true}
		f(r)
		return r
	}
	refuse(res("fwd", func(r *model.DNSResolver) { r.Mode = "forward" }), "upstreams")
	refuse(res("tls", func(r *model.DNSResolver) { r.Mode, r.Upstreams, r.TLS = "forward", []string{"9.9.9.9"}, true }), "needs #name")
	mustCreate(t, s, "a", res("resolver", func(*model.DNSResolver) {}))
	refuse(res("resolver-2", func(*model.DNSResolver) {}), "one DNS resolver per scope")

	refuse(&model.NTPService{Meta: at(model.Meta{Name: "ntp"}), Enabled: true, Interfaces: []string{"lan"}}, "at least one server")
	mustCreate(t, s, "a", &model.NTPService{Meta: at(model.Meta{Name: "ntp"}), Enabled: true, Interfaces: []string{"lan"}, Pools: []string{"2.debian.pool.ntp.org"}})

	rec := func(name, typ, value string) *model.DNSRecord {
		return &model.DNSRecord{Meta: model.Meta{Name: name}, Host: "nas.home.arpa", Type: typ, Value: value}
	}
	refuse(rec("a6", "A", "2001:db8::1"), "IPv4")
	refuse(rec("aaaa4", "AAAA", "192.0.2.1"), "IPv6")
	refuse(rec("cname-ip", "CNAME", "192.0.2.1"), "host name")
	mustCreate(t, s, "a", rec("nas", "A", "192.168.1.5"))
	refuse(rec("nas-again", "A", "192.168.1.5"), "same record")
}
