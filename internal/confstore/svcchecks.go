package confstore

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/noahzmr/testudo/internal/model"
)

// serviceChecks keep DHCP, router advertisements, DNS and NTP coherent:
// addresses inside their subnet and family, one scope per interface and
// family, one resolver and one NTP service per scope, records that match
// their type.
func serviceChecks(s *State, add func(model.Entity, string, string, ...any)) {
	type ifKey struct {
		scope model.Scope
		iface string
		v6    bool
	}
	scopes := map[ifKey]string{}
	for _, e := range sortedByName(s.objects[model.KindDHCPScope]) {
		d := e.(*model.DHCPScope)
		_, subnet, err := net.ParseCIDR(d.Subnet)
		if err != nil {
			continue
		}
		v6 := subnet.IP.To4() == nil
		k := ifKey{d.Scope, d.Interface, v6}
		if other, dup := scopes[k]; dup {
			add(d, "interface", "%s already has a %s scope here: %q", d.Interface, family(v6), other)
		}
		scopes[k] = d.Name
		for _, p := range d.Pools {
			first, last, ok := poolBounds(p)
			if !ok || !subnet.Contains(first) || !subnet.Contains(last) {
				add(d, "pools", "pool %s is not inside %s", p, d.Subnet)
			}
		}
		if d.Router != "" {
			if v6 {
				add(d, "router", "IPv6 clients learn their router from router advertisements, not DHCP")
			} else if !subnet.Contains(net.ParseIP(d.Router)) {
				add(d, "router", "%s is not inside %s", d.Router, d.Subnet)
			}
		}
		for _, list := range [][]string{d.DNSServers, d.NTPServers} {
			for _, a := range list {
				if ip := net.ParseIP(a); ip != nil && (ip.To4() == nil) != v6 {
					add(d, "dns_servers", "%s is not an %s address", a, family(v6))
				}
			}
		}
		addrs, macs, duids := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, r := range d.Reservations {
			ip := net.ParseIP(r.Address)
			if ip == nil || !subnet.Contains(ip) {
				add(d, "reservations", "%s is not inside %s", r.Address, d.Subnet)
			}
			if addrs[r.Address] {
				add(d, "reservations", "%s is reserved twice", r.Address)
			}
			addrs[r.Address] = true
			switch {
			case !v6 && r.MAC == "":
				add(d, "reservations", "the reservation of %s needs a hardware address", r.Address)
			case v6 && r.MAC == "" && r.DUID == "":
				add(d, "reservations", "the reservation of %s needs a DUID or a hardware address", r.Address)
			}
			if m := strings.ToLower(r.MAC); m != "" {
				if macs[m] {
					add(d, "reservations", "%s has two reservations", r.MAC)
				}
				macs[m] = true
			}
			if u := strings.ToLower(r.DUID); u != "" {
				if duids[u] {
					add(d, "reservations", "%s has two reservations", r.DUID)
				}
				duids[u] = true
			}
		}
	}

	ras := map[ifKey]string{}
	for _, e := range sortedByName(s.objects[model.KindRouterAdvert]) {
		r := e.(*model.RouterAdvert)
		k := ifKey{r.Scope, r.Interface, true}
		if other, dup := ras[k]; dup {
			add(r, "interface", "%s is announced already by %q", r.Interface, other)
		}
		ras[k] = r.Name
		for _, p := range r.Prefixes {
			if _, n, err := net.ParseCIDR(p); err == nil {
				if ones, bits := n.Mask.Size(); bits != 128 || ones != 64 {
					add(r, "prefixes", "%s: address autoconfiguration needs an IPv6 /64", p)
				}
			}
		}
		for _, a := range r.DNS {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				add(r, "dns", "%s is not an IPv6 address", a)
			}
		}
	}

	one := func(kind model.Kind, what string) {
		seen := map[model.Scope]string{}
		for _, e := range sortedByName(s.objects[kind]) {
			m := e.GetMeta()
			if other, dup := seen[m.Scope]; dup {
				add(e, "scope", "one %s per scope; %q is here already", what, other)
			}
			seen[m.Scope] = m.Name
		}
	}
	one(model.KindDNSResolver, "DNS resolver")
	one(model.KindNTPService, "NTP service")
	for _, e := range s.objects[model.KindDNSResolver] {
		r := e.(*model.DNSResolver)
		if r.TLS {
			for _, u := range r.Upstreams {
				if !strings.Contains(u, "#") {
					add(r, "upstreams", "%s: an upstream over TLS needs #name, the name on its certificate", u)
				}
			}
		}
		domains := map[string]bool{}
		for _, f := range r.DomainForwards {
			d := strings.ToLower(strings.TrimSuffix(f.Domain, "."))
			if domains[d] {
				add(r, "domain_forwards", "%s is forwarded twice", f.Domain)
			}
			domains[d] = true
		}
	}
	for _, e := range s.objects[model.KindNTPService] {
		n := e.(*model.NTPService)
		if n.Enabled && len(n.Servers) == 0 && len(n.Pools) == 0 {
			add(n, "servers", "name at least one server or pool to take the time from")
		}
	}
	records := map[string]string{}
	for _, e := range sortedByName(s.objects[model.KindDNSRecord]) {
		r := e.(*model.DNSRecord)
		ip := net.ParseIP(r.Value)
		switch r.Type {
		case "A":
			if ip == nil || ip.To4() == nil {
				add(r, "value", "an A record needs an IPv4 address")
			}
		case "AAAA":
			if ip == nil || ip.To4() != nil {
				add(r, "value", "an AAAA record needs an IPv6 address")
			}
		case "CNAME":
			if ip != nil || !model.ValidHostname(r.Value) {
				add(r, "value", "a CNAME record needs a host name")
			}
		case "TXT":
			if strings.ContainsAny(r.Value, "\"\n") {
				add(r, "value", "a TXT record cannot contain quotes or line breaks")
			}
		}
		k := fmt.Sprintf("%s|%s|%s|%s", r.Scope, strings.ToLower(strings.TrimSuffix(r.Host, ".")), r.Type, r.Value)
		if other, dup := records[k]; dup {
			add(r, "host", "the same record exists as %q", other)
		}
		records[k] = r.Name
	}
}

func family(v6 bool) string {
	if v6 {
		return "IPv6"
	}
	return "IPv4"
}

// poolBounds returns a pool's first and last address.
func poolBounds(p string) (first, last net.IP, ok bool) {
	if _, n, err := net.ParseCIDR(p); err == nil {
		first = n.IP
		last = make(net.IP, len(n.IP))
		for i := range n.IP {
			last[i] = n.IP[i] | ^n.Mask[i]
		}
		return first, last, true
	}
	a, b, found := strings.Cut(p, "-")
	if !found {
		return nil, nil, false
	}
	first, last = net.ParseIP(strings.TrimSpace(a)), net.ParseIP(strings.TrimSpace(b))
	if first == nil || last == nil {
		return nil, nil, false
	}
	if f4 := first.To4(); f4 != nil {
		first, last = f4, last.To4()
	}
	return first, last, last != nil && bytes.Compare(first, last) <= 0
}
