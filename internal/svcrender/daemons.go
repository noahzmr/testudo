package svcrender

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
)

func header(what string) string {
	return "# Written by testudo: " + what + ". Changes are overwritten.\n"
}

// PTRName is the reverse-lookup name of an address.
func PTRName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", v4[3], v4[2], v4[1], v4[0])
	}
	var b strings.Builder
	for i := len(ip) - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "%x.%x.", ip[i]&0xf, ip[i]>>4)
	}
	return b.String() + "ip6.arpa."
}

// AddressRecords are the local-data lines for a name and an address: the
// forward record and its reverse entry.
func AddressRecords(name string, ip net.IP, ttl int) []string {
	typ := "A"
	if ip.To4() == nil {
		typ = "AAAA"
	}
	name = strings.TrimSuffix(name, ".") + "."
	return []string{fmt.Sprintf("%s %d IN %s %s", name, ttl, typ, ip), fmt.Sprintf("%s %d IN PTR %s", PTRName(ip), ttl, name)}
}

// privateNets are answers a public name may not resolve to (DNS rebinding).
var privateNets = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10",
	"fd00::/8", "fe80::/10", "::ffff:0:0/96"}

func (r *renderer) unbound(res *Result) string {
	d := r.resolver
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, "  "+format+"\n", args...) }
	b.WriteString(header("DNS resolver " + d.Name))
	b.WriteString("server:\n")
	line(`username: "unbound"`)
	line(`chroot: ""`)
	line(`directory: %q`, r.opt.RunDir)
	line(`pidfile: ""`)
	line(`do-daemonize: no`)
	line(`use-syslog: no`)
	line(`logfile: ""`)
	line(`verbosity: 1`)
	line(`log-servfail: yes`)
	// Virtual addresses of an HA pair are bound before the node holds them.
	line(`ip-freebind: yes`)
	for _, iface := range sortedUnique(d.Interfaces) {
		var addrs []string
		for _, list := range [][]*net.IPNet{r.ifNets[iface], r.vips[iface]} {
			for _, n := range list {
				addrs = append(addrs, n.IP.String())
			}
		}
		addrs = sortedUnique(addrs)
		if len(addrs) == 0 {
			// Addresses the model does not know (a DHCP client, say):
			// whatever the interface has when the resolver starts.
			addrs = []string{iface}
		}
		for _, a := range addrs {
			line(`interface: %s`, a)
			line(`interface-action: %s allow`, a)
		}
	}
	for _, n := range d.AllowFrom {
		line(`access-control: %s allow`, n)
	}
	line(`do-ip6: yes`)
	line(`prefetch: yes`)
	line(`qname-minimisation: yes`)
	line(`hide-identity: yes`)
	line(`hide-version: yes`)
	line(`harden-glue: yes`)
	line(`harden-dnssec-stripped: yes`)
	line(`harden-below-nxdomain: yes`)
	if d.DNSSEC {
		line(`module-config: "validator iterator"`)
		line(`trust-anchor-file: %q`, RootKey)
		line(`aggressive-nsec: yes`)
	} else {
		line(`module-config: "iterator"`)
	}
	// Public names may not point into the networks behind the node; the
	// local domain and forwarded domains may.
	for _, n := range privateNets {
		line(`private-address: %s`, n)
	}
	local := res.LocalDomain
	inner := []string{local}
	for _, f := range d.DomainForwards {
		inner = append(inner, strings.TrimSuffix(strings.ToLower(f.Domain), "."))
	}
	for _, dom := range sortedUnique(inner) {
		line(`private-domain: "%s."`, dom)
		if d.DNSSEC {
			line(`domain-insecure: "%s."`, dom)
		}
	}
	line(`local-zone: "%s." static`, local)

	var data []string
	for _, rec := range r.records {
		ttl := rec.TTL
		if ttl == 0 {
			ttl = 3600
		}
		name := strings.TrimSuffix(strings.ToLower(rec.Host), ".") + "."
		switch rec.Type {
		case "A", "AAAA":
			data = append(data, AddressRecords(name, net.ParseIP(rec.Value), ttl)...)
		case "CNAME":
			data = append(data, fmt.Sprintf("%s %d IN CNAME %s.", name, ttl, strings.TrimSuffix(rec.Value, ".")))
		case "TXT":
			data = append(data, fmt.Sprintf(`%s %d IN TXT "%s"`, name, ttl, rec.Value))
		}
	}
	for _, s := range r.scopes {
		for _, h := range s.Reservations {
			if n := qualify(h.Hostname, r.scopeDomain(s)); n != "" {
				data = append(data, AddressRecords(n, net.ParseIP(h.Address), 3600)...)
			}
		}
	}
	data = sortedUnique(data)
	for _, rr := range data {
		line(`local-data: '%s'`, rr)
	}
	line(`include: %q`, filepath.Join(r.opt.RunDir, LeaseNames))

	upstream := func(u string, tls bool) string {
		if tls && !strings.Contains(strings.SplitN(u, "#", 2)[0], "@") {
			addr, name, _ := strings.Cut(u, "#")
			return addr + "@853#" + name
		}
		return u
	}
	if d.TLS {
		line(`tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"`)
	}
	type forward struct {
		domain  string
		servers []string
	}
	var fwd []forward
	for _, f := range d.DomainForwards {
		fwd = append(fwd, forward{strings.TrimSuffix(strings.ToLower(f.Domain), "."), f.Servers})
	}
	sort.Slice(fwd, func(i, j int) bool { return fwd[i].domain < fwd[j].domain })
	for _, f := range fwd {
		b.WriteString("forward-zone:\n")
		line(`name: "%s."`, f.domain)
		for _, s := range f.servers {
			line(`forward-addr: %s`, s)
		}
	}
	if d.Mode == "forward" {
		b.WriteString("forward-zone:\n")
		line(`name: "."`)
		for _, u := range d.Upstreams {
			line(`forward-addr: %s`, upstream(u, d.TLS))
		}
		if d.TLS {
			line(`forward-tls-upstream: yes`)
		}
	}
	b.WriteString("remote-control:\n")
	line(`control-enable: yes`)
	line(`control-interface: %q`, filepath.Join(r.opt.RunDir, UnboundCtl))
	line(`control-use-cert: no`)
	return b.String()
}

func (r *renderer) chrony() string {
	n := r.ntp
	var b strings.Builder
	b.WriteString(header("NTP service " + n.Name))
	opts := " iburst"
	if n.NTS {
		opts += " nts"
	}
	for _, p := range n.Pools {
		fmt.Fprintf(&b, "pool %s%s\n", p, opts)
	}
	for _, s := range n.Servers {
		fmt.Fprintf(&b, "server %s%s\n", s, opts)
	}
	b.WriteString("makestep 1.0 3\n")
	if len(n.Interfaces) > 0 {
		// Without a reachable upstream the node keeps serving its own clock,
		// marked as stratum 10, so its clients stay in step with each other.
		b.WriteString("local stratum 10 orphan\n")
	}
	if !n.ServeOnly {
		b.WriteString("rtcsync\n")
	}
	var allow []string
	for _, iface := range sortedUnique(n.Interfaces) {
		nets := r.networksOn(iface)
		if len(nets) == 0 {
			r.fail("NTP service %q: the model knows no network on %s; give the interface its addresses or name the networks under Also serve", n.Name, iface)
		}
		allow = append(allow, nets...)
	}
	allow = append(allow, n.AllowFrom...)
	for _, a := range sortedUnique(allow) {
		fmt.Fprintf(&b, "allow %s\n", a)
	}
	// No command socket: the status comes from the process and from NTP.
	b.WriteString("bindcmdaddress /\ncmdport 0\n")
	fmt.Fprintf(&b, "pidfile %s\n", filepath.Join(r.opt.RunDir, "chronyd.pid"))
	return b.String()
}

func (r *renderer) radvd() string {
	var b strings.Builder
	b.WriteString(header("router advertisements"))
	for _, a := range r.ras {
		var v6scope bool
		var prefixes []string
		for _, s := range r.scopes {
			if s.Interface == a.Interface && isV6(s.Subnet) {
				v6scope = true
				if _, n, err := net.ParseCIDR(s.Subnet); err == nil {
					if ones, _ := n.Mask.Size(); ones == 64 {
						prefixes = append(prefixes, n.String())
					}
				}
			}
		}
		if a.Mode != "slaac" && !v6scope {
			r.fail("router advertisement %q: mode %s needs a DHCPv6 scope on %s", a.Name, a.Mode, a.Interface)
		}
		if len(a.Prefixes) > 0 {
			prefixes = a.Prefixes
		} else {
			for _, n := range r.ifNets[a.Interface] {
				if n.IP.To4() == nil && !n.IP.IsLinkLocalUnicast() {
					if ones, _ := n.Mask.Size(); ones == 64 {
						prefixes = append(prefixes, (&net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask}).String())
					}
				}
			}
		}
		prefixes = sortedUnique(prefixes)
		if len(prefixes) == 0 && r.delegated[a.Interface] {
			// The prefix comes from the provider and can change: radvd
			// announces whatever /64 the interface has.
			prefixes = []string{"::/64"}
		}
		if len(prefixes) == 0 && a.Mode != "managed" {
			r.fail("router advertisement %q: no /64 prefix on %s; give the interface an IPv6 address or name the prefixes", a.Name, a.Interface)
		}
		onoff := func(v bool) string {
			if v {
				return "on"
			}
			return "off"
		}
		fmt.Fprintf(&b, "interface %s {\n", a.Interface)
		fmt.Fprintf(&b, "  AdvSendAdvert on;\n  MinRtrAdvInterval 30;\n  MaxRtrAdvInterval 120;\n")
		fmt.Fprintf(&b, "  AdvManagedFlag %s;\n  AdvOtherConfigFlag %s;\n", onoff(a.Mode == "managed"), onoff(a.Mode != "slaac"))
		if a.MTU > 0 {
			fmt.Fprintf(&b, "  AdvLinkMTU %d;\n", a.MTU)
		}
		for _, p := range prefixes {
			fmt.Fprintf(&b, "  prefix %s {\n    AdvOnLink on;\n    AdvAutonomous %s;\n  };\n", p, onoff(a.Mode != "managed"))
		}
		dns := a.DNS
		if len(dns) == 0 && r.resolver != nil && r.serves(r.resolver.Interfaces, a.Interface) {
			if addr := r.addrOn(a.Interface, true, nil); addr != "" {
				dns = []string{addr}
			}
		}
		if len(dns) > 0 {
			fmt.Fprintf(&b, "  RDNSS %s {\n  };\n", strings.Join(dns, " "))
		}
		domains := a.Domains
		if len(domains) == 0 && r.resolver != nil && r.serves(r.resolver.Interfaces, a.Interface) {
			domains = []string{r.localDomain()}
		}
		if len(domains) > 0 {
			fmt.Fprintf(&b, "  DNSSL %s {\n  };\n", strings.Join(domains, " "))
		}
		b.WriteString("};\n")
	}
	return b.String()
}
