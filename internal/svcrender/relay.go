package svcrender

import (
	"fmt"
	"path/filepath"
	"strings"
)

// relay renders dnsmasq as a DHCP relay and nothing else: port=0 switches
// its DNS side off. Each client interface relays from one of its own
// addresses of the server's family, which the server answers to.
func (r *renderer) relay(res *Result) string {
	served := map[string]bool{}
	for _, s := range r.scopes {
		served[fmt.Sprintf("%s/%v", s.Interface, isV6(s.Subnet))] = true
	}
	var b strings.Builder
	b.WriteString(header("dnsmasq, as a DHCP relay"))
	b.WriteString("port=0\n")
	fmt.Fprintf(&b, "pid-file=%s\n", filepath.Join(r.opt.RunDir, "dnsmasq.pid"))
	b.WriteString("bind-dynamic\n")
	seen := map[string]bool{}
	var v4, v6, from []string
	lines := 0
	for _, rl := range r.relays {
		for _, iface := range rl.Interfaces {
			if !seen[iface] {
				fmt.Fprintf(&b, "interface=%s\n", iface)
				seen[iface] = true
			}
			for _, srv := range rl.Servers {
				six := isV6(srv)
				if served[fmt.Sprintf("%s/%v", iface, six)] {
					r.fail("dhcp relay %q: %s is served by a DHCP scope of the same family", rl.Name, iface)
					continue
				}
				local := r.addrOn(iface, six, nil)
				if local == "" {
					r.fail("dhcp relay %q: %s has no address of the family of %s to relay from", rl.Name, iface, srv)
					continue
				}
				fmt.Fprintf(&b, "dhcp-relay=%s,%s\n", local, srv)
				lines++
				from = append(from, srv)
				if six {
					v6 = append(v6, iface)
				} else {
					v4 = append(v4, iface)
				}
			}
		}
	}
	if lines == 0 {
		return ""
	}
	res.Open.DHCP4 = sortedUnique(append(res.Open.DHCP4, v4...))
	res.Open.DHCP6 = sortedUnique(append(res.Open.DHCP6, v6...))
	res.Open.RelayFrom = sortedUnique(from)
	return b.String()
}
