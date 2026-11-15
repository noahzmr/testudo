// Package frrender turns the configuration model into the routing setup of
// one node: an FRRouting configuration (static routes, OSPF, BGP, BFD), the
// kernel VRF devices, and the policy-routing rules that send marked traffic
// through a chosen gateway.
//
// Render is pure. Which gateways are currently down is an input, so the same
// state and the same health always give the same result.
package frrender

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

// Options are the node-local facts the model does not hold.
type Options struct {
	SiteID, NodeID string
	// Down lists the gateways whose monitor currently fails, by gateway id.
	Down map[string]bool
}

// PolicyRule is one `ip rule`: traffic carrying Mark looks up Table.
type PolicyRule struct {
	Priority int    `json:"priority"`
	Mark     uint32 `json:"mark"`
	Table    uint32 `json:"table"`
}

// VRFDevice is one kernel VRF device and the interfaces enslaved to it.
type VRFDevice struct {
	Name    string   `json:"name"`
	Table   uint32   `json:"table"`
	Members []string `json:"members,omitempty"`
}

// Result is everything the routing stage applies.
type Result struct {
	// Conf is the complete frr.conf.
	Conf string `json:"conf"`
	// Daemons lists the FRR daemons the configuration needs besides zebra
	// and staticd.
	Daemons []string     `json:"daemons,omitempty"`
	Rules   []PolicyRule `json:"rules,omitempty"`
	VRFs    []VRFDevice  `json:"vrfs,omitempty"`
	// Degraded names gateway groups that have no healthy gateway; their
	// routes keep pointing at the preferred tier rather than disappearing.
	Degraded []string `json:"degraded,omitempty"`
	// Empty is true when the model asks for nothing at all: no routes, no
	// protocols, no VRF devices, no policy rules.
	Empty bool `json:"empty"`
	// NeedsDaemon is true when the configuration has content the routing
	// daemon must carry.
	NeedsDaemon bool `json:"needs_daemon"`
}

// RulePriorityBase is where Testudo's policy rules start. The range up to
// RulePriorityBase+999 belongs to it; rules there that the model does not
// ask for are removed.
const RulePriorityBase = 10000

// autoTableBase is where routing tables for policy routes without an
// explicit table start.
const autoTableBase = 20000

type renderer struct {
	st   *confstore.State
	opt  Options
	errs []string

	ifaces   map[string]*model.Interface
	vrfs     map[string]*model.VRF
	gateways map[string]*model.Gateway
	degraded map[string]bool
}

func each[T model.Entity](r *renderer, kind model.Kind, fn func(T)) {
	for _, e := range r.st.List(kind) {
		if !model.AppliesTo(e, r.opt.SiteID, r.opt.NodeID) {
			continue
		}
		eff, _, err := model.Effective(e, r.opt.SiteID, r.opt.NodeID)
		if err != nil {
			r.fail(e, "%v", err)
			continue
		}
		fn(eff.(T))
	}
}

func (r *renderer) fail(e model.Entity, format string, a ...any) {
	r.errs = append(r.errs, fmt.Sprintf("%s %q: %s", e.Kind(), e.GetMeta().Name, fmt.Sprintf(format, a...)))
}

func isV6(s string) bool {
	ip := net.ParseIP(strings.SplitN(s, "/", 2)[0])
	return ip != nil && ip.To4() == nil
}

// word makes a model name usable as an FRR identifier.
func word(s string) string {
	return strings.Map(func(c rune) rune {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			return c
		}
		return '_'
	}, s)
}

func (r *renderer) vrfName(ref model.Ref[model.VRF]) string {
	if v := r.vrfs[ref.ID]; v != nil {
		return v.Name
	}
	return ""
}

// nexthop renders "<address> <device>" for a gateway.
func (r *renderer) nexthop(g *model.Gateway) string {
	if i := r.ifaces[g.Interface.ID]; i != nil {
		return g.Address + " " + i.Device
	}
	return g.Address
}

// group returns the gateways a group currently routes through: the healthy
// ones of the lowest tier. When no gateway of the group is healthy it returns
// the lowest tier anyway and marks the group degraded, because a route that
// vanishes helps nobody.
func (r *renderer) group(name string, v6 bool) []*model.Gateway {
	var all []*model.Gateway
	for _, id := range sortedKeys(r.gateways) {
		g := r.gateways[id]
		if g.Enabled && g.Group == name && isV6(g.Address) == v6 {
			all = append(all, g)
		}
	}
	lowest := func(in []*model.Gateway) []*model.Gateway {
		var out []*model.Gateway
		for _, g := range in {
			switch {
			case len(out) == 0 || g.Priority < out[0].Priority:
				out = []*model.Gateway{g}
			case g.Priority == out[0].Priority:
				out = append(out, g)
			}
		}
		return out
	}
	var healthy []*model.Gateway
	for _, g := range all {
		if !r.opt.Down[g.ID] {
			healthy = append(healthy, g)
		}
	}
	if len(healthy) == 0 && len(all) > 0 {
		r.degraded[name] = true
		return lowest(all)
	}
	return lowest(healthy)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Render builds the routing setup for the node.
func Render(st *confstore.State, opt Options) (Result, error) {
	r := &renderer{st: st, opt: opt, ifaces: map[string]*model.Interface{}, vrfs: map[string]*model.VRF{},
		gateways: map[string]*model.Gateway{}, degraded: map[string]bool{}}
	var res Result
	var node *model.ClusterNode
	for _, e := range st.List(model.KindClusterNode) {
		if e.GetMeta().ID == opt.NodeID {
			node = e.(*model.ClusterNode)
		}
	}
	each(r, model.KindInterface, func(i *model.Interface) { r.ifaces[i.ID] = i })
	each(r, model.KindVRF, func(v *model.VRF) { r.vrfs[v.ID] = v })
	each(r, model.KindGateway, func(g *model.Gateway) { r.gateways[g.ID] = g })

	// VRF devices and their members.
	for _, id := range sortedKeys(r.vrfs) {
		v := r.vrfs[id]
		if len(v.Name) > 15 {
			r.fail(v, "the name becomes a kernel device and may have at most 15 characters")
			continue
		}
		dev := VRFDevice{Name: v.Name, Table: v.Table}
		for _, iid := range sortedKeys(r.ifaces) {
			if i := r.ifaces[iid]; i.Enabled && i.VRF.ID == id {
				dev.Members = append(dev.Members, i.Device)
			}
		}
		res.VRFs = append(res.VRFs, dev)
	}

	var b strings.Builder
	host := "testudo"
	if node != nil {
		host = node.Hostname
	}
	fmt.Fprintf(&b, "frr defaults traditional\nhostname %s\nlog syslog informational\nservice integrated-vtysh-config\n!\n", host)
	body := b.Len()

	// Static routes.
	var statics []string
	static := func(e model.Entity, dst string, gws []*model.Gateway, vrf string, distance int, table uint32) {
		for _, g := range gws {
			if isV6(g.Address) != isV6(dst) {
				r.fail(e, "destination %s and gateway %q are of different address families", dst, g.Name)
				continue
			}
			cmd := "ip route"
			if isV6(dst) {
				cmd = "ipv6 route"
			}
			line := fmt.Sprintf("%s %s %s", cmd, dst, r.nexthop(g))
			if distance > 0 {
				line += fmt.Sprintf(" %d", distance)
			}
			if table > 0 {
				line += fmt.Sprintf(" table %d", table)
			}
			if vrf != "" {
				line += " vrf " + vrf
			}
			statics = append(statics, line)
		}
	}
	resolve := func(e model.Entity, ref model.Ref[model.Gateway], group string, v6 bool) []*model.Gateway {
		if group != "" {
			gws := r.group(group, v6)
			if len(gws) == 0 {
				r.fail(e, "gateway group %q has no enabled gateway of this address family on this node", group)
			}
			return gws
		}
		g := r.gateways[ref.ID]
		if g == nil || !g.Enabled {
			r.fail(e, "its gateway is disabled or not in effect on this node")
			return nil
		}
		return []*model.Gateway{g}
	}
	each(r, model.KindRoute, func(rt *model.Route) {
		if !rt.Enabled {
			return
		}
		distance := 0
		if rt.Metric >= 1 && rt.Metric <= 255 {
			distance = rt.Metric
		}
		static(rt, rt.Destination, resolve(rt, rt.Gateway, rt.GatewayGroup, isV6(rt.Destination)), r.vrfName(rt.VRF), distance, 0)
	})

	// Policy routes: a default route in a table of its own, and the rule
	// that sends marked traffic there.
	var policies []*model.PolicyRoute
	each(r, model.KindPolicyRoute, func(p *model.PolicyRoute) {
		if p.Enabled {
			policies = append(policies, p)
		}
	})
	sort.Slice(policies, func(i, j int) bool { return policies[i].Mark < policies[j].Mark })
	marks := map[uint32]string{}
	for i, p := range policies {
		if other, dup := marks[p.Mark]; dup {
			r.fail(p, "mark 0x%x is already routed by %q", p.Mark, other)
			continue
		}
		marks[p.Mark] = p.Name
		table := p.Table
		if table == 0 {
			table = autoTableBase + p.Mark%10000
		}
		if i >= 1000 {
			r.fail(p, "more than 1000 policy routes")
			continue
		}
		// Both families get their default where the gateways provide one.
		found := false
		for _, v6 := range []bool{false, true} {
			var gws []*model.Gateway
			if p.GatewayGroup != "" {
				gws = r.group(p.GatewayGroup, v6)
			} else if g := r.gateways[p.Gateway.ID]; g != nil && g.Enabled && isV6(g.Address) == v6 {
				gws = []*model.Gateway{g}
			}
			if len(gws) == 0 {
				continue
			}
			found = true
			dst := "0.0.0.0/0"
			if v6 {
				dst = "::/0"
			}
			static(p, dst, gws, "", 0, table)
		}
		if !found {
			r.fail(p, "no enabled gateway to route through on this node")
			continue
		}
		res.Rules = append(res.Rules, PolicyRule{Priority: RulePriorityBase + i, Mark: p.Mark, Table: table})
	}
	// A gateway that is monitored through an address beyond itself needs a
	// host route to that address through the gateway. Otherwise the probe
	// would follow the default route and report on whichever uplink is
	// currently in use.
	for _, id := range sortedKeys(r.gateways) {
		g := r.gateways[id]
		if g.Enabled && g.Monitor != "" && g.Monitor != g.Address && isV6(g.Monitor) == isV6(g.Address) {
			bits := "/32"
			if isV6(g.Monitor) {
				bits = "/128"
			}
			static(g, g.Monitor+bits, []*model.Gateway{g}, r.vrfName(g.VRF), 0, 0)
		}
	}
	sort.Strings(statics)
	for _, l := range statics {
		b.WriteString(l + "\n")
	}
	if len(statics) > 0 {
		b.WriteString("!\n")
	}

	routerID := ""
	if node != nil {
		routerID = node.RouterID
		if routerID == "" && !isV6(node.Address) {
			routerID = node.Address
		}
	}

	daemons := map[string]bool{}
	r.bgp(&b, routerID, daemons)
	r.ospf(&b, routerID, daemons)
	if daemons["bfdd"] {
		b.WriteString("bfd\nexit\n!\n")
	}

	res.NeedsDaemon = b.Len() != body
	res.Empty = !res.NeedsDaemon && len(res.Rules) == 0 && len(res.VRFs) == 0
	res.Conf = b.String()
	res.Daemons = sortedKeys(daemons)
	res.Degraded = sortedKeys(r.degraded)
	if len(r.errs) > 0 {
		return res, fmt.Errorf("frrender: %s", strings.Join(r.errs, "; "))
	}
	return res, nil
}

func (r *renderer) bgp(b *strings.Builder, routerID string, daemons map[string]bool) {
	type key struct {
		as  uint32
		vrf string
	}
	routers := map[key][]*model.BGPNeighbor{}
	each(r, model.KindBGPNeighbor, func(n *model.BGPNeighbor) {
		if n.Enabled {
			k := key{n.LocalAS, r.vrfName(n.VRF)}
			routers[k] = append(routers[k], n)
		}
	})
	keys := make([]key, 0, len(routers))
	for k := range routers {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].vrf < keys[j].vrf || keys[i].vrf == keys[j].vrf && keys[i].as < keys[j].as
	})
	seenVRF := map[string]uint32{}
	for _, k := range keys {
		ns := routers[k]
		sort.Slice(ns, func(i, j int) bool { return ns[i].Name < ns[j].Name })
		if other, dup := seenVRF[k.vrf]; dup {
			r.fail(ns[0], "local AS %d conflicts with AS %d used by other neighbors in the same VRF", k.as, other)
			continue
		}
		seenVRF[k.vrf] = k.as
		daemons["bgpd"] = true

		// Policy objects first: FRR refuses to announce or accept anything
		// over eBGP without a policy, so every neighbor gets route maps.
		for _, n := range ns {
			name := word(n.Name)
			plist := func(dir string, prefixes []string) {
				seq := map[bool]int{}
				for _, p := range prefixes {
					cmd := "ip"
					if isV6(p) {
						cmd = "ipv6"
					}
					seq[isV6(p)] += 5
					fmt.Fprintf(b, "%s prefix-list %s-%s seq %d permit %s\n", cmd, name, dir, seq[isV6(p)], p)
				}
			}
			out := n.PrefixListOut
			if len(out) == 0 {
				out = n.Announce // announce exactly what is originated
			}
			plist("in", n.PrefixListIn)
			plist("out", out)
			rmap := func(dir string, prefixes []string, set string) {
				fmt.Fprintf(b, "route-map %s-%s permit 10\n", name, dir)
				has := map[bool]bool{}
				for _, p := range prefixes {
					has[isV6(p)] = true
				}
				switch {
				case len(prefixes) == 0:
				case has[false] && has[true]:
					// One clause matches one family; the second family gets
					// its own clause.
					fmt.Fprintf(b, " match ip address prefix-list %s-%s\n", name, dir)
					if set != "" {
						fmt.Fprintf(b, " %s\n", set)
					}
					fmt.Fprintf(b, "exit\nroute-map %s-%s permit 20\n match ipv6 address prefix-list %s-%s\n", name, dir, name, dir)
				case has[true]:
					fmt.Fprintf(b, " match ipv6 address prefix-list %s-%s\n", name, dir)
				default:
					fmt.Fprintf(b, " match ip address prefix-list %s-%s\n", name, dir)
				}
				if set != "" {
					fmt.Fprintf(b, " %s\n", set)
				}
				b.WriteString("exit\n")
			}
			var std, large []string
			for _, c := range n.Communities {
				if strings.Count(c, ":") == 2 {
					large = append(large, c)
				} else {
					std = append(std, c)
				}
			}
			set := ""
			if len(std) > 0 {
				set = "set community " + strings.Join(std, " ") + " additive"
			}
			if len(large) > 0 {
				if set != "" {
					set += "\n "
				}
				set += "set large-community " + strings.Join(large, " ") + " additive"
			}
			rmap("in", n.PrefixListIn, "")
			rmap("out", out, set)
		}
		b.WriteString("!\n")

		fmt.Fprintf(b, "router bgp %d", k.as)
		if k.vrf != "" {
			fmt.Fprintf(b, " vrf %s", k.vrf)
		}
		b.WriteString("\n")
		if routerID != "" {
			fmt.Fprintf(b, " bgp router-id %s\n", routerID)
		}
		b.WriteString(" no bgp default ipv4-unicast\n")
		announce := map[bool][]string{}
		for _, n := range ns {
			fmt.Fprintf(b, " neighbor %s remote-as %d\n", n.Address, n.RemoteAS)
			fmt.Fprintf(b, " neighbor %s description %s\n", n.Address, word(n.Name))
			if i := r.ifaces[n.UpdateSource.ID]; i != nil {
				fmt.Fprintf(b, " neighbor %s update-source %s\n", n.Address, i.Device)
			}
			if n.BFD {
				daemons["bfdd"] = true
				fmt.Fprintf(b, " neighbor %s bfd\n", n.Address)
			}
			if n.SessionSecret != "" {
				fmt.Fprintf(b, " neighbor %s password %s\n", n.Address, n.SessionSecret)
			}
			if n.HoldTimeSecond > 0 {
				fmt.Fprintf(b, " neighbor %s timers %d %d\n", n.Address, n.HoldTimeSecond/3, n.HoldTimeSecond)
			}
			for _, p := range n.Announce {
				announce[isV6(p)] = append(announce[isV6(p)], p)
			}
		}
		for _, fam := range []struct {
			v6   bool
			name string
		}{{false, "ipv4"}, {true, "ipv6"}} {
			var lines []string
			nets := announce[fam.v6]
			sort.Strings(nets)
			for i, p := range nets {
				if i == 0 || p != nets[i-1] {
					lines = append(lines, " network "+p)
				}
			}
			for _, n := range ns {
				// A session carries the family of its transport address,
				// and the other one when its policy mentions it.
				carries := isV6(n.Address) == fam.v6
				for _, p := range append(append(append([]string{}, n.PrefixListIn...), n.PrefixListOut...), n.Announce...) {
					carries = carries || isV6(p) == fam.v6
				}
				if !carries {
					continue
				}
				name := word(n.Name)
				lines = append(lines, fmt.Sprintf(" neighbor %s activate", n.Address),
					fmt.Sprintf(" neighbor %s route-map %s-in in", n.Address, name),
					fmt.Sprintf(" neighbor %s route-map %s-out out", n.Address, name))
				if n.RRClient {
					lines = append(lines, fmt.Sprintf(" neighbor %s route-reflector-client", n.Address))
				}
			}
			if len(lines) == 0 {
				continue
			}
			fmt.Fprintf(b, " address-family %s unicast\n", fam.name)
			for _, l := range lines {
				b.WriteString(" " + l + "\n")
			}
			// Equal-cost paths are used together.
			b.WriteString("  maximum-paths 8\n  maximum-paths ibgp 8\n exit-address-family\n")
		}
		b.WriteString("exit\n!\n")
	}
}

func (r *renderer) ospf(b *strings.Builder, routerID string, daemons map[string]bool) {
	type key struct {
		vrf string
		v6  bool
	}
	areas := map[key][]*model.OSPFArea{}
	each(r, model.KindOSPFArea, func(a *model.OSPFArea) {
		if a.Enabled {
			k := key{r.vrfName(a.VRF), a.IPv6}
			areas[k] = append(areas[k], a)
		}
	})
	keys := make([]key, 0, len(areas))
	for k := range areas {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].vrf < keys[j].vrf || keys[i].vrf == keys[j].vrf && !keys[i].v6 && keys[j].v6
	})
	for _, k := range keys {
		as := areas[k]
		sort.Slice(as, func(i, j int) bool { return as[i].Name < as[j].Name })
		daemon, router, ifcmd, idcmd := "ospfd", "router ospf", "ip ospf area", "ospf router-id"
		if k.v6 {
			daemon, router, ifcmd, idcmd = "ospf6d", "router ospf6", "ipv6 ospf6 area", "ospf6 router-id"
		}
		daemons[daemon] = true
		claimed := map[string]string{}
		for _, a := range as {
			for _, ref := range a.Interfaces {
				i := r.ifaces[ref.ID]
				if i == nil {
					r.fail(a, "one of its interfaces is not in effect on this node")
					continue
				}
				if other, dup := claimed[i.Device]; dup {
					r.fail(a, "interface %s is already in area %s", i.Device, other)
					continue
				}
				claimed[i.Device] = a.Area
				fmt.Fprintf(b, "interface %s\n %s %s\nexit\n", i.Device, ifcmd, a.Area)
			}
		}
		b.WriteString(router)
		if k.vrf != "" {
			fmt.Fprintf(b, " vrf %s", k.vrf)
		}
		b.WriteString("\n")
		if routerID != "" {
			fmt.Fprintf(b, " %s %s\n", idcmd, routerID)
		}
		for _, a := range as {
			if a.Stub {
				fmt.Fprintf(b, " area %s stub\n", a.Area)
			}
		}
		b.WriteString("exit\n!\n")
	}
}

// Gateways returns the gateways in effect on the node, for the monitor.
func Gateways(st *confstore.State, opt Options) []*model.Gateway {
	r := &renderer{st: st, opt: opt}
	var out []*model.Gateway
	each(r, model.KindGateway, func(g *model.Gateway) { out = append(out, g) })
	return out
}
