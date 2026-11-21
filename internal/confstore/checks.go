package confstore

import (
	"fmt"
	"net"
	"sort"

	"github.com/noahzmr/testudo/internal/model"
)

// Semantic checks look at the whole candidate model. They run on every
// commit and preview, after single-object validation and after every
// reference has been found to resolve.

func runChecks(s *State) []Problem {
	var out []Problem
	add := func(e model.Entity, field, format string, args ...any) {
		out = append(out, Problem{Kind: e.Kind(), ID: e.GetMeta().ID, Name: e.GetMeta().Name,
			Field: field, Message: fmt.Sprintf(format, args...)})
	}

	// A route and its gateway must live in the same VRF.
	for _, e := range s.objects[model.KindRoute] {
		r := e.(*model.Route)
		if gw, ok := s.peek(model.KindGateway, r.Gateway.ID).(*model.Gateway); ok && gw.VRF.ID != r.VRF.ID {
			add(r, "gateway", "gateway %q is in another VRF than the route", gw.Name)
		}
	}

	// A gateway group that a route or policy route names must have members.
	groups := map[string]bool{}
	for _, e := range s.objects[model.KindGateway] {
		if g := e.(*model.Gateway); g.Group != "" {
			groups[g.Group] = true
		}
	}
	for _, e := range s.objects[model.KindRoute] {
		if r := e.(*model.Route); r.GatewayGroup != "" && !groups[r.GatewayGroup] {
			add(r, "gateway_group", "no gateway belongs to group %q", r.GatewayGroup)
		}
	}
	for _, e := range s.objects[model.KindPolicyRoute] {
		if r := e.(*model.PolicyRoute); r.GatewayGroup != "" && !groups[r.GatewayGroup] {
			add(r, "gateway_group", "no gateway belongs to group %q", r.GatewayGroup)
		}
	}

	// An enabled router needs a pool that can take traffic.
	for _, e := range s.objects[model.KindLBRouter] {
		r := e.(*model.LBRouter)
		if !r.Enabled {
			continue
		}
		if pool, ok := s.peek(model.KindLBBackendPool, r.Pool.ID).(*model.LBBackendPool); ok {
			usable := 0
			for _, b := range pool.Backends {
				if !b.Drain {
					usable++
				}
			}
			if usable == 0 {
				add(r, "pool", "pool %q has no backend that accepts traffic", pool.Name)
			}
		}
		if svc, ok := s.peek(model.KindLBService, r.Service.ID).(*model.LBService); ok {
			if svc.Mode == "kernel" {
				add(r, "service", "service %q balances in the packet filter, which sees no host names; routers need a service in proxy mode", svc.Name)
			}
			if len(r.SNI) > 0 && svc.Protocol != "tcp" && svc.Protocol != "https" {
				add(r, "sni", "SNI matching needs a tcp or https service, %q is %s", svc.Name, svc.Protocol)
			}
			if r.TLS == "passthrough" && svc.Protocol != "tcp" {
				add(r, "tls", "TLS passthrough needs a tcp service, %q is %s", svc.Name, svc.Protocol)
			}
		}
	}

	// An enabled rule must not depend on a disabled tunnel.
	for _, e := range s.objects[model.KindFilterRule] {
		r := e.(*model.FilterRule)
		if tun, ok := s.peek(model.KindWGTunnel, r.Tunnel.ID).(*model.WGTunnel); ok && r.Enabled && !tun.Enabled {
			add(r, "tunnel", "tunnel %q is disabled", tun.Name)
		}
		for i, a := range r.PortAliases {
			if al, ok := s.peek(model.KindAlias, a.ID).(*model.Alias); ok && al.Type != "port" {
				add(r, fmt.Sprintf("port_aliases[%d]", i), "alias %q is of type %s, not port", al.Name, al.Type)
			}
		}
		for field, list := range map[string][]model.Ref[model.Alias]{"source": r.Source, "destination": r.Destination} {
			for i, a := range list {
				if al, ok := s.peek(model.KindAlias, a.ID).(*model.Alias); ok && al.Type == "port" {
					add(r, fmt.Sprintf("%s[%d]", field, i), "alias %q is a port alias and cannot match addresses", al.Name)
				}
			}
		}
	}

	// Nested aliases must be of the same type and must not form a cycle.
	for _, e := range s.objects[model.KindAlias] {
		a := e.(*model.Alias)
		for i, m := range a.Members {
			if child, ok := s.peek(model.KindAlias, m.ID).(*model.Alias); ok && child.Type != a.Type {
				add(a, fmt.Sprintf("members[%d]", i), "nested alias %q is of type %s, not %s", child.Name, child.Type, a.Type)
			}
		}
		if aliasCycle(s, a.ID, a.ID, map[string]bool{}) {
			add(a, "members", "nested aliases form a cycle")
		}
	}

	// A site's voting node must belong to that site.
	for _, e := range s.objects[model.KindSite] {
		site := e.(*model.Site)
		if n, ok := s.peek(model.KindClusterNode, site.Voter.ID).(*model.ClusterNode); ok && n.Site.ID != site.ID {
			add(site, "voter", "node %q belongs to another site", n.Name)
		}
	}

	// Balancing in the packet filter works on connections, not requests.
	for _, e := range s.objects[model.KindLBService] {
		svc := e.(*model.LBService)
		if !svc.Enabled || svc.Mode != "kernel" {
			continue
		}
		if svc.Protocol != "tcp" && svc.Protocol != "udp" {
			add(svc, "protocol", "kernel mode balances tcp and udp; %s needs proxy mode", svc.Protocol)
		}
		if svc.DefaultPool.ID == "" {
			add(svc, "default_pool", "kernel mode sends everything to the fallback pool; choose one")
		}
	}

	// Two enabled services cannot listen on the same address and port.
	listeners := map[string]string{}
	for _, e := range sortedByName(s.objects[model.KindLBService]) {
		svc := e.(*model.LBService)
		if !svc.Enabled {
			continue
		}
		l4 := "tcp"
		if svc.Protocol == "udp" {
			l4 = "udp"
		}
		key := fmt.Sprintf("%s|%s|%s|%d|%s", svc.Scope, svc.Zone.ID, svc.Address, svc.Port, l4)
		if other, dup := listeners[key]; dup {
			add(svc, "port", "service %q already listens on this address and port", other)
		}
		listeners[key] = svc.Name
	}

	// There is one firewall policy per scope.
	policies := map[model.Scope]string{}
	for _, e := range sortedByName(s.objects[model.KindFirewallPolicy]) {
		if other, dup := policies[e.GetMeta().Scope]; dup {
			add(e, "scope", "firewall policy %q already covers this scope", other)
		}
		policies[e.GetMeta().Scope] = e.GetMeta().Name
	}

	out = append(out, fabricChecks(s, add)...)

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return string(a.Kind)+a.Name+a.Field < string(b.Kind)+b.Name+b.Field
	})
	return out
}

func aliasCycle(s *State, start, at string, seen map[string]bool) bool {
	a, ok := s.peek(model.KindAlias, at).(*model.Alias)
	if !ok || seen[at] {
		return false
	}
	seen[at] = true
	for _, m := range a.Members {
		if m.ID == start || aliasCycle(s, start, m.ID, seen) {
			return true
		}
	}
	return false
}

func sortedByName(m map[string]model.Entity) []model.Entity {
	out := make([]model.Entity, 0, len(m))
	for _, e := range m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetMeta().Name < out[j].GetMeta().Name })
	return out
}

// fabricChecks keep the fabric's derived numbers unique and its names
// meaningful.
func fabricChecks(s *State, add func(model.Entity, string, string, ...any)) []Problem {
	var fabric *model.Fabric
	for _, e := range sortedByName(s.objects[model.KindFabric]) {
		if fabric != nil {
			add(e, "name", "there is one fabric; %q exists", fabric.Name)
			continue
		}
		fabric = e.(*model.Fabric)
	}
	colors := map[string]bool{}
	if fabric != nil {
		if ip, n, err := net.ParseCIDR(fabric.Pool); err != nil || ip.To4() == nil {
			add(fabric, "pool", "the pool has to be an IPv4 network")
		} else if ones, _ := n.Mask.Size(); ones != 16 {
			add(fabric, "pool", "the pool has to be a /16")
		}
		for _, c := range fabric.Colors {
			if colors[c] {
				add(fabric, "colors", "color %q is listed twice", c)
			}
			colors[c] = true
		}
		if fabric.PortBase+511 > 65535 {
			add(fabric, "port_base", "the 512 ports from %d do not fit below 65536", fabric.PortBase)
		}
		// User tunnels must not listen where the fabric's do.
		for _, e := range s.objects[model.KindWGTunnel] {
			if t := e.(*model.WGTunnel); t.ListenPort >= fabric.PortBase && t.ListenPort <= fabric.PortBase+511 {
				add(t, "listen_port", "port %d is in the range the fabric uses (%d to %d)", t.ListenPort, fabric.PortBase, fabric.PortBase+511)
			}
		}
	}
	indexes := map[int]string{}
	for _, e := range sortedByName(s.objects[model.KindClusterNode]) {
		n := e.(*model.ClusterNode)
		if n.MeshIndex > 0 {
			if other, dup := indexes[n.MeshIndex]; dup {
				add(n, "mesh_index", "node %q has fabric index %d already", other, n.MeshIndex)
			}
			indexes[n.MeshIndex] = n.Name
		}
		seen := map[string]bool{}
		for _, u := range n.Uplinks {
			if seen[u.Color] {
				add(n, "uplinks", "two uplinks of color %q", u.Color)
			}
			seen[u.Color] = true
			if fabric != nil && !colors[u.Color] {
				add(n, "uplinks", "color %q is not one of the fabric's", u.Color)
			}
		}
	}
	slots := map[int]string{}
	for _, e := range sortedByName(s.objects[model.KindVRF]) {
		if v := e.(*model.VRF); v.MeshSlot > 0 {
			if other, dup := slots[v.MeshSlot]; dup && other != v.Name {
				add(v, "mesh_slot", "VRF %q has fabric slot %d already", other, v.MeshSlot)
			}
			slots[v.MeshSlot] = v.Name
		}
	}
	marks := map[uint32]string{}
	for _, e := range sortedByName(s.objects[model.KindPolicyRoute]) {
		marks[e.(*model.PolicyRoute).Mark] = e.GetMeta().Name
	}
	for _, e := range sortedByName(s.objects[model.KindPathPolicy]) {
		p := e.(*model.PathPolicy)
		if other, dup := marks[p.Mark]; dup {
			add(p, "mark", "mark 0x%x is already routed by %q", p.Mark, other)
		}
		marks[p.Mark] = p.Name
		if p.Prefer != "lowest_latency" && p.Prefer != "lowest_loss" && !colors[p.Prefer] {
			add(p, "prefer", "%q is neither lowest_latency, lowest_loss nor one of the fabric's colors", p.Prefer)
		}
	}
	// HA pairs: two nodes of the pair's site, each with an address on the
	// sync link, one address family per VRRP instance, router ids unique
	// per interface.
	vrids := map[string]string{}
	for _, e := range sortedByName(s.objects[model.KindHAPair]) {
		p := e.(*model.HAPair)
		var nodes []*model.ClusterNode
		for _, r := range p.Nodes {
			if n, ok := s.peek(model.KindClusterNode, r.ID).(*model.ClusterNode); ok {
				nodes = append(nodes, n)
			}
		}
		if len(nodes) == 2 && nodes[0].ID == nodes[1].ID {
			add(p, "nodes", "a pair needs two different nodes")
		}
		for _, n := range nodes {
			if p.Scope != model.SiteScope(n.Site.ID) {
				add(p, "nodes", "node %q is not at the pair's site", n.Name)
			}
			if n.SyncAddress == "" {
				add(p, "nodes", "node %q has no address on the sync link", n.Name)
			}
		}
		for _, in := range p.Instances {
			v6 := map[bool]bool{}
			for _, ip := range in.VirtualIPs {
				addr, _, err := net.ParseCIDR(ip)
				if err == nil {
					v6[addr.To4() == nil] = true
				}
			}
			if len(v6) > 1 {
				add(p, "instances", "instance %d on %s mixes IPv4 and IPv6; use one instance per family", in.VRID, in.Interface)
			}
			key := fmt.Sprintf("%s|%s|%d", p.Scope, in.Interface, in.VRID)
			if other, dup := vrids[key]; dup {
				add(p, "instances", "virtual router id %d on %s is used by %q too", in.VRID, in.Interface, other)
			}
			vrids[key] = p.Name
		}
	}
	return nil
}
