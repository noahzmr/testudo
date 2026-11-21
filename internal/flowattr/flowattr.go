// Package flowattr places flows in the appliance's own terms: which site,
// zone and VRF they were seen in, which tunnel and peer (and so which
// person) they belong to, what address translation did to them, and what
// the load balancer did with them. It joins the flow table with what the
// model says, what conntrack knows and what the proxy logged; it captures
// nothing itself.
package flowattr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/flows"
	"github.com/noahzmr/testudo/internal/lbrender"
	"github.com/noahzmr/testudo/internal/mesh"
	"github.com/noahzmr/testudo/internal/model"
	"github.com/noahzmr/testudo/internal/netops"
)

// Input is what an index is built from.
type Input struct {
	State          *confstore.State
	SiteID, NodeID string
	Conntrack      []netops.ConntrackFlow
	Access         []Access
	// LocalIPs are this node's own addresses. With them a listener on
	// every address matches only connections to the node itself.
	LocalIPs []string
	Now      time.Time
}

type peer struct {
	nets []*net.IPNet
	name string
	user string
}

type iface struct {
	zone, vrf string
	tunnel    string // WireGuard tunnel name, or "fabric"
	peers     []peer // road-warrior and site-to-site peers
	fabric    *mesh.Tunnel
	peerSite  string
	peerName  string
}

type ctEntry struct {
	f    netops.ConntrackFlow
	conv string
}

// Index answers questions about flows. It is built once per round and is
// read-only afterwards.
type Index struct {
	site     string
	ifaces   map[string]*iface
	carriers map[string]*iface // "udp|ip:port" of a fabric tunnel's far end
	listen   map[int]string    // UDP port a WireGuard tunnel listens on -> tunnel name
	nat      map[string]ctEntry
	kernelLB map[string]string // "proto|ip:port" or "proto|*:port" -> service name
	proxyLB  map[string]string // "tcp|*:port" or "tcp|ip:port" -> service name
	lbZone   map[string]string // service name -> the zone it listens in
	local    map[string]bool
	access   map[string]Access // client ip:port -> the request seen last
	backends map[string]Access // backend ip:port -> the request that used it last
	pools    map[string]string // backend ip:port -> service name, from the model
	routers  map[string]string // proxy router name -> model router name
}

func effective[T model.Entity](st *confstore.State, kind model.Kind, siteID, nodeID string) []T {
	var out []T
	for _, e := range st.List(kind) {
		if !model.AppliesTo(e, siteID, nodeID) {
			continue
		}
		if eff, _, err := model.Effective(e, siteID, nodeID); err == nil {
			out = append(out, eff.(T))
		}
	}
	return out
}

// tupleKey identifies a connection whichever way round it was written.
func tupleKey(proto, a string, ap uint16, b string, bp uint16) string {
	x, y := net.JoinHostPort(a, strconv.Itoa(int(ap))), net.JoinHostPort(b, strconv.Itoa(int(bp)))
	if y < x {
		x, y = y, x
	}
	return proto + "|" + x + "|" + y
}

func conv(kind, key string) string {
	sum := sha256.Sum256([]byte(key))
	return kind + ":" + hex.EncodeToString(sum[:6])
}

func hostPort(ip string, port uint16) string { return net.JoinHostPort(ip, strconv.Itoa(int(port))) }

// Build makes an index. A missing piece (no model, no conntrack, no proxy)
// only means that part of the answer stays empty.
func Build(in Input) *Index {
	x := &Index{ifaces: map[string]*iface{}, carriers: map[string]*iface{}, listen: map[int]string{}, nat: map[string]ctEntry{},
		kernelLB: map[string]string{}, proxyLB: map[string]string{}, lbZone: map[string]string{}, local: map[string]bool{},
		access: map[string]Access{}, backends: map[string]Access{},
		pools: map[string]string{}, routers: map[string]string{}}
	for _, ip := range in.LocalIPs {
		x.local[ip] = true
	}
	if st := in.State; st != nil {
		x.fromModel(st, in.SiteID, in.NodeID)
	}
	for _, f := range in.Conntrack {
		if !f.NATed || f.ReplySrc == "" {
			continue
		}
		// The kernel marks connections that passed a NAT hook; only a
		// changed address or port is a translation.
		if f.OrigSrc == f.ReplyDst && f.OrigSport == f.ReplyDport && f.OrigDst == f.ReplySrc && f.OrigDport == f.ReplySport {
			continue
		}
		key := tupleKey(f.Proto, f.OrigSrc, f.OrigSport, f.OrigDst, f.OrigDport)
		e := ctEntry{f: f, conv: conv("nat", key)}
		x.nat[key] = e
		x.nat[tupleKey(f.Proto, f.ReplySrc, f.ReplySport, f.ReplyDst, f.ReplyDport)] = e
	}
	sort.Slice(in.Access, func(i, j int) bool { return in.Access[i].Time.Before(in.Access[j].Time) })
	for _, a := range in.Access {
		x.access[a.Client] = a
		if a.Backend != "" {
			x.backends[a.Backend] = a
		}
	}
	return x
}

func (x *Index) fromModel(st *confstore.State, siteID, nodeID string) {
	if e, ok := st.Get(model.KindSite, siteID); ok {
		x.site = e.GetMeta().Name
	}
	name := func(kind model.Kind, id string) string {
		if e, ok := st.Get(kind, id); ok {
			return e.GetMeta().Name
		}
		return ""
	}
	at := func(dev string) *iface {
		i := x.ifaces[dev]
		if i == nil {
			i = &iface{}
			x.ifaces[dev] = i
		}
		return i
	}
	for _, i := range effective[*model.Interface](st, model.KindInterface, siteID, nodeID) {
		if i.Enabled {
			a := at(i.Device)
			a.zone, a.vrf = name(model.KindZone, i.Zone.ID), name(model.KindVRF, i.VRF.ID)
		}
	}
	tunnels := map[string]*iface{}
	for _, t := range effective[*model.WGTunnel](st, model.KindWGTunnel, siteID, nodeID) {
		if !t.Enabled {
			continue
		}
		a := at(t.Device)
		a.zone, a.tunnel = name(model.KindZone, t.Zone.ID), t.Name
		tunnels[t.ID] = a
		x.listen[t.ListenPort] = t.Name
	}
	for _, p := range effective[*model.WGPeer](st, model.KindWGPeer, siteID, nodeID) {
		a := tunnels[p.Tunnel.ID]
		if a == nil || !p.Enabled {
			continue
		}
		pe := peer{name: p.Name}
		if u, ok := st.Get(model.KindUser, p.User.ID); ok {
			pe.user = u.(*model.User).Username
		}
		for _, c := range p.AllowedIPs {
			if _, n, err := net.ParseCIDR(c); err == nil {
				if ones, _ := n.Mask.Size(); ones > 0 {
					pe.nets = append(pe.nets, n)
				}
			}
		}
		a.peers = append(a.peers, pe)
	}
	if plan, err := mesh.Build(st, siteID, nodeID); err == nil && plan.Enabled {
		zone := name(model.KindZone, plan.Fabric.Zone.ID)
		for i := range plan.Tunnels {
			t := plan.Tunnels[i]
			a := at(t.Device)
			a.zone, a.vrf, a.tunnel, a.fabric = zone, t.VRF, "fabric", &t
			a.peerName, a.peerSite = t.PeerName, name(model.KindSite, t.PeerSite)
			x.carriers["udp|"+t.Endpoint] = a
		}
	}
	// Load balancing.
	services := map[string]*model.LBService{}
	for _, s := range effective[*model.LBService](st, model.KindLBService, siteID, nodeID) {
		if !s.Enabled {
			continue
		}
		services[s.ID] = s
		x.lbZone[s.Name] = name(model.KindZone, s.Zone.ID)
		l4 := "tcp"
		if s.Protocol == "udp" {
			l4 = "udp"
		}
		addr := "*"
		if s.Address != "" {
			addr = s.Address
		}
		key := l4 + "|" + net.JoinHostPort(addr, strconv.Itoa(s.Port))
		if s.Mode == "kernel" {
			x.kernelLB[key] = s.Name
		} else {
			x.proxyLB[key] = s.Name
		}
	}
	pools := map[string]*model.LBBackendPool{}
	for _, p := range effective[*model.LBBackendPool](st, model.KindLBBackendPool, siteID, nodeID) {
		pools[p.ID] = p
	}
	addPool := func(poolID, service string) {
		if p := pools[poolID]; p != nil {
			for _, b := range p.Backends {
				if _, done := x.pools[b.Address]; !done {
					x.pools[b.Address] = service
				}
			}
		}
	}
	for _, s := range services {
		addPool(s.DefaultPool.ID, s.Name)
	}
	for _, r := range effective[*model.LBRouter](st, model.KindLBRouter, siteID, nodeID) {
		x.routers[lbrender.Ident("rt", &r.Meta)] = r.Name
		if s := services[r.Service.ID]; s != nil {
			addPool(r.Pool.ID, s.Name)
		}
	}
	for _, s := range services {
		x.routers[lbrender.Ident("svc", &s.Meta)+"-fallback"] = s.Name + " (fallback)"
	}
}

// service looks a listener up by address and port, then by port alone.
func service(m map[string]string, proto, ip string, port uint16) string {
	if v := m[proto+"|"+hostPort(ip, port)]; v != "" {
		return v
	}
	return m[proto+"|"+net.JoinHostPort("*", strconv.Itoa(int(port)))]
}

func tuple(proto, sip string, sp uint16, dip string, dp uint16) string {
	return fmt.Sprintf("%s %s > %s", proto, hostPort(sip, sp), hostPort(dip, dp))
}

// Apply returns the flows with their attribution filled in.
func (x *Index) Apply(stats []flows.FlowStats) []flows.FlowStats {
	out := make([]flows.FlowStats, len(stats))
	for i, f := range stats {
		out[i] = f
		out[i].Attrs = x.attrs(f)
	}
	return out
}

func (x *Index) attrs(f flows.FlowStats) flows.Attrs {
	k := f.Key
	a := flows.Attrs{Site: x.site}
	if ifc := x.ifaces[k.Iface]; ifc != nil {
		a.Zone, a.VRF, a.Tunnel = ifc.zone, ifc.vrf, ifc.tunnel
		if ifc.fabric != nil {
			a.Peer, a.PeerSite, a.Path = ifc.peerName, ifc.peerSite, ifc.fabric.Color
		}
		// The peer a road warrior's or a branch's traffic belongs to: the
		// one whose allowed IPs hold one of the endpoints.
		for _, ip := range []string{k.A.IP, k.B.IP} {
			if a.Peer != "" {
				break
			}
			addr := net.ParseIP(ip)
			for _, p := range ifc.peers {
				for _, n := range p.nets {
					if addr != nil && n.Contains(addr) {
						a.Peer, a.User = p.name, p.user
					}
				}
			}
		}
	}
	// The encrypted carrier of a tunnel, on an uplink.
	if k.Proto == "udp" {
		for _, e := range []flows.Endpoint{k.A, k.B} {
			if c := x.carriers["udp|"+e.String()]; c != nil {
				a.Tunnel, a.Peer, a.PeerSite, a.Path, a.Carrier = "fabric", c.peerName, c.peerSite, c.fabric.Color, true
			}
		}
		if !a.Carrier {
			for _, e := range []flows.Endpoint{k.A, k.B} {
				if t := x.listen[int(e.Port)]; t != "" {
					a.Tunnel, a.Carrier = t, true
				}
			}
		}
	}
	// Address translation, and the kernel's load balancing that is one.
	if ct, ok := x.nat[tupleKey(k.Proto, k.A.IP, k.A.Port, k.B.IP, k.B.Port)]; ok {
		c := ct.f
		a.PreNAT = tuple(c.Proto, c.OrigSrc, c.OrigSport, c.OrigDst, c.OrigDport)
		a.PostNAT = tuple(c.Proto, c.ReplyDst, c.ReplyDport, c.ReplySrc, c.ReplySport)
		a.Conversation = ct.conv
		if svc := service(x.kernelLB, c.Proto, c.OrigDst, c.OrigDport); svc != "" {
			a.LBService, a.LBBackend = svc, hostPort(c.ReplySrc, c.ReplySport)
			a.LBRole = "backend"
			if tupleKey(k.Proto, k.A.IP, k.A.Port, k.B.IP, k.B.Port) == tupleKey(c.Proto, c.OrigSrc, c.OrigSport, c.OrigDst, c.OrigDport) {
				a.LBRole = "client"
			}
		}
	}
	// The proxy: a client's connection to a listener, or the proxy's own
	// connection to a backend.
	if a.LBRole == "" && k.Proto == "tcp" {
		for _, side := range [][2]flows.Endpoint{{k.A, k.B}, {k.B, k.A}} {
			listener, client := side[0], side[1]
			svc := service(x.proxyLB, "tcp", listener.IP, listener.Port)
			// A listener is on this node, in its zone: the same port
			// elsewhere is somebody else's service.
			if svc != "" && (len(x.local) > 0 && !x.local[listener.IP] || a.Zone != "" && x.lbZone[svc] != "" && a.Zone != x.lbZone[svc]) {
				svc = ""
			}
			if svc != "" {
				a.LBRole, a.LBService = "client", svc
				if r, ok := x.access[client.String()]; ok {
					a.LBRouter, a.LBHost, a.LBBackend = x.routerName(r.Router), r.Host, r.Backend
					a.Conversation = conv("lb", r.Router+"|"+r.Backend)
				}
				break
			}
		}
		if a.LBRole == "" {
			for _, e := range []flows.Endpoint{k.A, k.B} {
				svc, inPool := x.pools[e.String()]
				r, used := x.backends[e.String()]
				if !inPool && !used {
					continue
				}
				a.LBRole, a.LBService, a.LBBackend = "backend", svc, e.String()
				if used {
					a.LBRouter, a.LBHost = x.routerName(r.Router), r.Host
					a.Conversation = conv("lb", r.Router+"|"+r.Backend)
				}
				break
			}
		}
	}
	return a
}

func (x *Index) routerName(proxyName string) string {
	if n := x.routers[proxyName]; n != "" {
		return n
	}
	return strings.TrimSuffix(proxyName, "@file")
}
