// Package mesh derives the network between the sites from the model: which
// tunnels a node has, their addresses, ports and keys, and the BGP sessions
// that run over them. Nothing of it is stored; adding a site, a node, an
// uplink or a stretched VRF changes the result, and the stages that use it
// (WireGuard, packet filter, routing) bring the node in line.
//
// Every number is derived from stable inputs (a node's fabric index, the
// position of a color in the fabric, a VRF's slot), so a tunnel keeps its
// device, port and addresses when other sites come and go.
//
//	pool /16                     x.y.0.0 .. x.y.127.255   point-to-point links (/31)
//	                             x.y.255.<index>          node loopbacks
//	link  (i<j, color c, slot s) offset = ((s*4+c)<<10 | i<<5 | j) * 2
//	port  on i towards j         port_base + (s*4+c)*32 + j
//	device on i towards j        tm<j>c<c>s<s>
package mesh

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/model"
)

// KeyRef names the node's fabric private key in its own secret store. It is
// made on the node and is never replicated.
const KeyRef = "mesh-key"

// Limits that follow from the address and port layout.
const (
	MaxIndex  = 31
	MaxColors = 4
	MaxSlots  = 4 // the default VRF and three stretched ones
	MTU       = 1420
	Keepalive = 25
)

// Tunnel is one point-to-point WireGuard tunnel of the node.
type Tunnel struct {
	Device     string `json:"device"`
	ListenPort int    `json:"listen_port"`
	// Local is the node's address on the link (a /31); Peer is the other
	// end's address.
	Local string `json:"local"`
	Peer  string `json:"peer"`

	PeerNode, PeerName, PeerSite string
	PeerKey                      string `json:"peer_key"`
	// Endpoint is where the peer's end listens.
	Endpoint string `json:"endpoint"`

	Color      string `json:"color"`
	ColorIndex int    `json:"color_index"`
	Slot       int    `json:"slot"`
	// VRF is the id and name of the stretched VRF for slots above zero.
	VRFID, VRF string

	LocalAS, PeerAS uint32
	// IBGP is set when both sites use the same AS number. In a hub-and-
	// spoke fabric a hub then reflects routes to its spokes and puts
	// itself in as the next hop.
	IBGP            bool
	ReflectorClient bool
}

// Plan is the node's part of the fabric.
type Plan struct {
	Enabled bool
	Fabric  *model.Fabric
	Node    *model.ClusterNode
	Site    *model.Site
	ASN     uint32
	// Loopback is the node's own address in the fabric (a /32), announced
	// to every other node.
	Loopback string
	Tunnels  []Tunnel
	// Announce lists, per slot, what the node originates; Accept what it
	// takes from the fabric; Remote what each peer node stands for (its
	// site's networks and its loopback), by slot and peer node id.
	Announce map[int][]string
	Accept   map[int][]string
	Remote   map[int]map[string][]string
	// Reflect is set on a hub: it passes on what it learns.
	Reflect bool
}

// Ports lists the ports the node's tunnels listen on.
func (p Plan) Ports() []int {
	var out []int
	for _, t := range p.Tunnels {
		out = append(out, t.ListenPort)
	}
	sort.Ints(out)
	return out
}

// Devices lists the node's tunnel devices.
func (p Plan) Devices() []string {
	var out []string
	for _, t := range p.Tunnels {
		out = append(out, t.Device)
	}
	sort.Strings(out)
	return out
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

// Fabric returns the enabled fabric, or nil.
func Fabric(st *confstore.State) *model.Fabric {
	for _, e := range st.List(model.KindFabric) {
		if f := e.(*model.Fabric); f.Enabled {
			return f
		}
	}
	return nil
}

func addr(base uint32, off uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], base+off)
	return net.IP(b[:]).String()
}

// poolBase returns the first address of a /16 pool.
func poolBase(pool string) (uint32, error) {
	ip, n, err := net.ParseCIDR(pool)
	if err != nil || ip.To4() == nil {
		return 0, fmt.Errorf("the address pool %q is not an IPv4 network", pool)
	}
	if ones, _ := n.Mask.Size(); ones != 16 {
		return 0, fmt.Errorf("the address pool %q is not a /16", pool)
	}
	return binary.BigEndian.Uint32(n.IP.To4()), nil
}

// LinkAddrs returns the two ends of the link between the nodes with
// indexes a and b for a color and a slot; the lower index gets the first.
func LinkAddrs(pool string, a, b, color, slot int) (forA, forB string, err error) {
	base, err := poolBase(pool)
	if err != nil {
		return "", "", err
	}
	i, j := a, b
	if i > j {
		i, j = j, i
	}
	off := uint32(((slot*MaxColors+color)<<10 | i<<5 | j) * 2)
	lo, hi := addr(base, off), addr(base, off+1)
	if a < b {
		return lo, hi, nil
	}
	return hi, lo, nil
}

// Loopback returns the fabric address of the node with the given index.
func Loopback(pool string, index int) (string, error) {
	base, err := poolBase(pool)
	if err != nil {
		return "", err
	}
	return addr(base, 0xFF00+uint32(index)), nil
}

// Port is where the node with index self listens for the node with index
// peer.
func Port(base, peer, color, slot int) int { return base + (slot*MaxColors+color)*32 + peer }

// Device names the tunnel towards the node with index peer.
func Device(peer, color, slot int) string { return fmt.Sprintf("tm%02dc%ds%d", peer, color, slot) }

// Build works out the plan of one node. A node that is not part of the
// fabric (no fabric, no index, no key, a witness site) gets an empty plan
// and no error.
func Build(st *confstore.State, siteID, nodeID string) (Plan, error) {
	var p Plan
	f := Fabric(st)
	if f == nil || nodeID == "" {
		return p, nil
	}
	sites := map[string]*model.Site{}
	for _, e := range st.List(model.KindSite) {
		sites[e.GetMeta().ID] = e.(*model.Site)
	}
	var nodes []*model.ClusterNode
	var me *model.ClusterNode
	for _, e := range st.List(model.KindClusterNode) {
		n := e.(*model.ClusterNode)
		if s := sites[n.Site.ID]; s == nil || s.Witness || n.MeshIndex == 0 || n.MeshPublicKey == "" {
			continue
		}
		nodes = append(nodes, n)
		if n.ID == nodeID {
			me = n
		}
	}
	if me == nil {
		return p, nil
	}
	if _, err := poolBase(f.Pool); err != nil {
		return p, err
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].MeshIndex < nodes[j].MeshIndex })
	site := sites[me.Site.ID]
	asn := func(s *model.Site) uint32 {
		if s.ASN != 0 {
			return s.ASN
		}
		return f.ASN
	}
	p = Plan{Enabled: true, Fabric: f, Node: me, Site: site, ASN: asn(site), Reflect: f.Topology == "hub_spoke" && site.Hub,
		Announce: map[int][]string{}, Accept: map[int][]string{}, Remote: map[int]map[string][]string{}}
	var errs []string
	p.Loopback, _ = Loopback(f.Pool, me.MeshIndex)
	uplinks := func(n *model.ClusterNode) map[string]string {
		out := map[string]string{}
		for _, u := range n.Uplinks {
			out[u.Color] = u.Endpoint
		}
		return out
	}
	// Stretched VRFs, by slot: the ones in effect at this node.
	slots := map[int]*model.VRF{}
	for _, v := range effective[*model.VRF](st, model.KindVRF, siteID, nodeID) {
		if v.MeshSlot > 0 {
			slots[v.MeshSlot] = v
		}
	}
	// What every node stands for, per slot.
	stands := func(n *model.ClusterNode, slot int) []string {
		var out []string
		if slot == 0 {
			lb, _ := Loopback(f.Pool, n.MeshIndex)
			out = append(out, lb+"/32")
			out = append(out, sites[n.Site.ID].Networks...)
		} else if v := slots[slot]; v != nil {
			for _, ev := range effective[*model.VRF](st, model.KindVRF, n.Site.ID, n.ID) {
				if ev.ID == v.ID {
					out = append(out, ev.Networks...)
				}
			}
		}
		sort.Strings(out)
		return out
	}
	allSlots := []int{0}
	for s := range slots {
		allSlots = append(allSlots, s)
	}
	sort.Ints(allSlots)
	for _, s := range allSlots {
		p.Announce[s] = stands(me, s)
		p.Remote[s] = map[string][]string{}
	}
	mine := uplinks(me)
	seen := map[string]bool{}
	for _, peer := range nodes {
		if peer.ID == me.ID {
			continue
		}
		if peer.MeshIndex == me.MeshIndex {
			errs = append(errs, fmt.Sprintf("nodes %q and %q have the same fabric index %d", me.Name, peer.Name, me.MeshIndex))
			continue
		}
		psite := sites[peer.Site.ID]
		for _, s := range allSlots {
			for _, n := range stands(peer, s) {
				if !seen[fmt.Sprint(s, n)] {
					seen[fmt.Sprint(s, n)] = true
					p.Accept[s] = append(p.Accept[s], n)
				}
			}
		}
		if peer.Site.ID == me.Site.ID {
			continue // nodes of one site share its network; no tunnel
		}
		if f.Topology == "hub_spoke" && !site.Hub && !psite.Hub {
			continue
		}
		theirs := uplinks(peer)
		for _, s := range allSlots {
			vrfID, vrfName := "", ""
			if s > 0 {
				// A stretched VRF connects the sites where it is in effect.
				v := slots[s]
				present := false
				for _, ev := range effective[*model.VRF](st, model.KindVRF, peer.Site.ID, peer.ID) {
					present = present || ev.ID == v.ID
				}
				if !present {
					continue
				}
				vrfID, vrfName = v.ID, v.Name
			}
			p.Remote[s][peer.ID] = stands(peer, s)
			for c, color := range f.Colors {
				local, remote := mine[color], theirs[color]
				if local == "" || remote == "" {
					continue
				}
				la, pa, err := LinkAddrs(f.Pool, me.MeshIndex, peer.MeshIndex, c, s)
				if err != nil {
					errs = append(errs, err.Error())
					continue
				}
				t := Tunnel{Device: Device(peer.MeshIndex, c, s), ListenPort: Port(f.PortBase, peer.MeshIndex, c, s),
					Local: la + "/31", Peer: pa, PeerNode: peer.ID, PeerName: peer.Name, PeerSite: peer.Site.ID,
					PeerKey: peer.MeshPublicKey, Endpoint: net.JoinHostPort(remote, fmt.Sprint(Port(f.PortBase, me.MeshIndex, c, s))),
					Color: color, ColorIndex: c, Slot: s, VRFID: vrfID, VRF: vrfName,
					LocalAS: p.ASN, PeerAS: asn(psite)}
				t.IBGP = t.LocalAS == t.PeerAS
				t.ReflectorClient = t.IBGP && p.Reflect && !psite.Hub
				p.Tunnels = append(p.Tunnels, t)
			}
		}
	}
	for s := range p.Accept {
		sort.Strings(p.Accept[s])
	}
	sort.Slice(p.Tunnels, func(i, j int) bool { return p.Tunnels[i].Device < p.Tunnels[j].Device })
	if len(errs) > 0 {
		return p, fmt.Errorf("mesh: %s", strings.Join(errs, "; "))
	}
	return p, nil
}
