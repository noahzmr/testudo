// Package topology builds an in-memory graph of devices and the
// connections observed between them. The graph is assembled passively from
// flow telemetry and the device inventory - no active scans run here.
//
// The result is consumed by:
//   - the TUI topology view (rendered as a connection list)
//   - replay (snapshotted alongside flows / firewall state)
//   - alerting (a host going from reachable to unreachable raises an event)
package topology

import (
	"sort"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/discovery"
	"github.com/noahzmr/testudo/internal/flows"
)

// Node is one host in the topology.
type Node struct {
	IP       string
	Hostname string
	Vendor   string
	Iface    string
	LastSeen time.Time
}

// Edge is a directed conversation between two nodes on one interface and
// protocol. Edges accumulate byte counts across all flows that match.
type Edge struct {
	SrcIP    string
	DstIP    string
	Iface    string
	Proto    string
	Bytes    uint64
	Packets  uint64
	LastSeen time.Time
}

// Graph is a snapshot of nodes and edges at a point in time.
type Graph struct {
	BuiltAt time.Time
	Nodes   []Node
	Edges   []Edge
}

// Builder assembles graphs on demand. Stateless aside from caching the
// most recent snapshot for cheap re-reads from the UI layer.
type Builder struct {
	mu   sync.RWMutex
	last Graph
}

func NewBuilder() *Builder { return &Builder{} }

// Build assembles a fresh Graph from the supplied inventory and flow
// snapshots. Both inputs are read-only.
func (b *Builder) Build(devices []discovery.Device, fls []flows.FlowStats) Graph {
	nodes := nodesFromDevices(devices)
	nodeIndex := make(map[string]int, len(nodes))
	for i, n := range nodes {
		nodeIndex[n.IP] = i
	}

	edgeKey := func(src, dst, iface, proto string) string {
		return src + "|" + dst + "|" + iface + "|" + proto
	}
	edgeMap := make(map[string]*Edge, len(fls))

	for _, f := range fls {
		// Ensure both endpoints appear as nodes even if discovery didn't see them.
		for _, ip := range []string{f.Key.A.IP, f.Key.B.IP} {
			if _, ok := nodeIndex[ip]; !ok {
				nodes = append(nodes, Node{IP: ip, LastSeen: f.LastSeen})
				nodeIndex[ip] = len(nodes) - 1
			}
		}
		// Direction A→B: bytes that flowed from A to B.
		if f.BytesAtoB > 0 {
			k := edgeKey(f.Key.A.IP, f.Key.B.IP, f.Key.Iface, f.Key.Proto)
			e, ok := edgeMap[k]
			if !ok {
				e = &Edge{SrcIP: f.Key.A.IP, DstIP: f.Key.B.IP, Iface: f.Key.Iface, Proto: f.Key.Proto}
				edgeMap[k] = e
			}
			e.Bytes += f.BytesAtoB
			e.Packets += f.Packets
			if f.LastSeen.After(e.LastSeen) {
				e.LastSeen = f.LastSeen
			}
		}
		// Direction B→A.
		if f.BytesBtoA > 0 {
			k := edgeKey(f.Key.B.IP, f.Key.A.IP, f.Key.Iface, f.Key.Proto)
			e, ok := edgeMap[k]
			if !ok {
				e = &Edge{SrcIP: f.Key.B.IP, DstIP: f.Key.A.IP, Iface: f.Key.Iface, Proto: f.Key.Proto}
				edgeMap[k] = e
			}
			e.Bytes += f.BytesBtoA
			e.Packets += f.Packets
			if f.LastSeen.After(e.LastSeen) {
				e.LastSeen = f.LastSeen
			}
		}
	}

	edges := make([]Edge, 0, len(edgeMap))
	for _, e := range edgeMap {
		edges = append(edges, *e)
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].Bytes > edges[j].Bytes })
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].IP < nodes[j].IP })

	g := Graph{BuiltAt: time.Now(), Nodes: nodes, Edges: edges}
	b.mu.Lock()
	b.last = g
	b.mu.Unlock()
	return g
}

// Last returns the most recent Build result. Empty until Build is called.
func (b *Builder) Last() Graph {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.last
}

func nodesFromDevices(devs []discovery.Device) []Node {
	out := make([]Node, 0, len(devs))
	for _, d := range devs {
		out = append(out, Node{
			IP:       d.IP,
			Hostname: d.Hostname,
			Vendor:   d.Vendor,
			Iface:    d.Iface,
			LastSeen: d.LastSeen,
		})
	}
	return out
}
