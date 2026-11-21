// Package flowcorr joins what several sites saw of the same connections.
// Every site collects its own flows; nothing of it goes through the
// cluster's consensus. When someone asks, the flows of every member are
// fetched and a connection seen at more than one place becomes one entry,
// with where it was seen, over which tunnel and path.
package flowcorr

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/noahzmr/testudo/internal/flows"
)

// NodeFlows is what one member reports.
type NodeFlows struct {
	Node  string            `json:"node"`
	Site  string            `json:"site"`
	At    time.Time         `json:"at"`
	Flows []flows.FlowStats `json:"flows"`
	Error string            `json:"error,omitempty"`
}

// Sighting is one place a connection was seen.
type Sighting struct {
	Node      string      `json:"node"`
	Site      string      `json:"site"`
	Iface     string      `json:"iface"`
	Bytes     uint64      `json:"bytes"`
	Packets   uint64      `json:"packets"`
	FirstSeen time.Time   `json:"first_seen"`
	LastSeen  time.Time   `json:"last_seen"`
	Attrs     flows.Attrs `json:"attrs"`
}

// Connection is one connection with every place it was seen.
type Connection struct {
	Proto string `json:"proto"`
	A     string `json:"a"`
	B     string `json:"b"`
	// Sites lists the sites that saw it; Paths the fabric colors it took
	// between them.
	Sites     []string   `json:"sites"`
	Paths     []string   `json:"paths,omitempty"`
	Bytes     uint64     `json:"bytes"` // the largest count any one place saw
	Sightings []Sighting `json:"sightings"`
}

func endpoint(e flows.Endpoint) string { return net.JoinHostPort(e.IP, strconv.Itoa(int(e.Port))) }

// key is a connection's identity whichever way round it was written.
func key(proto, a, b string) string {
	if b < a {
		a, b = b, a
	}
	return proto + "|" + a + "|" + b
}

// tupleKeys reads the "proto src:port > dst:port" form of an attribution.
func tupleKey(t string) string {
	proto, rest, ok := strings.Cut(t, " ")
	if !ok {
		return ""
	}
	a, b, ok := strings.Cut(rest, " > ")
	if !ok {
		return ""
	}
	return key(proto, a, b)
}

type union struct{ parent []int }

func (u *union) find(i int) int {
	for u.parent[i] != i {
		u.parent[i] = u.parent[u.parent[i]]
		i = u.parent[i]
	}
	return i
}

func (u *union) join(i, j int) { u.parent[u.find(i)] = u.find(j) }

// Correlate joins the members' flows. A connection is the same where it
// has the same addresses and ports (before or after a translation), seen
// within window of each other. Only connections seen by more than one
// member are returned unless all is set.
func Correlate(sets []NodeFlows, window time.Duration, all bool) []Connection {
	type item struct {
		node, site string
		f          flows.FlowStats
		keys       []string
	}
	var items []item
	for _, s := range sets {
		for _, f := range s.Flows {
			own := key(f.Key.Proto, endpoint(f.Key.A), endpoint(f.Key.B))
			ks := []string{own}
			for _, t := range []string{f.Attrs.PreNAT, f.Attrs.PostNAT} {
				if k := tupleKey(t); k != "" && k != own {
					ks = append(ks, k)
				}
			}
			items = append(items, item{node: s.Node, site: s.Site, f: f, keys: ks})
		}
	}
	u := &union{parent: make([]int, len(items))}
	for i := range u.parent {
		u.parent[i] = i
	}
	byKey := map[string][]int{}
	for i, it := range items {
		for _, k := range it.keys {
			byKey[k] = append(byKey[k], i)
		}
	}
	overlap := func(a, b flows.FlowStats) bool {
		return !a.LastSeen.Add(window).Before(b.FirstSeen) && !b.LastSeen.Add(window).Before(a.FirstSeen)
	}
	for _, list := range byKey {
		for x := 1; x < len(list); x++ {
			for y := 0; y < x; y++ {
				if overlap(items[list[x]].f, items[list[y]].f) {
					u.join(list[x], list[y])
				}
			}
		}
	}
	groups := map[int][]int{}
	for i := range items {
		r := u.find(i)
		groups[r] = append(groups[r], i)
	}
	var out []Connection
	for _, g := range groups {
		nodes := map[string]bool{}
		for _, i := range g {
			nodes[items[i].node] = true
		}
		if len(nodes) < 2 && !all {
			continue
		}
		first := items[g[0]].f
		c := Connection{Proto: first.Key.Proto, A: endpoint(first.Key.A), B: endpoint(first.Key.B)}
		sites, paths := map[string]bool{}, map[string]bool{}
		for _, i := range g {
			it := items[i]
			c.Sightings = append(c.Sightings, Sighting{Node: it.node, Site: it.site, Iface: it.f.Key.Iface, Bytes: it.f.Bytes,
				Packets: it.f.Packets, FirstSeen: it.f.FirstSeen, LastSeen: it.f.LastSeen, Attrs: it.f.Attrs})
			if it.site != "" {
				sites[it.site] = true
			}
			if it.f.Attrs.Path != "" && !it.f.Attrs.Carrier {
				paths[it.f.Attrs.Path] = true
			}
			if it.f.Bytes > c.Bytes {
				c.Bytes = it.f.Bytes
			}
			// The pre-translation form names the connection best.
			if t := it.f.Attrs.PreNAT; t != "" {
				if _, rest, ok := strings.Cut(t, " "); ok {
					if a, b, ok := strings.Cut(rest, " > "); ok {
						c.A, c.B = a, b
					}
				}
			}
		}
		for s := range sites {
			c.Sites = append(c.Sites, s)
		}
		for p := range paths {
			c.Paths = append(c.Paths, p)
		}
		sort.Strings(c.Sites)
		sort.Strings(c.Paths)
		sort.Slice(c.Sightings, func(i, j int) bool {
			a, b := c.Sightings[i], c.Sightings[j]
			return a.Node < b.Node || a.Node == b.Node && a.Iface < b.Iface
		})
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	return out
}
