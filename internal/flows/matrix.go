package flows

import "sort"

// LANPair is one row in the LAN host-to-host matrix. A and B are
// ordered the same way the FlowKey orders them (A lexicographically
// smaller), so the matrix is symmetric - the same pair never appears
// twice.
type LANPair struct {
	A       string
	B       string
	Bytes   uint64
	Packets uint64
	Flows   int
}

// LANMatrix aggregates flow stats into LAN-internal host pairs. Only
// flows where BOTH endpoints are RFC1918 / link-local are kept;
// everything WAN-bound is filtered out so the matrix shows the LAN's
// east-west traffic exclusively. Sorted by bytes desc; n<=0 returns all.
func LANMatrix(snap []FlowStats, n int) []LANPair {
	type key struct{ A, B string }
	agg := map[key]*LANPair{}
	for _, f := range snap {
		if !IsLAN(f.Key.A.IP) || !IsLAN(f.Key.B.IP) {
			continue
		}
		k := key{A: f.Key.A.IP, B: f.Key.B.IP}
		p, ok := agg[k]
		if !ok {
			p = &LANPair{A: k.A, B: k.B}
			agg[k] = p
		}
		p.Bytes += f.Bytes
		p.Packets += f.Packets
		p.Flows++
	}
	out := make([]LANPair, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}
