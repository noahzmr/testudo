package flows

import (
	"net"
	"sort"
	"strings"
)

// HostRollup aggregates every flow heading to/from one remote host. Local
// endpoints (RFC1918, loopback, link-local) are treated as "this side" and
// rolled up under the **non-local** counterpart so the dashboard shows
// "talking to nas01.lan" rather than "talking to 192.168.1.20".
type HostRollup struct {
	Host      string // remote IP (or DNS name when known)
	DNS       string
	Country   string // optional - populated when a GeoIP DB is configured
	IsLAN     bool   // true when the remote is RFC1918 / link-local
	Bytes     uint64
	Packets   uint64
	Flows     int
	FirstSeen int64 // unix milli
	LastSeen  int64
}

// ProcessRollup aggregates every flow owned by one local process.
type ProcessRollup struct {
	Process string
	Bytes   uint64
	Packets uint64
	Flows   int
}

// ServiceRollup aggregates every flow by its classified service name
// (`flows.serviceFor` populates `Service`).
type ServiceRollup struct {
	Service string
	Proto   string
	Port    uint16
	Bytes   uint64
	Packets uint64
	Flows   int
}

// TopHosts returns the top-N remote hosts by total bytes. `n <= 0` returns
// everything.
func TopHosts(snap []FlowStats, n int) []HostRollup {
	agg := map[string]*HostRollup{}
	for _, f := range snap {
		// Pick the "remote" endpoint - the one that is NOT a private/LAN IP.
		// When both endpoints are private (host-to-host LAN traffic) we keep
		// the lexicographically larger one so the rollup is stable.
		var remoteIP, remotePort, _ = pickRemote(f.Key.A.IP, f.Key.B.IP)
		_ = remotePort
		host := remoteIP
		if f.DNSName != "" {
			host = f.DNSName
		}
		r, ok := agg[host]
		if !ok {
			r = &HostRollup{
				Host:      host,
				DNS:       f.DNSName,
				IsLAN:     isLocalIP(net.ParseIP(remoteIP)),
				FirstSeen: f.FirstSeen.UnixMilli(),
				LastSeen:  f.LastSeen.UnixMilli(),
			}
			agg[host] = r
		}
		r.Bytes += f.Bytes
		r.Packets += f.Packets
		r.Flows++
		if f.LastSeen.UnixMilli() > r.LastSeen {
			r.LastSeen = f.LastSeen.UnixMilli()
		}
	}
	out := make([]HostRollup, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// TopProcesses returns the top-N processes by total bytes. Flows without a
// resolved process name are bucketed under "-" so the row still surfaces.
func TopProcesses(snap []FlowStats, n int) []ProcessRollup {
	agg := map[string]*ProcessRollup{}
	for _, f := range snap {
		name := strings.TrimSpace(f.Process)
		if name == "" {
			name = "-"
		}
		r, ok := agg[name]
		if !ok {
			r = &ProcessRollup{Process: name}
			agg[name] = r
		}
		r.Bytes += f.Bytes
		r.Packets += f.Packets
		r.Flows++
	}
	out := make([]ProcessRollup, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// TopServices returns the top-N upper-layer services by total bytes.
// Flows that didn't match the well-known catalog are bucketed under "-".
func TopServices(snap []FlowStats, n int) []ServiceRollup {
	type key struct {
		Service string
		Proto   string
		Port    uint16
	}
	agg := map[key]*ServiceRollup{}
	for _, f := range snap {
		port := f.Key.A.Port
		if f.Key.B.Port < port && f.Key.B.Port != 0 {
			port = f.Key.B.Port
		}
		svc := f.Service
		if svc == "" {
			svc = "-"
		}
		k := key{Service: svc, Proto: strings.ToLower(f.Key.Proto), Port: port}
		r, ok := agg[k]
		if !ok {
			r = &ServiceRollup{Service: svc, Proto: k.Proto, Port: port}
			agg[k] = r
		}
		r.Bytes += f.Bytes
		r.Packets += f.Packets
		r.Flows++
	}
	out := make([]ServiceRollup, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// pickRemote decides which endpoint of a flow is the "remote" one. The
// caller already knows which endpoint is A vs B; we return the IP (and
// keep the port for callers who need it) of the side that is NOT in a
// private / link-local / loopback range. When both sides are local we
// fall back to the lexicographically larger string so the rollup key is
// stable across renders.
func pickRemote(aIP, bIP string) (ip string, port uint16, isLocal bool) {
	aLocal := isLocalIP(net.ParseIP(aIP))
	bLocal := isLocalIP(net.ParseIP(bIP))
	switch {
	case aLocal && !bLocal:
		return bIP, 0, false
	case !aLocal && bLocal:
		return aIP, 0, false
	default:
		// Both local or both remote - pick stably.
		if aIP > bIP {
			return aIP, 0, aLocal && bLocal
		}
		return bIP, 0, aLocal && bLocal
	}
}

// isLocalIP reports whether ip falls in an RFC1918 / link-local /
// loopback range - i.e. it should be treated as "this side" of a flow.
// Returns true for the nil IP too so unparsable strings don't slip
// through as "remote".
func isLocalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	v4 := ip.To4()
	if v4 != nil {
		switch {
		case v4[0] == 10:
			return true
		case v4[0] == 172 && v4[1]&0xF0 == 16:
			return true
		case v4[0] == 192 && v4[1] == 168:
			return true
		case v4[0] == 169 && v4[1] == 254:
			return true
		}
		return false
	}
	// IPv6 ULA fc00::/7
	if len(ip) == 16 && ip[0]&0xFE == 0xFC {
		return true
	}
	return false
}

// IsLAN exposes the local-range check so other packages can tag flows
// without re-importing net.
func IsLAN(ipStr string) bool {
	return isLocalIP(net.ParseIP(ipStr))
}
