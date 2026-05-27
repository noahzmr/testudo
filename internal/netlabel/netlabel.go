// Package netlabel classifies an IP address into an operator-facing scope
// bucket (public / private / internal / multicast) and, for IPv4, the
// historical classful network (A-E).
//
// It exists so the TUI and the Web UI render identical labels from a single
// source of truth rather than each re-deriving address ranges. The flows
// package keeps its own isLocalIP for hot-path rollup; this package is the
// presentation-layer classifier and may carry a little more detail.
package netlabel

import (
	"net"
	"strings"
)

// Scope is the routability bucket an address falls into.
type Scope string

const (
	// ScopePublic is a globally routable address.
	ScopePublic Scope = "public"
	// ScopePrivate is routed inside an organisation but never on the public
	// internet: RFC1918, IPv6 ULA (fc00::/7), and CGNAT (100.64.0.0/10).
	ScopePrivate Scope = "private"
	// ScopeInternal never crosses a router: loopback, link-local,
	// unspecified, and the IPv4 limited broadcast address.
	ScopeInternal Scope = "internal"
	// ScopeMulticast is a one-to-many group address (224.0.0.0/4, ff00::/8).
	ScopeMulticast Scope = "multicast"
	// ScopeUnknown is an unparsable string or a reserved (class E) address.
	ScopeUnknown Scope = "unknown"
)

// Label is the full classification of one address.
type Label struct {
	Scope  Scope  // routability bucket
	Class  string // IPv4 classful network "A".."E"; empty for IPv6 / unparsable
	Detail string // human reason: "RFC1918", "loopback", "CGNAT", "ULA", "global", ...
}

// Short returns a three-to-five letter code for dense table cells.
func (s Scope) Short() string {
	switch s {
	case ScopePublic:
		return "pub"
	case ScopePrivate:
		return "prv"
	case ScopeInternal:
		return "int"
	case ScopeMulticast:
		return "mcast"
	default:
		return "?"
	}
}

// Tag renders a compact "scope·class" badge for terminal cells, e.g. "prv·A",
// "pub·C", or just "int" when no IPv4 class applies.
func (l Label) Tag() string {
	t := l.Scope.Short()
	if l.Class != "" {
		t += "·" + l.Class
	}
	return t
}

// Classify parses s and returns its scope, IPv4 class, and a human-readable
// detail. An empty or unparsable string yields {ScopeUnknown}.
func Classify(s string) Label {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return Label{Scope: ScopeUnknown}
	}
	l := Label{Class: classOf(ip)}
	switch {
	case ip.IsUnspecified():
		l.Scope, l.Detail = ScopeInternal, "unspecified"
	case ip.IsLoopback():
		l.Scope, l.Detail = ScopeInternal, "loopback"
	case ip.IsLinkLocalUnicast():
		l.Scope, l.Detail = ScopeInternal, "link-local"
	case ip.IsMulticast():
		l.Scope, l.Detail = ScopeMulticast, "multicast"
	case isV4Broadcast(ip):
		l.Scope, l.Detail = ScopeInternal, "broadcast"
	case isCGNAT(ip):
		l.Scope, l.Detail = ScopePrivate, "CGNAT"
	case ip.IsPrivate():
		// IsPrivate covers RFC1918 (v4) and ULA fc00::/7 (v6).
		l.Scope = ScopePrivate
		if ip.To4() != nil {
			l.Detail = "RFC1918"
		} else {
			l.Detail = "ULA"
		}
	case isV4ClassE(ip):
		l.Scope, l.Detail = ScopeUnknown, "reserved"
	default:
		l.Scope, l.Detail = ScopePublic, "global"
	}
	return l
}

// classOf returns the IPv4 classful network letter, or "" for IPv6.
func classOf(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	switch o := v4[0]; {
	case o < 128:
		return "A"
	case o < 192:
		return "B"
	case o < 224:
		return "C"
	case o < 240:
		return "D"
	default:
		return "E"
	}
}

// isCGNAT reports whether ip is in the carrier-grade NAT range 100.64.0.0/10.
func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
}

// isV4Broadcast reports whether ip is the 255.255.255.255 limited broadcast.
func isV4Broadcast(ip net.IP) bool {
	return ip.Equal(net.IPv4bcast)
}

// isV4ClassE reports whether ip is in the reserved 240.0.0.0/4 range.
func isV4ClassE(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] >= 240
}
