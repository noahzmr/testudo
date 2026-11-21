package netops

import (
	"fmt"
	"sort"

	"github.com/vishvananda/netlink"
)

// RouteInfo is a denormalised view of one kernel route.
type RouteInfo struct {
	Dst      string // CIDR or "default"
	Gateway  string // empty if direct
	Iface    string // outgoing interface name
	Protocol string // human-readable RTPROT_*
	Scope    string // human-readable RT_SCOPE_*
	Metric   int
	Family   string // ipv4 / ipv6
	Table    int    // 254 = main
}

// ListRoutes returns the kernel's full routing table (all tables) ordered
// by family then by destination prefix length descending.
func (w *Writer) ListRoutes() ([]RouteInfo, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("route list: %w", err)
	}
	out := make([]RouteInfo, 0, len(routes))
	for _, r := range routes {
		out = append(out, routeToInfo(r))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Dst < out[j].Dst
	})
	return out, nil
}

func routeToInfo(r netlink.Route) RouteInfo {
	info := RouteInfo{
		Protocol: netlink.RouteProtocol(r.Protocol).String(),
		Scope:    r.Scope.String(),
		Metric:   r.Priority,
		Table:    r.Table,
	}
	if r.Dst == nil {
		info.Dst = "default"
		info.Family = "ipv4"
	} else {
		info.Dst = r.Dst.String()
		if r.Dst.IP.To4() != nil {
			info.Family = "ipv4"
		} else {
			info.Family = "ipv6"
		}
	}
	if r.Gw != nil {
		info.Gateway = r.Gw.String()
	}
	if r.LinkIndex > 0 {
		if link, err := netlink.LinkByIndex(r.LinkIndex); err == nil {
			info.Iface = link.Attrs().Name
		}
	}
	return info
}
