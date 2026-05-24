package netops

import (
	"fmt"
	"net"
	"sort"

	"github.com/vishvananda/netlink"
)

// RouteInfo is a denormalised view of one kernel route.
type RouteInfo struct {
	Dst       string // CIDR or "default"
	Gateway   string // empty if direct
	Iface     string // outgoing interface name
	Protocol  string // human-readable RTPROT_*
	Scope     string // human-readable RT_SCOPE_*
	Metric    int
	Family    string // ipv4 / ipv6
	Table     int    // 254 = main
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

// AddDefaultRoute installs a default route via gateway on iface.
func (w *Writer) AddDefaultRoute(iface, gateway string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("link %s: %w", iface, err)
	}
	gw := net.ParseIP(gateway)
	if gw == nil {
		return fmt.Errorf("invalid gateway %q", gateway)
	}
	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	if gw.To4() == nil {
		_, dst, _ = net.ParseCIDR("::/0")
	}
	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Gw:        gw,
	})
}

// AddRoute installs a route to a CIDR via gateway (optional) and iface.
func (w *Writer) AddRoute(cidr, gateway, iface string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse cidr %q: %w", cidr, err)
	}
	r := &netlink.Route{Dst: dst}
	if gateway != "" {
		gw := net.ParseIP(gateway)
		if gw == nil {
			return fmt.Errorf("invalid gateway %q", gateway)
		}
		r.Gw = gw
	}
	if iface != "" {
		link, err := netlink.LinkByName(iface)
		if err != nil {
			return fmt.Errorf("link %s: %w", iface, err)
		}
		r.LinkIndex = link.Attrs().Index
	}
	return netlink.RouteAdd(r)
}

// DelRoute removes the route to a CIDR.
func (w *Writer) DelRoute(cidr string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse cidr %q: %w", cidr, err)
	}
	return netlink.RouteDel(&netlink.Route{Dst: dst})
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
