package ifstage

import (
	"errors"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// netlinkLinks reads a device and its addresses. Reading needs no
// privileges.
func netlinkLinks(name string) (Link, bool, error) {
	link, err := netlink.LinkByName(name)
	var notFound netlink.LinkNotFoundError
	if errors.As(err, &notFound) {
		return Link{}, false, nil
	}
	if err != nil {
		return Link{}, false, err
	}
	attrs := link.Attrs()
	l := Link{Up: attrs.Flags&net.FlagUp != 0, MTU: attrs.MTU}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return l, true, err
	}
	for _, a := range addrs {
		if a.IPNet == nil {
			continue
		}
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		ones, _ := a.Mask.Size()
		p := netip.PrefixFrom(ip.Unmap(), ones).String()
		l.Addresses = append(l.Addresses, p)
		if a.Flags&unix.IFA_F_PERMANENT == 0 {
			l.Dynamic = append(l.Dynamic, p)
		}
	}
	return l, true, nil
}
