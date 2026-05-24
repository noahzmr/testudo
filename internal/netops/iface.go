// Package netops wraps Linux netlink operations (interfaces, routes,
// firewall, NAT) behind a uniform read/write API.
//
// All write operations are gated by Writer.AllowWrites — set at construction
// from --allow-netops-write. With writes disabled, callers can read and
// inspect freely; writes return ErrWritesDisabled without touching the kernel.
package netops

import (
	"errors"
	"fmt"
	"net"
	"sort"

	"github.com/vishvananda/netlink"
)

// ErrWritesDisabled is returned by every mutating call when AllowWrites=false.
var ErrWritesDisabled = errors.New("netops writes are disabled — toggle in Settings tab or start with --allow-netops-write")

// Writer is the entry point for both reads and writes. Construct one per
// process and pass it around; it has no fields that change after init.
type Writer struct {
	AllowWrites bool
}

// IfaceInfo is a denormalised view of one network interface.
type IfaceInfo struct {
	Name      string
	Index     int
	MTU       int
	Up        bool
	Running   bool
	HWAddr    string
	Addrs     []string
	TxBytes   uint64
	RxBytes   uint64
	TxPackets uint64
	RxPackets uint64
}

// ListIfaces returns every interface known to the kernel, sorted by name.
func (w *Writer) ListIfaces() ([]IfaceInfo, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("link list: %w", err)
	}
	out := make([]IfaceInfo, 0, len(links))
	for _, l := range links {
		attrs := l.Attrs()
		info := IfaceInfo{
			Name:    attrs.Name,
			Index:   attrs.Index,
			MTU:     attrs.MTU,
			Up:      attrs.Flags&net.FlagUp != 0,
			Running: attrs.OperState == netlink.OperUp,
			HWAddr:  attrs.HardwareAddr.String(),
		}
		if s := attrs.Statistics; s != nil {
			info.TxBytes, info.RxBytes = s.TxBytes, s.RxBytes
			info.TxPackets, info.RxPackets = s.TxPackets, s.RxPackets
		}
		// Addresses (IPv4 + IPv6).
		if addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL); err == nil {
			for _, a := range addrs {
				if a.IPNet != nil {
					info.Addrs = append(info.Addrs, a.IPNet.String())
				}
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// SetIfaceUp brings the named interface up. Returns ErrWritesDisabled when
// writes are off.
func (w *Writer) SetIfaceUp(name string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %s: %w", name, err)
	}
	return netlink.LinkSetUp(link)
}

// SetIfaceDown brings the named interface down.
func (w *Writer) SetIfaceDown(name string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %s: %w", name, err)
	}
	return netlink.LinkSetDown(link)
}

// AddAddr adds a CIDR address to the named interface.
func (w *Writer) AddAddr(iface, cidr string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("link %s: %w", iface, err)
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("parse cidr %q: %w", cidr, err)
	}
	return netlink.AddrAdd(link, addr)
}

// DelAddr removes a CIDR address from the named interface.
func (w *Writer) DelAddr(iface, cidr string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("link %s: %w", iface, err)
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("parse cidr %q: %w", cidr, err)
	}
	return netlink.AddrDel(link, addr)
}

// FlushAddrs removes every address from iface. Useful before swapping
// static config or before bringing the iface down.
func (w *Writer) FlushAddrs(iface string) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("link %s: %w", iface, err)
	}
	addrs, err := netlink.AddrList(link, 0)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		_ = netlink.AddrDel(link, &a)
	}
	return nil
}

// SetMTU changes the interface MTU.
func (w *Writer) SetMTU(iface string, mtu int) error {
	if !w.AllowWrites {
		return ErrWritesDisabled
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("link %s: %w", iface, err)
	}
	return netlink.LinkSetMTU(link, mtu)
}
