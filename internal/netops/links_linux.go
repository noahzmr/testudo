//go:build linux

package netops

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// linkAlias marks the devices Testudo created. VRF devices carry the same
// mark; each sync touches only its own kinds.
const linkAlias = "testudo"

var linkKinds = map[string]bool{"bond": true, "bridge": true, "vlan": true}

func (w *Writer) syncLinksDirect(spec LinksSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	var errs []error
	want := map[string]bool{}
	// Bonds and bridges first: a VLAN may sit on one.
	order := map[string]int{"bond": 0, "bridge": 1, "vlan": 2}
	links := append([]LinkSpec(nil), spec.Links...)
	for i := 1; i < len(links); i++ {
		for j := i; j > 0 && order[links[j].Kind] < order[links[j-1].Kind]; j-- {
			links[j], links[j-1] = links[j-1], links[j]
		}
	}
	for _, l := range links {
		want[l.Name] = true
		link, err := ensureLink(l)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", l.Kind, l.Name, err))
			continue
		}
		if l.Kind == "bridge" {
			if err := setBridgeSTP(l.Name, l.STP); err != nil {
				errs = append(errs, fmt.Errorf("bridge %s: stp: %w", l.Name, err))
			}
		}
		if l.Kind != "vlan" {
			errs = append(errs, syncMembers(l, link)...)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			errs = append(errs, fmt.Errorf("%s %s up: %w", l.Kind, l.Name, err))
		}
	}
	// Our devices that are no longer wanted, VLANs first.
	all, err := netlink.LinkList()
	if err != nil {
		errs = append(errs, err)
	}
	for _, pass := range []string{"vlan", "bridge", "bond"} {
		for _, link := range all {
			a := link.Attrs()
			if link.Type() != pass || a.Alias != linkAlias || want[a.Name] {
				continue
			}
			if err := netlink.LinkDel(link); err != nil && !isNotFound(err) {
				errs = append(errs, fmt.Errorf("remove %s %s: %w", pass, a.Name, err))
			}
		}
	}
	return errors.Join(errs...)
}

func isNotFound(err error) bool {
	var nf netlink.LinkNotFoundError
	return errors.As(err, &nf)
}

// ensureLink returns the device for l, created or recreated as needed.
func ensureLink(l LinkSpec) (netlink.Link, error) {
	link, err := netlink.LinkByName(l.Name)
	if err != nil && !isNotFound(err) {
		return nil, err
	}
	if err == nil {
		if link.Attrs().Alias != linkAlias {
			return nil, errors.New("a device of this name exists and was not made by Testudo")
		}
		if link.Type() == l.Kind && !differs(l, link) {
			return link, nil
		}
		// Kind, parent, id, mode and the like change only by recreating.
		if err := netlink.LinkDel(link); err != nil {
			return nil, err
		}
	}
	nl, err := newLink(l)
	if err != nil {
		return nil, err
	}
	if err := netlink.LinkAdd(nl); err != nil {
		return nil, err
	}
	link, err = netlink.LinkByName(l.Name)
	if err != nil {
		return nil, err
	}
	if err := netlink.LinkSetAlias(link, linkAlias); err != nil {
		_ = netlink.LinkDel(link)
		return nil, err
	}
	return link, nil
}

// primaryModes are the bond modes with a primary member; the others refuse
// one.
var primaryModes = map[netlink.BondMode]bool{netlink.BOND_MODE_ACTIVE_BACKUP: true,
	netlink.BOND_MODE_BALANCE_TLB: true, netlink.BOND_MODE_BALANCE_ALB: true}

func vlanProto(p string) netlink.VlanProtocol {
	if p == "802.1ad" {
		return netlink.VLAN_PROTOCOL_8021AD
	}
	return netlink.VLAN_PROTOCOL_8021Q
}

func bondMode(l LinkSpec) netlink.BondMode {
	if l.Mode == "" {
		return netlink.BOND_MODE_802_3AD
	}
	return netlink.StringToBondMode(l.Mode)
}

func newLink(l LinkSpec) (netlink.Link, error) {
	attrs := netlink.NewLinkAttrs()
	attrs.Name = l.Name
	switch l.Kind {
	case "vlan":
		parent, err := netlink.LinkByName(l.Parent)
		if err != nil {
			return nil, fmt.Errorf("parent %s: %w", l.Parent, err)
		}
		attrs.ParentIndex = parent.Attrs().Index
		return &netlink.Vlan{LinkAttrs: attrs, VlanId: l.VID, VlanProtocol: vlanProto(l.Protocol)}, nil
	case "bond":
		b := netlink.NewLinkBond(attrs)
		b.Mode = bondMode(l)
		if b.Mode == netlink.BOND_MODE_UNKNOWN {
			return nil, fmt.Errorf("unknown bond mode %q", l.Mode)
		}
		b.Miimon = 100
		if l.MIIMon > 0 {
			b.Miimon = l.MIIMon
		}
		if b.Mode == netlink.BOND_MODE_802_3AD {
			b.LacpRate = netlink.BOND_LACP_RATE_SLOW
			if l.LACPRate != "" {
				b.LacpRate = netlink.StringToBondLacpRate(l.LACPRate)
			}
		}
		if l.HashPolicy != "" {
			b.XmitHashPolicy = netlink.StringToBondXmitHashPolicy(l.HashPolicy)
		}
		if l.Primary != "" && primaryModes[b.Mode] {
			// The kernel keeps the name and makes it primary once enslaved.
			if p, err := netlink.LinkByName(l.Primary); err == nil {
				b.Primary = p.Attrs().Index
			}
		}
		return b, nil
	case "bridge":
		vf := l.VLANFiltering
		return &netlink.Bridge{LinkAttrs: attrs, VlanFiltering: &vf}, nil
	}
	return nil, fmt.Errorf("unknown kind %q", l.Kind)
}

// differs reports whether an existing device of the right kind has an
// attribute the spec sets differently and the kernel cannot change in place.
func differs(l LinkSpec, link netlink.Link) bool {
	switch v := link.(type) {
	case *netlink.Vlan:
		parent, err := netlink.LinkByName(l.Parent)
		return err != nil || v.ParentIndex != parent.Attrs().Index || v.VlanId != l.VID || v.VlanProtocol != vlanProto(l.Protocol)
	case *netlink.Bond:
		miimon := 100
		if l.MIIMon > 0 {
			miimon = l.MIIMon
		}
		if v.Mode != bondMode(l) || v.Miimon != miimon {
			return true
		}
		if l.HashPolicy != "" && v.XmitHashPolicy != netlink.StringToBondXmitHashPolicy(l.HashPolicy) {
			return true
		}
		if v.Mode == netlink.BOND_MODE_802_3AD && l.LACPRate != "" && v.LacpRate != netlink.StringToBondLacpRate(l.LACPRate) {
			return true
		}
		if l.Primary != "" && primaryModes[v.Mode] {
			p, err := netlink.LinkByName(l.Primary)
			if err != nil || v.Primary != p.Attrs().Index {
				return true
			}
		}
	case *netlink.Bridge:
		return v.VlanFiltering != nil && *v.VlanFiltering != l.VLANFiltering
	}
	return false
}

// setBridgeSTP switches the bridge's spanning tree over rtnetlink, which
// works in the namespace the process is in (sysfs shows the one it was
// mounted in).
func setBridgeSTP(name string, on bool) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	var v uint32
	if on {
		v = 1
	}
	req := nl.NewNetlinkRequest(unix.RTM_NEWLINK, unix.NLM_F_ACK)
	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(link.Attrs().Index)
	req.AddData(msg)
	info := nl.NewRtAttr(unix.IFLA_LINKINFO, nil)
	info.AddRtAttr(nl.IFLA_INFO_KIND, nl.NonZeroTerminated("bridge"))
	data := info.AddRtAttr(nl.IFLA_INFO_DATA, nil)
	data.AddRtAttr(nl.IFLA_BR_STP_STATE, nl.Uint32Attr(v))
	req.AddData(info)
	_, err = req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// BridgeSTP reads whether the bridge runs spanning tree.
func BridgeSTP(name string) (bool, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return false, err
	}
	req := nl.NewNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_ACK)
	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(link.Attrs().Index)
	req.AddData(msg)
	msgs, err := req.Execute(unix.NETLINK_ROUTE, unix.RTM_NEWLINK)
	if err != nil || len(msgs) == 0 {
		return false, err
	}
	attrs, err := nl.ParseRouteAttr(msgs[0][unix.SizeofIfInfomsg:])
	if err != nil {
		return false, err
	}
	for _, a := range attrs {
		if a.Attr.Type != unix.IFLA_LINKINFO {
			continue
		}
		infos, _ := nl.ParseRouteAttr(a.Value)
		for _, i := range infos {
			if i.Attr.Type != nl.IFLA_INFO_DATA {
				continue
			}
			data, _ := nl.ParseRouteAttr(i.Value)
			for _, d := range data {
				if d.Attr.Type == nl.IFLA_BR_STP_STATE && len(d.Value) >= 4 {
					return native.Uint32(d.Value[:4]) != 0, nil
				}
			}
		}
	}
	return false, nil
}

var native = nl.NativeEndian()

// syncMembers enslaves the members of a bond or the ports of a bridge and
// releases the ones that left.
func syncMembers(l LinkSpec, master netlink.Link) []error {
	var errs []error
	idx := master.Attrs().Index
	members := map[string]bool{}
	for _, m := range l.Members {
		members[m] = true
		dev, err := netlink.LinkByName(m)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s %s: member %s: %w", l.Kind, l.Name, m, err))
			continue
		}
		if dev.Attrs().MasterIndex == idx {
			continue
		}
		if l.Kind == "bond" {
			// A bond takes only members that are down; it brings them up.
			if err := netlink.LinkSetDown(dev); err != nil {
				errs = append(errs, fmt.Errorf("bond %s: member %s down: %w", l.Name, m, err))
				continue
			}
		}
		if err := netlink.LinkSetMaster(dev, master); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: member %s: %w", l.Kind, l.Name, m, err))
			continue
		}
		_ = netlink.LinkSetUp(dev)
	}
	all, _ := netlink.LinkList()
	for _, dev := range all {
		if dev.Attrs().MasterIndex == idx && !members[dev.Attrs().Name] {
			if err := netlink.LinkSetNoMaster(dev); err != nil {
				errs = append(errs, fmt.Errorf("%s %s: release %s: %w", l.Kind, l.Name, dev.Attrs().Name, err))
			}
		}
	}
	return errs
}
