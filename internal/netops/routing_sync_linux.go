//go:build linux

package netops

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// vrfAlias marks the VRF devices this program created, so it only ever
// removes its own.
const vrfAlias = "testudo"

func (w *Writer) syncRoutingDirect(spec RoutingSpec) error {
	var errs []error
	// VRF devices: create or correct, enslave members, remove our leftovers.
	want := map[string]RoutingVRF{}
	for _, v := range spec.VRFs {
		want[v.Name] = v
		link, err := netlink.LinkByName(v.Name)
		if err == nil {
			if vrf, ok := link.(*netlink.Vrf); !ok {
				errs = append(errs, fmt.Errorf("vrf %s: a device of another type has this name", v.Name))
				continue
			} else if vrf.Table != v.Table {
				// The table of a VRF cannot be changed in place.
				if err := netlink.LinkDel(link); err != nil {
					errs = append(errs, fmt.Errorf("vrf %s: %w", v.Name, err))
					continue
				}
				link = nil
			}
		} else {
			link = nil
		}
		if link == nil {
			vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: v.Name}, Table: v.Table}
			if err := netlink.LinkAdd(vrf); err != nil {
				errs = append(errs, fmt.Errorf("vrf %s: %w", v.Name, err))
				continue
			}
			if link, err = netlink.LinkByName(v.Name); err != nil {
				errs = append(errs, err)
				continue
			}
			_ = netlink.LinkSetAlias(link, vrfAlias)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			errs = append(errs, fmt.Errorf("vrf %s up: %w", v.Name, err))
		}
		members := map[string]bool{}
		for _, m := range v.Members {
			members[m] = true
			dev, err := netlink.LinkByName(m)
			if err != nil {
				errs = append(errs, fmt.Errorf("vrf %s: member %s: %w", v.Name, m, err))
				continue
			}
			if dev.Attrs().MasterIndex != link.Attrs().Index {
				if err := netlink.LinkSetMaster(dev, link); err != nil {
					errs = append(errs, fmt.Errorf("vrf %s: member %s: %w", v.Name, m, err))
				}
			}
		}
		links, _ := netlink.LinkList()
		for _, dev := range links {
			if dev.Attrs().MasterIndex == link.Attrs().Index && !members[dev.Attrs().Name] {
				if err := netlink.LinkSetNoMaster(dev); err != nil {
					errs = append(errs, fmt.Errorf("vrf %s: release %s: %w", v.Name, dev.Attrs().Name, err))
				}
			}
		}
	}
	links, err := netlink.LinkList()
	if err != nil {
		errs = append(errs, err)
	}
	for _, link := range links {
		if _, ok := link.(*netlink.Vrf); ok && link.Attrs().Alias == vrfAlias {
			if _, keep := want[link.Attrs().Name]; !keep {
				if err := netlink.LinkDel(link); err != nil {
					errs = append(errs, fmt.Errorf("remove vrf %s: %w", link.Attrs().Name, err))
				}
			}
		}
	}

	// Policy rules: the priority range is ours. Whatever is in it and not
	// wanted goes; whatever is wanted and missing is added, for both
	// address families.
	type key struct {
		prio, table int
		mark        uint32
	}
	wanted := map[key]bool{}
	for _, r := range spec.Rules {
		wanted[key{r.Priority, int(r.Table), r.Mark}] = true
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		have := map[key]bool{}
		rules, err := netlink.RuleList(family)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, r := range rules {
			if r.Priority < spec.RulePriorityLow || r.Priority > spec.RulePriorityHigh {
				continue
			}
			k := key{r.Priority, r.Table, r.Mark}
			if wanted[k] {
				have[k] = true
				continue
			}
			del := r
			del.Family = family
			if err := netlink.RuleDel(&del); err != nil {
				errs = append(errs, fmt.Errorf("remove rule %d: %w", r.Priority, err))
			}
		}
		for k := range wanted {
			if have[k] {
				continue
			}
			rule := netlink.NewRule()
			rule.Family, rule.Priority, rule.Table, rule.Mark = family, k.prio, k.table, k.mark
			if err := netlink.RuleAdd(rule); err != nil {
				errs = append(errs, fmt.Errorf("add rule %d: %w", k.prio, err))
			}
		}
	}
	return errors.Join(errs...)
}
