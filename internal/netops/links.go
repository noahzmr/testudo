package netops

import (
	"fmt"
	"regexp"
)

// Bonds, bridges and VLAN devices the model describes. The privileged side
// makes the kernel's devices of these kinds that Testudo created (alias
// "testudo") match a LinksSpec: it creates what is missing, recreates what
// differs in a way the kernel cannot change in place, enslaves and releases
// members, and removes its own devices that are no longer wanted. Devices
// it did not create are never changed or removed.

// OpSyncLinks makes the kernel's links match a LinksSpec (Op.Links).
const OpSyncLinks OpKind = "links_sync"

// LinkSpec is one bond, bridge or VLAN device.
type LinkSpec struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // bond, bridge, vlan

	// vlan
	Parent   string `json:"parent,omitempty"`
	VID      int    `json:"vid,omitempty"`
	Protocol string `json:"protocol,omitempty"` // 802.1q (default), 802.1ad

	// bond
	Mode       string `json:"mode,omitempty"` // 802.3ad (default), active-backup, ...
	LACPRate   string `json:"lacp_rate,omitempty"`
	MIIMon     int    `json:"miimon,omitempty"`
	HashPolicy string `json:"hash_policy,omitempty"`
	Primary    string `json:"primary,omitempty"`

	// bond members, bridge ports
	Members []string `json:"members,omitempty"`

	// bridge
	STP           bool `json:"stp,omitempty"`
	VLANFiltering bool `json:"vlan_filtering,omitempty"`
}

// LinksSpec is every device of these kinds Testudo should have on a node.
type LinksSpec struct {
	Links []LinkSpec `json:"links"`
}

var linkNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,14}$`)

// Validate checks a spec before it reaches the kernel.
func (s LinksSpec) Validate() error {
	names := map[string]bool{}
	master := map[string]string{}
	for _, l := range s.Links {
		if !linkNameRe.MatchString(l.Name) {
			return fmt.Errorf("link %q: bad device name", l.Name)
		}
		if names[l.Name] {
			return fmt.Errorf("link %s twice", l.Name)
		}
		names[l.Name] = true
		switch l.Kind {
		case "vlan":
			if !linkNameRe.MatchString(l.Parent) || l.VID < 1 || l.VID > 4094 {
				return fmt.Errorf("vlan %s: needs a parent and an id from 1 to 4094", l.Name)
			}
			if l.Protocol != "" && l.Protocol != "802.1q" && l.Protocol != "802.1ad" {
				return fmt.Errorf("vlan %s: protocol %q", l.Name, l.Protocol)
			}
		case "bond", "bridge":
		default:
			return fmt.Errorf("link %s: unknown kind %q", l.Name, l.Kind)
		}
		for _, m := range l.Members {
			if !linkNameRe.MatchString(m) || m == l.Name {
				return fmt.Errorf("%s %s: bad member %q", l.Kind, l.Name, m)
			}
			if other, ok := master[m]; ok {
				return fmt.Errorf("%s is a member of both %s and %s", m, other, l.Name)
			}
			master[m] = l.Name
		}
	}
	return nil
}

// SyncLinks makes the kernel's bonds, bridges and VLAN devices match spec.
func (w *Writer) SyncLinks(spec LinksSpec) error {
	if !w.AllowWrites {
		return fmt.Errorf("links sync: %w", ErrWritesDisabled)
	}
	if err := spec.Validate(); err != nil {
		return err
	}
	return w.mutate(Op{Kind: OpSyncLinks, Links: &spec})
}
