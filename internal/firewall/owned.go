package firewall

import (
	"reflect"

	"github.com/noahzmr/testudo/internal/netops"
)

// OwnerModel tags the rules that come from the configuration model. They are
// replaced as a block whenever the model changes; rules of every other owner
// (the operator's direct edits, WireGuard peers, access grants) are left
// alone and keep their position ahead of the model's rules.
const OwnerModel = "model"

// OwnedSet is everything one owner contributes to the policy.
type OwnedSet struct {
	Rules       []netops.FilterRule
	Forwards    []netops.PortForward
	Masquerades []netops.Masquerade
	// Enforce and Baseline are set only when the owner also decides the
	// policy's defaults; nil leaves them as they are.
	Enforce  *bool
	Baseline *netops.FilterBaseline
}

// ReplaceOwned swaps everything tagged with owner for set, as one atomic
// apply. With dryRun it only validates the resulting policy and changes
// nothing. An unchanged policy is not re-applied.
func (m *Manager) ReplaceOwned(owner string, set OwnedSet, dryRun bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revertTo != nil {
		return ErrPendingConfirm
	}
	c := m.pol.Clone()
	rules := c.Rules[:0:0]
	for _, r := range c.Rules {
		if r.Owner != owner {
			rules = append(rules, r)
		}
	}
	fwds := c.Forwards[:0:0]
	for _, f := range c.Forwards {
		if f.Owner != owner {
			fwds = append(fwds, f)
		}
	}
	masqs := c.Masquerades[:0:0]
	for _, x := range c.Masquerades {
		if x.Owner != owner {
			masqs = append(masqs, x)
		}
	}
	for _, r := range set.Rules {
		r.Owner = owner
		rules = append(rules, r)
	}
	for _, f := range set.Forwards {
		f.Owner = owner
		fwds = append(fwds, f)
	}
	for _, x := range set.Masquerades {
		x.Owner = owner
		masqs = append(masqs, x)
	}
	c.Rules, c.Forwards, c.Masquerades = rules, fwds, masqs
	if set.Enforce != nil {
		c.Enforce = *set.Enforce
	}
	if set.Baseline != nil {
		c.Baseline = *set.Baseline
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if dryRun {
		return nil
	}
	filterChanged := c.Enforce != m.pol.Enforce || !reflect.DeepEqual(c.Baseline, m.pol.Baseline) ||
		!reflect.DeepEqual(c.Rules, m.pol.Rules)
	natChanged := !reflect.DeepEqual(c.Forwards, m.pol.Forwards) || !reflect.DeepEqual(c.Masquerades, m.pol.Masquerades)
	if !filterChanged && !natChanged {
		return nil
	}
	return m.commitLocked(c, filterChanged, natChanged)
}

// CountOwned reports how many rules, forwards and masquerades an owner has.
func (m *Manager) CountOwned(owner string) (rules, forwards, masquerades int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.pol.Rules {
		if r.Owner == owner {
			rules++
		}
	}
	for _, f := range m.pol.Forwards {
		if f.Owner == owner {
			forwards++
		}
	}
	for _, x := range m.pol.Masquerades {
		if x.Owner == owner {
			masquerades++
		}
	}
	return
}
