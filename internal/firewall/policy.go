// Package firewall is the policy layer above netops: it owns the desired state
// of everything Testudo puts into nftables (filter rules, port forwards,
// masquerades, chain policies), persists it as a file the operator can read
// and back up, applies it atomically, and reconciles the kernel back to it when
// something else (a reboot, a stray `nft flush ruleset`) made them diverge.
//
// The kernel is never the only copy. netops knows how to rebuild a table from
// a spec; this package knows what the table should contain.
package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/noahzmr/testudo/internal/netops"
)

// PolicyVersion is the on-disk schema version of the policy file.
const PolicyVersion = 1

// Policy is the complete desired state. Rules are ordered; per chain they are
// installed after the baseline and before the trailing log rule. Forwards and
// masquerades are ordered too (NAT rules are first-match).
type Policy struct {
	Version     int                   `json:"version"`
	UpdatedAt   time.Time             `json:"updated_at"`
	Enforce     bool                  `json:"enforce"`
	Baseline    netops.FilterBaseline `json:"baseline"`
	Rules       []netops.FilterRule   `json:"rules"`
	Forwards    []netops.PortForward  `json:"forwards"`
	Masquerades []netops.Masquerade   `json:"masquerades"`
}

// DefaultPolicy is what a host starts with: default-accept chains, the
// textbook stateful baseline, no rules.
func DefaultPolicy() Policy {
	return Policy{Version: PolicyVersion, Baseline: netops.DefaultBaseline()}
}

// Clone returns a deep copy so callers can build a candidate without touching
// the committed policy.
func (p Policy) Clone() Policy {
	c := p
	c.Baseline.AllowTCPPorts = append([]uint16(nil), p.Baseline.AllowTCPPorts...)
	c.Baseline.AllowUDPPorts = append([]uint16(nil), p.Baseline.AllowUDPPorts...)
	c.Rules = append([]netops.FilterRule(nil), p.Rules...)
	c.Forwards = append([]netops.PortForward(nil), p.Forwards...)
	c.Masquerades = append([]netops.Masquerade(nil), p.Masquerades...)
	return c
}

// Normalize canonicalises every entry (see netops.FilterRule.Normalize) so IDs
// are stable and duplicates compare equal.
func (p Policy) Normalize() Policy {
	n := p.Clone()
	n.Version = PolicyVersion
	for i := range n.Rules {
		n.Rules[i] = n.Rules[i].Normalize()
	}
	for i := range n.Forwards {
		n.Forwards[i] = n.Forwards[i].Normalize()
	}
	for i := range n.Masquerades {
		n.Masquerades[i] = n.Masquerades[i].Normalize()
	}
	return n
}

// Validate checks every entry and rejects duplicates (same ID twice would be
// two identical kernel rules that the drift check could not tell apart).
func (p Policy) Validate() error {
	if p.Version != 0 && p.Version != PolicyVersion {
		return fmt.Errorf("unsupported policy version %d (want %d)", p.Version, PolicyVersion)
	}
	seen := map[string]int{}
	for i, r := range p.Rules {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("rule %d (%s): %w", i, r, err)
		}
		if r.Normalize().Owner == netops.OwnerBaseline {
			return fmt.Errorf("rule %d: owner %q is reserved", i, netops.OwnerBaseline)
		}
		if j, dup := seen[r.ID()]; dup {
			return fmt.Errorf("rule %d duplicates rule %d (%s)", i, j, r)
		}
		seen[r.ID()] = i
	}
	seen = map[string]int{}
	for i, f := range p.Forwards {
		if err := f.Validate(); err != nil {
			return fmt.Errorf("forward %d (%s): %w", i, f, err)
		}
		if j, dup := seen[f.ID()]; dup {
			return fmt.Errorf("forward %d duplicates forward %d (%s)", i, j, f)
		}
		seen[f.ID()] = i
	}
	seen = map[string]int{}
	for i, m := range p.Masquerades {
		if err := m.Validate(); err != nil {
			return fmt.Errorf("masquerade %d (%s): %w", i, m, err)
		}
		if j, dup := seen[m.ID()]; dup {
			return fmt.Errorf("masquerade %d duplicates masquerade %d (%s)", i, j, m)
		}
		seen[m.ID()] = i
	}
	for _, port := range append(append([]uint16{}, p.Baseline.AllowTCPPorts...), p.Baseline.AllowUDPPorts...) {
		if port == 0 {
			return errors.New("baseline: port 0 is not valid")
		}
	}
	if len(p.Baseline.LogPrefix) > 120 {
		return errors.New("baseline: log prefix is at most 120 characters")
	}
	return nil
}

// Inert reports whether the policy has nothing to enforce: default-accept
// chains, no rules, no NAT. An inert policy needs no kernel table at all - a
// missing table is then the correct state, not drift - so a fresh install
// leaves nftables untouched until the first rule or enforce.
func (p Policy) Inert() bool {
	return !p.Enforce && len(p.Rules) == 0 && len(p.Forwards) == 0 && len(p.Masquerades) == 0
}

// NATSpec is the NAT half of the policy as netops applies it.
func (p Policy) NATSpec() netops.NATSpec {
	return netops.NATSpec{
		Forwards:    append([]netops.PortForward(nil), p.Forwards...),
		Masquerades: append([]netops.Masquerade(nil), p.Masquerades...),
	}
}

// filterSpec is the filter half of the policy with the manager's protected
// ports merged into the baseline. Protected ports are not persisted: they
// describe this process (its Web UI listen port), not the operator's intent.
func (p Policy) filterSpec(protectedTCP []uint16) netops.FilterTableSpec {
	b := p.Baseline
	b.AllowTCPPorts = append(append([]uint16(nil), b.AllowTCPPorts...), protectedTCP...)
	return netops.FilterTableSpec{
		Enforce:  p.Enforce,
		Baseline: b,
		Rules:    append([]netops.FilterRule(nil), p.Rules...),
	}
}

// ---- persistence ------------------------------------------------------

// Store reads and writes the policy file. The file is 0600 and written via
// tmp + rename so a crash can never leave a half-written policy behind.
type Store struct {
	Path string
}

// Load returns the policy, whether the file existed, and any error.
func (s Store) Load() (Policy, bool, error) {
	data, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return Policy{}, false, nil
		}
		return Policy{}, false, fmt.Errorf("read policy: %w", err)
	}
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return Policy{}, true, fmt.Errorf("parse policy %s: %w", s.Path, err)
	}
	if p.Version == 0 {
		p.Version = PolicyVersion
	}
	return p, true, nil
}

// Save writes the policy atomically.
func (s Store) Save(p Policy) error {
	if s.Path == "" {
		return errors.New("policy path not set")
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return fmt.Errorf("create policy dir: %w", err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write policy: %w", err)
	}
	if err := os.Rename(tmp, s.Path); err != nil {
		return fmt.Errorf("rename policy: %w", err)
	}
	return nil
}
