// Package fwstage applies the nftables ruleset that internal/fwrender
// produces. It is the apply stage for the packet filter and, at the same
// time, the firewall manager's backend: the manager keeps owning the
// defaults and the rules of WireGuard peers, access grants and direct
// edits, but instead of programming the kernel itself it hands its tables to
// this stage, which loads them together with the model's rules as one
// ruleset in one transaction.
package fwstage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/noahzmr/testudo/internal/confstore"
	"github.com/noahzmr/testudo/internal/firewall"
	"github.com/noahzmr/testudo/internal/fwrender"
	"github.com/noahzmr/testudo/internal/netops"
)

// Runner loads and inspects rulesets. *netops.Writer implements it.
type Runner interface {
	WritesAllowed() bool
	NftCheck(ruleset string) error
	NftApply(ruleset string) error
	NftListTable(family, table string) ([]byte, error)
}

// Manager is the part of the firewall manager the stage needs.
type Manager interface {
	ReplaceOwned(owner string, set firewall.OwnedSet, dryRun bool) error
	PreviewOwned(owner string, set firewall.OwnedSet) (netops.FilterTableSpec, netops.NATSpec, error)
	Specs() (netops.FilterTableSpec, netops.NATSpec)
	Reconcile() firewall.Drift
}

// Stage implements confapply.Stage and firewall.Backend.
type Stage struct {
	Runner Runner
	// Locate finds this node in the model; nil means only global objects.
	Locate func(*confstore.State) (siteID, nodeID string)
	// Elements returns the current content of run-time aliases by alias id.
	Elements func() map[string][]string

	mu      sync.Mutex
	manager Manager
	frags   fwrender.Fragments
	filter  netops.FilterTableSpec
	nat     netops.NATSpec
	applied string // the ruleset the kernel is believed to hold
}

// SetManager connects the stage to the manager that uses it as its backend
// and takes over the manager's current tables.
func (s *Stage) SetManager(m Manager) {
	f, n := m.Specs()
	s.mu.Lock()
	s.manager, s.filter, s.nat = m, f, n
	s.mu.Unlock()
}

func (s *Stage) Name() string { return "packet-filter" }

type artifact struct {
	Fragments fwrender.Fragments `json:"fragments"`
	// Defaults carries the model's firewall policy to the manager, which
	// owns default deny and the baseline. Nil when the model has none.
	Defaults *firewall.OwnedSet `json:"defaults,omitempty"`
}

func ports(in []string) ([]uint16, error) {
	var out []uint16
	for _, p := range in {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("always-open port %q: list single ports", p)
		}
		out = append(out, uint16(n))
	}
	return out, nil
}

// Render builds the model's fragments. The result does not depend on the
// running side, so the same state always renders to the same artifact.
func (s *Stage) Render(st *confstore.State) ([]byte, error) {
	var opt fwrender.Options
	if s.Locate != nil {
		opt.SiteID, opt.NodeID = s.Locate(st)
	}
	if s.Elements != nil {
		opt.Elements = s.Elements()
	}
	frags, err := fwrender.Build(st, opt)
	if err != nil {
		return nil, err
	}
	a := artifact{Fragments: frags}
	if p := fwrender.Policy(st, opt); p != nil {
		tcp, err := ports(p.AllowTCPPorts)
		if err != nil {
			return nil, fmt.Errorf("firewall_policy %q: %w", p.Name, err)
		}
		udp, err := ports(p.AllowUDPPorts)
		if err != nil {
			return nil, fmt.Errorf("firewall_policy %q: %w", p.Name, err)
		}
		enforce := p.DefaultDeny
		a.Defaults = &firewall.OwnedSet{Enforce: &enforce, Baseline: &netops.FilterBaseline{
			AllowEstablished: p.AllowEstablished, DropInvalid: p.DropInvalid, AllowLoopback: p.AllowLoopback,
			AllowICMP: p.AllowICMP, AllowTCPPorts: tcp, AllowUDPPorts: udp, LogDrops: p.LogDrops, LogPrefix: p.LogPrefix}}
	}
	return json.MarshalIndent(a, "", " ")
}

func decode(raw []byte) (artifact, firewall.OwnedSet, error) {
	var a artifact
	if err := json.Unmarshal(raw, &a); err != nil {
		return a, firewall.OwnedSet{}, err
	}
	var set firewall.OwnedSet
	if a.Defaults != nil {
		set = *a.Defaults
	}
	return a, set, nil
}

func assemble(f fwrender.Fragments, filter netops.FilterTableSpec, nat netops.NATSpec) string {
	return fwrender.Assemble(f, &fwrender.Running{Filter: filter, NAT: nat, DropLegacyTables: true})
}

// Check assembles the ruleset the change would produce and has nft validate
// it. Nothing is loaded.
func (s *Stage) Check(_ context.Context, raw []byte) error {
	a, set, err := decode(raw)
	if err != nil {
		return err
	}
	filter, nat, err := s.manager.PreviewOwned(firewall.OwnerModel, set)
	if err != nil {
		return err
	}
	return s.Runner.NftCheck(assemble(a.Fragments, filter, nat))
}

// Apply makes the artifact the model's part of the running ruleset.
func (s *Stage) Apply(_ context.Context, raw []byte) error {
	a, set, err := decode(raw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	prev := s.frags
	s.frags = a.Fragments
	s.mu.Unlock()
	// The manager reloads through ApplyFilterTable/ApplyNATTable when the
	// defaults changed; the explicit load covers the case where they did not.
	err = s.manager.ReplaceOwned(firewall.OwnerModel, set, false)
	if err == nil {
		s.mu.Lock()
		err = s.loadLocked()
		s.mu.Unlock()
	}
	if err != nil {
		s.mu.Lock()
		s.frags = prev
		s.mu.Unlock()
	}
	return err
}

// Refresh renders the model again and loads the result if it differs. It is
// for content that changes without a model change: the elements of run-time
// aliases. Nothing is committed and there is no confirmation window, because
// the rules are the same ones the operator already confirmed.
func (s *Stage) Refresh(st *confstore.State) error {
	raw, err := s.Render(st)
	if err != nil {
		return err
	}
	a, _, err := decode(raw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.frags
	s.frags = a.Fragments
	if err := s.loadLocked(); err != nil {
		s.frags = prev
		return err
	}
	return nil
}

// Healthy reports whether the kernel holds the ruleset that was loaded.
func (s *Stage) Healthy(context.Context) error {
	if d := s.manager.Reconcile(); d.Error != "" {
		return errors.New(d.Error)
	}
	st, err := s.read()
	if err != nil {
		return err
	}
	if !st.current {
		return errors.New("the kernel does not hold the ruleset that was just loaded")
	}
	return nil
}

// loadLocked loads the assembled ruleset unless the kernel already has it.
func (s *Stage) loadLocked() error {
	text := assemble(s.frags, s.filter, s.nat)
	if text == s.applied {
		return nil
	}
	if err := s.Runner.NftApply(text); err != nil {
		return err
	}
	s.applied = text
	return nil
}

// ---- firewall.Backend ------------------------------------------------------

func (s *Stage) WritesAllowed() bool { return s.Runner.WritesAllowed() }

func (s *Stage) ApplyFilterTable(spec netops.FilterTableSpec) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.filter
	s.filter = spec
	if err := s.loadLocked(); err != nil {
		s.filter = prev
		return err
	}
	return nil
}

func (s *Stage) ApplyNATTable(spec netops.NATSpec) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.nat
	s.nat = spec
	if err := s.loadLocked(); err != nil {
		s.nat = prev
		return err
	}
	return nil
}

// Counter is the traffic one object has matched.
type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type kernelRule struct {
	chain   string
	handle  uint64
	comment string
	Counter
	hasCounter bool
}

type kernelState struct {
	exists   bool
	current  bool // the generation marker matches what was loaded
	policies map[string]string
	rules    []kernelRule
}

var genRe = regexp.MustCompile(`^gen_[0-9a-f]{16}$`)

// read lists the table and decodes what the manager and the model need.
func (s *Stage) read() (kernelState, error) {
	st := kernelState{policies: map[string]string{}}
	raw, err := s.Runner.NftListTable("inet", fwrender.Table)
	if errors.Is(err, netops.ErrNftTableMissing) {
		s.forget()
		return st, nil
	}
	if err != nil {
		return st, err
	}
	var doc struct {
		Nftables []struct {
			Chain *struct {
				Name   string `json:"name"`
				Policy string `json:"policy"`
			} `json:"chain"`
			Set *struct {
				Name string `json:"name"`
			} `json:"set"`
			Rule *struct {
				Chain   string            `json:"chain"`
				Handle  uint64            `json:"handle"`
				Comment string            `json:"comment"`
				Expr    []json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return st, fmt.Errorf("decode nft listing: %w", err)
	}
	st.exists = true
	s.mu.Lock()
	want := fwrender.Generation(s.frags, &fwrender.Running{Filter: s.filter, NAT: s.nat, DropLegacyTables: true})
	s.mu.Unlock()
	for _, o := range doc.Nftables {
		switch {
		case o.Chain != nil && o.Chain.Policy != "":
			st.policies[o.Chain.Name] = o.Chain.Policy
		case o.Set != nil && genRe.MatchString(o.Set.Name):
			st.current = o.Set.Name == want
		case o.Rule != nil:
			r := kernelRule{chain: o.Rule.Chain, handle: o.Rule.Handle, comment: o.Rule.Comment}
			for _, e := range o.Rule.Expr {
				var c struct {
					Counter *Counter `json:"counter"`
				}
				if json.Unmarshal(e, &c) == nil && c.Counter != nil {
					r.Counter, r.hasCounter = *c.Counter, true
				}
			}
			st.rules = append(st.rules, r)
		}
	}
	if !st.current {
		s.forget()
	}
	return st, nil
}

// forget makes the next load unconditional: the kernel no longer holds what
// was loaded last.
func (s *Stage) forget() {
	s.mu.Lock()
	s.applied = ""
	s.mu.Unlock()
}

// FilterTableState reports the manager's rules as the kernel holds them. A
// table that is not the one loaded last is reported as empty, which makes
// the manager's drift check reload it.
func (s *Stage) FilterTableState() (netops.FilterTableState, error) {
	st, err := s.read()
	out := netops.FilterTableState{Exists: st.exists, Policies: map[string]string{}}
	if err != nil || !st.exists || !st.current {
		return out, err
	}
	for chain, pol := range st.policies {
		if chain == "input" || chain == "forward" || chain == "output" {
			out.Policies[chain] = pol
		}
	}
	for _, r := range st.rules {
		if id, ok := strings.CutPrefix(r.comment, fwrender.RuleTag); ok {
			out.Rules = append(out.Rules, netops.ManagedRule{Chain: r.chain, Handle: r.handle, ID: id,
				Packets: r.Packets, Bytes: r.Bytes, HasCounter: r.hasCounter})
		}
	}
	sort.SliceStable(out.Rules, func(i, j int) bool { return out.Rules[i].Chain < out.Rules[j].Chain })
	return out, nil
}

func (s *Stage) NATTableState() (netops.NATTableState, error) {
	st, err := s.read()
	out := netops.NATTableState{Exists: st.exists && st.current}
	if err != nil || !out.Exists {
		return out, err
	}
	s.mu.Lock()
	nat := s.nat
	s.mu.Unlock()
	fwd := map[string]netops.PortForward{}
	for _, f := range nat.Forwards {
		fwd[f.ID()] = f
	}
	masq := map[string]netops.Masquerade{}
	for _, m := range nat.Masquerades {
		masq[m.ID()] = m
	}
	for _, r := range st.rules {
		if id, ok := strings.CutPrefix(r.comment, fwrender.ForwardTag); ok {
			out.Forwards = append(out.Forwards, netops.ManagedForward{PortForward: fwd[id], ID: id, Handle: r.handle,
				Packets: r.Packets, Bytes: r.Bytes, HasCounter: r.hasCounter})
		}
		if id, ok := strings.CutPrefix(r.comment, fwrender.MasqueradeTag); ok {
			out.Masquerades = append(out.Masquerades, netops.ManagedMasquerade{Masquerade: masq[id], ID: id, Handle: r.handle,
				Packets: r.Packets, Bytes: r.Bytes, HasCounter: r.hasCounter})
		}
	}
	return out, nil
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Counters returns what each model object has matched, by object id. A model
// rule can be several kernel rules; their counters are added up.
func (s *Stage) Counters() (map[string]Counter, error) {
	st, err := s.read()
	if err != nil {
		return nil, err
	}
	out := map[string]Counter{}
	for _, r := range st.rules {
		if uuidRe.MatchString(r.comment) {
			c := out[r.comment]
			c.Packets += r.Packets
			c.Bytes += r.Bytes
			out[r.comment] = c
		}
	}
	return out, nil
}
