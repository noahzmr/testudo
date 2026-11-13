package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/privsep"
)

// Backend is the privileged surface the manager drives. *netops.Writer
// satisfies it (directly or via the privsep helper); tests substitute a fake.
type Backend interface {
	WritesAllowed() bool
	ApplyFilterTable(netops.FilterTableSpec) error
	ApplyNATTable(netops.NATSpec) error
	FilterTableState() (netops.FilterTableState, error)
	NATTableState() (netops.NATTableState, error)
}

// Options configures a Manager.
type Options struct {
	// Path of the policy file, e.g. ~/.testudo/firewall.json.
	Path string
	// ProtectedTCPPorts are merged into the baseline on every apply so that
	// enabling Enforce can never cut the operator off: the Web UI listen port
	// and SSH. They are not persisted in the policy.
	ProtectedTCPPorts []uint16
	// Now is the clock (tests inject one).
	Now func() time.Time
}

// Errors callers can match on.
var (
	ErrWritesDisabled = netops.ErrWritesDisabled
	ErrPendingConfirm = errors.New("firewall: an enforce change is awaiting confirmation - confirm it or wait for the auto-revert")
	ErrNotFound       = errors.New("firewall: no matching entry")
	ErrTooLarge       = errors.New("firewall: policy too large for the privileged-helper transport")
)

// Manager owns the policy. Every mutation is candidate → apply → persist: a
// kernel error leaves both the committed policy and the file untouched.
type Manager struct {
	mu    sync.Mutex
	opts  Options
	store Store
	be    Backend
	pol   Policy

	lastApply time.Time
	lastErr   error
	drift     Drift
	imported  int // entries imported from a pre-policy kernel table on first open

	// commit-confirm state for SetEnforce(true, confirmWithin)
	confirmTimer *time.Timer
	pendingUntil time.Time
	revertTo     *Policy

	onChange func(Status)
}

// Open loads the policy (or starts from DefaultPolicy) and, when no policy
// file exists yet, imports whatever legacy Testudo rules are still in the
// kernel so an upgrade never silently drops them. It does not apply anything;
// call Reconcile / Run for that.
func Open(opts Options, be Backend) (*Manager, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	m := &Manager{opts: opts, store: Store{Path: opts.Path}, be: be}
	pol, existed, err := m.store.Load()
	if err != nil {
		return nil, err
	}
	if !existed {
		pol = DefaultPolicy()
		if be != nil {
			m.imported = importLegacy(&pol, be)
		}
		pol.UpdatedAt = opts.Now()
		if opts.Path != "" {
			if err := m.store.Save(pol); err != nil {
				return nil, err
			}
		}
	}
	pol = pol.Normalize()
	if err := pol.Validate(); err != nil {
		return nil, fmt.Errorf("policy file %s: %w", opts.Path, err)
	}
	m.pol = pol
	return m, nil
}

// importLegacy folds rules that predate the policy file (identifiable because
// they carry a decodable legacy key rather than a managed ID) into pol.
// Returns how many entries were imported.
func importLegacy(pol *Policy, be Backend) int {
	n := 0
	if fs, err := be.FilterTableState(); err == nil {
		for _, r := range fs.Rules {
			if r.Legacy == nil {
				continue
			}
			lr := r.Legacy.Normalize()
			if lr.Validate() != nil || hasRule(pol.Rules, lr.ID()) {
				continue
			}
			pol.Rules = append(pol.Rules, lr)
			n++
		}
	}
	if ns, err := be.NATTableState(); err == nil {
		for _, f := range ns.Forwards {
			if !f.Legacy {
				continue
			}
			pf := f.PortForward.Normalize()
			if pf.Validate() != nil || hasForward(pol.Forwards, pf.ID()) {
				continue
			}
			pol.Forwards = append(pol.Forwards, pf)
			n++
		}
		for _, mq := range ns.Masquerades {
			if !mq.Legacy {
				continue
			}
			ms := mq.Masquerade.Normalize()
			if ms.Validate() != nil || hasMasq(pol.Masquerades, ms.ID()) {
				continue
			}
			pol.Masquerades = append(pol.Masquerades, ms)
			n++
		}
	}
	return n
}

// SetOnChange registers a callback invoked (outside the lock) after every
// commit, reconcile and confirm-revert. The engine uses it to publish events.
func (m *Manager) SetOnChange(fn func(Status)) {
	m.mu.Lock()
	m.onChange = fn
	m.mu.Unlock()
}

// Policy returns a copy of the committed policy.
func (m *Manager) Policy() Policy {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pol.Clone()
}

// Imported reports how many legacy kernel entries Open folded into the policy.
func (m *Manager) Imported() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.imported
}

// FilterSpec is the filter table exactly as the manager applies it (protected
// ports merged). Exposed so UIs can render baseline rules too.
func (m *Manager) FilterSpec() netops.FilterTableSpec {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pol.filterSpec(m.opts.ProtectedTCPPorts)
}

// Status is the one-glance health of the firewall policy.
//
// Three distinct kernel conditions are reported: in sync (InSync), drifted
// (InSync false with DriftDetail), and *unreadable* (DriftError set - the
// tables could not be read at all, typically for lack of CAP_NET_ADMIN).
// Unreadable is a posture, not a drift: UIs must not call it a drift.
type Status struct {
	Enforce        bool      `json:"enforce"`
	WritesAllowed  bool      `json:"writes_allowed"`
	RuleCount      int       `json:"rule_count"`
	ForwardCount   int       `json:"forward_count"`
	MasqCount      int       `json:"masquerade_count"`
	InSync         bool      `json:"in_sync"`
	DriftDetail    []string  `json:"drift_detail,omitempty"`
	DriftError     string    `json:"drift_error,omitempty"` // kernel state unreadable: why
	Inert          bool      `json:"inert"`                 // nothing to enforce (no rules, default-accept, no NAT)
	TableExists    bool      `json:"table_exists"`          // testudo_filter present at the last check
	LastChecked    time.Time `json:"last_checked"`
	LastApply      time.Time `json:"last_apply"`
	LastError      string    `json:"last_error,omitempty"`
	PendingConfirm bool      `json:"pending_confirm"`
	PendingUntil   time.Time `json:"pending_until,omitempty"`
	Imported       int       `json:"imported,omitempty"`
	Path           string    `json:"path"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Status returns the current status (no kernel access; uses the last
// reconcile result).
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.statusLocked()
}

func (m *Manager) statusLocked() Status {
	st := Status{
		Enforce:      m.pol.Enforce,
		RuleCount:    len(m.pol.Rules),
		ForwardCount: len(m.pol.Forwards),
		MasqCount:    len(m.pol.Masquerades),
		InSync:       m.drift.InSync,
		DriftDetail:  append([]string(nil), m.drift.Details...),
		DriftError:   m.drift.Error,
		Inert:        m.pol.Inert(),
		TableExists:  m.drift.TableExists,
		LastChecked:  m.drift.Checked,
		LastApply:    m.lastApply,
		Imported:     m.imported,
		Path:         m.opts.Path,
		UpdatedAt:    m.pol.UpdatedAt,
	}
	if m.be != nil {
		st.WritesAllowed = m.be.WritesAllowed()
	}
	if m.lastErr != nil {
		st.LastError = m.lastErr.Error()
	}
	if m.revertTo != nil {
		st.PendingConfirm = true
		st.PendingUntil = m.pendingUntil
	}
	return st
}

// RuleStatus is a desired rule joined with its live kernel counters. Index is
// the position in Policy.Rules (-1 for baseline-rendered rules).
type RuleStatus struct {
	netops.FilterRule
	ID         string `json:"id"`
	Index      int    `json:"index"`
	Baseline   bool   `json:"baseline"`
	Live       bool   `json:"live"`
	Handle     uint64 `json:"handle,omitempty"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	HasCounter bool   `json:"has_counter"`
}

// Rules returns every rule the filter table should contain (baseline + user +
// trailing log rules) in install order, joined with live counters. A rule that
// is desired but not live is drift; it renders with Live=false.
func (m *Manager) Rules() ([]RuleStatus, error) {
	m.mu.Lock()
	spec := m.pol.filterSpec(m.opts.ProtectedTCPPorts)
	userIdx := map[string]int{}
	for i, r := range m.pol.Rules {
		userIdx[r.ID()] = i
	}
	be := m.be
	m.mu.Unlock()

	live := map[string]netops.ManagedRule{}
	var stateErr error
	if be != nil {
		st, err := be.FilterTableState()
		if err != nil {
			stateErr = err
		}
		for _, r := range st.Rules {
			if r.ID != "" {
				live[r.ID] = r
			}
		}
	}
	rendered := netops.RenderFilterRules(spec)
	out := make([]RuleStatus, 0, len(rendered))
	for _, r := range rendered {
		id := r.ID()
		rs := RuleStatus{FilterRule: r, ID: id, Index: -1, Baseline: r.Owner == netops.OwnerBaseline}
		if i, ok := userIdx[id]; ok {
			rs.Index = i
		}
		if lr, ok := live[id]; ok {
			rs.Live = true
			rs.Handle, rs.Packets, rs.Bytes, rs.HasCounter = lr.Handle, lr.Packets, lr.Bytes, lr.HasCounter
		}
		out = append(out, rs)
	}
	return out, stateErr
}

// ForwardStatus / MasqStatus are NAT entries joined with live counters.
type ForwardStatus struct {
	netops.PortForward
	ID         string `json:"id"`
	Index      int    `json:"index"`
	Live       bool   `json:"live"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	HasCounter bool   `json:"has_counter"`
}

type MasqStatus struct {
	netops.Masquerade
	ID         string `json:"id"`
	Index      int    `json:"index"`
	Live       bool   `json:"live"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	HasCounter bool   `json:"has_counter"`
}

// NAT returns the desired forwards and masquerades joined with live counters.
func (m *Manager) NAT() ([]ForwardStatus, []MasqStatus, error) {
	m.mu.Lock()
	pol := m.pol.Clone()
	be := m.be
	m.mu.Unlock()

	liveF := map[string]netops.ManagedForward{}
	liveM := map[string]netops.ManagedMasquerade{}
	var stateErr error
	if be != nil {
		st, err := be.NATTableState()
		if err != nil {
			stateErr = err
		}
		for _, f := range st.Forwards {
			if f.ID != "" {
				liveF[f.ID] = f
			}
		}
		for _, mq := range st.Masquerades {
			if mq.ID != "" {
				liveM[mq.ID] = mq
			}
		}
	}
	fw := make([]ForwardStatus, 0, len(pol.Forwards))
	for i, f := range pol.Forwards {
		fs := ForwardStatus{PortForward: f, ID: f.ID(), Index: i}
		if lf, ok := liveF[fs.ID]; ok {
			fs.Live, fs.Packets, fs.Bytes, fs.HasCounter = true, lf.Packets, lf.Bytes, lf.HasCounter
		}
		fw = append(fw, fs)
	}
	mq := make([]MasqStatus, 0, len(pol.Masquerades))
	for i, ms := range pol.Masquerades {
		s := MasqStatus{Masquerade: ms, ID: ms.ID(), Index: i}
		if lm, ok := liveM[s.ID]; ok {
			s.Live, s.Packets, s.Bytes, s.HasCounter = true, lm.Packets, lm.Bytes, lm.HasCounter
		}
		mq = append(mq, s)
	}
	return fw, mq, stateErr
}

// ---- mutations -------------------------------------------------------

// AddRule appends a rule. Adding a rule that already exists is a no-op.
func (m *Manager) AddRule(r netops.FilterRule) error {
	return m.InsertRule(-1, r)
}

// InsertRule inserts r at index (append when index < 0 or past the end).
func (m *Manager) InsertRule(index int, r netops.FilterRule) error {
	r = r.Normalize()
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Owner == netops.OwnerBaseline {
		return fmt.Errorf("owner %q is reserved for baseline rules", netops.OwnerBaseline)
	}
	return m.mutate(func(c *Policy) (bool, bool, error) {
		if hasRule(c.Rules, r.ID()) {
			return false, false, nil
		}
		if index < 0 || index >= len(c.Rules) {
			c.Rules = append(c.Rules, r)
		} else {
			c.Rules = append(c.Rules[:index], append([]netops.FilterRule{r}, c.Rules[index:]...)...)
		}
		return true, false, nil
	})
}

// DelRule removes the rule with the given ID.
func (m *Manager) DelRule(id string) error {
	return m.mutate(func(c *Policy) (bool, bool, error) {
		for i, r := range c.Rules {
			if r.ID() == id {
				c.Rules = append(c.Rules[:i], c.Rules[i+1:]...)
				return true, false, nil
			}
		}
		return false, false, ErrNotFound
	})
}

// DelRulesMatching removes every rule whose non-empty fields equal target's
// (empty target fields are wildcards). Returns how many were removed.
func (m *Manager) DelRulesMatching(target netops.FilterRule) (int, error) {
	target = target.Normalize()
	if target.Owner == netops.OwnerUser {
		target.Owner = "" // the default owner is not a deliberate filter
	}
	n := 0
	err := m.mutate(func(c *Policy) (bool, bool, error) {
		kept := c.Rules[:0]
		for _, r := range c.Rules {
			if matchesTarget(r, target) {
				n++
				continue
			}
			kept = append(kept, r)
		}
		c.Rules = kept
		return n > 0, false, nil
	})
	return n, err
}

// DelRulesByOwner removes every filter rule carrying owner (e.g. a WireGuard
// peer's preset rules). Returns how many were removed.
func (m *Manager) DelRulesByOwner(owner string) (int, error) {
	n := 0
	err := m.mutate(func(c *Policy) (bool, bool, error) {
		kept := c.Rules[:0]
		for _, r := range c.Rules {
			if r.Owner == owner {
				n++
				continue
			}
			kept = append(kept, r)
		}
		c.Rules = kept
		return n > 0, false, nil
	})
	return n, err
}

// Reorder sets the order of the user rules. ids must be a permutation of the
// current rule IDs.
func (m *Manager) Reorder(ids []string) error {
	return m.mutate(func(c *Policy) (bool, bool, error) {
		if len(ids) != len(c.Rules) {
			return false, false, fmt.Errorf("reorder: got %d ids for %d rules", len(ids), len(c.Rules))
		}
		byID := map[string]netops.FilterRule{}
		for _, r := range c.Rules {
			byID[r.ID()] = r
		}
		out := make([]netops.FilterRule, 0, len(ids))
		seen := map[string]bool{}
		for _, id := range ids {
			r, ok := byID[id]
			if !ok || seen[id] {
				return false, false, fmt.Errorf("reorder: unknown or repeated id %q", id)
			}
			seen[id] = true
			out = append(out, r)
		}
		c.Rules = out
		return true, false, nil
	})
}

// AddForward appends a port forward (no-op when it already exists).
func (m *Manager) AddForward(pf netops.PortForward) error {
	pf = pf.Normalize()
	if err := pf.Validate(); err != nil {
		return err
	}
	return m.mutate(func(c *Policy) (bool, bool, error) {
		if hasForward(c.Forwards, pf.ID()) {
			return false, false, nil
		}
		c.Forwards = append(c.Forwards, pf)
		return false, true, nil
	})
}

// DelForward removes the forward with the given ID.
func (m *Manager) DelForward(id string) error {
	return m.mutate(func(c *Policy) (bool, bool, error) {
		for i, f := range c.Forwards {
			if f.ID() == id {
				c.Forwards = append(c.Forwards[:i], c.Forwards[i+1:]...)
				return false, true, nil
			}
		}
		return false, false, ErrNotFound
	})
}

// DelForwardsMatching removes every forward for proto + wanPort. Returns how
// many were removed.
func (m *Manager) DelForwardsMatching(proto string, wanPort uint16) (int, error) {
	proto = strings.ToLower(strings.TrimSpace(proto))
	n := 0
	err := m.mutate(func(c *Policy) (bool, bool, error) {
		kept := c.Forwards[:0]
		for _, f := range c.Forwards {
			if f.Proto == proto && f.WANPort == wanPort {
				n++
				continue
			}
			kept = append(kept, f)
		}
		c.Forwards = kept
		return false, n > 0, nil
	})
	return n, err
}

// AddMasquerade appends a masquerade (no-op when it already exists).
func (m *Manager) AddMasquerade(ms netops.Masquerade) error {
	ms = ms.Normalize()
	if err := ms.Validate(); err != nil {
		return err
	}
	return m.mutate(func(c *Policy) (bool, bool, error) {
		if hasMasq(c.Masquerades, ms.ID()) {
			return false, false, nil
		}
		c.Masquerades = append(c.Masquerades, ms)
		return false, true, nil
	})
}

// DelMasquerade removes the masquerade with the given ID.
func (m *Manager) DelMasquerade(id string) error {
	return m.mutate(func(c *Policy) (bool, bool, error) {
		for i, ms := range c.Masquerades {
			if ms.ID() == id {
				c.Masquerades = append(c.Masquerades[:i], c.Masquerades[i+1:]...)
				return false, true, nil
			}
		}
		return false, false, ErrNotFound
	})
}

// DelMasqueradesMatching removes every masquerade for (outIface, srcCIDR).
func (m *Manager) DelMasqueradesMatching(outIface, srcCIDR string) (int, error) {
	want := netops.Masquerade{OutIface: outIface, SrcCIDR: srcCIDR}.Normalize()
	n := 0
	err := m.mutate(func(c *Policy) (bool, bool, error) {
		kept := c.Masquerades[:0]
		for _, ms := range c.Masquerades {
			if ms.OutIface == want.OutIface && ms.SrcCIDR == want.SrcCIDR {
				n++
				continue
			}
			kept = append(kept, ms)
		}
		c.Masquerades = kept
		return false, n > 0, nil
	})
	return n, err
}

// DelNATByOwner removes every forward and masquerade carrying owner.
func (m *Manager) DelNATByOwner(owner string) (int, error) {
	n := 0
	err := m.mutate(func(c *Policy) (bool, bool, error) {
		keptF := c.Forwards[:0]
		for _, f := range c.Forwards {
			if f.Owner == owner {
				n++
				continue
			}
			keptF = append(keptF, f)
		}
		c.Forwards = keptF
		keptM := c.Masquerades[:0]
		for _, ms := range c.Masquerades {
			if ms.Owner == owner {
				n++
				continue
			}
			keptM = append(keptM, ms)
		}
		c.Masquerades = keptM
		return false, n > 0, nil
	})
	return n, err
}

// SetBaseline replaces the baseline (filter table re-applied).
func (m *Manager) SetBaseline(b netops.FilterBaseline) error {
	return m.mutate(func(c *Policy) (bool, bool, error) {
		c.Baseline = b
		return true, false, nil
	})
}

// SetEnforce switches default-deny on or off. Turning it ON with confirmWithin
// > 0 is a commit-confirm transaction: the change is applied immediately but
// reverts automatically unless ConfirmEnforce is called in time - the
// standard guard against locking yourself out of a remote box. Turning it off
// is immediate and also cancels a pending confirmation.
func (m *Manager) SetEnforce(on bool, confirmWithin time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !on {
		m.cancelPendingLocked()
		if !m.pol.Enforce {
			return nil
		}
		c := m.pol.Clone()
		c.Enforce = false
		return m.commitLocked(c, true, false)
	}
	if m.revertTo != nil {
		return ErrPendingConfirm
	}
	if m.pol.Enforce {
		return nil
	}
	prev := m.pol.Clone()
	c := m.pol.Clone()
	c.Enforce = true
	if err := m.commitLocked(c, true, false); err != nil {
		return err
	}
	if confirmWithin > 0 {
		m.revertTo = &prev
		m.pendingUntil = m.opts.Now().Add(confirmWithin)
		m.confirmTimer = time.AfterFunc(confirmWithin, m.revertUnconfirmed)
	}
	return nil
}

// ConfirmEnforce keeps a pending enforce change. No-op when nothing is pending.
func (m *Manager) ConfirmEnforce() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revertTo == nil {
		return nil
	}
	m.cancelPendingLocked()
	log.Printf("firewall: enforce mode confirmed")
	return nil
}

func (m *Manager) cancelPendingLocked() {
	if m.confirmTimer != nil {
		m.confirmTimer.Stop()
		m.confirmTimer = nil
	}
	m.revertTo = nil
	m.pendingUntil = time.Time{}
}

// revertUnconfirmed runs when the confirm window elapsed without a confirm.
func (m *Manager) revertUnconfirmed() {
	m.mu.Lock()
	prev := m.revertTo
	m.revertTo = nil
	m.confirmTimer = nil
	m.pendingUntil = time.Time{}
	if prev == nil {
		m.mu.Unlock()
		return
	}
	err := m.commitLocked(*prev, true, false)
	st := m.statusLocked()
	fn := m.onChange
	m.mu.Unlock()
	if err != nil {
		log.Printf("firewall: enforce mode NOT confirmed in time; revert failed: %v", err)
	} else {
		log.Printf("firewall: enforce mode not confirmed in time - reverted to previous policy")
	}
	if fn != nil {
		fn(st)
	}
}

// mutate runs fn on a candidate copy; fn reports whether the filter and/or
// NAT table changed. Only the changed tables are re-applied (a rebuild resets
// that table's counters, so NAT edits leave filter hit counts intact).
func (m *Manager) mutate(fn func(c *Policy) (filterChanged, natChanged bool, err error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revertTo != nil {
		return ErrPendingConfirm
	}
	c := m.pol.Clone()
	fc, nc, err := fn(&c)
	if err != nil {
		return err
	}
	if !fc && !nc {
		return nil
	}
	return m.commitLocked(c, fc, nc)
}

// commitLocked validates, applies and persists the candidate. Caller holds mu.
func (m *Manager) commitLocked(c Policy, applyFilter, applyNAT bool) error {
	// Validate before normalising: Normalize stamps the current version, and an
	// import from a newer schema must be refused, not silently rewritten.
	if err := c.Validate(); err != nil {
		return err
	}
	c = c.Normalize()
	if m.be == nil {
		return errors.New("firewall: no backend")
	}
	if !m.be.WritesAllowed() {
		return ErrWritesDisabled
	}
	spec := c.filterSpec(m.opts.ProtectedTCPPorts)
	if err := checkFrameSize(netops.Op{Kind: netops.OpApplyFilterTable, FilterSpec: &spec}); err != nil {
		return err
	}
	nat := c.NATSpec()
	if err := checkFrameSize(netops.Op{Kind: netops.OpApplyNATTable, NATSpec: &nat}); err != nil {
		return err
	}
	if applyFilter {
		if err := m.be.ApplyFilterTable(spec); err != nil {
			m.lastErr = err
			return err
		}
	}
	if applyNAT {
		if err := m.be.ApplyNATTable(nat); err != nil {
			m.lastErr = err
			if applyFilter {
				// Roll the filter table back to the committed policy; best effort.
				_ = m.be.ApplyFilterTable(m.pol.filterSpec(m.opts.ProtectedTCPPorts))
			}
			return err
		}
	}
	c.UpdatedAt = m.opts.Now()
	m.pol = c
	m.lastApply = c.UpdatedAt
	m.lastErr = nil
	m.drift = Drift{Checked: c.UpdatedAt, InSync: true}
	if m.opts.Path != "" {
		if err := m.store.Save(c); err != nil {
			// The kernel has the new state; the file lagging is a loud warning,
			// not a reason to pretend the apply failed.
			m.lastErr = fmt.Errorf("applied but failed to persist policy: %w", err)
			log.Printf("firewall: %v", m.lastErr)
		}
	}
	m.notifyLocked()
	return nil
}

func (m *Manager) notifyLocked() {
	if m.onChange == nil {
		return
	}
	st := m.statusLocked()
	fn := m.onChange
	go fn(st)
}

// checkFrameSize makes sure the op fits one privsep message (messages are
// chunked across datagrams, so the bound is the reassembly cap, not a frame).
func checkFrameSize(op netops.Op) error {
	b, err := netops.EncodeOp(op)
	if err != nil {
		return err
	}
	if limit := privsep.MaxMessage - 4096; len(b) > limit {
		return fmt.Errorf("%w (%d bytes, limit %d)", ErrTooLarge, len(b), limit)
	}
	return nil
}

// ---- apply / reconcile ----------------------------------------------

// Apply (re)installs the committed policy into the kernel. Both tables are
// rebuilt, so all counters reset.
func (m *Manager) Apply() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyLocked()
}

func (m *Manager) applyLocked() error {
	if m.be == nil {
		return errors.New("firewall: no backend")
	}
	if !m.be.WritesAllowed() {
		return ErrWritesDisabled
	}
	if err := m.be.ApplyFilterTable(m.pol.filterSpec(m.opts.ProtectedTCPPorts)); err != nil {
		m.lastErr = err
		return err
	}
	if err := m.be.ApplyNATTable(m.pol.NATSpec()); err != nil {
		m.lastErr = err
		return err
	}
	m.lastApply = m.opts.Now()
	m.lastErr = nil
	return nil
}

// Drift is the result of comparing the kernel with the policy.
type Drift struct {
	Checked     time.Time `json:"checked"`
	InSync      bool      `json:"in_sync"`
	Details     []string  `json:"details,omitempty"`
	Corrected   bool      `json:"corrected"` // re-applied during this check
	Error       string    `json:"error,omitempty"`
	TableExists bool      `json:"table_exists"`
}

// Reconcile compares the live tables with the policy and, when they differ
// and writes are allowed, re-applies the policy. When writes are disabled it
// only reports. The result is kept for Status.
func (m *Manager) Reconcile() Drift {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.computeDriftLocked()
	if !d.InSync && d.Error == "" && m.be.WritesAllowed() {
		if err := m.applyLocked(); err != nil {
			d.Error = err.Error()
		} else {
			d.Corrected = true
			// Re-check so Status reflects the post-apply state.
			after := m.computeDriftLocked()
			d.InSync = after.InSync
			if !after.InSync {
				d.Details = append(d.Details, "still out of sync after re-apply: "+strings.Join(after.Details, "; "))
			}
		}
	}
	m.drift = d
	m.notifyLocked()
	return d
}

func (m *Manager) computeDriftLocked() Drift {
	d := Drift{Checked: m.opts.Now(), InSync: true}
	if m.be == nil {
		d.Error = "no backend"
		d.InSync = false
		return d
	}
	note := func(format string, args ...any) {
		d.InSync = false
		d.Details = append(d.Details, fmt.Sprintf(format, args...))
	}

	spec := m.pol.filterSpec(m.opts.ProtectedTCPPorts)
	fs, err := m.be.FilterTableState()
	if err != nil {
		d.Error = "read filter table: " + err.Error()
		d.InSync = false
		return d
	}
	d.TableExists = fs.Exists
	switch {
	case !fs.Exists && m.pol.Inert():
		// Nothing to enforce and nothing installed: exactly right. A fresh
		// host stays untouched until the first rule or enforce.
	case !fs.Exists:
		note("filter table missing")
	default:
		wantPol := netops.ChainPolicies(spec)
		for _, chain := range sortedKeys(wantPol) {
			if got := fs.Policies[chain]; got != wantPol[chain] {
				note("chain %s policy %q, want %q", chain, orNone(got), wantPol[chain])
			}
		}
		want := map[string][]string{}
		for _, r := range netops.RenderFilterRules(spec) {
			want[r.Chain] = append(want[r.Chain], r.ID())
		}
		got := map[string][]string{}
		unknown := 0
		for _, r := range fs.Rules {
			if r.ID == "" {
				unknown++
				continue
			}
			got[r.Chain] = append(got[r.Chain], r.ID)
		}
		if unknown > 0 {
			note("%d unmanaged rule(s) in filter table", unknown)
		}
		for _, chain := range []string{"input", "forward", "output"} {
			if !equalStrings(want[chain], got[chain]) {
				note("chain %s: %d rules live, %d desired (or order differs)", chain, len(got[chain]), len(want[chain]))
			}
		}
	}

	ns, err := m.be.NATTableState()
	if err != nil {
		d.Error = "read nat table: " + err.Error()
		d.InSync = false
		return d
	}
	if ns.LegacyMasqTable {
		note("legacy testudo_masq table present")
	}
	if !ns.Exists {
		if len(m.pol.Forwards) > 0 || len(m.pol.Masquerades) > 0 {
			note("nat table missing")
		}
	} else {
		var wantF, gotF, wantM, gotM []string
		for _, f := range m.pol.Forwards {
			wantF = append(wantF, f.ID())
		}
		for _, f := range ns.Forwards {
			gotF = append(gotF, f.ID)
		}
		for _, ms := range m.pol.Masquerades {
			wantM = append(wantM, ms.ID())
		}
		for _, ms := range ns.Masquerades {
			if !ms.Legacy {
				gotM = append(gotM, ms.ID)
			}
		}
		if !equalStrings(wantF, gotF) {
			note("port forwards: %d live, %d desired (or order differs)", len(gotF), len(wantF))
		}
		if !equalStrings(wantM, gotM) {
			note("masquerades: %d live, %d desired (or order differs)", len(gotM), len(wantM))
		}
	}
	return d
}

// Run applies the policy at start (Reconcile) and then re-checks on every
// tick until ctx ends. A failed boot apply is logged and retried on the next
// tick - the reconciler is the self-healing loop, not a one-shot.
func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	d := m.Reconcile()
	if d.Error != "" {
		log.Printf("firewall: boot reconcile: %s", d.Error)
	} else if d.Corrected {
		log.Printf("firewall: policy applied at boot (%s)", strings.Join(d.Details, "; "))
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Reconcile()
		}
	}
}

// ---- import / export -------------------------------------------------

// Export returns the policy as indented JSON (the same format as the file).
func (m *Manager) Export() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return json.MarshalIndent(m.pol, "", "  ")
}

// Import replaces the whole policy from JSON: validate → apply → persist.
// Enforce is taken from the import as-is, so importing an enforcing policy
// onto a host is an immediate change (callers wanting commit-confirm should
// import with Enforce=false and then SetEnforce).
func (m *Manager) Import(data []byte) error {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}
	if p.Version == 0 {
		p.Version = PolicyVersion
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.revertTo != nil {
		return ErrPendingConfirm
	}
	return m.commitLocked(p, true, true)
}

// ---- helpers ---------------------------------------------------------

func hasRule(rules []netops.FilterRule, id string) bool {
	for _, r := range rules {
		if r.ID() == id {
			return true
		}
	}
	return false
}

func hasForward(fs []netops.PortForward, id string) bool {
	for _, f := range fs {
		if f.ID() == id {
			return true
		}
	}
	return false
}

func hasMasq(ms []netops.Masquerade, id string) bool {
	for _, m := range ms {
		if m.ID() == id {
			return true
		}
	}
	return false
}

// matchesTarget returns true when every non-empty field of target equals the
// corresponding field of r. Empty fields in target act as wildcards.
func matchesTarget(r, target netops.FilterRule) bool {
	r = r.Normalize()
	if target.Chain != "" && r.Chain != target.Chain {
		return false
	}
	if target.Action != "" && r.Action != target.Action {
		return false
	}
	if target.Proto != "" && r.Proto != target.Proto {
		return false
	}
	if target.Port != 0 && r.Port != target.Port {
		return false
	}
	if target.PortEnd != 0 && r.PortEnd != target.PortEnd {
		return false
	}
	if target.InIface != "" && r.InIface != target.InIface {
		return false
	}
	if target.OutIface != "" && r.OutIface != target.OutIface {
		return false
	}
	if target.SrcCIDR != "" && r.SrcCIDR != target.SrcCIDR {
		return false
	}
	if target.DstCIDR != "" && r.DstCIDR != target.DstCIDR {
		return false
	}
	if target.CtState != "" && r.CtState != target.CtState {
		return false
	}
	if target.Owner != "" && r.Owner != target.Owner {
		return false
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
