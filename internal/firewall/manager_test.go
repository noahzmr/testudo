package firewall

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/netops"
)

// fakeBE records applies and serves a kernel state that, by default, mirrors
// the last applied specs (as the real kernel would). flushed simulates an
// external `nft flush ruleset`.
type fakeBE struct {
	mu            sync.Mutex
	writes        bool
	filterApplies []netops.FilterTableSpec
	natApplies    []netops.NATSpec
	failFilter    error
	failNAT       error
	flushed       bool
	stateErr      error // returned by both state reads (simulates EPERM)
	stateOverride *netops.FilterTableState
	natOverride   *netops.NATTableState
	counters      map[string]uint64 // id -> packets
}

func newFake() *fakeBE { return &fakeBE{writes: true} }

func (f *fakeBE) WritesAllowed() bool { return f.writes }

func (f *fakeBE) ApplyFilterTable(s netops.FilterTableSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFilter != nil {
		return f.failFilter
	}
	f.filterApplies = append(f.filterApplies, s)
	f.flushed = false
	return nil
}

func (f *fakeBE) ApplyNATTable(s netops.NATSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNAT != nil {
		return f.failNAT
	}
	f.natApplies = append(f.natApplies, s)
	f.flushed = false
	return nil
}

func (f *fakeBE) FilterTableState() (netops.FilterTableState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stateErr != nil {
		return netops.FilterTableState{}, f.stateErr
	}
	if f.stateOverride != nil {
		return *f.stateOverride, nil
	}
	if f.flushed || len(f.filterApplies) == 0 {
		return netops.FilterTableState{Policies: map[string]string{}}, nil
	}
	last := f.filterApplies[len(f.filterApplies)-1]
	st := netops.FilterTableState{Exists: true, Policies: netops.ChainPolicies(last)}
	for i, r := range netops.RenderFilterRules(last) {
		mr := netops.ManagedRule{Chain: r.Chain, Handle: uint64(i + 1), ID: r.ID(), HasCounter: true}
		mr.Packets = f.counters[mr.ID]
		st.Rules = append(st.Rules, mr)
	}
	return st, nil
}

func (f *fakeBE) NATTableState() (netops.NATTableState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stateErr != nil {
		return netops.NATTableState{}, f.stateErr
	}
	if f.natOverride != nil {
		return *f.natOverride, nil
	}
	if f.flushed || len(f.natApplies) == 0 {
		return netops.NATTableState{}, nil
	}
	last := f.natApplies[len(f.natApplies)-1]
	st := netops.NATTableState{Exists: true}
	for i, pf := range last.Forwards {
		st.Forwards = append(st.Forwards, netops.ManagedForward{PortForward: pf.Normalize(), ID: pf.ID(), Handle: uint64(i + 1), HasCounter: true})
	}
	for i, m := range last.Masquerades {
		st.Masquerades = append(st.Masquerades, netops.ManagedMasquerade{Masquerade: m.Normalize(), ID: m.ID(), Handle: uint64(i + 1), HasCounter: true})
	}
	return st, nil
}

func (f *fakeBE) applies() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.filterApplies), len(f.natApplies)
}

func (f *fakeBE) lastFilter() netops.FilterTableSpec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.filterApplies[len(f.filterApplies)-1]
}

func openTemp(t *testing.T, be Backend, opts Options) (*Manager, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "firewall.json")
	opts.Path = path
	m, err := Open(opts, be)
	if err != nil {
		t.Fatal(err)
	}
	return m, path
}

func loadFile(t *testing.T, path string) Policy {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

var sshDrop = netops.FilterRule{Chain: "input", Action: "drop", Proto: "tcp", Port: 22, SrcCIDR: "203.0.113.0/24"}

func TestOpenCreatesDefaultPolicyFile(t *testing.T) {
	be := newFake()
	m, path := openTemp(t, be, Options{})
	p := loadFile(t, path)
	if p.Version != PolicyVersion || p.Enforce || !p.Baseline.AllowEstablished || len(p.Rules) != 0 {
		t.Fatalf("default policy on disk: %+v", p)
	}
	if fa, na := be.applies(); fa != 0 || na != 0 {
		t.Fatal("Open must not apply anything")
	}
	if st := m.Status(); st.Enforce || !st.WritesAllowed || st.RuleCount != 0 {
		t.Fatalf("status: %+v", st)
	}
}

func TestAddRuleAppliesThenPersists(t *testing.T) {
	be := newFake()
	m, path := openTemp(t, be, Options{})
	if err := m.AddRule(sshDrop); err != nil {
		t.Fatal(err)
	}
	fa, na := be.applies()
	if fa != 1 || na != 0 {
		t.Fatalf("applies filter=%d nat=%d, want 1/0", fa, na)
	}
	spec := be.lastFilter()
	if len(spec.Rules) != 1 || spec.Rules[0].ID() != sshDrop.ID() {
		t.Fatalf("applied spec rules: %+v", spec.Rules)
	}
	if got := loadFile(t, path); len(got.Rules) != 1 || got.Rules[0].ID() != sshDrop.ID() || got.UpdatedAt.IsZero() {
		t.Fatalf("persisted: %+v", got)
	}
	// Idempotent: the same rule again is a no-op (no apply).
	if err := m.AddRule(sshDrop); err != nil {
		t.Fatal(err)
	}
	if fa, _ := be.applies(); fa != 1 {
		t.Fatalf("duplicate add re-applied: %d", fa)
	}
	// Invalid rules are rejected before any apply.
	if err := m.AddRule(netops.FilterRule{Chain: "nope", Action: "accept"}); err == nil {
		t.Fatal("invalid rule accepted")
	}
	if err := m.AddRule(netops.FilterRule{Chain: "input", Action: "accept", Owner: netops.OwnerBaseline}); err == nil {
		t.Fatal("baseline owner must be reserved")
	}
}

func TestApplyFailureLeavesPolicyUntouched(t *testing.T) {
	be := newFake()
	m, path := openTemp(t, be, Options{})
	before := loadFile(t, path)
	be.failFilter = errors.New("kernel said no")
	if err := m.AddRule(sshDrop); err == nil || err.Error() != "kernel said no" {
		t.Fatalf("err = %v", err)
	}
	if len(m.Policy().Rules) != 0 {
		t.Fatal("policy mutated despite apply failure")
	}
	after := loadFile(t, path)
	if !after.UpdatedAt.Equal(before.UpdatedAt) || len(after.Rules) != 0 {
		t.Fatal("file mutated despite apply failure")
	}
	if st := m.Status(); st.LastError == "" {
		t.Fatal("status must surface the last error")
	}
}

func TestWritesDisabledRefusesMutations(t *testing.T) {
	be := newFake()
	be.writes = false
	m, _ := openTemp(t, be, Options{})
	if err := m.AddRule(sshDrop); !errors.Is(err, ErrWritesDisabled) {
		t.Fatalf("err = %v, want ErrWritesDisabled", err)
	}
	if err := m.SetEnforce(true, 0); !errors.Is(err, ErrWritesDisabled) {
		t.Fatalf("enforce err = %v", err)
	}
	if fa, na := be.applies(); fa != 0 || na != 0 {
		t.Fatal("nothing may be applied with writes disabled")
	}
}

func TestNATOnlyChangeDoesNotRebuildFilter(t *testing.T) {
	be := newFake()
	m, _ := openTemp(t, be, Options{})
	pf := netops.PortForward{Proto: "tcp", WANPort: 443, LANIP: "192.168.1.10"}
	if err := m.AddForward(pf); err != nil {
		t.Fatal(err)
	}
	if err := m.AddMasquerade(netops.Masquerade{OutIface: "eth0", SrcCIDR: "10.8.0.0/24"}); err != nil {
		t.Fatal(err)
	}
	fa, na := be.applies()
	if fa != 0 || na != 2 {
		t.Fatalf("applies filter=%d nat=%d, want 0/2", fa, na)
	}
	fw, mq, err := m.NAT()
	if err != nil {
		t.Fatal(err)
	}
	if len(fw) != 1 || !fw[0].Live || fw[0].LANPort != 443 || len(mq) != 1 || !mq[0].Live {
		t.Fatalf("NAT() = %+v %+v", fw, mq)
	}
	if n, err := m.DelForwardsMatching("tcp", 443); err != nil || n != 1 {
		t.Fatalf("del forwards: n=%d err=%v", n, err)
	}
	if n, err := m.DelMasqueradesMatching("eth0", "10.8.0.0/24"); err != nil || n != 1 {
		t.Fatalf("del masq: n=%d err=%v", n, err)
	}
	if p := m.Policy(); len(p.Forwards) != 0 || len(p.Masquerades) != 0 {
		t.Fatalf("policy after deletes: %+v", p)
	}
	if err := m.DelForward("000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id err = %v", err)
	}
}

func TestEnforceCommitConfirmReverts(t *testing.T) {
	be := newFake()
	m, path := openTemp(t, be, Options{ProtectedTCPPorts: []uint16{8080}})
	var notified []Status
	var nmu sync.Mutex
	m.SetOnChange(func(s Status) { nmu.Lock(); notified = append(notified, s); nmu.Unlock() })

	if err := m.SetEnforce(true, 60*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	spec := be.lastFilter()
	if !spec.Enforce {
		t.Fatal("enforce not applied")
	}
	// Protected port merged into the applied baseline, not into the policy.
	found := false
	for _, p := range spec.Baseline.AllowTCPPorts {
		if p == 8080 {
			found = true
		}
	}
	if !found {
		t.Fatalf("protected port missing from applied baseline: %v", spec.Baseline.AllowTCPPorts)
	}
	for _, p := range m.Policy().Baseline.AllowTCPPorts {
		if p == 8080 {
			t.Fatal("protected port leaked into the persisted policy")
		}
	}
	st := m.Status()
	if !st.PendingConfirm || st.PendingUntil.IsZero() || !st.Enforce {
		t.Fatalf("status during window: %+v", st)
	}
	// Other mutations are refused while the confirm is pending.
	if err := m.AddRule(sshDrop); !errors.Is(err, ErrPendingConfirm) {
		t.Fatalf("mutation during pending: %v", err)
	}
	// Window elapses without a confirm -> revert.
	time.Sleep(200 * time.Millisecond)
	if m.Policy().Enforce {
		t.Fatal("enforce not reverted after the confirm window")
	}
	if fa, _ := be.applies(); fa != 2 || be.lastFilter().Enforce {
		t.Fatalf("revert apply missing: applies=%d lastEnforce=%v", fa, be.lastFilter().Enforce)
	}
	if st := m.Status(); st.PendingConfirm || st.Enforce {
		t.Fatalf("status after revert: %+v", st)
	}
	if loadFile(t, path).Enforce {
		t.Fatal("file still enforcing after revert")
	}
	nmu.Lock()
	n := len(notified)
	nmu.Unlock()
	if n < 2 {
		t.Fatalf("expected change notifications, got %d", n)
	}
	// Mutations work again after the revert.
	if err := m.AddRule(sshDrop); err != nil {
		t.Fatal(err)
	}
}

func TestEnforceConfirmedStays(t *testing.T) {
	be := newFake()
	m, path := openTemp(t, be, Options{})
	if err := m.SetEnforce(true, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := m.SetEnforce(true, time.Hour); !errors.Is(err, ErrPendingConfirm) {
		t.Fatalf("second enforce during pending: %v", err)
	}
	if err := m.ConfirmEnforce(); err != nil {
		t.Fatal(err)
	}
	st := m.Status()
	if st.PendingConfirm || !st.Enforce {
		t.Fatalf("status after confirm: %+v", st)
	}
	if !loadFile(t, path).Enforce {
		t.Fatal("file not enforcing after confirm")
	}
	// Confirm is idempotent; turning off is immediate.
	if err := m.ConfirmEnforce(); err != nil {
		t.Fatal(err)
	}
	if err := m.SetEnforce(false, 0); err != nil {
		t.Fatal(err)
	}
	if m.Policy().Enforce || be.lastFilter().Enforce {
		t.Fatal("enforce off not applied")
	}
	// Enforce without a window is immediate and needs no confirm.
	if err := m.SetEnforce(true, 0); err != nil {
		t.Fatal(err)
	}
	if st := m.Status(); st.PendingConfirm || !st.Enforce {
		t.Fatalf("immediate enforce: %+v", st)
	}
}

func TestOwnerAndWildcardDeletes(t *testing.T) {
	be := newFake()
	m, _ := openTemp(t, be, Options{})
	peer := []netops.FilterRule{
		{Chain: "forward", Action: "accept", InIface: "wg0", SrcCIDR: "10.8.0.2/32", DstCIDR: "192.168.1.0/24", Owner: "wg-peer:abc"},
		{Chain: "forward", Action: "drop", InIface: "wg0", SrcCIDR: "10.8.0.2/32", Owner: "wg-peer:abc"},
	}
	for _, r := range peer {
		if err := m.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.AddRule(sshDrop); err != nil {
		t.Fatal(err)
	}
	if n, err := m.DelRulesByOwner("wg-peer:abc"); err != nil || n != 2 {
		t.Fatalf("by owner: n=%d err=%v", n, err)
	}
	if p := m.Policy(); len(p.Rules) != 1 || p.Rules[0].ID() != sshDrop.ID() {
		t.Fatalf("rules after owner delete: %+v", p.Rules)
	}
	if n, err := m.DelRulesByOwner("wg-peer:none"); err != nil || n != 0 {
		t.Fatalf("no-op owner delete: n=%d err=%v", n, err)
	}
	// Wildcard match: chain + port only.
	if n, err := m.DelRulesMatching(netops.FilterRule{Chain: "input", Port: 22}); err != nil || n != 1 {
		t.Fatalf("wildcard: n=%d err=%v", n, err)
	}
	if len(m.Policy().Rules) != 0 {
		t.Fatal("rule survived wildcard delete")
	}
}

func TestReorderAndInsert(t *testing.T) {
	be := newFake()
	m, _ := openTemp(t, be, Options{})
	a := netops.FilterRule{Chain: "input", Action: "accept", Proto: "tcp", Port: 80}
	b := netops.FilterRule{Chain: "input", Action: "accept", Proto: "tcp", Port: 443}
	c := netops.FilterRule{Chain: "input", Action: "drop", Proto: "tcp", Port: 8080}
	for _, r := range []netops.FilterRule{a, b} {
		if err := m.AddRule(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.InsertRule(0, c); err != nil {
		t.Fatal(err)
	}
	ids := func() []string {
		var out []string
		for _, r := range m.Policy().Rules {
			out = append(out, r.ID())
		}
		return out
	}
	if got := ids(); got[0] != c.ID() || got[1] != a.ID() || got[2] != b.ID() {
		t.Fatalf("insert order: %v", got)
	}
	if err := m.Reorder([]string{b.ID(), a.ID(), c.ID()}); err != nil {
		t.Fatal(err)
	}
	if got := ids(); got[0] != b.ID() || got[2] != c.ID() {
		t.Fatalf("reorder: %v", got)
	}
	if err := m.Reorder([]string{b.ID(), a.ID()}); err == nil {
		t.Fatal("partial reorder accepted")
	}
	if err := m.Reorder([]string{b.ID(), a.ID(), a.ID()}); err == nil {
		t.Fatal("repeated id accepted")
	}
	// The applied spec follows the new order.
	spec := be.lastFilter()
	if spec.Rules[0].ID() != b.ID() {
		t.Fatal("applied spec not reordered")
	}
	// Rules() shows user rules with their index and baseline rules with -1.
	rs, err := m.Rules()
	if err != nil {
		t.Fatal(err)
	}
	seenUser := 0
	for _, r := range rs {
		if r.Baseline && r.Index != -1 {
			t.Fatalf("baseline rule with index: %+v", r)
		}
		if !r.Baseline {
			seenUser++
			if r.Index < 0 || !r.Live {
				t.Fatalf("user rule status: %+v", r)
			}
		}
	}
	if seenUser != 3 {
		t.Fatalf("user rules in Rules(): %d", seenUser)
	}
}

func TestReconcileCorrectsDrift(t *testing.T) {
	be := newFake()
	m, _ := openTemp(t, be, Options{})
	if err := m.AddRule(sshDrop); err != nil {
		t.Fatal(err)
	}
	d := m.Reconcile()
	if !d.InSync || d.Corrected {
		t.Fatalf("in-sync reconcile: %+v", d)
	}
	// Someone flushes the ruleset.
	be.mu.Lock()
	be.flushed = true
	be.mu.Unlock()
	d = m.Reconcile()
	if !d.Corrected || !d.InSync || len(d.Details) == 0 {
		t.Fatalf("drift reconcile: %+v", d)
	}
	if fa, na := be.applies(); fa != 2 || na != 1 {
		t.Fatalf("re-apply counts filter=%d nat=%d", fa, na)
	}
	if st := m.Status(); !st.InSync {
		t.Fatalf("status after correction: %+v", st)
	}
	// A policy flip from outside is drift too.
	st := netops.FilterTableState{Exists: true, Policies: map[string]string{"input": "drop", "forward": "accept", "output": "accept"}}
	for _, r := range netops.RenderFilterRules(be.lastFilter()) {
		st.Rules = append(st.Rules, netops.ManagedRule{Chain: r.Chain, ID: r.ID(), HasCounter: true})
	}
	be.mu.Lock()
	be.stateOverride = &st
	be.mu.Unlock()
	d = m.Reconcile()
	if d.InSync == true && !d.Corrected {
		t.Fatalf("policy drift not detected: %+v", d)
	}
	found := false
	for _, s := range d.Details {
		if contains(s, "chain input policy") {
			found = true
		}
	}
	if !found {
		t.Fatalf("drift detail missing policy mismatch: %v", d.Details)
	}
}

func TestReconcileReportsWhenWritesDisabled(t *testing.T) {
	be := newFake()
	m, _ := openTemp(t, be, Options{})
	if err := m.AddRule(sshDrop); err != nil {
		t.Fatal(err)
	}
	be.mu.Lock()
	be.flushed = true
	be.writes = false
	be.mu.Unlock()
	d := m.Reconcile()
	if d.InSync || d.Corrected {
		t.Fatalf("expected uncorrected drift: %+v", d)
	}
	if fa, _ := be.applies(); fa != 1 {
		t.Fatal("must not apply with writes disabled")
	}
	st := m.Status()
	if st.InSync || len(st.DriftDetail) == 0 || st.WritesAllowed {
		t.Fatalf("status: %+v", st)
	}
}

func TestInertPolicyNeedsNoTable(t *testing.T) {
	be := newFake()
	m, _ := openTemp(t, be, Options{})
	// Fresh default policy, nothing installed: in sync, and the reconciler
	// must not create a table (writes are allowed here).
	d := m.Reconcile()
	if !d.InSync || d.Corrected || d.TableExists {
		t.Fatalf("inert reconcile: %+v", d)
	}
	if fa, na := be.applies(); fa != 0 || na != 0 {
		t.Fatalf("inert policy applied: filter=%d nat=%d", fa, na)
	}
	st := m.Status()
	if !st.Inert || st.TableExists || !st.InSync {
		t.Fatalf("inert status: %+v", st)
	}
	// The first rule makes the table required; a missing table is drift again.
	if err := m.AddRule(sshDrop); err != nil {
		t.Fatal(err)
	}
	be.mu.Lock()
	be.flushed = true
	be.mu.Unlock()
	d = m.Reconcile()
	if d.InSync == true && !d.Corrected {
		t.Fatalf("non-inert policy with missing table must drift/correct: %+v", d)
	}
	if st := m.Status(); st.Inert {
		t.Fatalf("policy with a rule reported inert: %+v", st)
	}
	// Enforce alone (no rules) is not inert either: the baseline must land.
	if _, err := m.DelRulesMatching(netops.FilterRule{Chain: "input", Port: 22}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetEnforce(true, 0); err != nil {
		t.Fatal(err)
	}
	if m.Policy().Inert() {
		t.Fatal("enforcing policy reported inert")
	}
}

func TestReconcileUnreadableKernelIsNotDrift(t *testing.T) {
	be := newFake()
	m, _ := openTemp(t, be, Options{})
	if err := m.AddRule(sshDrop); err != nil {
		t.Fatal(err)
	}
	// Reads fail (no CAP_NET_ADMIN): the result must say "unreadable", carry
	// no drift details, and must not trigger a re-apply.
	be.mu.Lock()
	be.stateErr = errors.New("list tables: netlink receive: operation not permitted")
	be.mu.Unlock()
	d := m.Reconcile()
	if d.InSync || d.Corrected || d.Error == "" || len(d.Details) != 0 {
		t.Fatalf("unreadable reconcile: %+v", d)
	}
	if fa, _ := be.applies(); fa != 1 {
		t.Fatalf("re-applied despite unreadable state: %d applies", fa)
	}
	st := m.Status()
	if st.DriftError == "" || st.InSync || len(st.DriftDetail) != 0 {
		t.Fatalf("status must expose the read error, not a drift: %+v", st)
	}
	// Once readable again the status clears.
	be.mu.Lock()
	be.stateErr = nil
	be.mu.Unlock()
	if d := m.Reconcile(); !d.InSync || d.Error != "" {
		t.Fatalf("recovered reconcile: %+v", d)
	}
	if st := m.Status(); st.DriftError != "" || !st.InSync {
		t.Fatalf("recovered status: %+v", st)
	}
}

func TestLegacyImportOnFirstOpen(t *testing.T) {
	be := newFake()
	legacyRule := netops.FilterRule{Chain: "forward", Action: "accept", InIface: "wg0", SrcCIDR: "10.8.0.2/32"}
	be.stateOverride = &netops.FilterTableState{Exists: true, Policies: map[string]string{}, Rules: []netops.ManagedRule{
		{Chain: "forward", Handle: 3, Legacy: &legacyRule},
		{Chain: "input", Handle: 4, ID: "aaaaaaaaaaaa"}, // managed id with no policy: cannot be imported
	}}
	be.natOverride = &netops.NATTableState{Exists: true, LegacyMasqTable: true,
		Forwards:    []netops.ManagedForward{{PortForward: netops.PortForward{Proto: "tcp", WANPort: 80, LANIP: "192.168.1.5", LANPort: 80}, Legacy: true}},
		Masquerades: []netops.ManagedMasquerade{{Masquerade: netops.Masquerade{OutIface: "eth0", SrcCIDR: "10.8.0.0/24"}, Legacy: true}},
	}
	m, path := openTemp(t, be, Options{})
	if m.Imported() != 3 {
		t.Fatalf("imported = %d, want 3", m.Imported())
	}
	p := m.Policy()
	if len(p.Rules) != 1 || p.Rules[0].ID() != legacyRule.ID() || len(p.Forwards) != 1 || len(p.Masquerades) != 1 {
		t.Fatalf("imported policy: %+v", p)
	}
	if got := loadFile(t, path); len(got.Rules) != 1 {
		t.Fatal("import not persisted")
	}
	// Second open with the file present must not import again.
	m2, err := Open(Options{Path: path}, be)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Imported() != 0 || len(m2.Policy().Rules) != 1 {
		t.Fatalf("second open re-imported: %d", m2.Imported())
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	be := newFake()
	m, _ := openTemp(t, be, Options{})
	if err := m.AddRule(sshDrop); err != nil {
		t.Fatal(err)
	}
	if err := m.AddForward(netops.PortForward{Proto: "tcp", WANPort: 443, LANIP: "192.168.1.10"}); err != nil {
		t.Fatal(err)
	}
	data, err := m.Export()
	if err != nil {
		t.Fatal(err)
	}
	be2 := newFake()
	m2, _ := openTemp(t, be2, Options{})
	if err := m2.Import(data); err != nil {
		t.Fatal(err)
	}
	if fa, na := be2.applies(); fa != 1 || na != 1 {
		t.Fatalf("import applies filter=%d nat=%d", fa, na)
	}
	p1, p2 := m.Policy(), m2.Policy()
	if len(p2.Rules) != len(p1.Rules) || p2.Rules[0].ID() != p1.Rules[0].ID() || len(p2.Forwards) != 1 {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", p1, p2)
	}
	if err := m2.Import([]byte(`{"version": 99}`)); err == nil {
		t.Fatal("unsupported version accepted")
	}
	if err := m2.Import([]byte(`not json`)); err == nil {
		t.Fatal("garbage accepted")
	}
	// RenderNFT mentions both tables and the rule.
	out := m2.RenderNFT()
	if !contains(out, "table inet testudo_filter") || !contains(out, "table ip testudo_nat") || !contains(out, "203.0.113.0/24") {
		t.Fatalf("render:\n%s", out)
	}
}

func TestRulesJoinLiveCounters(t *testing.T) {
	be := newFake()
	be.counters = map[string]uint64{sshDrop.ID(): 42}
	m, _ := openTemp(t, be, Options{})
	if err := m.AddRule(sshDrop); err != nil {
		t.Fatal(err)
	}
	rs, err := m.Rules()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.ID == sshDrop.ID() {
			if !r.Live || r.Packets != 42 || !r.HasCounter {
				t.Fatalf("counters not joined: %+v", r)
			}
			return
		}
	}
	t.Fatal("rule not found in Rules()")
}

func TestPolicyValidateDuplicates(t *testing.T) {
	p := DefaultPolicy()
	p.Rules = []netops.FilterRule{sshDrop, sshDrop}
	if err := p.Validate(); err == nil {
		t.Fatal("duplicate rules accepted")
	}
	p = DefaultPolicy()
	p.Baseline.AllowTCPPorts = []uint16{0}
	if err := p.Validate(); err == nil {
		t.Fatal("port 0 accepted")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
