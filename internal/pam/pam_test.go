package pam

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/noahzmr/testudo/internal/auth"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/storage"
)

type fakeFW struct {
	mu    sync.Mutex
	rules []netops.FilterRule
	fail  error
}

func (f *fakeFW) AddRule(r netops.FilterRule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.rules = append(f.rules, r.Normalize())
	return nil
}

func (f *fakeFW) DelRulesByOwner(owner string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := f.rules[:0]
	n := 0
	for _, r := range f.rules {
		if r.Owner == owner {
			n++
			continue
		}
		kept = append(kept, r)
	}
	f.rules = kept
	return n, nil
}

func (f *fakeFW) byOwner(owner string) []netops.FilterRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []netops.FilterRule
	for _, r := range f.rules {
		if r.Owner == owner {
			out = append(out, r)
		}
	}
	return out
}

type fakeFlows struct {
	flows   []netops.ConntrackFlow
	flushed []netops.ConntrackFlow
	queries []netops.ConntrackQuery
}

// ListConntrackQuery records the filter and returns everything unfiltered, so
// the tests prove the manager's own matching is correct even when a backend
// ignores the server-side filter.
func (f *fakeFlows) ListConntrackQuery(q netops.ConntrackQuery) (netops.ConntrackResult, error) {
	f.queries = append(f.queries, q)
	return netops.ConntrackResult{Flows: f.flows, Total: len(f.flows)}, nil
}
func (f *fakeFlows) FlushConntrack(fl netops.ConntrackFlow) error {
	f.flushed = append(f.flushed, fl)
	return nil
}

type fakeCap struct {
	started []string // bpf filters
	stopped []string
}

func (c *fakeCap) Start(name, iface, bpf string) (string, error) {
	c.started = append(c.started, bpf)
	return "cap-" + name, nil
}
func (c *fakeCap) Stop(id string) error { c.stopped = append(c.stopped, id); return nil }

type fakePeers struct{ byUser map[string][]string }

func (p fakePeers) PeerIPs(_ context.Context, user string) ([]string, error) {
	return p.byUser[user], nil
}

type harness struct {
	m     *Manager
	st    *storage.Store
	fw    *fakeFW
	flows *fakeFlows
	cap   *fakeCap
	now   time.Time
	ctx   context.Context
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h := &harness{st: st, fw: &fakeFW{}, flows: &fakeFlows{}, cap: &fakeCap{}, now: time.Unix(1700000000, 0), ctx: context.Background()}
	h.m = New(st, h.fw, h.flows, h.cap, fakePeers{byUser: map[string][]string{
		"alice": {"10.8.0.2/32"},
		"bob":   {"10.8.0.3/32", "10.8.0.4/32"},
	}}, Options{Device: "wg0", Now: func() time.Time { return h.now }})
	return h
}

var (
	admin    = Subject{Name: "root", Role: auth.RoleAdmin, MFA: true}
	alice    = Subject{Name: "alice", Role: auth.RoleOperator}
	aliceMFA = Subject{Name: "alice", Role: auth.RoleOperator, MFA: true}
	bob      = Subject{Name: "bob", Role: auth.RoleOperator}
	carol    = Subject{Name: "carol", Role: auth.RoleApprover}
	vera     = Subject{Name: "vera", Role: auth.RoleViewer}
)

func (h *harness) resource(t *testing.T, name, cidr string, kind string) storage.PAMResource {
	t.Helper()
	r, err := h.m.AddResource(h.ctx, admin, storage.PAMResource{Name: name, Kind: kind, CIDR: cidr})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (h *harness) policy(t *testing.T, subject, resID string, maxTTL time.Duration, approval, mfa bool) storage.PAMPolicy {
	t.Helper()
	p, err := h.m.AddPolicy(h.ctx, admin, storage.PAMPolicy{
		Name: subject + "->" + resID, Subject: subject, ResourceID: resID,
		MaxTTL: int64(maxTTL.Seconds()), RequiresApproval: approval, RequiresMFA: mfa,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestResourceValidation(t *testing.T) {
	h := newHarness(t)
	if _, err := h.m.AddResource(h.ctx, alice, storage.PAMResource{Name: "x", Kind: "l3", CIDR: "10.0.0.1"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("operator added a resource: %v", err)
	}
	bad := []storage.PAMResource{
		{Name: "", Kind: "l3", CIDR: "10.0.0.1"},
		{Name: "x", Kind: "vnc", CIDR: "10.0.0.1"},
		{Name: "x", Kind: "l3", CIDR: "nope"},
		{Name: "x", Kind: "l3", CIDR: "10.0.0.1", Proto: "icmp"},
		{Name: "x", Kind: "l3", CIDR: "10.0.0.1", PortLo: 22},
		{Name: "x", Kind: "l3", CIDR: "10.0.0.1", Proto: "tcp", PortLo: 50, PortHi: 22},
	}
	for _, r := range bad {
		if _, err := h.m.AddResource(h.ctx, admin, r); err == nil {
			t.Fatalf("accepted invalid resource %+v", r)
		}
	}
	// Brokered kinds default their port.
	ssh := h.resource(t, "prod-ssh", "192.168.1.10", KindSSH)
	if ssh.Proto != "tcp" || ssh.PortLo != 22 {
		t.Fatalf("ssh default port: %+v", ssh)
	}
	rdp := h.resource(t, "win", "192.168.1.11", KindRDP)
	if rdp.PortLo != 3389 {
		t.Fatalf("rdp default port: %+v", rdp)
	}
	if _, err := h.m.AddPolicy(h.ctx, admin, storage.PAMPolicy{Name: "p", Subject: "team:ops", ResourceID: ssh.ID, MaxTTL: 60}); err == nil {
		t.Fatal("bad subject accepted")
	}
	if _, err := h.m.AddPolicy(h.ctx, admin, storage.PAMPolicy{Name: "p", Subject: "role:god", ResourceID: ssh.ID, MaxTTL: 60}); err == nil {
		t.Fatal("bad role subject accepted")
	}
	if _, err := h.m.AddPolicy(h.ctx, admin, storage.PAMPolicy{Name: "p", Subject: "user:alice", ResourceID: "res-missing", MaxTTL: 60}); err == nil {
		t.Fatal("policy for unknown resource accepted")
	}
}

func TestAutoApprovedGrantInstallsRulesAndCapture(t *testing.T) {
	h := newHarness(t)
	lan := h.resource(t, "lan", "192.168.1.0/24", KindL3)
	h.policy(t, "role:operator", lan.ID, time.Hour, false, false)

	if _, err := h.m.Request(h.ctx, alice, lan.ID, 30*time.Minute, "", ""); !errors.Is(err, ErrJustification) {
		t.Fatalf("empty justification: %v", err)
	}
	if _, err := h.m.Request(h.ctx, alice, lan.ID, 2*time.Hour, "maintenance", ""); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("ttl over max: %v", err)
	}
	if _, err := h.m.Request(h.ctx, vera, lan.ID, time.Minute, "maintenance", ""); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("viewer below role:operator: %v", err)
	}
	g, err := h.m.Request(h.ctx, alice, lan.ID, 30*time.Minute, "patch window", "CHG-42")
	if err != nil {
		t.Fatal(err)
	}
	if g.State != StateActive || g.ApprovedBy == "" || !g.EndsAt.Equal(h.now.Add(30*time.Minute)) {
		t.Fatalf("auto-approved grant: %+v", g)
	}
	rules := h.fw.byOwner(OwnerForGrant(g.ID))
	if len(rules) != 1 {
		t.Fatalf("rules = %+v", rules)
	}
	r := rules[0]
	if r.Chain != "forward" || r.Action != "accept" || r.InIface != "wg0" || r.SrcCIDR != "10.8.0.2/32" || r.DstCIDR != "192.168.1.0/24" {
		t.Fatalf("rule = %+v", r)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("rule invalid for netops: %v", err)
	}
	if len(h.cap.started) != 1 || h.cap.started[0] != "(host 10.8.0.2) and net 192.168.1.0/24" {
		t.Fatalf("capture filter = %v", h.cap.started)
	}
	if g.CaptureID == "" {
		t.Fatal("capture id not recorded")
	}
	o, err := h.m.Overview(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if o.ChainBroken != 0 || o.ChainChecked < 4 {
		t.Fatalf("chain: %+v", o)
	}
	actions := eventActions(o.Events)
	if !strings.Contains(actions, "requested") || !strings.Contains(actions, "activated") {
		t.Fatalf("events = %s", actions)
	}
}

func TestApprovalFlowAndSeparationOfDuties(t *testing.T) {
	h := newHarness(t)
	db := h.resource(t, "db", "10.1.0.5", KindL3)
	h.policy(t, "user:alice", db.ID, time.Hour, true, false)

	g, err := h.m.Request(h.ctx, alice, db.ID, time.Hour, "debug incident 123", "")
	if err != nil {
		t.Fatal(err)
	}
	if g.State != StatePending || len(h.fw.byOwner(OwnerForGrant(g.ID))) != 0 {
		t.Fatalf("pending grant must install nothing: %+v", g)
	}
	if _, err := h.m.Approve(h.ctx, bob, g.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("operator approved: %v", err)
	}
	aliceApprover := Subject{Name: "alice", Role: auth.RoleApprover}
	if _, err := h.m.Approve(h.ctx, aliceApprover, g.ID); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("self approval: %v", err)
	}
	g, err = h.m.Approve(h.ctx, carol, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if g.State != StateActive || g.ApprovedBy != "carol" {
		t.Fatalf("approved grant: %+v", g)
	}
	if _, err := h.m.Approve(h.ctx, carol, g.ID); !errors.Is(err, ErrState) {
		t.Fatalf("double approve: %v", err)
	}
	// Deny path on a fresh request.
	g2, _ := h.m.Request(h.ctx, alice, db.ID, time.Hour, "another look", "")
	if _, err := h.m.Deny(h.ctx, admin, g2.ID, "not now"); err != nil {
		t.Fatal(err)
	}
	got, _ := h.st.GetPAMGrant(h.ctx, g2.ID)
	if got.State != StateDenied || got.EndReason != "not now" {
		t.Fatalf("denied grant: %+v", got)
	}
}

func TestRevokeKillsFlowsAndStopsCapture(t *testing.T) {
	h := newHarness(t)
	db := h.resource(t, "db", "10.1.0.5", KindL3)
	h.policy(t, "role:operator", db.ID, time.Hour, false, false)
	g, err := h.m.Request(h.ctx, bob, db.ID, time.Hour, "backup restore", "")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(h.fw.byOwner(OwnerForGrant(g.ID))); n != 2 {
		t.Fatalf("bob has two peers, got %d rules", n)
	}
	h.flows.flows = []netops.ConntrackFlow{
		{Proto: "tcp", OrigSrc: "10.8.0.3", OrigDst: "10.1.0.5", OrigSport: 50000, OrigDport: 5432, Bytes: 100},
		{Proto: "tcp", OrigSrc: "10.8.0.4", OrigDst: "10.1.0.5", OrigSport: 50001, OrigDport: 5432, Bytes: 200},
		{Proto: "tcp", OrigSrc: "10.8.0.3", OrigDst: "10.1.0.9", OrigSport: 50002, OrigDport: 22},   // other target
		{Proto: "tcp", OrigSrc: "10.8.0.2", OrigDst: "10.1.0.5", OrigSport: 50003, OrigDport: 5432}, // alice's peer
	}
	h.m.Observe(h.ctx)
	got, _ := h.st.GetPAMGrant(h.ctx, g.ID)
	if got.ObservedFlows != 2 || got.ObservedBytes != 300 {
		t.Fatalf("observed: %+v", got)
	}
	// A viewer who is not the requester cannot revoke; the requester can.
	if _, err := h.m.Revoke(h.ctx, vera, g.ID, "x"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer revoked: %v", err)
	}
	g, err = h.m.Revoke(h.ctx, bob, g.ID, "done early")
	if err != nil {
		t.Fatal(err)
	}
	if g.State != StateRevoked || g.EndReason != "done early" {
		t.Fatalf("revoked: %+v", g)
	}
	if n := len(h.fw.byOwner(OwnerForGrant(g.ID))); n != 0 {
		t.Fatalf("rules left after revoke: %d", n)
	}
	if len(h.flows.flushed) != 2 {
		t.Fatalf("flushed %d flows, want exactly bob's two to the resource: %+v", len(h.flows.flushed), h.flows.flushed)
	}
	// The privileged side was asked only for bob's peers towards the resource.
	last := h.flows.queries[len(h.flows.queries)-1]
	if len(last.SrcIPs) != 2 || last.DstCIDR != "10.1.0.5/32" {
		t.Fatalf("conntrack query not scoped to the grant: %+v", last)
	}
	if len(h.cap.stopped) != 1 || h.cap.stopped[0] != g.CaptureID {
		t.Fatalf("capture not stopped: %v", h.cap.stopped)
	}
	if _, err := h.m.Revoke(h.ctx, bob, g.ID, "again"); !errors.Is(err, ErrState) {
		t.Fatalf("double revoke: %v", err)
	}
}

func TestExpiryAndBootReconcile(t *testing.T) {
	h := newHarness(t)
	db := h.resource(t, "db", "10.1.0.5", KindL3)
	h.policy(t, "role:operator", db.ID, time.Hour, false, false)
	g, err := h.m.Request(h.ctx, alice, db.ID, 10*time.Minute, "quick check", "")
	if err != nil {
		t.Fatal(err)
	}
	if n := h.m.Expire(h.ctx); n != 0 {
		t.Fatalf("expired early: %d", n)
	}
	h.now = h.now.Add(11 * time.Minute)
	if n := h.m.Expire(h.ctx); n != 1 {
		t.Fatalf("expire = %d", n)
	}
	got, _ := h.st.GetPAMGrant(h.ctx, g.ID)
	if got.State != StateExpired || len(h.fw.byOwner(OwnerForGrant(g.ID))) != 0 {
		t.Fatalf("expired grant: %+v rules=%d", got, len(h.fw.rules))
	}
	// A second manager over the same store (a restart) expires an overdue
	// active grant at Run start without needing the firewall state.
	g2, _ := h.m.Request(h.ctx, alice, db.ID, time.Minute, "restart test", "")
	h.now = h.now.Add(2 * time.Minute)
	m2 := New(h.st, h.fw, h.flows, h.cap, fakePeers{}, Options{Device: "wg0", Now: func() time.Time { return h.now }})
	ctx, cancel := context.WithCancel(h.ctx)
	done := make(chan struct{})
	go func() { m2.Run(ctx, time.Hour); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	got, _ = h.st.GetPAMGrant(h.ctx, g2.ID)
	if got.State != StateExpired {
		t.Fatalf("boot reconcile did not expire: %+v", got)
	}
}

func TestMFARequirementAndBreakGlass(t *testing.T) {
	h := newHarness(t)
	vault := h.resource(t, "vault", "10.1.0.7", KindSSH)
	h.policy(t, "user:alice", vault.ID, time.Hour, false, true)
	if _, err := h.m.Request(h.ctx, alice, vault.ID, time.Minute, "rotate keys", ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("no-MFA request accepted: %v", err)
	}
	if g, err := h.m.Request(h.ctx, aliceMFA, vault.ID, time.Minute, "rotate keys", ""); err != nil || g.State != StateActive {
		t.Fatalf("MFA request: %+v %v", g, err)
	}
	// The ssh resource compiles to tcp/22 only.
	rs := h.fw.rules
	last := rs[len(rs)-1]
	if last.Proto != "tcp" || last.Port != 22 {
		t.Fatalf("ssh rule = %+v", last)
	}
	// Break-glass: admin only, long justification, capped TTL, no policy needed.
	other := h.resource(t, "nopolicy", "10.9.9.9", KindL3)
	if _, err := h.m.Request(h.ctx, admin, other.ID, time.Minute, "no policy here", ""); !errors.Is(err, ErrNoPolicy) {
		t.Fatalf("admin bypassed policies via Request: %v", err)
	}
	if _, err := h.m.BreakGlass(h.ctx, alice, other.ID, time.Minute, "incident 77 - db down"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("operator break-glass: %v", err)
	}
	if _, err := h.m.BreakGlass(h.ctx, admin, other.ID, time.Minute, "short"); !errors.Is(err, ErrJustification) {
		t.Fatalf("short justification: %v", err)
	}
	if _, err := h.m.BreakGlass(h.ctx, admin, other.ID, 5*time.Hour, "incident 77 - db down"); err == nil {
		t.Fatal("ttl over cap accepted")
	}
	// root has no peer bound -> activation fails loudly, nothing installed.
	if _, err := h.m.BreakGlass(h.ctx, admin, other.ID, time.Hour, "incident 77 - db down"); !errors.Is(err, ErrNoPeer) {
		t.Fatalf("break-glass without peer: %v", err)
	}
	h.m.peers = fakePeers{byUser: map[string][]string{"root": {"10.8.0.9/32"}, "alice": {"10.8.0.2/32"}}}
	g, err := h.m.BreakGlass(h.ctx, admin, other.ID, time.Hour, "incident 77 - db down")
	if err != nil {
		t.Fatal(err)
	}
	if g.State != StateActive || !g.BreakGlass || g.ApprovedBy != "break-glass" {
		t.Fatalf("break-glass grant: %+v", g)
	}
	o, _ := h.m.Overview(h.ctx)
	if !strings.Contains(eventActions(o.Events), "break_glass") || o.ChainBroken != 0 {
		t.Fatalf("events: %s broken=%d", eventActions(o.Events), o.ChainBroken)
	}
	// Resources with live grants cannot be deleted.
	if err := h.m.DeleteResource(h.ctx, admin, other.ID); err == nil {
		t.Fatal("deleted a resource with an active grant")
	}
}

func TestRuleFailureRollsBackAndKeepsPending(t *testing.T) {
	h := newHarness(t)
	db := h.resource(t, "db", "10.1.0.5", KindL3)
	h.policy(t, "role:operator", db.ID, time.Hour, true, false)
	g, _ := h.m.Request(h.ctx, bob, db.ID, time.Hour, "needs approval", "")
	h.fw.fail = errors.New("nft said no")
	if _, err := h.m.Approve(h.ctx, carol, g.ID); err == nil {
		t.Fatal("approval succeeded despite rule failure")
	}
	got, _ := h.st.GetPAMGrant(h.ctx, g.ID)
	if got.State != StatePending {
		t.Fatalf("state after failed activation = %s, want pending", got.State)
	}
	if n := len(h.fw.byOwner(OwnerForGrant(g.ID))); n != 0 {
		t.Fatalf("partial rules left: %d", n)
	}
	h.fw.fail = nil
	if g2, err := h.m.Approve(h.ctx, carol, g.ID); err != nil || g2.State != StateActive {
		t.Fatalf("retry after fix: %+v %v", g2, err)
	}
}

type fakeBroker struct {
	activated   []string
	deactivated []string
	fail        error
}

func (b *fakeBroker) Activate(_ context.Context, g storage.PAMGrant, res storage.PAMResource) (string, error) {
	if b.fail != nil {
		return "", b.fail
	}
	ref := "conn-" + g.ID + "-" + res.Kind
	b.activated = append(b.activated, ref)
	return ref, nil
}
func (b *fakeBroker) Deactivate(_ context.Context, ref string) error {
	b.deactivated = append(b.deactivated, ref)
	return nil
}
func (b *fakeBroker) LaunchURL(ref string) string { return "https://guac/#/client/" + ref }

func TestBrokeredSSHGrant(t *testing.T) {
	h := newHarness(t)
	br := &fakeBroker{}
	h.m.opts.Broker = br
	bastion := h.resource(t, "bastion", "10.1.0.9", KindSSH)
	lan := h.resource(t, "lan", "10.2.0.0/24", KindL3)
	h.policy(t, "role:operator", bastion.ID, time.Hour, false, false)
	h.policy(t, "role:operator", lan.ID, time.Hour, false, false)

	g, err := h.m.Request(h.ctx, alice, bastion.ID, time.Hour, "deploy release", "")
	if err != nil {
		t.Fatal(err)
	}
	if g.BrokerRef == "" || len(br.activated) != 1 {
		t.Fatalf("ssh grant not brokered: %+v %v", g, br.activated)
	}
	if u := h.m.LaunchURL(g); !strings.HasSuffix(u, g.BrokerRef) {
		t.Fatalf("launch url = %q", u)
	}
	// L3 grants are not brokered.
	g2, err := h.m.Request(h.ctx, alice, lan.ID, time.Hour, "backup", "")
	if err != nil || g2.BrokerRef != "" || len(br.activated) != 1 {
		t.Fatalf("l3 grant brokered: %+v %v %v", g2, br.activated, err)
	}
	if _, err := h.m.Revoke(h.ctx, alice, g.ID, "done"); err != nil {
		t.Fatal(err)
	}
	if len(br.deactivated) != 1 || br.deactivated[0] != g.BrokerRef {
		t.Fatalf("broker not torn down: %v", br.deactivated)
	}
	// A broker failure is recorded but does not block the L3 grant.
	br.fail = errors.New("guacamole down")
	g3, err := h.m.Request(h.ctx, bob, bastion.ID, time.Hour, "hotfix", "")
	if err != nil || g3.State != StateActive || g3.BrokerRef != "" {
		t.Fatalf("broker failure blocked grant: %+v %v", g3, err)
	}
	o, _ := h.m.Overview(h.ctx)
	if !strings.Contains(eventActions(o.Events), "broker_failed") {
		t.Fatalf("broker_failed event missing: %s", eventActions(o.Events))
	}
}

func eventActions(evs []storage.AccessEvent) string {
	var parts []string
	for i := len(evs) - 1; i >= 0; i-- {
		parts = append(parts, evs[i].Action)
	}
	return strings.Join(parts, ",")
}
