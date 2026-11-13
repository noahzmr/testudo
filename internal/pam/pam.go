// Package pam is Testudo's privileged-access control plane: resources (what
// can be reached), policies (who may ask, on what terms), and grants - the
// just-in-time, time-boxed, approved permissions that are compiled into
// firewall rules for the requesting user's WireGuard peers and torn down,
// live connections included, when they end.
//
// The WireGuard tunnel is the transport, the firewall manager is the L3
// enforcement plane, the privileged helper's conntrack access kills sessions,
// and tcpdump records them. Every state transition is appended to a
// hash-chained access-event log.
package pam

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/auth"
	"github.com/noahzmr/testudo/internal/netops"
	"github.com/noahzmr/testudo/internal/storage"
)

// Resource kinds. l3 is a plain network reach; ssh / rdp / https additionally
// carry a broker reference used by the Guacamole / SSH-CA integrations.
const (
	KindL3    = "l3"
	KindSSH   = "ssh"
	KindRDP   = "rdp"
	KindHTTPS = "https"
)

// Grant states.
const (
	StatePending = "pending"
	StateActive  = "active"
	StateExpired = "expired"
	StateRevoked = "revoked"
	StateDenied  = "denied"
)

// Limits that are policy independent.
const (
	MaxBreakGlassTTL = 4 * time.Hour
	minJustification = 3
	breakGlassMinJus = 10
)

// Subject is the authenticated human making a request or decision.
type Subject struct {
	Name string
	Role auth.Role
	MFA  bool
}

// Store is the persistence the manager needs; *storage.Store satisfies it.
type Store interface {
	UpsertPAMResource(ctx context.Context, r storage.PAMResource) error
	DeletePAMResource(ctx context.Context, id string) error
	GetPAMResource(ctx context.Context, id string) (storage.PAMResource, error)
	ListPAMResources(ctx context.Context) ([]storage.PAMResource, error)
	UpsertPAMPolicy(ctx context.Context, p storage.PAMPolicy) error
	DeletePAMPolicy(ctx context.Context, id string) error
	ListPAMPolicies(ctx context.Context) ([]storage.PAMPolicy, error)
	UpsertPAMGrant(ctx context.Context, g storage.PAMGrant) error
	GetPAMGrant(ctx context.Context, id string) (storage.PAMGrant, error)
	ListPAMGrants(ctx context.Context, states []string, limit int) ([]storage.PAMGrant, error)
	AppendAccessEvent(ctx context.Context, e storage.AccessEvent) (storage.AccessEvent, error)
	ListAccessEvents(ctx context.Context, limit int) ([]storage.AccessEvent, error)
	VerifyAccessEvents(ctx context.Context) (checked int, broken int64, err error)
	WGPeerUsers(ctx context.Context) (map[string]string, error)
	SetWGPeerUser(ctx context.Context, pubkey, user string) error
}

// Enforcer is the firewall policy manager surface grants compile into.
type Enforcer interface {
	AddRule(netops.FilterRule) error
	DelRulesByOwner(owner string) (int, error)
}

// Flows lets the manager kill live connections when a grant ends. The query
// is filtered on the privileged side (peer sources → resource), so only the
// grant's own flows cross the privsep socket.
type Flows interface {
	ListConntrackQuery(netops.ConntrackQuery) (netops.ConntrackResult, error)
	FlushConntrack(netops.ConntrackFlow) error
}

// Capturer records a grant's traffic (metadata-level session recording).
// nil is allowed: grants then run without a capture.
type Capturer interface {
	Start(name, iface, bpf string) (id string, err error)
	Stop(id string) error
}

// PeerResolver maps a user to the tunnel addresses of their enrolled peers.
type PeerResolver interface {
	PeerIPs(ctx context.Context, user string) ([]string, error)
}

// Broker turns an ssh / rdp grant into a brokered session (Guacamole): the
// user never holds the target credential. Activation failures are recorded
// but do not block the L3 grant; nil disables brokering.
type Broker interface {
	Activate(ctx context.Context, g storage.PAMGrant, res storage.PAMResource) (ref string, err error)
	Deactivate(ctx context.Context, ref string) error
	LaunchURL(ref string) string
}

// Options configures a Manager.
type Options struct {
	Device       string // wg device grants are scoped to (iifname), e.g. "wg0"
	CaptureIface string // interface to capture on; defaults to Device
	Now          func() time.Time
	Broker       Broker
	// OnEvent is called (outside the lock) after every access event is stored.
	OnEvent func(storage.AccessEvent)
}

// Errors callers can match on.
var (
	ErrNotFound      = storage.ErrPAMNotFound
	ErrForbidden     = errors.New("pam: forbidden")
	ErrNoPolicy      = errors.New("pam: no policy allows this request")
	ErrState         = errors.New("pam: grant is not in a state that allows this")
	ErrNoPeer        = errors.New("pam: user has no WireGuard peer bound - bind one first")
	ErrSelfApproval  = errors.New("pam: requesters cannot approve their own grant")
	ErrJustification = errors.New("pam: a justification is required")
)

// Manager owns the grant lifecycle.
type Manager struct {
	mu    sync.Mutex
	store Store
	fw    Enforcer
	flows Flows
	cap   Capturer
	peers PeerResolver
	opts  Options
}

// New wires a manager. cap may be nil.
func New(store Store, fw Enforcer, flows Flows, cap Capturer, peers PeerResolver, opts Options) *Manager {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Device == "" {
		opts.Device = "wg0"
	}
	if opts.CaptureIface == "" {
		opts.CaptureIface = opts.Device
	}
	return &Manager{store: store, fw: fw, flows: flows, cap: cap, peers: peers, opts: opts}
}

// OwnerForGrant is the firewall ownership tag of a grant's rules.
func OwnerForGrant(id string) string { return "pam-grant:" + id }

// ---- resources & policies -------------------------------------------

// AddResource creates or updates a resource (admin).
func (m *Manager) AddResource(ctx context.Context, actor Subject, r storage.PAMResource) (storage.PAMResource, error) {
	if actor.Role != auth.RoleAdmin {
		return r, fmt.Errorf("%w: only admins manage resources", ErrForbidden)
	}
	r.Name = strings.TrimSpace(r.Name)
	r.Kind = strings.ToLower(strings.TrimSpace(r.Kind))
	r.CIDR = strings.TrimSpace(r.CIDR)
	r.Proto = strings.ToLower(strings.TrimSpace(r.Proto))
	if r.Name == "" {
		return r, errors.New("resource name required")
	}
	switch r.Kind {
	case KindL3, KindSSH, KindRDP, KindHTTPS:
	default:
		return r, fmt.Errorf("kind must be l3 / ssh / rdp / https, got %q", r.Kind)
	}
	if _, err := parsePrefix(r.CIDR); err != nil {
		return r, fmt.Errorf("cidr: %w", err)
	}
	switch r.Proto {
	case "", "tcp", "udp":
	default:
		return r, fmt.Errorf("proto must be tcp / udp / empty, got %q", r.Proto)
	}
	if r.PortLo != 0 && r.Proto == "" {
		return r, errors.New("a port requires proto tcp or udp")
	}
	if r.PortHi != 0 && (r.PortLo == 0 || r.PortHi < r.PortLo) {
		return r, errors.New("port_hi needs port_lo and must not be below it")
	}
	// Brokered kinds get a sensible default port so the rule is not wide open.
	if r.PortLo == 0 {
		switch r.Kind {
		case KindSSH:
			r.Proto, r.PortLo = "tcp", 22
		case KindRDP:
			r.Proto, r.PortLo = "tcp", 3389
		case KindHTTPS:
			r.Proto, r.PortLo = "tcp", 443
		}
	}
	if r.ID == "" {
		r.ID = newID("res")
	}
	if err := m.store.UpsertPAMResource(ctx, r); err != nil {
		return r, err
	}
	m.event(ctx, actor.Name, "resource_upsert", "", fmt.Sprintf("%s %s %s", r.ID, r.Name, r.CIDR))
	return r, nil
}

// DeleteResource removes a resource that no live grant references (admin).
func (m *Manager) DeleteResource(ctx context.Context, actor Subject, id string) error {
	if actor.Role != auth.RoleAdmin {
		return fmt.Errorf("%w: only admins manage resources", ErrForbidden)
	}
	live, err := m.store.ListPAMGrants(ctx, []string{StatePending, StateActive}, 1000)
	if err != nil {
		return err
	}
	for _, g := range live {
		if g.ResourceID == id {
			return fmt.Errorf("resource has a %s grant (%s); revoke it first", g.State, g.ID)
		}
	}
	if err := m.store.DeletePAMResource(ctx, id); err != nil {
		return err
	}
	m.event(ctx, actor.Name, "resource_delete", "", id)
	return nil
}

// AddPolicy creates or updates a policy (admin). Subject is "user:<name>" or
// "role:<role>" (the requester's role must be at least that role).
func (m *Manager) AddPolicy(ctx context.Context, actor Subject, p storage.PAMPolicy) (storage.PAMPolicy, error) {
	if actor.Role != auth.RoleAdmin {
		return p, fmt.Errorf("%w: only admins manage policies", ErrForbidden)
	}
	p.Name = strings.TrimSpace(p.Name)
	p.Subject = strings.TrimSpace(p.Subject)
	if p.Name == "" {
		return p, errors.New("policy name required")
	}
	if _, _, err := parseSubject(p.Subject); err != nil {
		return p, err
	}
	if _, err := m.store.GetPAMResource(ctx, p.ResourceID); err != nil {
		return p, fmt.Errorf("resource %q: %w", p.ResourceID, err)
	}
	if p.MaxTTL <= 0 {
		return p, errors.New("max_ttl_sec must be positive")
	}
	if p.ID == "" {
		p.ID = newID("pol")
	}
	if err := m.store.UpsertPAMPolicy(ctx, p); err != nil {
		return p, err
	}
	m.event(ctx, actor.Name, "policy_upsert", "", fmt.Sprintf("%s %s %s -> %s", p.ID, p.Name, p.Subject, p.ResourceID))
	return p, nil
}

// DeletePolicy removes a policy (admin). Existing grants keep running.
func (m *Manager) DeletePolicy(ctx context.Context, actor Subject, id string) error {
	if actor.Role != auth.RoleAdmin {
		return fmt.Errorf("%w: only admins manage policies", ErrForbidden)
	}
	if err := m.store.DeletePAMPolicy(ctx, id); err != nil {
		return err
	}
	m.event(ctx, actor.Name, "policy_delete", "", id)
	return nil
}

// BindPeer ties a WireGuard peer to a user (admin). Grants for the user
// compile to the peer's tunnel addresses.
func (m *Manager) BindPeer(ctx context.Context, actor Subject, pubkey, user string) error {
	if actor.Role != auth.RoleAdmin {
		return fmt.Errorf("%w: only admins bind peers", ErrForbidden)
	}
	pubkey, user = strings.TrimSpace(pubkey), strings.TrimSpace(user)
	if pubkey == "" {
		return errors.New("peer public key required")
	}
	if err := m.store.SetWGPeerUser(ctx, pubkey, user); err != nil {
		return err
	}
	m.event(ctx, actor.Name, "peer_bind", "", fmt.Sprintf("%s -> %q", shortKey(pubkey), user))
	return nil
}

// parseSubject splits "user:alice" / "role:operator".
func parseSubject(s string) (kind, value string, err error) {
	kind, value, ok := strings.Cut(s, ":")
	if !ok || value == "" {
		return "", "", fmt.Errorf("subject must be user:<name> or role:<role>, got %q", s)
	}
	switch kind {
	case "user":
	case "role":
		if !auth.Role(value).Valid() {
			return "", "", fmt.Errorf("unknown role %q in subject", value)
		}
	default:
		return "", "", fmt.Errorf("subject must be user:<name> or role:<role>, got %q", s)
	}
	return kind, value, nil
}

// policyMatches reports whether p lets subj request.
func policyMatches(p storage.PAMPolicy, subj Subject) bool {
	kind, value, err := parseSubject(p.Subject)
	if err != nil {
		return false
	}
	switch kind {
	case "user":
		return value == subj.Name
	case "role":
		return subj.Role.AtLeast(auth.Role(value))
	}
	return false
}

// ---- grant lifecycle -------------------------------------------------

// Request asks for access. It picks the most generous policy that matches
// the subject and the resource; without approval the grant activates
// immediately, otherwise it waits for an approver.
func (m *Manager) Request(ctx context.Context, subj Subject, resourceID string, ttl time.Duration, justification, ticket string) (storage.PAMGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	justification = strings.TrimSpace(justification)
	if len(justification) < minJustification {
		return storage.PAMGrant{}, ErrJustification
	}
	res, err := m.store.GetPAMResource(ctx, resourceID)
	if err != nil {
		return storage.PAMGrant{}, fmt.Errorf("resource: %w", err)
	}
	pols, err := m.store.ListPAMPolicies(ctx)
	if err != nil {
		return storage.PAMGrant{}, err
	}
	var best *storage.PAMPolicy
	var maxSeen time.Duration
	for i := range pols {
		p := pols[i]
		if p.ResourceID != res.ID || !policyMatches(p, subj) {
			continue
		}
		pmax := time.Duration(p.MaxTTL) * time.Second
		if pmax > maxSeen {
			maxSeen = pmax
		}
		if ttl > pmax {
			continue
		}
		// Prefer the policy that needs the least ceremony, then the longest TTL.
		if best == nil || (best.RequiresApproval && !p.RequiresApproval) ||
			(best.RequiresApproval == p.RequiresApproval && p.MaxTTL > best.MaxTTL) {
			best = &p
		}
	}
	if best == nil {
		if maxSeen > 0 {
			return storage.PAMGrant{}, fmt.Errorf("%w for %s (max TTL for you is %s)", ErrNoPolicy, ttl, maxSeen)
		}
		return storage.PAMGrant{}, fmt.Errorf("%w: %s may not request %s", ErrNoPolicy, subj.Name, res.Name)
	}
	if ttl <= 0 {
		return storage.PAMGrant{}, errors.New("ttl must be positive")
	}
	if best.RequiresMFA && !subj.MFA {
		return storage.PAMGrant{}, fmt.Errorf("%w: resource %s requires MFA - enroll an authenticator first", ErrForbidden, res.Name)
	}
	now := m.opts.Now()
	g := storage.PAMGrant{
		ID: newID("grant"), User: subj.Name, ResourceID: res.ID, PolicyID: best.ID,
		State: StatePending, Justification: justification, Ticket: strings.TrimSpace(ticket),
		TTL: int64(ttl.Seconds()), RequestedAt: now,
	}
	if err := m.store.UpsertPAMGrant(ctx, g); err != nil {
		return g, err
	}
	m.event(ctx, subj.Name, "requested", g.ID, fmt.Sprintf("%s for %s (%s): %s", res.Name, ttl, best.Name, justification))
	if !best.RequiresApproval {
		g.ApprovedBy, g.DecidedAt = "policy:"+best.Name, now
		if err := m.activateLocked(ctx, &g, res); err != nil {
			return g, err
		}
	}
	return g, nil
}

// Approve activates a pending grant. Approvers and admins may approve; nobody
// may approve their own request (separation of duties).
func (m *Manager) Approve(ctx context.Context, approver Subject, grantID string) (storage.PAMGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !approver.Role.CanApprove() {
		return storage.PAMGrant{}, fmt.Errorf("%w: role %s cannot approve", ErrForbidden, approver.Role)
	}
	g, err := m.store.GetPAMGrant(ctx, grantID)
	if err != nil {
		return g, err
	}
	if g.State != StatePending {
		return g, fmt.Errorf("%w (%s)", ErrState, g.State)
	}
	if g.User == approver.Name {
		return g, ErrSelfApproval
	}
	res, err := m.store.GetPAMResource(ctx, g.ResourceID)
	if err != nil {
		return g, fmt.Errorf("resource: %w", err)
	}
	g.ApprovedBy, g.DecidedAt = approver.Name, m.opts.Now()
	m.event(ctx, approver.Name, "approved", g.ID, fmt.Sprintf("%s for %s", g.User, res.Name))
	if err := m.activateLocked(ctx, &g, res); err != nil {
		return g, err
	}
	return g, nil
}

// Deny rejects a pending grant.
func (m *Manager) Deny(ctx context.Context, approver Subject, grantID, reason string) (storage.PAMGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !approver.Role.CanApprove() {
		return storage.PAMGrant{}, fmt.Errorf("%w: role %s cannot deny", ErrForbidden, approver.Role)
	}
	g, err := m.store.GetPAMGrant(ctx, grantID)
	if err != nil {
		return g, err
	}
	if g.State != StatePending {
		return g, fmt.Errorf("%w (%s)", ErrState, g.State)
	}
	now := m.opts.Now()
	g.State, g.ApprovedBy, g.DecidedAt, g.EndedAt, g.EndReason = StateDenied, approver.Name, now, now, strings.TrimSpace(reason)
	if err := m.store.UpsertPAMGrant(ctx, g); err != nil {
		return g, err
	}
	m.event(ctx, approver.Name, "denied", g.ID, reason)
	return g, nil
}

// Revoke ends an active grant (or withdraws a pending one). The requester,
// approvers and admins may revoke.
func (m *Manager) Revoke(ctx context.Context, actor Subject, grantID, reason string) (storage.PAMGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, err := m.store.GetPAMGrant(ctx, grantID)
	if err != nil {
		return g, err
	}
	if actor.Name != g.User && !actor.Role.CanApprove() {
		return g, fmt.Errorf("%w: only the requester, approvers or admins may revoke", ErrForbidden)
	}
	switch g.State {
	case StateActive:
		return g, m.deactivateLocked(ctx, &g, StateRevoked, firstNonEmpty(strings.TrimSpace(reason), "revoked by "+actor.Name), actor.Name)
	case StatePending:
		now := m.opts.Now()
		g.State, g.EndedAt, g.EndReason = StateRevoked, now, firstNonEmpty(strings.TrimSpace(reason), "withdrawn")
		if err := m.store.UpsertPAMGrant(ctx, g); err != nil {
			return g, err
		}
		m.event(ctx, actor.Name, "withdrawn", g.ID, g.EndReason)
		return g, nil
	}
	return g, fmt.Errorf("%w (%s)", ErrState, g.State)
}

// BreakGlass is the admin's emergency bypass: immediate access without a
// policy or approval, capped at MaxBreakGlassTTL, loudly recorded.
func (m *Manager) BreakGlass(ctx context.Context, admin Subject, resourceID string, ttl time.Duration, justification string) (storage.PAMGrant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if admin.Role != auth.RoleAdmin {
		return storage.PAMGrant{}, fmt.Errorf("%w: break-glass is admin only", ErrForbidden)
	}
	justification = strings.TrimSpace(justification)
	if len(justification) < breakGlassMinJus {
		return storage.PAMGrant{}, fmt.Errorf("%w: break-glass needs a real justification (>= %d characters)", ErrJustification, breakGlassMinJus)
	}
	if ttl <= 0 || ttl > MaxBreakGlassTTL {
		return storage.PAMGrant{}, fmt.Errorf("break-glass TTL must be between 1s and %s", MaxBreakGlassTTL)
	}
	res, err := m.store.GetPAMResource(ctx, resourceID)
	if err != nil {
		return storage.PAMGrant{}, fmt.Errorf("resource: %w", err)
	}
	now := m.opts.Now()
	g := storage.PAMGrant{
		ID: newID("grant"), User: admin.Name, ResourceID: res.ID, State: StatePending,
		Justification: justification, TTL: int64(ttl.Seconds()), RequestedAt: now,
		ApprovedBy: "break-glass", DecidedAt: now, BreakGlass: true,
	}
	if err := m.store.UpsertPAMGrant(ctx, g); err != nil {
		return g, err
	}
	m.event(ctx, admin.Name, "break_glass", g.ID, fmt.Sprintf("%s for %s: %s", res.Name, ttl, justification))
	if err := m.activateLocked(ctx, &g, res); err != nil {
		return g, err
	}
	return g, nil
}

// activateLocked compiles the grant into firewall rules for the user's peer
// addresses, starts the capture, and marks it active. On a rule failure every
// rule already added is removed and the grant stays pending (approval is not
// lost; the approver sees the error). Caller holds mu.
func (m *Manager) activateLocked(ctx context.Context, g *storage.PAMGrant, res storage.PAMResource) error {
	ips, err := m.peers.PeerIPs(ctx, g.User)
	if err != nil {
		return fmt.Errorf("resolve peers: %w", err)
	}
	if len(ips) == 0 {
		m.event(ctx, g.User, "activation_failed", g.ID, "no WireGuard peer bound to user")
		return ErrNoPeer
	}
	sort.Strings(ips)
	owner := OwnerForGrant(g.ID)
	for _, ip := range ips {
		rule := netops.FilterRule{
			Chain: "forward", Action: "accept", InIface: m.opts.Device,
			SrcCIDR: hostCIDR(ip), DstCIDR: res.CIDR, Proto: res.Proto, Port: res.PortLo, PortEnd: res.PortHi,
			Owner:   owner,
			Comment: fmt.Sprintf("pam %s %s -> %s", g.ID, g.User, res.Name),
		}
		if err := m.fw.AddRule(rule); err != nil {
			_, _ = m.fw.DelRulesByOwner(owner)
			m.event(ctx, g.User, "activation_failed", g.ID, err.Error())
			return fmt.Errorf("install access rule: %w", err)
		}
	}
	now := m.opts.Now()
	g.PeerIPs = ips
	g.StartsAt = now
	g.EndsAt = now.Add(time.Duration(g.TTL) * time.Second)
	g.State = StateActive
	if m.cap != nil {
		bpf := captureFilter(ips, res.CIDR)
		if id, err := m.cap.Start("pam-"+g.ID, m.opts.CaptureIface, bpf); err != nil {
			m.event(ctx, g.User, "capture_failed", g.ID, err.Error())
		} else {
			g.CaptureID = id
		}
	}
	brokered := ""
	if m.opts.Broker != nil && (res.Kind == KindSSH || res.Kind == KindRDP) {
		if ref, err := m.opts.Broker.Activate(ctx, *g, res); err != nil {
			m.event(ctx, g.User, "broker_failed", g.ID, err.Error())
		} else {
			g.BrokerRef = ref
			brokered = "; brokered session " + ref
		}
	}
	if err := m.store.UpsertPAMGrant(ctx, *g); err != nil {
		_, _ = m.fw.DelRulesByOwner(owner)
		if g.BrokerRef != "" {
			_ = m.opts.Broker.Deactivate(ctx, g.BrokerRef)
		}
		return err
	}
	m.event(ctx, g.User, "activated", g.ID, fmt.Sprintf("%s via %s until %s (peers %s)%s",
		res.Name, m.opts.Device, g.EndsAt.UTC().Format(time.RFC3339), strings.Join(ips, ","), brokered))
	return nil
}

// LaunchURL returns the brokered session's deep link for an active grant, or
// "" when the grant is not brokered.
func (m *Manager) LaunchURL(g storage.PAMGrant) string {
	if m.opts.Broker == nil || g.BrokerRef == "" || g.State != StateActive {
		return ""
	}
	return m.opts.Broker.LaunchURL(g.BrokerRef)
}

// deactivateLocked removes the grant's rules, kills live flows between the
// peers and the resource, stops the capture, and records the end. Caller
// holds mu.
func (m *Manager) deactivateLocked(ctx context.Context, g *storage.PAMGrant, state, reason, actor string) error {
	owner := OwnerForGrant(g.ID)
	removed, err := m.fw.DelRulesByOwner(owner)
	if err != nil {
		return fmt.Errorf("remove access rules: %w", err)
	}
	killed := 0
	if res, rerr := m.store.GetPAMResource(ctx, g.ResourceID); rerr == nil {
		killed = m.killFlows(g.PeerIPs, res.CIDR)
	}
	if m.cap != nil && g.CaptureID != "" {
		if err := m.cap.Stop(g.CaptureID); err != nil {
			log.Printf("pam: stop capture %s: %v", g.CaptureID, err)
		}
	}
	if m.opts.Broker != nil && g.BrokerRef != "" {
		if err := m.opts.Broker.Deactivate(ctx, g.BrokerRef); err != nil {
			// The L3 path is already closed; report, do not block the state change.
			m.event(ctx, actor, "broker_teardown_failed", g.ID, err.Error())
		}
	}
	g.State = state
	g.EndedAt = m.opts.Now()
	g.EndReason = reason
	if err := m.store.UpsertPAMGrant(ctx, *g); err != nil {
		return err
	}
	m.event(ctx, actor, state, g.ID, fmt.Sprintf("%s; %d rule(s) removed, %d live flow(s) killed", reason, removed, killed))
	return nil
}

// killFlows flushes every conntrack entry from one of the peer addresses to
// the resource, so an established SSH/RDP session does not outlive the grant.
func (m *Manager) killFlows(peerIPs []string, resourceCIDR string) int {
	if m.flows == nil {
		return 0
	}
	dst, err := parsePrefix(resourceCIDR)
	if err != nil {
		return 0
	}
	peers := map[string]bool{}
	var srcs []string
	for _, ip := range peerIPs {
		if a, err := parseAddr(ip); err == nil {
			peers[a.String()] = true
			srcs = append(srcs, a.String())
		}
	}
	res, err := m.flows.ListConntrackQuery(netops.ConntrackQuery{SrcIPs: srcs, DstCIDR: dst.String()})
	if err != nil {
		log.Printf("pam: list conntrack: %v", err)
		return 0
	}
	n := 0
	// Re-check locally too: a backend that ignores the filter must not make
	// us flush someone else's flows.
	for _, f := range res.Flows {
		src, err := parseAddr(f.OrigSrc)
		if err != nil || !peers[src.String()] {
			continue
		}
		d, err := parseAddr(f.OrigDst)
		if err != nil || !dst.Contains(d) {
			continue
		}
		if err := m.flows.FlushConntrack(f); err == nil {
			n++
		}
	}
	return n
}

// Expire ends every active grant whose window has passed. Returns how many.
func (m *Manager) Expire(ctx context.Context) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	active, err := m.store.ListPAMGrants(ctx, []string{StateActive}, 1000)
	if err != nil {
		log.Printf("pam: list active grants: %v", err)
		return 0
	}
	now := m.opts.Now()
	n := 0
	for i := range active {
		g := active[i]
		if !g.EndsAt.IsZero() && !now.Before(g.EndsAt) {
			if err := m.deactivateLocked(ctx, &g, StateExpired, "ttl elapsed", "system"); err != nil {
				log.Printf("pam: expire %s: %v", g.ID, err)
				continue
			}
			n++
		}
	}
	return n
}

// Observe samples conntrack for every active grant and records how many
// flows / bytes were seen between its peers and its resource.
func (m *Manager) Observe(ctx context.Context) {
	if m.flows == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	active, err := m.store.ListPAMGrants(ctx, []string{StateActive}, 1000)
	if err != nil || len(active) == 0 {
		return
	}
	for i := range active {
		g := active[i]
		res, err := m.store.GetPAMResource(ctx, g.ResourceID)
		if err != nil {
			continue
		}
		dst, err := parsePrefix(res.CIDR)
		if err != nil {
			continue
		}
		peers := map[string]bool{}
		var srcs []string
		for _, ip := range g.PeerIPs {
			if a, err := parseAddr(ip); err == nil {
				peers[a.String()] = true
				srcs = append(srcs, a.String())
			}
		}
		ctr, err := m.flows.ListConntrackQuery(netops.ConntrackQuery{SrcIPs: srcs, DstCIDR: dst.String()})
		if err != nil {
			return
		}
		var n, bytes uint64
		for _, f := range ctr.Flows {
			src, err := parseAddr(f.OrigSrc)
			if err != nil || !peers[src.String()] {
				continue
			}
			d, err := parseAddr(f.OrigDst)
			if err != nil || !dst.Contains(d) {
				continue
			}
			n++
			bytes += f.Bytes
		}
		if n > g.ObservedFlows || bytes > g.ObservedBytes {
			g.ObservedFlows, g.ObservedBytes = max(n, g.ObservedFlows), max(bytes, g.ObservedBytes)
			_ = m.store.UpsertPAMGrant(ctx, g)
		}
	}
}

// Run expires overdue grants at boot (the firewall reconciler already
// re-installed rules for the ones still valid) and then ticks.
func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if n := m.Expire(ctx); n > 0 {
		log.Printf("pam: expired %d grant(s) at boot", n)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Expire(ctx)
			m.Observe(ctx)
		}
	}
}

// ---- views -----------------------------------------------------------

// Overview is what the UIs render.
type Overview struct {
	Resources    []storage.PAMResource `json:"resources"`
	Policies     []storage.PAMPolicy   `json:"policies"`
	Grants       []storage.PAMGrant    `json:"grants"`
	Events       []storage.AccessEvent `json:"events"`
	ChainChecked int                   `json:"chain_checked"`
	ChainBroken  int64                 `json:"chain_broken_at"` // 0 = intact
	Device       string                `json:"device"`
	PeerUsers    map[string]string     `json:"peer_users"` // pubkey -> user
}

// Overview returns resources, policies, recent grants and events plus a chain
// verification.
func (m *Manager) Overview(ctx context.Context) (Overview, error) {
	var o Overview
	var err error
	if o.Resources, err = m.store.ListPAMResources(ctx); err != nil {
		return o, err
	}
	if o.Policies, err = m.store.ListPAMPolicies(ctx); err != nil {
		return o, err
	}
	if o.Grants, err = m.store.ListPAMGrants(ctx, nil, 200); err != nil {
		return o, err
	}
	if o.Events, err = m.store.ListAccessEvents(ctx, 200); err != nil {
		return o, err
	}
	o.ChainChecked, o.ChainBroken, _ = m.store.VerifyAccessEvents(ctx)
	o.PeerUsers, _ = m.store.WGPeerUsers(ctx)
	o.Device = m.opts.Device
	return o, nil
}

// ---- helpers ---------------------------------------------------------

func (m *Manager) event(ctx context.Context, actor, action, grantID, detail string) {
	ev, err := m.store.AppendAccessEvent(ctx, storage.AccessEvent{
		TS: m.opts.Now(), Actor: actor, Action: action, GrantID: grantID, Detail: detail,
	})
	if err != nil {
		log.Printf("pam: record access event %s: %v", action, err)
		return
	}
	if m.opts.OnEvent != nil {
		go m.opts.OnEvent(ev)
	}
}

// captureFilter builds the BPF for a grant: traffic between any of the peer
// addresses and the resource network.
func captureFilter(peerIPs []string, resourceCIDR string) string {
	hosts := make([]string, 0, len(peerIPs))
	for _, ip := range peerIPs {
		if a, err := parseAddr(ip); err == nil {
			hosts = append(hosts, "host "+a.String())
		}
	}
	if len(hosts) == 0 {
		return ""
	}
	target := "net " + resourceCIDR
	if p, err := parsePrefix(resourceCIDR); err == nil && p.IsSingleIP() {
		target = "host " + p.Addr().String()
	}
	return "(" + strings.Join(hosts, " or ") + ") and " + target
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("not an address or CIDR: %q", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func parseAddr(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, err
	}
	return a.Unmap(), nil
}

func hostCIDR(s string) string {
	if strings.Contains(s, "/") {
		return s
	}
	if ip := net.ParseIP(s); ip != nil && ip.To4() == nil {
		return s + "/128"
	}
	return s + "/32"
}

func newID(prefix string) string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return prefix + "-" + hex.EncodeToString(b[:])
}

func shortKey(k string) string {
	if len(k) <= 10 {
		return k
	}
	return k[:10] + "…"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
