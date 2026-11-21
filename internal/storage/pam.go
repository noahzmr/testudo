package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// pamSchema holds the privileged-access tables: what may be reached
// (resources), who may ask for it and on what terms (policies), the grants
// themselves, and the tamper-evident access-event log. None of these tables
// ever hold credentials - a resource's broker_ref is an identifier inside
// Guacamole or the SSH CA, never a password or key.
const pamSchema = `
CREATE TABLE IF NOT EXISTS pam_resources (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    kind       TEXT NOT NULL,                 -- l3 | ssh | rdp | https
    cidr       TEXT NOT NULL,                 -- target address or network
    proto      TEXT NOT NULL DEFAULT '',      -- '' (any) | tcp | udp
    port_lo    INTEGER NOT NULL DEFAULT 0,
    port_hi    INTEGER NOT NULL DEFAULT 0,
    login      TEXT NOT NULL DEFAULT '',      -- ssh principal / rdp user the broker uses
    broker_ref TEXT NOT NULL DEFAULT '',      -- guacamole connection id, ssh ca profile
    notes      TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pam_policies (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    subject           TEXT NOT NULL,          -- 'user:<name>' or 'role:<role>' (min role)
    resource_id       TEXT NOT NULL,
    max_ttl_sec       INTEGER NOT NULL,
    requires_approval INTEGER NOT NULL DEFAULT 1,
    requires_mfa      INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pam_grants (
    id             TEXT PRIMARY KEY,
    user           TEXT NOT NULL,
    resource_id    TEXT NOT NULL,
    policy_id      TEXT NOT NULL DEFAULT '',
    state          TEXT NOT NULL,             -- pending | active | expired | revoked | denied
    justification  TEXT NOT NULL DEFAULT '',
    ticket         TEXT NOT NULL DEFAULT '',
    ttl_sec        INTEGER NOT NULL,
    requested_at   INTEGER NOT NULL,
    approved_by    TEXT NOT NULL DEFAULT '',
    decided_at     INTEGER NOT NULL DEFAULT 0,
    starts_at      INTEGER NOT NULL DEFAULT 0,
    ends_at        INTEGER NOT NULL DEFAULT 0,
    ended_at       INTEGER NOT NULL DEFAULT 0,
    end_reason     TEXT NOT NULL DEFAULT '',
    peer_ips       TEXT NOT NULL DEFAULT '',  -- comma-separated peer addresses the grant was compiled for
    capture_id     TEXT NOT NULL DEFAULT '',
    broker_ref     TEXT NOT NULL DEFAULT '',  -- per-grant broker artifact (guacamole connection id)
    observed_flows INTEGER NOT NULL DEFAULT 0,
    observed_bytes INTEGER NOT NULL DEFAULT 0,
    break_glass    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_pam_grants_state ON pam_grants(state, ends_at);
CREATE INDEX IF NOT EXISTS idx_pam_grants_user ON pam_grants(user, requested_at);
-- access_events is a hash chain: hash = sha256(prev_hash | ts | actor | action | grant_id | detail).
-- VerifyAccessEvents walks it; a rewritten or deleted row breaks every hash after it.
CREATE TABLE IF NOT EXISTS access_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    grant_id  TEXT NOT NULL DEFAULT '',
    detail    TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
`

// ErrPAMNotFound is returned for an unknown resource / policy / grant id.
var ErrPAMNotFound = errors.New("not found")

// accessMu serialises hash-chain appends across goroutines in this process.
// SQLite's write lock serialises processes; this keeps prev_hash reads and the
// insert atomic within one.
var accessMu sync.Mutex

// PAMResource is something a grant can reach.
type PAMResource struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	CIDR      string    `json:"cidr"`
	Proto     string    `json:"proto"`
	PortLo    uint16    `json:"port_lo"`
	PortHi    uint16    `json:"port_hi"`
	Login     string    `json:"login"`
	BrokerRef string    `json:"broker_ref"`
	Notes     string    `json:"notes"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// PAMPolicy says which subject may request which resource and on what terms.
type PAMPolicy struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Subject          string    `json:"subject"`
	ResourceID       string    `json:"resource_id"`
	MaxTTL           int64     `json:"max_ttl_sec"`
	RequiresApproval bool      `json:"requires_approval"`
	RequiresMFA      bool      `json:"requires_mfa"`
	CreatedAt        time.Time `json:"created_at"`
}

// PAMGrant is one request for access and its whole lifecycle.
type PAMGrant struct {
	ID            string    `json:"id"`
	User          string    `json:"user"`
	ResourceID    string    `json:"resource_id"`
	PolicyID      string    `json:"policy_id"`
	State         string    `json:"state"`
	Justification string    `json:"justification"`
	Ticket        string    `json:"ticket"`
	TTL           int64     `json:"ttl_sec"`
	RequestedAt   time.Time `json:"requested_at"`
	ApprovedBy    string    `json:"approved_by"`
	DecidedAt     time.Time `json:"decided_at"`
	StartsAt      time.Time `json:"starts_at"`
	EndsAt        time.Time `json:"ends_at"`
	EndedAt       time.Time `json:"ended_at"`
	EndReason     string    `json:"end_reason"`
	PeerIPs       []string  `json:"peer_ips"`
	CaptureID     string    `json:"capture_id"`
	BrokerRef     string    `json:"broker_ref"`
	ObservedFlows uint64    `json:"observed_flows"`
	ObservedBytes uint64    `json:"observed_bytes"`
	BreakGlass    bool      `json:"break_glass"`
}

// AccessEvent is one hash-chained row of the access log.
type AccessEvent struct {
	ID       int64     `json:"id"`
	TS       time.Time `json:"ts"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	GrantID  string    `json:"grant_id"`
	Detail   string    `json:"detail"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
	// Member names the cluster member whose log holds the event; it is not
	// stored, only set where the logs of several members are shown.
	Member string `json:"member,omitempty"`
}

// ChainStatus is the outcome of checking one member's access-log chain.
type ChainStatus struct {
	Member   string `json:"member"`
	Checked  int    `json:"checked"`
	BrokenAt int64  `json:"broken_at,omitempty"` // 0 = intact
	Error    string `json:"error,omitempty"`     // the check could not be made
}

// ---- resources -------------------------------------------------------

func (s *Store) UpsertPAMResource(ctx context.Context, r PAMResource) error {
	now := time.Now()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pam_resources (id, name, kind, cidr, proto, port_lo, port_hi, login, broker_ref, notes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, kind=excluded.kind, cidr=excluded.cidr,
		  proto=excluded.proto, port_lo=excluded.port_lo, port_hi=excluded.port_hi, login=excluded.login,
		  broker_ref=excluded.broker_ref, notes=excluded.notes, updated_at=excluded.updated_at`,
		r.ID, r.Name, r.Kind, r.CIDR, r.Proto, int(r.PortLo), int(r.PortHi), r.Login, r.BrokerRef, r.Notes,
		r.CreatedAt.UnixMilli(), now.UnixMilli())
	return err
}

func (s *Store) DeletePAMResource(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM pam_resources WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrPAMNotFound
	}
	return nil
}

func (s *Store) GetPAMResource(ctx context.Context, id string) (PAMResource, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, kind, cidr, proto, port_lo, port_hi, login, broker_ref, notes, created_at, updated_at
		FROM pam_resources WHERE id = ?`, id)
	if err != nil {
		return PAMResource{}, err
	}
	defer rows.Close()
	out, err := scanResources(rows)
	if err != nil {
		return PAMResource{}, err
	}
	if len(out) == 0 {
		return PAMResource{}, ErrPAMNotFound
	}
	return out[0], nil
}

func (s *Store) ListPAMResources(ctx context.Context) ([]PAMResource, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, kind, cidr, proto, port_lo, port_hi, login, broker_ref, notes, created_at, updated_at
		FROM pam_resources ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanResources(rows)
}

func scanResources(rows *sql.Rows) ([]PAMResource, error) {
	var out []PAMResource
	for rows.Next() {
		var r PAMResource
		var lo, hi int
		var c, u int64
		if err := rows.Scan(&r.ID, &r.Name, &r.Kind, &r.CIDR, &r.Proto, &lo, &hi, &r.Login, &r.BrokerRef, &r.Notes, &c, &u); err != nil {
			return nil, err
		}
		r.PortLo, r.PortHi = uint16(lo), uint16(hi)
		r.CreatedAt, r.UpdatedAt = time.UnixMilli(c), time.UnixMilli(u)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- policies --------------------------------------------------------

func (s *Store) UpsertPAMPolicy(ctx context.Context, p PAMPolicy) error {
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pam_policies (id, name, subject, resource_id, max_ttl_sec, requires_approval, requires_mfa, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, subject=excluded.subject, resource_id=excluded.resource_id,
		  max_ttl_sec=excluded.max_ttl_sec, requires_approval=excluded.requires_approval, requires_mfa=excluded.requires_mfa`,
		p.ID, p.Name, p.Subject, p.ResourceID, p.MaxTTL, boolInt(p.RequiresApproval), boolInt(p.RequiresMFA), p.CreatedAt.UnixMilli())
	return err
}

func (s *Store) DeletePAMPolicy(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM pam_policies WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrPAMNotFound
	}
	return nil
}

func (s *Store) ListPAMPolicies(ctx context.Context) ([]PAMPolicy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, subject, resource_id, max_ttl_sec, requires_approval, requires_mfa, created_at
		FROM pam_policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PAMPolicy
	for rows.Next() {
		var p PAMPolicy
		var appr, mfa int
		var c int64
		if err := rows.Scan(&p.ID, &p.Name, &p.Subject, &p.ResourceID, &p.MaxTTL, &appr, &mfa, &c); err != nil {
			return nil, err
		}
		p.RequiresApproval, p.RequiresMFA = appr != 0, mfa != 0
		p.CreatedAt = time.UnixMilli(c)
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---- grants ----------------------------------------------------------

const grantCols = `id, user, resource_id, policy_id, state, justification, ticket, ttl_sec, requested_at, approved_by,
	decided_at, starts_at, ends_at, ended_at, end_reason, peer_ips, capture_id, broker_ref, observed_flows, observed_bytes, break_glass`

func (s *Store) UpsertPAMGrant(ctx context.Context, g PAMGrant) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO pam_grants (`+grantCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET state=excluded.state, approved_by=excluded.approved_by, decided_at=excluded.decided_at,
		  starts_at=excluded.starts_at, ends_at=excluded.ends_at, ended_at=excluded.ended_at, end_reason=excluded.end_reason,
		  peer_ips=excluded.peer_ips, capture_id=excluded.capture_id, broker_ref=excluded.broker_ref,
		  observed_flows=excluded.observed_flows, observed_bytes=excluded.observed_bytes`,
		g.ID, g.User, g.ResourceID, g.PolicyID, g.State, g.Justification, g.Ticket, g.TTL,
		ms(g.RequestedAt), g.ApprovedBy, ms(g.DecidedAt), ms(g.StartsAt), ms(g.EndsAt), ms(g.EndedAt), g.EndReason,
		strings.Join(g.PeerIPs, ","), g.CaptureID, g.BrokerRef, int64(g.ObservedFlows), int64(g.ObservedBytes), boolInt(g.BreakGlass))
	return err
}

func (s *Store) GetPAMGrant(ctx context.Context, id string) (PAMGrant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+grantCols+` FROM pam_grants WHERE id = ?`, id)
	if err != nil {
		return PAMGrant{}, err
	}
	defer rows.Close()
	out, err := scanGrants(rows)
	if err != nil {
		return PAMGrant{}, err
	}
	if len(out) == 0 {
		return PAMGrant{}, ErrPAMNotFound
	}
	return out[0], nil
}

// ListPAMGrants returns grants newest first; states filters when non-empty.
func (s *Store) ListPAMGrants(ctx context.Context, states []string, limit int) ([]PAMGrant, error) {
	if limit <= 0 {
		limit = 200
	}
	q := `SELECT ` + grantCols + ` FROM pam_grants`
	var args []any
	if len(states) > 0 {
		q += ` WHERE state IN (?` + strings.Repeat(",?", len(states)-1) + `)`
		for _, st := range states {
			args = append(args, st)
		}
	}
	q += ` ORDER BY requested_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGrants(rows)
}

func scanGrants(rows *sql.Rows) ([]PAMGrant, error) {
	var out []PAMGrant
	for rows.Next() {
		var g PAMGrant
		var req, dec, st, en, ended int64
		var peers string
		var flows, bytes int64
		var bg int
		if err := rows.Scan(&g.ID, &g.User, &g.ResourceID, &g.PolicyID, &g.State, &g.Justification, &g.Ticket, &g.TTL,
			&req, &g.ApprovedBy, &dec, &st, &en, &ended, &g.EndReason, &peers, &g.CaptureID, &g.BrokerRef, &flows, &bytes, &bg); err != nil {
			return nil, err
		}
		g.RequestedAt, g.DecidedAt, g.StartsAt, g.EndsAt, g.EndedAt = fromMS(req), fromMS(dec), fromMS(st), fromMS(en), fromMS(ended)
		if peers != "" {
			g.PeerIPs = strings.Split(peers, ",")
		}
		g.ObservedFlows, g.ObservedBytes = uint64(flows), uint64(bytes)
		g.BreakGlass = bg != 0
		out = append(out, g)
	}
	return out, rows.Err()
}

// ---- access events (hash chain) ---------------------------------------

// AppendAccessEvent links a new event to the chain and stores it. The hash
// covers the previous hash, so any later edit or deletion is detectable.
func (s *Store) AppendAccessEvent(ctx context.Context, e AccessEvent) (AccessEvent, error) {
	accessMu.Lock()
	defer accessMu.Unlock()
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	var prev string
	err := s.db.QueryRowContext(ctx, `SELECT hash FROM access_events ORDER BY id DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return e, err
	}
	e.PrevHash = prev
	e.Hash = accessEventHash(e)
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO access_events (ts, actor, action, grant_id, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.TS.UnixMilli(), e.Actor, e.Action, e.GrantID, e.Detail, e.PrevHash, e.Hash)
	if err != nil {
		return e, err
	}
	e.ID, _ = res.LastInsertId()
	return e, nil
}

// accessEventHash is the chain function. Millisecond timestamps keep it
// reproducible from the stored row.
func accessEventHash(e AccessEvent) string {
	h := sha256.New()
	h.Write([]byte(e.PrevHash))
	h.Write([]byte{0})
	fmt.Fprintf(h, "%d", e.TS.UnixMilli())
	h.Write([]byte{0})
	h.Write([]byte(e.Actor))
	h.Write([]byte{0})
	h.Write([]byte(e.Action))
	h.Write([]byte{0})
	h.Write([]byte(e.GrantID))
	h.Write([]byte{0})
	h.Write([]byte(e.Detail))
	return hex.EncodeToString(h.Sum(nil))
}

// ListAccessEvents returns the newest events first.
func (s *Store) ListAccessEvents(ctx context.Context, limit int) ([]AccessEvent, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, actor, action, grant_id, detail, prev_hash, hash FROM access_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAccessEvents(rows)
}

// VerifyAccessEvents walks the whole chain oldest-first and returns the number
// of rows checked plus the id of the first broken row (0 when intact).
func (s *Store) VerifyAccessEvents(ctx context.Context) (checked int, broken int64, err error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, actor, action, grant_id, detail, prev_hash, hash FROM access_events ORDER BY id ASC`)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	evs, err := scanAccessEvents(rows)
	if err != nil {
		return 0, 0, err
	}
	prev := ""
	for _, e := range evs {
		if e.PrevHash != prev || accessEventHash(e) != e.Hash {
			return checked, e.ID, nil
		}
		prev = e.Hash
		checked++
	}
	return checked, 0, nil
}

func scanAccessEvents(rows *sql.Rows) ([]AccessEvent, error) {
	var out []AccessEvent
	for rows.Next() {
		var e AccessEvent
		var t int64
		if err := rows.Scan(&e.ID, &t, &e.Actor, &e.Action, &e.GrantID, &e.Detail, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.TS = time.UnixMilli(t)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---- peer ↔ user binding ---------------------------------------------

// SetWGPeerUser binds a WireGuard peer (public key) to a user name so grants
// for that user compile to the peer's tunnel addresses. Creates the meta row
// if the peer has no name yet.
func (s *Store) SetWGPeerUser(ctx context.Context, pubkey, user string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO wg_peer_meta (pubkey, name, notes, user, created_at) VALUES (?, '', '', ?, ?)
		ON CONFLICT(pubkey) DO UPDATE SET user = excluded.user`,
		pubkey, user, time.Now().UnixMilli())
	return err
}

// WGPeerUsers returns pubkey -> user for every bound peer.
func (s *Store) WGPeerUsers(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT pubkey, user FROM wg_peer_meta WHERE user != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, u string
		if err := rows.Scan(&k, &u); err != nil {
			return nil, err
		}
		out[k] = u
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v)
}
