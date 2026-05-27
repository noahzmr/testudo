// Package storage persists sessions, metric samples, and operational events
// to SQLite. The schema is created on first use; writes are batched via the
// caller's normal flow (one INSERT per event) - adequate for Phase 1 volumes.
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    started_at  INTEGER NOT NULL,
    ended_at    INTEGER,
    targets     TEXT NOT NULL,
    note        TEXT
);

CREATE TABLE IF NOT EXISTS samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    kind        TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    label       TEXT,
    value       REAL,
    failed      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_samples_session ON samples(session_id);
CREATE INDEX IF NOT EXISTS idx_samples_ts      ON samples(ts);
CREATE INDEX IF NOT EXISTS idx_samples_kind    ON samples(session_id, kind);

CREATE TABLE IF NOT EXISTS anomalies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    severity    TEXT NOT NULL,
    message     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_anomalies_session ON anomalies(session_id);

CREATE TABLE IF NOT EXISTS flows (
    session_id   TEXT NOT NULL,
    iface        TEXT NOT NULL DEFAULT '',
    a_ip         TEXT NOT NULL,
    a_port       INTEGER NOT NULL,
    b_ip         TEXT NOT NULL,
    b_port       INTEGER NOT NULL,
    proto        TEXT NOT NULL,
    packets      INTEGER NOT NULL,
    bytes        INTEGER NOT NULL,
    bytes_a_to_b INTEGER NOT NULL,
    bytes_b_to_a INTEGER NOT NULL,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    process      TEXT NOT NULL DEFAULT '',
    dns_name     TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (session_id, iface, a_ip, a_port, b_ip, b_port, proto)
);
CREATE INDEX IF NOT EXISTS idx_flows_session ON flows(session_id);
CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(session_id, last_seen);
CREATE INDEX IF NOT EXISTS idx_flows_iface ON flows(session_id, iface);

CREATE TABLE IF NOT EXISTS incidents (
    id          TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    trigger     TEXT NOT NULL,
    summary     TEXT NOT NULL,
    bundle_path TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_session ON incidents(session_id);

CREATE TABLE IF NOT EXISTS devices (
    ip          TEXT PRIMARY KEY,
    mac         TEXT,
    hostname    TEXT,
    vendor      TEXT,
    iface       TEXT,
    open_ports  TEXT,
    services    TEXT,
    os_hint     TEXT,
    source      TEXT,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);

CREATE TABLE IF NOT EXISTS snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    kind        TEXT NOT NULL,  -- "firewall" | "route" | "nat" | "topology"
    ts          INTEGER NOT NULL,
    payload     TEXT NOT NULL   -- JSON-encoded
);
CREATE INDEX IF NOT EXISTS idx_snapshots_session ON snapshots(session_id, kind, ts);

CREATE TABLE IF NOT EXISTS firewall_rule_samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    family      TEXT NOT NULL,
    tbl         TEXT NOT NULL,
    chain       TEXT NOT NULL,
    handle      INTEGER NOT NULL,
    pkts        INTEGER NOT NULL,
    bytes       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fwsamples_session ON firewall_rule_samples(session_id, ts);
CREATE INDEX IF NOT EXISTS idx_fwsamples_rule ON firewall_rule_samples(session_id, family, tbl, chain, handle, ts);

CREATE TABLE IF NOT EXISTS neighbours (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    ip          TEXT NOT NULL,
    mac         TEXT NOT NULL,
    dev         TEXT NOT NULL,
    family      TEXT NOT NULL,
    state       TEXT NOT NULL,
    router      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_neighbours_session ON neighbours(session_id, ts);
CREATE INDEX IF NOT EXISTS idx_neighbours_ip ON neighbours(session_id, ip, ts);

CREATE TABLE IF NOT EXISTS conntrack_samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    proto       TEXT NOT NULL,
    orig_src    TEXT NOT NULL,
    orig_dst    TEXT NOT NULL,
    orig_sport  INTEGER NOT NULL,
    orig_dport  INTEGER NOT NULL,
    reply_src   TEXT NOT NULL,
    reply_dst   TEXT NOT NULL,
    state       TEXT NOT NULL,
    natted      INTEGER NOT NULL DEFAULT 0,
    packets     INTEGER NOT NULL,
    bytes       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_conntrack_session ON conntrack_samples(session_id, ts);

-- Per-(target, day-of-week, hour) baseline rollup. NOT session-scoped: the
-- baseline is the long-horizon "normal" learned across sessions. Retained far
-- longer than raw samples (~1 year vs 30 days) so it survives raw rotation.
CREATE TABLE IF NOT EXISTS quality_rollup (
    target    TEXT NOT NULL,
    dow       INTEGER NOT NULL,   -- 0..6
    hour      INTEGER NOT NULL,   -- 0..23
    p50_rtt   REAL NOT NULL DEFAULT 0,
    p95_rtt   REAL NOT NULL DEFAULT 0,
    p99_rtt   REAL NOT NULL DEFAULT 0,
    loss_pct  REAL NOT NULL DEFAULT 0,
    jitter_ms REAL NOT NULL DEFAULT 0,
    samples   INTEGER NOT NULL DEFAULT 0,
    updated   INTEGER NOT NULL,   -- unix ms
    PRIMARY KEY (target, dow, hour)
);

-- Periodic, timestamped flow snapshots — the time-bucketed counterpart to the
-- cumulative flows table, so "what was talking at 02:00?" is answerable.
CREATE TABLE IF NOT EXISTS flow_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    iface       TEXT NOT NULL DEFAULT '',
    src         TEXT NOT NULL,
    dst         TEXT NOT NULL,
    proto       TEXT NOT NULL,
    bytes_in    INTEGER NOT NULL DEFAULT 0,
    bytes_out   INTEGER NOT NULL DEFAULT 0,
    process     TEXT NOT NULL DEFAULT '',
    dns_name    TEXT NOT NULL DEFAULT '',
    tcp_rtt_us       INTEGER NOT NULL DEFAULT 0,
    tcp_retrans_rate REAL NOT NULL DEFAULT 0,
    tcp_cwnd         INTEGER NOT NULL DEFAULT 0,
    tcp_source       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_flow_snapshots_session ON flow_snapshots(session_id, ts);
`

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

// migrate handles schema drift between releases. Each release that needs a
// migration adds a step here; steps are idempotent so running them on a
// fresh DB is a no-op.
func migrate(db *sql.DB) error {
	// Phase 2 => Phase 3: flows gained iface/process/dns_name columns and the
	// primary key changed to include iface. SQLite can't alter a PK in-place,
	// so we drop the old table and let the schema DDL recreate it. The cost
	// is losing historical flow rows; per-target metrics/anomalies survive.
	hasFlows, err := tableExists(db, "flows")
	if err != nil {
		return err
	}
	if hasFlows {
		hasIface, err := columnExists(db, "flows", "iface")
		if err != nil {
			return err
		}
		if !hasIface {
			if _, err := db.Exec("DROP TABLE flows"); err != nil {
				return fmt.Errorf("drop old flows table: %w", err)
			}
		}
	}

	// Per-flow TCP telemetry (Task 06): flow_snapshots gained tcp_* columns.
	// ADD COLUMN is cheap and idempotent-guarded so existing sessions keep
	// their history and just acquire the new columns with their defaults.
	hasSnap, err := tableExists(db, "flow_snapshots")
	if err != nil {
		return err
	}
	if hasSnap {
		hasTCP, err := columnExists(db, "flow_snapshots", "tcp_source")
		if err != nil {
			return err
		}
		if !hasTCP {
			for _, ddl := range []string{
				"ALTER TABLE flow_snapshots ADD COLUMN tcp_rtt_us INTEGER NOT NULL DEFAULT 0",
				"ALTER TABLE flow_snapshots ADD COLUMN tcp_retrans_rate REAL NOT NULL DEFAULT 0",
				"ALTER TABLE flow_snapshots ADD COLUMN tcp_cwnd INTEGER NOT NULL DEFAULT 0",
				"ALTER TABLE flow_snapshots ADD COLUMN tcp_source TEXT NOT NULL DEFAULT ''",
			} {
				if _, err := db.Exec(ddl); err != nil {
					return fmt.Errorf("add flow_snapshots tcp columns: %w", err)
				}
			}
		}
	}
	return nil
}

func tableExists(db *sql.DB, name string) (bool, error) {
	var n int
	err := db.QueryRow(
		"SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?",
		name).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func columnExists(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *Store) Close() error { return s.db.Close() }

// SessionRecord is a row in the sessions table.
type SessionRecord struct {
	ID        string
	StartedAt time.Time
	EndedAt   *time.Time
	Targets   []string
	Note      string
}

// StartSession inserts a session header and returns its id.
func (s *Store) StartSession(ctx context.Context, id string, targets []string, note string) error {
	encoded, _ := json.Marshal(targets)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, started_at, targets, note) VALUES (?, ?, ?, ?)`,
		id, time.Now().UnixMilli(), string(encoded), note,
	)
	return err
}

// EndSession sets the ended_at timestamp.
func (s *Store) EndSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET ended_at = ? WHERE id = ?`,
		time.Now().UnixMilli(), id,
	)
	return err
}

// ListSessions returns sessions newest-first, capped by limit.
func (s *Store) ListSessions(ctx context.Context, limit int) ([]SessionRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, started_at, ended_at, targets, note
		   FROM sessions
		   ORDER BY started_at DESC
		   LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SessionRecord
	for rows.Next() {
		var (
			rec       SessionRecord
			startedMs int64
			endedMs   sql.NullInt64
			targets   string
			note      sql.NullString
		)
		if err := rows.Scan(&rec.ID, &startedMs, &endedMs, &targets, &note); err != nil {
			return nil, err
		}
		rec.StartedAt = time.UnixMilli(startedMs)
		if endedMs.Valid {
			t := time.UnixMilli(endedMs.Int64)
			rec.EndedAt = &t
		}
		if note.Valid {
			rec.Note = note.String
		}
		_ = json.Unmarshal([]byte(targets), &rec.Targets)
		out = append(out, rec)
	}
	return out, rows.Err()
}

// Sample is a single timestamped measurement.
type Sample struct {
	Kind   string
	Label  string
	Value  float64
	Failed bool
	TS     time.Time
}

// InsertSample appends a sample to the given session.
func (s *Store) InsertSample(ctx context.Context, sessionID string, sm Sample) error {
	if sessionID == "" {
		return errors.New("session id required")
	}
	ts := sm.TS
	if ts.IsZero() {
		ts = time.Now()
	}
	failed := 0
	if sm.Failed {
		failed = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO samples (session_id, kind, ts, label, value, failed)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sessionID, sm.Kind, ts.UnixMilli(), sm.Label, sm.Value, failed,
	)
	return err
}

// InsertAnomaly records an analyzer-detected operational issue.
func (s *Store) InsertAnomaly(ctx context.Context, sessionID, severity, message string) error {
	return s.InsertAnomalyAt(ctx, sessionID, severity, message, time.Now())
}

// InsertAnomalyAt records an anomaly/timeline event at a caller-supplied
// timestamp. Push-based state changes (link/addr/route) use this so replay
// reconstructs the exact moment the kernel emitted the change rather than
// quantising it to a poll interval. A zero ts falls back to now.
func (s *Store) InsertAnomalyAt(ctx context.Context, sessionID, severity, message string, ts time.Time) error {
	if ts.IsZero() {
		ts = time.Now()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO anomalies (session_id, ts, severity, message) VALUES (?, ?, ?, ?)`,
		sessionID, ts.UnixMilli(), severity, message,
	)
	return err
}

// FlowRow mirrors a row in the flows table.
type FlowRow struct {
	Iface          string
	AIP, BIP       string
	APort, BPort   uint16
	Proto          string
	Packets, Bytes uint64
	BytesAtoB      uint64
	BytesBtoA      uint64
	FirstSeen      time.Time
	LastSeen       time.Time
	Process        string
	DNSName        string
}

// UpsertFlow inserts or updates a flow row. Counters accumulate on conflict.
func (s *Store) UpsertFlow(ctx context.Context, sessionID string, f FlowRow) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO flows (session_id, iface, a_ip, a_port, b_ip, b_port, proto,
		                   packets, bytes, bytes_a_to_b, bytes_b_to_a,
		                   first_seen, last_seen, process, dns_name)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(session_id, iface, a_ip, a_port, b_ip, b_port, proto) DO UPDATE SET
		  packets      = packets + excluded.packets,
		  bytes        = bytes + excluded.bytes,
		  bytes_a_to_b = bytes_a_to_b + excluded.bytes_a_to_b,
		  bytes_b_to_a = bytes_b_to_a + excluded.bytes_b_to_a,
		  last_seen    = excluded.last_seen,
		  process      = CASE WHEN excluded.process != '' THEN excluded.process ELSE flows.process END,
		  dns_name     = CASE WHEN excluded.dns_name != '' THEN excluded.dns_name ELSE flows.dns_name END
	`,
		sessionID, f.Iface, f.AIP, f.APort, f.BIP, f.BPort, f.Proto,
		f.Packets, f.Bytes, f.BytesAtoB, f.BytesBtoA,
		f.FirstSeen.UnixMilli(), f.LastSeen.UnixMilli(),
		f.Process, f.DNSName,
	)
	return err
}

// FlowsBySession returns flows for a session ordered by recent activity.
func (s *Store) FlowsBySession(ctx context.Context, sessionID string, limit int) ([]FlowRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT iface, a_ip, a_port, b_ip, b_port, proto, packets, bytes,
		       bytes_a_to_b, bytes_b_to_a, first_seen, last_seen, process, dns_name
		  FROM flows
		 WHERE session_id = ?
		 ORDER BY last_seen DESC
		 LIMIT ?`, sessionID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FlowRow
	for rows.Next() {
		var f FlowRow
		var firstMs, lastMs int64
		if err := rows.Scan(&f.Iface, &f.AIP, &f.APort, &f.BIP, &f.BPort, &f.Proto,
			&f.Packets, &f.Bytes, &f.BytesAtoB, &f.BytesBtoA,
			&firstMs, &lastMs, &f.Process, &f.DNSName); err != nil {
			return nil, err
		}
		f.FirstSeen = time.UnixMilli(firstMs)
		f.LastSeen = time.UnixMilli(lastMs)
		out = append(out, f)
	}
	return out, rows.Err()
}

// IncidentRow mirrors a row in the incidents table.
type IncidentRow struct {
	ID         string
	TS         time.Time
	Trigger    string
	Summary    string
	BundlePath string
}

// InsertIncident records an incident header. The bundle_path points at a
// JSON file on disk holding the captured context.
func (s *Store) InsertIncident(ctx context.Context, sessionID string, r IncidentRow) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO incidents (id, session_id, ts, trigger, summary, bundle_path)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		r.ID, sessionID, r.TS.UnixMilli(), r.Trigger, r.Summary, r.BundlePath,
	)
	return err
}

// DeviceRow mirrors a row in the devices table.
type DeviceRow struct {
	IP        string
	MAC       string
	Hostname  string
	Vendor    string
	Iface     string
	OpenPorts string // comma-separated
	Services  string // comma-separated
	OSHint    string
	Source    string
	FirstSeen time.Time
	LastSeen  time.Time
}

// UpsertDevice inserts or updates a device row.
func (s *Store) UpsertDevice(ctx context.Context, d DeviceRow) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO devices (ip, mac, hostname, vendor, iface, open_ports, services,
		                     os_hint, source, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
		  mac        = CASE WHEN excluded.mac != '' THEN excluded.mac ELSE devices.mac END,
		  hostname   = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE devices.hostname END,
		  vendor     = CASE WHEN excluded.vendor != '' THEN excluded.vendor ELSE devices.vendor END,
		  iface      = CASE WHEN excluded.iface != '' THEN excluded.iface ELSE devices.iface END,
		  open_ports = excluded.open_ports,
		  services   = excluded.services,
		  os_hint    = CASE WHEN excluded.os_hint != '' THEN excluded.os_hint ELSE devices.os_hint END,
		  source     = excluded.source,
		  last_seen  = excluded.last_seen
	`,
		d.IP, d.MAC, d.Hostname, d.Vendor, d.Iface,
		d.OpenPorts, d.Services, d.OSHint, d.Source,
		d.FirstSeen.UnixMilli(), d.LastSeen.UnixMilli(),
	)
	return err
}

// ListDevices returns devices ordered by most-recent activity.
func (s *Store) ListDevices(ctx context.Context, limit int) ([]DeviceRow, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT ip, mac, hostname, vendor, iface, open_ports, services,
		        os_hint, source, first_seen, last_seen
		   FROM devices
		   ORDER BY last_seen DESC
		   LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceRow
	for rows.Next() {
		var d DeviceRow
		var firstMs, lastMs int64
		var mac, host, vendor, iface, ports, services, osh, src sql.NullString
		if err := rows.Scan(&d.IP, &mac, &host, &vendor, &iface, &ports, &services,
			&osh, &src, &firstMs, &lastMs); err != nil {
			return nil, err
		}
		d.MAC, d.Hostname, d.Vendor, d.Iface = mac.String, host.String, vendor.String, iface.String
		d.OpenPorts, d.Services, d.OSHint, d.Source = ports.String, services.String, osh.String, src.String
		d.FirstSeen = time.UnixMilli(firstMs)
		d.LastSeen = time.UnixMilli(lastMs)
		out = append(out, d)
	}
	return out, rows.Err()
}

// IncidentsBySession returns incidents newest-first.
func (s *Store) IncidentsBySession(ctx context.Context, sessionID string) ([]IncidentRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, trigger, summary, bundle_path FROM incidents
		 WHERE session_id = ? ORDER BY ts DESC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IncidentRow
	for rows.Next() {
		var r IncidentRow
		var ms int64
		var bundle sql.NullString
		if err := rows.Scan(&r.ID, &ms, &r.Trigger, &r.Summary, &bundle); err != nil {
			return nil, err
		}
		r.TS = time.UnixMilli(ms)
		if bundle.Valid {
			r.BundlePath = bundle.String
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AnomaliesBySession returns the persisted anomaly log for a session.
type AnomalyRow struct {
	TS       time.Time
	Severity string
	Message  string
}

func (s *Store) AnomaliesBySession(ctx context.Context, sessionID string) ([]AnomalyRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ts, severity, message FROM anomalies WHERE session_id = ? ORDER BY ts ASC`,
		sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AnomalyRow
	for rows.Next() {
		var a AnomalyRow
		var ms int64
		if err := rows.Scan(&ms, &a.Severity, &a.Message); err != nil {
			return nil, err
		}
		a.TS = time.UnixMilli(ms)
		out = append(out, a)
	}
	return out, rows.Err()
}

// SamplesBySession returns all samples for a session in chronological order.
func (s *Store) SamplesBySession(ctx context.Context, sessionID string) ([]Sample, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT kind, label, value, failed, ts FROM samples WHERE session_id = ? ORDER BY ts ASC`,
		sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Sample
	for rows.Next() {
		var (
			sm     Sample
			label  sql.NullString
			tsMs   int64
			failed int
		)
		if err := rows.Scan(&sm.Kind, &label, &sm.Value, &failed, &tsMs); err != nil {
			return nil, err
		}
		if label.Valid {
			sm.Label = label.String
		}
		sm.TS = time.UnixMilli(tsMs)
		sm.Failed = failed == 1
		out = append(out, sm)
	}
	return out, rows.Err()
}
