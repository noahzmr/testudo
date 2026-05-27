package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Snapshot kinds. Used as the `kind` column value in the snapshots table.
const (
	SnapshotKindFirewall = "firewall"
	SnapshotKindRoute    = "route"
	SnapshotKindNAT      = "nat"
	SnapshotKindTopology = "topology"
)

// SnapshotRow is one row in the snapshots table.
type SnapshotRow struct {
	ID         int64
	SessionID  string
	Kind       string
	TS         time.Time
	PayloadRaw []byte
}

// InsertSnapshot serialises payload as JSON and stores it under the given
// kind. Callers pass the actual subsystem struct (FirewallSummary, []RouteInfo,
// etc.); the storage layer doesn't care about its shape.
func (s *Store) InsertSnapshot(ctx context.Context, sessionID, kind string, payload any) error {
	if sessionID == "" {
		return fmt.Errorf("session id required")
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO snapshots (session_id, kind, ts, payload) VALUES (?, ?, ?, ?)`,
		sessionID, kind, time.Now().UnixMilli(), string(encoded),
	)
	return err
}

// SnapshotIndexEntry is one row in the snapshot index - id + kind + ts,
// without the payload. Used by history views that just need to list what
// snapshots exist before letting the user inspect a specific row.
type SnapshotIndexEntry struct {
	ID   int64
	Kind string
	TS   time.Time
}

// SnapshotIndexBySession returns every snapshot for a session, newest-first,
// without the payload column. Cheap enough to call on every history-tab
// refresh; the payload is fetched on demand via SnapshotByID.
func (s *Store) SnapshotIndexBySession(ctx context.Context, sessionID string) ([]SnapshotIndexEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, kind, ts FROM snapshots
		 WHERE session_id = ?
		 ORDER BY ts DESC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SnapshotIndexEntry
	for rows.Next() {
		var e SnapshotIndexEntry
		var ms int64
		if err := rows.Scan(&e.ID, &e.Kind, &ms); err != nil {
			return nil, err
		}
		e.TS = time.UnixMilli(ms)
		out = append(out, e)
	}
	return out, rows.Err()
}

// SnapshotByID returns one snapshot row by its primary key, payload included.
// Returns sql.ErrNoRows if the id is unknown.
func (s *Store) SnapshotByID(ctx context.Context, id int64) (SnapshotRow, error) {
	var r SnapshotRow
	var ms int64
	var payload string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, session_id, kind, ts, payload FROM snapshots WHERE id = ?`, id,
	).Scan(&r.ID, &r.SessionID, &r.Kind, &ms, &payload)
	if err != nil {
		return SnapshotRow{}, err
	}
	r.TS = time.UnixMilli(ms)
	r.PayloadRaw = []byte(payload)
	return r, nil
}

// SnapshotsBySession returns snapshots of one kind for a session, oldest first.
func (s *Store) SnapshotsBySession(ctx context.Context, sessionID, kind string) ([]SnapshotRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, payload FROM snapshots
		 WHERE session_id = ? AND kind = ?
		 ORDER BY ts ASC`, sessionID, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SnapshotRow
	for rows.Next() {
		var r SnapshotRow
		var ms int64
		var payload string
		if err := rows.Scan(&r.ID, &ms, &payload); err != nil {
			return nil, err
		}
		r.SessionID = sessionID
		r.Kind = kind
		r.TS = time.UnixMilli(ms)
		r.PayloadRaw = []byte(payload)
		out = append(out, r)
	}
	return out, rows.Err()
}

// FirewallRuleSample is one periodic per-rule counter reading. Persisted so
// replay can answer "which rule's drops climbed during the incident".
type FirewallRuleSample struct {
	TS      time.Time
	Family  string
	Table   string
	Chain   string
	Handle  uint64
	Packets uint64
	Bytes   uint64
}

// InsertFirewallRuleSample appends one per-rule counter reading to the
// session. TS defaults to now when zero.
func (s *Store) InsertFirewallRuleSample(ctx context.Context, sessionID string, sm FirewallRuleSample) error {
	if sessionID == "" {
		return fmt.Errorf("session id required")
	}
	ts := sm.TS
	if ts.IsZero() {
		ts = time.Now()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO firewall_rule_samples (session_id, ts, family, tbl, chain, handle, pkts, bytes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sessionID, ts.UnixMilli(), sm.Family, sm.Table, sm.Chain,
		int64(sm.Handle), int64(sm.Packets), int64(sm.Bytes),
	)
	return err
}

// FirewallRuleSamplesBySession returns every per-rule counter sample for a
// session, oldest first - the replay source for per-rule drop timelines.
func (s *Store) FirewallRuleSamplesBySession(ctx context.Context, sessionID string) ([]FirewallRuleSample, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ts, family, tbl, chain, handle, pkts, bytes
		 FROM firewall_rule_samples
		 WHERE session_id = ?
		 ORDER BY ts ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FirewallRuleSample
	for rows.Next() {
		var sm FirewallRuleSample
		var ms int64
		var handle, pkts, bytes int64
		if err := rows.Scan(&ms, &sm.Family, &sm.Table, &sm.Chain, &handle, &pkts, &bytes); err != nil {
			return nil, err
		}
		sm.TS = time.UnixMilli(ms)
		sm.Handle, sm.Packets, sm.Bytes = uint64(handle), uint64(pkts), uint64(bytes)
		out = append(out, sm)
	}
	return out, rows.Err()
}

// SearchAnomalies returns anomalies whose message matches the query LIKE
// pattern. Useful for the alerts tab search box.
func (s *Store) SearchAnomalies(ctx context.Context, sessionID, query string, limit int) ([]AnomalyRow, error) {
	if limit <= 0 {
		limit = 200
	}
	like := "%" + query + "%"
	args := []any{}
	sql := `SELECT ts, severity, message FROM anomalies WHERE message LIKE ?`
	args = append(args, like)
	if sessionID != "" {
		sql += ` AND session_id = ?`
		args = append(args, sessionID)
	}
	sql += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, sql, args...)
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

// DownsampleSamples collapses old samples into N-minute buckets. Buckets are
// keyed by (kind, label, bucket_start) and the per-bucket value is the mean.
// Rows older than `keep` are deleted; rows older than `compactAfter` but
// inside `keep` are replaced by their bucketed averages.
//
// Idempotent: re-running on already-bucketed rows is a no-op (the bucket
// start aligns exactly).
func (s *Store) DownsampleSamples(ctx context.Context, keep, compactAfter time.Duration, bucket time.Duration) error {
	if bucket <= 0 {
		bucket = 5 * time.Minute
	}
	now := time.Now()
	deleteCutoff := now.Add(-keep).UnixMilli()
	compactCutoff := now.Add(-compactAfter).UnixMilli()
	bucketMs := bucket.Milliseconds()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM samples WHERE ts < ?`, deleteCutoff); err != nil {
		return fmt.Errorf("prune old samples: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		CREATE TEMP TABLE samples_compact AS
		SELECT
		  session_id,
		  kind,
		  label,
		  (ts / ?) * ? AS bucket_ts,
		  AVG(value)  AS value,
		  MAX(failed) AS failed
		FROM samples
		WHERE ts < ?
		GROUP BY session_id, kind, label, bucket_ts
	`, bucketMs, bucketMs, compactCutoff); err != nil {
		return fmt.Errorf("build compact table: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM samples WHERE ts < ?`, compactCutoff); err != nil {
		return fmt.Errorf("delete pre-compact rows: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO samples (session_id, kind, ts, label, value, failed)
		SELECT session_id, kind, bucket_ts, label, value, failed FROM samples_compact
	`); err != nil {
		return fmt.Errorf("insert compacted rows: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DROP TABLE samples_compact`); err != nil {
		return fmt.Errorf("drop compact table: %w", err)
	}
	return tx.Commit()
}
