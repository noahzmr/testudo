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
