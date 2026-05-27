package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Retention windows. Rollups live far longer than raw samples so the baseline
// survives raw-sample rotation (assessment storage recommendation).
const (
	RawSampleRetention     = 30 * 24 * time.Hour  // raw samples / flow snapshots
	RollupRetention        = 365 * 24 * time.Hour // (target, dow, hour) baselines
	DefaultMaxIncidents    = 200                  // per-session incident cap (weakness #6)
	DefaultMaxFlowSnapRows = 50_000               // global flow_snapshots cap
)

// RollupRow mirrors a row in the quality_rollup table. RTT/jitter in ms, loss %.
type RollupRow struct {
	Target   string
	DOW      int
	Hour     int
	P50RTT   float64
	P95RTT   float64
	P99RTT   float64
	LossPct  float64
	JitterMs float64
	Samples  int64
	Updated  time.Time
}

// GetRollup returns the baseline row for (target, dow, hour). ok=false when no
// baseline has been learned yet - callers treat that as neutral.
func (s *Store) GetRollup(ctx context.Context, target string, dow, hour int) (RollupRow, bool, error) {
	var r RollupRow
	var updMs int64
	err := s.db.QueryRowContext(ctx,
		`SELECT target, dow, hour, p50_rtt, p95_rtt, p99_rtt, loss_pct, jitter_ms, samples, updated
		   FROM quality_rollup WHERE target = ? AND dow = ? AND hour = ?`,
		target, dow, hour,
	).Scan(&r.Target, &r.DOW, &r.Hour, &r.P50RTT, &r.P95RTT, &r.P99RTT,
		&r.LossPct, &r.JitterMs, &r.Samples, &updMs)
	if err != nil {
		// sql.ErrNoRows -> not learned yet; report neutral without surfacing it.
		return RollupRow{}, false, ignoreNoRows(err)
	}
	r.Updated = time.UnixMilli(updMs)
	return r, true, nil
}

// PutRollup writes a fully-merged baseline row (the EMA merge happens in the
// caller via the pure quality.MergeEMA, keeping SQLite dumb).
func (s *Store) PutRollup(ctx context.Context, r RollupRow) error {
	upd := r.Updated
	if upd.IsZero() {
		upd = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO quality_rollup (target, dow, hour, p50_rtt, p95_rtt, p99_rtt,
		                            loss_pct, jitter_ms, samples, updated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(target, dow, hour) DO UPDATE SET
		  p50_rtt   = excluded.p50_rtt,
		  p95_rtt   = excluded.p95_rtt,
		  p99_rtt   = excluded.p99_rtt,
		  loss_pct  = excluded.loss_pct,
		  jitter_ms = excluded.jitter_ms,
		  samples   = excluded.samples,
		  updated   = excluded.updated`,
		r.Target, r.DOW, r.Hour, r.P50RTT, r.P95RTT, r.P99RTT,
		r.LossPct, r.JitterMs, r.Samples, upd.UnixMilli(),
	)
	return err
}

// RollupsByTarget returns every learned bucket for a target, ordered (dow, hour)
// - enough to render the baseline band behind the live history line.
func (s *Store) RollupsByTarget(ctx context.Context, target string) ([]RollupRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT target, dow, hour, p50_rtt, p95_rtt, p99_rtt, loss_pct, jitter_ms, samples, updated
		   FROM quality_rollup WHERE target = ? ORDER BY dow, hour`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RollupRow
	for rows.Next() {
		var r RollupRow
		var updMs int64
		if err := rows.Scan(&r.Target, &r.DOW, &r.Hour, &r.P50RTT, &r.P95RTT, &r.P99RTT,
			&r.LossPct, &r.JitterMs, &r.Samples, &updMs); err != nil {
			return nil, err
		}
		r.Updated = time.UnixMilli(updMs)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ResetBaseline clears all learned buckets for a target. Used by the "reset
// baseline for <target>" action when the network legitimately changed.
func (s *Store) ResetBaseline(ctx context.Context, target string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM quality_rollup WHERE target = ?`, target)
	return err
}

// FlowSnapshotRow mirrors a row in the flow_snapshots table.
type FlowSnapshotRow struct {
	TS       time.Time
	Iface    string
	Src      string
	Dst      string
	Proto    string
	BytesIn  int64
	BytesOut int64
	Process  string
	DNSName  string

	// Per-flow TCP telemetry, joined from tcp_info. Zero/empty when no
	// telemetry was observed for the flow at snapshot time.
	TCPRTTus       int64
	TCPRetransRate float64
	TCPCwnd        int64
	TCPSource      string
}

// InsertFlowSnapshots writes a batch of timestamped flow rows in one tx.
func (s *Store) InsertFlowSnapshots(ctx context.Context, sessionID string, ts time.Time, rows []FlowSnapshotRow) error {
	if sessionID == "" || len(rows) == 0 {
		return nil
	}
	if ts.IsZero() {
		ts = time.Now()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO flow_snapshots (session_id, ts, iface, src, dst, proto, bytes_in, bytes_out, process, dns_name, tcp_rtt_us, tcp_retrans_rate, tcp_cwnd, tcp_source)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	ms := ts.UnixMilli()
	for _, r := range rows {
		if _, err := stmt.ExecContext(ctx, sessionID, ms, r.Iface, r.Src, r.Dst,
			r.Proto, r.BytesIn, r.BytesOut, r.Process, r.DNSName,
			r.TCPRTTus, r.TCPRetransRate, r.TCPCwnd, r.TCPSource); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// FlowSnapshotsAround returns flow snapshots near a moment in time for a session
// (the closest preceding bucket), answering "what was talking at 02:00?".
func (s *Store) FlowSnapshotsAround(ctx context.Context, sessionID string, at time.Time, limit int) ([]FlowSnapshotRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT ts, iface, src, dst, proto, bytes_in, bytes_out, process, dns_name, tcp_rtt_us, tcp_retrans_rate, tcp_cwnd, tcp_source
		  FROM flow_snapshots
		 WHERE session_id = ? AND ts <= ?
		 ORDER BY ts DESC, bytes_in + bytes_out DESC
		 LIMIT ?`, sessionID, at.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FlowSnapshotRow
	for rows.Next() {
		var r FlowSnapshotRow
		var tsMs int64
		if err := rows.Scan(&tsMs, &r.Iface, &r.Src, &r.Dst, &r.Proto,
			&r.BytesIn, &r.BytesOut, &r.Process, &r.DNSName,
			&r.TCPRTTus, &r.TCPRetransRate, &r.TCPCwnd, &r.TCPSource); err != nil {
			return nil, err
		}
		r.TS = time.UnixMilli(tsMs)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Retain enforces all retention policies relative to now. Rollups outlive raw
// data; incidents are capped per session. Safe to call periodically.
func (s *Store) Retain(ctx context.Context, now time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}
	rawCut := now.Add(-RawSampleRetention).UnixMilli()
	rollupCut := now.Add(-RollupRetention).UnixMilli()
	stmts := []struct {
		q   string
		arg int64
	}{
		{`DELETE FROM samples WHERE ts < ?`, rawCut},
		{`DELETE FROM flow_snapshots WHERE ts < ?`, rawCut},
		{`DELETE FROM quality_rollup WHERE updated < ?`, rollupCut},
	}
	for _, st := range stmts {
		if _, err := s.db.ExecContext(ctx, st.q, st.arg); err != nil {
			return err
		}
	}
	return nil
}

// CapIncidents bounds the incidents table for a session to the newest max rows
// (weakness #6: unbounded incidents). A non-positive max uses the default.
func (s *Store) CapIncidents(ctx context.Context, sessionID string, max int) error {
	if max <= 0 {
		max = DefaultMaxIncidents
	}
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM incidents
		 WHERE session_id = ?
		   AND id NOT IN (
		     SELECT id FROM incidents WHERE session_id = ? ORDER BY ts DESC LIMIT ?
		   )`, sessionID, sessionID, max)
	return err
}

// CapFlowSnapshots bounds the global flow_snapshots row count to the newest max.
func (s *Store) CapFlowSnapshots(ctx context.Context, max int) error {
	if max <= 0 {
		max = DefaultMaxFlowSnapRows
	}
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM flow_snapshots
		 WHERE id NOT IN (SELECT id FROM flow_snapshots ORDER BY ts DESC LIMIT ?)`, max)
	return err
}

func ignoreNoRows(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return err
}
