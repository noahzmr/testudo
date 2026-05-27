package storage

import (
	"context"
	"fmt"
	"time"
)

// NeighbourSample is one neighbour-table row captured at a point in time, so
// replay can answer "was there an IP conflict at 02:00?". Mirrors
// netops.Neighbour without importing it (storage stays dependency-free).
type NeighbourSample struct {
	TS     time.Time
	IP     string
	MAC    string
	Dev    string
	Family string
	State  string
	Router bool
}

// ConntrackSample is one conntrack flow captured at a point in time, so an
// incident bundle answers "what was NAT'd during the incident?".
type ConntrackSample struct {
	TS        time.Time
	Proto     string
	OrigSrc   string
	OrigDst   string
	OrigSport uint16
	OrigDport uint16
	ReplySrc  string
	ReplyDst  string
	State     string
	NATed     bool
	Packets   uint64
	Bytes     uint64
}

// InsertNeighbours writes a batch of neighbour rows under one timestamp. The
// whole batch shares the snapshot instant so a replay query can pull a
// coherent table for any tick.
func (s *Store) InsertNeighbours(ctx context.Context, sessionID string, ts time.Time, ns []NeighbourSample) error {
	if sessionID == "" {
		return fmt.Errorf("session id required")
	}
	if ts.IsZero() {
		ts = time.Now()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO neighbours (session_id, ts, ip, mac, dev, family, state, router)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	ms := ts.UnixMilli()
	for _, n := range ns {
		if _, err := stmt.ExecContext(ctx, sessionID, ms, n.IP, n.MAC, n.Dev, n.Family, n.State, boolToInt(n.Router)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// NeighboursBySession returns every neighbour sample for a session, oldest
// first - the replay source for the neighbour timeline.
func (s *Store) NeighboursBySession(ctx context.Context, sessionID string) ([]NeighbourSample, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ts, ip, mac, dev, family, state, router FROM neighbours
		 WHERE session_id = ? ORDER BY ts ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NeighbourSample
	for rows.Next() {
		var n NeighbourSample
		var ms int64
		var router int
		if err := rows.Scan(&ms, &n.IP, &n.MAC, &n.Dev, &n.Family, &n.State, &router); err != nil {
			return nil, err
		}
		n.TS = time.UnixMilli(ms)
		n.Router = router != 0
		out = append(out, n)
	}
	return out, rows.Err()
}

// InsertConntrack writes a batch of conntrack flows under one timestamp.
func (s *Store) InsertConntrack(ctx context.Context, sessionID string, ts time.Time, fs []ConntrackSample) error {
	if sessionID == "" {
		return fmt.Errorf("session id required")
	}
	if ts.IsZero() {
		ts = time.Now()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO conntrack_samples
		 (session_id, ts, proto, orig_src, orig_dst, orig_sport, orig_dport, reply_src, reply_dst, state, natted, packets, bytes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	ms := ts.UnixMilli()
	for _, f := range fs {
		if _, err := stmt.ExecContext(ctx, sessionID, ms, f.Proto, f.OrigSrc, f.OrigDst,
			int(f.OrigSport), int(f.OrigDport), f.ReplySrc, f.ReplyDst, f.State,
			boolToInt(f.NATed), int64(f.Packets), int64(f.Bytes)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ConntrackBySession returns every conntrack sample for a session, oldest first.
func (s *Store) ConntrackBySession(ctx context.Context, sessionID string) ([]ConntrackSample, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ts, proto, orig_src, orig_dst, orig_sport, orig_dport, reply_src, reply_dst, state, natted, packets, bytes
		 FROM conntrack_samples WHERE session_id = ? ORDER BY ts ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConntrackSample
	for rows.Next() {
		var f ConntrackSample
		var ms int64
		var sport, dport int
		var natted int
		var pkts, bytes int64
		if err := rows.Scan(&ms, &f.Proto, &f.OrigSrc, &f.OrigDst, &sport, &dport,
			&f.ReplySrc, &f.ReplyDst, &f.State, &natted, &pkts, &bytes); err != nil {
			return nil, err
		}
		f.TS = time.UnixMilli(ms)
		f.OrigSport, f.OrigDport = uint16(sport), uint16(dport)
		f.NATed = natted != 0
		f.Packets, f.Bytes = uint64(pkts), uint64(bytes)
		out = append(out, f)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
