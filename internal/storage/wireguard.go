package storage

import (
	"context"
	"fmt"
	"time"
)

// WireGuardSample is one WireGuard peer captured at a point in time so replay
// can answer "was the tunnel up during the incident?". PUBLIC KEYS ONLY - it
// deliberately has no field for a private or preshared key (secrets rule).
// HandshakeAgeSec is -1 when the peer never handshaked.
type WireGuardSample struct {
	TS              time.Time
	Device          string
	PeerPublicKey   string
	HandshakeAgeSec int64
	RxBytes         int64
	TxBytes         int64
}

// InsertWireGuardSamples writes a batch of WireGuard peer rows under one
// timestamp so a replay query can pull a coherent per-tick view. No-op for an
// empty batch.
func (s *Store) InsertWireGuardSamples(ctx context.Context, sessionID string, ts time.Time, ws []WireGuardSample) error {
	if sessionID == "" {
		return fmt.Errorf("session id required")
	}
	if len(ws) == 0 {
		return nil
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
		`INSERT INTO wireguard_samples (session_id, ts, device, peer_public_key, handshake_age_sec, rx_bytes, tx_bytes)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	ms := ts.UnixMilli()
	for _, w := range ws {
		if _, err := stmt.ExecContext(ctx, sessionID, ms, w.Device, w.PeerPublicKey,
			w.HandshakeAgeSec, w.RxBytes, w.TxBytes); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// WGPeerMeta is the human metadata for a peer that neither netplan nor the
// kernel stores. Keyed by public key. PUBLIC KEYS ONLY.
type WGPeerMeta struct {
	PublicKey string
	Name      string
	Notes     string
	CreatedAt time.Time
}

// UpsertWGPeerMeta stores/updates a peer's name + notes, keyed by public key.
// The created_at timestamp is set on first insert and preserved on update.
func (s *Store) UpsertWGPeerMeta(ctx context.Context, pubkey, name, notes string) error {
	if pubkey == "" {
		return fmt.Errorf("pubkey required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO wg_peer_meta (pubkey, name, notes, created_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(pubkey) DO UPDATE SET name=excluded.name, notes=excluded.notes`,
		pubkey, name, notes, time.Now().UnixMilli())
	return err
}

// WGPeerMetaMap returns every peer's metadata keyed by public key, for the
// collector's merged read (name lookup).
func (s *Store) WGPeerMetaMap(ctx context.Context) (map[string]WGPeerMeta, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT pubkey, name, notes, created_at FROM wg_peer_meta`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]WGPeerMeta{}
	for rows.Next() {
		var m WGPeerMeta
		var ms int64
		if err := rows.Scan(&m.PublicKey, &m.Name, &m.Notes, &ms); err != nil {
			return nil, err
		}
		m.CreatedAt = time.UnixMilli(ms)
		out[m.PublicKey] = m
	}
	return out, rows.Err()
}

// DeleteWGPeerMeta removes a peer's metadata (on deprovision).
func (s *Store) DeleteWGPeerMeta(ctx context.Context, pubkey string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM wg_peer_meta WHERE pubkey = ?`, pubkey)
	return err
}

// UpsertWGIfaceMeta stores/updates a device's human label, keyed by device name.
func (s *Store) UpsertWGIfaceMeta(ctx context.Context, device, name, notes string) error {
	if device == "" {
		return fmt.Errorf("device required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO wg_iface_meta (device, name, notes, created_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(device) DO UPDATE SET name=excluded.name, notes=excluded.notes`,
		device, name, notes, time.Now().UnixMilli())
	return err
}

// WGIfaceMetaMap returns device -> label for the collector's merged read.
func (s *Store) WGIfaceMetaMap(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT device, name FROM wg_iface_meta`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var dev, name string
		if err := rows.Scan(&dev, &name); err != nil {
			return nil, err
		}
		out[dev] = name
	}
	return out, rows.Err()
}

// WireGuardSamplesBySession returns every WireGuard sample for a session, oldest
// first, for replay reconstruction.
func (s *Store) WireGuardSamplesBySession(ctx context.Context, sessionID string) ([]WireGuardSample, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ts, device, peer_public_key, handshake_age_sec, rx_bytes, tx_bytes
		 FROM wireguard_samples WHERE session_id = ? ORDER BY ts ASC`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WireGuardSample
	for rows.Next() {
		var w WireGuardSample
		var ms int64
		if err := rows.Scan(&ms, &w.Device, &w.PeerPublicKey, &w.HandshakeAgeSec, &w.RxBytes, &w.TxBytes); err != nil {
			return nil, err
		}
		w.TS = time.UnixMilli(ms)
		out = append(out, w)
	}
	return out, rows.Err()
}
