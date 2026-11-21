package engine

import (
	"context"
	"errors"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/health"
	"github.com/noahzmr/testudo/internal/storage"
	"github.com/noahzmr/testudo/internal/wireguard"
)

// wgUnprivilegedHint is the actionable remediation surfaced when WireGuard state
// can't be read (needs CAP_NET_ADMIN via generic-netlink).
const wgUnprivilegedHint = "grant CAP_NET_ADMIN (sudo setcap cap_net_admin+ep ./testudo) or run with the privileged helper"

// errWireGuardNoNetops is returned by the management helpers when netops is
// unavailable (privileged mutations have nowhere to go).
var errWireGuardNoNetops = errors.New("wireguard management unavailable: netops not initialized")

// startWireGuardPersister consumes the WireGuard snapshot stream and (a) writes
// per-tick peer samples to SQLite for replay (public keys only) and (b) refines
// the "wireguard" subsystem health row: OK while snapshots flow, unprivileged/
// soft-fail when reads error, and a benign "no device" note when the tunnel is
// simply absent. It is a no-op when WireGuard monitoring is disabled.
func (e *Engine) startWireGuardPersister(ctx context.Context) {
	if e.wg0 == nil {
		return
	}
	sub := e.bus.SubscribeKinds(events.KindWireGuardSnapshot)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer sub.Close()
		// A slow ticker independently checks read availability, because a failed
		// read publishes no snapshot event - without this the health row would
		// never leave OK.
		healthTick := time.NewTicker(10 * time.Second)
		defer healthTick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-sub.C():
				if !ok {
					return
				}
				snap, ok := ev.Payload.(wireguard.Snapshot)
				if !ok {
					continue
				}
				e.persistWireGuardSnapshot(ctx, snap)
				e.reportWireGuardHealth()
			case <-healthTick.C:
				e.reportWireGuardHealth()
			}
		}
	}()
}

// persistWireGuardSnapshot writes one sample row per peer. HandshakeAgeSec is -1
// for a never-established peer so replay can tell "stale" from "never".
func (e *Engine) persistWireGuardSnapshot(ctx context.Context, snap wireguard.Snapshot) {
	var samples []storage.WireGuardSample
	for _, d := range snap.Devices {
		for _, p := range d.Peers {
			age := int64(-1)
			if !p.Never {
				age = int64(p.HandshakeAge.Seconds())
			}
			samples = append(samples, storage.WireGuardSample{
				TS:              snap.Time,
				Device:          d.Name,
				PeerPublicKey:   p.PublicKey,
				HandshakeAgeSec: age,
				RxBytes:         p.ReceiveBytes,
				TxBytes:         p.TransmitBytes,
			})
		}
	}
	_ = e.store.InsertWireGuardSamples(ctx, e.sessionID, snap.Time, samples)
}

// wireguardPeerNames returns the peer public-key -> display-name map from
// wg_peer_meta, feeding the collector's merged read. Never blocks the collector
// on a DB error - it just yields no names.
func (e *Engine) wireguardPeerNames() map[string]string {
	if e.store == nil {
		return nil
	}
	meta, err := e.store.WGPeerMetaMap(context.Background())
	if err != nil {
		return nil
	}
	out := make(map[string]string, len(meta))
	for k, m := range meta {
		if m.Name != "" {
			out[k] = m.Name
		}
	}
	return out
}

// wireguardIfaceNames returns the device -> label map from wg_iface_meta.
func (e *Engine) wireguardIfaceNames() map[string]string {
	if e.store == nil {
		return nil
	}
	m, err := e.store.WGIfaceMetaMap(context.Background())
	if err != nil {
		return nil
	}
	return m
}

// wgPerfSysctls is the recommended UDP socket-buffer profile (bytes). ~25 MiB
// max buffers and a deeper backlog markedly reduce drops on a busy tunnel.
var wgPerfSysctls = [][2]string{
	{"net.core.rmem_max", "26214400"},
	{"net.core.wmem_max", "26214400"},
	{"net.core.rmem_default", "1048576"},
	{"net.core.wmem_default", "1048576"},
	{"net.core.netdev_max_backlog", "5000"},
	{"net.core.optmem_max", "65536"},
}

// auditOp records an engine-level mutation to the audit log with the human
// actor behind it. Args is a JSON summary and must never carry secret material.
func (e *Engine) auditOp(ctx context.Context, actor, op, args string, opErr error) {
	if e.store == nil {
		return
	}
	result := "ok"
	if opErr != nil {
		result = opErr.Error()
	}
	_ = e.store.InsertAudit(ctx, storage.AuditEntry{Op: op, Actor: actor, Args: args, Result: result})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// WireGuardGrade returns the WireGuard sub-score for the Network Quality grade
// and whether it carries data. hasData=false (neutral 100) when WireGuard is
// disabled, unread, or has no device - the grade excludes it entirely so a host
// without WireGuard is never penalised.
func (e *Engine) WireGuardGrade() (score int, hasData bool) {
	if e.wg0 == nil {
		return 100, false
	}
	snap, ok := e.wg0.Snapshot()
	if !ok {
		return 100, false
	}
	return snap.SubScore()
}

// reportWireGuardHealth maps the collector's read state onto the subsystem
// registry. When reads fail (missing CAP_NET_ADMIN) the row goes "unprivileged"
// with a setcap hint; when reads succeed it is "ok" (even with zero devices -
// having no WireGuard is not a fault). Not marked core: a missing tunnel must
// never drag down the headline connectivity grade.
func (e *Engine) reportWireGuardHealth() {
	if e.wg0 == nil {
		return
	}
	if e.wg0.Available() {
		e.MarkSubsystem("wireguard", false, health.StateOK, "", "")
		return
	}
	if err := e.wg0.LastErr(); err != nil {
		e.MarkSubsystem("wireguard", false, health.StateUnprivileged, err.Error(), wgUnprivilegedHint)
	}
}
