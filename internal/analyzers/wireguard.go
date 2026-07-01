package analyzers

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/noahzmr/testudo/internal/events"
	"github.com/noahzmr/testudo/internal/wireguard"
)

// WireGuardHandshakeDetector rides the WireGuard snapshot stream and raises an
// anomaly when a peer's handshake goes stale - the key WG health signal, since a
// tunnel can be UP while a peer is dead. Thresholds live in the wireguard
// package (180 s WARN on keepalive peers, 300 s ERROR, never-established
// CRITICAL). A secondary signal flags a peer whose handshake is fresh but whose
// RX/TX has stalled.
//
// De-dup: an anomaly is (re)emitted only when a peer's severity worsens or after
// CoolDown, so a persistently-down peer doesn't spam the Alerts tab every tick.
type WireGuardHandshakeDetector struct {
	CoolDown time.Duration

	mu        sync.Mutex
	lastSev   map[string]wireguard.Severity // key: device|peer
	lastFired map[string]time.Time
	prevBytes map[string]int64 // key: device|peer -> rx+tx last seen
	init      bool
}

func (d *WireGuardHandshakeDetector) Name() string { return "wireguard_handshake" }

func (d *WireGuardHandshakeDetector) lazyInit() {
	if d.init {
		return
	}
	if d.CoolDown <= 0 {
		d.CoolDown = 120 * time.Second
	}
	d.lastSev = map[string]wireguard.Severity{}
	d.lastFired = map[string]time.Time{}
	d.prevBytes = map[string]int64{}
	d.init = true
}

func (d *WireGuardHandshakeDetector) Run(ctx context.Context, in <-chan events.Event, bus *events.Bus) error {
	d.lazyInit()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-in:
			if !ok {
				return nil
			}
			if ev.Kind != events.KindWireGuardSnapshot {
				continue
			}
			snap, ok := ev.Payload.(wireguard.Snapshot)
			if !ok {
				continue
			}
			d.inspect(snap, bus)
		}
	}
}

func (d *WireGuardHandshakeDetector) inspect(snap wireguard.Snapshot, bus *events.Bus) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, dev := range snap.Devices {
		for _, p := range dev.Peers {
			key := dev.Name + "|" + p.PublicKey
			d.checkHandshake(dev.Name, p, key, bus)
			d.checkStalled(dev.Name, p, key, bus)
			d.checkDrift(dev.Name, p, key, bus)
		}
	}
}

// checkDrift raises a WARN when a peer's live state disagrees with the netplan
// intent - a live-only peer (lost on the next apply/reboot) or a config
// mismatch. Rate-limited on the same per-peer clock.
func (d *WireGuardHandshakeDetector) checkDrift(dev string, p wireguard.Peer, key string, bus *events.Bus) {
	if p.Drift == wireguard.DriftNone || p.Drift == wireguard.DriftConfigOnly {
		// ConfigOnly (declared, not up yet) is already covered by the handshake
		// CRITICAL path; only flag genuine live-vs-netplan divergence here.
		return
	}
	driftKey := "drift|" + key
	last := d.lastFired[driftKey]
	if !last.IsZero() && time.Since(last) < d.CoolDown {
		return
	}
	d.lastFired[driftKey] = time.Now()
	var msg string
	switch p.Drift {
	case wireguard.DriftNotPersistent:
		msg = fmt.Sprintf("WireGuard peer %s on %s: live but not in netplan (lost on next apply/reboot)",
			p.PeerDisplayName(), dev)
	case wireguard.DriftConfig:
		msg = fmt.Sprintf("WireGuard peer %s on %s: AllowedIPs differ live vs netplan (config drift)",
			p.PeerDisplayName(), dev)
	default:
		msg = fmt.Sprintf("WireGuard peer %s on %s: config drift", p.PeerDisplayName(), dev)
	}
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: d.Name(),
		Payload: events.AnomalyPayload{Severity: string(events.SevWarn), Message: msg},
	})
}

func (d *WireGuardHandshakeDetector) checkHandshake(dev string, p wireguard.Peer, key string, bus *events.Bus) {
	sev := p.Severity
	if sev == wireguard.SevOK {
		// Peer recovered; clear its state so a future lapse fires cleanly.
		delete(d.lastSev, key)
		delete(d.lastFired, key)
		return
	}
	prev, seen := d.lastSev[key]
	last := d.lastFired[key]
	worsened := !seen || severityWorse(sev, prev)
	if !worsened && !last.IsZero() && time.Since(last) < d.CoolDown {
		return
	}
	d.lastSev[key] = sev
	d.lastFired[key] = time.Now()

	var msg string
	switch sev {
	case wireguard.SevCritical:
		msg = fmt.Sprintf("WireGuard peer %s on %s: handshake never established",
			p.PeerDisplayName(), dev)
	default:
		msg = fmt.Sprintf("WireGuard peer %s on %s: last handshake %s (stale)",
			p.PeerDisplayName(), dev, p.HandshakeLabel())
	}
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: d.Name(),
		Payload: events.AnomalyPayload{
			Severity: string(toEventSeverity(sev)),
			Message:  msg,
		},
	})
}

// checkStalled is the secondary signal: a peer with a fresh handshake and a
// keepalive but whose cumulative RX/TX hasn't moved is likely wedged.
func (d *WireGuardHandshakeDetector) checkStalled(dev string, p wireguard.Peer, key string, bus *events.Bus) {
	total := p.ReceiveBytes + p.TransmitBytes
	stalledKey := "bytes|" + key
	prev, seen := d.prevBytes[stalledKey]
	d.prevBytes[stalledKey] = total
	if !seen {
		return
	}
	if p.Severity != wireguard.SevOK || p.PersistentKeepalive <= 0 || p.Never {
		return
	}
	if total != prev {
		return // traffic is moving; not stalled
	}
	// Rate-limit the stalled signal on the same per-peer fired clock.
	last := d.lastFired[key]
	if !last.IsZero() && time.Since(last) < d.CoolDown {
		return
	}
	d.lastFired[key] = time.Now()
	bus.Publish(events.Event{
		Kind: events.KindAnomaly, Source: d.Name(),
		Payload: events.AnomalyPayload{
			Severity: string(events.SevWarn),
			Message: fmt.Sprintf(
				"WireGuard peer %s on %s: RX/TX stalled despite keepalive",
				p.PeerDisplayName(), dev),
		},
	})
}

func severityWorse(a, b wireguard.Severity) bool {
	return sevRank(a) > sevRank(b)
}

func sevRank(s wireguard.Severity) int {
	switch s {
	case wireguard.SevWarn:
		return 1
	case wireguard.SevError:
		return 2
	case wireguard.SevCritical:
		return 3
	}
	return 0
}

func toEventSeverity(s wireguard.Severity) events.Severity {
	switch s {
	case wireguard.SevWarn:
		return events.SevWarn
	case wireguard.SevError:
		return events.SevError
	case wireguard.SevCritical:
		return events.SevCritical
	}
	return events.SevInfo
}
