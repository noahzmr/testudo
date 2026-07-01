// Package wireguard treats WireGuard as a first-class Testudo subsystem rather
// than a generic interface. WireGuard state lives in its own generic-netlink
// family (WG_CMD_GET_DEVICE), not in normal link-state, so an interface can be
// UP/RUNNING while the tunnel is dead (no handshake, peer unreachable). This
// package surfaces that truth from a single collector + netops backend feeding
// both the TUI and the Web UI.
//
// Secrets rule (non-negotiable): private and preshared keys never touch the
// event bus, snapshots, logs, or SQLite. Only public keys / fingerprints are
// persisted or logged. Key generation happens in-process; a rendered client
// config containing a private key is produced exactly once and then dropped.
package wireguard

import (
	"fmt"
	"time"

	"github.com/noahzmr/testudo/internal/netops"
)

// Snapshot is the per-tick view of every WireGuard device published on the bus
// as the payload of events.KindWireGuardSnapshot. It carries public material
// only.
type Snapshot struct {
	Time    time.Time
	Devices []Device
}

// Device is one WireGuard device and its peers, enriched with handshake health
// and interface-level tx/rx error health. WireGuard exposes no per-peer error
// counters, so error/drop stats are interface-scoped here and folded into each
// peer's Health.
type Device struct {
	Name         string
	Label        string // human name from wg_iface_meta (SQLite), keyed by device
	PublicKey    string
	ListenPort   int
	FirewallMark int
	Peers        []Peer

	// Interface-level health from the kernel link stats.
	Up        bool
	Running   bool
	MTU       int
	TxQLen    int
	RxBytes   uint64
	TxBytes   uint64
	RxErrors  uint64
	TxErrors  uint64
	RxDropped uint64
	TxDropped uint64
	// Per-tick growth (this poll vs the previous one), the basis for ErrHealth.
	ErrDelta  uint64
	DropDelta uint64
	// ErrHealth is the device's tx/rx-error verdict: errors growing -> ERROR,
	// drops growing -> WARN, otherwise OK. Health also folds link state.
	ErrHealth Severity
	Health    Severity

	// Netplan (configured intent) reconciliation.
	NetplanKnown      bool   // this device was found in a parsed netplan file
	ConfiguredAddress string // first configured address per netplan
	ConfiguredPeers   int    // peer count declared in netplan
	DriftCount        int    // peers whose live/configured states disagree
}

// PeerDisplayName returns the peer's name when known, else its truncated key.
func (p Peer) PeerDisplayName() string {
	if p.Name != "" {
		return p.Name
	}
	return ShortKey(p.PublicKey)
}

// Drift is the reconciliation state of a peer between the live kernel device and
// the netplan YAML (the configured intent). It is the heart of the merged read:
// a live-only peer won't survive a reboot; a config-only peer isn't up yet.
type Drift string

const (
	DriftNone          Drift = ""                // live and configured agree
	DriftNotPersistent Drift = "not-persistent"  // live in kernel, absent from netplan
	DriftConfigOnly    Drift = "config-only"     // in netplan, not present on the live device
	DriftConfig        Drift = "config-mismatch" // AllowedIPs/endpoint differ live vs netplan
)

// Peer is one WireGuard peer enriched with derived health fields, its display
// name, and its live-vs-configured drift. RX/TX history (for the sparkline) is
// filled in by the collector.
type Peer struct {
	PublicKey           string
	Name                string // from wg_peer_meta (SQLite), keyed by public key
	Endpoint            string
	AllowedIPs          []string
	LastHandshake       time.Time
	HandshakeAge        time.Duration // time.Since(LastHandshake); 0 when never
	Never               bool          // handshake never established
	ReceiveBytes        int64
	TransmitBytes       int64
	PersistentKeepalive time.Duration

	// Reconciliation against netplan.
	Drift                Drift
	ConfiguredOnly       bool     // declared in netplan but not on the live device
	ConfiguredAllowedIPs []string // AllowedIPs per netplan (for the mismatch view)
	ConfiguredEndpoint   string   // endpoint per netplan
	// RXHistory/TXHistory are per-tick byte deltas (most-recent last), used to
	// draw a throughput sparkline. Populated by the collector.
	RXHistory []float64
	TXHistory []float64
	// Severity is the handshake-health verdict for this peer (see anomaly.go).
	Severity Severity
	// Health is the peer's overall verdict: the worst of its handshake severity
	// and its device's tx/rx-error health (peers share the interface counters).
	Health Severity
}

// ShortKey returns a truncated public-key fingerprint for compact display, e.g.
// "abc123def4…". Public material only.
func ShortKey(k string) string {
	if len(k) <= 10 {
		return k
	}
	return k[:10] + "…"
}

// PeerName is the compact identifier shown in UIs and logs for a peer.
func (p Peer) PeerName() string { return ShortKey(p.PublicKey) }

// fromNetops converts the secrets-free netops read model into the enriched
// snapshot model, computing handshake age relative to now.
func fromNetops(devs []netops.WGDeviceInfo, now time.Time) []Device {
	out := make([]Device, 0, len(devs))
	for _, d := range devs {
		dev := Device{
			Name:         d.Name,
			PublicKey:    d.PublicKey,
			ListenPort:   d.ListenPort,
			FirewallMark: d.FirewallMark,
		}
		for _, p := range d.Peers {
			peer := Peer{
				PublicKey:           p.PublicKey,
				Endpoint:            p.Endpoint,
				AllowedIPs:          append([]string(nil), p.AllowedIPs...),
				LastHandshake:       p.LastHandshake,
				ReceiveBytes:        p.ReceiveBytes,
				TransmitBytes:       p.TransmitBytes,
				PersistentKeepalive: p.PersistentKeepalive,
			}
			if p.LastHandshake.IsZero() {
				peer.Never = true
			} else {
				peer.HandshakeAge = now.Sub(p.LastHandshake)
			}
			peer.Severity = classifyPeer(peer)
			peer.Health = peer.Severity // baseline; collector folds device errors in
			dev.Peers = append(dev.Peers, peer)
		}
		out = append(out, dev)
	}
	return out
}

// HandshakeLabel renders a compact, human age for a peer's last handshake:
// "never", "12s ago", "4m ago".
func (p Peer) HandshakeLabel() string {
	if p.Never {
		return "never"
	}
	d := p.HandshakeAge
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
}
