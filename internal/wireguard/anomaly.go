package wireguard

import "time"

// Severity is the handshake-health verdict for a peer. It mirrors the canonical
// Testudo alert ladder plus an OK state for healthy peers.
type Severity string

const (
	SevOK       Severity = "OK"
	SevWarn     Severity = "WARN"
	SevError    Severity = "ERROR"
	SevCritical Severity = "CRITICAL"
)

// Handshake-staleness thresholds - the key WireGuard health signal. A tunnel can
// be UP with a dead peer; the last-handshake age is what reveals it.
const (
	// HandshakeWarn: a keepalive peer that hasn't handshaken in this long is
	// drifting - WARN.
	HandshakeWarn = 180 * time.Second
	// HandshakeError: any established peer this stale is effectively down -
	// ERROR.
	HandshakeError = 300 * time.Second
)

// classifyPeer maps a peer's handshake state to a severity:
//
//	never established .................... CRITICAL
//	handshake age > 300s ................. ERROR
//	handshake age > 180s w/ keepalive .... WARN
//	otherwise ........................... OK
//
// The >180s WARN is gated on persistent-keepalive because a peer without
// keepalive legitimately lets its handshake lapse when idle (WireGuard only
// re-handshakes when there is traffic), so flagging it would be noise.
func classifyPeer(p Peer) Severity {
	if p.Never {
		return SevCritical
	}
	if p.HandshakeAge > HandshakeError {
		return SevError
	}
	if p.PersistentKeepalive > 0 && p.HandshakeAge > HandshakeWarn {
		return SevWarn
	}
	return SevOK
}

// WorstSeverity returns the most severe peer verdict across a snapshot, or SevOK
// when there are no peers / no devices.
func (s Snapshot) WorstSeverity() Severity {
	worst := SevOK
	for _, d := range s.Devices {
		for _, p := range d.Peers {
			if severityRank(p.Severity) > severityRank(worst) {
				worst = p.Severity
			}
		}
	}
	return worst
}

// WorstOf returns the more severe of two verdicts.
func WorstOf(a, b Severity) Severity {
	if severityRank(b) > severityRank(a) {
		return b
	}
	return a
}

func severityRank(s Severity) int {
	switch s {
	case SevOK:
		return 0
	case SevWarn:
		return 1
	case SevError:
		return 2
	case SevCritical:
		return 3
	}
	return 0
}
