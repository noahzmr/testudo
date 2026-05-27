// Package flows aggregates packet-level updates into bidirectional 5-tuple
// summaries. Each FlowKey normalises endpoint order so traffic in both
// directions of a single conversation collapses into one entry.
package flows

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Endpoint identifies one side of a flow.
type Endpoint struct {
	IP   string
	Port uint16
}

func (e Endpoint) String() string {
	if e.Port == 0 {
		return e.IP
	}
	return net.JoinHostPort(e.IP, fmt.Sprintf("%d", e.Port))
}

// FlowKey identifies a bidirectional flow. A is always the lexicographically
// smaller endpoint; B is the larger. Iface lets a single conversation be
// tracked separately on each interface it traverses (NAT, bridges, VPN).
type FlowKey struct {
	Iface string
	A, B  Endpoint
	Proto string
}

// FlowStats holds aggregated counters for one flow key. Process and DNSName
// are populated by correlators after-the-fact; they may be empty.
type FlowStats struct {
	Key         FlowKey
	Packets     uint64
	Bytes       uint64
	FirstSeen   time.Time
	LastSeen    time.Time
	BytesAtoB   uint64
	BytesBtoA   uint64
	Process     string  // populated by proc-correlation
	ProcessName string  // alias used by external consumers / replay format
	DNSName     string  // populated by DNS reverse-correlation
	Service     string  // populated by services catalog (e.g. "HTTPS")
	AvgLatency  float64 // ms, populated by analyzers
	PacketLoss  float64 // 0..1, populated by analyzers

	// Cross-subsystem correlation tags populated by the engine's correlator.
	// Empty when the relevant subsystem hasn't observed this flow.
	FirewallChain string // e.g. "INPUT/ACCEPT" or "FORWARD/DROP"
	NATMapping    string // e.g. "DNAT 192.168.1.10:443 => 10.0.0.5:443"
	RouteVia      string // e.g. "10.0.0.1 dev eth0"

	// TCP carries per-flow TCP quality joined from the telemetry source
	// (INET_DIAG/ss -ti or eBPF). TCP.Source is empty when no telemetry has
	// been observed for this flow. See internal/telemetry.
	TCP FlowTCPStats
}

// FlowTCPStats holds per-flow TCP quality sampled from tcp_info - delivered by
// the kernel via INET_DIAG (pure-Go, Stage A) or an eBPF tracepoint (Stage B).
// It joins the flow table on the same 5-tuple key so the Flows tab enriches in
// place rather than maintaining a parallel table. Source tags the backend so
// the UI can label it the way WiFi labels its nl80211/proc backend.
type FlowTCPStats struct {
	RTTus       uint32    // smoothed RTT, microseconds (tcpi_rtt)
	RTTVarus    uint32    // RTT variance, microseconds (tcpi_rttvar)
	Retrans     uint32    // cumulative total retransmits (tcpi_total_retrans)
	RetransRate float64   // derived per-interval: % of segments retransmitted
	Cwnd        uint32    // congestion window in segments (tcpi_snd_cwnd)
	Source      string    // "inet_diag" | "ebpf"; empty when unobserved
	Updated     time.Time // when this sample was applied
}

// HasTCP reports whether per-flow TCP telemetry has been observed for this flow.
func (fs FlowStats) HasTCP() bool { return fs.TCP.Source != "" }

// RTTms returns the smoothed RTT in milliseconds for rendering/grade math.
func (s FlowTCPStats) RTTms() float64 { return float64(s.RTTus) / 1000.0 }

// FlowSummary is the Layer-2 storage shape: a flat, persistence-friendly
// projection of a FlowStats with both directions of byte counters separated
// into BytesIn / BytesOut relative to the local endpoint (Endpoint A).
//
// This matches the schema documented in CLAUDE.md and is what the storage
// and replay layers serialise.
type FlowSummary struct {
	Interface string

	SrcIP string
	DstIP string

	Protocol string

	BytesIn  uint64
	BytesOut uint64

	AvgLatency float64
	PacketLoss float64

	DNSName     string
	ProcessName string
}

// Summarize projects a FlowStats into the persistence-friendly FlowSummary
// shape. BytesIn/BytesOut are taken relative to endpoint A (the
// lexicographically smaller endpoint, treated as the "local" side).
func (fs FlowStats) Summarize() FlowSummary {
	proc := fs.ProcessName
	if proc == "" {
		proc = fs.Process
	}
	return FlowSummary{
		Interface:   fs.Key.Iface,
		SrcIP:       fs.Key.A.IP,
		DstIP:       fs.Key.B.IP,
		Protocol:    fs.Key.Proto,
		BytesIn:     fs.BytesBtoA,
		BytesOut:    fs.BytesAtoB,
		AvgLatency:  fs.AvgLatency,
		PacketLoss:  fs.PacketLoss,
		DNSName:     fs.DNSName,
		ProcessName: proc,
	}
}

// Aggregator is the in-memory flow table. Safe for concurrent use.
type Aggregator struct {
	mu      sync.RWMutex
	table   map[FlowKey]*FlowStats
	maxKeep int // bounds memory; oldest are evicted when exceeded
}

func NewAggregator() *Aggregator {
	return &Aggregator{table: make(map[FlowKey]*FlowStats), maxKeep: 4096}
}

// Update merges a single packet observation into the aggregator.
func (a *Aggregator) Update(iface string, srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string, bytes uint64) {
	src := Endpoint{IP: srcIP, Port: srcPort}
	dst := Endpoint{IP: dstIP, Port: dstPort}
	key, srcIsA := canonicalKey(iface, src, dst, proto)

	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	st, ok := a.table[key]
	if !ok {
		if len(a.table) >= a.maxKeep {
			a.evictOldest()
		}
		st = &FlowStats{Key: key, FirstSeen: now}
		a.table[key] = st
	}
	st.Packets++
	st.Bytes += bytes
	st.LastSeen = now
	if srcIsA {
		st.BytesAtoB += bytes
	} else {
		st.BytesBtoA += bytes
	}
}

// ApplyTCPStats joins a per-flow TCP telemetry sample onto the flow table.
// The directional (src,dst) tuple is canonicalised to the same key the capture
// path uses, so telemetry enriches an existing flow in place. When no flow is
// tracked yet (e.g. capture is disabled) the entry is created so the TCP stats
// are still surfaced - the socket is, by definition, active. LastSeen is bumped
// so a telemetry-only flow isn't immediately evicted as stale.
func (a *Aggregator) ApplyTCPStats(iface, srcIP string, srcPort uint16, dstIP string, dstPort uint16, proto string, st FlowTCPStats) {
	key, _ := canonicalKey(iface, Endpoint{IP: srcIP, Port: srcPort}, Endpoint{IP: dstIP, Port: dstPort}, proto)

	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	fs, ok := a.table[key]
	if !ok {
		if len(a.table) >= a.maxKeep {
			a.evictOldest()
		}
		fs = &FlowStats{Key: key, FirstSeen: now}
		a.table[key] = fs
	}
	st.Updated = now
	fs.TCP = st
	if fs.LastSeen.Before(now) {
		fs.LastSeen = now
	}
}

// TopByRecency returns up to n flows sorted by most-recent activity.
func (a *Aggregator) TopByRecency(n int) []FlowStats {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]FlowStats, 0, len(a.table))
	for _, st := range a.table {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Snapshot returns a defensive copy of every flow currently tracked.
func (a *Aggregator) Snapshot() []FlowStats {
	return a.TopByRecency(0)
}

// Reset empties the flow table. Useful when an operator wants a clean slate
// without restarting the engine - e.g. after enabling/disabling capture from
// the TUI.
func (a *Aggregator) Reset() {
	a.mu.Lock()
	a.table = make(map[FlowKey]*FlowStats)
	a.mu.Unlock()
}

// canonicalKey returns the FlowKey with endpoints ordered, plus a flag
// indicating whether the original src is endpoint A.
func canonicalKey(iface string, src, dst Endpoint, proto string) (FlowKey, bool) {
	if endpointLess(src, dst) {
		return FlowKey{Iface: iface, A: src, B: dst, Proto: proto}, true
	}
	return FlowKey{Iface: iface, A: dst, B: src, Proto: proto}, false
}

func endpointLess(a, b Endpoint) bool {
	if a.IP != b.IP {
		return a.IP < b.IP
	}
	return a.Port < b.Port
}

// evictOldest removes the least-recently-seen flow. Caller holds a.mu.
func (a *Aggregator) evictOldest() {
	var oldestKey FlowKey
	var oldestTime time.Time
	first := true
	for k, v := range a.table {
		if first || v.LastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.LastSeen
			first = false
		}
	}
	if !first {
		delete(a.table, oldestKey)
	}
}
