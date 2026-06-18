// Package telemetry delivers per-flow TCP quality (RTT, retransmits, cwnd) and
// drop-reason / frag-needed signals that userspace can't cheaply derive from
// /proc/net/snmp aggregates.
//
// It is staged so the pure-Go fallback ships first and any eBPF path is
// strictly additive (see docs/tasks/ebpf-telemetry.md):
//
//   - Stage A (this file + inetdiag.go): an INET_DIAG / tcp_info reader over
//     netlink. Pure Go, no cgo, no exec - the default build.
//   - Stage B (ebpf.go, behind //go:build ebpf): a CO-RE eBPF source that
//     falls back to Stage A when the kernel/BTF support is absent.
//
// The numeric derivations below (per-interval RTX rate, flow-weighted RTX,
// worst-flow RTT) are pure functions so they can be unit-tested without a
// kernel - exactly the highest-regression-risk pieces.
package telemetry

// Source identifiers, surfaced to the UI as a backend tag.
const (
	SourceInetDiag = "inet_diag"
	SourceEBPF     = "ebpf"
)

// EBPFInfo describes the eBPF telemetry backend for this build and host. It
// drives the Health-tab status card and the source tag. The actual probe is
// build-tagged: the default (cgo-free, no-eBPF) build always reports
// Compiled=false; the //go:build ebpf build does runtime BTF/capability
// detection and falls back to Stage A (INET_DIAG) when support is missing.
// EBPFStatus is provided by detect_ebpf.go / detect_noebpf.go.
type EBPFInfo struct {
	Compiled  bool   // built with -tags ebpf
	Available bool   // eBPF programs attachable on this host right now
	Detail    string // human-readable status for the Health card
}

// TCP socket states (linux/tcp_states.h) the active-traffic monitor
// distinguishes. Only the connection-setup states are named; everything else is
// treated as an up/established connection for grading purposes.
const (
	TCPEstablished uint8 = 1
	TCPSynSent     uint8 = 2
	TCPSynRecv     uint8 = 3
	TCPTimeWait    uint8 = 6
)

// IsConnecting reports whether a socket is still completing its TCP handshake
// (SYN_SENT / SYN_RECV) rather than established. A socket that lingers in this
// state across samples is a connection that cannot establish - the kernel-side
// view of the "request canceled while waiting for connection" / connect-timeout
// fault that userspace HTTP clients report.
func IsConnecting(state uint8) bool {
	return state == TCPSynSent || state == TCPSynRecv
}

// ActiveSource reports which backend per-flow TCP stats are coming from, given
// the build's eBPF status. It is the label shown next to the flow columns.
func ActiveSource(info EBPFInfo) string {
	if info.Available {
		return SourceEBPF
	}
	return SourceInetDiag
}

// RetransRate computes the per-interval retransmission percentage from two
// cumulative tcp_info samples: dRetrans / dSegsOut * 100. It returns 0
// (neutral) when no new segments were sent, when the window is empty, or when a
// counter went backwards (socket reuse / counter reset) - never a negative or
// runaway rate.
func RetransRate(prevRetrans, prevSegsOut, curRetrans, curSegsOut uint64) float64 {
	if curSegsOut <= prevSegsOut || curRetrans < prevRetrans {
		return 0
	}
	dSegs := curSegsOut - prevSegsOut
	if dSegs == 0 {
		return 0
	}
	dRetrans := curRetrans - prevRetrans
	rate := float64(dRetrans) / float64(dSegs) * 100
	if rate > 100 {
		rate = 100
	}
	return rate
}

// RTXSample is one flow's contribution to the flow-weighted retransmission
// rate: its per-interval rate and the bytes it moved over the window.
type RTXSample struct {
	Rate  float64 // per-interval RTX rate, percent
	Bytes uint64  // throughput weight; busy flows count more
}

// FlowWeightedRTX returns the byte-weighted mean retransmission rate across the
// supplied active TCP flows. Busy flows dominate, so a single idle flow
// retransmitting once doesn't drag the whole host's congestion signal down.
// ok=false when there are no active flows, so the grade can stay neutral-100
// rather than reading a fabricated 0 as "perfect".
//
// Flows that moved no bytes still count with unit weight so a stalled-but-
// retransmitting flow (the PMTU black-hole shape) isn't silently dropped.
func FlowWeightedRTX(samples []RTXSample) (rate float64, ok bool) {
	if len(samples) == 0 {
		return 0, false
	}
	var num, den float64
	for _, s := range samples {
		w := float64(s.Bytes)
		if w < 1 {
			w = 1
		}
		num += s.Rate * w
		den += w
	}
	if den == 0 {
		return 0, false
	}
	return num / den, true
}

// WorstFlowRTT returns the largest RTT (ms) across the supplied flows. ok=false
// when the slice is empty so the caller can leave the RTT sub-score on the
// probe target rather than reading 0 as "perfect".
func WorstFlowRTT(rttMs []float64) (worst float64, ok bool) {
	for _, v := range rttMs {
		if v > worst {
			worst = v
		}
		ok = true
	}
	return worst, ok
}
