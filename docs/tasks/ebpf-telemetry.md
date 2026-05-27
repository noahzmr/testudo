# Task 06 — eBPF Telemetry (Per-Flow TCP, Flow Accounting, Drop Reasons)

> Read the [cross-cutting requirements](README.md#cross-cutting-requirements-apply-to-every-task-below) first: full TUI+Web parity, every stat feeds Network Quality, one event bus.

## Why

From the assessment ("Recommended technical additions — eBPF opportunities, the
biggest long-term lever"):

> - `tcp_info`/`sock_ops` or just `ss -ti` parsing for per-flow RTT/RTX/cwnd —
>   far richer than `/proc/net/snmp` aggregates.
> - XDP/tc for high-rate flow accounting without per-packet userspace cost.
> - `kprobe`/tracepoint on `icmp_send`/`fib` for drop-reason and frag-needed events.

And Part 2:

> **Per-flow TCP quality** (RTX rate, RTT, cwnd) from `tcp_info`/`ss -ti` is
> absent — this is the single highest-value passive quality signal on a busy host.

## Current state

- Congestion/retransmissions are read **system-wide** from `/proc/net/snmp`
  (coarse — you can't attribute RTX to a flow).
- Flow accounting is done in userspace from AF_PACKET capture (correct call for
  now — the bus is deliberately bypassed for per-packet data, README
  §"Event-Driven Architecture").
- No drop-reason / frag-needed visibility.

## Goals

A new, **optional, capability-gated** telemetry source that delivers what
userspace can't cheaply get:

- **Per-flow TCP quality**: RTT (smoothed), RTX count/rate, cwnd, retransmit
  timeouts — keyed by 5-tuple, joinable to the existing flow table.
- **Low-overhead flow accounting** at high packet rates (XDP/tc) without the
  per-packet userspace cost.
- **Drop-reason / frag-needed events** (PMTU black-hole detection, fib failures).

## Design — staged, with a safe fallback first

Pure-Go is a core project value (no cgo). eBPF changes that calculus, so stage
it so the **fallback ships first and the eBPF path is strictly additive**:

### Stage A — `ss -ti` parser (no eBPF, ships immediately)

- New collector that parses `ss -tin` (or reads `tcp_info` via `SO_..` netlink
  `INET_DIAG`) for per-flow `rtt`, `retrans`, `cwnd`. `INET_DIAG` over
  `mdlayher/netlink` keeps it pure-Go and needs no exec.
- This alone closes the "per-flow TCP quality" gap and is the prerequisite data
  shape for the UI + grade work below.

### Stage B — eBPF (build-tagged, optional)

- A `//go:build ebpf` package using `cilium/ebpf` (pure-Go loader, CO-RE) with
  precompiled objects. Programs: a `sock_ops`/`tcp` tracepoint for per-flow
  stats, an optional XDP/tc program for flow byte/packet accounting, and
  `kprobe`/tracepoint on drop paths for drop-reason + frag-needed.
- The binary detects kernel/BTF support at runtime and **falls back to Stage A**
  when eBPF is unavailable. Default build stays pure-Go; eBPF is opt-in.

Shared model (`internal/telemetry` or extend [`internal/flows`](../../internal/flows/)):

```go
type FlowTCPStats struct {
    Key       FlowKey // existing 5-tuple
    RTTus     uint32
    RTTVarus  uint32
    Retrans   uint32  // cumulative
    RetransRate float64 // derived per-interval
    Cwnd      uint32
    Source    string  // "inet_diag" | "ebpf"
}
```

- Stats join the existing flow aggregator (same key), so the Flows tab enriches
  in place — no parallel flow table.
- Drop-reason and frag-needed publish as event-bus anomalies
  (`KindDropReason`, `KindFragNeeded`), feeding the existing analyzer/incident
  path. Frag-needed is the long-missing **PMTU black-hole** signal.

## TUI

- **Flows / Talkers tabs:** per-flow columns `RTT · RTX% · CWND`, with a source
  tag (`inet_diag`/`ebpf`) shown the same way WiFi already labels its backend.
  High-RTX flows sort to the top — the "which connection is actually suffering"
  view.
- **Alerts tab:** drop-reason and frag-needed anomalies, naming the flow.
- **Health tab:** a telemetry-source status card (eBPF attached / inet_diag
  fallback / unavailable).
- This data is observational; the editable affordance is the **toggle** in
  Settings (enable/disable eBPF, set RTX-rate alert threshold) — write-gated.

## Web UI

- Flows/Talkers views mirror the per-flow TCP columns + source tag; Settings
  panel mirrors the enable/disable + threshold controls. Snapshot/JSON exposes
  `FlowTCPStats` so both UIs render identical numbers.

## Network Quality

- **Per-flow RTX rate** is a far better congestion signal than the current
  system-wide `/proc/net/snmp` number. Replace/augment the retransmission input
  to the grade's congestion handling with the **flow-weighted RTX rate** (busy
  flows count more), keeping neutral-100 when there are no active TCP flows.
- **Frag-needed / PMTU black-hole** detected → penalty + anomaly (this is a
  real "some sites won't load" fault the grade should reflect).
- **Worst-flow RTT** can sharpen the RTT sub-score on a busy host (the path the
  user actually cares about, not just the probe target).
- README grade table updated to note the eBPF/inet_diag-sourced congestion input.

## Storage / replay

- Persist periodic per-flow TCP stat snapshots (timestamped, joins the flow
  snapshot work in [Task 04](rollup-baseline-quality-table.md)); incident
  bundles include the worst flows' TCP stats. Drop-reason events replay.

## Reliability & security

- eBPF needs `CAP_BPF`/`CAP_NET_ADMIN` (and a recent kernel + BTF). **Strictly
  optional and gated**; absence is a degraded-subsystem status (Task 07), never
  a crash. This also dovetails with **privilege separation**: the eBPF loader is
  a natural candidate for the thin privileged helper rather than the monolith.
- Bound map sizes; pin nothing persistently; detach cleanly on `ctx.Done()` to
  avoid leaking kernel objects.

## Testing

- Unit-test the **`ss -ti` / `INET_DIAG` parser** against captured output/bytes
  (pure — the highest-regression-risk piece, exactly where the assessment says
  to start testing).
- Unit-test the RTX-rate derivation (cumulative → per-interval) and the
  flow-weighting used for the grade.
- eBPF programs behind a build tag; integration-test in CI only where BTF is
  available, with the pure-Go fallback always covered.

## Acceptance criteria

- [ ] Stage A (`INET_DIAG`/`ss -ti`) per-flow RTT/RTX/cwnd ships pure-Go, default build.
- [ ] Stage B eBPF path is build-tagged, CO-RE, with runtime detection + fallback.
- [ ] Stats join the existing flow aggregator (one flow table, source-tagged).
- [ ] Drop-reason + frag-needed (PMTU) anomalies on the bus.
- [ ] TUI + Web show per-flow TCP columns, source tag, and the Settings toggles.
- [ ] Flow-weighted RTX rate + PMTU black-hole feed the grade; README updated.
- [ ] Per-flow stat snapshots persist + replay; in incident bundles.
- [ ] Parser + RTX-rate unit tests pass; default build stays cgo-free; `go vet` clean.
