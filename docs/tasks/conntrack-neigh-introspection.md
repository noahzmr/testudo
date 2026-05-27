# Task 02 — Conntrack & Neighbour (ARP/NDP) Introspection

> Read the [cross-cutting requirements](README.md#cross-cutting-requirements-apply-to-every-task-below) first: full TUI+Web parity, every stat feeds Network Quality, one event bus.

## Why

From the assessment (weakness §5, "No L3 state introspection — High"):

> No netlink NEIGH (ARP/NDP) dump, no conntrack table read, no policy routing —
> blinds NAT/duplicate-IP/asymmetric-route troubleshooting.

And the capability matrix:

> **ARP/NDP inspection — Partial.** parses `/proc/net/arp` for churn … No NDP
> (IPv6 neighbor), no netlink NEIGH dump, no stale/incomplete/duplicate-IP
> analysis.
> **NAT behavior — Partial.** … **No conntrack table inspection** (can't see/flush
> live NAT'd flows).

These two share a kernel mechanism (`mdlayher/netlink` over NFNL/RTNL) and the
same troubleshooting payoff, so they ship together.

## Current state

- L2/ARP: [`internal/netops`](../../internal/netops/) and the L2 collector parse
  `/proc/net/arp` for churn only — no netlink NEIGH, no IPv6 neighbours, no
  state flags (REACHABLE/STALE/FAILED/INCOMPLETE).
- NAT: only a conntrack **count** is read (for the NAT-exhaustion anomaly); the
  live conntrack *table* is invisible. DNAT rules can be added/listed but you
  can't see or flush an active translated flow.
- `mdlayher/netlink` is already a dependency.

## Goals

- **Neighbour table** via RTNETLINK `RTM_GETNEIGH` for both `AF_INET` (ARP) and
  `AF_INET6` (NDP): IP, MAC, dev, state, flags, with **duplicate-IP** and
  **stale/incomplete** analysis.
- **Conntrack table** via NFNL (`nf_conntrack`): per-flow original/reply tuples,
  protocol, state, NAT mark, bytes/packets, timeout — and the ability to
  **flush** a selected entry.
- Both surfaced and (where it makes sense) mutable in TUI + Web.

## Non-goals

- Policy routing (`ip rule`) — separate task.
- Writing neighbour entries (read + duplicate detection only).

## Design

New file [`internal/netops/neigh.go`](../../internal/netops/neigh.go):

```go
type Neighbour struct {
    IP      string
    MAC     string
    Dev     string
    Family  string // ipv4 / ipv6
    State   string // REACHABLE / STALE / DELAY / PROBE / FAILED / INCOMPLETE / PERMANENT
    Router  bool   // NDP: is this neighbour a router
}

func (w *Writer) ListNeighbours() ([]Neighbour, error) // RTM_GETNEIGH, FAMILY_ALL

// DuplicateIPs returns IPs answered by more than one MAC (conflict / rogue).
func DuplicateIPs(ns []Neighbour) []IPConflict
```

New file [`internal/netops/conntrack.go`](../../internal/netops/conntrack.go):

```go
type ConntrackFlow struct {
    Proto       string
    OrigSrc, OrigDst string
    OrigSport, OrigDport uint16
    ReplySrc, ReplyDst   string // != Orig when NAT'd
    State       string // ESTABLISHED / TIME_WAIT / ...
    NATed       bool
    Packets, Bytes uint64
    TimeoutSec  int
}

func (w *Writer) ListConntrack() ([]ConntrackFlow, error)          // NFNL dump
func (w *Writer) FlushConntrack(f ConntrackFlow) error             // write-gated
```

- Use `mdlayher/netlink` to issue the dump; decode attributes in pure helpers
  (`parseNeighMsg`, `parseCtAttrs`) that take raw bytes → struct, so they unit
  test without a kernel.
- `DuplicateIPs` and the stale/incomplete classification are pure functions over
  the decoded slice.
- A new collector polls neighbours + conntrack on a slow cadence (config
  `NeighInterval`, `ConntrackInterval`) and publishes deltas to the event bus
  (new kinds `KindNeighChange`, `KindDuplicateIP`).

## TUI

- **Devices tab:** enrich each device row with neighbour **state** and a
  conflict badge; a new "Neighbours" sub-view lists the full ARP/NDP table with
  state, filterable by family. Duplicate-IP rows are highlighted red.
- **NAT tab:** a new "Conntrack" section lists live (NAT'd) flows. Selecting a
  flow offers **Flush** (write-gated; greys out with the standard toast when
  writes are off). This is the "kill a stuck translated flow" affordance.
- Both are reachable through existing tab navigation; flush uses the standard
  confirm modal.

## Web UI

- Devices view gains the neighbour table + conflict badges; NAT view gains the
  conntrack table with a per-row **Flush** button behind the netops-write gate.
- JSON snapshot exposes `[]Neighbour` and `[]ConntrackFlow` so both UIs render
  from one source.

## Network Quality

- **Duplicate IP detected** is a hard local-network fault → emit `KindDuplicateIP`
  (WARN/ERROR) and apply a penalty to the **LAN** sub-score in
  [`grade.go`](../../internal/tui/grade.go) for as long as the conflict persists.
  A clean neighbour table = neutral 100.
- **Conntrack utilisation** (live entries ÷ `nf_conntrack_max`) folds into the
  existing NAT-exhaustion signal; near-saturation drags the grade and fires the
  existing exhaustion anomaly with real numbers instead of a bare count.
- **Stale/failed neighbour ratio** on the egress path contributes to the **Stab**
  sub-score (failed gateway neighbour = imminent connectivity loss).

## Storage / replay

- `neighbours` and `conntrack_samples` tables (timestamped snapshots), so replay
  answers "was there an IP conflict at 02:00?" and "what was NAT'd during the
  incident?". Incident bundles include a conntrack snapshot.

## Reliability & security

- Reads need `CAP_NET_ADMIN` for conntrack on some kernels; soft-fail to a
  "degraded subsystem" status (see Task 07) rather than crashing.
- `FlushConntrack` is write-gated and audit-logged (tuple + result).
- Bound the conntrack dump (cap rows rendered; the table can be huge on a busy
  router) — paginate in the UI, stream-decode in the collector.

## Testing

- Unit-test `parseNeighMsg` / `parseCtAttrs` against captured netlink byte
  fixtures (REACHABLE v4, STALE v6 router, NAT'd TCP flow).
- Unit-test `DuplicateIPs` and stale-ratio classification with table-driven cases.

## Acceptance criteria

- [ ] `ListNeighbours` returns v4+v6 neighbours with state; `DuplicateIPs` flags conflicts.
- [ ] `ListConntrack` returns live flows incl. NAT mapping; `FlushConntrack` works, write-gated, audited.
- [ ] TUI Devices (neighbours + conflict badge) and NAT (conntrack + flush) views land.
- [ ] Web UI mirrors both, including the flush button behind the write gate.
- [ ] Duplicate-IP → LAN penalty; conntrack utilisation → NAT-exhaustion grade input; documented in README.
- [ ] Neighbour/conntrack snapshots persist and replay; conntrack in incident bundles.
- [ ] Parser unit tests pass; `go vet` clean.
