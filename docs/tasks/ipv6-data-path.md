# Task 05 — IPv6 Across the Data Path

> Read the [cross-cutting requirements](README.md#cross-cutting-requirements-apply-to-every-task-below) first: full TUI+Web parity, every stat feeds Network Quality, one event bus.

## Why

This is the assessment's **#1 correctness gap** (§1a, Critical):

> IPv6 is effectively absent from the data path. ICMP/ping/traceroute hardcoded
> `ip4:icmp`. `filter.go`/`nat.go` explicit `TableFamilyIPv4` guards. capture
> `decode()` extracts only IPv4 + TCP/UDP, **drops ICMPv6, NDP, DHCPv6, RA**. No
> RA/SLAAC/DAD/NDP visibility at all. On any modern dual-stack network, Testudo
> is **blind to half the stack.**

The "IPv6 broken but IPv4 works" workflow is currently entirely unsupported.

## Current state (the v4-only chokepoints)

| Subsystem | File | v4-only because |
|---|---|---|
| Probes | [`internal/probes/probes.go`](../../internal/probes/probes.go) | `net.ResolveIPAddr("ip4", …)`, `icmp.ListenPacket("ip4:icmp", …)`, `ipv4.ICMPTypeEcho`, `IPv4PacketConn().SetTTL` |
| Doctor | [`internal/doctor/`](../../internal/doctor/) | route check filters `Family=="ipv4"`; WAN target is a v4 literal |
| Filter/NAT | `internal/netops/filter.go`, `nat.go` | `nftables.TableFamilyIPv4` guards |
| Capture | `internal/capture/capture.go` | `decode()` handles IPv4 + TCP/UDP only |

Note: `ListIfaces`/`ListRoutes`/neighbour reads already use `FAMILY_ALL`, so the
*inventory* side is partly v6-aware — it's the **active probes, filter/NAT, and
packet decode** that are blind.

## Goals

Dual-stack parity for the data path:

- **ICMPv6 probe path:** ping/traceroute over `ip6:ipv6-icmp` with
  `ipv6.ICMPTypeEchoRequest` and `IPv6PacketConn().SetHopLimit`, target-family
  auto-selected (or forced via flag).
- **Doctor v6 layer:** parallel v6 link/addr/route/gateway/DNS(AAAA)/WAN checks;
  the "IPv6 broken but IPv4 works" verdict falls straight out of the existing
  layered model run per-family.
- **filter/NAT v6:** `AF_INET6`/`TableFamilyIPv6` (and `inet` where dual) so v6
  rules are matched and shown.
- **capture decode v6:** extract IPv6, **ICMPv6, NDP (RS/RA/NS/NA), DHCPv6** so
  flows, anomalies and discovery see v6 traffic.
- **NDP/RA visibility:** router advertisements, SLAAC prefixes, DAD conflicts
  (pairs with [Task 02](conntrack-neigh-introspection.md)'s `AF_INET6` neighbour dump).

## Non-goals

- DHCPv6 *server* diagnostics beyond observing client exchanges (passive).

## Design

- **Probes:** add a `family` to `probes.Request` (`auto|4|6`); split `runICMP`/
  `runTraceroute` into a shared core parameterised by an `icmpProto` struct
  (`network, listenAddr, echoType, setTTL func`). `auto` resolves the target and
  picks the family of the first usable address. Keep the existing v4 behaviour
  as the default so nothing regresses.
- **Doctor:** the engine already orders `Check`s by layer; introduce a `Family`
  dimension and run the chain **twice** (v4, v6) where the host has addresses of
  that family, producing two ladders. `selectRootCause` already picks the
  lowest failing layer — extend the report to carry per-family verdicts so the
  UI can show "IPv4 ✔ / IPv6 ✗ at route".
- **filter/NAT:** parameterise the family; render family in the rule tables.
- **capture decode:** add the v6 + ICMPv6/NDP/DHCPv6 branches in `decode()`;
  emit NDP/RA as their own light event kinds for the L2/discovery analyzers.

## TUI

- Every table that shows addresses/routes/rules/flows gains a **family column /
  filter** (4 / 6 / both) — Interfaces, Routes, Firewall, NAT, Flows, Devices,
  Probes.
- **Probes tab:** family selector (auto/4/6) on the runner.
- **Doctor / Dashboard:** a **dual-stack health line** — "IPv4: healthy · IPv6:
  no default route" — the direct answer to "is my v6 broken?".
- **Devices/Neighbours:** show RA/SLAAC-learned prefixes and DAD conflicts.
- Editable surfaces (firewall/NAT/route modals) gain a family field so v6 rules
  and routes can be **created**, not just viewed — write-gated as usual.

## Web UI

- Same family columns/filters, same dual-stack health line, same family field in
  every create/edit modal. Snapshot/JSON carries family on every relevant record
  so both UIs and external consumers are dual-stack-consistent.

## Network Quality

- The grade becomes **dual-stack aware**. Two practical options, pick per the
  grade owner's preference and document it:
  1. **Worst-of** the two families per sub-score (conservative — a broken v6
     path correctly drags the grade), or
  2. a **separate v6 sub-score** with its own small weight.
- Recommended: WAN-side loss/RTT/jitter and DNS sub-scores measure **both**
  families and the grade reflects the worse of the two, with a per-family
  breakdown shown on hover/expand. A host with no v6 connectivity at all maps to
  **neutral** for v6 (don't punish v4-only networks) — same neutral-100 contract.
- README "Network Quality Grade" + "Target classification" tables updated to
  describe family routing.

## Storage / replay

- Add a `family` column to sample/flow/rule tables so historical data and replay
  distinguish v4 vs v6. Backfill defaults to `4` for existing rows.

## Reliability & security

- ICMPv6 raw sockets need `CAP_NET_RAW` (already held); the unprivileged
  `udp6`/`ipv6.ICMPType` ping fallback should mirror the v4 fallback.
- Soft-fail per family: a v4-only host must not error on v6 probe setup —
  report v6 as "unavailable", neutral to the grade.

## Testing

- Unit-test the family-selection logic (`auto` → correct proto for a v4 literal,
  a v6 literal, a dual-stack name).
- Unit-test the v6 branch of `decode()` against captured ICMPv6/NDP/RA/DHCPv6
  packet bytes (pure decode, no socket).
- Unit-test the doctor per-family root-cause selection (v4 ✔ / v6 fail).

## Acceptance criteria

- [ ] ICMPv6 ping + traceroute work; probe family selector (auto/4/6).
- [ ] Doctor produces per-family verdicts; "v4 ok / v6 broken" is reported.
- [ ] filter/NAT support v6; capture decodes v6 + ICMPv6/NDP/DHCPv6.
- [ ] Every UI table has a family column/filter; create/edit modals have a family field (both UIs).
- [ ] Dual-stack health line in TUI + Web.
- [ ] Grade is dual-stack aware with the neutral-for-absent-family contract; README updated.
- [ ] `family` column added to historical tables; replay distinguishes families.
- [ ] Family-selection + v6-decode + per-family doctor unit tests pass; `go vet` clean.
