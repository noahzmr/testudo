# Task 07 — Privilege Separation & Self-Status

> Read the [cross-cutting requirements](README.md#cross-cutting-requirements-apply-to-every-task-below) first: full TUI+Web parity, every stat feeds Network Quality, one event bus.

## Why

From the assessment (weakness #4, High; and the Security/Reliability summaries):

> **Monolithic process.** All collectors/analyzers/web in one PID with elevated
> caps. One panic can take the whole engine down; large attack surface holding
> CAP_NET_ADMIN. No seccomp.

> **Privilege separation:** split the CAP_NET_ADMIN-holding capture/netops into
> a thin helper; run web/TUI unprivileged; add a seccomp profile.

> One goroutine panic can crash the shared engine; add per-collector `recover()`
> + restart, and a self-status surface for soft-failed subsystems.

Today the web server (largest attack surface) runs in the **same PID** that
holds `CAP_NET_RAW`+`CAP_NET_ADMIN`. A web-plane compromise inherits raw socket
and netlink-write power. This task shrinks that blast radius.

## Current state

- Single process; capabilities granted via `setcap` on the one binary (README
  "Grant Capabilities").
- Writes gated by a single `--allow-netops-write` bool ([`netops.Writer`](../../internal/netops/iface.go));
  no per-op authz, no audit log of mutations.
- Collectors run as goroutines under one `WaitGroup`; a panic in one is not
  individually contained/restarted.
- No seccomp; no "which subsystems soft-failed" surface.

## Goals

1. **Privilege-dropping architecture:** a thin **privileged helper** holds the
   caps and performs the narrow set of operations that need them (raw sockets,
   AF_PACKET, netlink/nftables writes, eBPF load). The main engine — including
   the **web server and TUI — runs unprivileged**, talking to the helper over a
   local socket with a typed request/response protocol.
2. **Per-collector supervision:** each collector wrapped with `recover()` +
   bounded restart (backoff), so one panic degrades one subsystem, not the engine.
3. **Self-status surface:** a first-class "subsystem health" view (the assessment's
   "degraded subsystems" status) in both UIs.
4. **Audit log** of every privileged mutation; **seccomp** profile on the helper.

## Non-goals

- Multi-host/remote privilege brokering (single-host helper only).
- Replacing the `--allow-netops-write` gate — layer authz/audit on top of it.

## Design

### Helper / engine split

- New `cmd/testudo-helper` (or a re-exec of the same binary with a `__helper`
  subcommand) that retains caps and exposes a small **typed API** over a
  `SOCK_SEQPACKET` Unix socket with `SO_PEERCRED` checks:
  - `OpenICMPSocket`, `OpenAFPacket(iface)` → pass an fd back via `SCM_RIGHTS`.
  - `NetlinkWrite(op)` for the existing `netops.Writer` mutations.
  - `NftApply(rule)`, `ConntrackFlush(tuple)`, `EBPFLoad(obj)`.
- The engine drops caps at startup (after spawning/handshaking the helper) via
  `prctl(PR_SET_NO_NEW_PRIVS)` + clearing the bounding set, then runs the web/TUI
  with no special privilege.
- [`netops.Writer`](../../internal/netops/iface.go) gains a backend interface:
  `directBackend` (today's behaviour, for the helper) and `helperBackend` (RPC
  to the socket). The huge advantage: **call sites don't change** — `ListIfaces`,
  `AddRoute`, etc. keep their signatures; only the backend swaps.

### Supervision

- A `supervise(name string, run func(ctx) error)` wrapper used by the engine for
  every collector: `recover()` → log + emit `KindSubsystemDegraded` → restart
  with capped exponential backoff; after N failures, mark **permanently
  degraded** and stop retrying (no crash-loop).

### Self-status

- A `health.Registry` tracking each subsystem's state (`ok | degraded | failed |
  unprivileged`) with last error + restart count. Every soft-fail in the tree
  (capture without CAP_NET_RAW, netlink subscribe unavailable, eBPF unsupported,
  conntrack denied) reports here instead of silently no-op'ing.

### Audit & seccomp

- Every helper mutation appends to an `audit_log` table (`ts, op, args, peer_uid,
  result`) — closes the "no audit log of changes" security gap.
- A seccomp-bpf allowlist applied to the helper (it makes a *small* set of
  syscalls), and `PR_SET_NO_NEW_PRIVS` on the unprivileged engine.

## TUI

- **New "Status" / "Health" surface** (extend the existing Health tab): a table
  of subsystems with `STATE · LAST ERROR · RESTARTS · PRIVILEGE`. A capture that
  soft-failed for lack of caps shows `unprivileged` with the exact `setcap` hint
  — turning today's silent failures into an actionable list.
- **Settings:** the netops-write gate moves here as an explicit, **editable**
  toggle (it already is, via `--allow-netops-write`/Settings) and gains a view
  of the **audit log** (read-only scroll of recent mutations).
- The TUI itself now runs unprivileged — surfaced as a one-line "running
  unprivileged; privileged ops via helper (pid N)" status.

## Web UI

- Mirror the subsystem-health table and the audit-log view. Because the web
  server is now **unprivileged**, document and show that prominently (it also
  reduces the urgency of the separate HTTP/CSRF hardening item, though that
  stays its own fix). Mutating endpoints still funnel through the write gate,
  now backed by the helper + audit log.

## Network Quality

- **Observability of itself** is a rated dimension in the assessment
  ("Soft-fails silently; add a degraded-subsystems status — Medium"). Surface a
  small **self-health indicator** next to the Network Quality grade: if core
  signal collectors (ICMP, DNS, capture) are degraded/unprivileged, the grade
  card shows a "⚠ measuring with reduced coverage" badge so an A-grade isn't
  mistaken for "all good" when half the collectors are down.
- Degraded **measurement** sub-scores map to **neutral** (not falsely perfect)
  and are flagged, preserving the neutral-100 contract without hiding blind spots.

## Storage / replay

- `audit_log` persists; subsystem state transitions emit events so replay shows
  "capture went degraded at 19:44" alongside the incident.

## Reliability & security

- This task **is** the reliability/security hardening: smaller privileged
  surface, supervised collectors (no whole-engine crash), audited mutations,
  seccomp. It also unblocks safe rollout of [eBPF (Task 06)](ebpf-telemetry.md)
  by giving the loader a privileged home.

## Testing

- Unit-test `supervise` restart/backoff and the permanently-degraded transition
  (injected panicking func + fake clock).
- Unit-test the `health.Registry` state machine.
- Unit-test the helper RPC codec (encode/decode each op) without a real socket;
  integration-test fd-passing (`SCM_RIGHTS`) and `SO_PEERCRED` rejection.
- Verify the engine actually drops caps (assert `/proc/self/status` Cap* bits in
  an integration test).

## Acceptance criteria

- [ ] Privileged ops run in a thin helper; engine + web + TUI run unprivileged (caps dropped, verified).
- [ ] `netops.Writer` backend abstraction lets call sites stay unchanged.
- [ ] Helper enforces `SO_PEERCRED`, applies seccomp; engine sets `NO_NEW_PRIVS`.
- [ ] Every collector is supervised: panic → degrade+restart, never engine crash; `-race` clean.
- [ ] `health.Registry` powers a subsystem-status table in TUI **and** Web.
- [ ] All privileged mutations are audit-logged; audit log viewable in both UIs.
- [ ] Self-health badge on the Network Quality card; degraded measurements map to neutral + flagged; README updated.
- [ ] supervise/registry/RPC-codec unit tests pass; `go vet` clean.
