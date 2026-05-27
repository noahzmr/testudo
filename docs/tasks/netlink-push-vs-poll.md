# Task 03 — Netlink Push (Subscribe) Instead of Poll

> Read the [cross-cutting requirements](README.md#cross-cutting-requirements-apply-to-every-task-below) first: full TUI+Web parity, every stat feeds Network Quality, one event bus.

## Why

From the assessment (weakness #7, Medium):

> **Polling where netlink could push.** Link/route/addr changes polled instead
> of subscribing to RTNETLINK multicast groups — slower detection, wasted ticks.

And the recommended additions:

> **Netlink push, not poll**: subscribe to `RTNLGRP_LINK`, `RTNLGRP_IPV4_ROUTE`,
> `RTNLGRP_NEIGH`, `RTNLGRP_IPV4_IFADDR` for instant change events (already
> importing `vishvananda/netlink` + `mdlayher/netlink`).

Today a link flap or a default-route change is only noticed on the next poll
tick (seconds of latency, and wasted CPU when nothing changes). The control
plane is *already* event-driven (README §"Event-Driven Architecture") — the
kernel state feeds just need to become real event sources instead of timers.

## Current state

- `iface_health.go` polls link up/running every 5 s (`IfaceHealthInterval`).
- Route changes are surfaced by re-reading the table, not by subscription.
- Address changes are inferred on the next interface poll.
- `vishvananda/netlink` (which has `LinkSubscribe`, `RouteSubscribe`,
  `AddrSubscribe`, `NeighSubscribe`) and `mdlayher/netlink` are both deps.

## Goals

- A single **netlink watcher** subsystem that subscribes to RTNETLINK multicast
  groups and publishes change events on the bus the instant the kernel emits
  them: link up/down, addr add/del, route add/del/change, neigh add/del/change.
- Polling collectors fall back to a **slow reconcile poll** (e.g. 60 s) purely
  as a safety net against missed multicast messages — not as the primary signal.
- Detection latency for a link flap drops from "up to one poll interval" to
  "sub-second".

## Non-goals

- Replacing the *statistics* polling (RX/TX byte counters still need periodic
  reads — there's no push for counters). This task is about **state-change**
  events, not metrics sampling.

## Design

New file [`internal/netops/watch.go`](../../internal/netops/watch.go) (or a
`internal/collectors/netlink_watch.go` collector):

```go
type NetlinkWatcher struct {
    Bus *events.Bus
}

// Run subscribes to RTNLGRP_LINK / IPV4_IFADDR / IPV6_IFADDR / IPV4_ROUTE /
// IPV6_ROUTE / NEIGH and translates each kernel message into a bus event until
// ctx is cancelled. It owns its goroutines and drains them on Stop.
func (w *NetlinkWatcher) Run(ctx context.Context) error
```

- Use `netlink.LinkSubscribeWithOptions(ch, done, opts)` etc. with a `done`
  channel wired to `ctx.Done()` so there are **no goroutine leaks** (a named
  weakness target — README coding standards).
- Each subscription runs in its own goroutine under the engine's central
  `sync.WaitGroup` (same lifecycle pattern the engine already uses).
- Translate to existing/new event kinds: `KindLinkStateChange`,
  `KindAddrChange`, `KindRouteChange`, `KindNeighChange`. Reuse the existing
  link-transition anomaly logic — it just gets fed by push instead of poll.
- **Debounce/coalesce**: a flapping link can emit a burst; coalesce within a
  short window (e.g. 250 ms) before publishing an anomaly, so the Alerts tab
  shows "eth0 flapped 6× in 2s" rather than six rows.
- Keep a **reconcile timer** (slow) that re-reads full state and diffs against
  last-known, catching any dropped multicast message.

## TUI

- **Interfaces / Routes tabs:** update **instantly** on kernel change (no longer
  gated by the poll tick). A small "live" indicator confirms the push feed is
  attached; if the watcher soft-failed, show "(polled — netlink subscribe
  unavailable)".
- **Alerts tab:** link/route/addr flaps appear immediately, coalesced.
- No new editable surface here — this task changes *how fast* existing views
  update, so the affordance is "freshness", surfaced as a status line.

## Web UI

- Snapshot endpoint already drives the web tables; with push, the underlying
  snapshot updates immediately, so the web Interfaces/Routes views reflect
  changes on their next refresh with zero added latency. Expose the
  watcher-attached vs polled status in the snapshot so the web header can show
  the same "live/polled" indicator.

## Network Quality

- **Link/route stability** is exactly the **Stab** sub-score. Faster, push-based
  flap detection makes Stab *accurate*: a 300 ms flap that a 5 s poll missed
  entirely now correctly drags the grade.
- Add a **flap-rate** input (transitions per minute on the egress interface) to
  Stab, with the existing neutral-100-when-quiet contract.
- Route churn (default route changing repeatedly) is an ISP/uplink instability
  signal — feed it into the WAN-side scoring as well.

## Storage / replay

- Push events persist like any other event, so replay gains **precise
  timestamps** for state changes (currently quantised to the poll interval).
  This sharpens incident timelines ("link dropped at 19:44:18.220").

## Reliability & security

- Reads only — no extra privilege beyond what link/route reads already need.
- If `*Subscribe` fails (restricted kernel, namespace), **soft-fail to polling**
  and report the subsystem as degraded (Task 07's self-status surface) — never
  crash.
- Bound the change channel; drop-with-counter on overflow rather than blocking
  the kernel reader.

## Testing

- Unit-test the **coalesce/debounce** logic with synthetic event bursts (pure
  timing logic, injectable clock).
- Unit-test the **reconcile-diff** that compares last-known vs freshly-read
  state and emits the right synthetic change events.
- Integration test in a netns: bring a veth up/down, assert a `KindLinkStateChange`
  event arrives sub-second.

## Acceptance criteria

- [ ] Watcher subscribes to link/addr/route/neigh groups and publishes bus events.
- [ ] Goroutines are tied to ctx; `go test -race` and a leak check are clean.
- [ ] Slow reconcile timer catches dropped messages.
- [ ] TUI Interfaces/Routes update sub-second; "live/polled" indicator present in both UIs.
- [ ] Flap-rate + route-churn feed the Stab/WAN grade inputs; documented in README.
- [ ] Replay shows precise change timestamps.
- [ ] Coalesce + reconcile unit tests pass; `go vet` clean.
