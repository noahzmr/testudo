# Testudo — Engineering Task Specs

These are the actionable engineering specs derived from
[`docs/DIAGNOSTICS_ASSESSMENT.md`](../DIAGNOSTICS_ASSESSMENT.md). Each one takes
a single roadmap item from that assessment and turns it into a concrete plan:
what to build, where it lives in the codebase, how it surfaces in **both** UIs,
and how its measurements feed the **Network Quality** grade.

The assessment is the *diagnosis*. These specs are the *prescription*.

## Cross-cutting requirements (apply to every task below)

These three rules are non-negotiable for every task in this folder. Each spec
restates the specifics, but the principles are shared:

1. **Full TUI + Web UI parity — viewable *and* editable.**
   Every new piece of state must be (a) visible in the relevant Bubble Tea tab
   in [`internal/tui/`](../../internal/tui/) and (b) mirrored in the embedded
   web console in [`internal/web/`](../../internal/web/). Where the task adds a
   mutable resource (a counter to reset, a neighbour to flush, a rule to edit,
   a baseline to clear), it must be editable through the existing **modal
   workflow** in both UIs — never read-only-in-one, editable-in-the-other. The
   TUI is canonical; the web UI mirrors it (README §"Unified UI Architecture").
   A feature that only exists on the CLI is incomplete.

2. **Every new measurement is part of Network Quality.**
   Any metric a task produces that reflects connectivity health must be routed
   into the composite grade in [`internal/tui/grade.go`](../../internal/tui/grade.go)
   and [`internal/web/grade.go`](../../internal/web/grade.go) — either as a new
   weighted sub-score or folded into an existing one — and documented in the
   README "Network Quality Grade" table. "Stats that nobody scores" is an
   anti-goal: if it matters enough to collect, it matters enough to grade.
   Empty/unavailable inputs must map to a **neutral 100** so a host that lacks
   the signal isn't penalised (the existing grade contract).

3. **One engine, two faces, one event bus.**
   New data flows through [`internal/events/`](../../internal/events/) and is
   persisted via [`internal/storage/`](../../internal/storage/) so it is
   replayable (README §"Event-Driven Architecture"). No direct cross-module
   calls in the data plane. Anything observable live must be reconstructable in
   replay from a session ID.

## The tasks (roughly roadmap order)

| # | Spec | Theme | Assessment ref |
|---|---|---|---|
| 01 | [per-rule-nftables-counters.md](per-rule-nftables-counters.md) | Firewall debuggability | Immediate win #3, weakness §2-#1(firewall) |
| 02 | [conntrack-neigh-introspection.md](conntrack-neigh-introspection.md) | L3 state visibility | Short term #8, weakness §5 |
| 03 | [netlink-push-vs-poll.md](netlink-push-vs-poll.md) | Event-driven kernel state | Short term #10, weakness #7 |
| 04 | [rollup-baseline-quality-table.md](rollup-baseline-quality-table.md) | Baselines & real scoring | Short term #11, Part-2 gaps |
| 05 | [ipv6-data-path.md](ipv6-data-path.md) | Dual-stack correctness | Long term #12, §1a (critical) |
| 06 | [ebpf-telemetry.md](ebpf-telemetry.md) | Per-flow kernel telemetry | Long term #13 |
| 07 | [privilege-separation.md](privilege-separation.md) | Security / blast radius | Long term #14, weakness #4 |

## Spec format

Every spec follows the same skeleton so they read consistently:

- **Why** — the gap, quoted from the assessment.
- **Current state** — what exists in the tree today.
- **Goals / Non-goals**.
- **Design** — packages, types, kernel mechanism, concurrency model.
- **TUI** — exact tab, view, and edit affordance.
- **Web UI** — mirrored view and edit affordance.
- **Network Quality** — the sub-score or stat this contributes to the grade.
- **Storage / replay** — schema and event-bus integration.
- **Reliability & security**.
- **Testing** — what to unit-test (parsers/pure logic first).
- **Acceptance criteria** — a checklist that defines "done".
