# Task 04 — Rollup / Baseline Quality Table & Real Scoring

> Read the [cross-cutting requirements](README.md#cross-cutting-requirements-apply-to-every-task-below) first: full TUI+Web parity, every stat feeds Network Quality, one event bus.

## Why

From the assessment (Part 2, "What's missing for a real network quality score"):

> **No baseline/anomaly-relative scoring beyond spike factors.** … there's no
> persisted *baseline profile* per target (per-hour-of-day, per-link) to compare
> "is tonight worse than normal."

And the storage recommendation:

> Add a **rollup table keyed (target, hour-bucket)** holding p50/p95/p99/loss/
> jitter for baseline comparison and long-horizon trends — separate from raw
> samples so retention can differ.

Plus Part 2 gaps: no p50/p99 (only min/max/avg/p95), no bufferbloat letter
grade, no ISP-degradation isolation. This task is where Network Quality grows
from "current snapshot" into "current *vs. normal*".

## Current state

- [`internal/metrics`](../../internal/metrics/) keeps a 256-sample rolling
  window with min/max/avg/**p95** and MAD jitter.
- [`grade.go`](../../internal/tui/grade.go) computes an instantaneous letter
  grade from current sub-scores (README §"Network Quality Grade") — no history,
  no baseline.
- SQLite stores raw samples + downsamples >24 h to 5-min buckets; there is **no**
  `(target, hour-bucket)` rollup and the `flows` table is cumulative (loses the
  time dimension — weakness #6).

## Goals

- A persisted **rollup table** keyed `(target, dow, hour)` holding
  p50/p95/p99/loss/jitter/samples — the per-target, per-hour-of-day baseline.
- Add **p50** and **p99** to the live percentile set.
- A **baseline-relative** signal: "RTT to 1.1.1.1 right now is 3.1× its Tuesday-
  21:00 median" → drives anomalies *and* a grade modifier.
- **Bufferbloat letter grade (A–F)** from the measured idle-vs-loaded delta.
- **ISP-degradation isolation**: decompose first-hop vs gateway vs WAN vs target
  into a single "where's the problem" verdict (reuses traceroute + the
  [`doctor`](../../internal/doctor/) layering).
- **Time-bucketed flow snapshots** so "what was talking at 02:00" is answerable.

## Non-goals

- Per-flow TCP RTT/cwnd from the kernel — that's [Task 06 (eBPF)](ebpf-telemetry.md);
  this task can consume it once available but doesn't block on it.

## Design

In [`internal/storage`](../../internal/storage/):

```sql
CREATE TABLE quality_rollup (
    target   TEXT NOT NULL,
    dow      INTEGER NOT NULL,   -- 0..6
    hour     INTEGER NOT NULL,   -- 0..23
    p50_rtt  REAL, p95_rtt REAL, p99_rtt REAL,
    loss_pct REAL, jitter_ms REAL,
    samples  INTEGER NOT NULL,
    updated  INTEGER NOT NULL,   -- unix ts
    PRIMARY KEY (target, dow, hour)
);

CREATE TABLE flow_snapshots (   -- periodic, timestamped (vs cumulative flows)
    ts INTEGER, iface TEXT, src TEXT, dst TEXT, proto TEXT,
    bytes_in INTEGER, bytes_out INTEGER, process TEXT, dns_name TEXT
);
```

- A rollup aggregator subscribes to metric samples and, each hour bucket,
  updates the `(target, dow, hour)` row via an exponential moving merge so the
  baseline adapts slowly (recent weeks dominate, old data decays). Separate
  retention from raw samples (keep rollups ~1 year; raw stays 30 days).
- `metrics` gains `P50()` / `P99()` alongside the existing percentiles (pure
  additions to the percentile computation).
- New `quality` package helper:
  `BaselineRatio(target string, now Sample) float64` — current value ÷ baseline
  for this dow/hour. Pure given the rollup row; trivially testable.
- **Bufferbloat grade:** map the measured Δ to A–F (`<30ms A … >300ms F`) — a
  pure function in the bufferbloat collector path.
- **ISP isolation:** a pure `IsolateFault(hops []TraceHop, gwRTT, wanRTT float64)`
  that returns `first-hop | gateway | WAN | target | none`, reusing the
  traceroute hop deltas already collected.
- Flow snapshotter writes a `flow_snapshots` row set on a timer (e.g. 60 s).

## TUI

- **Dashboard / Network Quality card:** each sub-score line gains a baseline
  badge — `RTT 18ms (≈ normal)` / `RTT 54ms (3.1× normal ▲)`. The single most
  requested operator signal: *is tonight worse than usual?*
- **Bufferbloat** shows its own A–F letter next to the delta.
- **A new "where's the problem" line** from `IsolateFault`: e.g. "Degradation
  isolated to: WAN (gateway healthy)".
- **History tab:** plot the rollup baseline as a band behind the live line, so
  the operator literally sees today's curve against the normal envelope.
- **Editable:** baselines are auto-learned, but the Settings modal gets a "Reset
  baseline for <target>" action (clears the rollup rows) for when the network
  legitimately changed (new ISP, moved desk) — write-gated like other settings.

## Web UI

- Dashboard grade card mirrors the baseline badges and the bufferbloat letter.
- History view renders the baseline band behind the live series.
- Settings panel exposes the same "Reset baseline" action.
- Snapshot/JSON exposes baseline ratios and the isolation verdict so both UIs
  and external consumers agree.

## Network Quality

This task **is** the Network Quality upgrade:

- The grade gains a **baseline-relative modifier**: when current metrics are far
  worse than the learned baseline for this hour, the letter is nudged down even
  if absolute thresholds aren't breached yet (early warning). Within normal
  envelope → no modifier (neutral).
- p50/p99 make the RTT/jitter sub-scores more honest (tail latency, not just avg).
- Bufferbloat letter and the ISP-isolation verdict become first-class grade
  context, documented in the README "Network Quality Grade" section.
- Empty baseline (first run / new target) → neutral, no penalty, per the
  existing contract.

## Storage / replay

- Rollup + flow snapshots persist; replay can show the baseline band for the
  session's moment in time and answer "what was talking at 02:00?".
- Add the **incident table cap/rotation** the assessment flags (weakness #6)
  while touching storage: bound `incidents`, time-bucket `flows`.

## Reliability & security

- All local SQLite; no new privilege.
- Rollup merge must be allocation-light and off the render path (runs on a
  worker, writes batched) — README performance rules.

## Testing

- Unit-test `P50`/`P99`, `BaselineRatio`, the bufferbloat A–F mapping, and
  `IsolateFault` — all pure, table-driven.
- Unit-test the EMA rollup merge (feed samples, assert the row converges).
- Unit-test rollup retention/rotation separate from raw-sample retention.

## Acceptance criteria

- [ ] `quality_rollup` + `flow_snapshots` tables exist with their own retention.
- [ ] p50/p99 added; baseline ratio computed per (target, dow, hour).
- [ ] Bufferbloat A–F grade and ISP-isolation verdict implemented (pure, tested).
- [ ] TUI: baseline badges, bufferbloat letter, isolation line, History baseline band, "reset baseline" action.
- [ ] Web UI mirrors all of the above incl. reset action.
- [ ] Grade gains a baseline-relative modifier; README grade table updated.
- [ ] `incidents` capped, `flows` time-bucketed.
- [ ] Pure-logic unit tests pass; `go vet` clean.
