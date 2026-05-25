# Architecture

Testudo is organised as a set of loosely-coupled subsystems that communicate
through an in-process event bus. The data plane (packet capture → flow
aggregation) bypasses the bus to stay fast; the control plane (anomalies,
lifecycle, alerts) rides on it.

## Subsystem map

```text
                        ┌──────────────┐
                        │  collectors  │  ICMP / DNS / mDNS probes
                        └──────┬───────┘
                               │ events
   ┌──────────┐                ▼
   │  capture │──► flows ─► analyzers ─► incidents (alerts)
   └──────────┘     │            │
                    ▼            ▼
                topology      metrics ──► storage (SQLite)
                    │
                    └──► TUI / Web

                netops ◄── TUI / Web (gated by Writer.AllowWrites)
```

## Data flow

1. `capture.Multi` opens an AF_PACKET handle per interface and parses each
   frame into a `flows.FlowKey` + byte count.
2. The flow aggregator stores per-key counters in memory, bounded by
   `maxKeep` and evicted LRU-style.
3. `flows.Decorate` enriches snapshots with process / DNS / service info.
4. Analyzers (latency, loss, jitter, DNS timing) consume snapshots on a
   tick and publish `KindAnomaly` events when thresholds trip.
5. Incidents listens for anomalies, applies dedupe and severity policy,
   and exposes the live alert list to the TUI / web.
6. Replay sessions periodically snapshot flows, topology, firewall, and
   metrics into SQLite under `storage/sessions/<id>.db`.

## Storage layers

See [storage.md](storage.md). Briefly: ring buffer (RAM, seconds) → flow
aggregation (RAM, minutes) → SQLite metrics (disk, days) → selective PCAP
(disk, incident-scoped).

## Why the event bus skips packets

A single 1 Gbit/s NIC can produce 80k+ packets per second. Fanning that
through a channel-based bus would saturate the scheduler before any
analysis happened. Capture writes directly into `flows.Aggregator`; the
bus is reserved for low-frequency control signals.

## Module boundaries

* Subsystems never import each other's internals - they exchange typed
  values (`flows.FlowStats`, `discovery.Device`, `topology.Graph`) or
  events (`events.Event`).
* Kernel writes funnel through `netops.Writer`, which honours an explicit
  `AllowWrites` flag. The default in production is off.
* The TUI and Web UI share the same engine handles - they're two
  presentations of the same underlying state, not parallel implementations.
