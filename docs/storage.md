# Storage Layers

Testudo deliberately avoids permanently storing every packet. Four layers
trade off retention against fidelity.

| Layer               | Medium     | Capacity              | Retention       | Implemented in                   |
| ------------------- | ---------- | --------------------- | --------------- | -------------------------------- |
| 1. Ring buffer      | RAM        | bounded by capacity   | seconds         | `internal/capture/ringbuffer.go` |
| 2. Flow aggregation | RAM        | `maxKeep` flows (LRU) | minutes         | `internal/flows/flow.go`         |
| 3. Metrics          | SQLite     | rolling time series   | days–weeks      | `internal/storage/sqlite.go`     |
| 4. Selective PCAP   | filesystem | per-incident files    | incident-scoped | `internal/capture/`              |

## Layer 1 - Ring buffer

`capture.RingBuffer` is a fixed-capacity circular buffer of `PacketRecord`s.
Push overwrites the oldest entry when full; Snapshot returns the buffer in
chronological order. Used by:

* the TUI live-render loop ("show me the last second of traffic")
* analyzers that need a short look-behind window
* instant replay before a session has been written to disk

The buffer holds defensive copies of payloads - callers own their input
slices.

## Layer 2 - Flow aggregation

`flows.Aggregator` collapses packets into bidirectional 5-tuple flows. Each
flow tracks packets, bytes, both-direction byte counters, first/last seen
timestamps, and optionally process / DNS / service / latency / loss. Memory
is bounded; the oldest flow is evicted when the table is full.

`flows.FlowSummary` is the persistence-friendly projection: flat fields,
`BytesIn` / `BytesOut` relative to the local endpoint, no `time.Time`
nesting. That's what's written to disk in layers 3 and the replay session
store.

## Layer 3 - Metrics

Time-series counters live in SQLite under `storage/metrics/`. Examples:

* latency (per target, per minute)
* packet loss (per interface, per minute)
* firewall hits (per rule)
* DNS resolution times (per resolver)
* alert counts (per severity)

Old buckets are downsampled rather than deleted - operators retain shape
forever, exact resolution for the last 30 days (configurable).

## Layer 4 - Selective PCAP

PCAP capture is OFF by default. It activates only when an anomaly engine
trips one of the configured triggers:

* packet loss bursts
* firewall anomalies
* DNS failures
* retransmission spikes
* route instability
* NAT exhaustion

Files land in `storage/captures/`, rotate by size, and are pruned by
retention policy.
