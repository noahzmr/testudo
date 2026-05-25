# Topology

The topology subsystem builds an in-memory graph of devices and the
conversations between them. It runs passively - no active scans are
issued by `internal/topology/`. Scans, when needed, come from
`internal/discovery/`.

## Inputs

* `discovery.Device` snapshots - the inventory of known hosts (IP, MAC,
  hostname, vendor, interface, OS hint, last-seen).
* `flows.FlowStats` snapshots - observed conversations with directional
  byte counts and timestamps.

## Outputs

`topology.Graph`:

* `Nodes []Node` - one per IP we've ever seen, sorted by IP. Nodes that
  appear in flows but not in discovery are still added (with only IP and
  last-seen populated).
* `Edges []Edge` - directed (src→dst) per interface and protocol, sorted
  by total bytes descending.

Each edge accumulates bytes and packets across every flow that matched
its (src, dst, iface, proto) key. `LastSeen` is the most recent
contribution.

## Lifecycle

The TUI and Web topology tabs call `Builder.Build` on a tick (default
2s). The Builder caches the last result so re-reads from the UI are
free.

## What this isn't

* Not a network map in the SNMP / LLDP sense - it's a flow-derived view.
  A device that doesn't talk doesn't appear in edges (it still appears
  in nodes if discovery saw it).
* Not authoritative for direction. A flow's "A → B" direction is chosen
  by lexicographic ordering of the endpoints, then split into BytesAtoB
  and BytesBtoA. The topology builder treats those as two directed edges.
* Not transitive. We don't infer "host X reaches subnet Y via router Z"
  - that requires routing-table awareness, which lives in `netops`.

## Replay

Topology snapshots are written to the per-session SQLite database on the
cadence configured in Settings (default: 30s). Replay renders them
verbatim - the graph at the cursor's timestamp.
