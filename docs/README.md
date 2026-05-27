# Testudo Documentation

This directory hosts deeper documentation that doesn't belong in the top-level
`README.md` (user-facing) or `DEVELOPER.md` (contributor-facing).

## Index

| Document                                               | Audience             | Summary                                                              |
| ------------------------------------------------------ | -------------------- | -------------------------------------------------------------------- |
| [architecture.md](architecture.md)                     | engineers            | Subsystems, data flow, lifecycle                                     |
| [storage.md](storage.md)                               | engineers, operators | Four storage layers and their lifetimes                              |
| [replay.md](replay.md)                                 | operators            | Session capture, replay engine, timeline navigation                  |
| [firewall.md](firewall.md)                             | operators            | nftables (default) and iptables (fallback) backends                  |
| [topology.md](topology.md)                             | operators            | Passive topology graph: nodes, edges, sources                        |
| [alerts.md](alerts.md)                                 | operators            | Severity levels, default thresholds, anomaly engine                  |
| [DIAGNOSTICS_ASSESSMENT.md](DIAGNOSTICS_ASSESSMENT.md) | engineers            | Senior-engineer review: capability matrix, gaps, prioritized roadmap |

The diagnostics assessment's prioritized roadmap was carried under the same
cross-cutting contract: **full TUI + Web UI parity (viewable *and* editable)**,
**every new measurement feeds the Network Quality grade**, and **one event bus /
replayable**. Most of that roadmap has shipped (per-rule nftables counters,
conntrack/NEIGH introspection, netlink push-vs-poll, the rollup/baseline quality
table, per-flow TCP telemetry, and privilege separation); IPv6 across the full
data path is the main remaining item.

If a topic isn't covered yet, check `.claude/CLAUDE.md` - it's the canonical
project spec - or open an issue.
