# Testudo Documentation

This directory hosts deeper documentation that doesn't belong in the top-level
`README.md` (user-facing) or `DEVELOPER.md` (contributor-facing).

## Index

| Document | Audience | Summary |
|---|---|---|
| [architecture.md](architecture.md) | engineers | Subsystems, data flow, lifecycle |
| [storage.md](storage.md) | engineers, operators | Four storage layers and their lifetimes |
| [replay.md](replay.md) | operators | Session capture, replay engine, timeline navigation |
| [firewall.md](firewall.md) | operators | nftables (default) and iptables (fallback) backends |
| [topology.md](topology.md) | operators | Passive topology graph: nodes, edges, sources |
| [alerts.md](alerts.md) | operators | Severity levels, default thresholds, anomaly engine |

If a topic isn't covered yet, check `.claude/CLAUDE.md` - it's the canonical
project spec - or open an issue.
