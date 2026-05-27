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
| [DIAGNOSTICS_ASSESSMENT.md](DIAGNOSTICS_ASSESSMENT.md) | engineers | Senior-engineer review: capability matrix, gaps, prioritized roadmap |
| [tasks/](tasks/README.md) | engineers | Actionable implementation specs derived from the assessment (one per roadmap item) |

## Implementation specs (`tasks/`)

The [`tasks/`](tasks/) folder turns each roadmap item from the assessment into a
concrete engineering spec. Every spec carries the same three cross-cutting
requirements: **full TUI + Web UI parity (viewable *and* editable)**, **every new
measurement feeds the Network Quality grade**, and **one event bus / replayable**.
See [tasks/README.md](tasks/README.md) for the index.

If a topic isn't covered yet, check `.claude/CLAUDE.md` - it's the canonical
project spec - or open an issue.
