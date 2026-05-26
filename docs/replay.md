# Replay

Replay reconstructs a past session: flows, topology, firewall counters,
NAT state, alerts, and metrics - all timeline-navigable.

## Session capture

When `testudo live` runs, the engine periodically snapshots state into a
per-session SQLite database under `storage/sessions/<id>.db`. The session
id is the start timestamp in `session-YYYY-MM-DD-HHMMSS` form.

Snapshot cadence is configurable in Settings. Defaults:

| State             | Cadence          |
| ----------------- | ---------------- |
| flow summaries    | 5s               |
| topology graph    | 30s              |
| firewall counters | 30s              |
| route table       | on change        |
| NAT rules         | on change        |
| metrics           | continuous       |
| alerts            | on emit          |
| PCAP              | on incident only |

## Listing sessions

```bash
testudo sessions
```

Returns id, start, end, duration, alert count, and PCAP size for each
session.

## Opening a replay

```bash
testudo replay session-2026-05-23-191742
```

Inside replay mode the TUI runs against the recorded snapshots instead of
live state. The same tabs work - flows, topology, firewall, alerts - and
keyboard bindings (`,` / `.`) step the timeline backwards / forwards.

## What replay can - and can't - show

Replay can show:

* every flow that was active in the captured window
* the topology graph as it existed
* firewall hit counters at each snapshot
* every alert that fired, with its severity and source
* metrics at native resolution

Replay can't reconstruct anything that wasn't captured. If PCAP wasn't
triggered, you can see the flow summary but not the wire-level bytes.
That's the trade-off - full PCAP everywhere would have eaten disk.

## Incident timelines

The replay engine renders alert timelines like:

```text
19:42:11  Session started
19:44:02  WARN  DNS latency spike
19:44:15  WARN  Upload saturation
19:44:18  CRIT  Packet loss burst
19:44:21  ERROR Firewall drops increasing
```

Each entry is clickable in the TUI and jumps the timeline cursor.
