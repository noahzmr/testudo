# Alerts

The alert engine listens for `KindAnomaly` events on the bus and
maintains a deduplicated, severity-ranked list for the UI and replay.

## Severity levels

| Level    | Meaning            |
| -------- | ------------------ |
| INFO     | informational      |
| WARN     | degraded condition |
| ERROR    | operational issue  |
| CRITICAL | severe degradation |

## Default thresholds

| Metric          | Default | Configurable in                |
| --------------- | ------- | ------------------------------ |
| Packet loss     | 2%      | Settings => Anomaly thresholds |
| DNS latency     | 120ms   | Settings => Anomaly thresholds |
| RTT             | 150ms   | Settings => Anomaly thresholds |
| Jitter          | 20ms    | Settings => Anomaly thresholds |
| Retransmissions | 5%      | Settings => Anomaly thresholds |

Thresholds are evaluated per metric on the analyzer tick. Crossing a
threshold raises an event with the appropriate severity; the incidents
engine applies dedupe (same source + same message within N seconds
collapses into one entry with a hit count).

## What triggers an alert

* sustained packet loss above threshold
* DNS resolution latency above threshold (any resolver)
* TCP retransmission rate above threshold
* route change on a monitored interface
* firewall drops exceeding rate threshold
* NAT table approaching exhaustion
* interface flapping
* discovery: previously-seen host going unreachable

## Replay

Every alert is recorded in the per-session SQLite database. Replay
renders the same severity colouring and dedupe behaviour as live mode.
The incident timeline in [replay.md](replay.md) is derived from this
table.
