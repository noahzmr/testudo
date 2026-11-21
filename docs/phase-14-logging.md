# Phase 14: logging, SIEM and monitoring

What a security team asks of a firewall before it goes in: every logged
packet and every change where their SIEM can see it, an audit trail nobody
can quietly rewrite, SNMP for the network monitoring, and flow records in
the format their collector speaks.

## Logged packets

Filter rules with logging on, and the policy's drop logging, log to
netfilter log group 7 instead of the kernel log, with the rule's id (or
`drop:<chain>` for a default drop) as the prefix. Opening and binding the
group's socket needs CAP_NET_ADMIN, so the privileged helper does it and
hands the descriptor over (`OpOpenSocket`, type `nflog`); the engine only
reads. Only the first 96 bytes of a packet are copied: addresses, protocol
and ports, never the payload (`internal/nflog`, no new dependency).

The engine names the rule from the model, keeps the latest 200 packets for
the Firewall page and publishes each as a `firewall_log` event.

## Log export

A `log_export` object names a collector (host:port), a transport (UDP, TCP,
TLS with the collector's CA or the system's roots), a format and what to
send:

| Format | What the collector gets |
| --- | --- |
| `rfc5424` | syslog with the record's fields as structured data (`[testudo@32473 ...]`) |
| `cef` | ArcSight CEF inside syslog: `src dst spt dpt proto act cs1=rule suser ...` |
| `json` | one JSON object per line |

| Category | Records |
| --- | --- |
| `firewall` | logged packets, with rule, action, interfaces, addresses, ports |
| `alerts` | anomalies and incidents with their severity |
| `access` | access requests, approvals, grants, break-glass |
| `audit` | every audit row (engine and privileged helper alike, followed in the database) |
| `config` | every change of the configuration model: who, record, kind, object |

Streams use octet counting (RFC 6587) for syslog and line breaks for JSON.
Each exporter has a bounded queue (4096); a slow or absent collector costs
the oldest records, which are counted, and the connection is made again
with a backoff. One exporter runs per object that applies to the node; the
Settings page shows what each sent, dropped, and why it is not connected.

## The configuration log is hash-chained

Every record carries the hash of the one before it and its own (SHA-256
over the record), computed as it is written, the same on every member of a
cluster; snapshots keep the chain head, so compaction and restores keep the
chain. `testudo config verify` and `GET /api/v1/history/verify` check it;
every member checks its own copy hourly and raises a critical alert when a
record was changed. Together with the access log's chain, the trail of who
changed what and who got access cannot be rewritten quietly.

## SNMPv3

An `snmp_agent` answers on the listed interfaces, from the listed networks
only, for the `snmp_user` objects it names: SHA-256 and AES, read-only, no
community strings. net-snmp's `snmpd` runs as a managed service with an
engine id derived from the node; its configuration holds the passwords and
is written 0600; passwords that net-snmp's parser would misread are
refused. snmpd serves the kernel's own MIBs (interfaces, addresses,
routes).

## NetFlow v9

The flow exporter speaks NetFlow version 9 (RFC 3954) besides IPFIX, chosen
in the node settings: the same fields, NAT included (225-228).

## Tests

* Unit: the nflog parser and its bind messages; the three log formats and
  the three transports (with a TLS collector and a wrong CA); the chain
  across compaction, a restart and replication, and a rewritten record;
  SNMP rendering and refusals; the NetFlow v9 packet as a collector decodes
  it.
* Real kernel: a packet logged to the group and read back; through the
  real binary with the privileged helper, a logged packet from a
  neighbour reaches the console and, with a configuration change, a
  syslog collector; snmpget reads the agent with the model's user and a
  wrong password gets nothing.

## Open

* SNMP traps (alerts go to collectors as syslog).
* snmpd and the DHCP relay run as root like Kea; dropping to their own
  users needs persistent directories owned by them.
