# Firewall

Testudo's firewall is a **policy file applied atomically to nftables and
reconciled back whenever the kernel drifts from it**. The kernel is never the
only copy of the ruleset: a reboot, a stray `nft flush ruleset`, or a lost
helper process cannot silently turn a default-deny host into an open one.

| Layer | Package | Role |
| ----- | ------- | ---- |
| policy | `internal/firewall` | desired state (`~/.testudo/firewall.json`), validation, atomic commit, drift reconcile, commit-confirm for default-deny |
| mechanism | `internal/netops` (`filter.go`, `nat.go`) | rule model, expression compiler, one-batch table rebuild, live state read-back |
| read-only views | `internal/netops/firewall.go`, `firewall_iptables.go` | decode *any* nftables ruleset (and legacy iptables) for the diagnostic "what's blocking me" view |

## Tables Testudo owns

```text
table inet testudo_filter   chains input / forward / output   (priority filter)
table ip   testudo_nat      chains prerouting (DNAT) / postrouting (masquerade)
```

Both tables are private to Testudo. An accept in `testudo_filter` never
bypasses a drop in the operator's own tables; a drop in either is final. The
legacy `testudo_masq` table from older builds is imported into the policy and
removed on first apply.

## Policy file

```json
{
  "version": 1,
  "enforce": false,
  "baseline": {
    "allow_established": true, "drop_invalid": true, "allow_loopback": true,
    "allow_icmp": true, "allow_tcp_ports": [22], "log_drops": true
  },
  "rules":       [ { "chain": "forward", "action": "accept", "in_iface": "wg0",
                     "src": "10.8.0.2/32", "dst": "192.168.1.0/24",
                     "owner": "wg-peer:<pubkey>", "comment": "wg split preset" } ],
  "forwards":    [ { "proto": "tcp", "wan_port": 443, "lan_ip": "192.168.1.10", "lan_port": 8443 } ],
  "masquerades": [ { "out_iface": "eth0", "src": "10.8.0.0/24", "owner": "wg-peer:<pubkey>" } ]
}
```

* **Rules are ordered.** Per chain they are installed after the baseline and
  before the trailing log rule. Reorder from the Web UI (▲/▼) or
  `POST /api/firewall/reorder`.
* **Every entry has a stable ID** (content hash, 12 hex chars) and an **owner**
  tag (`user`, `wg-peer:<pubkey>`, later `pam-grant:<id>`). The kernel rule
  carries only `comment "tf1:<id> …"`, so `nft list ruleset` stays readable and
  a subsystem can remove exactly what it created (`DelRulesByOwner`).
* **Protected ports are not persisted.** The engine merges SSH (22) and the Web
  UI listen port into the baseline on every apply, so enabling default-deny can
  never cut the operator's own session.

Rule fields: `chain` (input/forward/output), `action` (accept/drop/reject/log),
`proto` (tcp/udp/icmp/icmpv6), `port` + `port_end` (range), `in_iface`,
`out_iface`, `src`/`dst` (IPv4 **or IPv6**, bare or CIDR, one family per rule),
`ct_state` (new/established/related/invalid/untracked, comma-combined), `log`,
`rate_limit` (`N/second|minute|hour|day`) + `rate_over`, `comment`, `owner`.

## Default-deny (enforce)

`enforce: true` sets the **input and forward chain policies to drop**; output
stays accept. The baseline keeps the host reachable and stateful:

```text
ct state established,related accept   ct state invalid drop   iifname lo accept
meta l4proto icmp accept   meta l4proto ipv6-icmp accept
tcp dport {22, <web port>} accept      [limit rate 10/minute log prefix "testudo-drop: "]
```

Enabling enforce is a **commit-confirm transaction**: the change is applied
immediately and reverts automatically unless confirmed within the window.

* Web UI: *Enable default-deny* → the page confirms itself on its next
  successful snapshot poll (proof it can still reach the API). 90 s window.
* TUI: `E` → modal → `C` to confirm within the window (default 60 s).
* CLI: `testudo firewall enforce on --confirm-sec 60` → type `yes` to keep.

Mutations are refused while a confirm is pending. Turning enforce off is
immediate.

## Reconciliation and drift

`firewall.Manager.Run` applies the policy at engine start and compares the
live tables with it every 30 s: table present, chain policies, ordered rule IDs
per chain, forwards, masquerades, no leftover legacy table. A mismatch is
re-applied when netops writes are allowed, otherwise only reported.
Transitions surface as anomalies (`WARN` drift detected / `INFO` back in sync /
`ERROR` apply failed) and in the Health tab's `firewall` row.

```bash
testudo firewall status      # mode, counts, kernel in sync / DRIFT
testudo firewall rules       # policy rendered nft-style
testudo firewall export > fw.json
testudo firewall import --file fw.json   # validate → apply → persist
testudo firewall apply       # re-apply (needs CAP_NET_ADMIN)
```

## Transaction semantics

Every mutation is **candidate → apply → persist**. The whole table is rebuilt
in one netlink batch (`delete table` + `add table` + chains + rules), so either
everything lands or nothing changes, and a kernel error leaves both the
committed policy and the file untouched. A filter change rebuilds only the
filter table and a NAT change only the NAT table, so the other table's hit
counters survive.

## Privilege separation

In the default mode the engine drops every capability after spawning the
privileged helper. nf_tables, conntrack and WireGuard **reads** need
CAP_NET_ADMIN just like writes, so all of them travel the helper's query seam
(`netops.Writer` → `Backend.Query` → helper → JSON back): `FilterTableState`,
`NATTableState`, `ListFirewall`, `ListFirewallRules`, `ListWGDevices`,
`ListConntrackQuery`. The privsep transport chunks messages across 64 KiB
datagrams (`OpContinue` / `StatusMore`, 64 MiB cap), so a full rule dump or a
conntrack table is fine; conntrack is additionally filtered and truncated on
the privileged side (`ConntrackQuery`) so only the rows a caller needs cross
the socket. Without the helper (`--privsep=false`) the same reads run
in-process and need the binary to carry the capabilities (`setcap`).

The kernel bounds a single nftables netlink batch by the socket send buffer.
Like `nft` itself, the apply raises the buffer (`SO_SNDBUFFORCE` when
privileged, `SO_SNDBUF` up to `net.core.wmem_max` otherwise) so a table of
thousands of rules still lands in one atomic batch.

## WireGuard presets

Peer presets (full / split / isolated) are ordinary policy rules tagged
`wg-peer:<pubkey>`. They therefore persist across reboots together with the
netplan-declared peers, and `Deprovision` removes them by owner no matter how
the preset inputs changed since. Replies to peers are covered by the baseline's
`ct state established,related` rule; there is no per-peer return rule any more.

## iptables (legacy, read-only)

`Writer.ListIptables` shells out to `iptables -L -v -n -x` and parses the
`filter`, `nat` and `mangle` tables for display only. On distributions running
`iptables-nft`, both the nftables and the iptables views show overlapping data -
a distribution artefact, not a bug. Testudo never writes through iptables.

## Testing

* `go test ./internal/netops/` - expression-builder unit tests plus
  **real-kernel integration tests** that re-exec the test binary under
  `unshare -Urn` (a private user + network namespace, no root needed) and
  apply, read back and verify the tables. They skip automatically where
  namespaces are unavailable.
* `go test ./internal/firewall/` - manager tests with a fake backend:
  apply-before-persist, commit-confirm revert, owner teardown, drift
  reconcile, legacy import, export/import.

## Roadmap

Still open (see [GAP-ANALYSIS.md](GAP-ANALYSIS.md)): named
sets / address groups, GeoIP sets, IPv6 NAT and hairpin, policy routing,
scheduled rules, `firewalld` coexistence checks.
