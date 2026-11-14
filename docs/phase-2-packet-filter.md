# Phase 2: packet filter and NAT

Design note. The status at the end says what is enforced today and what is
still owed.

## One place to edit the firewall

The model is where firewall rules are made. In the console the Firewall
section has the tabs Rules, Zones, Aliases, Policy and Running state; NAT
has NAT rules and Running state. There is no separate configuration area:
every model screen is a tab in the section it belongs to (routing kinds
under Routes, tunnels and peers under WireGuard, and so on), with Load
balancer, Cluster and Changes as sections of their own.

"Running state" is the existing live view: what the kernel has loaded, with
counters and drift, including rules that do not come from the model.

## How the ruleset reaches the kernel

There are two paths. The engine picks one at start.

| | nftables stage (`internal/fwstage`) | bridge (`internal/fwbridge`) |
| --- | --- | --- |
| Used when | `nft` can be run with network privileges | it cannot (no helper, no `nft`, an unprivileged run) |
| Renderer | `internal/fwrender`: one `inet` table as text | rules in the firewall manager's format |
| Applied by | `nft -f`, one transaction, dry run with `nft -c` | the manager's netlink path |
| Named sets, run-time aliases | yes | no: zones and aliases expand into rules |
| NAT | destination, source, masquerade, one-to-one, reflection; IPv4 and IPv6 | port forward and masquerade, IPv4 |
| Anti-spoofing, SYN flood guard, conntrack timeouts, marks | yes | refused, naming the object |

`/api/v1/runtime` reports which one is in use (`packet_filter`).

### Running nft

The privileged helper denies itself `execve`, and the engine has dropped its
capabilities. So the helper starts a **runner** process before it installs
that restriction. The runner does three things and nothing else: check a
ruleset, load a ruleset, list one table as JSON. Requests arrive over a pipe
that only the helper holds; the ruleset is passed on standard input and the
argument vector is fixed per request. To let `nft` (a program without file
capabilities) use the network capability, the runner raises it into its
ambient set.

A load is a mutation: it goes through the write gate and is audited with the
ruleset's size and hash, not its text.

### One table, two authors

The firewall manager still owns default deny, the baseline with the
protected ports, and the rules of three owners that are not the model:
direct edits (`user`), WireGuard peer presets (`wg-peer:<key>`) and access
grants (`pam-grant:<id>`). On the nftables path it no longer programs the
kernel itself. The stage is its backend: whenever the manager changes, the
stage assembles **one** ruleset from the manager's tables and the model's
fragments and loads it. Chain order:

1. connection-tracking timeouts,
2. the manager's baseline (established, invalid, loopback, ICMP, open ports),
3. the model's guards (reverse-path check, SYN flood guard),
4. the manager's rules of other owners,
5. the model's rules in sequence order,
6. traffic inside a zone, zone defaults, the final log rule.

The model's firewall policy, when there is one, is handed to the manager, so
there is one owner of the defaults. The first load removes the two tables
of the netlink path in the same transaction.

Every kernel rule carries a comment: the manager's rule id or the model
object's UUID. That is how counters are reported per object and how the
manager's drift check works. A marker set named after a hash of the ruleset
tells whether the kernel still holds what was loaded; if someone flushes or
edits the table, the next check (every 30 s) reloads it.

### Run-time aliases

`internal/aliasfeed` keeps the content of URL-table aliases (one address or
network per line, fetched over HTTP at the alias's interval, at least one
minute) and GeoIP aliases (the networks of the listed countries, read from
the MaxMind country or city database once a day). Content is cached on disk
and rendered into the named sets, so a restart or reload does not empty
them. A source that fails keeps its previous content and shows the error in
the Aliases tab. A page that is not a list is an error, not an empty set.

When content changes, the ruleset is reloaded without a confirmation
window: the rules are the ones already confirmed, only set content moved.

### Which node

The stage finds the local node in the model by host name on every render.
Until a cluster node with this host name exists, only objects with global
scope apply and zones have no interfaces.

## Moving existing rules into the model

`testudo config import-legacy --apply` (daemon stopped, empty model) turns
the rules made directly into model objects and removes them from
`firewall.json`; the original is kept as `firewall.json.before-import`.
Rules it cannot translate faithfully (log-only rules, rules matching traffic
over a rate) and rules of WireGuard peers and access grants stay where they
are and keep working.

## Tests

Real kernel (`scripts/netns-tests.sh`; root or the Debian 12 image from
`scripts/netns-image/`, which has `nft` 1.0.6):

* `TestGoldenRulesetLoadsIntoAKernel`: the ruleset behind the golden file,
  with every feature, is checked and loaded by `nft`.
* `TestRulesetOnARealKernel`: a router between two namespaces. With real
  connections: the switch from the old tables, default deny for IPv4 and
  IPv6, an alias-based allow, a run-time block list taking effect, counters
  per object, source NAT, a port forward, connection-tracking timeouts, a
  rule added through the manager, automatic rollback of an unconfirmed
  change, and the reload after the table was flushed.
* `TestPrivilegedPathEndToEnd`: the real binary with privilege separation;
  a change made through the HTTP API reaches the kernel through helper and
  runner.
* `TestModelDrivesTheKernel`: the same idea for the bridge path.

Without a kernel: golden files for both renderers, every refusal of the
bridge by name, the manager's owner-scoped replacement, the alias feed
against a local HTTP server, and the runner's request validation.

## Status

Phase 2 is complete on the nftables path: zones, aliases (static, URL
table, GeoIP), ordered rules with logging, default deny, connection
tracking with timeouts, invalid-state drop, anti-spoofing, rate limits, SYN
flood guard, destination and source NAT, masquerade, one-to-one, reflection,
IPv4 and IPv6 in one `inet` table, transactional apply with rollback.

Not verified, and why:

* **The runner as a non-root user with file capabilities.** Every privileged
  test here runs as root, where capabilities survive an exec anyway. The
  code that raises the ambient capability has not run in a test.
* **GeoIP aliases against a real database.** No MaxMind database was
  available; the code path that walks the database is untested.
* **Reflection and one-to-one NAT with traffic.** They load into the kernel;
  no test sends packets through them.

Left for later phases, deliberately:

* WireGuard presets and access grants stay rules of the firewall manager
  until Phases 4 and 6 make them model objects.
* Running state still allows direct edits, and the terminal UI and
  `testudo firewall` edit the manager, not the model.
* Flow attribution for NAT (pre/post addresses) is Phase 9.
* A full reload resets rule counters; run-time alias refreshes reload the
  whole table instead of only the set.
