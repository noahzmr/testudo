# Firewall

The packet filter is **the configuration model, rendered into one nftables
table, loaded in one transaction and loaded again whenever the kernel drifts
from it**. The kernel is never the only copy of the ruleset: a reboot, a
stray `nft flush ruleset` or a lost helper process cannot silently turn a
default-deny host into an open one.

| Layer | Package | Role |
| ----- | ------- | ---- |
| desired state | `internal/model` | firewall policy, zones, aliases, filter rules, NAT rules, access grants, all with UUIDs and versions |
| rendering | `internal/fwrender` | the model for one node as an nftables ruleset; golden-file tested |
| apply | `internal/fwstage` | the packet-filter stage of the transactional apply: check, load, health, drift reload, counters |
| mechanism | `internal/netops` (`nft.go`) | `nft -c` and `nft -f` through the privileged helper |
| read-only views | `internal/netops/firewall.go`, `firewall_iptables.go` | decode *any* nftables ruleset (and legacy iptables) for the diagnostic "what's blocking me" view |

How the ruleset is built, chain by chain, is in
[phase-2-packet-filter.md](phase-2-packet-filter.md).

## The table Testudo owns

```text
table inet testudo   filter chains input / forward / output, NAT chains
                     prerouting / postrouting, sets for aliases and grants
```

The table is private to Testudo. An accept in it never bypasses a drop in
the operator's own tables; a drop in either is final. The tables of older
builds (`inet testudo_filter`, `ip testudo_nat`) are removed in the same
transaction that loads the model's table.

## Editing

Every change is a change of the model: in the Web UI's Firewall and NAT
sections, through `/api/v1`, or by importing a model. Like every change it
is a **commit-confirm transaction**: applied at once and rolled back unless
confirmed within 60 seconds ([phase-1-config-core.md](phase-1-config-core.md)).
Default-deny is a field of the firewall policy object.

* **Rules are ordered** by their `sequence`.
* **Every rule has a stable ID** (the object's UUID); editing a rule keeps it.
  The kernel rule carries the ID as its comment, so counters, audit history
  and drift detection all key on the object, and `nft list ruleset` shows
  which object a rule came from.
* **Every rule has an owner.** Rules made by people have none; access grants
  are rendered from `access_grant` objects and torn down with them; rules
  moved in from the old policy file keep their old owner tag
  (`wg-peer:<pubkey>`, `user`).
* **Protected ports are not stored.** SSH (22) and the Web UI's port are
  always accepted on the input chain, so default-deny can never cut the
  operator's own session.

Nothing else writes the table. The Web UI's *Running state*, the TUI's
Firewall and NAT tabs and `testudo firewall` show what the kernel holds and
what each rule has matched; they do not change rules.

```bash
testudo firewall status      # policy, default-deny, kernel in step with the model
testudo firewall rules       # the model's rules with their counters
testudo nat                  # the model's NAT rules with their counters
```

The commands talk to the running daemon over its control socket
(`<storage>/control.sock`).

## Moving from the old policy file

Builds before the model kept the policy in `<storage>/firewall.json`. The
first start of this build moves it into the model, once:

* rules, port forwards and masquerades become filter and NAT rules,
  interfaces become zones (an interface the model already has keeps its
  zone), names stay unique;
* the rules the old WireGuard provisioner wrote come along with their owner;
* a firewall policy already in the model wins over the file's
  default-deny and baseline;
* what has no model equivalent (rate-over rules, log-only rules) is listed
  in the log and in the audit row `firewall_migration`;
* the file is kept as `firewall.json.migrated`.

A node that is not in the model yet is added first, in a site called
`default`. `testudo config import-legacy` still imports a whole older
install into an empty model.

## Reconciliation and drift

The engine compares the kernel's table with the model's ruleset every 30 s
by a generation marker the ruleset carries. A table that is missing or
differs is loaded again when netops writes are allowed, otherwise only
reported. Transitions surface as anomalies (`WARN` reloaded / `INFO` back in
step / `ERROR` reload failed) and in the Health tab's `firewall` row.

A node without privileges (no helper, writes off) takes every model change
that does not need the packet filter; a model with a firewall policy is
refused there.

## Privilege separation

In the default mode the engine drops every capability after spawning the
privileged helper. nf_tables, conntrack and WireGuard **reads** need
CAP_NET_ADMIN just like writes, so all of them travel the helper's query
seam (`netops.Writer` → `Backend.Query` → helper → JSON back). The privsep
transport chunks messages across 64 KiB datagrams (64 MiB cap), so a full
rule dump or a conntrack table is fine. Without the helper
(`--privsep=false`) the same reads run in-process and need the binary to
carry the capabilities (`setcap`).

## iptables (legacy, read-only)

`Writer.ListIptables` runs `iptables -L -v -n -x` and parses the `filter`,
`nat` and `mangle` tables for display only. On distributions running
`iptables-nft`, both the nftables and the iptables views show overlapping
data - a distribution artefact, not a bug. Testudo never writes through
iptables.

## Testing

* `go test ./internal/fwrender/` - golden files for the rendered ruleset.
* `go test ./internal/fwstage/` - the stage without privileges.
* `./scripts/netns-tests.sh` - the ruleset, kernel load balancing, the
  migration of an old policy file and the default-deny path end to end, on a
  real kernel in a privileged container.
