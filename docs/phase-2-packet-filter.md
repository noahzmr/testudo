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

## Two renderers, one of them applied

| | `internal/fwbridge` | `internal/fwrender` |
| --- | --- | --- |
| Output | rules for the existing firewall manager | an nftables ruleset as text |
| Applied by | the manager: atomic netlink apply through the privileged helper | `nft -f` (with `nft -c` as dry run) |
| State | **in use**: registered as the first apply stage | written and pinned by a golden file; **not applied yet** |
| Named sets, zone sets | no: zones and aliases expand into rules | yes |
| IPv4 and IPv6 | filter yes, NAT IPv4 only | both, one inet table |

`fwrender` is the target. It is not applied because the privileged helper
may not execute programs (its seccomp filter denies `execve`), and the
engine itself has dropped its capabilities. Driving `nft` needs a dedicated
runner on the privileged side; until it exists the bridge enforces what the
running packet filter can express.

### What the bridge does

A model change goes through the apply engine like any other: render, dry
run, commit, apply, health check, 60 seconds to confirm. The bridge renders
the model into rules owned by `model` and replaces that block in the running
policy in one atomic apply (`firewall.Manager.ReplaceOwned`). Rules of other
owners are untouched and stay ahead of the model's rules:

* `user`: rules made directly (Running state, terminal UI, command line),
* `wg-peer:<key>`: WireGuard peer presets,
* `pam-grant:<id>`: just-in-time access grants.

So WireGuard provisioning and access grants keep working unchanged.

Translation:

* A zone is the set of this node's interfaces (and enabled tunnels) assigned
  to it. A rule that names a zone becomes one rule per interface.
* An alias expands to its addresses; nested aliases are flattened. A rule
  becomes one kernel rule per combination of interface, address, port range
  and protocol, at most 256 per model rule.
* A firewall policy sets default deny and the baseline. The protected ports
  (SSH, the web UI) are added by the manager whatever the model says.
* A port forward comes with the forward-accept rule for the translated
  connection, and loses it when it is removed.
* A zone with "allow traffic inside the zone" gets accept rules between its
  interfaces.

Refused in the dry run, naming the object (nothing is dropped silently):
aliases filled at run time (URL table, GeoIP), firewall marks, source NAT,
one-to-one NAT, reflection, IPv6 NAT, port ranges in forwards, the
reverse-path check and the SYN flood guard. A disabled object of such a kind
is accepted, so they can be prepared.

### Which node

The stage finds the local node in the model by host name on every render.
Until a cluster node with this host name exists, only objects with global
scope apply; zones then have no interfaces, and a rule naming one is refused
with that reason.

## Tests

* `internal/fwbridge`: golden file of the generated policy, every refusal by
  name, a run through the apply engine with a fake manager.
* `TestModelDrivesTheKernel`: a router between two network namespaces with
  the real manager and nftables. It checks with real connections that
  default deny blocks, an alias-based rule allows, masquerade rewrites the
  source, a port forward reaches its target, an unconfirmed change is taken
  back by itself, and a rule made outside the model survives it all.
* `internal/fwrender`: golden ruleset, policy selection by scope, overrides
  per node, protected ports, determinism.
* `scripts/netns-tests.sh` runs the real-kernel tests (and fails when they
  cannot run); `scripts/netns-image/Dockerfile` is the Debian 12 image for
  hosts that forbid unprivileged user namespaces.

## Status

Enforced through the model today: zones, aliases (static), ordered filter
rules for IPv4 and IPv6 with logging, connection states and rate limits,
default deny with the baseline, port forwards, masquerade.

Still owed in this phase:

* A privileged `nft` runner, then `fwrender` as the stage: named sets, URL
  tables and GeoIP with an updater, marks, source NAT, one-to-one,
  reflection, IPv6 NAT, anti-spoofing, SYN flood guard, conntrack timeouts.
* The golden ruleset has not been loaded into a kernel: `nft -c` needs
  network privileges even for a check, so its syntax is unverified until
  the runner exists.
* Moving the remaining owners onto the model: importing rules made directly
  (`testudo config import-legacy` translates them but does not yet remove
  the originals), then WireGuard presets and access grants as model objects.
* Running state still lets an operator add rules directly, and the terminal
  UI edits the manager, not the model.
* Per-rule counters joined onto the model's rules in the Rules tab.
