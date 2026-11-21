# Phase 12: one source of truth

Phases 1 to 11 put every new subsystem on the configuration model, but the
code from before the model kept working next to it: a firewall manager with
its own policy file, a WireGuard provisioner, users in a JSON file, access
resources and grants in SQLite, sessions in memory, a console that polled
and wrote to the kernel with hand-written forms. This phase removes the
second paths. It answers the list "What the existing code makes harder" in
[GAP-ANALYSIS.md](GAP-ANALYSIS.md).

## Decisions

| Question | Decision |
| --- | --- |
| The old firewall and WireGuard path | moved into the model once, then removed |
| Access grants | objects of the model, replicated, rendered by the packet filter |
| Local users | in the model, including the built-in `testudo`; hashes in the secret store |
| Sessions | in the secret store, replicated: good on every member |
| Permissions | limited to a site or a node where a role says so |
| Live views | pushed to the console; forms that the model replaces are gone |

## What moved where

| Before | Now | Migration |
| --- | --- | --- |
| `firewall.json`, `internal/firewall.Manager` | firewall policy, zones, filter and NAT rules; `fwrender` + `fwstage` | at the first start; file kept as `.migrated` |
| WireGuard provisioner, presets, netplan files | `wg_tunnel`, `wg_peer`, filter rules | the provisioner's rules come with `firewall.json` |
| `users.json` | `user` objects; password hashes and TOTP secrets in the secret store | at the first start; file kept as `.migrated` |
| PAM resources, policies, peer bindings (SQLite) | `access_resource`, `access_policy`, the user on `wg_peer` | at the first start |
| PAM grants as firewall rules owned by `pam-grant:<id>` | `access_grant` objects | at the first start: a grant active at the upgrade becomes a model grant with the same end |
| sessions in memory | `session-<id>` entries in the secret store | a login after the upgrade |
| `/api/firewall/*` writes, `/api/nat/del`, `/api/wireguard/*`, `/api/users*`, `/api/route/add|del` | the model's API (`/api/v1`) | - |
| 2 s snapshot poll | `/api/live` (server-sent events) | - |

PAM requests, approvals and the hash-chained access log stay in SQLite on
the member that handled them: they are a record, not configuration.

## Firewall

`fwrender` renders the model for one node into the table `inet testudo`;
`fwstage` checks it with `nft -c`, loads it with `nft -f` in one transaction
together with the removal of the old manager's tables, and confirms the
kernel holds it by a generation set the ruleset carries. Every 30 s the
engine compares again and reloads on drift, raising an anomaly. Nothing else
writes the table; the TUI, the console and `testudo firewall` read it.

Rules keep their UUID through every edit, and the kernel rule's comment is
that UUID: counters, history and drift checks key on the object
(gap item 2).

A model change touches only the stages whose rendered artifact differs from
what each last applied, so a user change does not reload the packet filter.
A node without privileges takes every change that asks nothing of nftables;
a model with a firewall policy is refused there.

## Users, sessions and permissions

Users are model objects on every member. A local user's secrets are entries
of the node's secret store, which a cluster replicates sealed in Raft; the
first member of a new cluster takes its existing secrets along. The CLI
(`testudo user ...`) changes users through the running daemon's control
socket (`<storage>/control.sock`, 0600, root or the daemon's user), acting
as the break-glass administrator `host-root` with the usual commit-confirm,
which the command confirms.

Sessions are secret-store entries holding what was proven at the login
(never a password). Every member works out from the model what a session
may do, so a role change applies at once, and a logout or an expiry ends
the session everywhere; the cluster's leader collects expired ones.

Permissions take an optional scope: `area:verb@site:<uuid>` or
`@node:<uuid>`. A site scope covers its nodes. A scoped role reads global
objects but may not create them, sees only its own pending changes, cannot
confirm someone else's change and cannot read the history; a token is never
wider than its creator (gap item 5).

## Access grants

An approved request, a policy without approval or a break-glass creates an
`access_grant` (user, resource, end) through the cluster's leader with the
identity `system`. Every member renders the user's peers' access to the
resource into its packet filter; when the grant is deleted, every member
kills the flows it allowed. The leader removes grants 30 s past their end,
so a grant ends even when the member that made it is down.

## Live views

`/api/live` streams the console's snapshot: once whole, then the top-level
parts that changed. One builder per member serves every open console: at
most once a second while the engine has news, at least every five seconds
for counters nothing announces, at once for alerts, link, address and route
changes and access events. A viewer that falls behind is dropped and
reconnects with a fresh snapshot; a stream ends with its session. The page
closes the stream while the tab is hidden. The model's own sections already
listened to `/api/v1/events`.

## The remaining rules, restated

* **Shell-out** (gap item 3). Not in the packet path, not in the apply path
  beyond a validated dry run (`nft -c`, FRR, Traefik, Kea, Unbound, chrony
  checks). Managed daemons are driven through one narrow, audited runner on
  the privileged side. WireGuard and conntrack stay pure Go.
* **Layout** (gap item 4). The package runs from `/var/lib/testudo` with
  `/etc/default/testudo`; `~/.testudo` remains the default for a developer
  run. Nothing in this phase depends on a home directory.
* **Naming** (gap item 7). Host PAM is `internal/pamauth`; `internal/pam` is
  privileged access management.

## Tests

* `internal/localauth`, `internal/perm`, `internal/web` (sessions, live
  stream), `internal/confapi` (scopes), `internal/confimport`
  (`TestTranslateIntoAModel`), `internal/fwstage` (no privileges),
  `internal/svcstage`.
* Real kernel (`scripts/netns-tests.sh`): `TestLegacyFirewallMovesIntoTheModel`,
  `TestLocalUsersEndToEnd`, the cluster test following a session from member
  to member, the VPN test requesting, approving and revoking access through
  the binary, and the packet-filter tests on the model's ruleset alone.
* In a browser: the console receives one snapshot and then only changed
  parts, makes no snapshot requests, and goes to the login when the session
  ends on another browser.

## Open

* The privileged helper still accepts operations nobody sends any more
  (whole-table netlink loads of the old manager, netplan writes, WireGuard
  peer changes outside the stage). Narrowing its operation set is the next
  hardening step.
* Interface addresses, MTU, DHCP client and link state are fields of the
  model that no stage applies yet; the console's interface forms still
  change the kernel directly.
* Node settings (`settings.json`: thresholds, integrations) stay per node
  and are not replicated.
* PAM requests and the access log are per member; a cluster-wide view of
  requests is not built.
