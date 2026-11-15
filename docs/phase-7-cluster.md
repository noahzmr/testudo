# Phase 7: The cluster core

Decisions: [ADR 0002](adr/0002-raft-library.md) (hashicorp/raft),
[ADR 0004](adr/0004-ha-pairs-as-raft-members.md) (pairs inside a site,
which arrive with Phase 10).

Several nodes share one configuration. Raft replicates the **control
plane** only: the model, change sets, the state of a rollout, secrets
(sealed), join tokens and who the members are. Packets, sessions and flow
records never go through it.

```text
 any member                    leader                       every member
 ──────────                    ──────                       ────────────
 API request ──forward──► validate, prepare record ──Raft──► apply record to its
 (identity travels)        + deadline + rollout              own model, then to
                                                             its own kernel, FRR,
                                                             WireGuard, proxy
                                   ▲                                │
                                   └────────── apply report ────────┘
```

## The model is the state machine

`internal/confstore` gained a replication hook. A write is validated and
turned into a complete record on the leader; the record is agreed on; every
member, the leader included, applies it. Because a record carries the
resolved result of the change, applying it is the same computation on every
member, and an object's `version` is the same number everywhere, so
`If-Match` means the same on every member.

Every log entry is `{type, version, actor, payload}`
(`internal/cluster/command.go`). Types: `record`, `seed`, `apply_result`,
`pending`, `rollout`, `member`, `secret`, `revoke`, `token`.

### Mixed builds

Each member announces its build, the model schema it knows, and the highest
format version it can apply of every command type. The leader proposes a
command only when every voter can apply it; otherwise the request fails
with "finish the upgrade first". Should an entry reach a member that cannot
read it all the same, the member **stops there**. It does not skip the
entry and continue with a state that differs from everyone else's; after
the upgrade it continues from where it stopped.

So a rolling upgrade is: upgrade one member at a time; nothing new is used
until the last voter runs the new build.

## Voters, and why two are not enough

A change needs a majority of the voters. With three voters, any one can be
lost. With **two voters, neither can**: one alone is half, not a majority,
so a cluster of two stops accepting changes when either member or the link
between them fails. It is strictly worse than a single node. Two main sites
therefore need a third voter somewhere else. That voter can be small (it
only has to keep the log and vote), which is all a "witness" is.

Use three or five voters at three or more locations. Everything else joins
without a vote: it receives the model and does not affect the majority. A
join token says which of the two a new member becomes; the console warns
about two voters and about even numbers.

Timing (`internal/cluster/node.go`): heartbeat 1.5 s, election 3 s, leader
lease 1 s. They are chosen for WAN links and can be overridden per member.
Pre-vote is on, so a member that was cut off does not force an election
when it comes back.

## Membership and security

* **A cluster has its own authority and key**, created by `init`. The
  authority issues one certificate per member, for both ends of a
  connection, with the member's id as subject. The key seals secrets.
* **Join** with a one-time token (`POST /api/v1/cluster/token`). The token
  names the address to contact and the fingerprint of the authority to
  expect there, so the joining node recognises the cluster before it sends
  anything. It sends a certificate request; its private key never leaves
  it. The answer carries its certificate and the cluster key, over that
  verified connection. Tokens are stored by hash, used once, and expire.
* **Both listeners accept only members.** The consensus transport requires
  a client certificate of the cluster's authority that is not revoked. The
  member API (`/cluster/v1/…`) does the same for everything except `join`.
  Host names are not compared: members move, and what identifies one is
  the authority's signature over its id.
* **Removing a member revokes its certificate**; the revocation is
  replicated and checked on every handshake.
* **Certificates** are valid for 90 days and renewed at two thirds of that,
  with a new key.
* **Secrets** created through the API (tunnel keys, certificate keys, the
  identity provider's client secret, the authority's own key) go through
  the log sealed with the cluster key (AES-256-GCM, bound to the entry
  name) and are opened into each member's own secret store. The cluster
  key itself is never in the log.
* A member may propose for itself only: its own apply report and its own
  announcement, secrets and tokens. Records and rollouts are the leader's.

Bind `--cluster-raft` and `--cluster-api` to an address of the site mesh.
Nothing in this phase stops an operator from binding them to a WAN
interface; the mesh that makes the right address obvious is Phase 8.

## Writes on any member

A member that does not lead passes a change on to the leader through the
member API, with the identity of whoever asked (name, permissions, whether
it is a token or a break-glass administrator). The leader checks the
permissions again and writes the audit row with the person's name. The
answer goes back unchanged, so conflicts, validation errors and "used by"
lists look the same on every member. Reads are served locally.

## Applying across the cluster

`internal/confapply/cluster.go`:

1. The leader validates, renders and dry-runs the change, then commits it.
   The record, the **confirmation deadline** and the **rollout** are one
   log entry.
2. The leader is the **canary**: only it applies at first.
3. When its stages are healthy it opens the rollout. Every other member
   applies the model itself (validate, render, dry run, apply, health
   check) and reports the result.
4. If the canary is unhealthy, the change is reverted before any other
   member touched it. If more members fail than allowed (currently none
   may), or nobody confirms within 60 seconds, the change is rolled back
   for everyone. Whoever leads at that moment does it: the deadline is
   cluster state, not a timer in one process.

Each member checks every 30 seconds whether it still runs what the model
says (every stage's health check), applies the model again if not, and
reports the drift either way. `GET /api/v1/cluster` and the console's
Cluster → Overview show per member: role, the record it applied, pending,
failed, drift.

### A proposal that looked failed

A leader that is cut off while it proposes a change tells the operator the
change failed. The entry may still be in its log and be agreed on after the
partition heals: in Raft the outcome of such a proposal is unknown, not
negative. Because the deadline travels in the same entry, the change
arrives overdue and is rolled back at once. Nobody ends up running a change
they were told had failed.

## Partitions

A member that cannot reach a majority **keeps running its last
configuration** and turns read-only: changes answer 503 with "read-only
until it can reach a majority". Nothing is torn down.

**Emergency override.** `POST /api/v1/cluster/override` changes what runs
on that member only. It needs a break-glass administrator (the built-in
account, or a host account in the group `testudo-admin`), a reason, and it
is audited. The model is not touched. When the member is back, it receives
the cluster's model and **keeps running the override**: it is never
overwritten or merged silently. The cluster shows the member as differing,
with the reason. Someone reviews it and resolves it (`DELETE
/api/v1/cluster/override`); the override's changes are handed back to be
made again as an ordinary change, or dropped.

### Lost quorum

When the majority of voters is gone for good, the remaining member can
decide nothing. `testudo cluster recover --unsafe --cluster-raft ADDR`
(daemon stopped) makes it a cluster of one from what it has on disk.
Whatever the lost members had agreed on and this one never received is
gone. If a lost member comes back, wipe its storage and join it again; do
not start it as it is.

## Tests

In process, with links that can be cut (`internal/cluster`, 23 tests):

* replication and identical versions; leader loss; partition 2:1 (the
  cut-off former leader accepts nothing) and 1:1:1 (nobody decides);
  snapshot for a member that joins after the log was shortened; members
  joining and leaving under load with every acknowledged write present
  afterwards; mixed builds (gate, and stopping at an unknown entry); a
  cluster started from a node that already has a model; sealed secrets.
* cluster-wide apply: canary first; an unhealthy canary stops the rollout
  before anyone else runs the change; a failure on another member rolls
  everyone back; an unconfirmed change goes away everywhere; a new leader
  rolls back at the deadline, or confirms; a cut-off member keeps running
  and can be overridden, and the override survives the heal until resolved;
  a change that surfaces late is rolled back.
* membership over real TLS: join with a token, a used, expired or made-up
  token, a token pointed at another cluster, strangers and members of
  another cluster on both listeners, a removed member's certificate,
  forwarding with identity, renewal, restart, a join through a new leader.

Real daemons (`TestClusterEndToEnd`, part of `scripts/netns-tests.sh`):
three in three network namespaces behind a router, on links with 20 ms
delay each way, 5 ms jitter and 0.5 % loss (`tc netem`). Forming the
cluster from a node with an existing model; a change through a follower
ends up in every node's own nftables; the audit row names the person; the
leader is killed; partition 2:1 with a read-only minority that keeps
enforcing; a break-glass override, its drift report and its review;
partition 1:1:1; two of three voters lost and the survivor recovered.

## Status

Phase 7 is complete for a cluster of members that can reach each other,
with these parts **not verified or not built**:

* **A rolling upgrade with two real builds.** The gate and the stop at an
  unknown entry are tested in process by announcing an older build, not by
  running one.
* **Snapshots and members joining or leaving under load with real
  daemons.** Both are covered in process only.
* **Backup and restore of the whole cluster state.** The model can be
  exported and imported as before (`/api/v1/export`). There is no single
  backup that also holds the sealed secrets and the cluster key, and no
  restore into a new cluster. Only the lost-quorum recovery is tested.
* **Automatic certificate renewal over time.** Renewal itself is tested;
  the loop that triggers it at two thirds of the lifetime never ran that
  long.
* **The canary is always the leader, and no member may fail.** A chosen
  canary node or site and a tolerated number of failures are not
  configurable yet.
* **A linearizability check** (Jepsen-style) was not done.
* One run of the in-process tests hung before a data race in the test
  harness was fixed; it did not happen again in 35 runs, 23 of them under
  the race detector. The cause was not proven to be the harness.

Known limits:

* Console sessions and the built-in user store are per member. A person
  logs in on the member they talk to.
* A member that restarts while a change is still with the canary applies
  the model it has, including that change, before the rollout is opened.
  A rollback still reaches it.
* All secrets made through the API are replicated to all members, sealed.
  That includes a tunnel's private key that only one member uses.
* Raft members are named by `--node-name` (default: the host name). The
  `cluster_node` objects of the model match a member by host name; they
  are not created when a member joins.
* The consensus numbers are in `GET /api/v1/cluster`, not yet in a
  metrics endpoint.
* Promoting a site's standby when its voter dies (ADR 0004) belongs to
  Phase 10.
