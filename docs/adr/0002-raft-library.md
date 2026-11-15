# ADR 0002: hashicorp/raft for the control-plane log

Status: accepted (Phase 7). The spike confirmed what was open: v1.7.1 has
pre-vote and it is on by default; non-voters, leadership transfer and
`RecoverCluster` work as needed. See [phase-7-cluster.md](../phase-7-cluster.md).

## Context

The cluster replicates the control plane only: the model, change sets,
identities, key metadata and membership. It needs 3 or 5 voters across at
least three locations, non-voting members for further sites, WAN-tolerant
timeouts, pre-vote, snapshots, versioned commands for mixed-version clusters,
and a documented recovery path for lost quorum. Testudo is pure Go and
MPL-2.0.

Candidates:

| | hashicorp/raft | etcd-io/raft |
| --- | --- | --- |
| License | MPL-2.0 (same as Testudo) | Apache-2.0 |
| Scope | complete library: transport, log and snapshot store interfaces, membership, leadership transfer | the consensus state machine only |
| What we write | FSM, a TLS stream layer, the join protocol | all of that plus transport, write-ahead log, snapshot shipping, the ready loop |
| Non-voters | yes (`AddNonvoter`) | yes (learners) |
| Membership change | single-server changes | joint consensus |
| Pre-vote | available in recent releases; verify in the spike | yes, long-standing |
| Lost-quorum recovery | documented `peers.json` / `RecoverCluster` | manual, by rewriting stored state |
| Storage | pluggable; bbolt-backed store (MPL-2.0 over MIT bbolt) | bring your own |

## Decision

hashicorp/raft, with a bbolt-backed log and stable store, the file snapshot
store, and a custom stream layer that speaks mutual TLS on the site-mesh
address.

## Why

* The risk in this project is not the consensus algorithm; both libraries are
  proven. The risk is everything around it: transport, durable log, snapshot
  transfer, membership. hashicorp/raft ships those and they are the parts
  that take longest to get right.
* Its recovery procedure for lost quorum is an existing, documented mechanism
  that the required disaster-recovery test can exercise directly.
* Single-server membership changes are enough for a cluster that adds or
  removes one site at a time.
* Same license as the project; no new obligations.

etcd-io/raft would be the choice if finer control were needed (joint
consensus, custom batching, multi-group). Nothing in the target needs it.

## Design rules that follow

* **The FSM is the model store.** An object's `version` is the index of the
  log entry that last wrote it, which makes `If-Match` meaningful on every
  node.
* **Every entry is `{type, schema_version, actor, payload}`.** A node refuses
  to start applying an entry type or version it does not know and reports
  itself as lagging; the leader refuses to propose a command that is not
  enabled by a cluster-wide feature gate until all voters advertise support.
* **No secrets in the log in clear text.** Private keys are wrapped with a
  cluster key that is distributed at join time and stored 0600 outside the
  log; the log carries ciphertext and metadata.
* **Packets, sessions and flow records never go through Raft.** Apply results
  per node do, as small status commands, so rollout state is consistent.
* **Writes on any node** are forwarded to the leader over the same mutually
  authenticated channel, carrying the authenticated identity and roles as
  evaluated on the receiving node; the leader re-checks authorisation against
  its own model before proposing.
* **Timeouts are cluster configuration**, with WAN defaults well above the
  library's LAN defaults.

## Consequences

* A new on-disk store per node (`/var/lib/testudo/raft/`), separate from the
  existing SQLite database, which stays node-local for metrics and flows.
* A single-node installation is a one-voter cluster. There is no separate
  non-clustered code path, which keeps Phase 1's config core and Phase 7's
  replicated store the same interface.
* Linearizable reads cost a round trip to the leader; the API offers stale
  reads explicitly for dashboards.

## Open point for the spike

Confirm pre-vote behaviour and non-voter promotion in the pinned release
under the partition tests (2:1, 1:1:1) before committing to the library.
