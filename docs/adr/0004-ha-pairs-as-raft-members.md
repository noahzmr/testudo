# ADR 0004: How intra-site HA pairs count as Raft members

Status: accepted; implemented in Phase 10 (see "Implementation" below).

## Context

Two layers of redundancy exist in the target:

* **Inside a site**: an active/passive pair using VRRP (keepalived) for the
  service addresses and conntrackd for session state. Failover has to happen
  in about a second and must not depend on any other site.
* **Between sites**: Raft replicates configuration. Voters must be spread
  over at least three locations and their number must be odd.

If both nodes of a pair vote, a site carries two votes. Two paired sites plus
a witness give five voters (2+2+1), which survives any single-site loss, but
one paired site plus an unpaired one gives an even count, and the number of
voters then changes whenever a pair is built or broken. Quorum arithmetic
would depend on hardware layout.

## Decision

**Every node is its own Raft server. Each site contributes exactly one voter.
The other node of a pair is a fully replicated non-voter.**

* A site's voter is designated in the model (`Site.voter`). The standby holds
  the complete log and applies every change set, so it always forwards with
  current configuration.
* If the site's voter is unreachable for longer than a configurable period
  while its partner is healthy and caught up, the leader demotes the dead
  node and promotes the partner. This is one membership change, it needs a
  quorum of the *other* voters, and it is audited. It never happens without
  quorum.
* **VRRP state and Raft role are independent.** VRRP decides which node
  forwards packets; Raft decides what the configuration is. The Raft leader
  may be a VRRP backup and the other way round.
* Both nodes of a pair render the same site-scoped objects. Node-scoped
  objects (interface bindings, VRRP priority, router IDs, the conntrackd
  peer address) differ and live under `node:<id>` scope.
* keepalived and conntrackd configuration are rendered from the model by the
  same transactional apply as everything else.

## Why two voters never work

With two voters a majority is two. If the link between them fails, each sees
one vote and neither can commit: the cluster is read-only until the link
returns, which is worse than a single node. Giving one side a tie-break
weight only moves the problem, since the weighted side failing stops
everything. Hence, with two main sites, a small witness voter at a third
location is mandatory. The witness stores the log but can run on minimal
hardware and carries no traffic.

## Behaviour in failure cases

| Event | Data plane | Control plane |
| --- | --- | --- |
| Active node of a pair dies | VRRP moves addresses to the standby in about a second; conntrackd has the sessions | unaffected if the dead node was the non-voter; otherwise the site's vote is missing until promotion, quorum holds through the other sites |
| Whole site loses its uplinks | keeps forwarding local traffic with the last applied configuration | site loses quorum, its configuration API turns read-only |
| Pair is split (sync link down, both up) | keepalived's usual split-brain risk; mitigated by a dedicated sync link and tracking scripts, outside Raft's scope | no effect, each node talks to the cluster on its own |
| Standby is promoted to voter, then the old voter returns | none | the returning node rejoins as a non-voter and catches up |

## Consequences

* The number of voters equals the number of voting sites and is independent
  of whether sites are paired.
* The rollout order for a change set inside a site is standby first, then the
  active node, so a bad change is caught on the node that carries no traffic.
* conntrackd synchronises session state inside a site only. Sessions are not
  replicated between sites.
* Promotion needs a health definition for "partner is healthy and caught up"
  (applied index within a bound, last contact within a bound); that is part
  of Phase 7's tests.

## Implementation

* The pair is the model's `ha_pair` (two nodes of one site, VRRP instances,
  a sync interface); `internal/harender` renders keepalived and conntrackd,
  `internal/hastage` applies them through the privileged helper, which
  supervises both daemons.
* The leader records every member it fails to heartbeat
  (`FailedHeartbeatObservation`) and forgets it when heartbeats resume or a
  new term starts. A voter silent for `FailoverAfter` (30 s by default) is
  replaced when its partner is a non-voter that the leader reaches and that
  has announced itself. "Caught up" is left to Raft: the partner has been
  replicating the log all along, and a lagging new voter costs liveness at
  most, never safety.
* The replacement is two member records (dead: non-voter, partner: voter),
  a `DemoteVoter` of the dead node and the usual promotion of the partner.
  The dead node steps down first, so the quorum for the step is counted
  among the voters that are alive. A returning node keeps its non-voter
  record and catches up.
* The engine writes an audit row (`cluster_voter_failover`) and sets the
  site's `voter` in the model to the partner.
* Not implemented: the standby-first rollout order inside a site. A change
  set rolls out canary-first (the leader) and then to every member at once.
