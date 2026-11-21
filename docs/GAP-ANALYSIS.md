# Gap analysis: current state vs target appliance

Companion to [ARCHITECTURE-current.md](ARCHITECTURE-current.md). Updated at
the end of every phase.

**Status: Phases 0 to 11 complete. Packet filter, NAT, routing, WireGuard
with identity-aware access, and load balancing with SNI routing and
certificates are driven by the model and verified against a real kernel
([phase-2](phase-2-packet-filter.md), [phase-3](phase-3-routing.md),
[phase-4](phase-4-vpn.md), [phase-5](phase-5-load-balancing.md)). Logins
go through PAM, OIDC or the built-in store and end in permissions from the
model ([phase-6](phase-6-identity.md)). Nodes form a Raft cluster that
replicates the model and applies changes canary first
([phase-7](phase-7-cluster.md)), the network between their sites is
derived from it ([phase-8](phase-8-fabric.md)), and flows are attributed
to zones, tunnels, people, translations and the load balancer, and joined
across sites ([phase-9](phase-9-flows.md)). A site can run an
active/standby pair whose connections survive a failover, the cluster
hands a dead voter's vote to its partner, and a node has metrics, health
endpoints, encrypted backups and a Debian package with a sandboxed unit
([phase-10](phase-10-ha.md), runbook in [operations.md](operations.md)).
Nodes hand out addresses, answer names and serve time per interface, with
DHCP leases shared across an HA pair ([phase-11](phase-11-services.md)).
What is open is listed per area below.**

Effort is rough engineering time for one experienced engineer, including
tests and documentation. Risk is the chance of the area going wrong in a way
that hurts an operator (lock-out, outage, data loss, security defect).

## Summary

| # | Area | Today | Effort | Risk |
| --- | --- | --- | --- | --- |
| 1 | Data model, generation, config core | done | - | - |
| 2 | Stateful packet filter and NAT | done | - | - |
| 3 | Routing (FRR), multi-WAN, PBR | done | - | - |
| 4 | WireGuard and identity-aware access | done | - | - |
| 5 | Load balancing, SNI, certificates | done | - | - |
| 6 | Linux-PAM, OIDC, RBAC, audit | done | - | - |
| 7 | Raft cluster core | done | - | - |
| 8 | Multi-site SDN fabric | done | - | - |
| 9 | Flow analysis extensions | done | - | - |
| 10 | Intra-site HA, hardening, operations | done | - | - |
| 11 | DHCP, DNS and NTP per interface | done | - | - |

The Phase 0 estimate was 15 to 18 months of single-engineer work. Every
area now exists; the open items per area are below.

## What the existing code gives the target for free

* An atomic, owner-tagged nftables apply path with drift reconciliation.
* A privilege-separated writer with an audit row per mutation.
* A commit-confirm mechanism (for one operation) that can be generalised.
* WireGuard provisioning as a transaction with rollback.
* Just-in-time access grants that already compile identity into firewall
  rules, which is the core of identity-aware access.
* A hash-chained access log.
* A flow pipeline with per-interface keying, enrichment and IPFIX export.

## What the existing code makes harder

1. **Three sources of truth.** Firewall policy lives in a JSON file, WireGuard
   in netplan YAML plus SQLite rows, users in another JSON file, settings in a
   fourth. The target needs one replicated model. Every existing subsystem
   has to be re-pointed at it, with a migration for each on-disk format.
2. **Content-hash rule IDs.** Editing a rule changes its identity. The target
   needs stable UUIDs with versions; counters, audit history and drift
   detection all key on the current IDs.
3. **"No shell-out, pure Go, no cgo."** The target requires `frr-reload.py`,
   `vtysh`, `nft -c`, a Traefik check and Linux-PAM. FRR and Traefik become
   supervised sibling daemons, Linux-PAM needs cgo or a separate helper, and
   the privileged helper currently denies `execve`. This rule has to be
   restated as "no shell-out in the packet and apply hot path; managed daemons
   are driven through a narrow, audited runner".
4. **Per-user home directory layout** (`~/.testudo`). An appliance needs
   `/etc/testudo`, `/var/lib/testudo` and system units.
5. **Path-prefix RBAC and in-memory sessions.** Object-level authorisation,
   cluster-wide sessions and identity that travels with a Raft command need a
   different shape.
6. **A polling UI written by hand.** 3200 lines of hand-written forms cannot
   follow a generated model. It needs a schema-driven renderer and a push
   channel.
7. **Name collision.** `internal/pam` is privileged access management. Linux
   PAM integration needs a different package name (`internal/auth/hostpam`).

## 1. Go core, data model and configuration

| Target | State |
| --- | --- |
| `internal/model` structs with json/yaml/validate/ui/secret tags | done: 25 kinds, tag lint test |
| Generated OpenAPI and UI schema, staleness test, route coverage test | done |
| UI forms generated from the schema, inline creation of references | done |
| `Meta` with UUID, version, scope, overrides, effective value with origin | done |
| Typed references, reference index, delete protection | done |
| Version tied to the log index | done (local log; Raft in Phase 7) |
| Optimistic concurrency, `If-Match`, 409 with field diff | done |
| Change sets, combined review, one transaction | done |
| Live updates with the author's identity | done (server-sent events) |
| Audit with before/after per object and per apply | done |
| Transactional apply with dry run, health check, timed rollback, crash recovery | done; no real stage yet |
| History, diff, revert, export, import, migrations, compaction | done |
| Golden files for renderers | helper done; first renderer in Phase 2 |
| Existing subsystems moved onto the model | open by design: one per phase, starting with Phase 2 |

The remaining risk sits in the switch-overs: each replaces an on-disk format
operators already have.

## 2. Stateful packet filter (nftables)

Done; see [phase-2-packet-filter.md](phase-2-packet-filter.md) for what is
enforced, how, and the three things that are not verified (the runner
without root, GeoIP against a real database, reflection and one-to-one NAT
under traffic). WireGuard presets and access grants are still rules of the
firewall manager and move into the model in Phases 4 and 6.

## 3. Routing

Done; see [phase-3-routing.md](phase-3-routing.md) for what is driven, how,
what the host needs, and the parts that are rendered and parsed but not
exercised in a kernel test (OSPF adjacency, BFD, equal-cost routes, VRF
routes, IPv6 routes).

## 4. VPN (WireGuard)

Done; see [phase-4-vpn.md](phase-4-vpn.md). Open by design: approval-gated
access still runs through the existing access manager, and identities
become login identities with Phase 6.

## 5. Load balancing and SNI

Done; see [phase-5-load-balancing.md](phase-5-load-balancing.md). Open:
obtaining a certificate from Let's Encrypt on a host with network access
has not been tried, routers that require a login stay closed until Phase 6
provides the login service, and `least_connections` is not available.

## 6. Authentication and authorisation

Done; see [phase-6-identity.md](phase-6-identity.md). Open: sessions are
in memory until the cluster holds them, PAM is an opt-in build tag, and
directory or one-time-code modules behind PAM have not been tried.

The direct editing of firewall rules outside the model (Web UI, TUI,
`testudo firewall import|enforce`) was removed on request; see
[firewall.md](firewall.md).

## 7. Multi-site clustering

Done; see [phase-7-cluster.md](phase-7-cluster.md). Open: a rolling
upgrade with two real builds has not been run, a backup holds one node's
model and secrets but not the consensus state, the canary is always the
leader, and sessions are per member.

## 8. SDN fabric

Done; see [phase-8-fabric.md](phase-8-fabric.md). Open: stretched VRFs,
path policies and hub-and-spoke are not tested with traffic, the fabric is
IPv4 only, EVPN/VXLAN is not built, and cluster traffic does not move onto
the fabric.

## 9. Flow analysis

Done; see [phase-9-flows.md](phase-9-flows.md).

| Target | Today |
| --- | --- |
| Capture on all interfaces including tunnels | present; follows interfaces that come and go |
| Per-interface flows with directions | present; A/B ordering is by string, there is no initiator |
| Pre/post-NAT attribution | present, from conntrack |
| Zone, tunnel peer, user identity on flows | present |
| Listener-to-backend linkage for load-balanced traffic | present (proxy: access log; kernel: conntrack) |
| Conntrack events as a source | polled every 3 s, not subscribed |
| IPFIX export | present (UDP) with post-NAT fields; no NetFlow v9, no collector |
| Cross-site correlation | present, member to member on request |
| ICMP and other protocols | dropped |
| Documented retention | documented; session flows now retired after 30 days |
| Regression tests | baseline plus a test per new path |

## 10. Operations and hardening

Done; see [phase-10-ha.md](phase-10-ha.md) and
[operations.md](operations.md).

| Target | Today |
| --- | --- |
| Intra-site HA (keepalived, conntrackd) | present; connections survive a failover on a real kernel; no fencing |
| Voter failover (ADR 0004) | present; "caught up" left to Raft, fixed 30 s |
| Prometheus metrics, health and readiness | present (`/metrics` with login, `/healthz`, `/readyz`) |
| Structured logs | `--log-json` |
| Backup and restore | present, encrypted and authenticated; consensus state not included |
| systemd unit with sandboxing | present; verified and scored, not run under systemd with every daemon |
| Debian package | present for amd64, install-tested; unsigned, no repository |
| OpenAPI | generated from the model since Phase 1 |
| Upgrade migrations | the schema version gate from Phase 7; no data migrations were needed |
| CI | absent: the checks run from the commit hooks and `scripts/` |

## 11. Network services

Done; see [phase-11-services.md](phase-11-services.md).

| Target | Today |
| --- | --- |
| DHCPv4 and DHCPv6 per interface | present (Kea): pools, reservations, options, leases in the console |
| IPv6 router advertisements | present (radvd): SLAAC, stateless, managed, RDNSS, DNSSL |
| DNS resolver per interface | present (Unbound): recursive or forwarding, DNS over TLS, DNSSEC, local records, domain forwards, rebind protection |
| Client names in DNS | present, from the leases, live |
| NTP per interface | present (chrony), NTS, orphan mode |
| HA | DHCP hot-standby over the sync link; RA from both nodes |
| Relay, prefix delegation, PXE, free-form options, external DDNS | absent |

## Phase 0 deliverables

* [ARCHITECTURE-current.md](ARCHITECTURE-current.md), this document,
  [THIRD_PARTY.md](THIRD_PARTY.md), four decision records in [adr/](adr/).
* `internal/testnet`: a namespace and veth harness for integration tests that
  needs no external tools.
* The flow-analysis baseline: `internal/flows/flow_test.go` (flow-table
  contract, runs everywhere) and `internal/capture/baseline_linux_test.go`
  (known IPv4/IPv6 UDP and TCP traffic through a three-namespace router
  topology, exact packet, byte and direction assertions on both interfaces).
* `scripts/flow-baseline.sh` and the commit hooks in `scripts/hooks/`.

## Answers received (2026-11-14)

1. React is acceptable for the UI.
2. The "pure Go, no cgo, no shell-out" rule is relaxed for managed daemons,
   dry runs and host PAM.
3. Existing on-disk formats are imported one way.
4. OIDC is external; Keycloak for tests.
5. Rollback window: 60 seconds.

Still unanswered: the target OS (Debian 12 assumed) and the number and names
of the planned sites (three assumed).
