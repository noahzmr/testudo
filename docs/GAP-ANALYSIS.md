# Gap analysis: current state vs target appliance

Companion to [ARCHITECTURE-current.md](ARCHITECTURE-current.md). Updated at
the end of every phase.

**Status: Phases 0 and 1 complete. Phase 2 in progress
([phase-2-packet-filter.md](phase-2-packet-filter.md)): the model now drives
the running packet filter for zones, aliases, filter rules, port forwards,
masquerade and the default policy, proven against a real kernel. The
features that need the nftables text renderer are written but not applied.**

Effort is rough engineering time for one experienced engineer, including
tests and documentation. Risk is the chance of the area going wrong in a way
that hurts an operator (lock-out, outage, data loss, security defect).

## Summary

| # | Area | Today | Effort | Risk |
| --- | --- | --- | --- | --- |
| 1 | Data model, generation, config core | done | - | - |
| 2 | Stateful packet filter and NAT | about 65 % | 2–3 weeks left | high |
| 3 | Routing (FRR), multi-WAN, PBR | about 5 % | 6–8 weeks | medium |
| 4 | WireGuard and identity-aware access | about 45 % | 5–6 weeks | medium |
| 5 | Load balancing, SNI, certificates | nothing | 7–9 weeks | medium |
| 6 | Linux-PAM, OIDC, RBAC, audit | about 25 % | 5–6 weeks | high |
| 7 | Raft cluster core | nothing | 10–12 weeks | very high |
| 8 | Multi-site SDN fabric | nothing | 8–10 weeks | high |
| 9 | Flow analysis extensions | about 50 % | 5–6 weeks | medium |
| 10 | Intra-site HA, hardening, operations | about 10 % | 5–6 weeks | medium |

Roughly 15 to 18 months of single-engineer work. The target is a second
product built around the first; it is not an increment.

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

| Target | Today |
| --- | --- |
| Ordered rules, per-rule logging, default deny, counters, rate limits | present |
| IPv4 and IPv6 in one inet filter table | present |
| Zones, aliases (host, network, port, URL table, GeoIP) as named sets | absent |
| Invalid-state drop, conntrack timeouts | baseline option only; no timeout management |
| Anti-spoofing (fib), SYN-flood guard | absent |
| SNAT, 1:1 NAT, reflection, outbound NAT per interface | absent (DNAT and masquerade only) |
| IPv6 NAT / NPT | absent (`ip` family table) |
| Rollback on every ruleset change | only when enabling default-deny |
| Dry run before apply | absent |

The existing whole-table atomic rebuild stays; it grows named sets and a
second chain layer per zone. Risk is high because this is where lock-outs
happen.

## 3. Routing

Today: static routes in the main table, runtime-only. Everything else is
missing: FRR lifecycle and configuration rendering, OSPFv2/v3, BGP with
policy, BFD, ECMP, VRFs, `ip rule` policy routing tied to firewall marks,
gateway groups with health monitoring, state read-back through `vtysh` JSON.

## 4. VPN (WireGuard)

| Target | Today |
| --- | --- |
| Kernel WireGuard, monitoring, anomaly detection | present |
| Peer create with rollback, client config, QR | present |
| Full and split tunnel presets | present |
| Multiple tunnels, site-to-site model | interfaces can be created; provisioning uses one device; no site model |
| Preshared keys, rotation, expiry, revoke with history | absent |
| IPv6 inside the tunnel | absent (IPAM and masquerade are IPv4-only, yet the full-tunnel client config announces `::/0`) |
| Zone per tunnel | absent |
| Routes distributed through FRR | absent |
| Peers and resources bound to identity with per-resource policy | present for local users through grants; no groups, no OIDC identity |
| Management reachable over the VPN, tested end to end | works in practice, not tested |

## 5. Load balancing and SNI

Nothing exists. See [ADR 0001](adr/0001-managed-traefik-vs-native-proxy.md).
The only TLS code is the Web UI's own certificate handling.

## 6. Authentication and authorisation

| Target | Today |
| --- | --- |
| Local users, roles, TOTP | present, in-house store |
| Linux-PAM service for all local logins | absent |
| OIDC with PKCE, discovery, JWKS rotation, logout | absent |
| Claim and group to role mapping, groups at all | absent (no groups) |
| RBAC enforced in the API per object | per URL prefix |
| API tokens | absent |
| Break-glass local admin | bootstrap admin exists; no IdP to fail yet |
| Audit with before/after | operation and argument summary only |

Risk is high: authentication defects are security defects, and Linux-PAM
forces a decision about cgo (see open questions).

## 7. Multi-site clustering

Nothing exists. See [ADR 0002](adr/0002-raft-library.md) and
[ADR 0004](adr/0004-ha-pairs-as-raft-members.md). This is the highest-risk
area: consensus, membership security, cluster-wide apply with canary and
rollback, and partition behaviour all have to be proven by tests, not by
inspection.

## 8. SDN fabric

Nothing exists. Depends on phases 1, 3, 4 and 7.

## 9. Flow analysis

| Target | Today |
| --- | --- |
| Capture on all interfaces including tunnels | present; no hot-plug |
| Per-interface flows with directions | present; A/B ordering is by string, there is no initiator |
| Pre/post-NAT attribution | absent (string tag only) |
| Zone, tunnel peer, user identity on flows | absent |
| Listener-to-backend linkage for load-balanced traffic | absent |
| Conntrack events as a source | polled for a separate view only |
| IPFIX export | present (UDP); no NetFlow v9, no collector |
| Cross-site correlation | absent |
| ICMP and other protocols | dropped |
| Documented retention | row caps, undocumented |
| Regression tests | **added in Phase 0** |

## 10. Operations and hardening

Present: privilege separation, capability drop, seccomp on the helper,
structured-enough audit rows, optional crash reporting. Absent: OpenAPI,
Prometheus metrics, health endpoints, systemd units and sandboxing, packaging,
backup/restore, upgrade migrations, keepalived and conntrackd integration, CI.

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
