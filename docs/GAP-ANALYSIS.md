# Gap analysis: current state vs target appliance

Companion to [ARCHITECTURE-current.md](ARCHITECTURE-current.md). Updated at
the end of every phase.

**Status: Phases 0 to 12 complete. Packet filter, NAT, routing, WireGuard
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
The code from before the model no longer runs next to it: the firewall,
users, sessions and access grants have one source of truth, and the
console's live views are pushed ([phase-12](phase-12-consolidation.md)).
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
| 12 | One source of truth, pushed live views | done | - | - |
| 13 | Bonds, bridges, VLANs, PPPoE, DHCPv6-PD, DHCP relay | done | - | - |

The Phase 0 estimate was 15 to 18 months of single-engineer work. Every
area now exists; the open items per area are below.

## What the existing code gives the target for free

* An atomic, owner-tagged nftables apply path with drift reconciliation
  (kept: the drift reload now serves the model's ruleset).
* A privilege-separated writer with an audit row per mutation.
* A commit-confirm mechanism (for one operation) that can be generalised.
* WireGuard provisioning as a transaction with rollback (replaced by the
  model's tunnels and peers).
* Just-in-time access grants that already compile identity into firewall
  rules, which is the core of identity-aware access (now model objects).
* A hash-chained access log.
* A flow pipeline with per-interface keying, enrichment and IPFIX export.

## What the existing code makes harder

Resolved in Phase 12 ([phase-12-consolidation.md](phase-12-consolidation.md)).

| # | Obstacle | Now |
| --- | --- | --- |
| 1 | **Three sources of truth.** Firewall policy in a JSON file, WireGuard in netplan YAML plus SQLite rows, users in another JSON file, settings in a fourth. | The firewall, WireGuard, interfaces, users, roles, node settings, access resources, policies and grants are model objects, replicated by the cluster; access requests are shared by the members. `firewall.json`, `users.json`, `settings.json` and the access catalogue move into the model at the first start and are kept as backups; the old manager, provisioner and every hand-written write path are gone. Only a node's switch for kernel writes stays its own. |
| 2 | **Content-hash rule IDs.** Editing a rule changed its identity. | Rules are model objects with UUIDs and versions; the kernel rule's comment is the UUID, so counters, history and drift checks key on the object. |
| 3 | **"No shell-out, pure Go, no cgo."** | Restated: no shell-out in the packet path; dry runs (`nft -c`, FRR, Traefik, Kea, Unbound, chrony) and managed daemons go through one narrow, audited runner on the privileged side; host PAM is an opt-in cgo build. The helper accepts only the operations the stages and views send. |
| 4 | **Per-user home directory layout.** | The package runs from `/var/lib/testudo` under a sandboxed unit (Phase 10); `~/.testudo` is only the default of a developer run. The CLI reaches the service through `<storage>/control.sock`. |
| 5 | **Path-prefix RBAC and in-memory sessions.** | Permissions are scoped to a site or node and checked per object; sessions live in the replicated secret store and are good on every member; model changes carry the actor through Raft, also the leader-forwarded changes of access grants. |
| 6 | **A polling UI written by hand.** | The model's forms are generated from the schema (Phase 1); the live views are pushed over `/api/live`; the hand-written forms for firewall, NAT, WireGuard, users and routes are gone. |
| 7 | **Name collision `internal/pam`.** | Host PAM is `internal/pamauth`. |

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
under traffic). WireGuard presets and access grants moved into the model
in Phase 12; the old firewall manager is gone.

## 3. Routing

Done; see [phase-3-routing.md](phase-3-routing.md) for what is driven, how,
what the host needs, and the parts that are rendered and parsed but not
exercised in a kernel test (OSPF adjacency, BFD, equal-cost routes, VRF
routes, IPv6 routes).

## 4. VPN (WireGuard)

Done; see [phase-4-vpn.md](phase-4-vpn.md). Access grants are model
objects and requests are shared by the members since Phase 12.

## 5. Load balancing and SNI

Done; see [phase-5-load-balancing.md](phase-5-load-balancing.md). Open:
obtaining a certificate from Let's Encrypt on a host with network access
has not been tried, routers that require a login stay closed until Phase 6
provides the login service, and `least_connections` is not available.

## 6. Authentication and authorisation

Done; see [phase-6-identity.md](phase-6-identity.md) and
[identity.md](identity.md). Sessions and local users are cluster-wide and
permissions can be limited to a site or node since Phase 12. Open: PAM is
an opt-in build tag, and directory or one-time-code modules behind PAM have
not been tried.

## 7. Multi-site clustering

Done; see [phase-7-cluster.md](phase-7-cluster.md). Open: a rolling
upgrade with two real builds has not been run, a backup holds one node's
model and secrets but not the consensus state, and the canary is always the
leader.

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

## Toward the enterprise market

What buyers check before anything else, and what is planned for it. Every
item uses kernel features or open-source programs run as separate
processes; libraries linked into the binary are permissively licensed.
Release engineering, Terraform and Ansible come later; the API they need
exists.

| Phase | Area | Built on |
| --- | --- | --- |
| 13 | Bonds/LACP, bridges, VLANs, PPPoE, DHCPv6 prefix delegation, DHCP relay | netlink, pppd, dhcpcd, dnsmasq ([phase-13](phase-13-interfaces.md)) |
| 14 | Filter-rule logs, syslog/CEF/JSON export, hash-chained configuration log, SNMPv3, NetFlow v9 | NFLOG, net-snmp |
| 15 | IPsec IKEv2 site-to-site | strongSwan (vici) |
| 16 | LDAP groups, SAML, RADIUS/TACACS+ for admin logins, user identity on the LAN | go-ldap, crewjam/saml, layeh/radius |
| 17 | IPS, application identification, DNS filtering, threat feeds | Suricata (NFQUEUE), Unbound RPZ |
| 18 | Flowtable offload, XDP early drop, scale tests | nftables, XDP |
| 19 | Fencing, backups with the consensus state, a canary that is not the leader | keepalived, Raft |

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
