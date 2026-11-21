# Phase 10: Intra-site HA, hardening and operations

A site can now run two nodes as an active/standby pair: the service
addresses move with VRRP, and the connections move with them because the
standby has the active node's connection table. The cluster replaces a
site's voter by its partner when the voter is gone. A node reports metrics
and health, can be backed up and restored, and ships as a Debian package
with a sandboxed systemd unit. The operator's runbook is
[operations.md](operations.md); the decision behind the pair is
[ADR 0004](adr/0004-ha-pairs-as-raft-members.md).

```text
           VRRP adverts (lan, wan)            VIP 10.0.0.1 / 192.0.2.1
   ┌──────────────── fw1 ◄──────────────────────► fw2 ────────────────┐
   │  keepalived  conntrackd                 keepalived  conntrackd   │
   │        └── state sync, UDP 3780 on the sync link ──┘             │
   └─ both render the same site objects; Raft: one voter per site ────┘
```

## The model

`ha_pair` (site scope, **Cluster → HA pairs** in the console):

| Field | Meaning |
| --- | --- |
| `nodes` | exactly two nodes of the pair's site; the first is preferred |
| `instances` | VRRP instances: interface, virtual router id (1–255), virtual addresses |
| `sync_interface` | the link conntrackd uses; a dedicated cable or VLAN |
| `advert_ms` | advert interval (default 1000 ms) |
| `preempt` | whether the preferred node takes the addresses back when it returns (default: no) |

Each node needs `sync_address` (its address on the sync link) and may set
`vrrp_priority`. The checks refuse a pair whose nodes are the same or at
another site, a node without a sync address, an instance that mixes IPv4
and IPv6 (keepalived needs one instance per family), and a virtual router
id used twice on one interface of a site.

## Rendering and applying

`internal/harender` renders per node:

* `keepalived.conf`: VRRP version 3, every instance starts as BACKUP so the
  election decides; priority 150 for the first node and 100 for the second
  unless set; `nopreempt` unless `preempt`; all instances in one sync group,
  so the addresses move together; `enable_script_security`.
* `conntrackd.conf`: FTFW mode over UDP port 3780 between the two sync
  addresses, with an external cache; the sync link's own traffic and
  loopback are not synchronised.
* `become-active.sh`: commit the external cache into the kernel, flush it,
  resynchronise and send a bulk update. `become-standby.sh` (also on fault):
  flush the internal cache and ask the partner for a full resync.

`internal/hastage` is a stage of the transactional apply, after the packet
filter and routing and before the proxy. It writes the files to
`<storage>/ha` (directory 0700, configuration 0600, scripts 0700: keepalived
refuses scripts others could change), then asks the privileged helper to
keep the daemons running: conntrackd first (restarted when its
configuration changed), then keepalived (reloaded with SIGHUP). Health
after an apply is both daemons running. Disabling the pair stops keepalived
first, so the addresses are given up, then conntrackd, and removes the
files.

The helper supervises the daemons itself (`internal/netops/daemons.go`):
they run in the foreground with their pid files and conntrackd's control
socket in `/run/testudo-ha`, they get SIGTERM when the helper ends, and
only keepalived and conntrackd with their own configuration file names and
clean absolute paths are accepted.

The packet filter lets the pair talk ahead of the operator's rules, so a
default-deny policy cannot split it: VRRP (IP protocol 112) on the
instances' interfaces, and UDP 3780 from the partner's sync address on the
sync interface.

## Status

`GET /api/v1/runtime` reports `ha`: the pair, whether this node holds all
virtual addresses (`active`) or not (`standby`), which ones it holds, the
partner's sync address and both daemons' state. The cluster overview shows
the same as a card; `/metrics` exports `testudo_ha_active` and
`testudo_ha_daemon_up`.

## Voter failover

As ADR 0004 decided: each site has one voter, the pair's other node is a
non-voter with the whole log. The leader now records every member it fails
to heartbeat. A voter silent for 30 seconds is replaced by its pair partner
when that partner is a reachable, announced non-voter: the dead voter is
recorded as a non-voter and demoted first (so the quorum for the step is
counted among the live voters), then the partner is recorded as a voter
and promoted. The engine writes a `cluster_voter_failover` audit row and
sets the site's `voter` in the model. A returning node keeps its non-voter
record and catches up. Nothing changes without quorum.

## Monitoring

* `GET /healthz`: 200 while the process serves. No login.
* `GET /readyz`: 200 once the configuration model is open and has been
  applied since the start, 503 with the reason before. A member without
  cluster quorum is ready; it forwards with what it has. No login.
* `GET /metrics`: Prometheus text format, for a session or an API token
  (`Authorization: Bearer`); 401 without one. Subsystem state and restarts,
  model index and pending confirmation, cluster role, quorum, members,
  voters and unreachable members, gateway state, fabric path state, latency,
  jitter and loss, HA role and daemons, load-balancer backend state,
  per-rule packet and byte counters, WireGuard peers, live flows, uptime.
  A scrape reads state the engine keeps; it runs no probe.
* `--log-json` writes the log as JSON lines (`log/slog`) for journald or a
  shipper.

## Backup and restore

`testudo backup create --out FILE` writes the configuration log and
snapshot, the secrets directory (tunnel, certificate and fabric keys, the
cluster's key and authority), users, settings, the SSH user CA, TLS
material and the ACME account. Left out: the SQLite database, captures,
the consensus state and everything rendered from the model. The archive is
a gzip-compressed tar sealed with AES-256-GCM under a scrypt key
(N=2^15, r=8, p=1), with the header as additional data. The copied
configuration has to replay before the archive is written.

`testudo backup restore --in FILE` decrypts and checks the whole archive
before it writes anything, writes only the paths a backup can contain,
takes the configuration store's lock (so the daemon must be stopped), and
refuses a node that has a configuration unless `--force`.
`testudo backup inspect` checks an archive and lists it. The passphrase
comes from `--passphrase-file`, `$TESTUDO_BACKUP_PASSPHRASE` or a prompt,
and has at least 12 characters.

## Packaging

`scripts/build-deb.sh` builds `dist/testudo_<version>_<arch>.deb` offline
in a Debian 12 image, with PAM support. It installs the binary, the unit,
`/etc/pam.d/testudo` and `/etc/default/testudo` (both conffiles), and the
documentation; `postinst` creates the group `testudo-admin` and
`/var/lib/testudo` (0700), enables and starts the service on a first
install and restarts it on an upgrade. A purge keeps `/var/lib/testudo`. Commands run as root on the host use
`/var/lib/testudo` once the service has created its configuration there
(or `$TESTUDO_STORAGE`), so `testudo user passwd` and `testudo backup`
act on the installed appliance without `--storage`.

`packaging/systemd/testudo.service` runs `testudo web` as root with the
helper split as before, inside a sandbox: a capability bounding set of
network administration and what the supervised daemons and the flow-to-
process correlation need, `NoNewPrivileges`, `ProtectSystem=strict` with
write access to its state, `/etc/frr`, `/etc/netplan` and `/run/frr`
only, private `/tmp`, no home directories, restricted address families
and namespaces, a system-call filter, and `MemoryDenyWriteExecute`.
`ProtectKernelTunables` stays off because forwarding and conntrack
settings are written through `/proc/sys`. `systemd-analyze security` rates
it 4.9 ("OK").

## Tests

| Test | What it shows |
| --- | --- |
| `internal/hastage` `TestPairOnARealKernel` (real kernel) | Two routers with a strict stateful forward chain (established, or new SYN only; `nf_conntrack_tcp_loose=0`) are configured from the model through the stage. A TCP connection through the active router carries 200 bytes over ten seconds; after two seconds the active router loses both links. The standby takes the addresses and the connection delivers all 200 bytes; the standby's external cache had the connection before the failure and its kernel table has it after. |
| manual run of the same topology without conntrackd | the connection stops at the failover (80 of 400 bytes), which is what the test above guards against |
| `internal/harender` | both members' files mirror each other: priorities, VRID order, `nopreempt`, notify scripts, sync addresses, control socket path |
| `internal/fwrender` `TestHAPairOpensVRRPAndSync` | VRRP and the partner's sync are let in ahead of a default-deny policy, and only on pair members |
| `internal/confstore` `TestHAPairChecks` | the model checks above |
| `internal/netops` `TestDaemonRequestsAreChecked` | unknown daemons, modes, configuration names and unclean paths are refused |
| `internal/cluster` `TestPartnerTakesTheVoteOfADeadVoter` | three voters plus a non-voter partner: the voter dies, the partner votes in its place, the audit hook fires once, the cluster takes a write, the old voter returns as a non-voter |
| `cmd/testudo` `TestPrivilegedPathEndToEnd` (real kernel) | `/healthz`, `/readyz` without login, `/metrics` 401 without and 200 with a session, `testudo_config_ready 1` |
| `internal/backup` | round trip, modes, excluded files; wrong passphrase, changed body, changed header and truncation all fail without writing; hostile paths in a correctly sealed archive are refused; restore refuses while the store is open |
| `scripts/deb-install-test.sh` | the package installs on Debian 12, files, modes, group and conffiles are right, the unit's command line serves `/healthz` and `/readyz`, removal and purge behave |
| `systemd-analyze verify` | the unit is valid |

## Status

Done. Open, and the risks to know about:

* **Restarting the active node fails the pair over.** The daemons stop with
  the helper, so a restart or upgrade of the active node moves the
  addresses once; conntrackd keeps the connections. Upgrade the standby
  first.
* **No fencing.** If the network between the pair splits on an instance's
  segment, both nodes can hold the addresses. The sync link carries only
  state, not the election; a dedicated sync link does not prevent this.
* **The engine writes configurations that root daemons run.** keepalived
  runs the notify scripts as root; FRR and the proxy were already in the
  same position. A compromised engine process can therefore reach root
  through the helper. Rendering in the helper would close this.
* **"Caught up" is not measured** before a partner gets the vote; a lagging
  partner costs liveness, not safety. The failover period is fixed at 30 s.
* The standby-first rollout order inside a site (ADR 0004) is not built.
* IPv6 virtual addresses are rendered and checked, but only IPv4 failover
  is tested.
* `/readyz` looks at the configuration only; `/metrics` is readable by any
  logged-in user or token.
* The sandbox is validated with `systemd-analyze`, not by running the
  appliance under systemd with all daemons; a capability a daemon needs and
  the bounding set lacks would show up only there.
* The package is built and tested for amd64 only and not signed; there is
  no repository.
* A backup does not include the consensus state: a restored member joins
  its cluster again, a lost cluster is restored on one node and recovered
  as a cluster of one.
