# Operating Testudo

The runbook for an appliance: install, first steps, sites and pairs,
monitoring, backup, upgrades, and the ways back in when something is
broken. The design behind each part is in the phase notes
([phase-1](phase-1-config-core.md) to [phase-10](phase-10-ha.md)).

## Install

Debian 12 on amd64.

```sh
./scripts/build-deb.sh                 # dist/testudo_<version>_amd64.deb
apt install ./dist/testudo_*.deb       # pulls nftables, iproute2, PAM
apt install frr frr-pythontools keepalived conntrackd conntrack wireguard-tools   # as needed
```

The package enables and starts `testudo.service`. Its command line is in
the unit; extra arguments (listen address, cluster addresses, node name,
`--log-json`) go into `/etc/default/testudo`. State lives in
`/var/lib/testudo` (mode 0700): the configuration log, secrets, users, TLS
material, the database.

On the first start the console's built-in user `testudo` gets a random
password, printed once to the log:

```sh
journalctl -u testudo | grep password:
testudo user passwd testudo      # set your own
```

Commands run as root on the host work on `/var/lib/testudo` once the
service has created it (or wherever `$TESTUDO_STORAGE` points); as another
user they use `~/.testudo`. `--storage` overrides both. `testudo user`,
`testudo firewall` and `testudo nat` talk to the running service over
`<storage>/control.sock`, which only root and the service's own user may
use; they act as the break-glass administrator `host-root`, and their
changes are model changes like any other.

### Upgrading from a build before the model

The first start of this build moves the older files into the model, once,
and keeps each original next to it:

| File | Becomes | Kept as |
| --- | --- | --- |
| `users.json` | local users, their hashes and second factors in the secret store | `users.json.migrated` |
| `firewall.json` | firewall policy, zones, filter and NAT rules, with the old WireGuard provisioner's rules | `firewall.json.migrated` |
| access resources, policies, peer bindings and active grants in the database | `access_resource`, `access_policy` and `access_grant` objects, the user on each `wg_peer` | the database rows |
| open access requests in the database | entries of the replicated store | the database rows |
| thresholds and integrations of `settings.json` | a `node_settings` object | `settings.json`, which keeps the node's write switch |

What could not be carried over is in the log and in the audit row
`firewall_migration`. The hand-written forms that changed rules, routes,
interfaces, WireGuard peers, users and settings directly are gone; all of
that is changed in the model now. Interfaces of the model that carry
addresses are now applied: check that they match what the device should
have before upgrading.

The console is at `https://<host>:8443` with a self-signed certificate
until you configure one (Settings → Certificates: Let's Encrypt or the
local authority).

## First steps

1. **Who logs in.** Settings → Users, Groups, Roles; or an OIDC provider;
   or host accounts through PAM (`/etc/pam.d/testudo`). Put the
   administrators' host accounts into the group `testudo-admin`: they get
   in when everything else fails.
2. **Zones and interfaces.** Firewall → Zones, then Interfaces →
   Configuration: the zone of each device and, where Testudo should set
   them, its addresses, DHCP client, MTU and link state (see below).
3. **Policy.** Firewall → Policy. Turning on default-deny, like every
   change, applies at once and **rolls back after 60 seconds unless you
   confirm** (the banner, or `POST /api/v1/apply/confirm`). If the change
   cut you off, wait: it undoes itself. SSH, the console port, loopback,
   ICMP and established connections stay open under any policy.
4. **Rules, NAT, routes, tunnels, services** in their sections. Several
   changes can be collected in a change set and applied together.

`testudo config status` and `testudo config history` show the model from
the host; `testudo config compact` folds old history into a snapshot.

## Sites and the cluster

Model the sites and nodes first (Cluster → Sites, Nodes): every node has
its name (the host name, or `--node-name`), its address, and for the
fabric a mesh index and uplinks.

Each node listens for the cluster on the site mesh, never on a WAN:

```sh
# /etc/default/testudo on fw1
TESTUDO_ARGS="--listen 0.0.0.0:8443 --tls-auto --node-name fw1 --cluster-raft 10.255.255.1:7400 --cluster-api 10.255.255.1:7401"
```

On the first node: Cluster → Start a cluster. For every other node: on a
member, Cluster → "Token for a voter" (a site's first node) or "Token for a
member without a vote" (the second node of a pair), then on the new node
Cluster → Join and paste it. Plan one voter per site and an odd number of voting sites;
with two main sites, add a small witness node at a third place.

The fabric (Cluster → Fabric) builds the tunnels and BGP sessions between
the sites from the model; keys fill in by themselves.

## A pair inside a site

1. Two nodes of the site, each with `sync_address` on a dedicated link
   (a cable between the two, or its own VLAN).
2. Cluster → HA pairs → New: both nodes (the first is preferred), the sync
   interface, and one VRRP instance per interface and address family with
   the service addresses. Leave `preempt` off unless you want the addresses
   back on the preferred node whenever it returns.
3. Apply and confirm. The cluster overview shows which node is active and
   whether keepalived and conntrackd run on each.

Routes, NAT and services that clients reach should use the virtual
addresses. Test a failover in a maintenance window: stop the active node
(`systemctl stop testudo`) and watch the addresses move; connections
continue.

If the pair's voter is unreachable for 30 seconds, the cluster gives the
site's vote to the partner and the audit log says
`cluster_voter_failover`. The old voter comes back as a non-voter.

## Interfaces

An interface of the model configures the device it names, on its node,
as the first stage of every apply: addresses, a DHCP client (IPv4;
dhclient, else dhcpcd, as the unit `testudo-dhcp@<device>` or
`testudo-dhcpcd@<device>`), the MTU and whether the link is down. Only what is set is configured, and only what Testudo did
is undone: an interface that only names a zone changes nothing, and
addresses from a DHCP lease, the HA pair, WireGuard and router
advertisements stay. Switching an interface off (enabled unchecked)
undoes what Testudo did to the device. What it did is recorded in
`/var/lib/testudo/interfaces/managed.json`. Like every change this
rolls back after 60 seconds unless confirmed, which covers an address
change that cuts the console off. A device the node does not have is
skipped. The DHCP client's script sets the routes and name servers the
lease brings, as the distribution's would; `systemctl status
testudo-dhcp@eth0` and `journalctl -u testudo-dhcp@eth0` show it. The
lease is kept while Testudo restarts.

If the distribution's own network configuration (ifupdown, netplan,
NetworkManager) also manages a device, let only one of them set its
addresses.

### Bonds, bridges, VLANs, PPPoE, DHCPv6

Interfaces → Bonds, Bridges, VLANs, PPPoE and DHCPv6 create those devices
on a node; an interface of the model then gives them addresses and a
zone. Testudo only changes or removes devices it made: a device of the
same name made by the distribution is refused. PPPoE sessions run as
`testudo-pppoe@<device>` and DHCPv6 clients as `testudo-dhcpcd6@<device>`.
A DHCPv6 client can ask the provider for a prefix and give /64s of it to
LAN interfaces; a router advertisement there announces it. DHCP relay
(Services → DHCP relay) passes requests on a LAN to a central DHCP
server.

## Node settings

Thresholds, flow export and the integrations (Sentry, Guacamole,
MaxMind) are node settings of the model (Settings → Node settings): one
object for every node, and per site or per node where they differ; the
narrowest applies. An empty value is the built-in default. Whether a
node may write to the kernel stays its own switch (Settings, "allow
netops writes", or `--allow-netops-write`).

## DHCP, DNS and NTP

Services → DHCP, Router advertisements, DNS resolver, DNS records, NTP.
Each object names the interfaces it serves; the firewall opens its port on
those interfaces only. Give the interfaces their addresses in the model
(Interfaces → Configuration): the defaults (gateway, DNS and NTP server
handed to clients) are derived from them, or from the pair's virtual
address. Before the first service, stop the distribution's own units:

```sh
systemctl disable --now kea-dhcp4-server kea-dhcp6-server unbound chrony radvd systemd-timesyncd
```

* **DHCP**: one scope per interface and family, with pools and
  reservations. Tick "Register client names in DNS" to make clients
  resolvable under the scope's domain (default: the resolver's local
  domain, `home.arpa`). Services → Leases lists who has which address.
* **IPv6**: a router advertisement per interface. `slaac` for plain
  networks, `managed` with a DHCPv6 scope when addresses must be handed
  out and recorded.
* **DNS**: recursive by default with DNSSEC; or forward to upstreams, over
  TLS as `9.9.9.9#dns.quad9.net`. Internal domains of a directory go into
  domain forwards. VPN clients that reach the resolver through another
  interface go into "Also answer".
* **NTP**: pools or servers to follow. The node sets its own clock
  unless "Leave the system clock alone" is on; with no source reachable it
  keeps serving its clock at stratum 10.

On an HA pair, put the scopes at the site: both nodes run DHCP
hot-standby over the sync link and the standby takes over within seconds
(port 8000/8001 on the sync link). Clients get the virtual address as
gateway, DNS and NTP server.

Logs of the daemons are in `/var/lib/testudo/services/<daemon>.log`; the
configuration in `/run/testudo-svc`.

## Monitoring

| Endpoint | Login | Use |
| --- | --- | --- |
| `/healthz` | no | liveness: the process answers |
| `/readyz` | no | readiness: the configuration is applied |
| `/metrics` | session or API token | Prometheus scrape |

Create a token for the scraper (Settings → API tokens) with read
permissions only, and scrape with `Authorization: Bearer <token>`. Worth
alerting on: `testudo_config_ready == 0`, `testudo_config_pending == 1` for
long, `testudo_cluster_quorum == 0`, `testudo_cluster_unreachable_seconds`,
`testudo_ha_daemon_up == 0`, `testudo_gateway_up == 0`,
`testudo_fabric_path_up == 0`, `testudo_lb_backend_up == 0`,
`testudo_subsystem_ok == 0`.

The audit log (Changes → Audit log) records every change, apply, rollback,
login and override with the person behind it.

## Backup and restore

```sh
umask 077; printf '%s\n' 'a long passphrase' > /root/backup-pass
testudo backup create --storage /var/lib/testudo --out /root/fw1-$(date +%F).tbk --passphrase-file /root/backup-pass
testudo backup inspect --in /root/fw1-2026-11-21.tbk --passphrase-file /root/backup-pass
```

Creating works while the service runs. Keep the archive and the passphrase
apart; the archive holds every private key of the node.

To restore onto a fresh install:

```sh
systemctl stop testudo
testudo backup restore --storage /var/lib/testudo --in fw1.tbk --passphrase-file /root/backup-pass [--force]
systemctl start testudo
```

`--force` replaces a configuration the node already has. A restored cluster
member joins its cluster again with a new token. If the whole cluster is
lost, restore one node, recover it as a cluster of one (below) and join
the others.

## Upgrades

1. Back up.
2. Inside a pair, upgrade the standby first, then the active node; the
   active node's restart moves the addresses once (connections survive).
3. Across sites, one node at a time. A change that needs the new version
   is refused ("finish the upgrade first") until every voter runs it.

```sh
apt install ./dist/testudo_<new>_amd64.deb    # restarts the service
curl -fsk https://localhost:8443/readyz
```

## When something is broken

* **Locked out by a change**: wait 60 seconds, the change rolls back. A
  confirmed change that locks you out: log in over SSH or on the console
  port (both stay open) and revert the record in Changes → History.
* **Identity provider down**: a local user such as `testudo`, or a host
  account in `testudo-admin`. As root on the host, `testudo user passwd
  testudo` resets the password through the control socket; the new one is
  good on every member.
* **A site cut off from the cluster**: it keeps running its configuration
  read-only. An urgent local change is an emergency override
  (`POST /api/v1/cluster/override`, break-glass administrators only); it is
  kept and shown on the cluster page until someone resolves it there.
* **Quorum lost for good**: on the surviving member,
  `systemctl stop testudo`, then
  `testudo cluster recover --unsafe --cluster-raft <addr>`,
  start it, and join the others again after wiping their storage.
  Whatever the lost members agreed on and this one never received is gone.
* **The HA daemons**: `/var/lib/testudo/ha` holds the rendered
  configuration and the daemons' logs (`keepalived.log`, `conntrackd.log`),
  `/run/testudo-ha` the pid files and conntrackd's control socket
  (`conntrackd -C /var/lib/testudo/ha/conntrackd.conf -s` for statistics,
  `-i`/`-e` for the internal and external caches).
* **Logs**: `journalctl -u testudo` for Testudo and its helper.
