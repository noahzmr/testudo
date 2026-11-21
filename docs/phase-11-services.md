# Phase 11: DHCP, DNS and NTP per interface

A node now hands out addresses, answers name lookups and serves time to
the networks behind it. Every service names the interfaces it serves;
it listens only there, and the packet filter opens its port only there.
Everything comes from the model and goes through the transactional apply
like the rest of the appliance.

```text
                 model: dhcp_scope, router_advert, dns_resolver, dns_record, ntp_service
                                          │
                     internal/svcrender ──┼── internal/fwrender (ports per interface)
                                          ▼
   internal/svcstage ─► helper ─► kea-dhcp4  kea-dhcp6  unbound  chronyd  radvd
            ▲                         │ leases, name announcements (127.0.0.1:53001)
            └── engine: client names ─┘──► Unbound control socket, flow view
```

| Service | Daemon (Debian 12) | Unit of configuration |
| --- | --- | --- |
| DHCPv4, DHCPv6 | Kea 2.2 | `dhcp_scope`: one per interface and address family |
| IPv6 router advertisements | radvd 2.19 | `router_advert`: one per interface |
| DNS resolver | Unbound 1.17 | `dns_resolver`: one per scope, with the interfaces it answers on; `dns_record` for local names |
| NTP | chrony 4.3 | `ntp_service`: one per scope, with the interfaces it serves |

## The model

**`dhcp_scope`** (site or node scope, **Services → DHCP**): interface,
subnet (its family is the scope's family), pools as ranges or networks,
default gateway (IPv4), DNS and NTP servers, domain, lease time,
reservations (hardware address or DUID, address, host name) and whether
client names go into DNS. Defaults point at the node: the gateway is the
interface's virtual address on an HA pair, else the node's own address in
the subnet; DNS and NTP are the node when its resolver or NTP service
serves that interface.

**`router_advert`**: interface and mode: `slaac` (clients form their
addresses), `stateless` (and ask DHCPv6 for options) or `managed` (DHCPv6
assigns addresses); prefixes (default: the interface's IPv6 /64s), RDNSS
and DNSSL (default: the node and the local domain when the resolver serves
the interface), MTU.

**`dns_resolver`**: interfaces, `recursive` or `forward` to upstreams
(optionally over TLS, `address#name`), DNSSEC validation, the local domain
(default `home.arpa`, RFC 8375), per-domain forwards (an internal
directory's domain), and extra networks it answers (a VPN behind another
interface). **`dns_record`**: A, AAAA (with their reverse entries), CNAME,
TXT.

**`ntp_service`**: interfaces, servers, pools, NTS, extra networks, and
`serve_only` for a node whose clock something else sets.

The checks refuse pools, gateways and reservations outside the subnet or
of the other family, a second scope for the same interface and family, a
reservation without a client identifier, duplicate reservations, router
advertisements of other than /64 prefixes, a second resolver or NTP
service in one scope, an upstream over TLS without its name, an NTP
service without a source, and records whose value does not fit the type.

## Rendering

`internal/svcrender` writes one configuration per daemon.

* **Kea** listens on the scopes' interfaces (raw sockets for DHCPv4),
  keeps leases in `<storage>/services/kea-leases{4,6}.csv`, answers on a
  control socket with the lease commands hook loaded, and derives each
  subnet's numeric id from the scope's UUID, so leases survive re-renders.
  The DHCPv6 server identifier is fixed (enterprise number 32473 and the
  node id). Name updates are switched on for scopes that register names:
  Kea keeps the client's name with the lease only then. The updates go to
  the engine on the loopback, not to a DNS server.
* **Unbound** runs as its own user. It binds the interface's addresses
  from the model and the pair's virtual addresses (`ip-freebind`, so the
  standby binds them before it holds them), or the interface by name when
  the model has no addresses for it. Queries are allowed per interface
  (`interface-action`), plus the extra networks. It has QNAME minimisation,
  hardened glue and DNSSEC with Debian's `dns-root-data` anchor, and rebind
  protection: public names may not resolve into private networks, except
  under the local and forwarded domains. The local domain is a static
  zone with the records, the reservations and an include file of client
  names.
* **chrony** takes its sources from the model, allows the networks on the
  served interfaces, keeps serving its own clock at stratum 10 when no
  source is reachable (orphan), and has no command socket.
* **radvd** advertises per interface with the M and O flags by mode,
  prefixes autonomous unless managed, RDNSS and DNSSL, and drops to its
  own user.

Configuration goes to `/run/testudo-svc` (readable, nothing secret), so
Unbound and radvd can read it again as their own users on a reload.

## Applying

`internal/svcstage` is a stage after the HA pair (whose addresses the
services bind) and before the proxy. **Check** runs each daemon's own
checker on the candidate (`kea-dhcp4 -t`, `kea-dhcp6 -t`,
`unbound-checkconf`, `radvd -c`, `chronyd -p`), so a broken configuration
never reaches a running daemon. It also refuses to start chronyd while
another program disciplines the clock (chrony, ntpd, systemd-timesyncd)
unless the service is `serve_only`. **Apply** writes what changed, stops
the daemons that are no longer wanted, then starts, reloads (Kea, Unbound
and radvd on SIGHUP) or restarts (chronyd) the others. **Healthy** wants
every daemon running; otherwise the change rolls back. The privileged
helper supervises the daemons as it does keepalived, with each daemon's
options limited to a short list (`serve-only` for chronyd).

The packet filter lets clients in ahead of the operator's rules, on the
served interfaces only: UDP 67, UDP 547, TCP and UDP 53, UDP 123, the
neighbour-discovery messages on advertised interfaces, the extra networks
for DNS and NTP, and the HA partner's DHCP failover traffic on the sync
link.

## Client names

When Kea records a lease with a name it announces it on
`127.0.0.1:53001`; the engine also looks every ten seconds. It asks both
Kea servers for their leases over their control sockets and enters the
names of active leases of registering scopes into Unbound: as an include
file for the next start, and live through Unbound's control socket, so a
new client needs no reload. A name the model gives (a record or a
reservation) is never taken over by a client, and a name outside the
scope's domain is ignored. The same names label the clients in the flow
view.

## HA pairs

On the two nodes of a pair, both Kea servers run in hot-standby with the
HA hook: the first node of the pair is primary, the second standby, and
they talk over the sync link (TCP 8000 for DHCPv4, 8001 for DHCPv6, with
Kea's dedicated listener and multi-threading). The standby keeps a copy
of every lease and takes over six seconds after the primary stops
answering. Scopes of a pair must be at the site, because a scope on one
node would not be shared. Unbound and chrony run on both nodes and bind
the virtual addresses, so clients keep using the same server after a
VRRP failover.

## Status

`GET /api/v1/runtime` has `services`: daemons and their state, the
interfaces each serves, active leases per scope. `GET /api/v1/dhcp/leases`
lists the leases (`services:read`). The console's **Services** section has
an overview, the lease list and a tab per kind. `/metrics` exports
`testudo_service_up{daemon}` and `testudo_dhcp_leases_active{scope,interface}`.
The built-in operator role may change the services (`services:write`);
operator roles created before this phase need that permission added.

## Packaging

The package recommends `kea-dhcp4-server`, `kea-dhcp6-server`, `unbound`,
`dns-root-data`, `chrony` and `radvd`. Testudo runs its own instances:
disable the distribution's units of those daemons
(`systemctl disable --now kea-dhcp4-server kea-dhcp6-server unbound chrony radvd`).
The unit adds `/run/testudo-svc`, `CAP_SYS_TIME` and the clock system
calls for chronyd, and write access to `/var/lib/kea`;
`systemd-analyze security` now rates it 5.2 (it was 4.9 without clock
control).

## Tests

| Test | What it shows |
| --- | --- |
| `internal/svcstage` `TestServicesOnARealKernel` (real kernel) | From the model through the stage, on a LAN interface with a WAN interface beside it: a client gets a DHCPv4 lease with gateway, DNS, NTP and domain; a default route from the router advertisement and a DHCPv6 address in the pool; its own name, the reservation, the record and the reverse entry from the resolver over IPv4 and IPv6; a new and a released name through the control socket without a reload; the time over NTP. From the WAN side: no DNS answer, no time, no lease. Switching the advertisement off stops radvd. |
| `internal/svcstage` `TestDHCPFailoverOnARealKernel` (real kernel) | Two nodes of a pair: the client leases from the primary, the standby learns the lease with its name, the primary's server dies, and after the take-over the client gets the same address from the standby. |
| `cmd/testudo` `TestServicesEndToEnd` (real kernel) | Through the binary and the API under a default-deny policy: lease, the client's name resolved after Kea's announcement, a record, NTP, the leases endpoint, the metrics, the DNS opening in the ruleset. |
| `internal/svcrender` | every daemon's configuration and defaults, a node override of the resolver, TLS forwarding, the pair's hot-standby configuration and virtual addresses, a node-only scope refused on a pair, reverse names |
| `internal/svcstage` `TestDesiredNames` | which lease names are registered |
| `internal/fwrender` `TestServicesOpenTheirInterfacesOnly` | each port on its interfaces and from its extra networks, nothing elsewhere |
| `internal/confstore` `TestServiceChecks`, `internal/model` | the checks and the new validators |
| `internal/netops` | the daemon option list |

## Status and open points

Done. Open:

* **Router advertisements on an HA pair** come from both nodes with their
  own link-local addresses; clients may route through the standby. An
  advertisement from a virtual link-local address is not built.
* **DHCP split brain**: if the sync link fails while both nodes run, the
  standby takes over too and both hand out addresses from the same pool
  until the link returns. The take-over does not wait for unanswered
  clients (`max-unacked-clients` 0); the sync link has to be dedicated.
* No DHCP relay, prefix delegation, PXE options or free-form options; no
  dynamic DNS towards external servers; leases are not shown across the
  cluster, only per node.
* Unbound binds an interface by name only at its start: an address that
  appears later on an interface the model has no addresses for needs a
  restart (any change applies one).
* Kea's configuration check needs the interfaces to exist when the change
  is checked.
* The DNS of a client name lives on the node that leased it and its HA
  partner; other sites do not learn it.
