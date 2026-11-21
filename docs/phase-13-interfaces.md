# Phase 13: interfaces for real networks

The interface stage (Phase 12) configured existing devices. Enterprise and
provider networks need more: aggregated uplinks, VLAN trunks, bridges,
PPPoE, DHCPv6 prefix delegation, and DHCP relay to a central server. All of
it uses kernel features over netlink, or open-source programs run as
separate processes (pppd, dhcpcd, dnsmasq), like the other managed daemons.

## Model

| Kind | What it is | Applied by |
| --- | --- | --- |
| `bond` | members, mode (802.3ad LACP by default, active-backup, ...), LACP rate, transmit hash, link check, primary | interface stage, netlink |
| `bridge` | ports, spanning tree, VLAN-aware | interface stage, netlink and rtnetlink |
| `vlan` | parent, id 1-4094, 802.1q or 802.1ad (QinQ) | interface stage, netlink |
| `pppoe` | PPP device, Ethernet device, credentials (a model secret), MTU, default route, provider DNS, IPv6 | interface stage, pppd |
| `dhcpv6_client` | upstream interface, address (IA_NA), delegated prefix length (IA_PD), /64s for LAN interfaces by subnet number | interface stage, dhcpcd |
| `dhcp_relay` | client interfaces, DHCP servers (IPv4 and IPv6) | services stage, dnsmasq |

All are node-scoped except the relay, which is a service like a DHCP scope.
An `interface` object gives any of these devices addresses and a zone.

## Bonds, bridges, VLANs

The privileged side makes the devices of these kinds that Testudo created
(alias `testudo`) match the spec in one sync: it creates what is missing,
recreates what the kernel cannot change in place (a VLAN's id or parent, a
bond's mode, hash, link check or primary), sets bridge spanning tree over
rtnetlink (sysfs shows the namespace it was mounted in, not the process's),
enslaves and releases members, and removes its own devices that are no
longer wanted. A device of the same name that Testudo did not make is
refused and never touched. Bonds and bridges are made before VLANs, which
may sit on them. A member cannot have addresses of its own.

## PPPoE and DHCPv6 clients

Both are daemons the interface stage runs from a file it writes (0600):
pppd's options with the credentials, which never appear on a command line
or in an audit row; dhcpcd's IPv6-only configuration, so it runs next to an
IPv4 client on the same interface. A changed file restarts the daemon; a
session or client that leaves the model is stopped and its file removed;
dhcpcd takes its addresses and delegated /64s with it. Credentials with
line breaks are refused (they would add options). Under systemd the
daemons are units of their own, `testudo-pppoe@<device>` and
`testudo-dhcpcd6@<device>`, outside Testudo's sandbox, so their scripts set
routes and name servers.

The packet filter lets DHCPv6 answers in on the upstream interface (from
the server's link-local address, which connection tracking cannot match to
the multicast request). A router advertisement on an interface that gets a
delegated /64 announces whatever prefix it has (`prefix ::/64`).

## DHCP relay

dnsmasq runs as a relay only (`port=0` switches its DNS side off), checked
with `dnsmasq --test` before it is applied. Each client interface relays
from one of its own addresses of the server's family; the packet filter
opens DHCP on the interfaces and the servers' answers. An interface is
either relayed or served by a Kea scope of the same family; Kea uses raw
sockets, so both share port 67 on different interfaces.

## Tests

* Unit: link spec validation, the stage with a fake kernel (a bond with a
  VLAN on top and its removal, members without addresses, PPPoE options
  and redaction, DHCPv6 configuration and its contradictions, the earlier
  artifact form), relay and delegated-prefix rendering, the daemon request
  checks.
* Real kernel (`scripts/netns-tests.sh`): bonds, bridges and VLANs with a
  mode change and a foreign device; a PPPoE session against
  `pppoe-server`; a delegated /56 from Kea and radvd given out as two /64s;
  a client getting its address from Kea behind the node through the relay.
  The test image carries pppd, pppoe-server, dhcpcd and dnsmasq.

## Open

* Bridge VLAN membership per port (the bridge is VLAN-aware, the port VLAN
  table is not modelled yet).
* Kea cannot serve DHCPv6 from a delegated prefix (it changes); delegated
  LANs use SLAAC.
* Name servers that a DHCPv6 lease or PPPoE session brings are set by the
  daemons' scripts, not fed into the DNS resolver service.
