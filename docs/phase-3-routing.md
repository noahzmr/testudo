# Phase 3: routing

Design note. The status at the end says what is verified and what is not.

## What the model drives

| Object | Becomes |
| --- | --- |
| Static route | an `ip route` / `ipv6 route` line in FRR, optionally in a VRF |
| Gateway, gateway group | the next hops of routes; groups give failover and load sharing |
| Policy route | a default route in a routing table of its own plus an `ip rule` for a firewall mark |
| VRF | a kernel VRF device with its member interfaces, and the FRR routes and protocols inside it |
| BGP neighbor | `router bgp` with per-neighbor prefix lists, route maps, communities, BFD, timers, password |
| OSPF area | `router ospf` / `router ospf6` and the interface assignments |

`internal/frrender` renders all of this for one node. It is pure: the model
and the set of gateways that are currently down go in, a complete `frr.conf`
plus the VRF devices and policy rules come out. A golden file pins the
output, and FRR's own parser reads that file in the test image.

## Gateways, groups and failover

A route names either one gateway or a gateway group. A group routes through
the healthy gateways of its lowest tier:

* gateways of the same tier share the load (equal-cost next hops),
* when a whole tier is down the next tier takes over,
* when every gateway of the group is down the route stays on the preferred
  tier and the group is reported as degraded. A default route that vanishes
  helps nobody, and a monitor that is wrong should not cut the box off.

`internal/gwmon` decides what "down" means. A gateway with a monitor address
is pinged every five seconds; three failures in a row take it down, three
answers in a row bring it back, so a lost packet or a flapping link does not
move routes back and forth. If probing itself is impossible (the unprivileged
ping socket is not allowed), nothing is concluded and the gateway counts as
up; the reason is shown in the Gateways tab.

A gateway monitored through an address beyond itself gets a host route to
that address through the gateway. Without it the probe would follow the
default route and report on whichever uplink happens to be in use.

When health changes, the routes are rendered again and applied without a
confirmation window: it is not a configuration change, and waiting for an
operator defeats the purpose.

## Policy routing

A filter rule sets a mark (`mark` on the rule, Phase 2). A policy route says
where traffic with that mark goes: a gateway or a group. It is rendered as a
default route in a table (20000 + mark unless a table is given) and a rule
`fwmark <mark> lookup <table>` for IPv4 and IPv6. The priorities 10000 to
10999 belong to Testudo; rules in that range that the model does not ask for
are removed, rules outside it are never touched.

## How it reaches the system

`internal/frrstage` is the apply stage, after the packet filter:

1. **Check**: FRR's parser validates the configuration (`vtysh -C`).
2. **Apply**: VRF devices and policy rules in the kernel over netlink, then
   `frr-reload.py --reload`, which changes the running daemons to match and
   writes `/etc/frr/frr.conf`.
3. **Health**: the daemons the configuration needs are running.

Like `nft`, FRR's tools run in the runner on the privileged side, which
accepts three FRR requests: check a configuration, reload from one, read one
of seven fixed state views. Configurations are written with mode 0640 next
to FRR's own and removed afterwards; audit rows carry size and hash, because
a configuration can contain session passwords. The same passwords are hidden
when a plan shows the rendered configuration.

**An existing FRR configuration is left alone** until the model has routing
objects. From then on the model owns `frr.conf`; when the last routing object
is removed, the configuration is emptied and ownership is given up again.

Rollback is the same reload with the previous configuration.

## Requirements on the host

* FRR with `frr-pythontools`, and the daemons enabled in `/etc/frr/daemons`
  for the protocols in use (`bgpd`, `ospfd`, `ospf6d`, `bfdd`). The health
  check names any that are missing.
* The runner must be allowed to talk to FRR: root, or membership in the
  `frrvty` group plus write access to `/etc/frr`.
* For gateway monitoring: `net.ipv4.ping_group_range` must include the
  daemon's group (the Debian default does).

## Tests

* Golden `frr.conf`; gateway-group failover across tiers; every refusal by
  name; the monitor's hysteresis.
* `TestGoldenConfigPassesFRRCheck`: FRR 8.4 (Debian 12) parses the golden
  configuration.
* `TestRoutingOnARealKernel`: FRR running in a private namespace with two
  uplinks. It checks in the kernel: the default route on the preferred
  gateway, a static route, the policy table and its rule, the VRF device
  and its member; then a BGP session that reaches Established with a prefix
  received and installed and one announced; then failover to the backup
  gateway after three failed probes and the way back; then that removing the
  objects removes routes and rule. An empty model leaves the running
  configuration untouched.

  The BGP peer in that test is a minimal speaker written for it, because a
  second FRR instance would not start its BGP daemon in the test container.

## Status

Phase 3 is complete as specified, with these parts not verified:

* **OSPF adjacency and BFD sessions.** Their configuration is rendered,
  parsed by FRR and loaded; no test forms a neighbor relationship.
* **Equal-cost routes in the kernel.** The renderer emits several next hops
  for a tier; the kernel test uses one gateway per tier.
* **Routes and BGP inside a VRF, and IPv6 routes, in the kernel.** Rendered
  and parsed; the kernel test covers the VRF device and IPv4.
* **The runner as a non-root user.** As in Phase 2, privileged tests run as
  root.
* **The Health and Session columns in the browser.** The data is served; the
  columns were not opened in a browser.

Not built: route redistribution between protocols, OSPF authentication and
interface costs, BGP confederations and graceful restart, per-next-hop
weights (FRR's static routes share equally), and display of the full routing
table from the daemon (the existing Routes live view shows the kernel's).
