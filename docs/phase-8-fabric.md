# Phase 8: The fabric between the sites

The network between the sites is not configured; it is derived. Sites,
nodes and their uplinks are in the model, and from them every node works out
its tunnels, addresses, ports, BGP sessions and firewall openings
(`internal/mesh`). Adding a site creates its tunnels and sessions; removing
one removes them.

```text
 model:  fabric (pool, colors, AS, topology)   site (networks, AS, hub)
         node (fabric index, uplinks, public key)   VRF (fabric slot)
            │
            ▼  mesh.Build — the same answer on every node
 per node:  WireGuard: one point-to-point device per peer node, color, slot
            FRR:       one BGP session per device, BFD, loopback, networks
            nftables:  the devices in the fabric's zone; tunnel, BGP, BFD let in
            pathmon:   latency, jitter, loss per device → preferred color
```

## The model

* **`fabric`** (one): enabled, topology (`full_mesh` or `hub_spoke`), an
  IPv4 /16 pool, a first port, the default AS number, the colors (kinds of
  uplink, at most four: for example `inet`, `mpls`), the zone the tunnels
  belong to, BFD, and the path-selection margin and hold time.
* **`site`**: `networks` it announces, `asn` (default: the fabric's),
  `hub`. A `witness` site carries no traffic and gets no tunnels.
* **`cluster_node`**: `mesh_index` (1 to 31, unique), `uplinks` (a color and
  the address the other sites reach this uplink at), `mesh_public_key`
  (filled in by the node itself).
* **`vrf`**: `mesh_slot` (1 to 3) stretches it across the sites where it is
  in effect; `networks` (usually per site, through an override) are
  announced in it.
* **`path_policy`**: traffic carrying a firewall mark goes to the other
  sites over a color, or over the path with the lowest latency or loss.

## Tunnels

A tunnel exists between two nodes when they are at different sites, both
have a fabric index, a public key and an uplink of the same color, and the
topology allows it (in `hub_spoke` one of the two sites is a hub). A
stretched VRF adds a tunnel per color for every pair of sites where it is in
effect. Each tunnel is its own WireGuard device with a single peer and
`AllowedIPs = 0.0.0.0/0, ::/0`, so that the kernel's routing table, filled
by BGP, decides which tunnel a packet takes.

Numbers follow from stable inputs, so a tunnel keeps its device, port and
addresses when other sites come and go (`internal/mesh/mesh.go`):

| | |
| --- | --- |
| link (i<j, color c, slot s) | pool + ((s·4+c)<<10 \| i<<5 \| j)·2, a /31; the lower index gets the even address |
| node loopback | pool x.y.255.<index> |
| port on i towards j | port_base + (s·4+c)·32 + j (512 ports in all) |
| device on i towards j | `tm<j>c<c>s<s>`, for example `tm02c1s0` |

This bounds a fabric to 31 nodes, 4 colors and 3 stretched VRFs.

### Keys

Each node makes its fabric key pair itself and keeps the private key in its
own secret store, outside the cluster's replication: it never leaves the
node. The public key is announced with the node's cluster membership; the
leader writes it into the node's object, where the other nodes read it. A
node outside a cluster writes it itself. Nodes without a key are not in the
fabric yet.

## Routing

FRR runs one BGP session per tunnel over its link addresses, with BFD when
the fabric asks for it (`internal/frrender`, `fabric()`):

* sites with different AS numbers talk eBGP; a hub passes on what it learns;
* sites with the same AS number talk iBGP; in a hub-and-spoke fabric the hub
  is a route reflector for its spokes and sets itself as next hop, because
  spokes have no tunnels to each other;
* every node announces its loopback and its site's networks and accepts
  exactly the other sites' networks and loopbacks;
* ECMP over up to 8 paths; a stretched VRF has its own BGP instance and its
  own tunnels (VRF-lite).

The loopback is put on `lo` by FRR's own `interface lo` stanza. A site's
network is announced only while it is in the routing table (FRR's import
check), so a network that is not there is not blackholed elsewhere.

## Path selection

`internal/pathmon` probes every tunnel's peer address every two seconds and
keeps latency, jitter and loss over the last twenty probes. Per peer node it
chooses a color:

* a path that misses three probes in a row is **down** and is left at once;
* otherwise a path takes over only when it is better by the margin (default
  10 ms) **and** by a fifth, for the hold time (default 15 s);
* by loss: two percentage points better.

The preferred color gets local preference 200 on the sessions it carries,
the others 100, so traffic to that node takes it. BFD notices a dead tunnel
within about a second and withdraws its routes regardless.

A **path policy** builds a routing table of its own (the other sites'
networks through the chosen tunnels) and an `ip rule` from its mark to that
table. A filter rule sets the mark. Traffic to anywhere else finds no route
in that table and continues with the main one. A policy for a color whose
tunnel is down uses the best path instead.

## Firewall

The tunnels are members of the fabric's zone, so rules about traffic between
the sites name that zone. Ahead of the operator's rules every node accepts
the tunnels' UDP ports (WireGuard answers only to keys it knows), and BGP
and BFD on the tunnel devices only, so a default-deny policy cannot cut the
sites apart. The fabric needs the nftables packet filter; the netlink path
refuses it.

## Already distributed

* **Firewall policy** defined once applies on every site: objects in global
  scope are rendered on every node, site- and node-scoped ones where they
  belong (Phase 1).
* **Identities and groups** are cluster-wide: they are in the replicated
  model (Phase 6, 7).
* **Load balancing across sites**: a pool whose backends name their site
  sends traffic to the backends at the local site (and those without a
  site) and fails over to the other sites' backends when the local ones
  fail their HTTP health check (Traefik's `failover` service).

## Tests

* `TestFabricEndToEnd` (real-kernel suite): three daemons in three network
  namespaces form a cluster; each node has its own FRR instance (in its own
  mount namespace) and two emulated uplinks, internet (20 ms) and MPLS
  (5 ms). With nothing but the model: each node makes its key and the
  leader publishes it; tunnels per color appear; BGP with BFD comes up; one
  site's network reaches the other's over a real TCP connection; traffic
  takes the faster MPLS tunnel, and moves to the internet tunnel when MPLS
  degrades to 120 ms; a third site is connected as soon as it is added, and
  its tunnels disappear everywhere when it is removed. The private keys
  stay on their nodes. Passed three times in a row.
* `TestProxyPrefersLocalBackends` (real Traefik): the local backend gets
  the traffic, the other site's takes over when the local one fails its
  health check, and gives it back.
* Unit tests: the planner (full mesh, hub-and-spoke, iBGP reflection,
  stretched VRFs, numbers that stay put, layout limits), the routing
  configuration (sessions, preferences, reflection, VRF, path policy tables,
  fallback when a color is down), accepted by FRR's own parser; the path
  monitor's hysteresis and failover; the model checks.

## Status

Phase 8 is complete for IPv4 fabrics, with these parts **not verified or not
built**:

* **Stretched VRFs and path policies with traffic.** Both are rendered,
  checked by FRR's parser and unit tested; no end-to-end test sends traffic
  through them.
* **Hub-and-spoke and iBGP reflection with real daemons.** Unit tested;
  the end-to-end test runs a full mesh with eBGP.
* **The live tunnel table in a browser.** Its data was checked in the
  end-to-end test through the runtime report; in the browser only the
  "not in the fabric" message was seen.
* **EVPN/VXLAN** for layer-2 extension was optional and is not built.
* **IPv6 in the fabric**: link addresses and loopbacks are IPv4; IPv6 site
  networks are not carried.
* **Raft over the fabric**: cluster traffic runs where the cluster was told
  to listen (with mutual TLS). The loopbacks would serve, but a cluster
  formed over the underlay cannot move onto them yet.

Known limits:

* At most 31 nodes, 4 colors and 3 stretched VRFs per fabric (the address
  and port layout).
* Path preference is per peer node, not per application; per-application
  steering is what path policies are for.
* Probes need the unprivileged ICMP socket
  (`net.ipv4.ping_group_range`); Debian's default allows it.
* A site's network is announced only while it is in the node's routing
  table.
* Changing the fabric's pool, port base or a node's index renumbers its
  tunnels: every session involved drops once.
