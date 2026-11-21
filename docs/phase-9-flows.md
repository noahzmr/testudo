# Phase 9: Flow analysis for the new paths

The capture pipeline from before is unchanged in what it counts: one entry
per interface and connection, bytes and packets per direction (the
Phase 0 baseline guards it at every commit). What is new is that every flow
is placed in the appliance's own terms, that tunnels created later are
captured too, and that what several sites saw of one connection can be
joined.

```text
 capture (per interface) ─► flow table ─► Decorate (process, DNS, service)
                                              │
     model ──┐                                ▼
  conntrack ─┼─► flowattr.Index ───────► Attribute ─► dashboard, storage, IPFIX
 proxy log ──┘    (every 3 s)                 │
                                              ▼
                       member API (mutual TLS) ─► flowcorr ─► /api/v1/flows/sites
```

## Attribution

Every flow carries `attrs` (`internal/flows`, `flows.Attrs`), filled by
`internal/flowattr` from three sources. A field stays empty when nothing is
known.

| Field | From | Meaning |
| --- | --- | --- |
| `site`, `zone`, `vrf` | model: the node's site, the interface's zone and VRF; tunnels' and the fabric's zones | where the flow was seen |
| `tunnel`, `peer`, `user` | model: WireGuard tunnels, peers by allowed IPs, the peer's user | whose traffic a VPN tunnel carries |
| `tunnel=fabric`, `peer`, `peer_site`, `path` | the fabric plan | which site and color a fabric tunnel leads to |
| `carrier` | fabric endpoints, tunnel listen ports | the encrypted UDP that carries a tunnel over an uplink |
| `pre_nat`, `post_nat` | conntrack (translated entries only) | the connection before and after address translation |
| `lb_role`, `lb_service`, `lb_backend` | conntrack, for services balanced in the packet filter | client side or backend side, and which backend |
| `lb_role`, `lb_service`, `lb_router`, `lb_host`, `lb_backend` | the proxy's access log, for proxy services | which router and host sent a client's request to which backend; the proxy's connection to that backend gets the same |
| `conversation` | derived | shared by flows that are parts of one exchange: both sides of a translation; a client's connections and the backend connection they were passed to |

Details that matter:

* The conntrack dump asks for translated entries only, at most 50 000, so a
  busy router does not ship its whole table every few seconds. An entry the
  kernel flags as translated although nothing changed is ignored.
* A proxy listener on every address matches only connections to the node
  itself and in the listener's zone; port 443 elsewhere is someone else's.
* The proxy writes HTTP requests to its access log; TCP routers (SNI
  passthrough) have no log, so their flows are attributed as balancer
  traffic by service and backend, without router and host.

The attribution is shown in the flow table (column *Where*), stored with
the flow (one JSON column `attrs`, added to existing databases by
migration) and kept when a later flush knows less.

## Capture follows new interfaces

Auto-discovered capture used to look for interfaces once, at start. A
WireGuard device or fabric tunnel created afterwards was never captured.
It now looks again every five seconds, starts on new interfaces and stops
on vanished ones. Tunnels without a link layer are read as bare IP, as
before. The flow baseline runs a test for it.

## IPFIX

Records carry the connection after translation: `postNATSourceIPv4Address`,
`postNATDestinationIPv4Address`, `postNAPTSourceTransportPort`,
`postNAPTDestinationTransportPort` (IANA 225 to 228). A translated flow is
sent the way it was opened (from its `pre_nat`), with its translated
addresses; other flows repeat their own. The template changed; collectors
read the new one from the template set as usual.

## Across sites

Each member collects its own flows. Nothing of it goes through the
cluster's consensus log. When someone opens *Cluster → Flows across sites*
(`GET /api/v1/flows/sites`), the member asks every other member over the
member API (mutual TLS) for its 2 000 most recently active flows, attributed,
and `internal/flowcorr` joins them:

* the same addresses and ports, either way round, before or after a
  translation, seen within 30 seconds of each other, are one connection;
* the result lists the sites that saw it, the fabric colors it took, and
  every sighting (member, interface, attribution);
* by default only connections seen at more than one member; `?all=1` adds
  the rest.

A member that does not answer within five seconds is listed with the error
and left out.

## Retention

| Data | Kept |
| --- | --- |
| live flow table | in memory, at most 4 096 flows, the oldest evicted |
| session flows (`flows` table, with attribution) | 30 days after they were last seen (new: they were never deleted) |
| flow snapshots | 30 days, at most the newest rows of the global cap |
| raw samples | 30 days |
| rollups (baselines) | 365 days |
| attribution sources | conntrack: what the kernel holds; proxy access log: the last 5 minutes and 20 000 requests in memory (the file itself is not rotated by Testudo) |
| cross-site view | not stored; computed when asked |

## Tests

* `TestFlowBaseline` (unchanged) and `TestCaptureFollowsNewInterfaces`
  (new) in the flow baseline, before every commit.
* `TestNATAttributionOnARealKernel`: an nftables port forward between
  namespaces, real capture on both sides of the router, real conntrack: the
  outside and inside flows carry the same before/after translation and one
  conversation, each in its zone.
* `TestVPNEndToEnd`: a road warrior's connection through the tunnel is
  attributed to her peer and her user, in the daemon's own flow table.
* `TestFabricEndToEnd`: a connection from one site's network to another's
  appears in the cross-site view once, seen at both members inside the
  fabric tunnel, with peer, peer site and the path it took.
* `TestProxyPrefersLocalBackends`: the real proxy's access log yields the
  client, router and backend attribution reads.
* Unit tests: attribution of VPN, fabric, carrier, NAT, kernel and proxy
  balancing flows, listeners elsewhere not mistaken for the proxy; the
  access-log follower (partial lines, rotation, forgetting); the cross-site
  join (tunnels, translations, time window); IPFIX decoded from the wire;
  the attribution column and its migration; flow retention.

## Status

Phase 9 is complete with these parts **not verified or not built**:

* **Proxy balancing attribution in a running daemon.** The access-log
  format was checked against the real proxy and the join is unit tested;
  no end-to-end test captures client and backend connections through the
  daemon.
* **Kernel balancing and VRF attribution with traffic.** Unit tested.
* **Attributed rows in the browser.** The column renders; rows with
  attribution were checked through the API.
* **Conntrack events.** Conntrack is read every three seconds, not
  subscribed to; a translation that lives shorter than that can be missed.
* **NetFlow v9** export is not built; IPFIX is.
* Unchanged from before: flows have no initiator (A and B are ordered by
  address), ICMP and other non-TCP/UDP protocols are not in the flow table,
  and IPFIX carries IPv4 only.

Known limits:

* Policy routing (path policies, policy routes) is visible through the
  tunnel or interface a flow was seen on, not through the mark that sent it
  there.
* The cross-site view compares the most recent 2 000 flows per member; on a
  busy member a long-lived connection can drop out of that window.
* A member's flows reach another member only as the answer to a request;
  there is no central flow store.
