# Phase 5: Load balancing, SNI routing and certificates

Design: [ADR 0001](adr/0001-managed-traefik-vs-native-proxy.md). The model's
load-balancer objects now drive two data planes from one definition: a
managed proxy (Traefik) for HTTP, TLS and SNI, and the packet filter for
plain TCP and UDP at kernel speed.

## What the model drives

| Kind | Becomes |
| --- | --- |
| `lb_service` in proxy mode | an entry point of the proxy |
| `lb_service` in kernel mode | a destination NAT rule in `inet testudo` |
| `lb_router` | an HTTP or TCP router: host, path prefix, SNI |
| `lb_backend_pool` | a proxy service with servers, or the targets of the NAT rule |
| `middleware` | a proxy middleware |
| `certificate` | a Let's Encrypt resolver, or a certificate file plus key |

The stage order is WireGuard, packet filter, routing, load balancer: the
proxy starts last because its backends are reached over what the earlier
stages set up.

## Proxy mode

`internal/lbrender` renders two files below `<storage>/proxy`:
`traefik.yml` (entry points, API on loopback, metrics, certificate
resolvers) and `dynamic/testudo.yml` (routers, services, middlewares,
certificates). `internal/lbstage` writes them, the dynamic file last, and
restarts the proxy only when the static file changed; everything else the
proxy picks up while running.

* **Host and path routing** for `http` and `https` services.
* **SNI routing** for `tcp` services: `passthrough` hands the TLS stream to
  the backend untouched, `terminate` ends TLS at the proxy. A service's
  fallback pool takes names no router matched, for plain and for TLS
  connections.
* **Weighted round robin**, active **health checks** (TCP or HTTP),
  **sticky sessions** by cookie, **PROXY protocol** towards TCP backends,
  **draining** (a draining backend gets no new traffic).
* **Require a login**: a router with `require_groups` asks a loopback
  listener of the engine before it forwards. Until Phase 6 installs the
  login service the listener refuses, so such a router is closed, not open.
* Middleware settings are translated one by one; an unknown setting is an
  error, not ignored.

The proxy has no offline check for its dynamic configuration. The stage
therefore asks the proxy's API after the apply whether every router was
accepted. A refusal fails the apply and the previous configuration is put
back, by the same rollback that protects the packet filter.

### Privileges

The proxy is started by the privileged runner (the same child that runs
`nft` and FRR), through `testudo __proxy-exec`, which drops every capability
except binding low ports before it executes Traefik. The proxy's API and
metrics listen on `127.0.0.1:18089`. The proxy dies with the runner.

## Kernel mode

A `tcp` or `udp` service with `mode: kernel` never touches the proxy.
`internal/fwrender` writes, per address family:

```text
iifname @z_wan tcp dport 443 counter dnat ip addr . port to \
    numgen inc mod 4 map { 0-2 : 10.50.0.2 . 8443, 3 : 10.50.0.3 . 8443 }
```

* Weights are slots of the map. A **sticky** pool replaces the counter with
  a hash of the client address.
* **Draining** and **unhealthy** backends are left out; connections they
  already have continue, because an established connection keeps its
  translation.
* The kernel cannot check health, so `internal/lbhealth` does (TCP connect
  or HTTP GET, two results in a row change the state) and the packet-filter
  stage reloads when a backend changes state. No model change, no
  confirmation window: the rules are the ones already confirmed.
* The client's address is preserved. The backends therefore need a route
  back through the firewall.
* A translated connection is forwarded by the existing
  `ct status dnat accept`; no extra filter rule is needed.
* Kernel mode sees no names: the model refuses routers, `http`/`https`,
  and the PROXY protocol on such a service.

## Certificates

Two sources are first-class:

* **Let's Encrypt** (`source: acme`). The resolver names the Let's Encrypt
  directory explicitly, production by default and staging when the
  certificate says so. Challenges: HTTP-01 (needs an HTTP service on port
  80), TLS-ALPN-01 (needs a service on port 443), DNS-01 (required for
  wildcards). The proxy obtains and renews the certificate and keeps the
  account and keys in `<storage>/proxy/acme.json`, mode 0600.
* **Local** (`source: internal_ca`). `internal/pki` is a certificate
  authority whose key lives in the node's secret store. `POST
  /api/v1/pki/issue` issues a server certificate; `GET /api/v1/pki/ca` hands
  out the authority's certificate for clients to trust.

A certificate issued elsewhere can be imported (`POST /api/v1/pki/import`):
the key is checked against the certificate, stored in the secret store and
never returned.

In every case the model holds the certificate chain and the *name* of the
key entry. Private keys are not in the configuration log, in snapshots, in
API answers or in the audit log.

`GET /api/v1/runtime` reports the expiry of every certificate the model
holds; the console marks one with fewer than 14 days left.

## Firewall rules are proposed, not created

A proxy-mode service needs an inbound filter rule. `GET
/api/v1/lb/firewall-hints` says per service whether an enabled rule already
lets clients in and, if not, returns the rule that would. The console shows
it with a button. Creating it is an ordinary write: reviewed, applied,
confirmed within 60 seconds.

## Observability

Per pool: requests, 5xx answers, mean answer time, and the health of each
backend, from the proxy's metrics and API. Per kernel-mode service: the
counter of its rule. Both appear in `GET /api/v1/runtime` and in the
console's Pools and Services tabs.

## Tests

* `TestProxyOnARealKernel` (real Traefik 3.3.4 between network namespaces):
  host routing; a 3:1 weighting gives exactly 30 and 10 of 40 requests; SNI
  passthrough shows the client each backend's own certificate, including a
  wildcard name; SNI termination presents a certificate from the local
  authority that verifies; an unknown name reaches the fallback pool; a
  failing backend is taken out by the health check and reported as down; a
  configuration the proxy refuses is rolled back and the old one keeps
  serving; removing every service stops the proxy.
* `TestKernelBalancingOnARealKernel` (real nftables, default deny): 3:1
  weighting with the client address preserved; a sticky pool keeps a client
  on one backend; draining; a backend marked down is left out and comes
  back; with every backend down the service refuses.
* Unit tests: renderer golden file and refusals, kernel-mode rules for both
  families, the health monitor's streaks, the model's checks, the
  certificate authority, the certificate and hint endpoints.
* The certificate screens were run in a browser: issue from the local
  authority, save, expiry in the list, a Let's Encrypt certificate.
* The image for real-kernel tests now contains Traefik, pinned by version.

## Status

Phase 5 is complete as specified, with these parts **not verified**:

* **Let's Encrypt itself.** The resolver configuration is rendered and unit
  tested. It has not been loaded into a running proxy, and no certificate
  has been obtained from
  Let's Encrypt or from a test ACME server: the test environment has no
  network. Try the staging switch first on a real host.
* **Backends reached over WireGuard.** Nothing prevents it (the proxy runs
  after the tunnels are up), but no test does it.
* **The proxy under the full privilege separation.** The test drives the
  supervisor directly; the path through the helper, the runner and
  `__proxy-exec` with its capability drop is built and not exercised.
* **The loops in the running daemon**: backend health for kernel mode and
  the fail-closed login listener are tested as parts, not in the binary.
* **UDP** in either mode, **IPv6** in kernel mode, **sticky cookies**, the
  **PROXY protocol** and every middleware except a refused one are rendered
  and unit tested, not checked with traffic.
* The **filter-rule proposal button** was tested through the API, not seen
  in a browser (the development host has no proxy to enable a service).

Known limits:

* `least_connections` is in the model and refused by both data planes.
  The kernel path would need IPVS for it.
* DNS-01 needs the provider's credentials in the proxy's environment, and
  there is no place to enter them yet.
* Certificates from the local authority are not renewed automatically; the
  console shows their expiry and "Issue again" replaces one.
* Only the mean answer time is reported, no percentiles.
* Kernel mode has no hairpin: a client behind the firewall cannot reach a
  service through its outside address.
