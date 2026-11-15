# Phase 4: WireGuard and identity-aware access

Design note. The status at the end says what is verified and what is not.

## What the model drives

| Object | Becomes |
| --- | --- |
| WireGuard tunnel | a kernel WireGuard device with its addresses, port and MTU, in a firewall zone |
| WireGuard peer | a peer of that device, optionally bound to a user and groups, optionally with an expiry |
| Access resource | something a policy can open: a host or network, with protocol and ports |
| Access policy | who may reach a resource: users, groups or everyone with an identity |

`internal/wgrender` renders the devices for one node. A disabled peer and a
peer past its expiry are left out; two peers of one tunnel may not claim
overlapping addresses or share a key, and the change that would cause it is
refused with both names.

## Keys never enter the model

A tunnel's private key and a peer's preshared key live in the node's secret
store (`<storage>/secrets`, one file per entry, mode 0600). The model holds
the **name** of the entry (`key_ref`, `preshared_ref`), which the API masks.
The apply stage and the privileged helper pass names only; the helper reads
the key where the device is configured. Nothing with key material is written
to the configuration log, the audit log or a snapshot, and a test checks the
log for it.

* `POST /api/v1/wg/tunnel-key` creates a tunnel key on the node and returns
  the entry name and the public key.
* `POST /api/v1/wg/preshared-key` creates a preshared key and returns it
  once.
* A **client's private key is generated in the browser** (X25519 through the
  Web Crypto API) and never sent anywhere. A browser that cannot do that
  falls back to `POST /api/v1/wg/client-keypair`, which returns a pair once
  and stores nothing.
* `GET /api/v1/wg-peers/{id}/client-config` returns the peer's configuration
  with placeholders where the two secrets go. The console fills them in from
  memory right after it created them and shows the complete file, a QR code
  and a download **once**.

Rotation is the same buttons on an existing object: a new tunnel key or a
new client key pair, put into effect by saving.

## Applying without cutting tunnels

`internal/wgstage` runs before the packet filter and the routing daemon,
because both refer to the devices. The kernel sync sends only differences.
That matters: setting a private key, even the same one, expires every peer's
session keys, and replacing a peer forgets where it is. A sync that rewrote
everything would cut every tunnel on every configuration change, including
the one an operator is using to make the change. (The end-to-end test found
exactly that in the first version.)

A model without tunnels leaves the node's WireGuard devices alone. A model
tunnel that names an **existing device** takes it over: its peers become
exactly the model's peers. Leaving `key_ref` empty keeps the device's key, so
a device can be adopted without its key ever being read;
`testudo config import-legacy` creates tunnels and peers that way.

Devices the stage created are removed when their tunnel is.

## Routes and firewall

* Every tunnel is in a zone, so filter rules, NAT and default deny apply to
  VPN traffic like to any other.
* For a **site-to-site** tunnel the networks behind a peer get a route
  through the tunnel device in the routing daemon. From the routing table
  they can be originated into BGP (`announce` on a neighbor), which is how
  tunnel routes reach the rest of the network. Road-warrior peers need no
  routes: their addresses are inside the tunnel's own network.
* The management port is in the lock-out baseline, so the console and the
  API are reachable over a tunnel without any rule.

## Identity-aware access

A peer bound to a user may reach a resource when a policy names the user,
one of the user's groups, one of the peer's groups, or everyone. The rule
that is rendered matches the peer's **own tunnel address** on its tunnel's
device, so access follows the identity and not a network:

    iifname "wg0" ip saddr { 10.8.0.2 } ip daddr 10.50.0.10 tcp dport 22 accept

A peer without a user matches no policy. A disabled user and a disabled peer
get nothing. Removing a user from a policy closes the resource at the next
apply, and the model's history says who changed it.

A policy that requires approval or a second factor grants nothing by itself.
Access under it is still given for a limited time by the existing access
manager when a request is approved; that flow moves onto model objects with
authentication in Phase 6.

## Tests

* `TestVPNEndToEnd` (real kernel, real binary, privilege separation): the
  operator builds site, node, zones, firewall policy, tunnel, user, peer,
  resource and policy over the HTTP API. A WireGuard client in another
  namespace connects. Then, **through the tunnel**: log in, read, change
  configuration and confirm it, load the console. The client reaches the
  resource its policy grants (the server sees its tunnel address) and not
  another port; after the user is removed from the policy the resource is
  closed while management still works; after the peer is revoked the tunnel
  is dead. No key material is in the configuration log.
* Unit tests: devices and expiry, conflicts by name, client configurations
  for split and full tunnel, identity rules for users, groups, everyone,
  disabled users and unbound peers, site-to-site routes, the stage's dry run
  against the secret store.
* The peer flow was run in a browser: key pair generated there, preshared
  key, the complete configuration with QR shown once, placeholders when the
  peer is reopened.

## Status

Phase 4 is complete as specified, with these parts not verified:

* **Site-to-site between two appliances.** The routes are rendered and unit
  tested; no test connects two nodes. That arrives with the site mesh in
  Phase 8.
* **IPv6 inside a tunnel under traffic.** Addresses, allowed IPs and rules
  handle both families; the end-to-end test uses IPv4.
* **Expiry in the running daemon.** The renderer and the stage are tested
  with a clock; the 30-second loop that triggers it is not exercised.
* **The runner as a non-root user**, as before.

Known limits:

* Rotating a key leaves the previous entry in the secret store.
* The existing WireGuard pane (Running state) still provisions peers its own
  way, with its own firewall presets. Peers made there on a device that the
  model also manages are removed at the next apply.
* Flow capture discovers interfaces at start, so a tunnel created later is
  captured after a restart (Phase 9).
* Identities are model users; logging in as them through OIDC or host PAM,
  and group membership from an identity provider, are Phase 6.
