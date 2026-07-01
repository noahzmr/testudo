# WireGuard

Status: **roadmap**. Testudo today treats `wg0` as a generic interface, so a few
things work by accident (AF_PACKET capture, interface-health polls, flow scope
labels, routes over the tunnel). The dedicated subsystem described here adds the
part that doesn't live in normal link-state.

The build checklist and ordering live in
[.claude/todos/wireguard.md](../.claude/todos/wireguard.md); this document is the
design rationale behind it.

## Why a dedicated subsystem

WireGuard state lives in its own generic-netlink family (`WG_CMD_GET_DEVICE`),
not in RTNETLINK link-state. An interface can be `UP`/`RUNNING` while the tunnel
is effectively dead - no handshake, peer unreachable. Without reading the WG
family directly, Testudo cannot see peers, last handshake, endpoints, allowed
IPs, per-peer RX/TX, or persistent-keepalive - and therefore cannot raise the
single most important WG health signal: "handshake older than 3 minutes."

## Technical approach

Uses `golang.zx2c4.com/wireguard/wgctrl` (+ `wgtypes`). It speaks
generic-netlink directly and falls back to the UAPI socket under
`/var/run/wireguard/*.sock` - no `wg`/`wg-quick` binary, no `cgo`, consistent
with the rest of the platform.

| Need                     | API                                          |
| ------------------------ | -------------------------------------------- |
| Read all devices + peers | `wgctrl.Client.Devices()` / `Device(name)`   |
| Configure device/peers   | `wgctrl.Client.ConfigureDevice()`            |
| Generate private key     | `wgtypes.GeneratePrivateKey()`               |
| Generate preshared key   | `wgtypes.GenerateKey()`                       |
| Routes                   | existing `netops` route backend              |
| Firewall                 | existing `netops` nftables/iptables backend  |

One collector plus the existing `netops` backend feeds both the TUI and Web UI
from the same snapshots. Every privileged mutation goes through the write-gated,
audit-logged `privsep` helper, gated by `--allow-netops-write`.

## Secrets rule (non-negotiable)

Private and preshared keys **never** touch `audit_log`, snapshots, or SQLite -
only public keys / fingerprints are persisted or logged. A client config
containing a private key is rendered exactly once (server-side keygen mode),
then dropped from memory. QR codes are generated client-side in the browser, so
the key is not re-sent over the network. An audit entry reads
`peer added, pubkey=abc123…`, never the secret.

## Monitoring

Collector (`internal/wireguard`) polls ~5–10 s and emits a
`KindWireGuardSnapshot` per tick - device (name, public key, listen port,
fwmark) and per peer (public key truncated, endpoint, allowed IPs, last
handshake, RX/TX bytes, persistent-keepalive). Per-peer throughput history uses
rolling buckets like existing per-device bandwidth (→ sparkline).

Handshake anomaly (`internal/analyzers`) rides the existing severity ladder and
incident engine:

| Condition                                   | Severity |
| ------------------------------------------- | -------- |
| last handshake > 180 s (peer w/ keepalive)  | WARN     |
| last handshake > 300 s                       | ERROR    |
| never established                            | CRITICAL |

Secondary signal: RX/TX stalled on an otherwise-active peer. A small WG
sub-score (~5 %) feeds the Network Quality grade, neutral 100 when no WG device
exists (the existing "nothing measured → no penalty" contract). Samples persist
to `wireguard_samples` (peer, handshake age, RX/TX per tick) for replay -
**public keys only**. The WG collector appears as its own row in the Health
subsystem-status table, soft-failing to "not available" when no WG interface is
present.

## Management

### Provision Peer is a transaction, not a call

A full add-peer flow spans multiple subsystems and rolls back on any failure -
never leaving a half-configured state. It runs entirely in the privileged helper
as a single audit-logged operation:

1. **Generate keypair** - Curve25519 via `wgtypes` (client-side by default; the
   private key never leaves the client device). Server-side keygen is offered
   for convenience but the key is never persisted.
2. **Assign IP** - small IPAM: next free address in the server subnet, avoiding
   collisions with existing AllowedIPs. No extra persisted state - the tunnel is
   the source of truth.
3. **Configure the peer** - `ConfigureDevice` with the new public key + AllowedIPs.
4. **Set route** - for simple setups WireGuard handles this via AllowedIPs; for
   site-to-site, an explicit route over `wg0` through the existing route backend.
5. **Apply firewall preset** - through the existing firewall backend.
6. **Return client config** - server-side mode only; rendered once, then gone.

### Firewall presets (not free-form rules)

Presets bound the degrees of freedom because the firewall is where mistakes cost
the most - a wrong FORWARD or masquerade rule either blocks peer traffic
entirely or silently creates open routing.

| Preset               | Behaviour                                                   |
| -------------------- | ----------------------------------------------------------- |
| **Full tunnel**      | peer reaches everything; masquerade on the WAN interface    |
| **Split / LAN-only** | peer reaches only specified subnets; FORWARD otherwise DROP |
| **Isolated**         | peer reaches only the server; no peer-to-peer               |

Every Testudo-created rule carries a `testudo-wg-peer-<id>` marker/comment so
removal finds it cleanly. **Deprovision Peer** is the transactional reverse path:
remove peer from the device, remove its route, remove all `testudo-wg-peer-<id>`
firewall rules, free the IP.

## UI parity

Mirrored in TUI and Web (same contract as the rest of the platform):
an "Add Peer" wizard (name, keygen mode, firewall preset, optional fixed IP) and
a peer list showing live handshake data from the monitoring side. Web adds
`GET /api/wireguard` (snapshot), `POST /api/wireguard/peer`, etc.

## Adding this subsystem

1. Add `golang.zx2c4.com/wireguard/wgctrl` (+ `wgtypes`) to `go.mod`.
2. Create `internal/wireguard/` (collector, keygen/IPAM, provisioning orchestrator).
3. Add `KindWireGuardSnapshot` to `internal/events` and the handshake rule to
   `internal/analyzers`.
4. Add the `wireguard_samples` table to `internal/storage`.
5. Wire the WG sub-score into `internal/quality` and the Health tab.
6. Add the TUI tab + Web routes; update this doc and `DEVELOPER.md`.
