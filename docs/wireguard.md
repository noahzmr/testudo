# WireGuard

WireGuard has two halves in Testudo: monitoring (this page) and the
tunnels and peers themselves, which are objects of the configuration model
configured by the WireGuard stage ([phase-4-vpn.md](phase-4-vpn.md)). What
is still open is tracked in [GAP-ANALYSIS.md](GAP-ANALYSIS.md).

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
| Configure device/peers   | `wgctrl.Client.ConfigureDevice()` (WireGuard stage) |
| Routes                   | the routing stage (FRR)                      |
| Firewall                 | the packet-filter stage                      |

One collector feeds both the TUI and Web UI from the same snapshots. Every
privileged mutation goes through the write-gated, audit-logged `privsep`
helper, gated by `--allow-netops-write`.

## Secrets rule (non-negotiable)

Private and preshared keys **never** touch `audit_log`, snapshots, or SQLite -
only public keys / fingerprints are persisted or logged. The tunnel's own
private key lives in the node's secret store; a peer's key pair is made in
the browser, which shows the client configuration and its QR code once. An audit entry reads
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

Tunnels (`wg_tunnel`) and peers (`wg_peer`) are model objects, changed like
any other: in the Web UI's WireGuard section or through `/api/v1`, with the
usual commit-confirm. A peer names the user it belongs to; access grants and
the identity on flows follow from that. What a peer may reach is a matter of
filter rules (and access grants), not of a preset.

The TUI's WireGuard tab and the console's live view show the running
devices and peers read-only. The old provisioner (keygen, address pool,
presets, netplan files) is gone; the rules it wrote moved into the model
with the old firewall policy file ([firewall.md](firewall.md)).
