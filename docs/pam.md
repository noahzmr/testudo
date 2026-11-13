# Privileged access (PAM)

Testudo's access layer turns the WireGuard concentrator into a **remote
privileged access** system: a human requests time-boxed access to a named
resource, a different human approves it (or a policy auto-approves), the grant
is compiled into firewall rules for exactly that user's peers, its traffic is
recorded, and when it ends - by TTL or revocation - the rules go and live
connections are killed. Every step is appended to a hash-chained access log.

```text
request ──► pending ──approve──► active ──ttl / revoke──► expired | revoked
               │                   ▲
               └──deny──► denied   └── break-glass (admin, no policy, ≤ 4 h)
```

| Piece | Where | Role |
| ----- | ----- | ---- |
| control plane | `internal/pam` | resources, policies, grant lifecycle, separation of duties |
| enforcement | `internal/firewall` | grant → `forward accept iif wg0 src <peer> dst <resource> …` rules owned by `pam-grant:<id>` |
| session kill | `netops.ListConntrack` / `FlushConntrack` | connections from the peers to the resource are flushed when the grant ends |
| recording | `capture.TCPDumpManager` | one rolling pcap per grant: `(host <peer> …) and net <resource>` |
| identity | `internal/auth` | roles, MFA; peers bind to users via `wg_peer_meta.user` |
| proof | `access_events` (`internal/storage/pam.go`) | SHA-256 hash chain; `VerifyAccessEvents` detects edits and deletions |

## Objects

**Resource** - what can be reached: name, kind (`l3`, `ssh`, `rdp`, `https`),
address or CIDR, optional proto/port range, a login hint and a broker
reference (Guacamole connection id, SSH CA profile). `ssh`/`rdp`/`https`
default to tcp/22, 3389, 443 when no port is given.

**Policy** - who may ask: `subject` is `user:<name>` or `role:<role>` (the
requester's role must be at least that role), a resource, `max_ttl_sec`,
`requires_approval`, `requires_mfa`.

**Grant** - one request and its whole life: user, resource, policy, state,
justification, ticket, requested/decided/started/ended timestamps, the peer
addresses it was compiled for, capture id, observed flows/bytes, break-glass
flag.

## Rules

* A **justification is mandatory**; break-glass needs at least 10 characters.
* **Separation of duties**: operators request, approvers/admins approve - and
  nobody approves their own request.
* **MFA-gated resources** refuse requesters who have not enrolled an
  authenticator.
* A user with **no bound WireGuard peer** cannot be granted anything
  (`ErrNoPeer`); bind peers under Access → Peer bindings (admin).
* Activation is **all-or-nothing**: if one rule fails to install, the ones
  already added are removed and the grant stays pending with the error shown.
* **Break-glass** (admin only) bypasses policy and approval, is capped at 4 h,
  and raises a WARN alert.
* Resources with pending or active grants cannot be deleted.

## Lifecycle details

* **Activate**: resolve the user's peer tunnel addresses → one
  `forward accept` rule per address (`Owner: pam-grant:<id>`) → start the
  capture → state `active`, `ends_at = now + ttl`.
* **Deactivate** (expire / revoke): `DelRulesByOwner` → flush every conntrack
  entry from the peers to the resource → stop the capture → record how many
  rules were removed and flows killed.
* The manager ticks every 10 s: expires overdue grants and samples conntrack
  so `observed_flows` / `observed_bytes` show whether the access was used.
* After a restart the firewall reconciler re-installs the rules of grants that
  are still valid (they are ordinary policy rules) and the PAM manager expires
  the ones whose window passed while Testudo was down.

## HTTP API

| Method | Path | Role |
| ------ | ---- | ---- |
| GET | `/api/pam` | any (overview, events, chain check) |
| POST | `/api/pam/request` | operator+ |
| POST | `/api/pam/approve`, `/api/pam/deny` | approver or admin |
| POST | `/api/pam/revoke` | requester, approver or admin |
| POST | `/api/pam/breakglass` | admin |
| POST | `/api/pam/resource/add|del`, `/api/pam/policy/add|del`, `/api/pam/peer/bind` | admin |

Alerts: break-glass, denials and activation failures surface as WARN
anomalies; the ordinary lifecycle as INFO (source `pam`).

## Brokered sessions (no standing credentials)

**Guacamole** (`internal/integrations/guacamole`): with API credentials set in
Settings (`Guacamole API user / password`, an account allowed to manage
connections), an `ssh` or `rdp` grant creates a **per-grant connection**
named `pam-<grant>-<user>`: the parameters of the resource's template
connection (`broker ref`, where an admin stored the target credentials) are
cloned, `recording-path` / `typescript-path` are set so the session is
recorded under the grant id, and a Guacamole user with the same name as the
Testudo user is given READ on it. The Access tab shows **open session**. At
grant end the live session is killed and the connection deleted; the target
credential never left Guacamole. A broker failure is recorded
(`broker_failed`) and does not block the L3 grant.

**SSH CA** (`internal/sshca`): Testudo keeps an Ed25519 user CA under
`~/.testudo/sshca/` (private key 0600, never exported). Targets trust it with

```text
TrustedUserCAKeys /etc/ssh/testudo_ca.pub      # the key shown on the Access tab
```

For an active `ssh` grant the requester pastes their own public key (**ssh
cert** on the Access tab, or `POST /api/pam/ssh/cert`) and receives a
certificate valid exactly for the grant window, for the resource's `login`
as principal, usable only from the grant's peer addresses
(`source-address`). Nothing is left to revoke: the certificate expires with
the grant.

## Out of scope (by design)

Password vaulting and rotation, endpoint privilege elevation. See
[.claude/todos/pam.md](../.claude/todos/pam.md) for what is still open
(OIDC, export/replay, enrollment links, approvals notifications).
