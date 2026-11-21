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
| catalogue | the model | `access_resource`, `access_policy` and `access_grant` objects, replicated to every member |
| control plane | `internal/pam` | requests, approvals, grant lifecycle, separation of duties |
| enforcement | `internal/fwrender` | an `access_grant` → `forward accept` rules from the user's peers to the resource, commented with the grant's id |
| session kill | `netops.ListConntrack` / `FlushConntrack` | connections from the peers to the resource are flushed when the grant ends |
| recording | `capture.TCPDumpManager` | one rolling pcap per grant: `(host <peer> …) and net <resource>` |
| identity | `internal/identity` | users, roles, MFA; a WireGuard peer belongs to the user named on it in the model |
| proof | `access_events` (`internal/storage/pam.go`) | SHA-256 hash chain; `VerifyAccessEvents` detects edits and deletions |

## Objects

**Resource** (`access_resource`, model) - what can be reached: type
(`network`, `ssh`, `rdp`), address or network, protocol and ports, a login
name and a broker reference (Guacamole connection id).

**Policy** (`access_policy`, model) - who may ask: users, groups or every
authenticated user, a resource, the longest grant, whether it needs
approval and a second factor.

**Request** (SQLite, per member) - one request and its whole life: user,
resource, policy, state, justification, ticket, requested/decided/started/
ended timestamps, capture id, observed flows/bytes, break-glass flag.

**Grant** (`access_grant`, model) - what an approved request, a policy
without approval or a break-glass becomes: user, resource, end, policy,
justification, approver. While it exists the packet filter of every member
lets the user's peers reach the resource.

## Rules

* A **justification is mandatory**; break-glass needs at least 10 characters.
* **Separation of duties**: operators request, approvers/admins approve - and
  nobody approves their own request.
* **MFA-gated resources** refuse requesters who have not enrolled an
  authenticator.
* A user with **no WireGuard peer** in the model cannot be granted anything
  (`ErrNoPeer`); a peer belongs to the user named on it.
* Activation is a model change: if it fails, the request stays pending with
  the error shown.
* **Break-glass** (admin only) bypasses policy and approval, is capped at 4 h,
  and raises a WARN alert.
* Resources with grants cannot be deleted (the model refuses to delete an
  object something refers to).

## Lifecycle details

* **Activate**: create the `access_grant` object (forwarded to the cluster's
  leader, with the actor `system`) → every member renders it into its packet
  filter → start the capture → state `active`, `ends_at = now + ttl`.
* **Deactivate** (expire / revoke): delete the grant object → every member's
  ruleset loses its rules, and every member flushes the conntrack entries
  from the peers to the resource → stop the capture → record how many flows
  were killed.
* The manager ticks every 10 s: expires overdue requests and samples
  conntrack so `observed_flows` / `observed_bytes` show whether the access was
  used. The cluster's leader also removes any grant 30 s past its end, so a
  grant ends even when the member that made it is down.
* After a restart the grants are still in the model and still in the
  ruleset; the ones whose end passed while Testudo was down are removed.

Resources and policies are edited like every other model object (Access in
the Web UI, `/api/v1`). Those of older builds were moved into the model on
the first start.

## HTTP API

| Method | Path | Role |
| ------ | ---- | ---- |
| GET | `/api/pam` | any (overview, events, chain check) |
| POST | `/api/pam/request` | operator+ |
| POST | `/api/pam/approve`, `/api/pam/deny` | approver or admin |
| POST | `/api/pam/revoke` | requester, approver or admin |
| POST | `/api/pam/breakglass` | admin |

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
`<storage>/sshca/` (private key 0600, never exported). Targets trust it with

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
[GAP-ANALYSIS.md](GAP-ANALYSIS.md) for what is still open
(export/replay, enrollment links, approvals notifications).
