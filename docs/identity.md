# Identity, roles and audit

Every privileged action in Testudo is attributable to a **human**: the Web UI
session user, the OS user at the TUI, or the CLI caller. This is the layer the
firewall, WireGuard and access grants hang off.

Logins through the host's PAM stack and an identity provider, API tokens and
the audit endpoint are described in [phase-6-identity.md](phase-6-identity.md).
This page covers local users, roles, sessions and the command line.

## Users

Users are objects of the configuration model (`user`, with `source` `local`,
`host` or `oidc`), replicated to every member of a cluster. A local user's
password hash and TOTP secret are not in the model: they are entries of the
node's secret store (`<storage>/secrets`, 0600, sealed in the cluster's
replication), so a local user logs in on any member.

The first start of a node that is not part of a cluster and has no local
user creates the administrator `testudo` and prints its password once. A
`users.json` from older builds is moved into the model on the first start
with its hashes and second factors, and kept as `users.json.migrated`.

```bash
testudo user list
testudo user add alice --role operator      # prompts for a password
testudo user role alice approver
testudo user disable alice | enable alice
testudo user passwd alice
testudo user totp enroll alice               # prints the otpauth:// URI once
testudo user totp disable alice
testudo user del alice
```

The commands talk to the running daemon over `<storage>/control.sock`
(0600). The socket accepts root and the daemon's own user and acts as the
break-glass administrator `host-root`; every change it makes is a model
change with the usual commit-confirm, confirmed by the command. In the Web
UI, users and roles are managed under Settings; every user changes their
own password and second factor under Settings → My account.

## Roles and permissions

Roles are model objects that hold permissions of the form
`area:read|write`, optionally limited to one site or node:

```text
firewall:write                       everywhere
firewall:write@site:<site-uuid>      objects of that site and its nodes
routing:read@node:<node-uuid>        objects of that node
*:read                               every area
```

A scoped role sees and changes only the objects in its scope and the global
objects it may read; it cannot create a global object, confirm someone
else's change, or read the change history. An API token never carries more
than the user who creates it.

| Built-in role | Permissions |
| ---- | --- |
| `admin` | `*:write` |
| `operator` | `*:read`, write on firewall, routing, vpn, loadbalancer, interfaces, access, services |
| `approver` | `*:read`, `access:write`: decides on access requests |
| `read-only` | `*:read` |
| `vpn-user` | tunnels and published services, not the console |

Separation of duties: nobody approves their own access request.

## Break-glass

Two ways in stay open whatever the model says:

* a host account in the group `testudo-admin`, logging in through the host's
  PAM stack, is an administrator;
* root on the host reaches the daemon through the control socket.

## MFA

TOTP per RFC 6238 (SHA-1, 30 s, 6 digits, ±1 step skew), implemented in
`internal/auth/totp.go` - no external dependency. Enrollment returns the
`otpauth://` URI exactly once; the Web UI renders the QR client-side. A user
with MFA enrolled must supply the code on the login form.

## Web sessions

* A session is stored in the secret store, which a cluster replicates: a
  login on one member is good on all of them, and a logout or an expired
  session ends everywhere. What a session may do is worked out from the
  model on each member, so a role change takes effect at once.
* **CSRF**: state-changing requests must be same-origin (`Origin` /
  `Sec-Fetch-Site` check) and the session cookie is `SameSite=Lax`,
  `HttpOnly`, `Secure` under TLS.
* **TLS**: `testudo web --tls-cert FILE --tls-key FILE`, or `--tls-auto` for a
  self-signed ECDSA P-256 certificate generated into `<storage>/tls/` on
  first use (its SHA-256 fingerprint is logged at startup for pinning).
  Plain HTTP still works but is warned about at startup.
* Disabling or deleting a user ends their sessions.
* The console's live views come from `/api/live`, a server-sent event
  stream that pushes what changed; the stream ends with the session.

## Audit trail

`audit_log` rows carry two identities:

| Column | Meaning |
| ------ | ------- |
| `peer_uid` | the **process** that asked the privileged helper (SO_PEERCRED) |
| `actor` | the **human** behind it: Web user name, `tui:<os-user>`, `cli:<os-user>`, `system` |

The actor is threaded from the Web session (or the TUI's OS user) into every
engine mutation and, via `netops.Writer.WithActor`, into every kernel op the
helper executes for that request. Model changes carry the actor in the
configuration log; logins (granted and denied) and settings changes are
recorded by the engine with the actor as well.

Secrets rule: passwords, TOTP secrets, WireGuard private keys and session ids
never appear in audit args.
