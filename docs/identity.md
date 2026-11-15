# Identity, roles and audit

Every privileged action in Testudo is attributable to a **human**: the Web UI
session user, the OS user at the TUI, or the CLI caller. This is the layer the
firewall policy, WireGuard provisioning and (later) PAM grants hang off.

## Users and roles

Accounts live in `~/.testudo/users.json` (0600): bcrypt password hash, role,
optional TOTP secret, disabled flag. Users written by older builds load as
`admin` so the single bootstrap account keeps working after an upgrade.

| Role | May |
| ---- | --- |
| `viewer` | read everything, change their own password / MFA |
| `approver` | viewer + approve or deny access requests (PAM) |
| `operator` | approver's reads + mutate network state (rules, routes, NAT, WireGuard, captures), request access |
| `admin` | everything: users, settings, enable default-deny, import policies |

Separation of duties: an operator cannot approve; the last enabled admin
cannot be demoted, disabled or deleted.

```bash
testudo user list
testudo user add alice --role operator      # prompts for a password
testudo user role alice approver
testudo user disable alice | enable alice
testudo user passwd alice
testudo user totp enroll alice               # prints the otpauth:// URI once
testudo user totp disable alice
```

The same operations are available to admins in the Web UI (Settings → Users)
and to every user for their own account (Settings → My account).

## MFA

TOTP per RFC 6238 (SHA-1, 30 s, 6 digits, ±1 step skew), implemented in
`internal/auth/totp.go` - no external dependency. Enrollment returns the
`otpauth://` URI exactly once; the Web UI renders the QR client-side. A user
with MFA enrolled must supply the code on the login form.

## Web session security

* **Roles are enforced server-side** in `web.protect`: GET is open to every
  role; any other method needs `operator`, the admin-only paths
  (`/api/settings`, `/api/users/*`)
  need `admin`, the `/api/me/*` self-service paths need only a login.
* **CSRF**: state-changing requests must be same-origin (`Origin` / `Sec-Fetch-Site`
  check) and the session cookie is `SameSite=Lax`, `HttpOnly`, `Secure` under TLS.
* **TLS**: `testudo web --tls-cert FILE --tls-key FILE`, or `--tls-auto` for a
  self-signed ECDSA P-256 certificate generated into `~/.testudo/tls/` on
  first use (its SHA-256 fingerprint is logged at startup for pinning).
  Plain HTTP still works but is warned about at startup.
* Demoting, disabling or deleting a user ends their sessions immediately.

## Audit trail

`audit_log` rows carry two identities:

| Column | Meaning |
| ------ | ------- |
| `peer_uid` | the **process** that asked the privileged helper (SO_PEERCRED) |
| `actor` | the **human** behind it: Web user name, `tui:<os-user>`, `cli:<os-user>` |

The actor is threaded from the Web session (or the TUI's OS user) into every
engine mutation and, via `netops.Writer.WithActor`, into every kernel op the
helper executes for that request. Policy-level events (rule add, enforce,
confirm, import), logins (granted and denied), user and settings changes are
recorded by the engine with the actor as well.

Secrets rule: passwords, TOTP secrets, WireGuard private keys and session ids
never appear in audit args.
