# Phase 6: PAM, OIDC, roles and audit

Who someone is can be proven in four ways. What they may do is decided in
one place.

Since Phase 12 local users are model objects too (no more `users.json`),
sessions are cluster-wide and permissions can be limited to a site or node
([phase-12-consolidation.md](phase-12-consolidation.md),
[identity.md](identity.md)).

```text
built-in account ─┐
host account (PAM) ┼─► identity.Resolve ─► principal ─► API, console,
identity provider ─┤     users, groups,     (permissions)  published services
API token ─────────┘     roles of the model
```

## Ways to log in

| Source | Proven by | Notes |
| --- | --- | --- |
| `local` | the built-in user store (`users.json`, bcrypt, optional TOTP) | the first administrator; unchanged |
| `pam` | the host's PAM stack, service `testudo` | local accounts, LDAP/SSSD, RADIUS, one-time codes: whatever the stack does |
| `oidc` | the identity provider | authorization code flow with PKCE |
| `token` | an API token (`Authorization: Bearer tdo_…`) | for programs |

The login page takes a name and a password. A name the built-in store
knows is checked there; every other name goes to PAM. "Sign in with
&lt;provider&gt;" appears when a provider is enabled.

### PAM

`packaging/pam.d/testudo` is the service file to install as
`/etc/pam.d/testudo`. As shipped: local accounts with `pam_unix` and
lock-out with `pam_faillock`. All three phases run (`internal/pamauth`):

* **auth**: the first hidden prompt of the stack gets the password, a
  second one gets the "one-time code" field. When the stack asks for a code
  and none was entered, the page asks for it.
* **account**: an expired or locked account is refused with the right
  password, and the page says why.
* **session**: opened and closed at once, so modules that record or limit
  logins see this one.

The check runs in the privileged runner, where reading the shadow database
is allowed. The request is a query: the helper does not write queries to
the audit log, which matters because this one carries a password.

The binding needs cgo and is compiled in with `-tags pam`. It declares the
few functions it uses itself, so building needs `libpam.so.0` and not the
development package. A binary built without the tag has no PAM logins; the
built-in store and OIDC work the same.

### OIDC

One `oidc_provider` object (Settings → Identity provider): issuer, client
id, redirect URL, optional extra scopes, the names of the user-name and
groups claims, and the accepted signature algorithms. The client secret is
stored on the node (`POST /api/v1/oidc/client-secret`); the object holds
the name of the entry.

`internal/oidcauth`:

* discovery from the issuer; the issuer in the document has to match;
* authorization code flow with PKCE (S256), state and nonce per attempt,
  kept on the server and good once;
* ID token validation: signature with an algorithm from the allow-list
  (default RS256 and ES256; `none` and HMAC can not be configured), issuer,
  audience (and `azp` with several audiences), expiry, nonce;
* keys are cached and fetched again when a token names an unknown key, so
  rotation is followed;
* refresh: when the tokens run out the session is extended with the refresh
  token, and the groups are read again; when the provider refuses, the
  session ends;
* logout: the console's logout leads to the provider's end-session
  endpoint with `id_token_hint`; back-channel logout tokens
  (`/auth/oidc/backchannel-logout`) end the sessions they name, once.

## From login to permissions

`internal/identity`. A user object is found by subject (OIDC) or by name,
among users of the same kind of source. Its roles and groups count, and so
does every group whose **claim value** is among the names the source
reported: values of the provider's groups claim, or the host groups of a
PAM user. Roles are sets of permissions `<area>:read|write`.

* A login nothing gives a role to is **refused**. Being known to the
  provider is not enough.
* A disabled user object stays out, whatever groups would let them in.
* Built-in roles, created in the model on first start: `admin`,
  `operator`, `read-only`, `vpn-user`. A `vpn-user` may use tunnels and
  published services and not the console.
* A session is worked out again whenever the model changes. Taking a role
  away or disabling a user ends access at the next request, not at the next
  login.

Enforcement is in the API: `/api/v1` checks the permission for the area of
each object kind, and the older endpoints check the rank the permissions
map to. The console only hides what the API would refuse.

### Break-glass

Two ways in that do not depend on the identity provider or on the model's
users and roles:

* the built-in account (`testudo`, password reset with `testudo user
  passwd` on the host);
* any host account in the group **`testudo-admin`**, through PAM. It is an
  administrator with an empty or broken model, and the audit row says
  `break_glass`.

With the provider stopped, the login page says so and both keep working.

## API tokens

`POST /api/v1/tokens` (Settings → API tokens → New) creates a token for the
caller with some of the caller's own permissions, never more, and an
optional expiry. The token is shown once; the model keeps its SHA-256.
Tokens cannot create tokens. Disabling one is an ordinary change.

## Published services

A load-balancer router with `require_groups` has the proxy ask this program
about each request. A visitor without access is sent to the console
(`--public-url`, or the address the provider redirects to), logs in the
usual way and comes back with a one-time ticket for that host name. The
cookie it sets is a reference to the console session: logging out, leaving
the group or being disabled closes the service at the next request. The
application receives the user's name in `X-Forwarded-User`. Tickets are
only made for hosts a router with the requirement serves.

## Audit

`GET /api/v1/audit` (Changes → Audit log): logins and logouts with source
and address, refused logins with the reason, throttled attempts, sessions
ended because access was withdrawn, configuration applies with the objects
they changed, confirmations, rollbacks, refusals at published services, and
every privileged operation on the kernel. The values before and after a
configuration change are in the history record the row names, with secrets
masked. Passwords, tokens and client secrets are in none of it.

More than ten failed logins from one address within five minutes are
refused before they reach the stack.

## Tests

* `scripts/oidc-test/run.sh`: the real binary against a real provider
  (Keycloak 26). Login with PKCE, group claim to role, permissions enforced
  by the API, a token capped by its creator, users without a role refused,
  a made-up state refused, a withdrawn role ending the session, logout at
  the provider, logout **by** the provider (back-channel), and the built-in
  administrator working while the provider is stopped.
* `scripts/pam-test/run.sh`: the binary built with `-tags pam`, as root in
  a Debian 12 container, with the shipped service file and real accounts:
  break-glass group, a host group mapped to a role and unmapped again, an
  expired account, lock-out after three failures and its reset, throttling,
  and a search of every file the daemon wrote for the passwords used.
* `TestPublishedServiceNeedsLogin` (real kernel suite, real proxy,
  privilege separation): the detour through the console, a user outside
  the group, leaving the group, logging out.
* Unit tests: the resolver, the relying party against a provider that
  misbehaves (wrong nonce, audience, issuer, expired, HMAC and unlisted
  algorithms, rotated and withdrawn keys, replayed and malformed logout
  tokens), the PAM conversation through the real library with a private
  service file (password, account phase, session phase, second prompt),
  the token and secret endpoints.

The realm in `scripts/oidc-test/realm.json` and the passwords in the PAM
test exist for those tests only.

## Status

Phase 6 is complete as specified, with these parts **not verified**:

* **PAM with an unprivileged engine.** In the container the daemon runs as
  root throughout; the request does go engine → helper → runner, but an
  engine that has dropped its privileges was not part of the test.
* **PAM with LDAP/SSSD, RADIUS or a real one-time-code module.** The
  conversation for a second prompt is tested with a test module; no
  directory or OTP module was installed.
* **Other providers.** Only Keycloak was run. Entra ID and Authentik
  should work through the same standard endpoints and were not tried.
* **Refresh against the real provider.** Covered against the fake one
  only; the Keycloak run does not wait for tokens to expire.
* **The console screens for PAM and OIDC logins in a browser.** The token,
  provider and audit screens were run in a browser; the logins were driven
  over HTTP.

Known limits:

* Console sessions, tickets and service cookies live in memory: a restart
  logs everyone out. They become cluster state with Phase 7.
* One login at a time goes through the runner, which also loads rulesets;
  a slow directory behind PAM delays an apply by as long as it takes.
* The built-in store and its TOTP stay as they were. Moving those accounts
  to host accounts is possible now and not forced.
* Operators may change the firewall policy, including default deny, as
  they could before. Splitting that off needs a finer permission than the
  area.
* The default build has no PAM (`-tags pam` adds it); packages for Debian
  should be built with the tag.
