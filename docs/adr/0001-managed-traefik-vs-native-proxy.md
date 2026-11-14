# ADR 0001: Managed Traefik instead of a native Go proxy

Status: proposed (Phase 0), to be confirmed before Phase 5.

## Context

The appliance needs L7 routing (host, path, headers, TLS termination, HTTP/2
and HTTP/3, middlewares), L4 routing by SNI with passthrough or termination,
UDP services, PROXY protocol, weighted balancing, sticky sessions, health
checks, ACME with three challenge types, and per-router metrics. Testudo has
none of it today. Its own TLS code only serves the Web UI.

Options:

1. **Managed Traefik.** Testudo renders Traefik's static and dynamic
   configuration from the model, supervises the daemon, and reads metrics and
   access logs back. Traefik is MIT-licensed and consumed as an unmodified
   binary.
2. **Native Go proxy** in the Testudo binary, modelled on Traefik.
3. **Traefik as a Go library.** Rejected up front: its packages are not a
   supported API, and importing them would pull several hundred modules into
   a binary that today has seventeen direct dependencies.

## Decision

Option 1. Traefik runs as its own unprivileged systemd unit. Testudo writes
dynamic configuration through the file provider (watched directory, atomic
rename, hot reload without restart) and the static configuration only when
entry points change.

Kernel-level L4 balancing (nftables `numgen` / `jhash` maps) is **not**
delegated: it is rendered by the existing firewall manager from the same
`LBService` model, because it is a ruleset concern and must take part in the
same atomic apply and rollback.

## Why

* HTTP/3, ACME, circuit breakers, mirroring and the PROXY protocol are each
  weeks of work and a long tail of interoperability defects. Rebuilding them
  buys nothing an operator can see.
* A proxy that terminates TLS for untrusted clients is the most exposed code
  on the box. A separate process with its own user, no capabilities beyond
  binding low ports and a systemd sandbox contains a defect far better than
  code inside the process that also programs the firewall.
* The model stays the source of truth either way; choosing Traefik only
  decides who interprets the rendered output. Golden-file tests on the
  rendered configuration keep that boundary reviewable.

## Consequences

* A second daemon to install, version-pin, supervise and upgrade. The pinned
  version and its license go in `THIRD_PARTY.md`; rolling cluster upgrades
  have to handle a Traefik version change like a model schema change.
* "Dry run" for Traefik is weaker than `nft -c`: there is no offline
  validator for dynamic configuration. The apply pipeline validates in the
  model, renders, and then checks the API of a running instance for rejected
  routers before confirming. This limitation is accepted and documented.
* Flow linkage (client → listener, proxy → backend) cannot come from inside
  the proxy. It is rebuilt from Traefik's structured access log, joined to
  the two captured flows by 5-tuple and time. This is the main cost of the
  decision and is scheduled in Phase 9.
* Certificates: Traefik owns ACME state; imported and internal-CA
  certificates are owned by the model and rendered as files (0600) for
  Traefik to read. Private keys never enter the replicated log in clear text
  (see ADR 0002).
* The existing rule "no shell-out" is narrowed: supervised sibling daemons
  are allowed; ad-hoc command execution in apply paths is not.

## Revisit when

A hard requirement appears that Traefik cannot meet (for example
least-connections for TCP services, where its support is partial), or the
access-log join proves too lossy for the flow requirements.
