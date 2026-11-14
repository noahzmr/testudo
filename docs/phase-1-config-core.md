# Phase 1: data model and configuration core

Design note. Status at the end tells what is built and what is still open.

## Packages

| Package | Role |
| --- | --- |
| `internal/model` | Entities as tagged structs, `Meta`, scopes and overrides, typed references, validation, secret masking |
| `internal/model/schema` | Reflection-based generation of `openapi.json` and `ui.json`; both committed and embedded |
| `internal/model/gen` | The `go generate` entry point |
| `internal/confstore` | Versioned store: log, optimistic concurrency, reference index, cross-object checks, change sets, history, events |
| `internal/confapply` | Transactional apply: render, dry run, commit, apply, health check, confirm or roll back |

None of this is wired into the running daemon yet. The existing firewall,
WireGuard and user stores keep working unchanged, and so does flow analysis.

## Model

Every entity embeds `Meta`: UUID, name (unique per kind), description,
version, created/updated at and by, labels, scope, overrides.

**Scope** is `global`, `site:<uuid>` or `node:<uuid>`. Each kind declares the
levels it allows: an `Interface` is node-only, a `User` is global-only, an
`Alias` may be any. A scope is itself a reference, so a site cannot be
deleted while objects are scoped to it.

**Overrides** replace top-level fields for one site or node. `Effective`
resolves an object for a node (base, then site override, then node override)
and reports for each overridden field where its value came from. Identity
and bookkeeping fields cannot be overridden.

**References** are `Ref[T]`, a UUID on the wire. They are found by
reflection, so the reference index needs no per-entity code.

**Tags.** `json` and `yaml` carry the same snake_case name. `validate` is
evaluated by go-playground/validator plus twelve custom rules. `ui` is
`label=…,widget=…,ref=…,group=…,order=…,help=…`. `secret:"true"` marks string
fields that are masked on the way out; a client that sends the mask back
keeps the stored value.

Private keys are not model fields at all. `WGTunnel.KeyRef`,
`WGPeer.PresharedRef` and `Certificate.KeyRef` name an entry in a node-local
secret store, which keeps key material out of the replicated log.

Two tests guard the contract: the tag lint (every field has all tags, wire
names agree, references point at registered kinds) and the staleness check
(committed generated files equal a fresh generation, byte for byte).

## Store

The store is a deterministic state machine over a log of records. Today the
log is a local JSON-lines file (`config.log`, 0600, fsynced per record,
replayed on open, a torn last line is dropped). In Phase 7 the same
`prepare` step runs inside the Raft state machine; that is why time, actor
and new IDs enter through arguments and never through the clock.

* **Version = log index.** `Meta.Version` is the index of the record that
  last wrote the object.
* **Optimistic concurrency.** Update and delete carry the version they are
  based on. A stale write returns a `ConflictError` with the current
  version, who changed it, and a field-level diff of the caller's object
  against the current one (secrets masked).
* **Integrity on every commit.** Object validation, unique names, every
  reference resolves, deletion of a referenced object is refused with the
  list of its users, then the cross-object checks.
* **Change sets.** A change set is a named list of ops owned by a user,
  stored in the same log. Several can be combined, previewed as one diff and
  committed as one record. Ops keep their base versions, so a draft that has
  gone stale conflicts at apply time, and two drafts touching the same
  object cannot be merged silently.
* **History.** Each record holds before and after for every object. `Revert`
  appends the inverse as a new record and refuses if the objects changed
  since.
* **Events.** Subscribers get one event per record (kind, id, name, actor,
  no content). A slow subscriber is told to resync instead of blocking
  writers.

## Apply

A `Stage` has `Render`, `Check`, `Apply` and `Healthy`. Phase 2 adds the
nftables stage, Phase 3 FRR, Phase 4 WireGuard, Phase 5 the proxy.

1. Render the current model (kept for rollback) and the candidate.
2. Dry-run every stage. Nothing has changed yet.
3. Commit to the store.
4. Write the pending marker to disk.
5. Apply the stages in order, then run every health check. Any failure
   restores all stages in reverse order and reverts the record.
6. Wait for `Confirm`. Without it the change is rolled back after the window
   (60 s by default), or at the next start if the process died meanwhile.

While a change is pending no other change is accepted. Rollback keeps going
past a stage that fails to restore, so one broken daemon cannot hold the
packet filter on an unconfirmed ruleset.

## Decisions taken with the answers of 2026-11-14

* The new configuration UI may use React; the generated `ui.json` contract
  is the same either way (ADR 0003).
* cgo, supervised daemons and command execution in apply stages are allowed
  where the target needs them (FRR, the proxy, `nft -c`, host PAM).
* Existing on-disk formats are imported once into the new store; there is no
  two-way sync.
* OIDC is an external provider; Keycloak is used for tests.
* Rollback window: 60 seconds.

## Status

Built and tested: model, generation, store, apply engine.

Still open in Phase 1:

* HTTP API over the store and engine: CRUD with `ETag` / `If-Match`, 409
  with the diff, change-set endpoints, an SSE stream, object-level RBAC.
* Wiring the engine into the daemon and a one-way import of
  `firewall.json`, `users.json`, `settings.json` and the WireGuard metadata.
* The schema-driven UI renderer, including inline creation of referenced
  objects.
* Schema fingerprints and migrations; log compaction and snapshots;
  configuration export and import.
* A golden-file helper for stage renderers (the first real renderer arrives
  with Phase 2).
* Model entities for the existing privileged-access objects (resources,
  policies, grants).
