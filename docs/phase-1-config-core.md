# Phase 1: data model and configuration core

Design note for Phase 1. The status at the end says what later phases still owe.

## Packages

| Package | Role |
| --- | --- |
| `internal/model` | Entities as tagged structs, `Meta`, scopes and overrides, typed references, validation, secret masking |
| `internal/model/schema` | Reflection-based generation of `openapi.json` and `ui.json`; both committed and embedded |
| `internal/model/gen` | The `go generate` entry point |
| `internal/confstore` | Versioned store: log, optimistic concurrency, reference index, cross-object checks, change sets, history, events |
| `internal/confapply` | Transactional apply: render, dry run, commit, apply, health check, confirm or roll back |
| `internal/confapi` | HTTP API with per-kind permissions, change sets, history, event stream |
| `internal/confimport` | One-way translation of the pre-model state into model objects |
| `internal/testutil/golden` | Golden-file helper for renderer tests |

The engine runs the store and the apply engine and the web server exposes
them, but no apply stage is registered yet: the existing firewall, WireGuard
and user stores keep driving the running system unchanged, and so does flow
analysis.

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

## HTTP API

`internal/confapi` serves everything below `/api/v1/`. The generated
OpenAPI document (`/api/v1/schema/openapi.json`) is the reference; a test
fails when it and the registered routes disagree.

| Situation | Answer |
| --- | --- |
| Update or delete without `If-Match` | 428 |
| Stale `If-Match` | 409 `conflict` with the field diff and the current object |
| Delete of a referenced object | 409 `in_use` with the list of users |
| Invalid object | 422 `invalid` with one entry per JSON field path |
| Cross-object problem | 422 `inconsistent` |
| A stage refuses in its dry run | 422 `stage_failed`; nothing was changed |
| A stage fails while applying | 502 `stage_failed` with `rolled_back` |
| Another change awaits confirmation | 423 `pending` |

A write without `?changeset=` is applied at once and answers with
`Testudo-Pending` and `Testudo-Confirm-By`; it stays until confirmed or
comes back by itself. A write with `?changeset=<id>` is recorded in that
change set and answered with 202.

**Permissions** are `<area>:read|write`, where the area is the first menu
segment of a kind (`firewall`, `routing`, `vpn`, `loadbalancer`,
`interfaces`, `access`, `system`, `cluster`). They are checked per object
kind on every request, for every op inside a change set, and before an
object is named on the event stream. Until Phase 6 the four existing roles
are mapped onto them: admin `*:write`; operator read everything and write
the network areas; approver read everything and write `access`; viewer read
everything.

**Live updates** are server-sent events at `/api/v1/events`: `change` per
committed record (kind, id, name, actor; no content) and `apply` per apply
outcome.

## Page

`/config` is built from `ui.json` at run time: menus, tables, forms and
pickers, with no per-entity code and no build step (plain JavaScript, same
as the existing pages). A reference picker has a "+ new" button that
creates the target through the target's own endpoint and selects it. A
conflict shows the differing fields with "discard mine" and "save mine over
it". A blocked delete lists its users with links. After an immediate apply
the page confirms on its own after five seconds, because reaching the
server again is the proof that management access survived; the operator
can roll back in that time.

## Operations

* The engine opens the store under `<storage>/config` and settles an
  unconfirmed change from a previous run at start. Apply outcomes are also
  written to the existing audit log (`config_applied`, `config_confirmed`,
  `config_rolled_back`, `config_rollback_failed`).
* One process writes the log (exclusive lock). `testudo config status` and
  `export` read next to a running daemon; `history`, `compact` and
  `import-legacy --apply` need it stopped.
* Records carry the schema version they were written with. A migration per
  version step is applied on replay; a store written by a newer build is
  refused. `schema/released.json` freezes the wire format of a released
  version: copy `fingerprints.json` into it when a release is cut.
* `testudo config compact --keep N` folds older records into
  `config.snapshot`; history and revert then reach the remaining N records.

## Import of the existing state

`testudo config import-legacy` translates `firewall.json`, the user list and
live WireGuard devices into model objects and prints what it would create
and what it cannot carry over. `--apply` writes it into an empty model.

It is not run automatically. The existing firewall, WireGuard and user
stores remain the source of truth for the running system until their phase
moves them onto the model; importing earlier would produce a copy that
drifts. Each subsystem's switch-over runs the import for its part.

Not carried over, by design or because the model has no equivalent yet:
password hashes and second factors (the model holds no credentials),
private keys, log-only rules, rules that match traffic *over* a rate, owner
tags on NAT rules, and `settings.json` (node-local thresholds and
integration credentials stay where they are).

## Status

Phase 1 is complete: model, generation, store, apply engine, HTTP API,
page, import, migrations, compaction, export and import.

Carried into later phases:

* No apply stage exists yet, so the model is stored, versioned and audited
  but does not change the running system. Phase 2 adds the nftables stage
  and with it the first golden files (the helper is in
  `internal/testutil/golden`).
* The node-local secret store that `key_ref` fields point to (Phase 4 for
  WireGuard keys, Phase 5 for certificates).
* Authentication is still the existing user store; roles from the model
  take over in Phase 6.
* The page was verified in a browser by hand-driven scripts, not by an
  automated browser test in the suite.
