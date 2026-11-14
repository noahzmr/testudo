# ADR 0003: Generating OpenAPI, UI forms and validation from the model

Status: proposed (Phase 0). The UI part needs an explicit answer before Phase 1.

## Context

Every entity will be a Go struct in `internal/model` carrying `json`, `yaml`,
`validate`, `ui` and `secret` tags. Forms, the OpenAPI schema and validation
must come from those structs and never be written twice; a test must fail
when a field lacks tags or generated output is stale.

Today structs carry `json` tags only, the API has no specification, and the
UI is hand-written vanilla JavaScript with no build step.

## Decision

1. **One generator, driven by reflection.** `internal/model/gen` is a small
   Go program run by `go generate ./internal/model`. It imports the model
   package, walks a registry of entity types with `reflect`, and writes:
   * `internal/web/assets/schema/openapi.json` (OpenAPI 3.1), and
   * `internal/web/assets/schema/ui.json` (per entity: fields, labels, menus,
     widgets, reference targets, groups, order, help, secret flags).

   Reflection is preferred over parsing source because it sees exactly what
   the encoder and the validator see, including embedded `Meta` and generic
   `Ref[T]` fields.

2. **Validation is not generated code.** `go-playground/validator` (MIT)
   evaluates the `validate` tags at runtime, with custom validators
   (`portrange`, `fqdn_or_wildcard`, `wgkey`, …) registered in one place. The
   generator translates the same tags into JSON Schema constraints so the UI
   can pre-validate, and a test asserts that every tag in use is translatable.
   The server stays authoritative.

3. **Two build-failing tests.**
   * *Tag lint*: every exported field of every registered entity has `json`,
     `yaml`, `validate` (possibly `-`) and `ui` tags; `json` and `yaml` names
     are equal and snake_case; every `Ref[T]` names a registered entity;
     every `secret` field is excluded from logs by the masking encoder.
   * *Staleness*: the generator runs in memory and its output must equal the
     committed files byte for byte.

4. **Migrations are checked by generation and written by hand.** The
   generator emits a fingerprint of each entity's schema. A changed
   fingerprint without a bumped schema version and a registered migration
   function fails a test. Purely additive changes (a new optional field with
   a default) get their migration generated; anything else cannot be derived
   safely and is written by a person.

5. **UI: a schema-driven renderer.** One generic form and table renderer
   reads `ui.json` and drives every menu, including inline creation of a
   referenced object through the same endpoint. No per-entity form code.

## The open choice

The renderer can be built two ways:

* **A. Stay build-step-free** (proposed). A vanilla JavaScript renderer,
  embedded like today. Keeps the single static binary, no Node toolchain, no
  JavaScript dependency tree to audit on a firewall.
* **B. React** (or similar) with a bundler. Faster to build rich widgets
  (diff views, drag-to-reorder, topology), at the price of a second
  toolchain, a lock file to maintain and a build artefact to embed.

The generated `ui.json` contract is the same for both, so the choice can be
revisited without touching the model.

## Consequences

* Existing structs (`netops.FilterRule`, `firewall.Policy`, `auth.User`, …)
  are not retagged in place. `internal/model` is introduced beside them and
  each subsystem is moved over in its own phase, with a one-way import of the
  old on-disk format.
* `ui` tag grammar becomes an internal contract and needs its own parser
  tests.
* Generated files are committed, so model changes are visible in review.
