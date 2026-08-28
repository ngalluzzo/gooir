# 0046 — Application generation is one frontend, reusable facts, and external generators

Status: proposed; acceptance requires the Fleetd proof below

## Context

GOOIR can install exact external tools, plan ordinary capability graphs, admit
their outputs, and publish an admitted `ContentSet`. Those primitives do not by
themselves give an application author a usable product path. The current
experiments still require callers to assemble capability coordinates, policy
and observation JSON, process limits, package order, surface bindings, and
separate provider entry points.

The experiments also exposed the wrong abstractions. A storage-shaped data
model was asked to describe application DTOs. Operations referenced that model
instead of a general schema. HTTP lowering invented CRUD routes from tables.
Target-only Axum and Rust source intermediates became package contracts without
independent consumers. Handwritten attesters reproduced generators instead of
validating their output with target-native authorities.

Adding a kernel `Backend`, parser graph, lowering kind, lens, or universal
workspace IR would make these mistakes permanent. The missing product is an
external ecosystem contract and a thin host composition over the existing
kernel.

## Decision

Greenfield application generation has one blessed external frontend based on
TypeSpec. One frontend invocation parses and type-checks the complete source
program with the official TypeSpec compiler, then emits several named portable
facts. External generators consume those admitted facts independently.

```text
TypeSpec source ContentSet
  -> official TypeSpec parse and type checking, once
  -> canonical JSON Schema catalog
     Operations v2
     Persistence overlay
     HTTP/CLI/MCP bridge bindings
  -> reusable bridge providers
  -> native HTTP / CLI / MCP
  -> one complete backend artifact per managed root
  -> target-native validation
  -> contextual admission
  -> ContentSets
  -> managed publication
```

TypeSpec is not a GOOIR kernel dialect. It is an external source ecosystem and
provider implementation. The kernel remains unaware of TypeSpec syntax,
compiler objects, decorators, targets, and file layouts.

The normal consumer inputs are:

- one `main.tsp`, which may import other TypeSpec files; and
- one `gooir.toml` containing only a selected locked preset, requested outputs,
  destinations, and explicit migration-safety choices.

The normal consumer operation is one workspace build. Capability identities,
output ports, measured implementations, package ordering, process bounds, and
managed-output identities come from the selected lock, not from repeated
command-line or handwritten JSON input. Provider execution permission and
provider authority do **not** come from that lock; they are separate explicit
host-owned grants described below. The existing exact `compile` and `build`
surfaces remain diagnostic and integration tools.

The concrete first-use path is:

1. select one local content-addressed Rust/Axum/SQLite preset during
   `workspace init` and explicitly approve its exact execution and admission
   grants;
2. write `main.tsp` and output destinations in `gooir.toml`;
3. run one output-specific genesis-authorized build for a new migration
   lineage; and
4. use ordinary `workspace build` thereafter.

That build produces three disjoint managed roots: a complete generated Rust
crate, an OpenAPI document root, and a SQLite migration-history root. The
stable handwritten seam is one Cargo dependency on the generated crate plus
one implementation of its operation trait. Regeneration requires no provider
CLI, binding JSON, generated-file edits, or Cargo/module stitching.

## Stage ownership

The following words describe ecosystem work, not distinct kernel edge kinds:

- **Parse** turns source bytes into the authoritative tool's native syntax and
  semantic objects. The TypeSpec AST and `Program` remain private to the
  frontend.
- **Lift** exports independently useful meaning from a native tool into a
  versioned portable fact.
- **Lower** combines portable facts with an explicit target profile and, when
  required, prior state to produce target meaning.
- **Emit** renders target meaning as a `ContentSet`. Lowering and emission stay
  in one provider when no independently reused target IR exists.
- **Validate** uses the target's mature authority: the TypeSpec compiler, JSON
  Schema validator, Rust compiler, database engine and catalog, Clap, or the
  official MCP SDK. It does not reconstruct expected output with a shadow
  generator.
- **Admit** applies the existing exact-provider or independent-conformance
  authority membrane.
- **Publish** writes admitted bytes through the artifact SDK. It knows no
  target semantics.

A lens is not a stage or kernel abstraction. Round-trip laws are qualification
tests where a meaningful inverse exists. Database migration replay followed by
catalog introspection is one such test. Source generation generally is not
invertible and must not be presented as a lens.

An intermediate becomes a versioned package fact only when it crosses an
ownership or process boundary and has concrete independent reuse. Internal
compiler ASTs, graphs, and passes remain implementation details. Two known
independent consumers are sufficient evidence; anticipated reuse is not.

## Portable facts and their joins

The application ecosystem standardizes only these semantic waists:

1. **Canonical JSON Schema 2020-12 catalog** — one JSON document containing
   every exported logical value shape and every surface-effective wire shape.
   This reuses the external standard instead of inventing a general GOOIR
   shape model.
2. **Operations v2** — callable identity, schema-referenced logical inputs and
   outcomes, faults, effects, replay semantics, and authority requirements. It
   does not embed or depend on the storage-shaped DataModel v1.
3. **Persistence overlay** — stable entity and field identities, physical
   names, keys, uniqueness, references, generated values, and migration-only
   meaning, each referencing a logical schema location.
4. **HTTP, CLI, and MCP bridge bindings** — complete exposed-or-omitted
   decisions for one exact Operations fact. They map logical operation values
   to mechanism coordinates and wire values. They are generated by the
   frontend for greenfield TypeSpec, not hand-authored by the normal consumer.
5. **Native HTTP, CLI, and MCP** — independently authorable mechanism meaning.
   These facts do not depend on Operations and therefore remain usable for
   brownfield or non-Operations sources.
6. **ContentSet** — portable final bytes.

Backend-specific target profiles are ordinary typed inputs owned and versioned
by each external backend. They are not one ecosystem-wide profile vocabulary.

Every schema reference is
`(catalog FactId, absolute resource URI without fragment, optional RFC 6901
JSON Pointer)`. The fact identity must equal the exact admitted catalog input.
The resource URI comes from an explicit application identity, not a file path
or `$defs` key, and must equal exactly one embedded `$id`. A resolver registry
is constructed only from the admitted document, and the optional pointer
resolves within that resource. Duplicate `$id`s, unresolved pointers, any
`$ref` or `$dynamicRef` whose resource is absent, and every attempted network
fetch are invalid. The root-relative `schema.json` is never a cross-fact
resource identity.

The first catalog value-kind version fixes the official JSON Schema emitter to
`file-type=json`, `bundleId=schema.json`, `emitAllModels=false` with application
roots explicitly marked `@jsonSchema`, `emitAllRefs=false`,
`int64-strategy=number`, `seal-object-schemas=true`, and
`polymorphic-models-strategy=oneOf`. Open or unsupported polymorphism is a typed
inability. These choices are semantics of the catalog version, not a mutable
profile envelope or downstream flag. The relative `bundleId` is only the
official emitter's root filename and `$id`; it is not the cross-fact identity
of an exported shape.

The first vNext contract is not releasable until its Fleetd fixtures prove
every reference resolves with a Draft 2020-12 validator and include at least
one logical value whose HTTP-visible or encoded wire shape differs. The public
JSON Schema emitter does not by itself establish those effective HTTP shapes.
The frontend must derive them from the pinned official `HttpOperation`,
metadata/visibility, and encoding APIs, place them in the same catalog, and
return a typed inability for encodings it cannot preserve.

Operations schema references describe the values accepted and returned by the
handwritten handler. Native surfaces describe protocol-effective wire values.
A bridge binding names the exact Operations fact and surface identity and
explicitly maps between the two; equality is never inferred from a shared
model name. For HTTP, the TypeSpec frontend uses the official HTTP metadata and
visibility APIs to determine path, query, header, body, status, content-type,
and effective payload shapes. It must emit referenced effective shapes into
the same catalog or return a typed inability. Axum, OpenAPI, and other HTTP
consumers do not rerun TypeSpec visibility rules.

For the supported subset, vNext HTTP bindings and native facts preserve the
URI template; encoded parameter name and path/query/header location;
requiredness; style, explode, and `allowReserved`; body and response content
types; response status, range, or default; response headers; encoding;
authentication; and streaming. Any represented `HttpOperation` variant whose
meaning cannot be preserved in those coordinates is a typed inability.

The frontend uses the official TypeSpec compiler and `@typespec/http`. A small
`@gooi/app` TypeSpec library adds only semantics TypeSpec does not already own:
persistence, effect/replay and authority annotations, CLI exposure, and MCP
exposure. It emits the schema catalog, Operations, persistence, and bridge
bindings in one invocation. Ordinary bridge providers then produce native
HTTP, CLI, and MCP facts. Directly authored native facts remain valid inputs to
the same downstream providers.

The official TypeSpec JSON Schema and OpenAPI emitters provide source-native
reference artifacts for qualification; their OpenAPI bytes never satisfy the
portable OpenAPI target. The normal OpenAPI artifact is produced from admitted
native HTTP plus its exact schema catalog by an external OpenAPI backend. This
keeps a second authoring frontend from having to reproduce a TypeSpec-only
OpenAPI path.

The frontend returns a typed inability with compiler diagnostics when required
meaning is incomplete. It never converts compiler errors or unknown required
decorators into partial trusted application semantics.

The external authorities selected here are their upstream projects, not local
reimplementations:

- [TypeSpec compiler and emitter model](https://typespec.io/docs/extending-typespec/emitters-basics/);
- [TypeSpec HTTP library](https://typespec.io/docs/libraries/http/reference/);
- [TypeSpec JSON Schema emitter](https://typespec.io/docs/emitters/json-schema/reference/emitter/);
- [TypeSpec OpenAPI emitter](https://typespec.io/docs/emitters/openapi3/reference/emitter/);
- [JSON Schema 2020-12](https://json-schema.org/draft/2020-12); and
- [Quicktype](https://github.com/glideapps/quicktype).

## External generator topology

There is no kernel backend type. Every generator is an ordinary external
capability provider and may expose several implementations through
`ProviderApp`. The ownership rule is exact: **one provider invocation owns one
complete managed root**. The workspace never unions source fragments or lets
several providers overwrite the same directory.

Every requested destination resolves through the lock to exactly one final
capability output and `ManagedOutputId`. Destinations are pairwise distinct
and may not contain one another. `ContentSet` rejects duplicate, reserved, and
portable-colliding paths. The Rust backend additionally constructs one global
module and symbol table and refuses duplicate module paths, Rust items, import
aliases, Cargo features, incompatible dependency requirements, HTTP routes,
CLI command paths, or MCP tool names. It never silently renames, overwrites, or
patches consumer-owned files. The pinned Rust compiler checks the complete
crate.

The first Rust service backend consumes the schema catalog, Operations, exact
bridge bindings, native HTTP/CLI/MCP facts, and one backend-owned Rust profile.
It emits one complete, independently compiling generated crate as one
`ContentSet`: `Cargo.toml`, DTO modules, the operation trait, Axum routes, Clap
commands, MCP tools, imports, and module declarations. It owns all generated
names and paths, checks symbol collisions before emission, and exposes one
documented crate API to the handwritten application. Quicktype is an internal
library of this backend for DTO rendering; its `TypeGraph` and partial files do
not cross the provider boundary. This deliberately replaces separate DTO,
port, Axum, Clap, and MCP `ContentSet`s whose composition would require manual
Cargo and module wiring.

That cohesive provider belongs in an external Rust application-integration
repository. It does not make `gooir-http` depend on Operations: `gooir-http`
continues to own only independently authored native HTTP, Axum handler
bindings/profile, and their target lowering. The integration backend may reuse
those libraries internally. No new handler-manifest fact or public assembly IR
is introduced for the first proof.

Other complete artifact backends may coexist without sharing a managed root:

- a standalone TypeScript types or client backend may consume the catalog and
  emit a complete package;
- an OpenAPI backend consumes native HTTP plus the exact catalog and emits one
  complete document root; and
- SQLite and PostgreSQL migration backends consume the catalog, persistence,
  a backend profile, explicit genesis or prior managed state, and emit one
  complete migration-history root.

If a future product truly needs independently generated fragments in one
root, it must first add and justify an ordinary conflict-checking assembly
capability with a complete layout/manifest contract. Publication itself will
not become a merge operation. The Fleetd proof adds no such assembly layer.

Generated HTTP, CLI, and MCP adapters call one handwritten implementation of
the generated operation trait. Interface generation cannot and does not invent
business behavior.

A cohesive backend may support many target profiles without one executable or
capability per emitted module. Quicktype is a backend implementation detail,
not a dialect and not one provider per language. Target choices that affect
meaning are typed backend-owned profile inputs, not capability-name
proliferation or hidden flags.

## Authority and validation

A locked host may explicitly authorize a complete measured deterministic
frontend or generator offer under Decision 0045. Installation alone never
grants that authority. Untrusted, agent-produced, or independently governed
tools retain the independent-conformance path.

The first workspace product separates three documents and three concerns:

- an immutable, content-addressed **preset bundle**, released by an external
  stack repository and selected by explicit local path and digest, declares
  desired packages, profiles, routes, outputs, and resource bounds;
- machine-generated `gooir.lock` resolves that preset to exact package,
  resource, implementation, offer, suite, profile, and output coordinates; it
  is availability and deterministic selection, never trust; and
- a host-local **execution and admission grant**, scoped to the workspace,
  records which exact measured resources may execute, which complete
  `CapabilityOffer` values may use provider authority, and which complete
  `ConformanceAuthority` values the local policy accepts for independent
  assessment.

Preset production is data-driven too. An ecosystem release uses a generic
packing command over offer-free package manifests, explicit executable paths,
backend profiles, output roles, and bounds to produce an immutable local
preset bundle containing the existing exact toolchain image plus a versioned
workspace-preset manifest. Backend authors do not write product-specific
toolchain assembly programs. The first distribution mechanism is deliberately
only a local directory or archive plus its expected digest.

`workspace init` resolves an explicitly selected preset bundle, writes the
lock, displays the exact resources and offers, and requires an explicit
one-time approval before they can execute or receive provider authority. The
approval may grant execution while retaining independent conformance for
admission. It is stored in the host control plane, not copied from the preset
or semantic lock. CI supplies the equivalent host-owned grant out of band.

`workspace build` neither creates nor changes a lock. `workspace update`
accepts another explicit preset bundle and produces an exact inventory,
profile, and route diff before replacing the lock. Exact unchanged grant
entries remain valid; changed resources, offers, or conformance authorities
have no matching grant. Update never edits authority automatically. The next
build refuses before affected execution or admission until the host accepts
the new exact entries. The first implementation supports local preset bundles;
registry discovery, ranking, network update, signatures, and publisher trust
are separate distribution concerns and are not implied by this decision.

Invoking the local workspace host separately authorizes bounded observation of
the source roots declared in `gooir.toml`. The host records the exact observer
and evidence for the bytes it observed. That establishes source-byte
provenance for the run; it grants no semantic authority to a frontend or
generator. For that run, the workspace constructs the complete
`ObservationAuthority` for its exact observer implementation and measured
artifact and adds it to the policy's accepted observation authorities. Neither
the preset nor the lock can supply that acceptance.

Independent validation must not become a second generator. Examples include:

- compile emitted Rust with the pinned Rust toolchain;
- parse and inspect generated Clap or MCP registrations with their official
  libraries;
- validate JSON Schema and OpenAPI with their authoritative schemas/tools; and
- apply SQL to the real target database, introspect its catalog, and compare
  supported persistence semantics.

Passing target syntax checks is not proof of semantic correspondence. A
validator claims only the checks it actually performed. Fixture or corpus
qualification must be labeled as such and cannot be generalized to arbitrary
consumer specifications.

## Migration state

Migration generation is a transition, not a pure projection of the desired
snapshot. Every managed migration directory contains:

- immutable migration history;
- a backend-owned canonical baseline with the previous admitted persistence
  identity, stable object identities, target/profile and generator identities,
  and migration inventory; and
- the artifact SDK ownership marker.

Before a subsequent build, the publisher verifies ownership and drift and
returns the existing managed bytes without its own marker. The workspace
observes and admits that snapshot as a new input. The migration provider then:

1. verifies the embedded baseline and unchanged history;
2. compares previous and desired persistence facts;
3. requires explicit rename, backfill, and destructive-change policy where
   intent cannot be derived safely;
4. appends a deterministic migration and next baseline;
5. replays the complete history in an actual temporary target database;
6. introspects the resulting catalog and compares supported semantics; and
7. emits the entire replacement as one `ContentSet`.

A missing destination proves only that no local baseline is available; it does
not prove genesis. Normal builds refuse it with `NeedGenesisOrPriorBaseline`.
The first migration build requires either a one-invocation, output-specific
genesis authorization or an externally supplied admitted prior history. A
genesis authorization is a command action, not a persistent permissive setting
in `gooir.toml`, so deleting a managed migration directory cannot silently
reset the lineage on the next ordinary build. Existing unmanaged, wrong-owner,
symlinked, or drifted destinations are refused. Importing existing handwritten
migrations is an explicit one-time validated adoption operation. Target
features outside the portable persistence vocabulary remain explicit target
extensions or a separate manual migration stream; they are never guessed.

## Workspace host

The workspace layer is optional host SDK, not semantic kernel. It performs:

1. bounded, symlink-refusing source-tree observation;
2. exact preset, lock, toolchain, and separate host-grant loading;
3. in-memory construction of source authority and admission policy from those
   host grants, never from installed inventory alone;
4. one frontend derivation and named-output recovery;
5. bridge derivations and complete-root backend derivations from retained
   admitted references;
6. read-only baseline and publication preflight for every disjoint destination;
   and
7. deterministic managed publication.

`Workspace::prepare` completes every semantic derivation, validation,
admission, baseline read, and publication check without modifying a
destination. `PreparedWorkspace::publish` commits destinations in canonical
order.

There is no honest atomic transaction across unrelated directories. A failure
after one commit returns the exact committed prefix, and rerunning is
idempotent. The workspace must not claim cross-directory rollback or invent a
distributed filesystem transaction.

The machine-generated lock pins package and resource identities, exact offers,
suites, backend profiles, output coordinates, and process limits. It does not
pin or grant authority. Friendly preset names are display labels for the exact
selected preset digest and lock contents. There is no registry discovery,
provider ranking, implicit trust, overlapping output ownership, or serialized
universal build graph.

## Compatibility and retirement

The following remain valid low-level or compatibility surfaces:

- the one-edge `Fact --Capability--> Fact` kernel;
- exact package/toolchain loading, planning, authority, derivation, and
  artifact publication;
- `ContentSet` as source and final-byte carrier;
- the exact `compile` and `build` commands for diagnostics and integration;
- independently useful current contracts until their vNext replacements ship;
  and
- handwritten business behavior behind generated ports.

The following are not foundations for new consumer work:

- `.entities` as greenfield application syntax;
- DataModel v1 as a general type model;
- Operations v1 and its embedded DataModel references;
- hand-authored operation or bridge-binding JSON as the normal greenfield
  TypeSpec path;
- table-to-CRUD OpenAPI projection;
- package-visible Axum IR or `RustSourceTree` without a second real consumer;
- multi-hop HTTP-to-Axum-to-Rust graphs whose sole product is source bytes;
- per-capability executable mains;
- handwritten shadow generators presented as independent attesters; and
- Fleetd-specific package assembly, policy construction, Git-blob observation,
  and four-command generation machinery.

Those paths remain available where they are independently useful, including
direct native HTTP and brownfield bridge authoring. The Fleetd proof may retire
only the exact Fleetd files and provider paths it replaces. Contract-wide
deprecation requires separate consumer evidence and a separate decision. No
replacement is described as general or production-qualified before its stated
proof exists.

## Implementation order

1. Extract bounded source-tree observation and add read-only managed-output
   snapshotting.
2. Define the minimal vNext schema, Operations, persistence, bridge-binding,
   and native-surface contracts from one real Fleetd slice, including the
   exact logical-to-wire schema joins above.
3. Build the external TypeSpec frontend using official compiler and emitters.
4. Build or update the reusable Operations-to-native bridge providers and the
   native-HTTP-to-OpenAPI backend.
5. Add local preset resolution, exact lock generation/diff, separate host
   execution/admission grants, and prepare/publish host composition.
6. Build one cohesive Rust service backend and the first SQLite migration
   backend. Quicktype, Axum, Clap, and MCP generation are internal components
   of the single Rust artifact owner, not competing directory writers.
7. Prove one Fleetd TypeSpec root produces a complete generated Rust crate, SQL
   migrations, and OpenAPI. Fleetd must compile and run against that crate;
   existing behavior, HTTP/OpenAPI, CLI, MCP, and migration tests must pass;
   the proved slice must have no parallel handwritten adapter, generated-file
   edits, or module/manifest stitching. Only one handwritten implementation of
   the generated operation trait remains.
8. Remove or mark unsupported only the exact Fleetd proof machinery replaced
   by that slice. Expand retirement only as further real consumers migrate.

## Acceptance gate

This decision becomes accepted only when one pinned Fleetd `list_agents`
vertical slice proves all of the following:

1. One `main.tsp` and `gooir.toml` produce DTOs, the operation trait, Axum
   route, Clap command, MCP tool, OpenAPI, and SQLite history through one
   workspace build.
2. The TypeSpec compiler runs once. Bridge and backend providers consume
   retained admitted outputs without reparsing or re-observing the source.
3. The Rust result is one complete managed companion crate. The caller writes
   no binding JSON, capability coordinates, authority JSON, Cargo modules,
   generated imports, or file-tree union code.
4. Fleetd directly compiles and uses the generated crate. Its production
   `GET /v1/agents` route and corresponding CLI and MCP registrations use the
   generated adapters, and the parallel handwritten adapters for that slice
   are removed.
5. One product-owned implementation of the generated operation trait retains
   Fleetd authorization and `Store::list_agents` behavior. Generation does not
   move business logic into the companion crate.
6. Existing authentication, durable-data, response-shape, crate-boundary,
   OpenAPI, CLI, and MCP tests remain at least as strong and pass against the
   generated path. The native-HTTP-plus-catalog OpenAPI result is compared by
   normalized supported semantics, not bytes, with the official TypeSpec
   `getOpenAPI3` result. A separately authored brownfield native-HTTP fixture
   passes through the same portable OpenAPI backend.
7. SQLite history is applied to a real temporary database and its catalog is
   introspected. A second schema revision proves baseline use, deterministic
   append, and full replay. Missing history without explicit genesis or prior
   baseline is tested as refusal.
8. A second unchanged build reports unchanged outputs and requires no manual
   edits. A changed preset resource or offer remains unavailable for execution
   or direct provider authority until explicitly approved.
9. At least one request or response proves a logical handler schema differs
   from its HTTP-effective wire schema; generated bindings preserve the
   visibility and encoding difference, while an unsupported encoding refuses.

Passing this slice retires only its hardcoded Fleetd orchestration and parallel
adapters. It does not by itself retire every DataModel v1, Operations v1,
native HTTP, or other compatibility consumer.

## Consequences

- The usable n+m boundary is producers to a small set of portable semantic
  facts plus consumers from those facts, not every source paired with every
  target.
- One parse supplies the schema, Operations, persistence, and bridge facts;
  reusable bridge providers supply native surfaces to target backends.
- Adding a target adds an external provider and profile; it does not add a
  dialect CLI or kernel layer.
- Adding a compliant authoring language adds one frontend to the same portable
  facts and bindings; it reuses the bridge and target backends, including the
  portable OpenAPI route.
- Materialization remains admitted host I/O, never a semantic lowering edge.
- Every new intermediate and authority mechanism must demonstrate a gap in
  these existing boundaries before it can enter the architecture.
