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
     proven surface bindings
  -> reusable Operations + HTTP binding bridge
  -> native HTTP
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

- one conventional portable `spec/` source root containing `main.tsp`, which
  may import other files in that root. The application declaration in
  `main.tsp` includes its stable application identity and absolute schema
  retrieval-base URI; and
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
2. write `spec/main.tsp` and output destinations in `gooir.toml`;
3. run one output-specific genesis-authorized build for a new migration
   lineage; and
4. use ordinary `workspace build` thereafter.

For a greenfield application that build may produce three disjoint managed
roots: a complete generated Rust crate, an OpenAPI document root, and a SQLite
migration-history root. A brownfield application may enable a root only after
it can transfer ownership of that complete root. In particular, the first
Fleetd HTTP proof produces only the Rust crate and OpenAPI roots; Fleetd's
shared SQLx history requires a later whole-history adoption. The stable
handwritten server seam is one Cargo dependency on the generated crate plus
one implementation of its server operation trait and one explicit
composition-root registration of the crate's complete generated router.
Registration is dependency injection, not discoverable compiler behavior.
Regeneration requires no provider CLI, binding JSON, generated-file edits,
generated module declarations, or file-tree stitching.

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
4. **Surface bridge bindings** — complete exposed-or-omitted decisions for one
   exact Operations fact. They map logical operation values to mechanism
   coordinates and wire values. They are generated by the frontend for
   greenfield TypeSpec, not hand-authored by the normal consumer. HTTP vNext is
   defined first. CLI and MCP vNext are defined only with the product slice
   that establishes their invocation and authority semantics.
5. **Native HTTP** — independently authorable protocol meaning. It does not
   depend on Operations. Current `gooir-http` proves the Rust/Axum consumer;
   native HTTP vNext is not releasable until Gate A proves portable OpenAPI as
   the second independent consumer. Native CLI and MCP facts are not introduced
   merely in anticipation of reuse; the cohesive Rust backend may consume
   their proven Operations bindings directly.
6. **ContentSet** — portable final bytes.

Backend-specific target profiles are ordinary typed inputs owned and versioned
by each external backend. They are not one ecosystem-wide profile vocabulary.

Every schema reference is `(catalog FactId, absolute resolved resource URI
without fragment, optional RFC 6901 JSON Pointer)`. The fact identity must
equal the exact admitted catalog input. The catalog records one explicit
absolute retrieval base URI supplied as application semantics. Each embedded
absolute or relative `$id` is resolved under JSON Schema base-URI rules,
starting from that retrieval base and applying nested base changes under RFC
3986. The schema reference names the resulting absolute URI, not the literal
`$id`, a filename, or a `$defs` key. A resolver registry is constructed only
from the admitted document, and the optional pointer resolves within that
resource.
Duplicate resolved resource URIs, unresolved pointers, any `$ref` or
`$dynamicRef` whose resolved resource is absent, and every attempted network
fetch are invalid.

The retrieval base is declared in the `@gooi/app` application annotation in
`main.tsp`, is observed and admitted with that source root, and must be a
portable absolute URI independent of checkout paths. File and other
host-local URI schemes are refused. Changing it is an ordinary semantic source
change and therefore changes the catalog and every reference to it.

The first catalog value-kind version fixes the official JSON Schema emitter to
`file-type=json`, `bundleId=schema.json`, `emitAllModels=false` with application
roots explicitly marked `@jsonSchema`, `emitAllRefs=false`,
`int64-strategy=number`, `seal-object-schemas=true`, and
`polymorphic-models-strategy=oneOf`. Open or unsupported polymorphism is a typed
inability. These choices are semantics of the catalog version, not a mutable
profile envelope or downstream flag. The relative `bundleId` is both the
official emitter's root filename and literal root `$id`. Its resolution against
the catalog's explicit absolute retrieval base is the resource URI used by a
cross-fact reference. This removes the previous contradiction between a
relative `bundleId` and an absolute schema reference without post-processing
the official emitter's schema semantics.

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
persistence, effect/replay and authority annotations, and each proven surface
exposure. It emits the exact set of requested named facts in one invocation.
An ordinary bridge provider produces native HTTP. Directly authored native
HTTP remains a valid input to the same downstream providers. CLI and MCP
bindings feed the cohesive application backend directly until another real
consumer justifies native intermediate facts.

A preset requests only named facts whose contracts and consumers are present
in that stack version. The Gate A frontend therefore emits catalog,
Operations, and HTTP binding outputs in its one compiler run; later versions
add persistence, CLI, or MCP outputs without turning their absence from the
earlier exact specification into a silent partial result.

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

The Rust `ProviderApp` is the reference SDK, not a mandate that compiler
ecosystems be rewritten in Rust. TypeSpec and Quicktype both have native
JavaScript implementations, so the external stack also supplies one small
JavaScript provider SDK for the existing neutral protocol: strict framing,
exact specification/implementation dispatch, canonical fact construction,
extension handling, typed inability, and multi-capability service. It creates
no new wire protocol or kernel abstraction, and it is justified by those two
real consumers rather than one wrapper per provider.

Every requested destination resolves through the lock to exactly one final
capability output and `ManagedOutputId`. Destinations are pairwise distinct
and may not contain one another or the portable `spec/` source root in either
direction. `ContentSet` rejects duplicate, reserved, and portable-colliding
paths. The Rust backend additionally constructs one global module and symbol
table and refuses duplicate module paths, Rust items, import
aliases, Cargo features, incompatible dependency requirements, HTTP routes,
CLI command paths, or MCP tool names. It never silently renames, overwrites, or
patches consumer-owned files. The complete crate must pass the pinned Rust
toolchain in provider-release qualification and in the consuming application's
build.

The first Rust service backend consumes the schema catalog, Operations, exact
surface bindings, native HTTP, and one backend-owned Rust profile. It emits one
complete generated crate as one `ContentSet`: `Cargo.toml`, DTO modules, the
server operation trait, Axum routes, and every surface adapter proven by the
selected product profile, plus all imports and module declarations. It owns all
generated names and paths, checks symbol collisions before emission, and
exposes one documented crate API to the handwritten application. Quicktype is
an internal library of this backend for DTO rendering; its `TypeGraph` and
partial files do not cross the provider boundary. This deliberately replaces
separate DTO, port, Axum, Clap, and MCP `ContentSet`s whose composition would
require manual Cargo and module wiring.

The generated crate exports a complete router constructor parameterized by the
product's operation implementation. The application must call that constructor
once from its composition root and merge the result under its existing global
middleware and state. The backend cannot discover or mutate the caller's route
graph. Fleetd's gate replaces `generated_list_agents::routes()` with this
documented crate-root registration; it does not pretend a Cargo dependency or
trait implementation installs routes by itself.

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

Generated server adapters call one handwritten implementation of the generated
server operation trait. A remote CLI client is a transport client and does not
pretend to be another invocation of that server implementation. An MCP adapter
is generated only after the product defines who may invoke it and what
authority it carries. Interface generation cannot and does not invent business
behavior or product authority.

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
  assessment. It also records the complete `ObservationAuthority` values for
  the bounded preset-resource observer, each scoped to one exact resource
  source and value kind it may introduce as an initial typed profile fact.

Preset production is data-driven too. An ecosystem release uses a generic
packing command over offer-free package manifests, explicit executable paths,
backend profiles, output roles, and bounds to produce an immutable local
preset bundle containing the existing exact toolchain image plus a versioned
workspace-preset manifest. Backend authors do not write product-specific
toolchain assembly programs. The first distribution mechanism is deliberately
only a local directory or archive plus its expected digest.

`workspace init` resolves an explicitly selected preset bundle, writes the
lock, displays the exact executable resources, profile resources, offers, and
their distinct authority choices, and requires an explicit
one-time approval before they can execute, receive provider authority, or
enter the ledger as observed profile facts. The
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
the workspace's portable `spec/` root containing `main.tsp`. The host records
the exact observer and evidence for the bytes it observed. That establishes
source-byte provenance for the run; it grants no semantic authority to a
frontend or generator. For that run, the workspace constructs the complete
`ObservationAuthority` for its exact observer implementation and measured
artifact and adds it to the policy's accepted observation authorities. Neither
the preset nor the lock can supply that acceptance.

The same invocation separately authorizes the bounded, no-follow configuration
loader for `gooir.toml`. It records that exact observer and evidence, constructs
only the typed meaning-affecting configuration facts named by the locked input
routes, and adds the matching complete `ObservationAuthority` value for each
source/value-kind pair to policy for the run. This does not admit output paths
or other orchestration-only fields as semantic facts.

Backend profiles and migration choices affect generated meaning and therefore
enter derivation as exact admitted typed facts. For preset-owned profiles, the
lock pins the expected value identity, kind, specification, and route but
cannot turn bytes into trusted inputs. The bounded preset/package-resource
loader constructs their exact observations only under the separately granted
preset-resource `ObservationAuthority` matching each profile source and value
kind, which the workspace adds to admission policy explicitly. For later
user-authored migration choices, the lock pins only the expected kind,
specification, input port, and route; each build derives the value identity
from the currently observed `gooir.toml`, so a legitimate policy edit never
requires rewriting the lock.
Requested output roles and destinations remain orchestration inputs rather than
semantic facts. `gooir.toml` is not a hidden flag channel: only its
meaning-affecting backend and migration choices are lifted into explicit facts
by the bounded, no-follow workspace configuration loader under a separate
host-owned configuration observation authority. A prior managed snapshot
becomes an input only after the workspace observes and admits its exact
recovered bytes.

Independent validation must not become a second generator. Examples include:

- compile emitted Rust with the pinned Rust toolchain during provider-release
  qualification and as a consumer build gate;
- parse and inspect generated Clap or MCP registrations with their official
  libraries;
- validate JSON Schema and OpenAPI with their authoritative schemas/tools; and
- apply SQL to the real target database, introspect its catalog, and compare
  supported persistence semantics.

Passing target syntax checks is not proof of semantic correspondence. A
validator claims only the checks it actually performed. Fixture or corpus
qualification must be labeled as such and cannot be generalized to arbitrary
consumer specifications.

The current `LocalStdioHost` executes one copied provider artifact with an
empty environment and exposes no companion package resources. It therefore
cannot honestly invoke a separately pinned Cargo or `rustc` during candidate
admission. The first stack uses exact provider authority plus the release and
consumer build gates above; it never invokes ambient `cargo` and describes that
as locked validation. Per-candidate compilation would require a separately
reviewed package execution capsule with declared companion resources, not an
implicit exception in a backend.

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

Migration ownership is by history root, not by operation or entity. Fleetd's
`sqlx::migrate!()` consumes one checksummed history for the complete store, so
the `list_agents` slice cannot publish an operation-local replacement. Its
migration gate requires an explicit validated adoption of the whole existing
history, followed by generation and replay of the complete successor history.
Until then, the HTTP proof makes no SQL-generation claim.

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
2. Prove one JavaScript implementation of the existing neutral provider
   protocol packaged as one directly executable self-contained offer artifact,
   then extract the shared SDK only across the TypeSpec and Quicktype-backed
   executables. The current host supplies no ambient Node, `PATH`,
   `node_modules`, or companion runtime resources.
3. Define the minimal catalog, Operations v2, HTTP binding, and native HTTP
   contracts from one real Fleetd HTTP slice, including the exact
   logical-to-wire schema joins above. Persistence, CLI, and MCP vNext wait for
   their actual product slices.
4. Build the external compile-once TypeSpec frontend, the Operations-to-native
   HTTP bridge, and the native-HTTP-plus-catalog OpenAPI backend.
5. Build one cohesive Rust HTTP service backend. Quicktype and Axum generation
   are internal components of the complete crate owner, not public fragment
   facts or competing directory writers.
6. Prove the raw external chain against Fleetd: one TypeSpec source produces
   admitted complete Rust-crate and OpenAPI `ContentSet`s; Fleetd compiles and
   runs its production `GET /v1/agents` path through the generated crate; and
   no parallel in-tree admitted fragment adapter, generated module declaration,
   or partial-file stitching remains. The only route wiring is the generated
   crate's documented composition-root registration.
7. Productize that chain with local preset resolution, exact lock
   generation/diff, separate host execution/admission grants, admitted profile
   facts, and prepare/publish workspace composition.
8. Make explicit Fleetd product decisions for the remote CLI client and a new
   operator MCP surface and authority model. Only then add and prove their
   binding/backend support in the same complete crate.
9. Define the persistence overlay and SQLite transition contracts by adopting
   Fleetd's complete existing SQLx history. Prove full replay, catalog
   introspection, baseline evolution, and a second schema revision.
10. Remove or mark unsupported only the exact Fleetd machinery replaced by
    each proved stage. Expand retirement only as further real consumers
    migrate.

## Acceptance gate

This decision remains proposed until three honest Fleetd gates pass. They may
land separately; no later claim is folded into the first proof.

### Gate A — HTTP, OpenAPI, and complete Rust crate

1. One `main.tsp` and `gooir.toml` produce DTOs, a server operation trait, an
   Axum route, and OpenAPI through one workspace build.
2. The TypeSpec compiler runs once. Bridge and backend providers consume
   retained admitted outputs without reparsing or re-observing source.
3. The Rust result is one complete managed companion crate. The caller writes
   no binding JSON, capability coordinates, authority JSON, Cargo modules,
   generated imports, or file-tree union code. Fleetd keeps one explicit call
   that registers the complete generated router in its composition root.
4. Fleetd directly compiles and uses that crate for production
   `GET /v1/agents`; the existing in-tree admitted fragment adapter is removed.
5. One product-owned server implementation retains Fleetd authorization and
   `Store::list_agents` behavior. Generation does not move business logic into
   the companion crate.
6. Existing authentication, durable-data, response-shape, crate-boundary, and
   OpenAPI tests remain at least as strong. Portable OpenAPI is compared by
   normalized supported semantics, not bytes, with the official TypeSpec
   result, and a brownfield native-HTTP fixture uses the same OpenAPI backend.
7. At least one request or response proves a logical handler schema differs
   from its HTTP-effective wire schema; supported visibility and encoding are
   preserved and an unsupported encoding returns typed inability.
8. A second unchanged build reports unchanged outputs and requires no manual
   edits. A changed preset resource or offer cannot execute or receive direct
   provider authority until explicitly approved.

### Gate B — CLI and MCP product semantics

1. Fleetd explicitly chooses whether `agent list` remains a generated HTTP
   client or becomes an in-process command; the selected transport behavior is
   tested and is not described as the server trait implementation.
2. Fleetd defines an operator MCP operation, caller authority, and exposure
   policy instead of repurposing its invocation-scoped publish-only MCP server.
3. The compile-once frontend and cohesive crate backend generate the selected
   CLI and MCP adapters with no hand-authored binding files or parallel
   registration glue.

### Gate C — whole-history SQLite evolution

1. Fleetd explicitly adopts its complete existing SQLx migration history into
   one managed root; no operation-local generator claims ownership of it.
2. The complete history is applied to a real temporary SQLite database and its
   catalog is introspected. A second schema revision proves baseline use,
   deterministic append, and full replay.
3. Missing history without explicit one-shot genesis or an admitted prior
   baseline refuses, and unmanaged or drifted history is never overwritten.

Passing Gate A retires only the hardcoded Fleetd HTTP orchestration and
parallel HTTP adapter it replaces. Gates B and C retire only their exact
counterparts. None of these gates by itself retires every DataModel v1,
Operations v1, native HTTP, or compatibility consumer.

## Consequences

- The usable n+m boundary is producers to a small set of portable semantic
  facts plus consumers from those facts, not every source paired with every
  target.
- One parse supplies the schema, Operations, persistence, and bridge facts;
  a reusable bridge supplies native HTTP where two downstream consumers
  justify it, while the cohesive backend consumes single-use bindings directly.
- Adding a target adds an external provider and profile; it does not add a
  dialect CLI or kernel layer.
- Adding a compliant authoring language adds one frontend to the same portable
  facts and bindings; it reuses the bridge and target backends, including the
  portable OpenAPI route.
- Materialization remains admitted host I/O, never a semantic lowering edge.
- Every new intermediate and authority mechanism must demonstrate a gap in
  these existing boundaries before it can enter the architecture.
