# GOOIR

GOOIR derives facts about software over a **capability graph**. You supply what
only you have; it works out what can be reached, produces it, and names exactly
what is missing so somebody or something else can produce that.

It never guesses. An identity is matched exactly and never by range, a fact
that could not be fully established says so, and a capability nobody implements
stays in the plan as an assignable need rather than disappearing.

## Five concepts

| | |
| --- | --- |
| **Fact** | a typed, identified value, carrying whether its coverage was complete |
| **Capability** | a versioned promise from exact input fact types to exact output fact types |
| **Provider** | one implementation of a capability |
| **Plan** | a derivation over capabilities from what you have to what you want |
| **Admission** | the separate decision that a produced fact may be trusted |

Everything else is a special case. A *lift* is a capability whose inputs come
from existing software; a *lowering* is one whose outputs are a target format;
a *projection* moves between two semantic facts; an *analysis* produces
findings. The planner knows none of those words — it only composes typed edges.

## Start here

```bash
cargo run -q --bin gooir
```

One command is the whole surface:

```text
gooir facts                        every fact type, and how it is reached
gooir capabilities                 every promise, and whether it has a provider
gooir needs                        promises with no provider, as work contracts
gooir doctor                       graph health
gooir plan <target>                the route to a target
gooir derive <target> --from FILE  run it, and print the derivation chain
```

Write a few lines of text and derive a real artifact from it:

```bash
cat examples/tasks.entities
cargo run -q --bin gooir -- derive postgres_ddl --from examples/tasks.entities
```

Ask for something nothing can produce yet, and the answer is a contract rather
than a shrug:

```bash
cargo run -q --bin gooir -- derive model_types --from examples/tasks.entities
```

Then install a provider for it. This one is a Python script:

```bash
cargo run -q --bin gooir -- derive model_types \
  --from examples/tasks.entities \
  --plugin examples/plugins/typescript-types/plugin.json
```

A provider is any program that reads one JSON document and writes another, so
it need not be Rust, or compiled, or built here. The host names each manifest
explicitly and measures the implementation itself — see
[0019](docs/DECISIONS/0019_PLUGIN_LIFECYCLE.md).

## How the crates are organised

Forty crates, six roles. Every crate is exactly one of these:

| role | what it holds | examples |
| --- | --- | --- |
| **kernel** | the primitives, knowing no domain | `gooir-identity`, `gooir-core`, `gooir-capability`, `gooir-analysis`, `gooir-doctor` |
| **fact family** | a versioned vocabulary of fact types | `semantics-data-model-v1`, `semantics-effects-v1`, `semantics-interaction-activation-v0` |
| **provider** | one implementation that produces facts | `prisma-schema-lifter`, `sql-ddl-lowering`, `entity-spec` |
| **provider pack** | registers capabilities and providers into a graph | `gooir-datamodel-pack`, `fleetd-capability-pack` |
| **tool** | reads or reports on a graph | `gooir-cli` — the one entry point |
| **support** | shared machinery and empirical probes | `lift-defeasible`, `gooir-provider` (the SDK), `interaction-activation-recurrence` |

A crate named `*-lifter` or `*-lowering` is a provider; the suffix says which
direction it travels, not that it is a different kind of thing.

## Where the reasoning lives

Twenty-seven decision records in [docs/DECISIONS](docs/DECISIONS) carry the
argument, including the ones that overturned earlier plans. The most load-bearing:

- [0002](docs/DECISIONS/0002_EVIDENCE_TRUST_POLICY.md) — evidence is trusted contextually, never by self-declaration
- [0011](docs/DECISIONS/0011_CAPABILITIES_AS_TYPED_DERIVATIONS.md) — capabilities as typed derivations
- [0014](docs/DECISIONS/0014_AUTHORING_AS_A_CAPABILITY.md) — hand-written text is an ordinary source fact
- [0015](docs/DECISIONS/0015_GOOIR_DOCTOR.md) — the graph reports on its own health
- [0017](docs/DECISIONS/0017_ONE_ADMISSION_RULE.md) — passing a suite and being admitted are two conditions
- [0023](docs/DECISIONS/0023_PACK_MANIFEST.md) — a capability graph is declared as data
- [0024](docs/DECISIONS/0024_PROVIDER_SDK.md) — a provider is its transformation; coverage is derived, never declared
- [0027](docs/DECISIONS/0027_INTERACTION_ACTIVATION_RECURRENCE.md) — interaction starts at observed activation, not a parallel component system

Also the [project brief](docs/PROJECT_BRIEF.md),
[architecture](docs/ARCHITECTURE.md) and [milestones](docs/MILESTONES.md).

## Interaction recurrence probe

The first ecosystem-derived interaction contract comes from pinned React,
Vue, Ink, shadcn/ui, and Mantine source—not an authored GOOIR component model:

```bash
cargo test -p interaction-activation-recurrence
npm ci --prefix tools/interaction-activation-lifters
npm test --prefix tools/interaction-activation-lifters
npm run check --prefix tools/interaction-activation-lifters
```

Source-specific AST projections over the independently governed React DOM and
Vue runtime-dom lineages recur on only one positive meaning: a source-local
activation invokes its registered handler. DOM buttons, terminal keys, labels,
enablement, effect counts, renderers, and component-library names remain native
or unknown. Ink is measured as a React renderer and non-voting host-diversity
participant, with that lineage recovered from its pinned reconciler imports;
shadcn as a registry/source materializer; Mantine as an installed React package.
Existing programs can use those native routes without producing an Interaction
fact at all.

The checked-in corpus verifies exact upstream revisions and file digests. A
pinned Babel parser and deterministic ecosystem-specific lifters produce exact
source spans; mutation tests revoke the fact when any positive path is broken.
The recurrence suite then proves that every measured divergence remains
preserved. See [decision 0027](docs/DECISIONS/0027_INTERACTION_ACTIVATION_RECURRENCE.md).

## Fleetd multi-dialect dogfood

The first Fleetd operator-surface probe composes the neutral data-model
contract with a product-specific Fleetd control contract, then lowers the same
interaction meaning to web and terminal target IRs:

```bash
cargo run -q -p fleetd-control-projection --bin fleetd-control-check -- \
  /path/to/fleetd
```

The command resolves Fleetd's exact Git revision, refuses modified source
inputs, and reads its generated OpenAPI plus the Rust guards and resolution
implementation. See [decision 0010](docs/DECISIONS/0010_FLEETD_MULTI_DIALECT_DOGFOOD.md).

The same derivation now runs through the experimental capability registry:

```bash
cargo run -q -p fleetd-capability-pack --bin fleetd-capability-check -- \
  /path/to/fleetd
```

The registry discovers and executes the web and terminal routes, preserves
fact-level derivation provenance, and emits the missing runnable-web provider
as a machine-readable capability need plus `runnable_web_request`, which binds
that need to the exact web-target fact for Fleetd consumption. Capability
meaning is independent of whether a later provider is an in-process pass,
external compiler, or agent.

The return path is now explicit as well. Fleetd can strictly lift a durable
provider attempt into an exact, still-unverified `CapabilityCandidate`. GOOIR
accepts candidate facts only after a separately identified implementation runs
the request's exact conformance suite. Passing facts carry request, candidate,
provider implementation, input, and conformance-result identities in their
derivation; a failing suite produces a durable report and no admitted facts.
The checked-in cross-repository fixture intentionally fails conformance to
prove that successful transport cannot masquerade as a runnable artifact.

The first real suite is now implemented in the product-specific Fleetd pack.
Its artifact contract binds the exact target fact to a trusted Fleetd Git
revision, a fixed operator entrypoint, and a SHA-256 manifest of served assets.
The verifier checks out that revision itself and injects a verifier-owned
black-box test of the public surface, exact served target contract,
authentication boundary, and both resolution effects:

```bash
cargo run -q -p fleetd-capability-pack \
  --bin fleetd-runnable-web-conformance -- \
  /path/to/fleetd request.json candidate.json
```

An existing clean Fleetd revision can enter through the other side of the same
waist. The deterministic brownfield projector emits an unverified provider
response containing the exact Git revision and asset manifest; it neither
generates the UI nor claims the suite passed:

```bash
cargo run -q -p fleetd-capability-pack \
  --bin fleetd-runnable-web-project -- \
  /path/to/fleetd request.json
```

The first live loop is qualified: the brownfield projection traveled through a
durable Fleetd message, strict extraction, independent Git/asset/runtime
conformance, admission, and a zero-need re-plan. The qualification identities
are recorded in [the milestones](docs/MILESTONES.md).

See [decision 0011](docs/DECISIONS/0011_CAPABILITIES_AS_TYPED_DERIVATIONS.md).
See also [decision 0012](docs/DECISIONS/0012_CANDIDATES_REQUIRE_INDEPENDENT_CONFORMANCE.md).
See also [decision 0013](docs/DECISIONS/0013_RUNNABLE_WEB_ARTIFACT_CONFORMANCE.md).

## Earlier proof surfaces

`GOOIR-000` proved the kernel boundary: unknown dialect data round-trips
without a plugin, analyzers depend on exact contracts rather than dialect
names, equivalent projections normalise equally, unverified claims never become
safety facts, and a meaning-changing version requires an explicit bridge.

`GOOIR-001` lifted a pinned Buzz event surface and reported a real cross-layer
gap with exact scope and provenance:

```bash
cargo run -q -p buzz-surface-check
```

See the [ten-minute Slice 1 demo](docs/SLICE_1_DEMO.md).

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Verification harnesses that need a live PostgreSQL:

```bash
./scripts/store-round-trip.sh
./scripts/app-runtime-smoke.sh
```
