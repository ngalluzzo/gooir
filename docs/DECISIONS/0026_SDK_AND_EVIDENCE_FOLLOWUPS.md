# 0026 — A narrow SDK and an eight-binary evidence surface

Status: complete

## The two open questions

[0024](0024_PROVIDER_SDK.md) left four multi-input providers hand-written
because the SDK had no demonstrated safe affordance for them. [0025](0025_ONE_DOCTOR.md)
left ten specialised binaries because deciding from `env::var` or
`Command::new` would classify implementation details, not purpose.

Both sets have now been read at their semantic boundaries.

## The multi-input measurement

The four implementations share an input count greater than one and little
else:

| provider | inputs | published payload | source of coverage |
| --- | --- | --- | --- |
| Fleetd native lift | four revision-pinned source documents | raw `FleetdControlLift` | its product-specific `NativeCoverage` witness |
| interaction composition | two `Defeasible` semantic facts | `Defeasible<BlockedDeliveryInteractionPlan>` | the returned defeats |
| web target lowering | interaction plus native lift | raw `WebSurface` | fallible lowering after complete-only inputs |
| terminal target lowering | interaction plus native lift | raw `TerminalSurface` | fallible lowering after complete-only inputs |

Only interaction composition has the output contract accepted by
`register_transform`: a `Defeasible<T>` whose defeats determine coverage. A
safe multi-input variant would therefore replace one 20-line provider while
adding another SDK registration shape and its tests. It would not remove the
native provider's same-revision check, adapt its distinct coverage witness, or
publish the two raw target payloads.

Making one abstraction cover all four requires either caller-supplied
`FactCoverage` — reopening the exact hole the SDK closes — or product-specific
output adapters and wrappers. That is more ceremony with a less obvious trust
boundary than the four explicit implementations.

So the SDK stays one-input/one-output. Multi-input providers continue to name
each input fact exactly and keep cross-input invariants next to the
transformation. Reconsider this when a second multi-input provider has the same
`Defeasible<T>` output contract, not merely the same arity.

## Every specialised binary

The ten binaries recorded by 0025 are the explicitly declared binaries other
than `gooir`. Four Buzz lifter/check binaries discovered automatically by Cargo
are a separate GOOIR-001 product surface and were not part of that count.

| binary | disposition | reason |
| --- | --- | --- |
| `app-runtime` | keep outside `cargo test` | long-running runtime over a live PostgreSQL; `scripts/app-runtime-smoke.sh` owns its 28 behavioral checks |
| `data-model-convergence` | keep report; assertions already in `cargo test` | cited by 0005 and 0007; `tests/convergence.rs` requires zero field, attribute, and unique-set divergence, while remaining entity or relation divergence must coexist with recorded defeats |
| `prisma-round-trip` | keep report; assertions already in `cargo test` | cited by 0007; `prisma-schema-lowering/tests/round_trip.rs` asserts the law over the same four applications |
| `ddl-round-trip` | keep outside `cargo test` | command surface used by `scripts/store-round-trip.sh` to cross a real PostgreSQL boundary |
| `openapi-round-trip` | delete | uncited deterministic report duplicated by stronger assertions in `tests/openapi_round_trip.rs` over the same corpus |
| `fleetd-control-check` | keep outside `cargo test` | 0010's live probe binds a clean external Fleetd Git revision and four source artifacts |
| `fleetd-capability-check` | keep outside `cargo test` | 0011's live proof binds a clean external Fleetd checkout and emits the exact request and derivation |
| `fleetd-runnable-web-conformance` | keep outside `cargo test` | effectful verifier checks out and executes the candidate revision against verifier-owned behavior |
| `fleetd-runnable-web-project` | keep outside `cargo test` | brownfield projector measures a clean external revision and its served assets |
| `gooir-datamodel-check` | delete | uncited predecessor to `gooir derive`; its graph, coverage, artifact, and open-need claims now fail in `tests/authoring_capability.rs` |

The cited deterministic reports remain useful reproductions even though their
invariants also fail under `cargo test`. The effectful binaries remain explicit
because silently skipping an absent database, checkout, or candidate runtime
would turn a missing check into a green one.

## Result

Specialised explicitly declared binaries: 10 → 8. No cited evidence command
was removed. The authored example gained a test over the real checked-in
`tasks.entities` file, including all three implemented routes, their coverage,
artifact shape, and the exact providerless TypeScript need.

335 tests, clippy and fmt clean.
