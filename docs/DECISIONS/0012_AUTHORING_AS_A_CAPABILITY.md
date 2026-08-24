# 0012 — Authoring as a capability

Status: complete

## What changed

`entity-spec` was a standalone front door with its own command and its own
pipeline. It is now an ordinary source fact in the capability graph.

`gooir-datamodel-pack` is the neutral counterpart to
`fleetd-capability-pack`: it owns the canonical fact and capability identities
for the data-model family and contains no product concepts.

```text
authored .entities text ─> DataModel ─┬─> PostgreSQL DDL
                                      ├─> OpenAPI CRUD surface
                                      └─> TypeScript types   (no provider)
```

Three providers are registered — the authoring parser and the two lowerings
from [0006](0006_PHASE1_ROUND_TRIP.md)/[0007](0007_STORE_ROUND_TRIP.md) and
[0008](0008_POLYMORPHIC_CRUD_SURFACE.md). The fourth capability is declared
with **no provider on purpose**.

## Why this is the right shape

The previous framing had authoring and lifting as separate programs that
happened to build the same struct. Under [0011](0011_CAPABILITIES_AS_TYPED_DERIVATIONS.md)
they are two capabilities producing one exact fact, and that difference is
load-bearing: everything downstream of `DataModel` becomes reachable from
authored text **by planning rather than by wiring.** Adding a lowering
benefits the author and the lifter at once, with no integration step.

A test registers both packs in one registry and plans to
`org.gooi.semantics.data_model/model@1.0.0` twice — once from authored text,
once from a lifted OpenAPI document. Both plans are executable, both target the
same fact, and their steps differ. That is the interchangeability claim, tested
rather than asserted.

## The provider-less capability is the interesting one

Asking for TypeScript types yields an exact need:

```text
NEED     org.gooi.capability/lower_typescript_types@0.1.0
  requires org.gooi.semantics.data_model/model@1.0.0 (CompleteOnly)
  produces org.gooi.artifact.typescript/model_types@0.1.0
  suite    org.gooi.conformance.typescript_model_types@0.1.0
  reason   no installed provider implements this exact capability
```

I never wrote a TypeScript lowering. Before this, that absence was silence.
Now it is a machine-readable contract Fleetd can bind through
`work.capability.request/v1` and assign to a generator or an agent seat.

This is the cold-start mechanism, and it is not the one earlier decisions
assumed. [0004](0004_RECURRENCE_PROBE.md) proposed *lift patterns to fill a
catalog*. The actual mechanism is **name the gap exactly and let any provider
attempt it**. The catalog fills as providers register, and nothing is ever
silently missing.

## Fact identity is guarded across packs

`data_model_fact()` is declared in both packs, because the product pack must
name it to consume it and the neutral pack must own it. Two declarations of one
identity is exactly the drift this project exists to eliminate, so a test
asserts they are equal. `fleetd-capability-pack` is a **dev-dependency only**:
the neutral pack does not build-depend on a product pack, but a divergence
fails a test rather than quietly splitting the graph into two lookalike halves.

## Coverage stayed honest

Running `examples/tasks.entities` through the registry:

| target | coverage | why |
| --- | --- | --- |
| DataModel | Complete | the parse raised no defeat |
| PostgreSQL DDL | Complete | 3 tables, 1 enum type, 3 foreign keys, nothing filled in |
| OpenAPI CRUD surface | **Partial** | JSON Schema cannot express identity, uniqueness, defaults or relations |

The OpenAPI artifact is partial for the reasons [0008](0008_POLYMORPHIC_CRUD_SURFACE.md)
established, and the registry now carries that fact rather than the reader
having to remember it.

A specification with an unresolved defeat — an unmodelled domain like
`geography` — plans fine and then **fails execution** on the complete-only
lowering edge. Planning proves a typed route exists; it does not promise the
runtime fact will qualify.

## `app-runtime` is parked, deliberately

A runtime is not a derivation, so it does not belong in the graph as it stands.
The honest place for it is later, as a provider of a runnable-artifact
capability alongside Fleetd's `org.gooi.artifact.web/runnable_fleetd_surface`.
Until something asks for that, it stays a demonstration and is not pretended
to be on the path.

## State

271 tests, clippy and fmt clean. Registry: 4 capabilities, 3 providers in the
neutral pack; both packs coexist in one registry.
