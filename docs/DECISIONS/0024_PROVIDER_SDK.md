# 0024 — The provider SDK

Status: complete

## What this closes

The data-model loss study, now retained with the extracted data-model
ecosystem, measured the ceremony and named the target:

> **842 lines of pack. Nine of them call a lifter or a lowering.**

[0023](0023_PACK_MANIFEST.md) moved the *declarations* out of Rust and into a
manifest. What was left was the *plumbing*: decode the input fact, decide
coverage, wrap the output, describe yourself. Written once per provider, nine
times over, and copied between packs.

An SDK has exactly four jobs, and they are the same four in every language:

| the job | Rust | Python |
| --- | --- | --- |
| read a declared input | `input(inputs, &fact)` | `ctx.input(fact)` |
| admit what could not be carried | a `Defeat` on the result | `ctx.defeat(kind, subject, reason)` |
| publish an output | `publish(fact, &result)` | `ctx.produce(fact, value)` |
| decide coverage | — | — |

The fourth row is empty on purpose.

## The rule the SDK exists to hold

**Coverage is derived from what was lost. It is never declared.**

A provider that can set its own coverage can claim completeness it did not
earn, which is the one thing a `Defeasible` result exists to prevent. Before
this, every provider computed its own `coverage(...)` boolean, and the Python
plugin wrote `"complete" if not losses else "partial"` by hand — correct, but
correct by authorship rather than by construction.

Both SDKs now derive it, and the Python one recomputes at response time, so a
defeat recorded *after* `produce` still lands:

```python
ctx.produce(TYPES, source)
ctx.defeat("authority_cannot_express", "createdAt", "timestamp is an ISO string")
# -> partial. Completeness cannot be banked before the provider admits its losses.
```

## Two shapes, one entry point

The first cut accepted only `Fn(I) -> Defeasible<O>`, which locked out every
fallible lift — `lift_openapi` returns a `Result`, because a document it cannot
parse leaves it with nothing rather than with a partial result. Rather than a
second function name, one trait admits both:

```rust
pub trait Outcome<O> { fn into_defeasible(self) -> Result<Defeasible<O>, String>; }
impl<O> Outcome<O> for Defeasible<O>
impl<O, E: Display> Outcome<O> for Result<Defeasible<O>, E>
```

A provider is now its transformation and nothing else:

```rust
gooir_provider::register_transform(
    registry,
    provider_id("openapi_data"),
    openapi_data_capability(),
    implementation("openapi_data"),
    |source: SourceDocument| lift_openapi(&source.text),
)?;
```

The fact types are absent because the manifest already declares them: `invoke`
receives the capability spec, so a transform is handed the input its capability
requires and publishes the output its capability produces. Naming them here
would be the third copy of a fact identity.

## Identity is the caller's, not the SDK's

`register_transform` takes a `ProviderId`, not a name. The checked-in
cross-repository fixture pins
`dev.fleetd.provider.in_process/fleetd_web_target@0.1.0` inside
`inputs[0].derivation`; a package chosen by the SDK would cascade into the
`request_id`. A provider belongs to whoever publishes it, and its identity
appears in the derivation of every fact it produces — an SDK inventing one
would rename other people's evidence.

## What moved

| | before | after |
| --- | --- | --- |
| pack source (the two `lib.rs`) | 704 lines | 584 |
| hand-written `impl CapabilityProvider` in packs | 9 | 4 |
| the example plugin | 130 lines | 98 |
| lines in it that touch the wire | 14 | 1 |
| tests | 325 | 331 |

The four remaining hand-written impls are the multi-input providers, which take
two to four facts and in one case check that they came from the same revision.
`register_transform` deliberately refuses rather than guessing which input is
which. Whether a multi-input affordance is worth its complexity is a separate
measurement, not a foregone conclusion.

*Lines that touch the wire* means lines naming the protocol, the response
frame, a fact type, or coverage — counted by grep, discounting prose and one
`json.dumps` that renders an enum rather than framing a reply. It undercounts
the before, because multi-line blocks like the input scan and the response
literal have lines that mention none of those words. The plugin's whole
`main()` is gone; what is left is `field_type` and the loop that builds the
interfaces.

The Python SDK is 140 lines and the plugin now imports it, so the manifest lists
it among the files the host measures — the digest covers what actually runs.

## Verifying the instrument

An SDK is code, and its guarantees are only worth what the host receives, so
the Python SDK is tested through the real interpreter over the real protocol
rather than in a Python-only harness. Then each test was checked against a
deliberately broken SDK:

| perturbation | caught |
| --- | --- |
| coverage not recomputed at response time | yes |
| any defeat kind accepted | yes |
| input envelope not unwrapped | **no** |
| (Rust) `publish` always claims `Complete` | yes |

The third was a real gap. Every test fed a *bare* input payload, so the
unwrapping path never ran — while the actual plugin receives an enveloped
data-model fact and would have failed in production looking like an empty
model. One test with an enveloped input closed it, and the perturbation then
failed as it should.

The test count is against this branch's starting point, not the data-model
study's 305 — [0023](0023_PACK_MANIFEST.md) landed in between.

## State

331 tests, clippy and fmt clean. The cross-repository fixtures are byte-identical,
which is the check that the provider identities did not move.
