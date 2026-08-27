# 0035 — Typed authoring for neutral v1 providers

Status: experimental pending two independent consumers

## Context

Decision 0034 established one host-facing derivation façade over exact package,
planning, invocation, conformance, and admission protocols. It deliberately did
not put execution inside GOOIR. A package-backed provider nevertheless had to
manually repeat the neutral protocol boundary: validate the invocation, compare
the complete capability specification and selected implementation, find and
decode named inputs, recover declared output kinds, construct facts and named
outputs, distinguish inability from provider failure, construct a correlated
result, and frame JSON over stdin/stdout.

The older `gooir-provider::register_transform` helper proved that provider
authorship should collapse to the transformation itself. That helper is tied to
the compatibility `CapabilityRegistry`, supports exactly one input and one
output, and invokes providers in-process. Extending that path would create a
second runtime beside the v1 package and external-host boundary.

HTTP-to-framework generation supplies the immediate non-speculative shape: an
implementation may consume HTTP semantics, handler bindings, and a target
profile and produce one or more target artifacts. Repeated value kinds remain
distinguishable only by port name. The authoring surface therefore has to
support the complete hyperedge rather than another source/target shortcut.

## Decision

`gooir-provider::neutral` is the experimental Rust authoring surface for
neutral v1 package-backed providers. `Provider` binds one exact
`CapabilitySpec` to one exact `ImplementationId`. It validates every invocation
and checks both the complete specification and selected implementation before
calling provider code. Offers and artifact identity remain package/host-owned;
provider code validates the selection it receives but never manufactures one.

A handler receives a `Context` and returns an `Outcome`:

```rust
provider.invoke(&invocation, |context| {
    let source: Source = context.input("source")?;
    let profile: Profile = context.input("profile")?;
    let target = lower(source, profile);

    context.produced().output("target", target)?.finish()
})
```

Inputs and outputs are selected by exact declared port name. Payloads are
decoded and encoded through caller-supplied Rust types, while value-kind
identity comes only from the capability declaration. The produced builder
accepts outputs in any authoring order, refuses unknown and duplicate ports,
requires the complete declared output set, and emits the declaration's exact
order before constructing a `CapabilityResult`.

`Context::input` refuses facts carrying semantic extensions so typed decoding
cannot silently discard unknown meaning. `input_with_extensions` is the
explicit escape hatch: it exposes the decoded value, complete fact, admitted
reference, and linking extensions. Output fact and envelope extensions likewise
require an explicit API. Protocol constructors remain the final authority and
reject reserved or incompatible extension data.

Semantic inability is an `Outcome` constructed with an exact `FailureKindId`
and typed detail. SDK, framing, serialization, and provider authoring errors
remain `ProviderError`. A provider therefore cannot report
"could not derive this value" by accidentally looking like a crashed host, nor
can a crashed host manufacture a semantic inability.

`invoke_json`, `serve_once`, and `serve_stdio` own only the credential-free
document framing. Launch, artifact measurement, authority-record resolution,
resource limits, deadlines, retries, recovery, and admission remain
external-host concerns.

`DerivationRequest::unique_only` and `DerivationRequest::explicit` provide the
matching caller convenience. They remove empty-extension and selection-envelope
boilerplate while still constructing untrusted requests whose exact invariants
are checked by `DerivationFacade::answer`.

## Consequences

- One API authors lifts, lowerings, analyses, bridges, and generators. Direction
  remains ecosystem meaning rather than a kernel trait hierarchy.
- Multi-input and multi-output providers no longer require hand-written neutral
  protocol code.
- The SDK cannot select a route, provider, conformance suite, or attester and
  cannot admit its own output.
- Provider packages and hosts retain their existing dependency direction; no
  HTTP, Axum, Rust source, Fleetd, or filesystem concept enters GOOIR.
- The top-level in-process helpers remain available for compatibility but are
  not the package-backed v1 execution path.
- This interface remains experimental until two independent downstream
  consumers exercise it; successful internal tests alone do not promote it.
