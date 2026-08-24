# 0011 — Capabilities as typed derivations

Status: experimental kernel and first Fleetd pack implemented

## Question

How can GOOIR discover and compose work without knowing OpenAPI, Fleetd,
interaction plans, web targets, agents, or the protocol used to invoke a
worker?

The answer must let an in-process implementation, an external compiler, and an
agent compete to satisfy the same semantic need without pretending those
providers are equally trustworthy.

## Distinctions

Four concepts are separate:

| Concept | Meaning |
| --- | --- |
| capability | a versioned, observable promise from exact input fact types to exact output fact types |
| provider | one implementation claiming it can attempt that promise |
| protocol | how a provider is discovered, invoked, observed, cancelled, or resumed |
| work contract | one authorized invocation with concrete inputs, expected outputs, acceptance checks, and ownership |

ACP, a process protocol, HTTP, an in-process Rust call, and a Fleetd worker
lease can all transport a provider invocation. None is itself the semantic
capability. Likewise an agent session is a domain-specific stateful resource,
usually composed from start, send, stream, cancel, resume, and inspect
capabilities plus lifecycle laws; it is not a kernel primitive.

## Kernel shape

`gooir-capability` adds a semantically agnostic registry. It knows only:

- exact fact, capability, and provider identities;
- conjunctive typed requirements and typed outputs;
- whether a requirement accepts a partial fact;
- a named conformance suite;
- provider availability;
- derivation planning and fact provenance.

A capability is a directed hyperedge because it may require several facts at
once. Planning uses exact identities and versions. It never guesses semantic
compatibility. A capability with no installed provider remains in the plan as
a machine-readable `CapabilityNeed`; it does not silently disappear.

Execution rejects missing inputs, partial facts supplied to complete-only
requirements, unavailable providers, provider failures, and output sets that
do not exactly match the capability specification. Produced fact identities
bind their payload, coverage, capability, provider, and exact input fact
identities.

`Complete` is coverage, not trust. It says the producing mechanism reported no
unresolved defeat. It does not prove that the provider is conformant, honest,
or authoritative. The current registry records the conformance suite a
provider would need to pass but does not yet admit or verify conformance
evidence.

## First product pack

`fleetd-capability-pack` registers the already-proven dogfood stages as six
in-process providers:

```text
Fleetd OpenAPI ───────────────> DataModel ─┐
                                          ├─> Fleetd interaction ─> web target IR
Fleetd OpenAPI + Rust ─> native control ──┤                       └> terminal target IR
                             └> FleetdControl
```

The registry, rather than a hand-wired checker, reconstructs and executes both
five-stage derivations. Against Fleetd revision
`1016c7862a9d4fe4984f6081896f6398cfc63c52`, both plans were executable and
their normalized semantic fingerprints were equal. Every output carries its
full derivation chain back to the four revision-pinned source facts.

The pack also declares:

```text
web target IR -> runnable Fleetd web artifact
```

No provider is registered for that capability. The planner therefore emits an
exact `CapabilityNeed` naming the required input, expected output, version, and
conformance suite. This is the first useful boundary for Fleetd to turn into a
work contract for OpenCode, Qwen, a conventional generator, or any later
provider.

`CapabilityRequest::bind` now performs that provider-neutral handoff. It binds
the need to the exact produced web-target fact and derives `request_id` as
SHA-256 over the RFC 8785 canonical JSON request body. Authority, recipient,
leases, deadlines, and ownership are deliberately absent: Fleetd adds those
when it durably consumes the request. The live checker emits this value as
`runnable_web_request`.

Fleetd's experimental `work.capability.request/v1` adapter accepts the emitted
request without translation, persists it as an immutable message, admits an
exact configured capability, and executes it in a per-request session lane
whose binding generation and owner epoch are durable. The correlated response
is explicitly an unverified provider attempt, not an accepted output.

Run the live proof from a clean Fleetd revision:

```bash
cargo run -q -p fleetd-capability-pack --bin fleetd-capability-check -- \
  /path/to/fleetd
```

## What this does not claim

- Providers are currently registered and invoked in-process; there is no
  generic plugin lifecycle or wire protocol.
- Registration is not capability conformance or trust admission.
- The pack's implementation digest is a deterministic registration
  fingerprint over its source, manifest, lockfile, and provider name; it is not
  a reproducible-build attestation of the complete dependency closure.
- Planning proves that a typed route and installed providers exist. Runtime
  facts may still be partial and cause a complete-only edge to reject them.
- A bound request is not itself a Fleetd lease or accepted result; Fleetd adds
  assignment and ownership, while conformance admission remains unimplemented.
- The product-specific interaction fact has not earned a generic Interaction,
  UI, Workflow, or Agent dialect.

## Next falsification

Extract candidate facts from Fleetd's provider-attempt result and accept them
only after the exact named conformance suite runs against the bound request.
The provider protocol must remain an adapter: replacing OpenCode with a local
Qwen harness or a deterministic generator must not change the capability,
request, or acceptance meaning.
