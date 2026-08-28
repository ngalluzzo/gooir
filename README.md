# GOOIR

GOOIR is a small semantic compiler substrate for an open provider ecosystem.
It gives independently governed vocabularies one exact way to name values,
declare typed transformations, link an implementation, and carry the evidence
needed for local admission. It does not know tasks, conversations, data
models, UI components, agents, Fleetd, or any execution provider.

The object-level center is deliberately finite:

```text
typed facts --capabilities--> candidate typed facts
```

An ecosystem supplies the meaning. A host supplies selection, credentials,
execution, durability, recovery, and policy.

## What is here

The 0.1 semantic substrate and product façade consist of six crates:

| Crate | Owns |
| --- | --- |
| `gooir-identity` | exact dialect, value-kind, capability, provider, and evidence identities |
| `gooir-capability` | facts, typed capability declarations, candidates, conformance, and admission records |
| `gooir-package` | exact package resources, dependencies, offers, exports, and installed locks |
| `gooir-planning` | provider-neutral plans and explicit implementation linking |
| `gooir-derive` | five-outcome façade, compiler driver, admission membrane, and bounded local stdio host |
| `gooir-doctor` | diagnostics over an installed capability graph |

The repository also contains narrow, optional support:

| Crate | Status |
| --- | --- |
| `gooir-cli` | bounded local `compile`, neutral graph inspection, and a legacy execution adapter |
| `gooir-provider` | neutral v1 provider and attester authoring SDKs plus legacy in-process adapter; not trusted kernel |
| `gooir-plugin-process` | transitional process-provider adapter; host-side, not a universal ABI |
| `gooir-wasip1-command-runtime` | bounded WASI command runner for hosts |
| `gooir-module-v0` | foundational heterogeneous module dialect; structural composition, not a kernel concept |
| `gooir-module-planning` | target legality and exact occurrence binding over the existing capability graph |
| `gooir-module-observer` | explicit containment evidence and policy-gated child source observations |
| `lift-defeasible` | reusable value-plus-defeaters representation |

Nothing domain-specific is installed by default. The CLI receives exact
package directories explicitly, in dependency order:

```sh
cargo run -q --bin gooir -- capabilities --package /path/to/package
cargo run -q --bin gooir -- doctor --package /path/to/package
cargo run -q --bin gooir -- plan org.example/result@1.0.0 --package /path/to/package
```

`gooir compile` is the default executable composition over that inventory. It
accepts only explicitly named package directories, source-observation JSON,
one admission-policy JSON document, attester-binding JSON, a target, and
mandatory positive stdin/stdout/stderr/time bounds. It admits the observations,
uses conservative complete selection, explicitly links each step, runs the
exact copied offer artifact over local stdio, independently assesses it with an
exact copied attester resource, and admits the result before linking a later
step. Run `gooir --help` for the complete invocation.

An attester-binding document is local host configuration, not a package offer:

```json
{
  "authority": { "suite": "org.example.suite/exact@1.0.0", "attester": { "implementation": "org.example.attester/exact@1.0.0", "artifact_digest": "sha256:..." } },
  "package": "org.example.attesters@1.0.0",
  "resource": "exact-attester"
}
```

The complete authority must be accepted by the policy, and its artifact digest
must equal the copied installed resource bytes.

This bounded adapter executes selected artifacts with the caller's OS
privileges. It supplies no arguments or environment, performs no `PATH` lookup,
and kills and reaps a child that exceeds its deadline, but it is not a sandbox
or durable execution host. JSON output is the existing five-outcome derivation
answer, not a new stable compile receipt, and no target-specific file is
materialized. Planning remains separately inspectable and provider-neutral.
The temporary `derive --pack ... --plugin ...` command remains an explicitly
legacy compatibility bridge. GOOIR never scans for executable code.

`gooir-module-v0` is the optional whole-unit composition vocabulary. One
module fact contains ordered operations that wrap ordinary content-identified
facts from any explicitly declared dialect. Operations may declare local
symbols and carry named, exactly typed references to other operations. The
module adds no target, pass pipeline, implementation choice, execution, or
domain meaning; those remain compiler request, capability, and host concerns.

`gooir-module-planning` supplies the corresponding compiler-request layer. A
target names one required result and the exact operation kinds legal in the
final module. Candidate planning presents the unique contained kind set to the
ordinary semantic planner; route binding then maps named capability input uses
back to exact operation occurrences and refuses to legalize a module unless
every illegal occurrence is covered. Legal operations remain outside that
coverage. These content-identified documents perform no provider execution,
invocation linking, admission, rewriting, or target materialization, and a
contained fact never becomes independently admitted merely because its module
was admitted.

`gooir-module-observer` bridges bound occurrences to the existing authority
membrane without changing invocation or authority protocols. It resolves an
exact admitted module, verifies the complete occurrence coordinate, emits a
content-identified containment witness, and returns an ordinary untrusted
source observation. Projection itself grants nothing: local policy must accept
the exact observer implementation and artifact before the child becomes
linkable. Once admitted, that child is an ordinary fact in that ledger; v1 does
not restrict its later use to one module compilation. True invocation-scoped
child authority would require a future protocol rather than an adapter trick.

## Writing a provider

Package-backed providers use one typed closure over their capability's named
ports. The SDK validates the exact invocation and implementation before the
closure runs, derives fact identities and value kinds from the declaration,
requires every output, and owns neutral JSON/stdin framing:

```rust
let provider = gooir_provider::neutral::Provider::new(
    http_to_axum_spec(),
    axum_implementation_id(),
)?;

let result = provider.invoke(&invocation, |context| {
    let http: HttpService = context.input("http")?;
    let handlers: HandlerBindings = context.input("handlers")?;
    let profile: AxumProfile = context.input("profile")?;
    let program = lower_to_axum(http, handlers, profile);

    context.produced().output("program", program)?.finish()
})?;
```

The same surface authors lifts, lowerings, analyses, bridges, and generators;
those are capability meanings, not separate kernel mechanisms. Multiple
inputs and outputs are first-class. `Context::input` refuses unhandled semantic
extensions rather than dropping them, while `input_with_extensions` exposes
the complete envelope to providers that understand them. The data-model and
native HTTP/Axum ecosystems independently exercise this surface; its authoring
contract is established for 0.1. `gooir-provider::attester` supplies the
corresponding narrow assessment-request and assessment-authoring seam for
independent attesters. Execution, artifact measurement, and trust remain host
responsibilities.

## Downstream ecosystems

Three downstream repositories prove real consumer boundaries:

- [`../gooir-datamodel`](../gooir-datamodel) is the data-model contract,
  provider pack, transformations, fixtures, and package/host proofs.
- [`../gooir-http`](../gooir-http) is the independently expressive native HTTP,
  Axum implementation, and Rust-source ecosystem with a two-hop neutral
  provider plan.
- [`../gooir-fleetd-direct-conversation`](../gooir-fleetd-direct-conversation)
  is the stateful Fleetd contract, two independent providers, attester,
  package proof, and crash-recoverable external host proof.

They depend on this repository through public crates. This repository has no
dependency back to any of them. The data-model and Fleetd conversation
ecosystems moved out during subtraction; the HTTP ecosystem was authored
downstream afterward.

Earlier lifters, UI/control experiments, interaction-activation and activity
projection probes, and the representation corpus were superseded research.
They remain recoverable from Git history and the owner-only retirement archive;
they are no longer active package surface.

## Architectural boundary

[Architecture](docs/ARCHITECTURE.md) states the complete trusted boundary.
[Decision 0031](docs/DECISIONS/0031_MINIMAL_SEMANTIC_SUBSTRATE.md) records why
the substrate is finite. [Decision 0033](docs/DECISIONS/0033_SUBTRACT_AND_EXTRACT.md)
records the repository split. [Decision 0034](docs/DECISIONS/0034_V1_DERIVATION_FACADE.md)
defines the 0.1 product façade.

The short version:

- dialects own value kinds; facts are instances of exact value kinds;
- capabilities are exact named-port promises, not implementations;
- packages offer implementations but never choose them;
- linking is explicit and content-bound;
- conformance and admission remain distinct;
- a derivation ends as `Produced`, `Blocked`, `Unreachable`, `Refused`, or
  `Failed`, without collapsing their remedies;
- unknown and incompatible claims fail closed;
- GOOIR emits neutral documents; an external host performs effects.

## Qualify

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
