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
| `gooir-derive` | five-outcome derivation façade and external-host admission membrane |
| `gooir-doctor` | diagnostics over an installed capability graph |

The repository also contains narrow, optional support:

| Crate | Status |
| --- | --- |
| `gooir-cli` | neutral graph inspection and a legacy local execution adapter |
| `gooir-provider` | experimental neutral v1 provider-authoring SDK plus legacy in-process adapter; not trusted kernel |
| `gooir-plugin-process` | transitional process-provider adapter; host-side, not a universal ABI |
| `gooir-wasip1-command-runtime` | bounded WASI command runner for hosts |
| `lift-defeasible` | reusable value-plus-defeaters representation |

Nothing domain-specific is installed by default. The CLI receives exact
package directories explicitly, in dependency order:

```sh
cargo run -q --bin gooir -- capabilities --package /path/to/package
cargo run -q --bin gooir -- doctor --package /path/to/package
cargo run -q --bin gooir -- plan org.example/result@1.0.0 --package /path/to/package
```

Planning displays the complete provider-neutral graph and exact offers. It
does not choose or execute them. The temporary `derive --pack ... --plugin ...`
command is explicitly a legacy compatibility bridge; it is not the 0.1 host
boundary or a universal provider transport. GOOIR never scans for executable
code.

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
the complete envelope to providers that understand them. This surface remains
experimental until two independent downstream consumers exercise it.

## What moved out

Two bodies of work survived the subtraction because they proved real consumer
boundaries:

- [`../gooir-datamodel`](../gooir-datamodel) is the data-model contract,
  provider pack, transformations, fixtures, and package/host proofs.
- [`../gooir-fleetd-direct-conversation`](../gooir-fleetd-direct-conversation)
  is the stateful Fleetd contract, two independent providers, attester,
  package proof, and crash-recoverable external host proof.

They depend on this repository through public crates. This repository has no
dependency back to either one.

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
