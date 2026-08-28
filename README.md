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
| `gooir-cli` | reference bounded local `compile`/managed `build` compositions, neutral graph inspection, and a legacy execution adapter |
| `gooir-provider` | neutral v1 provider and attester authoring SDKs plus legacy in-process adapter; not trusted kernel |
| `gooir-plugin-process` | transitional process-provider adapter; host-side, not a universal ABI |
| `gooir-toolchain` | host SDK for measuring, staging, locking, and independently loading external provider/attester deployment images |
| `gooir-artifact-sdk` | admitted portable content-set contract and checked managed-directory publisher; target-neutral host support |
| `gooir-wasip1-command-runtime` | bounded WASI command runner for hosts |
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
one admission-policy JSON document, zero or more attester-binding documents, a target, and
mandatory positive stdin/stdout/stderr/time bounds. It admits the observations,
uses conservative complete selection, explicitly links each step, runs the
exact copied offer artifact over local stdio, and admits it through the
authority basis fixed by policy before linking a later step. An exact offer
explicitly accepted by policy needs no attester; every other offer requires an
accepted independent assessment. Run `gooir --help` for the complete invocation.

The in-memory compiler driver also accepts an exact capability/output-port
goal. That form is required for product generation when an input bundle and
multiple independent generators all use the same portable `ContentSet` kind:
the kind describes the carrier, while the capability output names what the
caller asked to run. Conservative route, offer, input, and authority-basis
selection still occurs beneath that named terminal.

An attester-binding document is local host configuration, not a package offer:

```json
{
  "authority": { "suite": "org.example.suite/exact@1.0.0", "attester": { "implementation": "org.example.attester/exact@1.0.0", "artifact_digest": "sha256:..." } },
  "package": "org.example.attesters@1.0.0",
  "resource": "exact-attester"
}
```

When assessment is required, the complete attester authority must be accepted
by policy, and its artifact digest must equal the copied installed resource
bytes. Direct provider authority likewise matches the complete installed
`CapabilityOffer`, including its measured artifact digest. Installation alone
does not add that offer to policy.

`gooir build` is the reference composition from raw portable files to a
managed admitted artifact. It takes an installed toolchain, an exact capability
and output port, explicit source authority and admission policy, one or more
binary-safe source paths, a managed-output identity and destination, and
mandatory process bounds. The named output must declare `ContentSet`; naming
the exact output prevents an input `ContentSet` or an unrelated generator with
the same carrier kind from satisfying the request.

```sh
gooir build org.example.rust/generate@1.0.0 files \
  --toolchain /opt/example-toolchain \
  --source specs/api.yaml \
  --source-authority source-authority.json \
  --policy admission-policy.json \
  --output generated/rust --output-id example.rust@1.0.0 \
  --stdin-bytes 16777216 --stdout-bytes 16777216 \
  --stderr-bytes 1048576 --timeout-ms 30000
```

This command adds no build-description protocol. It packages each explicitly
named source path and its exact bytes into one admitted `ContentSet`, then uses
the same public SDK composition available to any host:

```rust
let installed = InstalledToolchain::load(toolchain, ToolchainLimits::default())?;
let host = LocalStdioHost::new(
    installed.registry(),
    installed.local_attester_bindings().iter().cloned(),
    stdio_limits,
)?;
let authorities = host.authorities().cloned().collect::<Vec<_>>();
let mut compiler = CompilerDriver::new(
    installed.registry(), policy, authorities, host, derivation_limits,
)?;
if let Answer::Produced(produced) = compiler.compile_output(exact_output, observations) {
    let artifact = Admitted::<ContentSet>::resolve(compiler.ledger(), &produced.target)?;
    let receipt = LocalPublisher::default().publish(&artifact, &managed_output)?;
}
```

The CLI is only this reference host. Backend repositories ship independently
versioned provider packages and, when their threat model requires
per-candidate assessment, attester packages that can be assembled into a
toolchain image; they do not need per-dialect CLIs. Other hosts can use the
same Rust SDKs with their own execution and policy boundary.

External ecosystems do not need to recreate the deployment assembly.
`gooir-toolchain` accepts exact offer-free package manifests plus explicitly
named final provider resources and any required attester resources, measures
their bytes, derives ordinary provider offers, retains attesters only as host
bindings, publishes a create-only toolchain image, and independently reloads it into a package
registry and attester inventory. It never discovers or builds executables,
chooses a provider, or imports target meaning into GOOIR.

This bounded adapter executes selected artifacts with the caller's OS
privileges. It supplies no arguments or environment, performs no `PATH` lookup,
and kills and reaps a child that exceeds its deadline, but it is not a sandbox
or durable execution host. JSON output is the existing five-outcome derivation
answer, not a new stable compile receipt, and no target-specific file is
materialized. Planning remains separately inspectable and provider-neutral.
The temporary `derive --pack ... --plugin ...` command remains an explicitly
legacy compatibility bridge. GOOIR never scans for executable code.

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

## Publishing admitted artifacts

`gooir-artifact-sdk` is the optional, target-neutral bridge from an admitted
generated value to a usable local directory. External generators return the
offer-free `org.gooi.artifact.content_set/set@1.0.0` value kind through ordinary
capabilities. A host resolves the exact admitted fact-authority reference,
checks or diffs a dedicated managed output, and creates or atomically replaces
the complete directory:

```rust
let artifact = Admitted::<ContentSet>::resolve(&ledger, &reference)?;
let output = ManagedOutput::new(
    ManagedOutputId::parse("my-product.rust@1")?,
    "generated/rust",
)?;
let receipt = LocalPublisher::default().publish(&artifact, &output)?;
```

The SDK owns no Rust, SQL, OpenAPI, HTTP, CLI, MCP, or backend semantics. It
publishes only exact bounded bytes that already have authority. Existing
unmanaged, wrong-owner, drifted, or symlink-containing trees are refused before
mutation. Repeated identical publication is `Unchanged`; changed clean output
is a whole-tree atomic exchange that removes obsolete files.

The first local publisher supports macOS and Linux local filesystems with
atomic no-replace rename and directory exchange. Its parent lock coordinates
cooperating publishers and assumes the caller controls the non-symlink parent;
it is not a sandbox against a malicious process. Receipts explicitly preserve
post-commit directory-sync and retired-tree cleanup uncertainty.

## Downstream ecosystems

Three downstream repositories prove real consumer boundaries:

- [`../gooir-datamodel`](../gooir-datamodel) is the data-model contract,
  provider pack, transformations, fixtures, and package/host proofs.
- [`../gooir-http`](../gooir-http) is the independently expressive native HTTP,
  Axum implementation, and Rust-source ecosystem. Its current plan ends at a
  `RustSourceTree`; it does not yet prove `ContentSet` publication or managed
  materialization.
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
