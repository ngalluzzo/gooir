# GOOIR

GOOIR is a lift-first semantic compiler workbench for existing software.

It imports facts from authoritative tools and formats, preserves their distinctions and unknown regions, links those facts through separately versioned semantic contracts, and runs analyses that no individual tool can perform alone. Generation and lowering are later projections, not prerequisites for value.

```text
existing semantic artifacts
          ↓ lift
native, lossless dialects
          ↓ explicit bridge
versioned semantic contracts
          ↓ link + analyze
scoped, provenance-bearing findings
          ↓ optional lowering
existing generators and runtimes
```

The microkernel does not know `page`, `entity`, `retry`, React, Postgres, or Buzz event kinds. It knows only structural IR, exact contract identities, evidence/provenance transport, opaque extension data, pass mechanics, legality, artifacts, and diagnostics.

## Current milestone

`GOOIR-000` is merged and proves the architectural boundary:

- unknown dialect data round-trips without a plugin;
- analyzers consume exact semantic contracts rather than dialect names;
- unfamiliar dialects with equivalent projections produce equivalent normalized results;
- unverified or unknown claims never become safety facts;
- meaning-changing contract versions require an explicit bridge.
- partial legality reports the exact pinned/unknown portability frontier.

`GOOIR-001` now has source-derived protocol, relay, and CLI lifts plus a generic contract-only completeness analyzer. Exact local admission produces six relay-ingest contradictions and one exhaustive CLI gap; SDK and runtime absences remain unknown until their coverage-witnessed lifters land. The hand-authored staging snapshot stays outside the trusted path.

Run the first real-software product slice from a clean checkout:

```bash
cargo run -q -p buzz-surface-check
```

The one-screen default view marks the behavior `BROKEN`, follows one Buzz agent-job event from declaration through production, relay acceptance, and runtime consumption, explains the impact and next action, and names the boundaries that remain unknown. Use `--details` for exact evidence or `--json` for the complete machine-readable report. See the [ten-minute Slice 1 demo](docs/SLICE_1_DEMO.md) for the evidence-mutation trust check and product gate.

See the [project brief](docs/PROJECT_BRIEF.md), [architecture](docs/ARCHITECTURE.md), and [milestones](docs/MILESTONES.md).

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

See [decision 0011](docs/DECISIONS/0011_CAPABILITIES_AS_TYPED_DERIVATIONS.md).
See also [decision 0012](docs/DECISIONS/0012_CANDIDATES_REQUIRE_INDEPENDENT_CONFORMANCE.md).
See also [decision 0013](docs/DECISIONS/0013_RUNNABLE_WEB_ARTIFACT_CONFORMANCE.md).

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
