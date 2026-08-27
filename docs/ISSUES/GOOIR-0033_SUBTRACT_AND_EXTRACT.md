# GOOIR-0033 — Subtract the kernel and extract proven ecosystems

Status: complete

Origin: owner request in the Codex task that recovered GOOIR and its Fleetd
proof. Buzz and its originating channel service have been retired, so this
issue is the durable local authority under the existing Buzz-retirement
exception.

## Problem

GOOIR proved more than one useful boundary, but accumulated its kernel, two
real provider ecosystems, and several superseded research probes in one Cargo
workspace. That makes the kernel appear to know data models, Fleetd, Buzz,
interaction frameworks, and UI projection even though those concepts are not
part of its semantic substrate.

The compiled dependency graph also makes the `gooir` command install the data
model pack implicitly. An empty GOOIR installation therefore is not empty.

## Decision

Keep only the domain-neutral semantic substrate and host SDKs in this
repository. Extract the proven data-model and Fleetd direct-conversation
families as ordinary downstream consumers. Remove superseded probes from the
active tree; Git history and the owner-only retirement archive preserve them.

The retained kernel is:

- `gooir-identity`
- `gooir-capability`
- `gooir-package`
- `gooir-planning`
- `gooir-doctor`

The retained neutral host surface is:

- `gooir-plugin-process`
- `gooir-wasip1-command-runtime`
- `gooir-provider`
- `lift-defeasible`
- `gooir-cli`, with only explicitly named capability manifests and providers

The extracted ecosystems are:

- `gooir-datamodel`: the data-model contract, lifters, lowerings, providers,
  fixtures, and package/host proofs
- `gooir-fleetd-direct-conversation`: the Fleetd contract, two independent
  providers, attester, package proof, and recoverable external-host proof

Everything else is historical research, not an active product surface.

## Acceptance

- The GOOIR workspace contains only the retained neutral crates.
- The core CLI has no dependency on a domain pack and loads capability
  declarations only from explicit `--pack` paths.
- Both extracted repositories compile and test against GOOIR's public crates;
  GOOIR has no reverse dependency on either consumer.
- Active documentation names the finite kernel and the ecosystem boundary
  without presenting retired experiments as current architecture.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D
  warnings`, and `cargo test --workspace` pass in all three repositories.
- Before local integration, an agent other than the author approves the exact
  GOOIR commit. Local integration replaces a Buzz PR because the service is
  retired and no Git remote exists.
- The final report records file, source-line, package, binary, and test counts
  before and after extraction.

## Result

- GOOIR now has 10 packages and no dependency outside its own repository.
- The data-model ecosystem is a clean 15-package repository at
  `6d49425b1a32777f4420764ec79c70da26dafc93`.
- The Fleetd direct-conversation proof is a clean 7-package repository at
  `bfb03de93a914ea5d6bbec2709b5d1b8e2b42df5`.
- Fifteen superseded research packages and their corpora were retired rather
  than promoted into new products.
- The core CLI reports zero capabilities without explicit installation and
  consumes the extracted data-model `pack.json` through `--pack`.
- Format, clippy, and workspace tests pass in all three repositories.
