# GOOIR-0041 — Extract the external ecosystem toolchain-image SDK

Status: complete

Origin: owner request to make GOOIR useful to independently maintained backend
repositories without moving those backends into GOOIR.

## Problem

`gooir-provider::neutral`, `gooir-provider::attester`, and
`gooir-derive::CompilerDriver` already provide the typed provider, independent
assessment, and complete derivation spine. They do not give an external
ecosystem one reusable way to turn its final provider and attester artifacts
into an exact installed toolchain.

The HTTP acceptance proof consequently measures four binaries, reconstructs a
deployment manifest and offers, stages resources, reloads the package, and
constructs attester authorities and local bindings inside its compiler-spine
test. The data-model ecosystem independently implements the same concerns as a
large package-proof product with its own deployment lock. This is recurring
host machinery, not HTTP or data-model meaning.

Adding a `Backend` protocol or another wrapper over `Provider` would not remove
that duplication. Concrete Rust, SQL, OpenAPI, HTTP, CLI, and MCP backends must
remain in independently versioned downstream repositories.

## Scope

Add one optional `gooir-toolchain` SDK crate that:

- accepts package recipes derived from exact offer-free package manifests;
- measures caller-supplied final resource bytes instead of accepting claimed
  sizes or digests;
- turns explicit provider bindings into ordinary package implementation
  offers;
- retains attester artifact bindings only in a host-owned toolchain lock;
- stages resources before manifests in private sibling storage;
- independently reloads every staged package through `load_local_package`;
- derives and verifies package, offer, resource, and attester coordinates from
  the copied bytes;
- enforces per-package and image-wide resource and manifest byte budgets;
- atomically publishes one complete, create-only toolchain image; and
- reloads that image into an immutable `PackageRegistry` plus exact local
  attester bindings suitable for `LocalStdioHost`.

The lock is deployment data, not a semantic package, selection directive,
admission decision, or compile receipt. Loading it never chooses among provider
offers.

## Non-goals

- No concrete backend, target profile, artifact vocabulary, or convention.
- No new kernel identity or edge kind named `Backend`.
- No provider or attester code generation.
- No executable discovery, Cargo invocation, `PATH` lookup, or dependency
  solving.
- No product-output materialization. Managed admitted-artifact publication is
  a separate follow-up issue with a different conflict and recovery lifecycle.
- No lens abstraction. Existing consumers demonstrate lossy normalization and
  one-way generation, not bidirectional update laws.

## Acceptance

- Resource sizes and digests in the published image come only from bytes read
  under explicit limits.
- Provider offers resolve to the exact copied resource bytes from which their
  artifact digests were derived.
- Attester bindings resolve to exact copied resources and remain outside
  package implementation offers.
- Provider and attester implementation/artifact identity independence is
  checked globally before an installed toolchain is returned.
- Provider-offer, attester, authority, resource, and base-manifest extensions
  are preserved and revalidated through their authoritative constructors.
- No ordinary error is returned after atomic publication commits; a failed
  parent-directory sync is a committed publication with uncertain durability.
- A fresh loader can reconstruct the registry and attester inventory using
  only the published image.
- Changed resource bytes, package manifests, lock package coordinates, lock
  resource coordinates, unsafe paths, duplicate bindings, and a pre-existing
  output root are refused.
- HTTP's acceptance proof can delete its local artifact hashing, deployment
  manifest augmentation, loading loop, and attester-binding construction while
  preserving its admitted two-hop result.
- The data-model package proof can be expressed as toolchain recipes and retain
  its mutation and independence checks.
- GOOIR, HTTP, and data-model qualification commands pass against the exact
  reviewed revisions.
