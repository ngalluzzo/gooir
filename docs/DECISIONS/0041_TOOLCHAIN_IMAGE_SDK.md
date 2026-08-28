# 0041 — A host-owned toolchain-image SDK for external ecosystems

Status: proposed by GOOIR-0041

## Context

The neutral provider SDK makes a capability implementation one typed function.
The attester SDK supplies the corresponding closed independent-assessment seam.
The compiler driver supplies source admission and the complete
plan/link/invoke/assess/admit composition. None of those surfaces should know
that a provider happens to play a frontend, bridge, analysis, lowering,
generation, or backend role.

Two unrelated downstream repositories nevertheless reproduce the machinery
between final executable artifacts and those existing SDKs. They measure
resources, construct deployment packages and offers, publish package trees,
reload them, bind independent attesters, and retain host-local deployment
coordinates. That repetition is the demonstrated SDK gap.

## Decision

`gooir-toolchain` is optional host support over `gooir-package` and
`gooir-derive`. The identity, capability, package, planning, and derivation
protocols do not depend on it.

A `ToolchainImageBuilder` receives an ordered collection of exact
`PackageRecipe` values. A recipe begins with a valid package manifest and may
add measured resources, provider bindings, and host attester bindings. Resource
inputs are explicit final files or bytes. The builder does not run Cargo,
resolve `PATH`, scan a directory, fetch dependencies, or compile anything.

Provider bindings augment the recipe's manifest with ordinary
`ImplementationOfferDeclaration` values. Availability therefore continues to
enter the semantic planner only through installed package offers. Attester
bindings never become package offers. After resource measurement they become
complete `ConformanceAuthority` values and exact package/resource coordinates
in a separately versioned `ToolchainLock`.

The builder writes resources before the manifest, validates the complete image
by independently loading and installing its packages in declared order, writes
the resulting lock, synchronizes private sibling staging, and publishes only by
atomic create. Existing output is never replaced by this first slice.

`InstalledToolchain::load` treats the lock and package directories as untrusted.
It reloads packages through `load_local_package`, requires each exact package
identity and digest from the lock, resolves each attester resource from the
installed registry, reconstructs and validates the complete authority, checks
every attester implementation and artifact digest for global independence from
every provider offer, and returns an immutable registry plus host bindings. It
performs no provider selection and no execution.

Package and lock reads remain subject to per-document limits plus image-wide
resource and manifest byte budgets. Each package load is capped to the
remaining image budget before its files are read.

Create-only publication distinguishes its commit boundary. Errors are returned
only before the atomic no-replace rename. After that rename,
`ToolchainPublication` reports whether parent-directory synchronization
completed or durability is uncertain; it never presents a committed image as a
retryable ordinary failure. The image has already been independently loaded
from staging before commit, so no fallible verification step follows rename.

## Consequences

External backend repositories retain all target meaning and implementation
code while sharing the artifact-to-installed-toolchain path. Products may bind
the returned inventory to `LocalStdioHost` and `CompilerDriver` without
reconstructing deployment claims.

The lock is serializable host configuration. It is not a fact, capability,
package, admission record, compile request, or claim that its artifacts are
safe to execute. Package validation establishes exact availability;
independent conformance and contextual admission remain later operations.

This decision does not solve physical publication of generated artifacts. A
later optional artifact SDK may define an admitted portable content set and a
managed-output publisher, but it must be driven by a real downstream generator
and must support repeatable checked replacement rather than one-shot
`RefuseExisting` publication.

## Rejected alternatives

### Add a `Backend` abstraction over `Provider`

The existing provider SDK already owns typed named ports, inability, extension
handling, and neutral framing. Renaming that surface deletes no downstream
machinery and would contradict the one-edge architecture.

### Put attester availability into package offers

An attester is host-selected independent authority, not an implementation
alternative for the capability. The lock records exact deployability without
changing semantic planning.

### Hide package installation behind target-specific build commands

That would reproduce the same assembly separately for every external backend
and make target names enter GOOIR. Toolchain construction remains target
agnostic and explicit.

### Add lenses to the SDK now

The current data-model conversions are deliberately lossy normalizations and
HTTP generation is intentionally one-way. A future brownfield synchronization
consumer can express observe/revise as ordinary capabilities with an explicit
trace fact and law suite; no current SDK duplication requires that abstraction.
