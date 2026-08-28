# 0037 — File-tree artifact dialect without filesystem authority

Status: accepted first artifact-boundary slice

## Context

Two independent downstream ecosystems now produce collections of physical
source files. The native HTTP/Axum ecosystem has a target-specific
`RustSourceTree`; the data-model ecosystem produces Prisma and other textual
artifacts. Their semantic targets differ, but the final virtual artifact shape
recurs: portable relative paths paired with exact content.

Leaving that shape private forces every generator, product build driver, and
materializer to recreate path validation, collision handling, content
identity, and bounds. Moving filesystem writes into the kernel would solve a
different problem by granting effects to code that currently reasons only
about semantic values and authority.

## Decision

`gooir-file-tree-v1` owns the separately versioned
`org.gooi.artifact.file_tree@1.0.0` dialect and its one `tree` value kind. It is
optional support. The identity, capability, package, planning, derivation, and
provider crates do not depend on it.

A file-tree value contains a non-empty canonical sequence of:

- bounded portable relative paths;
- bounded exact file bytes using canonical padded Base64 on the JSON wire,
  including non-UTF-8 content;
- bounded media-type declarations;
- a lowercase SHA-256 digest for every file; and
- preserved extension data that cannot shadow known fields.

Validation rejects exact duplicates, ASCII-case aliases, file/directory
ancestor collisions including case aliases, unsafe path components, stale
digests, noncanonical ordering, and exceeded per-file or aggregate limits. The
checked-in package declaration exports only the value kind. It declares no
capabilities, implementation offers, resources, or conformance attesters.

A domain package may declare an ordinary semantic capability whose output is
this exact file-tree kind. A richer target-specific artifact, such as a Rust
source tree, remains independently governed; converting it to the generic kind
is an explicit capability when the projection is useful. No relationship is
inferred merely because two values contain files.

The file tree does not contain an output root, absolute path, filesystem
handle, permissions, overwrite or deletion policy, observed filesystem state,
write status, or receipt. Those coordinates belong to a product host. A future
materializer must receive an exact admitted file-tree authority, revalidate the
payload, apply caller-selected destination and conflict policy, perform the
effect, and return host evidence. A product build driver may compose semantic
derivation with that host operation, but `CompilerDriver` and the capability
graph do not treat `build` or `materialize` as semantic capabilities.

## Consequences

Generators can share a deterministic final artifact boundary without sharing
their source dialects or granting filesystem access. Materializers can be
implemented once per host environment and can refuse ambiguous trees before a
write begins. Build orchestration must make its trust dependency explicit by
resolving an admitted authority record rather than accepting a bare provider
candidate or unvalidated payload.

This does not standardize a generic effect dialect, an effect system, a build
receipt, or host policy. It also does not automatically replace richer
artifact dialects: information absent from `FileTree` is intentionally lost by
projection. The next slice is a host-side materialization protocol and bounded
local implementation, not a kernel dependency on this dialect.

## Acceptance evidence

- Constructors derive per-file content identities and canonicalize tree order.
- Validation rejects traversal, absolute and Windows-style paths, reserved
  device names, exact and portable collisions, ancestor collisions, stale
  digests, reserved extension shadows, and bounded-resource violations.
- Arbitrary byte content and unknown extension data survive serialization.
- The checked-in package manifest equals its semantic builder and exports one
  value kind with no capabilities or implementation offers.
