# GOOIR-0042 — Publish admitted artifacts as repeatable managed outputs

Status: complete

Origin: owner request for the small reusable SDK between external generators
and usable Rust, SQL, OpenAPI, HTTP, CLI, MCP, or other product artifacts.

## Problem

The compiler spine can derive and admit a generated value, but every external
ecosystem would otherwise have to invent content paths, admission gates,
ownership markers, drift checks, whole-tree replacement, and receipts. The
retired FileTree experiment exposed a host boundary but was one-shot: its
refuse-existing output could not support an ordinary edit/generate/check loop.

This is shared effect-boundary machinery. It is not target semantics and does
not justify moving concrete backends into GOOIR.

## Scope

Add one optional `gooir-artifact-sdk` crate that:

- declares an offer-free `org.gooi.artifact.content_set@1.0.0` package and
  portable content-set value kind;
- preserves unknown contract extensions through serialization but refuses to
  publish them until the local publisher explicitly understands them;
- exposes typed artifact values only after exact `AdmissionLedger` resolution,
  exact-kind checking, fact validation, decoding, and contract validation;
- binds a caller-chosen `ManagedOutputId` to one dedicated local directory;
- checks and diffs the directory without mutation;
- creates a missing output, returns `Unchanged` for an identical clean output,
  or atomically exchanges a changed clean output and removes stale files;
- writes a canonical ownership manifest binding exact admitted authority plus
  every canonical path, digest, and length; and
- returns a canonical receipt that distinguishes commit outcome, parent sync,
  and retired-tree cleanup uncertainty.

## Operational boundary

The first publisher is available only on macOS and Linux and requires a local
filesystem supporting atomic no-replace rename and atomic directory exchange.
Its parent-directory `flock` coordinates cooperating publishers; it is not a
sandbox or defense against a malicious process controlling the parent. The
destination must therefore be a dedicated directory under a caller-controlled,
non-symlink parent. The SDK never follows symlinks inside the managed tree.

## Acceptance

- Empty and nonempty sets are valid; paths are portable, relative, canonical,
  collision-free, and cannot name the ownership marker.
- A forged reference, wrong value kind, malformed payload, and unsupported
  extension never yield publish authority.
- Missing, unmanaged, wrong-owner, clean, and drifted states remain distinct.
- `check` and `diff` perform no writes.
- Repeated identical publication is unchanged; changed clean publication is a
  whole-tree atomic replacement and removes obsolete files.
- Existing unmanaged, wrong-owner, or drifted data is unchanged on conflict.
- Symlink and bounded-resource cases fail closed.
- Errors occur only before the atomic commit. Post-commit sync and cleanup
  uncertainty is represented in the returned receipt.
- Concurrent cooperating publishers expose a complete old or complete new
  tree, never a partially populated destination.
- GOOIR and the HTTP three-hop generation/materialization proof qualify.

## Non-goals

- No concrete generator, backend, target profile, formatting convention, or
  build invocation.
- No `Backend`, `Materialize`, lowering, lifting, or lens kernel abstraction.
- No recursive merge into a user-owned source tree.
- No Windows publisher in the first slice.
- No claim that directory `fsync` proves power-loss durability on every local
  filesystem or hardware stack.
