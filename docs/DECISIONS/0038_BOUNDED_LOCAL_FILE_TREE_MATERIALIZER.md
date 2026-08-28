# 0038 — Bounded local FileTree materialization after admission

Status: accepted first physical-artifact host

## Context

Decision 0037 established a FileTree as a pure semantic artifact: exact bytes
at portable relative paths, without a destination or write authority. A usable
product must eventually create physical files, but treating that effect as a
semantic capability would let graph reachability stand in for filesystem
authorization. Accepting a bare provider result would similarly bypass the
existing conformance and admission membrane.

Physical publication also has failure modes absent from the semantic value:
symlink traversal, pre-existing destinations, partial trees, host resource
exhaustion, permission policy, crashes, and the ambiguity created when an
effect succeeds just before reporting fails.

## Decision

`gooir-file-tree-materializer` is an optional host library. No identity,
capability, package, planning, derivation, or provider crate depends on it. Its
`FileTreeMaterializer` trait is an orchestration seam and never enters the
semantic capability graph.

`AdmittedFileTree` can be constructed publicly only by supplying an
`AdmissionLedger` and exact `AdmittedFactRef`; it resolves the reference
internally, so a publicly assembled `ResolvedFact` cannot bypass ledger
membership. The host remains responsible for authenticating and selecting the
ledger itself. Construction revalidates the complete authority record, requires
the exact `org.gooi.artifact.file_tree/tree@1.0.0` value kind, decodes and
validates the payload through borrowed, bounded deserialization, and requires
equality between the resolved fact and the fact bound into the authority.
Per-file Base64 length plus file-count and aggregate decoded-byte limits are
enforced while decoding rather than after an unbounded clone. Because this
materializer has no extension semantics, it rejects every extension in the
selected reference, complete authority chain, fact, tree, and file instead of
silently ignoring one.

The first `LocalFileTreeMaterializer` requires all of the following before its
first filesystem mutation:

- a nonzero maximum file count, directory count, per-file byte count, and
  aggregate byte count;
- ordinary Unix file and directory modes, with owner read/write/execute kept
  on directories so bounded cleanup remains possible;
- an existing real destination parent opened no-follow; and
- the sole conflict policy `RefuseExisting`.

The local host reserves a 128-bit random private staging-directory name in the
destination parent. Every subdirectory and file is created relative to
retained descriptors with no-follow and exclusive-create flags. Exact bytes
are written, modes applied, and file and directory descriptors synchronized
before publication. One same-parent atomic no-replace rename is the commit
point. An existing file, directory, or symlink at the destination is never
followed, merged, replaced, or deleted. Pre-commit failure triggers bounded
best-effort removal of only the entries this attempt created; failure of that
cleanup is reported explicitly.

A successful rename always returns a `LocalMaterializationReceipt` bound to the
exact authority record, fact, destination, policy, and file digests. Parent
directory synchronization after the rename cannot turn into an ordinary error:
the receipt instead says either `ParentDirectorySynced` or `Uncertain`. This
prevents a caller from retrying as though publication did not occur. The
receipt is non-constructible, in-process host evidence. It is deliberately not
a stable serialized protocol or semantic fact.

## Scope and tradeoffs

The caller remains responsible for the origin and concurrent control of the
destination's ancestor namespace. The final parent itself is opened no-follow,
and all staging traversal is descriptor-relative, but this slice does not
claim a sandbox against another principal already able to rename ancestor
directories.

This version cannot overwrite, merge, delete, or update an existing tree. It
does not infer a safe replacement merely because a prior receipt exists. A
crash can leave a private staging directory, or can publish the destination
after the commit point without returning its receipt. Durable attempt journals,
startup reconciliation, ownership markers, and controlled replacement belong
to a product build host with explicit policy.

The fixed contract is for local Unix-style filesystems supported by the
descriptor and no-replace primitives used here. It does not make this adapter
a universal filesystem ABI and does not move build orchestration into GOOIR's
kernel.

## Acceptance evidence

- A ledger-admitted FileTree publishes exact text and non-UTF-8 bytes with the
  requested modes and an authority-bound receipt.
- Wrong value kinds, mismatched admitted references, and unhandled semantic
  extensions fail before materialization.
- A forged reference or an extension-qualified reference or authority chain
  cannot cross the public admission gate.
- Host resource limits fail before a destination or staging directory exists.
- Existing directory and symlink destinations are unchanged and staging is
  removed after atomic no-replace refusal.
- A symlink used as the immediate destination parent is refused and receives
  no files.
- Unsafe permission modes are refused before filesystem effects.
- Fault injection proves staging-open and partial-population cleanup failures
  are reported, while a post-publish parent-sync failure returns an
  `Uncertain` receipt instead of an ordinary retryable error.
