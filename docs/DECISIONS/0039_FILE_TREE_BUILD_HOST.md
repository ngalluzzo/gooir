# 0039 — Compose admitted FileTree derivation and physical materialization in a product host

Status: accepted first build-host composition

## Context

Decision 0037 defines FileTree as a semantic value without filesystem
authority. Decision 0038 defines an authority-gated materializer without build
orchestration. The existing `CompilerDriver` can produce and admit an exact
FileTree but intentionally cannot choose a destination or write it.

Treating build as another capability would let graph reachability stand in for
host write authority. Calling the materializer on a provider result would
bypass independent conformance and admission. Simply connecting the existing
APIs also reveals one real semantic integration point: `CompilerDriver`
content-binds its complete selection identity into every linked invocation as
an authority extension, while the standalone materializer defaults to
rejecting every extension it does not understand.

## Decision

`gooir-file-tree-build` is a separate optional host crate. It owns an already
configured `CompilerDriver` and one explicit `FileTreeMaterializer`; neither
the semantic kernel nor either component depends back on the composition.

`FileTreeBuildDriver::build` performs one ordered operation:

1. ask `CompilerDriver` for the fixed FileTree target;
2. return `Blocked`, `Unreachable`, `Refused`, or `Failed` without calling the
   materializer;
3. for `Produced`, resolve its exact target through the same compiler ledger;
4. validate the complete reachable authority chain; and
5. call the selected materializer with the caller's destination and policy.

The build host implements one authority-extension semantic: at exact
implementation-selection scope, `org.gooi.derive.complete_selection_id` must be
a string equal to the returned `ProducedAnswer.selection_id`. All other
authority extensions are unhandled. FileTree fact, tree, and file extensions
remain unconditionally refused. The materializer's ordinary `resolve` API
continues to use a reject-all validator.

Physical success is
`Materialized { produced: ProducedAnswer, receipt: MaterializerReceipt }`.
Artifact-gate and materializer failures are host-local `Result` errors, not new
serialized semantic answers. Both retain the exact admitted `ProducedAnswer`
so diagnosis does not lose the semantic product that existed before the host
failure.

## Scope and tradeoffs

This slice adds no build dialect, build capability, generic effect system,
serialized build protocol, CLI command, retry loop, overwrite policy, journal,
or crash recovery. It cannot make a generic materializer's errors retry-safe;
callers must obey that implementation's documented commit and receipt
semantics. With the local materializer, an ordinary error remains precommit and
post-rename parent-sync failure returns an `Uncertain` success receipt.

Owning both compiler and materializer prevents accidental use of a different
ledger between semantic production and physical gating. It does not authenticate
the original package inventory, policy, ledger source, destination ancestry, or
OS principal; those remain surrounding-host responsibilities.

## Acceptance evidence

- One admitted generated FileTree creates exact physical text and binary files,
  and the semantic target agrees with the authority and fact in the local
  receipt.
- `Blocked`, `Unreachable`, `Refused`, and `Failed` never call the materializer.
- An unknown extension in reachable source authority fails before the
  materializer is called while retaining the admitted target.
- A materializer error retains the exact target that still resolves through the
  compiler ledger.
- The compiler's exact complete-selection extension is accepted only at its
  declared scope with the value bound to the produced selection identity.
