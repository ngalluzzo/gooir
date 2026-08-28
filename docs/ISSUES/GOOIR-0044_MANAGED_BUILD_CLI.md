# GOOIR-0044 — Build and materialize one exact toolchain output

Status: complete

Origin: owner request for the smallest usable SDK path from one or two source
specifications to admitted generated artifacts, without per-dialect CLIs.

## Problem

The repository separately exposes installed toolchain loading, bounded local
execution, exact-output compilation, admission, and safe `ContentSet`
publication. A consumer must still hand-compose those APIs. That makes the
backend-neutral product path difficult to find and easy to get wrong even
though no new semantic protocol is required.

## Scope

- Add one generic `gooir build` command over an explicit installed toolchain
  image and exact capability/output coordinate.
- Admit one caller-supplied source `ContentSet` assembled from repeatable,
  bounded, no-follow regular files, plus optional existing source-observation
  documents.
- Require an explicit source authority and admission policy; do not claim that
  the CLI measured or executed the named observer.
- Preflight that the installed exact output exists and is the portable
  `ContentSet` contract before any provider effect.
- Use the existing `InstalledToolchain`, `LocalStdioHost`, `CompilerDriver`,
  admission ledger, `Admitted<ContentSet>`, `ManagedOutput`, and
  `LocalPublisher` APIs.
- Publish only a produced and admitted exact target into one explicit managed
  output directory.

## Acceptance

- One command can take one or two binary-safe source files through an installed
  external generator and publish its admitted `ContentSet`.
- The target is an exact capability and named output port; no shared carrier
  kind or backend is inferred.
- Source and JSON document reads are bounded and reject symlinks, FIFOs, and
  directories. Source content paths are portable and deterministic.
- Unknown target, non-`ContentSet` target, source-authority mismatch, policy
  refusal, ambiguous route, missing provider/attester, failed conformance, and
  output conflicts stop before unsafe publication.
- The command does not define a backend registry, recipe format, workflow,
  dialect parser, or target-specific materializer.

## Non-goals

- No per-dialect CLI or source syntax parser.
- No ambient package, executable, attester, authority, or destination
  discovery.
- No assertion that an arbitrary authority document proves the CLI itself
  observed the supplied files.
- No incremental SQL migration, Rust compilation, route serving, or other
  target-specific effect.
