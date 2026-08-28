# 0040 — Expose the FileTree build host as an explicit local command

Status: accepted first physical product entrypoint

## Context

Decision 0039 establishes an in-process composition from `CompilerDriver` to an
authority-gated `FileTreeMaterializer`, but leaves it to product code to load
packages and authority inputs, select local execution, choose a destination,
and state publication policy. The existing `gooir compile` command already
owns the first half of that local product configuration, but intentionally
emits only a semantic derivation answer and accepts an arbitrary target.

Making materialization an optional compile flag would cause one command to
change effect class based on a trailing option. Accepting a caller-selected
target for physical build would also weaken the type-level FileTree boundary,
and serializing the local receipt would prematurely promise a portable build
protocol.

## Decision

`gooir build <destination>` is a separate command over
`FileTreeBuildDriver<LocalStdioHost, LocalFileTreeMaterializer>`. It shares only
the explicit package, policy, source-observation, attester-binding, and bounded
stdio inputs with `gooir compile`. It has no target argument: the build driver
fixes the target to `org.gooi.artifact.file_tree/tree@1.0.0`.

The caller must provide every local publication choice:

- an absent destination whose parent already exists;
- positive maximum files, directories, bytes per file, and aggregate bytes;
- ordinary Unix directory and file modes; and
- the existing positive stdin, stdout, stderr, and deadline bounds.

Conflict policy is fixed to atomic no-replace. `Blocked` exits with the
existing retryable status, while `Unreachable`, `Refused`, and `Failed` retain
their existing failure status and remedy. None invokes the materializer. An
artifact-gate or materializer error reports the exact admitted fact and
authority retained by the build error.

Physical success prints human-readable host evidence: fact and authority
identities, destination, exact file paths/digests/sizes, modes, and durability.
There is deliberately no `--json` mode because
`LocalMaterializationReceipt` is non-serializable, in-process evidence rather
than a stable semantic or effect protocol.

## Scope and tradeoffs

The command executes provider and attester artifacts with the caller's OS
authority and then writes beneath a caller-selected parent. Explicit package
loading, content binding, admission, no-follow staging, and no-replace publish
reduce ambiguity and substitution; they do not sandbox child processes or
authenticate the surrounding namespace and principal.

This command adds no build dialect, generic effect declaration, overwrite or
merge mode, deletion behavior, durable journal, retry loop, or crash recovery.
An uncertain post-publish durability receipt is still success and explicitly
warns against retrying as if publication failed.

## Acceptance evidence

- A subprocess test loads one exact package, executes its copied provider and
  independent attester, admits the generated FileTree, and creates exact text
  and binary files with the requested modes.
- Repeating the same command refuses the existing destination without changing
  its files and reports the retained admitted product.
- Missing attester availability returns `Blocked` and creates no destination.
- An unknown extension in reachable source authority fails before publication
  while retaining the admitted fact identity.
- Grammar tests require all limits and modes, reject duplicates and unknown
  flags, and confirm that `--json` is unavailable.
