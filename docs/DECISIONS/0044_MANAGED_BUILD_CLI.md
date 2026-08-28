# 0044 — One reference build composition over installed toolchains

Status: accepted by GOOIR-0044

## Context

GOOIR already had every public component needed to produce usable artifacts:
an exact installed toolchain, bounded provider and attester execution, exact
capability-output compilation, admission-ledger resolution, a portable
`ContentSet`, and managed publication. Requiring every consumer to discover
that call sequence made the product path unnecessarily theoretical.

A value-kind-only target was insufficient because raw source bundles and many
unrelated generators can all use `ContentSet`. GOOIR-0043 added an exact
capability/output goal, retaining caller intent while leaving dependency route,
offer, input, and attester selection conservative.

Established build systems consistently retain an explicit terminal: MLIR
names passes and pipelines, protoc and Buf name plugins that emit portable file
responses, Smithy maps explicit plugin identifiers to artifact directories,
Bazel runs actions required by a requested label or output group, and Nix
derivations name outputs. That evidence supports an exact terminal and one
driver. It does not establish a need for another recipe language in GOOIR.

## Decision

`gooir build` is the reference local composition. Its two positional arguments
name an exact capability and output port. It loads one explicit
`InstalledToolchain`, constructs `LocalStdioHost`, calls
`CompilerDriver::compile_output`, resolves the produced reference as
`Admitted<ContentSet>` through that same driver's ledger, and calls
`LocalPublisher` for one explicit `ManagedOutput`.

Repeatable `--source PATH` inputs form one canonical source `ContentSet`. PATH
is both the local path and portable content path. Reads are bounded, binary
safe, regular-file-only, and no-follow. Each exact file is retained as raw
SHA-256 evidence under
`org.gooi.cli.evidence/raw-file-sha256@1.0.0`. The caller supplies one complete
`ObservationAuthority`; the admission policy must accept it exactly. The CLI
constructs an untrusted observation and does not claim it measured or executed
the observer named by that authority.

Before any provider effect, the command verifies that the installed exact
capability and port exist and declare the portable `ContentSet` output kind.
Only `Produced` proceeds through the private-constructor admitted-artifact gate.
Blocked, unreachable, refused, and failed answers retain their existing
remedies. Publication retains the SDK's owner fencing, drift refusal, atomic
replacement, and post-commit uncertainty receipt.

The command is not the SDK boundary. The Rust composition remains public so a
different host can substitute its own execution or policy. External backend
repositories ship ordinary provider and attester packages, not dialect-specific
GOOIR command-line programs.

## Consequences

One or two raw specifications can now reach an explicitly selected external
generator and a repeatable managed output without adding backend discovery.
The same `ContentSet` kind can remain both the source carrier and terminal
artifact carrier because the named capability output, not the kind, is the
requested graph root.

No recipe, workflow, source dialect, backend registry, filesystem effect edge,
or plugin configuration protocol is introduced. A future recursive source
directory option would be host-side bounded traversal, not new semantics.

## Prior-art references

- [MLIR pass infrastructure](https://mlir.llvm.org/docs/PassManagement/)
- [Protocol Buffers compiler plugins](https://protobuf.dev/reference/cpp/api-docs/google.protobuf.compiler.plugin/)
- [Buf code generation](https://buf.build/docs/generate/)
- [Smithy build projections and plugins](https://smithy.io/2.0/guides/smithy-build-json.html)
- [Bazel exact output requests](https://bazel.build/rules/faq#why-is-my-file-not-produced--my-action-never-executed)
- [Nix derivation outputs](https://releases.nixos.org/nix/nix-2.31.2/manual/store/derivation/outputs/index.html)
