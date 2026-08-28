# 0042 — A managed admitted-artifact SDK outside the semantic kernel

Status: accepted by GOOIR-0042

## Context

GOOIR already composes ordinary capabilities through planning, invocation,
independent conformance, and contextual admission. External repositories can
therefore provide data-model, HTTP, Rust, SQL, OpenAPI, CLI, MCP, and future
generators without a `Backend` role in the kernel. The remaining repeated work
begins after a generated fact is admitted: safely turning exact bytes into a
repeatable physical directory.

The earlier FileTree/materializer experiment correctly separated pure artifact
data, admission, and host effects. It was not a useful product loop because it
published only into an absent destination. It also spread the first slice
across several crates before ownership, checking, replacement, and receipts
were established.

## Decision

`gooir-artifact-sdk` is optional and depends on the authority and package
protocols; no kernel crate depends on it. It owns one separately versioned,
offer-free `ContentSet` contract, one generic ledger-resolved `Admitted<T>`
gate, and one local managed-output host.

`ContentSet` contains only canonical relative paths and bytes. It contains no
destination, mode, overwrite instruction, generator identity, or backend noun.
Unknown extension data is preserved as data and refused by the initial local
publisher, rather than silently discarded or interpreted as safe.

`Admitted<T>` has no public constructor. It can be obtained only by resolving
an exact fact-and-authority pair through `AdmissionLedger`, checking the exact
contract kind, validating the content identity, decoding, and running the
contract validator. Publication therefore never treats generated-but-unadmitted
data as host write authority.

A `ManagedOutput` binds an explicit versioned owner identity to one dedicated
directory. Its marker binds that owner, the exact admitted reference, and each
file path, digest, and length. Inspection refuses malformed markers, symlinks,
unsupported entries, wrong ownership, and drift. `check` and `diff` are
read-only. `publish` creates a missing directory, returns unchanged for the
same clean manifest, or stages a complete new tree and atomically exchanges it
with a changed clean tree. Stale files disappear with the retired tree.

Publication distinguishes the commit boundary. A precommit failure is an
ordinary error and private staging is cleaned where possible. Once no-replace
rename or directory exchange succeeds, the method returns a receipt. Parent
sync failure and retired-tree cleanup failure become explicit receipt states;
they are not retryable-looking errors that obscure a committed tree.

The implementation is limited to macOS and Linux local filesystems that
support atomic directory exchange. A descriptor opened on the immediate parent
receives a cooperative `flock`, and atomic renames are relative to that parent.
The lock coordinates SDK users; it cannot constrain a malicious or privileged
non-cooperating process. Callers must control the non-symlink parent. A
completed directory sync is reported exactly as such, not upgraded into a
portable claim of power-loss durability.

## Consequences

An external ecosystem can now express generation as an ordinary provider that
returns `ContentSet`, run it through the existing compiler/admission spine, and
hand the exact admitted reference to a small reusable publisher. Concrete
backends remain independently versioned repositories. The same machinery works
for any bounded tree of bytes without naming Rust, SQL, HTTP, OpenAPI, CLI, MCP,
or a future target in GOOIR.

Managed publication deliberately replaces the complete dedicated output. It
does not merge generated files into a user-owned tree. A future brownfield
synchronization product would need explicit trace/conflict semantics and can be
modeled with ordinary observe/revise capabilities; it is not implied by this
SDK.

## Rejected alternatives

### Add a `Backend` or `Materialize` capability kind

Generation is already an ordinary capability role. Physical publication is a
host effect over an admitted value. A second edge kind would duplicate the
existing plan/invoke/assess/admit machinery without removing any filesystem
work.

### Make every backend implement publication

That repeats security-sensitive ownership, drift, atomicity, and receipt code
for each target. The target-specific part ends at `ContentSet`; the local host
mechanics are shared.

### Use a lens as the primary abstraction

Current consumers demonstrate one-way generation and often lossy lowering.
They do not establish bidirectional round-trip laws. A lens would hide conflict
and authority choices that need to remain explicit.

### Keep refuse-existing publication

Create-only publication is appropriate for immutable toolchain deployment,
not for a generate/check/regenerate product loop. Dedicated managed outputs
need checked, owner-fenced, whole-tree replacement.
