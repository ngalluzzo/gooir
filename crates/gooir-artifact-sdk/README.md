# gooir-artifact-sdk

Optional host SDK for publishing an exact admitted artifact into one dedicated
managed directory. This crate is outside GOOIR's semantic kernel and contains
no target-specific backend.

The pure contract is `org.gooi.artifact.content_set@1.0.0`, value kind
`org.gooi.artifact.content_set/set@1.0.0`. `ContentSet` is a canonical list of
portable relative paths and bytes; an empty list is valid. `package_manifest()`
returns its offer-free package declaration.

```rust
let set = ContentSet::new(vec![
    ContentFile::new("src/lib.rs", generated_rust)?,
    ContentFile::new("Cargo.toml", generated_manifest)?,
])?;

// A provider returns `set` as an ordinary fact. After independent assessment
// and admission, the caller retains `ledger` and the exact `reference`.
let artifact = Admitted::<ContentSet>::resolve(&ledger, &reference)?;
let output = ManagedOutput::new(
    ManagedOutputId::parse("example.rust-crate@1")?,
    "generated/rust",
)?;

let check = LocalPublisher::default().check(&artifact, &output)?;
let diff = LocalPublisher::default().diff(&artifact, &output)?;
let receipt = LocalPublisher::default().publish(&artifact, &output)?;
```

`Admitted<T>` has no public constructor. Resolution requires an exact
fact-authority pair in `AdmissionLedger`, the exact value kind, a valid fact
identity, successful decoding, and contract validation. Contract, file, fact,
or reference extensions survive serialization but the first local publisher
refuses them rather than silently dropping unknown meaning.

Publication is bounded and manages the complete directory. It creates a
missing output, returns `Unchanged` for identical clean content, or atomically
exchanges a changed clean output. The ownership marker binds the output owner,
exact admitted reference, and every file path, digest, and length. Unmanaged,
wrong-owner, drifted, ambiguous, and symlink-containing state is never
overwritten.

## Platform and threat model

The local publisher is available on macOS and Linux when the destination's
local filesystem supports atomic no-replace rename and atomic directory
exchange. Runtime lack of either operation is an explicit error before commit.

The publisher takes `flock` on the immediate parent directory, so cooperating
publishers serialize complete-tree inspection and replacement. It assumes the
caller controls that non-symlink parent. The lock is advisory and is not a
sandbox against a malicious, privileged, or non-cooperating process.

Errors are returned before the atomic commit. Once a rename commits, the method
returns a `PublicationReceipt`; parent-directory sync or retired-tree cleanup
problems are explicit `SyncStatus` and `CleanupStatus` values. A successful
directory sync is reported exactly as that, not as a universal guarantee of
power-loss durability across filesystems and hardware.
