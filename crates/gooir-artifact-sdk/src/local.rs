//! Local managed-directory publication implementation.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};

use gooir_capability::protocol::AdmittedFactRef;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{Admitted, ContentPath, ContentSet};

const MANIFEST_PROTOCOL: &str = "gooir-managed-output/1";
const RECEIPT_PROTOCOL: &str = "gooir-local-publication/1";

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ManagedOutputId(String);

impl ManagedOutputId {
    /// Parses an explicitly versioned managed-output identity.
    ///
    /// # Errors
    ///
    /// Returns [`ManagedOutputError::InvalidId`] when the value is not `name@version`.
    pub fn parse(value: impl Into<String>) -> Result<Self, ManagedOutputError> {
        let value = value.into();
        let Some((name, version)) = value.rsplit_once('@') else {
            return Err(ManagedOutputError::InvalidId(value));
        };
        if name.is_empty()
            || version.is_empty()
            || name.starts_with('.')
            || name.ends_with('.')
            || !name
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
            || !version
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || ".-+_".contains(character))
        {
            return Err(ManagedOutputError::InvalidId(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ManagedOutputId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedOutput {
    id: ManagedOutputId,
    destination: PathBuf,
    destination_text: String,
}

impl ManagedOutput {
    /// Binds one managed-output identity to one local destination.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, non-UTF-8, or lexically ambiguous destination.
    pub fn new(
        id: ManagedOutputId,
        destination: impl Into<PathBuf>,
    ) -> Result<Self, ManagedOutputError> {
        let destination = destination.into();
        validate_destination(&destination)?;
        let destination_text = destination
            .to_str()
            .ok_or_else(|| ManagedOutputError::NonUtf8Destination(destination.clone()))?
            .to_owned();
        Ok(Self {
            id,
            destination,
            destination_text,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &ManagedOutputId {
        &self.id
    }

    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagedOutputError {
    InvalidId(String),
    InvalidDestination(PathBuf),
    NonUtf8Destination(PathBuf),
}

impl fmt::Display for ManagedOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId(value) => write!(formatter, "invalid managed output id `{value}`"),
            Self::InvalidDestination(path) => {
                write!(
                    formatter,
                    "invalid managed output destination `{}`",
                    path.display()
                )
            }
            Self::NonUtf8Destination(path) => write!(
                formatter,
                "managed output destination `{}` is not portable UTF-8",
                path.display()
            ),
        }
    }
}

impl Error for ManagedOutputError {}

macro_rules! digest_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            fn from_bytes(bytes: &[u8]) -> Self {
                Self(format!("sha256:{:x}", Sha256::digest(bytes)))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

digest_id!(ContentDigest);
digest_id!(ManifestId);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicationReceiptId(String);

impl PublicationReceiptId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PublicationReceiptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedFile {
    pub path: ContentPath,
    pub digest: ContentDigest,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipManifest {
    pub protocol: String,
    pub manifest_id: ManifestId,
    pub output_id: ManagedOutputId,
    pub source: AdmittedFactRef,
    pub files: Vec<ManagedFile>,
}

impl OwnershipManifest {
    fn new(output: &ManagedOutput, artifact: &Admitted<ContentSet>) -> Result<Self, PublishError> {
        let files: Vec<ManagedFile> = artifact
            .value()
            .files
            .iter()
            .map(|file| ManagedFile {
                path: file.path.clone(),
                digest: ContentDigest::from_bytes(&file.content),
                bytes: u64::try_from(file.content.len()).unwrap_or(u64::MAX),
            })
            .collect();
        let unsigned = UnsignedManifest {
            protocol: MANIFEST_PROTOCOL,
            output_id: output.id(),
            source: artifact.reference(),
            files: &files,
        };
        let manifest_id = ManifestId::from_bytes(&canonical_json(&unsigned)?);
        Ok(Self {
            protocol: MANIFEST_PROTOCOL.to_owned(),
            manifest_id,
            output_id: output.id().clone(),
            source: artifact.reference().clone(),
            files,
        })
    }

    /// Validates the protocol, canonical ordering, and content-derived identity.
    ///
    /// # Errors
    ///
    /// Returns [`PublishError::InvalidManifest`] when any invariant fails.
    pub fn validate(&self) -> Result<(), PublishError> {
        if self.protocol != MANIFEST_PROTOCOL {
            return Err(PublishError::InvalidManifest(
                "unsupported protocol".to_owned(),
            ));
        }
        ManagedOutputId::parse(self.output_id.to_string())
            .map_err(|error| PublishError::InvalidManifest(error.to_string()))?;
        self.source
            .validate()
            .map_err(|error| PublishError::InvalidManifest(error.to_string()))?;
        if self
            .files
            .iter()
            .any(|file| !is_sha256(file.digest.as_str()))
        {
            return Err(PublishError::InvalidManifest(
                "file digest is not an exact lowercase SHA-256 identity".to_owned(),
            ));
        }
        let unsigned = UnsignedManifest {
            protocol: &self.protocol,
            output_id: &self.output_id,
            source: &self.source,
            files: &self.files,
        };
        let actual = ManifestId::from_bytes(&canonical_json(&unsigned)?);
        if actual != self.manifest_id {
            return Err(PublishError::InvalidManifest(
                "manifest id does not match its canonical content".to_owned(),
            ));
        }
        if self
            .files
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err(PublishError::InvalidManifest(
                "file entries are not canonically ordered".to_owned(),
            ));
        }
        Ok(())
    }

    /// Serializes this validated manifest as canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or canonical serialization fails.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, PublishError> {
        self.validate()?;
        canonical_json(self)
    }
}

#[derive(Serialize)]
struct UnsignedManifest<'a> {
    protocol: &'a str,
    output_id: &'a ManagedOutputId,
    source: &'a AdmittedFactRef,
    files: &'a [ManagedFile],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationLimits {
    pub max_files: usize,
    pub max_directories: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_manifest_bytes: u64,
}

impl Default for PublicationLimits {
    fn default() -> Self {
        Self {
            max_files: 16_384,
            max_directories: 16_384,
            max_file_bytes: 64 * 1024 * 1024,
            max_total_bytes: 512 * 1024 * 1024,
            max_manifest_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputState {
    Missing,
    Unmanaged,
    WrongOwner,
    ManagedClean,
    ManagedDrifted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckReport {
    pub state: OutputState,
    pub expected_manifest_id: ManifestId,
    pub actual_manifest_id: Option<ManifestId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathChangeKind {
    Added,
    Changed,
    Removed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathChange {
    pub path: ContentPath,
    pub kind: PathChangeKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiffReport {
    pub state: OutputState,
    pub changes: Vec<PathChange>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationOutcome {
    Created,
    Replaced { previous_manifest_id: ManifestId },
    Unchanged { existing_manifest_id: ManifestId },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    NotApplicable,
    DirectorySyncCompleted,
    Uncertain { detail: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupStatus {
    NotApplicable,
    Complete,
    Deferred {
        retained_path: String,
        detail: String,
    },
    Partial {
        retained_path: String,
        detail: String,
    },
    PersistenceUncertain {
        detail: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceipt {
    pub protocol: String,
    pub receipt_id: PublicationReceiptId,
    pub source: AdmittedFactRef,
    pub output_id: ManagedOutputId,
    pub destination: String,
    pub manifest_id: ManifestId,
    pub outcome: PublicationOutcome,
    pub sync: SyncStatus,
    pub cleanup: CleanupStatus,
}

impl PublicationReceipt {
    fn new(
        artifact: &Admitted<ContentSet>,
        output: &ManagedOutput,
        manifest_id: ManifestId,
        outcome: PublicationOutcome,
        sync: SyncStatus,
        cleanup: CleanupStatus,
    ) -> Self {
        let receipt_id = receipt_id(
            artifact.reference(),
            output.id(),
            &output.destination_text,
            &manifest_id,
            &outcome,
            &sync,
            &cleanup,
        );
        Self {
            protocol: RECEIPT_PROTOCOL.to_owned(),
            receipt_id,
            source: artifact.reference().clone(),
            output_id: output.id().clone(),
            destination: output.destination_text.clone(),
            manifest_id,
            outcome,
            sync,
            cleanup,
        }
    }

    /// Validates the protocol and deterministic receipt identity.
    ///
    /// # Errors
    ///
    /// Returns [`PublishError::InvalidReceipt`] when any invariant fails.
    pub fn validate(&self) -> Result<(), PublishError> {
        if self.protocol != RECEIPT_PROTOCOL {
            return Err(PublishError::InvalidReceipt(
                "unsupported protocol".to_owned(),
            ));
        }
        if !self.source.extensions.is_empty() {
            return Err(PublishError::InvalidReceipt(
                "local publication receipts cannot contain source-reference extensions".to_owned(),
            ));
        }
        self.source
            .validate()
            .map_err(|error| PublishError::InvalidReceipt(error.to_string()))?;
        ManagedOutputId::parse(self.output_id.to_string())
            .map_err(|error| PublishError::InvalidReceipt(error.to_string()))?;
        if !is_sha256(self.manifest_id.as_str())
            || match &self.outcome {
                PublicationOutcome::Created => false,
                PublicationOutcome::Replaced {
                    previous_manifest_id,
                } => !is_sha256(previous_manifest_id.as_str()),
                PublicationOutcome::Unchanged {
                    existing_manifest_id,
                } => !is_sha256(existing_manifest_id.as_str()),
            }
        {
            return Err(PublishError::InvalidReceipt(
                "receipt contains a malformed manifest identity".to_owned(),
            ));
        }
        validate_destination(Path::new(&self.destination))
            .map_err(|error| PublishError::InvalidReceipt(error.to_string()))?;
        let actual = receipt_id(
            &self.source,
            &self.output_id,
            &self.destination,
            &self.manifest_id,
            &self.outcome,
            &self.sync,
            &self.cleanup,
        );
        if actual == self.receipt_id {
            Ok(())
        } else {
            Err(PublishError::InvalidReceipt(
                "receipt id does not match its canonical content".to_owned(),
            ))
        }
    }

    /// Serializes this validated receipt as canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or canonical serialization fails.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, PublishError> {
        self.validate()?;
        canonical_json(self)
    }
}

fn receipt_id(
    source: &AdmittedFactRef,
    output_id: &ManagedOutputId,
    destination: &str,
    manifest_id: &ManifestId,
    outcome: &PublicationOutcome,
    sync: &SyncStatus,
    cleanup: &CleanupStatus,
) -> PublicationReceiptId {
    let mut digest = Sha256::new();
    for field in [
        RECEIPT_PROTOCOL,
        &source.fact_id.to_string(),
        &source.authority_record_id.to_string(),
        output_id.as_str(),
        destination,
        manifest_id.as_str(),
    ] {
        framed_digest_field(&mut digest, field);
    }
    match outcome {
        PublicationOutcome::Created => framed_digest_field(&mut digest, "created"),
        PublicationOutcome::Replaced {
            previous_manifest_id,
        } => {
            framed_digest_field(&mut digest, "replaced");
            framed_digest_field(&mut digest, previous_manifest_id.as_str());
        }
        PublicationOutcome::Unchanged {
            existing_manifest_id,
        } => {
            framed_digest_field(&mut digest, "unchanged");
            framed_digest_field(&mut digest, existing_manifest_id.as_str());
        }
    }
    match sync {
        SyncStatus::NotApplicable => framed_digest_field(&mut digest, "sync:not_applicable"),
        SyncStatus::DirectorySyncCompleted => {
            framed_digest_field(&mut digest, "sync:directory_sync_completed");
        }
        SyncStatus::Uncertain { detail } => {
            framed_digest_field(&mut digest, "sync:uncertain");
            framed_digest_field(&mut digest, detail);
        }
    }
    match cleanup {
        CleanupStatus::NotApplicable => {
            framed_digest_field(&mut digest, "cleanup:not_applicable");
        }
        CleanupStatus::Complete => framed_digest_field(&mut digest, "cleanup:complete"),
        CleanupStatus::Deferred {
            retained_path,
            detail,
        } => {
            framed_digest_field(&mut digest, "cleanup:deferred");
            framed_digest_field(&mut digest, retained_path);
            framed_digest_field(&mut digest, detail);
        }
        CleanupStatus::Partial {
            retained_path,
            detail,
        } => {
            framed_digest_field(&mut digest, "cleanup:partial");
            framed_digest_field(&mut digest, retained_path);
            framed_digest_field(&mut digest, detail);
        }
        CleanupStatus::PersistenceUncertain { detail } => {
            framed_digest_field(&mut digest, "cleanup:persistence_uncertain");
            framed_digest_field(&mut digest, detail);
        }
    }
    PublicationReceiptId(format!("sha256:{:x}", digest.finalize()))
}

fn framed_digest_field(digest: &mut Sha256, value: &str) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value.as_bytes());
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug)]
pub enum PublishError {
    UnsupportedPlatform,
    UnsupportedRuntime(String),
    ArtifactExtensions,
    LimitExceeded(&'static str),
    MissingParent(PathBuf),
    Unmanaged(PathBuf),
    WrongOwner {
        expected: ManagedOutputId,
        actual: ManagedOutputId,
    },
    Drift(PathBuf),
    InvalidManifest(String),
    InvalidReceipt(String),
    Race(String),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    Serialization(String),
    CleanupAfterFailure {
        original: Box<Self>,
        cleanup: String,
    },
}

impl fmt::Display for PublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => formatter
                .write_str("local publication is supported only on macOS and Linux"),
            Self::UnsupportedRuntime(detail) => write!(
                formatter,
                "atomic directory publication is unsupported by this runtime: {detail}"
            ),
            Self::ArtifactExtensions => formatter.write_str(
                "local publication refuses preserved content-set, file, fact-reference, or fact extensions",
            ),
            Self::LimitExceeded(limit) => write!(formatter, "publication exceeds `{limit}`"),
            Self::MissingParent(path) => write!(
                formatter,
                "managed output parent `{}` does not exist",
                path.display()
            ),
            Self::Unmanaged(path) => write!(
                formatter,
                "destination `{}` is not a managed output",
                path.display()
            ),
            Self::WrongOwner { expected, actual } => {
                write!(formatter, "destination is owned by `{actual}`, not `{expected}`")
            }
            Self::Drift(path) => {
                write!(formatter, "managed output `{}` has drifted", path.display())
            }
            Self::InvalidManifest(detail) => {
                write!(formatter, "invalid ownership manifest: {detail}")
            }
            Self::InvalidReceipt(detail) => write!(formatter, "invalid publication receipt: {detail}"),
            Self::Race(detail) => write!(formatter, "publication race detected: {detail}"),
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "{operation} `{}` failed: {source}",
                path.display()
            ),
            Self::Serialization(detail) => write!(formatter, "canonical JSON failed: {detail}"),
            Self::CleanupAfterFailure { original, cleanup } => {
                write!(formatter, "{original}; staging cleanup also failed: {cleanup}")
            }
        }
    }
}

impl Error for PublishError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::CleanupAfterFailure { original, .. } => Some(original),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct LocalPublisher {
    limits: PublicationLimits,
}

impl LocalPublisher {
    /// Creates a publisher with explicit resource bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when any configured limit is zero.
    pub fn new(limits: PublicationLimits) -> Result<Self, PublishError> {
        if limits.max_files == 0
            || limits.max_directories == 0
            || limits.max_file_bytes == 0
            || limits.max_total_bytes == 0
            || limits.max_manifest_bytes == 0
        {
            return Err(PublishError::LimitExceeded("nonzero configured limit"));
        }
        Ok(Self { limits })
    }

    /// Inspects destination ownership and drift without mutating it.
    ///
    /// # Errors
    ///
    /// Returns an error when the request violates publication policy or inspection fails.
    pub fn check(
        &self,
        artifact: &Admitted<ContentSet>,
        output: &ManagedOutput,
    ) -> Result<CheckReport, PublishError> {
        self.validate_request(artifact, output)?;
        platform::with_parent_lock(output, false, || self.check_unlocked(artifact, output))
    }

    /// Compares admitted content with the destination without mutating it.
    ///
    /// # Errors
    ///
    /// Returns an error when the request violates publication policy or inspection fails.
    pub fn diff(
        &self,
        artifact: &Admitted<ContentSet>,
        output: &ManagedOutput,
    ) -> Result<DiffReport, PublishError> {
        self.validate_request(artifact, output)?;
        platform::with_parent_lock(output, false, || self.diff_unlocked(artifact, output))
    }

    /// Creates or atomically replaces one clean dedicated managed directory.
    ///
    /// # Errors
    ///
    /// Errors are returned only before an atomic commit. After commit this
    /// method always returns a receipt, with sync or cleanup uncertainty in it.
    pub fn publish(
        &self,
        artifact: &Admitted<ContentSet>,
        output: &ManagedOutput,
    ) -> Result<PublicationReceipt, PublishError> {
        self.validate_request(artifact, output)?;
        platform::with_parent_lock(output, true, || self.publish_unlocked(artifact, output))
    }

    fn validate_request(
        &self,
        artifact: &Admitted<ContentSet>,
        output: &ManagedOutput,
    ) -> Result<(), PublishError> {
        if artifact.value().has_extensions()
            || !artifact.fact_extensions().is_empty()
            || !artifact.reference().extensions.is_empty()
        {
            return Err(PublishError::ArtifactExtensions);
        }
        let files = &artifact.value().files;
        if files.len() > self.limits.max_files {
            return Err(PublishError::LimitExceeded("max_files"));
        }
        let mut directories = BTreeSet::new();
        let mut total = 0_u64;
        for file in files {
            let length = u64::try_from(file.content.len()).unwrap_or(u64::MAX);
            if length > self.limits.max_file_bytes {
                return Err(PublishError::LimitExceeded("max_file_bytes"));
            }
            total = total
                .checked_add(length)
                .ok_or(PublishError::LimitExceeded("max_total_bytes"))?;
            if total > self.limits.max_total_bytes {
                return Err(PublishError::LimitExceeded("max_total_bytes"));
            }
            let components: Vec<_> = file.path.as_str().split('/').collect();
            let mut current = PathBuf::new();
            for component in components.iter().take(components.len().saturating_sub(1)) {
                current.push(component);
                directories.insert(current.clone());
            }
        }
        if directories.len() > self.limits.max_directories {
            return Err(PublishError::LimitExceeded("max_directories"));
        }
        let size = u64::try_from(
            OwnershipManifest::new(output, artifact)?
                .to_canonical_json()?
                .len(),
        )
        .unwrap_or(u64::MAX);
        if size > self.limits.max_manifest_bytes {
            return Err(PublishError::LimitExceeded("max_manifest_bytes"));
        }
        Ok(())
    }

    fn check_unlocked(
        &self,
        artifact: &Admitted<ContentSet>,
        output: &ManagedOutput,
    ) -> Result<CheckReport, PublishError> {
        let expected = OwnershipManifest::new(output, artifact)?;
        let inspection = inspect(output, &self.limits)?;
        Ok(CheckReport {
            state: inspection.state,
            expected_manifest_id: expected.manifest_id,
            actual_manifest_id: inspection
                .manifest
                .as_ref()
                .map(|manifest| manifest.manifest_id.clone()),
        })
    }

    fn diff_unlocked(
        &self,
        artifact: &Admitted<ContentSet>,
        output: &ManagedOutput,
    ) -> Result<DiffReport, PublishError> {
        let inspection = inspect(output, &self.limits)?;
        let expected = expected_files(artifact);
        let mut paths: BTreeSet<_> = expected.keys().cloned().collect();
        paths.extend(inspection.observed.keys().cloned());
        let changes = paths
            .into_iter()
            .filter_map(
                |path| match (expected.get(&path), inspection.observed.get(&path)) {
                    (Some(_), None) => Some(PathChange {
                        path,
                        kind: PathChangeKind::Added,
                    }),
                    (None, Some(_)) => Some(PathChange {
                        path,
                        kind: PathChangeKind::Removed,
                    }),
                    (Some(expected), Some(actual)) if expected != actual => Some(PathChange {
                        path,
                        kind: PathChangeKind::Changed,
                    }),
                    _ => None,
                },
            )
            .collect();
        Ok(DiffReport {
            state: inspection.state,
            changes,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn publish_unlocked(
        &self,
        artifact: &Admitted<ContentSet>,
        output: &ManagedOutput,
    ) -> Result<PublicationReceipt, PublishError> {
        let expected = OwnershipManifest::new(output, artifact)?;
        let inspection = inspect(output, &self.limits)?;
        match inspection.state {
            OutputState::Unmanaged => {
                return Err(PublishError::Unmanaged(output.destination.clone()));
            }
            OutputState::WrongOwner => {
                let actual = inspection
                    .manifest
                    .as_ref()
                    .map(|manifest| manifest.output_id.clone())
                    .ok_or_else(|| PublishError::Unmanaged(output.destination.clone()))?;
                return Err(PublishError::WrongOwner {
                    expected: output.id.clone(),
                    actual,
                });
            }
            OutputState::ManagedDrifted => {
                return Err(PublishError::Drift(output.destination.clone()));
            }
            OutputState::ManagedClean
                if inspection
                    .manifest
                    .as_ref()
                    .is_some_and(|actual| actual == &expected) =>
            {
                return Ok(PublicationReceipt::new(
                    artifact,
                    output,
                    expected.manifest_id.clone(),
                    PublicationOutcome::Unchanged {
                        existing_manifest_id: expected.manifest_id,
                    },
                    SyncStatus::NotApplicable,
                    CleanupStatus::NotApplicable,
                ));
            }
            OutputState::Missing | OutputState::ManagedClean => {}
        }

        let stage = platform::stage(output, artifact, &expected)?;
        match inspection.state {
            OutputState::Missing => {
                if let Err(error) = platform::commit_create(output, &stage) {
                    return Err(clean_stage_after_error(&stage, error));
                }
                let sync = platform::sync_parent(output);
                // The commit has happened. Construction from fixed serializable fields is
                // infallible in practice; retain a receipt even if persistence is uncertain.
                Ok(PublicationReceipt::new(
                    artifact,
                    output,
                    expected.manifest_id,
                    PublicationOutcome::Created,
                    sync,
                    CleanupStatus::NotApplicable,
                ))
            }
            OutputState::ManagedClean => {
                let previous_manifest_id = inspection
                    .manifest
                    .as_ref()
                    .expect("clean inspection has a manifest")
                    .manifest_id
                    .clone();
                // Re-read the complete tree just before exchange. This catches
                // non-cooperating changes that occurred while staging.
                let rechecked = match inspect(output, &self.limits) {
                    Ok(inspection) => inspection,
                    Err(error) => return Err(clean_stage_after_error(&stage, error)),
                };
                if rechecked.state != OutputState::ManagedClean
                    || rechecked.manifest != inspection.manifest
                    || rechecked.observed != inspection.observed
                {
                    return Err(clean_stage_after_error(
                        &stage,
                        PublishError::Race(
                            "destination changed while the replacement was staged".to_owned(),
                        ),
                    ));
                }
                if let Err(error) = platform::commit_exchange(output, &stage) {
                    return Err(clean_stage_after_error(&stage, error));
                }
                let sync = platform::sync_parent(output);
                let cleanup = if matches!(sync, SyncStatus::DirectorySyncCompleted) {
                    platform::cleanup_retired(output, &stage)
                } else {
                    CleanupStatus::Deferred {
                        retained_path: stage.to_string_lossy().into_owned(),
                        detail:
                            "parent sync did not complete; retained the retired tree for recovery"
                                .to_owned(),
                    }
                };
                Ok(PublicationReceipt::new(
                    artifact,
                    output,
                    expected.manifest_id,
                    PublicationOutcome::Replaced {
                        previous_manifest_id,
                    },
                    sync,
                    cleanup,
                ))
            }
            _ => unreachable!("conflicting states returned before staging"),
        }
    }
}

fn expected_files(artifact: &Admitted<ContentSet>) -> BTreeMap<ContentPath, (ContentDigest, u64)> {
    artifact
        .value()
        .files
        .iter()
        .map(|file| {
            (
                file.path.clone(),
                (
                    ContentDigest::from_bytes(&file.content),
                    u64::try_from(file.content.len()).unwrap_or(u64::MAX),
                ),
            )
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
fn inspect(output: &ManagedOutput, limits: &PublicationLimits) -> Result<Inspection, PublishError> {
    let destination = output.destination();
    let metadata = match std::fs::symlink_metadata(destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(Inspection {
                state: OutputState::Missing,
                manifest: None,
                observed: BTreeMap::new(),
            });
        }
        Err(error) => return Err(io_error("inspect", destination, error)),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Ok(Inspection {
            state: OutputState::Unmanaged,
            manifest: None,
            observed: BTreeMap::new(),
        });
    }
    let marker = destination.join(crate::MANAGED_OUTPUT_MARKER);
    let marker_metadata = match std::fs::symlink_metadata(&marker) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
        Ok(_) => {
            return Ok(Inspection {
                state: OutputState::Unmanaged,
                manifest: None,
                observed: BTreeMap::new(),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(Inspection {
                state: OutputState::Unmanaged,
                manifest: None,
                observed: BTreeMap::new(),
            });
        }
        Err(error) => return Err(io_error("inspect marker", marker, error)),
    };
    if marker_metadata.len() > limits.max_manifest_bytes {
        return Ok(Inspection {
            state: OutputState::Unmanaged,
            manifest: None,
            observed: BTreeMap::new(),
        });
    }
    let marker_bytes = match platform::read_nofollow(&marker, limits.max_manifest_bytes) {
        Ok(bytes) => bytes,
        Err(PublishError::Drift(_)) => {
            return Ok(Inspection {
                state: OutputState::Unmanaged,
                manifest: None,
                observed: BTreeMap::new(),
            });
        }
        Err(error) => return Err(error),
    };
    let manifest: OwnershipManifest = match serde_json::from_slice(&marker_bytes) {
        Ok(manifest) => manifest,
        Err(_) => {
            return Ok(Inspection {
                state: OutputState::Unmanaged,
                manifest: None,
                observed: BTreeMap::new(),
            });
        }
    };
    if !manifest.source.extensions.is_empty()
        || manifest.validate().is_err()
        || manifest.to_canonical_json().ok().as_deref() != Some(&marker_bytes)
    {
        return Ok(Inspection {
            state: OutputState::Unmanaged,
            manifest: None,
            observed: BTreeMap::new(),
        });
    }
    if manifest.output_id != output.id {
        return Ok(Inspection {
            state: OutputState::WrongOwner,
            manifest: Some(manifest),
            observed: BTreeMap::new(),
        });
    }
    let observed_tree = match walk_managed(destination, limits) {
        Ok(tree) => tree,
        Err(WalkError::Drift) => {
            return Ok(Inspection {
                state: OutputState::ManagedDrifted,
                manifest: Some(manifest),
                observed: BTreeMap::new(),
            });
        }
        Err(WalkError::Publish(error)) => return Err(error),
    };
    let declared: BTreeMap<_, _> = manifest
        .files
        .iter()
        .map(|file| (file.path.clone(), (file.digest.clone(), file.bytes)))
        .collect();
    let declared_directories = managed_directories(manifest.files.iter().map(|file| &file.path));
    let state =
        if declared == observed_tree.files && declared_directories == observed_tree.directories {
            OutputState::ManagedClean
        } else {
            OutputState::ManagedDrifted
        };
    Ok(Inspection {
        state,
        manifest: Some(manifest),
        observed: observed_tree.files,
    })
}

fn managed_directories<'a>(paths: impl Iterator<Item = &'a ContentPath>) -> BTreeSet<String> {
    let mut directories = BTreeSet::new();
    for path in paths {
        let components: Vec<_> = path.as_str().split('/').collect();
        for length in 1..components.len() {
            directories.insert(components[..length].join("/"));
        }
    }
    directories
}

enum WalkError {
    Drift,
    Publish(PublishError),
}

struct WalkedTree {
    files: BTreeMap<ContentPath, (ContentDigest, u64)>,
    directories: BTreeSet<String>,
}

fn walk_managed(destination: &Path, limits: &PublicationLimits) -> Result<WalkedTree, WalkError> {
    let mut observed = BTreeMap::new();
    let mut observed_directories = BTreeSet::new();
    let mut stack = vec![destination.to_owned()];
    let mut total = 0_u64;
    while let Some(directory) = stack.pop() {
        let entries = std::fs::read_dir(&directory).map_err(|error| {
            WalkError::Publish(io_error("read managed directory", &directory, error))
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                WalkError::Publish(io_error("read managed entry", &directory, error))
            })?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                WalkError::Publish(io_error("inspect managed entry", &path, error))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(WalkError::Drift);
            }
            if metadata.is_dir() {
                let relative = path
                    .strip_prefix(destination)
                    .map_err(|_| WalkError::Drift)?
                    .to_str()
                    .ok_or(WalkError::Drift)?
                    .replace(std::path::MAIN_SEPARATOR, "/");
                ContentPath::parse(&relative).map_err(|_| WalkError::Drift)?;
                if observed_directories.len() >= limits.max_directories {
                    return Err(WalkError::Drift);
                }
                observed_directories.insert(relative);
                stack.push(path);
                continue;
            }
            if !metadata.is_file() {
                return Err(WalkError::Drift);
            }
            let relative = path
                .strip_prefix(destination)
                .map_err(|_| WalkError::Drift)?;
            let relative = relative
                .to_str()
                .ok_or(WalkError::Drift)?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if relative == crate::MANAGED_OUTPUT_MARKER {
                continue;
            }
            if observed.len() >= limits.max_files || metadata.len() > limits.max_file_bytes {
                return Err(WalkError::Drift);
            }
            total = total.checked_add(metadata.len()).ok_or(WalkError::Drift)?;
            if total > limits.max_total_bytes {
                return Err(WalkError::Drift);
            }
            let portable = ContentPath::parse(relative).map_err(|_| WalkError::Drift)?;
            let bytes = platform::read_nofollow(&path, limits.max_file_bytes)
                .map_err(WalkError::Publish)?;
            if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != metadata.len() {
                return Err(WalkError::Drift);
            }
            observed.insert(
                portable,
                (ContentDigest::from_bytes(&bytes), metadata.len()),
            );
        }
    }
    Ok(WalkedTree {
        files: observed,
        directories: observed_directories,
    })
}

fn clean_stage_after_error(stage: &Path, original: PublishError) -> PublishError {
    match std::fs::remove_dir_all(stage) {
        Ok(()) => original,
        Err(error) if error.kind() == io::ErrorKind::NotFound => original,
        Err(error) => PublishError::CleanupAfterFailure {
            original: Box::new(original),
            cleanup: error.to_string(),
        },
    }
}

fn validate_destination(path: &Path) -> Result<(), ManagedOutputError> {
    if path.as_os_str().is_empty()
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(ManagedOutputError::InvalidDestination(path.to_owned()));
    }
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, PublishError> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|error| PublishError::Serialization(error.to_string()))
}

#[derive(Debug)]
struct Inspection {
    state: OutputState,
    manifest: Option<OwnershipManifest>,
    observed: BTreeMap<ContentPath, (ContentDigest, u64)>,
}

fn io_error(operation: &'static str, path: impl Into<PathBuf>, source: io::Error) -> PublishError {
    PublishError::Io {
        operation,
        path: path.into(),
        source,
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod platform;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::*;

    pub(super) fn with_parent_lock<T>(
        _output: &ManagedOutput,
        _exclusive: bool,
        _operation: impl FnOnce() -> Result<T, PublishError>,
    ) -> Result<T, PublishError> {
        Err(PublishError::UnsupportedPlatform)
    }

    pub(super) fn read_nofollow(_path: &Path, _max_bytes: u64) -> Result<Vec<u8>, PublishError> {
        Err(PublishError::UnsupportedPlatform)
    }

    pub(super) fn stage(
        _output: &ManagedOutput,
        _artifact: &Admitted<ContentSet>,
        _manifest: &OwnershipManifest,
    ) -> Result<PathBuf, PublishError> {
        Err(PublishError::UnsupportedPlatform)
    }

    pub(super) fn commit_create(
        _output: &ManagedOutput,
        _stage: &Path,
    ) -> Result<(), PublishError> {
        Err(PublishError::UnsupportedPlatform)
    }

    pub(super) fn commit_exchange(
        _output: &ManagedOutput,
        _stage: &Path,
    ) -> Result<(), PublishError> {
        Err(PublishError::UnsupportedPlatform)
    }

    pub(super) fn sync_parent(_output: &ManagedOutput) -> SyncStatus {
        SyncStatus::Uncertain {
            detail: "local publication is unsupported on this platform".to_owned(),
        }
    }

    pub(super) fn cleanup_retired(_output: &ManagedOutput, stage: &Path) -> CleanupStatus {
        CleanupStatus::Deferred {
            retained_path: stage.to_string_lossy().into_owned(),
            detail: "local publication is unsupported on this platform".to_owned(),
        }
    }
}
