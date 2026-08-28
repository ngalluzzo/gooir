//! Optional artifact contract and admitted local-publication SDK.
//!
//! This crate is outside GOOIR's semantic kernel. External ecosystems may
//! produce its portable [`ContentSet`] value through ordinary capabilities.
//! A host may then resolve an exact admitted value and publish it under
//! explicit local authority. Publication is never a capability edge.

#![forbid(unsafe_code)]

mod local;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use base64::Engine as _;
use gooir_capability::authority::AdmissionLedger;
use gooir_capability::protocol::{AdmittedFactRef, AuthorityRecordId};
use gooir_capability::{FactId, ValueKindId};
use gooir_package::{DialectDeclaration, PackageId, PackageManifest, ValueKindDeclaration};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

pub use local::{
    CheckReport, CleanupStatus, ContentDigest, DiffReport, LocalPublisher, ManagedFile,
    ManagedOutput, ManagedOutputError, ManagedOutputId, ManifestId, OutputState, OwnershipManifest,
    PathChange, PathChangeKind, PublicationLimits, PublicationOutcome, PublicationReceipt,
    PublicationReceiptId, PublishError, SyncStatus,
};

/// Exact package coordinate for the portable content-set contract.
pub const CONTENT_SET_PACKAGE: &str = "org.gooi.artifact.content_set@1.0.0";
/// Exact dialect package name for the portable content-set contract.
pub const CONTENT_SET_DIALECT: &str = "org.gooi.artifact.content_set";
/// Exact dialect version for the portable content-set contract.
pub const CONTENT_SET_VERSION: &str = "1.0.0";
/// Value-kind name for a portable content set.
pub const CONTENT_SET_KIND: &str = "set";
/// Path reserved for the host-owned managed-output marker.
pub const MANAGED_OUTPUT_MARKER: &str = ".gooir-managed-output.json";

/// Exact value kind consumed by the local artifact publisher.
#[must_use]
pub fn content_set_contract() -> ValueKindId {
    ValueKindId::new(CONTENT_SET_DIALECT, CONTENT_SET_KIND, CONTENT_SET_VERSION)
}

/// Offer-free package declaration for the separately versioned artifact contract.
///
/// # Panics
///
/// Panics only if this crate's static package coordinates cease to satisfy the
/// package library's invariants, which is a build-time programming defect.
#[must_use]
pub fn package_manifest() -> PackageManifest {
    PackageManifest::new(
        PackageId::parse(CONTENT_SET_PACKAGE).expect("static package identity is valid"),
        Vec::new(),
        Vec::new(),
        vec![DialectDeclaration {
            id: content_set_contract().dialect().clone(),
            value_kinds: vec![ValueKindDeclaration {
                id: content_set_contract(),
                schema: None,
                extensions: BTreeMap::new(),
            }],
            extensions: BTreeMap::new(),
        }],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        BTreeMap::new(),
    )
    .expect("static content-set package declaration is valid")
}

/// Validation contract required before a typed admitted value may be exposed.
pub trait ArtifactContract: DeserializeOwned {
    type Error: Error + Send + Sync + 'static;

    fn value_kind() -> ValueKindId;
    /// Validates all contract invariants after decoding.
    ///
    /// # Errors
    ///
    /// Returns the contract-specific validation error.
    fn validate(&self) -> Result<(), Self::Error>;
}

/// A typed artifact resolved only through an exact admission-ledger reference.
#[derive(Clone, Debug, PartialEq)]
pub struct Admitted<T> {
    reference: AdmittedFactRef,
    authority_record_id: AuthorityRecordId,
    fact_id: FactId,
    fact_extensions: BTreeMap<String, Value>,
    value: T,
}

impl<T> Admitted<T>
where
    T: ArtifactContract,
{
    /// Resolves and validates an exact ledger reference as this artifact type.
    ///
    /// # Errors
    ///
    /// Returns an error if resolution, exact-kind checking, decoding, or
    /// contract validation fails.
    #[allow(clippy::result_large_err)]
    pub fn resolve(
        ledger: &AdmissionLedger,
        reference: &AdmittedFactRef,
    ) -> Result<Self, AdmittedArtifactError> {
        let resolved = ledger
            .resolve(reference)
            .map_err(|error| AdmittedArtifactError::Resolution(error.to_string()))?;
        let expected = T::value_kind();
        if resolved.fact.value_kind != expected {
            return Err(AdmittedArtifactError::WrongValueKind {
                expected,
                actual: resolved.fact.value_kind.clone(),
            });
        }
        resolved
            .fact
            .validate()
            .map_err(|error| AdmittedArtifactError::InvalidFact(error.to_string()))?;
        let value: T = serde_json::from_value(resolved.fact.payload.clone())
            .map_err(|error| AdmittedArtifactError::Decode(error.to_string()))?;
        value
            .validate()
            .map_err(|error| AdmittedArtifactError::InvalidArtifact(error.to_string()))?;
        Ok(Self {
            reference: reference.clone(),
            authority_record_id: reference.authority_record_id.clone(),
            fact_id: resolved.fact.id.clone(),
            fact_extensions: resolved.fact.extensions.clone(),
            value,
        })
    }

    #[must_use]
    pub const fn reference(&self) -> &AdmittedFactRef {
        &self.reference
    }

    #[must_use]
    pub const fn authority_record_id(&self) -> &AuthorityRecordId {
        &self.authority_record_id
    }

    #[must_use]
    pub const fn fact_id(&self) -> &FactId {
        &self.fact_id
    }

    #[must_use]
    pub const fn fact_extensions(&self) -> &BTreeMap<String, Value> {
        &self.fact_extensions
    }

    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmittedArtifactError {
    Resolution(String),
    WrongValueKind {
        expected: ValueKindId,
        actual: ValueKindId,
    },
    InvalidFact(String),
    Decode(String),
    InvalidArtifact(String),
}

impl fmt::Display for AdmittedArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolution(detail) => {
                write!(formatter, "admitted reference did not resolve: {detail}")
            }
            Self::WrongValueKind { expected, actual } => write!(
                formatter,
                "artifact kind `{actual}` does not match expected kind `{expected}`"
            ),
            Self::InvalidFact(detail) => write!(formatter, "admitted fact is invalid: {detail}"),
            Self::Decode(detail) => {
                write!(formatter, "artifact payload cannot be decoded: {detail}")
            }
            Self::InvalidArtifact(detail) => {
                write!(formatter, "artifact payload is invalid: {detail}")
            }
        }
    }
}

impl Error for AdmittedArtifactError {}

/// Canonical portable relative content path.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ContentPath(String);

impl ContentPath {
    /// Parses a portable relative content path.
    ///
    /// # Errors
    ///
    /// Returns an error for absolute, ambiguous, reserved, or non-portable paths.
    pub fn parse(value: impl Into<String>) -> Result<Self, ContentSetError> {
        let path = Self(value.into());
        validate_path(path.as_str())?;
        Ok(path)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContentPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContentPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// One exact file in a portable [`ContentSet`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContentFile {
    pub path: ContentPath,
    #[serde(with = "base64_bytes")]
    pub content: Vec<u8>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl ContentFile {
    /// Creates one extension-free content file.
    ///
    /// # Errors
    ///
    /// Returns an error when `path` is not portable.
    pub fn new(path: impl Into<String>, content: Vec<u8>) -> Result<Self, ContentSetError> {
        Self::with_extensions(path, content, BTreeMap::new())
    }

    /// Creates one content file while preserving extension data.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths or extensions shadowing contract fields.
    pub fn with_extensions(
        path: impl Into<String>,
        content: Vec<u8>,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ContentSetError> {
        validate_extensions("content file", &extensions, &["path", "content"])?;
        Ok(Self {
            path: ContentPath::parse(path)?,
            content,
            extensions,
        })
    }

    /// Validates this file's portable path and extension namespace.
    ///
    /// # Errors
    ///
    /// Returns a contract validation error.
    pub fn validate(&self) -> Result<(), ContentSetError> {
        validate_path(self.path.as_str())?;
        validate_extensions("content file", &self.extensions, &["path", "content"])
    }
}

/// Canonically ordered portable files without destination or write authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContentSet {
    pub files: Vec<ContentFile>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl ContentSet {
    /// Creates an extension-free, canonically ordered content set.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid, colliding, or ancestor file paths.
    pub fn new(files: Vec<ContentFile>) -> Result<Self, ContentSetError> {
        Self::with_extensions(files, BTreeMap::new())
    }

    /// Creates a canonically ordered content set while preserving extensions.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, collisions, or reserved extensions.
    pub fn with_extensions(
        mut files: Vec<ContentFile>,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ContentSetError> {
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let set = Self { files, extensions };
        set.validate()?;
        Ok(set)
    }

    /// Validates canonical ordering, portable uniqueness, and extensions.
    ///
    /// # Errors
    ///
    /// Returns a contract validation error.
    pub fn validate(&self) -> Result<(), ContentSetError> {
        validate_extensions("content set", &self.extensions, &["files"])?;
        let mut exact = BTreeSet::new();
        let mut folded = BTreeMap::<String, String>::new();
        let mut previous: Option<&ContentPath> = None;
        for file in &self.files {
            file.validate()?;
            if previous.is_some_and(|prior| prior >= &file.path) {
                return Err(ContentSetError::NonCanonicalOrder);
            }
            previous = Some(&file.path);
            let path = file.path.as_str();
            if !exact.insert(path.to_owned()) {
                return Err(ContentSetError::DuplicatePath(path.to_owned()));
            }
            let portable = path.to_ascii_lowercase();
            if let Some(first) = folded.insert(portable, path.to_owned()) {
                return Err(ContentSetError::PortablePathCollision {
                    first,
                    second: path.to_owned(),
                });
            }
        }
        for (portable, actual) in &folded {
            for (index, _) in portable.match_indices('/') {
                if let Some(ancestor) = folded.get(&portable[..index]) {
                    return Err(ContentSetError::AncestorCollision {
                        file: ancestor.clone(),
                        descendant: actual.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn has_extensions(&self) -> bool {
        !self.extensions.is_empty() || self.files.iter().any(|file| !file.extensions.is_empty())
    }
}

impl ArtifactContract for ContentSet {
    type Error = ContentSetError;

    fn value_kind() -> ValueKindId {
        content_set_contract()
    }

    fn validate(&self) -> Result<(), Self::Error> {
        Self::validate(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentSetError {
    InvalidPath(String),
    ReservedPath(String),
    DuplicatePath(String),
    PortablePathCollision { first: String, second: String },
    AncestorCollision { file: String, descendant: String },
    NonCanonicalOrder,
    ReservedExtension { scope: &'static str, key: String },
}

impl fmt::Display for ContentSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(path) => write!(
                formatter,
                "`{}` is not a portable relative content path",
                path.escape_debug()
            ),
            Self::ReservedPath(path) => write!(
                formatter,
                "content path `{}` is reserved by the managed-output host",
                path.escape_debug()
            ),
            Self::DuplicatePath(path) => write!(
                formatter,
                "duplicate content path `{}`",
                path.escape_debug()
            ),
            Self::PortablePathCollision { first, second } => write!(
                formatter,
                "content paths `{}` and `{}` collide portably",
                first.escape_debug(),
                second.escape_debug()
            ),
            Self::AncestorCollision { file, descendant } => write!(
                formatter,
                "content file `{}` is an ancestor of `{}`",
                file.escape_debug(),
                descendant.escape_debug()
            ),
            Self::NonCanonicalOrder => {
                formatter.write_str("content files are not in canonical path order")
            }
            Self::ReservedExtension { scope, key } => write!(
                formatter,
                "{scope} extension `{}` shadows a contract field",
                key.escape_debug()
            ),
        }
    }
}

impl Error for ContentSetError {}

fn validate_path(path: &str) -> Result<(), ContentSetError> {
    if path.is_empty()
        || path.len() > 4_096
        || !path.is_ascii()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains(['<', '>', ':', '"', '|', '?', '*'])
        || path.chars().any(char::is_control)
        || path.eq_ignore_ascii_case(MANAGED_OUTPUT_MARKER)
    {
        return if path.eq_ignore_ascii_case(MANAGED_OUTPUT_MARKER) {
            Err(ContentSetError::ReservedPath(path.to_owned()))
        } else {
            Err(ContentSetError::InvalidPath(path.to_owned()))
        };
    }
    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > 255
            || component.ends_with('.')
            || component.ends_with(' ')
            || windows_reserved(component)
        {
            return Err(ContentSetError::InvalidPath(path.to_owned()));
        }
    }
    Ok(())
}

fn windows_reserved(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || upper
            .strip_prefix("COM")
            .is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
        || upper
            .strip_prefix("LPT")
            .is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
}

fn validate_extensions(
    scope: &'static str,
    extensions: &BTreeMap<String, Value>,
    reserved: &[&str],
) -> Result<(), ContentSetError> {
    if let Some(key) = extensions
        .keys()
        .find(|key| reserved.contains(&key.as_str()))
    {
        Err(ContentSetError::ReservedExtension {
            scope,
            key: key.clone(),
        })
    } else {
        Ok(())
    }
}

mod base64_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)?;
        if base64::engine::general_purpose::STANDARD.encode(&bytes) != encoded {
            return Err(serde::de::Error::custom(
                "content is not canonical padded Base64",
            ));
        }
        Ok(bytes)
    }
}
