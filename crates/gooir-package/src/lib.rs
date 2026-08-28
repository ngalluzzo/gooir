//! Structural protocol for independently installable GOOIR packages.
//!
//! This crate validates package declarations, copies exact package-local bytes,
//! and installs their identities into an in-memory registry. It does not
//! compile schemas, select or execute implementations, establish conformance,
//! admit facts, discover packages, fetch dependencies, or solve versions.

mod loader;
mod registry;

pub use loader::{
    LoadLimits, OwnedResource, PACKAGE_MANIFEST_FILE, PackageLoadError, ValidatedPackage,
    load_local_package,
};
pub use registry::{InstallError, InstalledPackage, PackageRegistry};

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use gooir_capability::protocol::{ConformanceSuiteId, ImplementationId};
use gooir_capability::strict_json::{self, StrictJsonError};
use gooir_capability::{
    CapabilityId, CapabilityRegistry, CapabilitySpec, DialectId, FactAcceptance, InputPort,
    OutputPort, PortName, ValueKindId,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Exact package manifest protocol implemented by this crate.
pub const PACKAGE_PROTOCOL: &str = "org.gooi.package/v1";

/// The legacy declaration-only pack remains a different protocol and is never
/// reinterpreted as a package.
pub const LEGACY_PACK_PROTOCOL: &str = gooir_capability::PACK_PROTOCOL;

const MAX_RESOURCE_NAME_BYTES: usize = 128;
const MAX_RESOURCE_PATH_BYTES: usize = 4_096;
const MAX_MEDIA_TYPE_BYTES: usize = 255;
const MAX_JCS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// One exact independently installable package, in `name@version` form.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PackageId(String);

impl PackageId {
    /// Parses an exact package identity without filling or normalizing parts.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not an unambiguous `name@version`.
    pub fn parse(value: impl Into<String>) -> Result<Self, PackageIdentityError> {
        let value = value.into();
        let Some((name, version)) = value.split_once('@') else {
            return Err(PackageIdentityError(value));
        };
        if name.trim().is_empty()
            || version.trim().is_empty()
            || name.trim() != name
            || version.trim() != version
            || value.trim() != value
            || value.chars().any(char::is_control)
            || name.contains('/')
            || version.contains('/')
            || version.contains('@')
        {
            return Err(PackageIdentityError(value));
        }
        Ok(Self(value))
    }

    /// Returns the exact display identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PackageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PackageId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Why a package identity could not be parsed exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageIdentityError(String);

impl fmt::Display for PackageIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "`{}` is not an exact package identity",
            self.0.escape_debug()
        )
    }
}

impl Error for PackageIdentityError {}

macro_rules! sha256_identity {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Parses an exact lowercase `sha256:<64 hex digits>` identity.
            ///
            /// # Errors
            ///
            /// Returns an error when the value is not exact lowercase SHA-256.
            pub fn parse(value: impl Into<String>) -> Result<Self, DigestParseError> {
                let value = value.into();
                if is_sha256(&value) {
                    Ok(Self(value))
                } else {
                    Err(DigestParseError(value))
                }
            }

            /// Returns the exact digest identity.
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

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::parse(String::deserialize(deserializer)?)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

sha256_identity! {
    /// JCS/SHA-256 identity of a package manifest without only its root digest.
    PackageDigest
}

sha256_identity! {
    /// SHA-256 identity declared for exact package-local resource bytes.
    ResourceDigest
}

/// Why a digest was not an exact lowercase SHA-256 identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestParseError(String);

impl fmt::Display for DigestParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "`{}` is not an exact SHA-256 identity",
            self.0.escape_debug()
        )
    }
}

impl Error for DigestParseError {}

/// Exact package-local lookup name for one declared resource.
///
/// A resource name is not a path. GOOIR preserves its spelling and rejects
/// only names that are blank, padded, controlled, or too large to use safely.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ResourceName(String);

impl ResourceName {
    /// Parses one bounded, exact package-local name.
    ///
    /// # Errors
    ///
    /// Returns an error for blank, padded, controlled, or oversized names.
    pub fn parse(value: impl Into<String>) -> Result<Self, ResourceNameError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_RESOURCE_NAME_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            Err(ResourceNameError(value))
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ResourceName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceNameError(String);

impl fmt::Display for ResourceNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "`{}` is not an exact resource name",
            self.0.escape_debug()
        )
    }
}

impl Error for ResourceNameError {}

/// Exact direct dependency coordinate. No range, solver, or transitive claim
/// exists in this document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageDependency {
    pub package: PackageId,
    pub digest: PackageDigest,
    pub extensions: BTreeMap<String, Value>,
}

/// Metadata for package-local bytes. Reading and trusting those bytes belongs
/// to a later filesystem loader.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageResource {
    pub name: ResourceName,
    pub path: String,
    pub media_type: String,
    pub size: u64,
    pub digest: ResourceDigest,
    pub extensions: BTreeMap<String, Value>,
}

/// One dialect-owned value kind. A schema is only an optional reference to an
/// opaque local resource; this crate does not parse or compile it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueKindDeclaration {
    pub id: ValueKindId,
    pub schema: Option<ResourceName>,
    pub extensions: BTreeMap<String, Value>,
}

/// One governed dialect and the exact value kinds it owns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DialectDeclaration {
    pub id: DialectId,
    pub value_kinds: Vec<ValueKindDeclaration>,
    pub extensions: BTreeMap<String, Value>,
}

/// One exact conformance-suite identity exported by this package.
///
/// This is an ownership declaration only. It does not contain an attester,
/// execute a check, or establish admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceSuiteDeclaration {
    pub id: ConformanceSuiteId,
    pub extensions: BTreeMap<String, Value>,
}

/// Availability declaration whose measured artifact digest and final offer ID
/// can only be formed by a later byte loader.
///
/// The set-ordering identity is the exact `(capability, implementation,
/// artifact)` tuple. Opaque extension data remains content-identified but is
/// not an ordering or selection key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImplementationOfferDeclaration {
    pub implementation: ImplementationId,
    pub capability: CapabilityId,
    pub artifact: ResourceName,
    pub extensions: BTreeMap<String, Value>,
}

/// Validated structural content of one package manifest.
///
/// All known set-like arrays are required to be identity-sorted. Capability
/// port order and arrays inside opaque extensions remain content-significant.
/// Cross-package value-kind, capability, implementation, and conformance-suite
/// ownership is deliberately unresolved here: only an installer holding exact
/// dependency handles can prove which identities those dependencies export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageManifest {
    pub package: PackageId,
    pub content_digest: PackageDigest,
    pub dependencies: Vec<PackageDependency>,
    pub resources: Vec<PackageResource>,
    pub dialects: Vec<DialectDeclaration>,
    pub conformance_suites: Vec<ConformanceSuiteDeclaration>,
    pub capabilities: Vec<CapabilitySpec>,
    pub implementation_offers: Vec<ImplementationOfferDeclaration>,
    pub extensions: BTreeMap<String, Value>,
}

impl PackageManifest {
    /// Constructs a structurally validated manifest and derives its content
    /// identity. Callers must already provide identity-sorted set arrays.
    ///
    /// # Errors
    ///
    /// Returns an error when any declaration is malformed, ambiguously
    /// ordered, shadowed by an extension, or not canonically representable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package: PackageId,
        dependencies: Vec<PackageDependency>,
        resources: Vec<PackageResource>,
        dialects: Vec<DialectDeclaration>,
        conformance_suites: Vec<ConformanceSuiteDeclaration>,
        capabilities: Vec<CapabilitySpec>,
        implementation_offers: Vec<ImplementationOfferDeclaration>,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, PackageManifestError> {
        let mut manifest = Self {
            package,
            content_digest: PackageDigest(format!("sha256:{}", "0".repeat(64))),
            dependencies,
            resources,
            dialects,
            conformance_suites,
            capabilities,
            implementation_offers,
            extensions,
        };
        manifest.validate_structure()?;
        manifest.content_digest = manifest.derived_content_digest()?;
        Ok(manifest)
    }

    /// Validates structure and the JCS content identity.
    ///
    /// This does not resolve referenced identities against dependency exports;
    /// an installer must do that with the exact declared dependency handles.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid declarations or a stale content digest.
    pub fn validate(&self) -> Result<(), PackageManifestError> {
        self.validate_structure()?;
        let expected = self.derived_content_digest()?;
        if self.content_digest != expected {
            return Err(PackageManifestError::ContentDigestMismatch {
                expected,
                actual: self.content_digest.clone(),
            });
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), PackageManifestError> {
        PackageId::parse(self.package.to_string()).map_err(|error| invalid("package", error))?;
        validate_extensions(
            "package root",
            &self.extensions,
            &[
                "protocol",
                "package",
                "content_digest",
                "dependencies",
                "resources",
                "dialects",
                "conformance_suites",
                "capabilities",
                "implementation_offers",
            ],
        )?;

        validate_dependencies(&self.package, &self.dependencies)?;
        let resource_names = validate_resources(&self.resources)?;
        validate_dialects(&self.dialects, &resource_names)?;
        validate_conformance_suites(&self.conformance_suites)?;
        validate_capabilities(&self.capabilities)?;
        validate_offers(&self.implementation_offers, &resource_names)?;
        Ok(())
    }

    fn derived_content_digest(&self) -> Result<PackageDigest, PackageManifestError> {
        let value = serde_json::to_value(WirePackageManifestBody::from(self))
            .map_err(|error| PackageManifestError::Serialization(error.to_string()))?;
        let bytes = canonical_json_bytes(&value)?;
        PackageDigest::parse(sha256_bytes(&bytes))
            .map_err(|error| PackageManifestError::Serialization(error.to_string()))
    }
}

/// Reads and validates one exact package/v1 JSON document.
///
/// Duplicate keys are rejected recursively before any typed decoding occurs.
///
/// # Errors
///
/// Returns an error for malformed JSON, duplicate keys, the wrong protocol,
/// invalid declarations, or an incorrect package content digest.
pub fn read_manifest(json: &str) -> Result<PackageManifest, PackageManifestError> {
    let raw = parse_strict_json(json)?;
    let protocol = raw.get("protocol").and_then(Value::as_str).ok_or_else(|| {
        PackageManifestError::Parse("root `protocol` must be a string".to_owned())
    })?;
    if protocol == LEGACY_PACK_PROTOCOL {
        return Err(PackageManifestError::LegacyPackV2);
    }
    if protocol != PACKAGE_PROTOCOL {
        return Err(PackageManifestError::ProtocolMismatch {
            expected: PACKAGE_PROTOCOL,
            actual: protocol.to_owned(),
        });
    }
    let raw_digest = manifest_value_digest(&raw)?;
    let wire: WirePackageManifest = serde_json::from_value(raw)
        .map_err(|error| PackageManifestError::Parse(error.to_string()))?;
    let manifest = PackageManifest::try_from(wire)?;
    manifest.validate_structure()?;
    if manifest.content_digest != raw_digest {
        return Err(PackageManifestError::ContentDigestMismatch {
            expected: raw_digest,
            actual: manifest.content_digest,
        });
    }
    manifest.validate()?;
    Ok(manifest)
}

/// Writes a validated package/v1 JSON document.
///
/// Validation occurs before flattening extensions, so an extension cannot
/// create a duplicate reserved field on this public serialization path.
///
/// # Errors
///
/// Returns an error when the semantic manifest is invalid or its digest is
/// stale, or when its JSON representation cannot be formed exactly.
pub fn write_manifest(manifest: &PackageManifest) -> Result<String, PackageManifestError> {
    manifest.validate()?;
    serde_json::to_string(&WirePackageManifest::from(manifest))
        .map_err(|error| PackageManifestError::Serialization(error.to_string()))
}

/// Structural package document failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageManifestError {
    Parse(String),
    DuplicateJsonKey(String),
    ProtocolMismatch {
        expected: &'static str,
        actual: String,
    },
    LegacyPackV2,
    InvalidField {
        scope: String,
        detail: String,
    },
    ReservedExtension {
        scope: String,
        key: String,
    },
    UnsortedOrDuplicateSet(String),
    UnknownResource {
        scope: String,
        resource: ResourceName,
    },
    InvalidCapability(String),
    ContentDigestMismatch {
        expected: PackageDigest,
        actual: PackageDigest,
    },
    CanonicalSemanticDrift,
    Serialization(String),
}

impl fmt::Display for PackageManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(detail) => {
                write!(formatter, "package manifest is not valid JSON: {detail}")
            }
            Self::DuplicateJsonKey(key) => write!(formatter, "duplicate JSON object key `{key}`"),
            Self::ProtocolMismatch { expected, actual } => {
                write!(
                    formatter,
                    "package declares protocol `{actual}`, expected `{expected}`"
                )
            }
            Self::LegacyPackV2 => write!(
                formatter,
                "legacy `{LEGACY_PACK_PROTOCOL}` is not `{PACKAGE_PROTOCOL}` and is never reinterpreted"
            ),
            Self::InvalidField { scope, detail } => write!(formatter, "invalid {scope}: {detail}"),
            Self::ReservedExtension { scope, key } => {
                write!(formatter, "{scope} extension `{key}` shadows a known field")
            }
            Self::UnsortedOrDuplicateSet(scope) => {
                write!(
                    formatter,
                    "{scope} must be strictly identity-sorted and unique"
                )
            }
            Self::UnknownResource { scope, resource } => {
                write!(
                    formatter,
                    "{scope} references unknown local resource `{resource}`"
                )
            }
            Self::InvalidCapability(detail) => write!(formatter, "invalid capability: {detail}"),
            Self::ContentDigestMismatch { expected, actual } => write!(
                formatter,
                "package content digest mismatch: expected {expected}, got {actual}"
            ),
            Self::CanonicalSemanticDrift => write!(
                formatter,
                "package cannot be represented by JCS without changing its JSON value"
            ),
            Self::Serialization(detail) => {
                write!(formatter, "package manifest serialization failed: {detail}")
            }
        }
    }
}

impl Error for PackageManifestError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WirePackageDependency {
    package: String,
    digest: String,
    #[serde(default, flatten)]
    extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WirePackageResource {
    name: String,
    path: String,
    media_type: String,
    size: u64,
    digest: String,
    #[serde(default, flatten)]
    extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WireValueKindDeclaration {
    id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_string"
    )]
    schema: Option<String>,
    #[serde(default, flatten)]
    extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WireDialectDeclaration {
    id: String,
    value_kinds: Vec<WireValueKindDeclaration>,
    #[serde(default, flatten)]
    extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WireConformanceSuiteDeclaration {
    id: String,
    #[serde(default, flatten)]
    extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WireInputPort {
    name: String,
    value_kind: String,
    acceptance: FactAcceptance,
    #[serde(default, flatten)]
    extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WireOutputPort {
    name: String,
    value_kind: String,
    #[serde(default, flatten)]
    extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WireCapabilitySpec {
    id: String,
    input_ports: Vec<WireInputPort>,
    output_ports: Vec<WireOutputPort>,
    default_conformance_suite: String,
    #[serde(default, flatten)]
    extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WireOfferDeclaration {
    implementation: String,
    capability: String,
    artifact: String,
    #[serde(default, flatten)]
    extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WirePackageManifest {
    protocol: String,
    package: String,
    content_digest: String,
    dependencies: Vec<WirePackageDependency>,
    resources: Vec<WirePackageResource>,
    dialects: Vec<WireDialectDeclaration>,
    conformance_suites: Vec<WireConformanceSuiteDeclaration>,
    capabilities: Vec<WireCapabilitySpec>,
    implementation_offers: Vec<WireOfferDeclaration>,
    #[serde(default, flatten)]
    extensions: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct WirePackageManifestBody {
    protocol: &'static str,
    package: String,
    dependencies: Vec<WirePackageDependency>,
    resources: Vec<WirePackageResource>,
    dialects: Vec<WireDialectDeclaration>,
    conformance_suites: Vec<WireConformanceSuiteDeclaration>,
    capabilities: Vec<WireCapabilitySpec>,
    implementation_offers: Vec<WireOfferDeclaration>,
    #[serde(flatten)]
    extensions: BTreeMap<String, Value>,
}

fn deserialize_present_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

impl From<&PackageManifest> for WirePackageManifestBody {
    fn from(manifest: &PackageManifest) -> Self {
        Self {
            protocol: PACKAGE_PROTOCOL,
            package: manifest.package.to_string(),
            dependencies: wire_dependencies(&manifest.dependencies),
            resources: wire_resources(&manifest.resources),
            dialects: wire_dialects(&manifest.dialects),
            conformance_suites: wire_conformance_suites(&manifest.conformance_suites),
            capabilities: wire_capabilities(&manifest.capabilities),
            implementation_offers: wire_offers(&manifest.implementation_offers),
            extensions: manifest.extensions.clone(),
        }
    }
}

impl From<&PackageManifest> for WirePackageManifest {
    fn from(manifest: &PackageManifest) -> Self {
        Self {
            protocol: PACKAGE_PROTOCOL.to_owned(),
            package: manifest.package.to_string(),
            content_digest: manifest.content_digest.to_string(),
            dependencies: wire_dependencies(&manifest.dependencies),
            resources: wire_resources(&manifest.resources),
            dialects: wire_dialects(&manifest.dialects),
            conformance_suites: wire_conformance_suites(&manifest.conformance_suites),
            capabilities: wire_capabilities(&manifest.capabilities),
            implementation_offers: wire_offers(&manifest.implementation_offers),
            extensions: manifest.extensions.clone(),
        }
    }
}

impl TryFrom<WirePackageManifest> for PackageManifest {
    type Error = PackageManifestError;

    fn try_from(wire: WirePackageManifest) -> Result<Self, Self::Error> {
        Ok(Self {
            package: PackageId::parse(wire.package).map_err(|error| invalid("package", error))?,
            content_digest: PackageDigest::parse(wire.content_digest)
                .map_err(|error| invalid("content_digest", error))?,
            dependencies: wire
                .dependencies
                .into_iter()
                .map(|dependency| {
                    Ok(PackageDependency {
                        package: PackageId::parse(dependency.package)
                            .map_err(|error| invalid("dependency package", error))?,
                        digest: PackageDigest::parse(dependency.digest)
                            .map_err(|error| invalid("dependency digest", error))?,
                        extensions: dependency.extensions,
                    })
                })
                .collect::<Result<_, PackageManifestError>>()?,
            resources: wire
                .resources
                .into_iter()
                .map(|resource| {
                    Ok(PackageResource {
                        name: ResourceName::parse(resource.name)
                            .map_err(|error| invalid("resource name", error))?,
                        path: resource.path,
                        media_type: resource.media_type,
                        size: resource.size,
                        digest: ResourceDigest::parse(resource.digest)
                            .map_err(|error| invalid("resource digest", error))?,
                        extensions: resource.extensions,
                    })
                })
                .collect::<Result<_, PackageManifestError>>()?,
            dialects: wire
                .dialects
                .into_iter()
                .map(parse_dialect)
                .collect::<Result<_, _>>()?,
            conformance_suites: wire
                .conformance_suites
                .into_iter()
                .map(|suite| {
                    Ok(ConformanceSuiteDeclaration {
                        id: ConformanceSuiteId::parse(&suite.id)
                            .map_err(|error| invalid("conformance suite", error))?,
                        extensions: suite.extensions,
                    })
                })
                .collect::<Result<_, PackageManifestError>>()?,
            capabilities: wire
                .capabilities
                .into_iter()
                .map(parse_capability)
                .collect::<Result<_, _>>()?,
            implementation_offers: wire
                .implementation_offers
                .into_iter()
                .map(|offer| {
                    Ok(ImplementationOfferDeclaration {
                        implementation: ImplementationId::parse(&offer.implementation)
                            .map_err(|error| invalid("offer implementation", error))?,
                        capability: CapabilityId::parse(&offer.capability)
                            .map_err(|error| invalid("offer capability", error))?,
                        artifact: ResourceName::parse(offer.artifact)
                            .map_err(|error| invalid("offer artifact", error))?,
                        extensions: offer.extensions,
                    })
                })
                .collect::<Result<_, PackageManifestError>>()?,
            extensions: wire.extensions,
        })
    }
}

fn parse_dialect(wire: WireDialectDeclaration) -> Result<DialectDeclaration, PackageManifestError> {
    Ok(DialectDeclaration {
        id: DialectId::parse(&wire.id).map_err(|error| invalid("dialect", error))?,
        value_kinds: wire
            .value_kinds
            .into_iter()
            .map(|value_kind| {
                Ok(ValueKindDeclaration {
                    id: ValueKindId::parse(&value_kind.id)
                        .map_err(|error| invalid("value kind", error))?,
                    schema: value_kind
                        .schema
                        .map(ResourceName::parse)
                        .transpose()
                        .map_err(|error| invalid("value kind schema", error))?,
                    extensions: value_kind.extensions,
                })
            })
            .collect::<Result<_, PackageManifestError>>()?,
        extensions: wire.extensions,
    })
}

fn parse_capability(wire: WireCapabilitySpec) -> Result<CapabilitySpec, PackageManifestError> {
    Ok(CapabilitySpec {
        id: CapabilityId::parse(&wire.id).map_err(|error| invalid("capability", error))?,
        input_ports: wire
            .input_ports
            .into_iter()
            .map(|port| {
                Ok(InputPort {
                    name: PortName::parse(port.name)
                        .map_err(|error| invalid("input port", error))?,
                    value_kind: ValueKindId::parse(&port.value_kind)
                        .map_err(|error| invalid("input value kind", error))?,
                    acceptance: port.acceptance,
                    extensions: port.extensions,
                })
            })
            .collect::<Result<_, PackageManifestError>>()?,
        output_ports: wire
            .output_ports
            .into_iter()
            .map(|port| {
                Ok(OutputPort {
                    name: PortName::parse(port.name)
                        .map_err(|error| invalid("output port", error))?,
                    value_kind: ValueKindId::parse(&port.value_kind)
                        .map_err(|error| invalid("output value kind", error))?,
                    extensions: port.extensions,
                })
            })
            .collect::<Result<_, PackageManifestError>>()?,
        default_conformance_suite: wire.default_conformance_suite,
        extensions: wire.extensions,
    })
}

fn wire_dependencies(items: &[PackageDependency]) -> Vec<WirePackageDependency> {
    items
        .iter()
        .map(|item| WirePackageDependency {
            package: item.package.to_string(),
            digest: item.digest.to_string(),
            extensions: item.extensions.clone(),
        })
        .collect()
}

fn wire_resources(items: &[PackageResource]) -> Vec<WirePackageResource> {
    items
        .iter()
        .map(|item| WirePackageResource {
            name: item.name.to_string(),
            path: item.path.clone(),
            media_type: item.media_type.clone(),
            size: item.size,
            digest: item.digest.to_string(),
            extensions: item.extensions.clone(),
        })
        .collect()
}

fn wire_dialects(items: &[DialectDeclaration]) -> Vec<WireDialectDeclaration> {
    items
        .iter()
        .map(|item| WireDialectDeclaration {
            id: item.id.to_string(),
            value_kinds: item
                .value_kinds
                .iter()
                .map(|value_kind| WireValueKindDeclaration {
                    id: value_kind.id.to_string(),
                    schema: value_kind.schema.as_ref().map(ToString::to_string),
                    extensions: value_kind.extensions.clone(),
                })
                .collect(),
            extensions: item.extensions.clone(),
        })
        .collect()
}

fn wire_conformance_suites(
    items: &[ConformanceSuiteDeclaration],
) -> Vec<WireConformanceSuiteDeclaration> {
    items
        .iter()
        .map(|item| WireConformanceSuiteDeclaration {
            id: item.id.to_string(),
            extensions: item.extensions.clone(),
        })
        .collect()
}

fn wire_capabilities(items: &[CapabilitySpec]) -> Vec<WireCapabilitySpec> {
    items
        .iter()
        .map(|item| WireCapabilitySpec {
            id: item.id.to_string(),
            input_ports: item
                .input_ports
                .iter()
                .map(|port| WireInputPort {
                    name: port.name.to_string(),
                    value_kind: port.value_kind.to_string(),
                    acceptance: port.acceptance,
                    extensions: port.extensions.clone(),
                })
                .collect(),
            output_ports: item
                .output_ports
                .iter()
                .map(|port| WireOutputPort {
                    name: port.name.to_string(),
                    value_kind: port.value_kind.to_string(),
                    extensions: port.extensions.clone(),
                })
                .collect(),
            default_conformance_suite: item.default_conformance_suite.clone(),
            extensions: item.extensions.clone(),
        })
        .collect()
}

fn wire_offers(items: &[ImplementationOfferDeclaration]) -> Vec<WireOfferDeclaration> {
    items
        .iter()
        .map(|item| WireOfferDeclaration {
            implementation: item.implementation.to_string(),
            capability: item.capability.to_string(),
            artifact: item.artifact.to_string(),
            extensions: item.extensions.clone(),
        })
        .collect()
}

fn offer_sort_key(
    offer: &ImplementationOfferDeclaration,
) -> (&CapabilityId, &ImplementationId, &ResourceName) {
    (&offer.capability, &offer.implementation, &offer.artifact)
}

fn validate_sorted_unique<T: Ord>(
    scope: &str,
    values: impl IntoIterator<Item = T>,
) -> Result<(), PackageManifestError> {
    let mut previous: Option<T> = None;
    for value in values {
        if previous.as_ref().is_some_and(|previous| previous >= &value) {
            return Err(PackageManifestError::UnsortedOrDuplicateSet(
                scope.to_owned(),
            ));
        }
        previous = Some(value);
    }
    Ok(())
}

fn validate_dependencies(
    package: &PackageId,
    dependencies: &[PackageDependency],
) -> Result<(), PackageManifestError> {
    validate_sorted_unique(
        "dependencies",
        dependencies.iter().map(|item| &item.package),
    )?;
    for dependency in dependencies {
        if dependency.package == *package {
            return Err(PackageManifestError::InvalidField {
                scope: "dependency".to_owned(),
                detail: "a package cannot depend on itself".to_owned(),
            });
        }
        validate_extensions(
            &format!("dependency `{}`", dependency.package),
            &dependency.extensions,
            &["package", "digest"],
        )?;
    }
    Ok(())
}

fn validate_resources(
    resources: &[PackageResource],
) -> Result<BTreeSet<ResourceName>, PackageManifestError> {
    validate_sorted_unique("resources", resources.iter().map(|item| &item.name))?;
    for resource in resources {
        validate_resource(resource)?;
    }
    Ok(resources
        .iter()
        .map(|resource| resource.name.clone())
        .collect())
}

fn validate_dialects(
    dialects: &[DialectDeclaration],
    resource_names: &BTreeSet<ResourceName>,
) -> Result<(), PackageManifestError> {
    validate_sorted_unique("dialects", dialects.iter().map(|item| &item.id))?;
    for dialect in dialects {
        if !dialect.id.is_well_formed() {
            return Err(PackageManifestError::InvalidField {
                scope: format!("dialect `{}`", dialect.id),
                detail: "dialect identity is malformed".to_owned(),
            });
        }
        validate_extensions(
            &format!("dialect `{}`", dialect.id),
            &dialect.extensions,
            &["id", "value_kinds"],
        )?;
        validate_sorted_unique(
            &format!("value kinds in dialect `{}`", dialect.id),
            dialect.value_kinds.iter().map(|item| &item.id),
        )?;
        for value_kind in &dialect.value_kinds {
            if !value_kind.id.is_well_formed() || value_kind.id.dialect() != dialect.id {
                return Err(PackageManifestError::InvalidField {
                    scope: format!("value kind `{}`", value_kind.id),
                    detail: format!("identity is not owned by dialect `{}`", dialect.id),
                });
            }
            if let Some(schema) = &value_kind.schema
                && !resource_names.contains(schema)
            {
                return Err(PackageManifestError::UnknownResource {
                    scope: format!("value kind `{}` schema", value_kind.id),
                    resource: schema.clone(),
                });
            }
            validate_extensions(
                &format!("value kind `{}`", value_kind.id),
                &value_kind.extensions,
                &["id", "schema"],
            )?;
        }
    }
    Ok(())
}

fn validate_capabilities(capabilities: &[CapabilitySpec]) -> Result<(), PackageManifestError> {
    validate_sorted_unique("capabilities", capabilities.iter().map(|item| &item.id))?;
    let mut registry = CapabilityRegistry::default();
    for capability in capabilities {
        ConformanceSuiteId::parse(&capability.default_conformance_suite)
            .map_err(|error| invalid("capability conformance suite", error))?;
        registry
            .register_spec(capability.clone())
            .map_err(|error| PackageManifestError::InvalidCapability(error.to_string()))?;
    }
    Ok(())
}

fn validate_conformance_suites(
    suites: &[ConformanceSuiteDeclaration],
) -> Result<(), PackageManifestError> {
    validate_sorted_unique("conformance suites", suites.iter().map(|suite| &suite.id))?;
    for suite in suites {
        ConformanceSuiteId::parse(&suite.id.to_string())
            .map_err(|error| invalid("conformance suite", error))?;
        validate_extensions(
            &format!("conformance suite `{}`", suite.id),
            &suite.extensions,
            &["id"],
        )?;
    }
    Ok(())
}

fn validate_offers(
    offers: &[ImplementationOfferDeclaration],
    resource_names: &BTreeSet<ResourceName>,
) -> Result<(), PackageManifestError> {
    validate_sorted_unique("implementation offers", offers.iter().map(offer_sort_key))?;
    for offer in offers {
        if !offer.implementation.is_well_formed() || !offer.capability.is_well_formed() {
            return Err(PackageManifestError::InvalidField {
                scope: format!("implementation offer `{}`", offer.implementation),
                detail: "implementation or capability identity is malformed".to_owned(),
            });
        }
        if !resource_names.contains(&offer.artifact) {
            return Err(PackageManifestError::UnknownResource {
                scope: format!("implementation offer `{}`", offer.implementation),
                resource: offer.artifact.clone(),
            });
        }
        validate_extensions(
            &format!("implementation offer `{}`", offer.implementation),
            &offer.extensions,
            &["implementation", "capability", "artifact"],
        )?;
    }
    Ok(())
}

fn validate_resource(resource: &PackageResource) -> Result<(), PackageManifestError> {
    ResourceName::parse(resource.name.to_string())
        .map_err(|error| invalid("resource name", error))?;
    if resource.path.is_empty()
        || resource.path.len() > MAX_RESOURCE_PATH_BYTES
        || resource.path.starts_with('/')
        || resource.path.ends_with('/')
        || resource.path.contains('\\')
        || has_windows_drive_prefix(&resource.path)
        || resource.path.chars().any(char::is_control)
        || resource
            .path
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(PackageManifestError::InvalidField {
            scope: format!("resource `{}` path", resource.name),
            detail: "must be a safe relative portable path".to_owned(),
        });
    }
    if resource.media_type.is_empty()
        || resource.media_type.len() > MAX_MEDIA_TYPE_BYTES
        || resource.media_type.trim() != resource.media_type
        || resource.media_type.chars().any(char::is_control)
    {
        return Err(PackageManifestError::InvalidField {
            scope: format!("resource `{}` media_type", resource.name),
            detail: "must be a nonblank exact media type".to_owned(),
        });
    }
    if resource.size > MAX_JCS_SAFE_INTEGER {
        return Err(PackageManifestError::InvalidField {
            scope: format!("resource `{}` size", resource.name),
            detail: "must be an I-JSON safe integer".to_owned(),
        });
    }
    validate_extensions(
        &format!("resource `{}`", resource.name),
        &resource.extensions,
        &["name", "path", "media_type", "size", "digest"],
    )
}

fn validate_extensions(
    scope: &str,
    extensions: &BTreeMap<String, Value>,
    reserved: &[&str],
) -> Result<(), PackageManifestError> {
    if let Some(key) = reserved.iter().find(|key| extensions.contains_key(**key)) {
        Err(PackageManifestError::ReservedExtension {
            scope: scope.to_owned(),
            key: (*key).to_owned(),
        })
    } else {
        Ok(())
    }
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn invalid(scope: &str, error: impl fmt::Display) -> PackageManifestError {
    PackageManifestError::InvalidField {
        scope: scope.to_owned(),
        detail: error.to_string(),
    }
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut identity = String::with_capacity(71);
    identity.push_str("sha256:");
    for byte in digest {
        use fmt::Write as _;
        write!(identity, "{byte:02x}").expect("writing to a string cannot fail");
    }
    identity
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, PackageManifestError> {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .map_err(|error| PackageManifestError::Serialization(error.to_string()))?;
    let round_trip: Value = serde_json::from_slice(&bytes)
        .map_err(|error| PackageManifestError::Serialization(error.to_string()))?;
    if &round_trip != value {
        return Err(PackageManifestError::CanonicalSemanticDrift);
    }
    Ok(bytes)
}

fn manifest_value_digest(value: &Value) -> Result<PackageDigest, PackageManifestError> {
    let mut body = value.clone();
    let object = body.as_object_mut().ok_or_else(|| {
        PackageManifestError::Parse("package manifest root must be an object".to_owned())
    })?;
    if object.remove("content_digest").is_none() {
        return Err(PackageManifestError::Parse(
            "package manifest omitted root `content_digest`".to_owned(),
        ));
    }
    let bytes = canonical_json_bytes(&body)?;
    PackageDigest::parse(sha256_bytes(&bytes))
        .map_err(|error| PackageManifestError::Serialization(error.to_string()))
}

fn parse_strict_json(input: &str) -> Result<Value, PackageManifestError> {
    strict_json::from_str(input).map_err(|error| match error {
        StrictJsonError::DuplicateObjectKey(key) => PackageManifestError::DuplicateJsonKey(key),
        StrictJsonError::Invalid(detail) => PackageManifestError::Parse(detail),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn resource(name: &str, path: &str, byte: char) -> PackageResource {
        PackageResource {
            name: ResourceName::parse(name).unwrap(),
            path: path.to_owned(),
            media_type: "application/octet-stream".to_owned(),
            size: 17,
            digest: ResourceDigest::parse(digest(byte)).unwrap(),
            extensions: BTreeMap::new(),
        }
    }

    fn kind(dialect: &DialectId, name: &str, schema: Option<&str>) -> ValueKindDeclaration {
        ValueKindDeclaration {
            id: ValueKindId::in_dialect(dialect.clone(), name),
            schema: schema.map(|name| ResourceName::parse(name).unwrap()),
            extensions: BTreeMap::new(),
        }
    }

    fn port(name: &str) -> PortName {
        PortName::parse(name).unwrap()
    }

    fn sample_manifest() -> PackageManifest {
        let dialect = DialectId::new("org.example.model", "1.0.0");
        let source = ValueKindId::in_dialect(dialect.clone(), "source");
        let output = ValueKindId::in_dialect(dialect.clone(), "output");
        let capability = CapabilitySpec {
            id: CapabilityId::new("org.example.capability", "convert", "1.0.0"),
            input_ports: vec![
                InputPort::complete(port("right"), source.clone()),
                InputPort::complete(port("left"), source),
            ],
            output_ports: vec![OutputPort::new(port("result"), output)],
            default_conformance_suite: "org.example.conformance/convert@1.0.0".to_owned(),
            extensions: BTreeMap::new(),
        };
        PackageManifest::new(
            PackageId::parse("org.example.package@1.0.0").unwrap(),
            vec![PackageDependency {
                package: PackageId::parse("org.example.dependency@2.0.0").unwrap(),
                digest: PackageDigest::parse(digest('a')).unwrap(),
                extensions: BTreeMap::new(),
            }],
            vec![
                resource("implementation", "bin/provider", 'b'),
                resource("schema", "schemas/model.json", 'c'),
            ],
            vec![DialectDeclaration {
                id: dialect.clone(),
                value_kinds: vec![
                    kind(&dialect, "output", None),
                    kind(&dialect, "source", Some("schema")),
                ],
                extensions: BTreeMap::new(),
            }],
            vec![ConformanceSuiteDeclaration {
                id: ConformanceSuiteId::parse("org.example.conformance/convert@1.0.0").unwrap(),
                extensions: BTreeMap::new(),
            }],
            vec![capability.clone()],
            vec![ImplementationOfferDeclaration {
                implementation: ImplementationId::new(
                    "org.example.implementation",
                    "convert",
                    "1.0.0",
                ),
                capability: capability.id,
                artifact: ResourceName::parse("implementation").unwrap(),
                extensions: BTreeMap::new(),
            }],
            BTreeMap::new(),
        )
        .unwrap()
    }

    #[test]
    fn exact_manifest_round_trips_and_preserves_port_order() {
        let manifest = sample_manifest();
        let encoded = write_manifest(&manifest).unwrap();
        let decoded = read_manifest(&encoded).unwrap();
        assert_eq!(decoded, manifest);
        assert_eq!(
            decoded.capabilities[0]
                .input_ports
                .iter()
                .map(|port| port.name.as_str())
                .collect::<Vec<_>>(),
            ["right", "left"]
        );
        assert_eq!(
            decoded.capabilities[0].input_ports[0].value_kind,
            decoded.capabilities[0].input_ports[1].value_kind
        );
    }

    #[test]
    fn package_identity_rejects_padded_or_controlled_display_forms() {
        assert_eq!(
            PackageId::parse("org.example@1.0.0").unwrap().as_str(),
            "org.example@1.0.0"
        );
        for malformed in [
            " org.example@1.0.0",
            "org.example@1.0.0 ",
            "org.example @1.0.0",
            "org.example@ 1.0.0",
            "org.example\n@1.0.0",
            "org.example@1.0.0\u{7f}",
        ] {
            assert!(
                PackageId::parse(malformed).is_err(),
                "accepted {malformed:?}"
            );
        }
    }

    #[test]
    fn unknown_extensions_survive_every_scope_and_array_order_is_content() {
        let mut manifest = sample_manifest();
        manifest
            .extensions
            .insert("x.root".to_owned(), json!([3, 1, 2]));
        manifest.dependencies[0]
            .extensions
            .insert("x.dependency".to_owned(), json!({"opaque": true}));
        manifest.resources[0]
            .extensions
            .insert("x.resource".to_owned(), json!(["b", "a"]));
        manifest.dialects[0]
            .extensions
            .insert("x.dialect".to_owned(), json!(1));
        manifest.dialects[0].value_kinds[0]
            .extensions
            .insert("x.kind".to_owned(), json!([2, 1]));
        manifest.conformance_suites[0]
            .extensions
            .insert("x.suite".to_owned(), json!(["opaque", 1]));
        manifest.capabilities[0]
            .extensions
            .insert("x.capability".to_owned(), json!(["z", "a"]));
        manifest.capabilities[0].input_ports[0]
            .extensions
            .insert("x.input".to_owned(), json!([2, 1]));
        manifest.capabilities[0].output_ports[0]
            .extensions
            .insert("x.output".to_owned(), json!({"v": null}));
        manifest.implementation_offers[0]
            .extensions
            .insert("x.offer".to_owned(), json!([false, true]));
        manifest = PackageManifest::new(
            manifest.package,
            manifest.dependencies,
            manifest.resources,
            manifest.dialects,
            manifest.conformance_suites,
            manifest.capabilities,
            manifest.implementation_offers,
            manifest.extensions,
        )
        .unwrap();

        let round_trip = read_manifest(&write_manifest(&manifest).unwrap()).unwrap();
        assert_eq!(round_trip, manifest);
        assert_eq!(round_trip.extensions["x.root"], json!([3, 1, 2]));

        let mut changed = manifest.clone();
        changed
            .extensions
            .insert("x.root".to_owned(), json!([1, 2, 3]));
        changed = PackageManifest::new(
            changed.package,
            changed.dependencies,
            changed.resources,
            changed.dialects,
            changed.conformance_suites,
            changed.capabilities,
            changed.implementation_offers,
            changed.extensions,
        )
        .unwrap();
        assert_ne!(manifest.content_digest, changed.content_digest);
    }

    #[test]
    fn duplicate_json_keys_are_refused_recursively() {
        let encoded = write_manifest(&sample_manifest()).unwrap();
        let duplicate_root = encoded.replacen(
            &format!("\"protocol\":\"{PACKAGE_PROTOCOL}\""),
            &format!("\"protocol\":\"{PACKAGE_PROTOCOL}\",\"protocol\":\"{PACKAGE_PROTOCOL}\""),
            1,
        );
        assert!(matches!(
            read_manifest(&duplicate_root),
            Err(PackageManifestError::DuplicateJsonKey(key)) if key == "protocol"
        ));

        let nested = encoded.replacen("\"x\":1", "\"x\":1,\"x\":2", 1);
        assert_eq!(
            nested, encoded,
            "sample has no accidental extension fixture"
        );
        let raw = r#"{"outer":{"same":1,"same":2}}"#;
        assert!(matches!(
            parse_strict_json(raw),
            Err(PackageManifestError::DuplicateJsonKey(key)) if key == "same"
        ));
    }

    #[test]
    fn reserved_extension_shadowing_is_refused_before_write() {
        let mut root = sample_manifest();
        root.extensions.insert("protocol".to_owned(), json!(null));
        assert!(matches!(
            write_manifest(&root),
            Err(PackageManifestError::ReservedExtension { scope, key })
                if scope == "package root" && key == "protocol"
        ));

        let mut offer = sample_manifest();
        offer.implementation_offers[0]
            .extensions
            .insert("artifact".to_owned(), json!(null));
        assert!(matches!(
            write_manifest(&offer),
            Err(PackageManifestError::ReservedExtension { key, .. }) if key == "artifact"
        ));

        let mut suite = sample_manifest();
        suite.conformance_suites[0]
            .extensions
            .insert("id".to_owned(), json!(null));
        assert!(matches!(
            write_manifest(&suite),
            Err(PackageManifestError::ReservedExtension { scope, key })
                if scope.starts_with("conformance suite") && key == "id"
        ));
    }

    #[test]
    fn known_set_arrays_must_be_strictly_identity_sorted() {
        let mut resources = sample_manifest();
        resources.resources.swap(0, 1);
        assert!(matches!(
            write_manifest(&resources),
            Err(PackageManifestError::UnsortedOrDuplicateSet(scope)) if scope == "resources"
        ));

        let mut kinds = sample_manifest();
        kinds.dialects[0].value_kinds.swap(0, 1);
        assert!(matches!(
            write_manifest(&kinds),
            Err(PackageManifestError::UnsortedOrDuplicateSet(scope))
                if scope.starts_with("value kinds")
        ));

        let mut duplicate = sample_manifest();
        duplicate
            .dependencies
            .push(duplicate.dependencies[0].clone());
        assert!(matches!(
            write_manifest(&duplicate),
            Err(PackageManifestError::UnsortedOrDuplicateSet(scope)) if scope == "dependencies"
        ));

        let mut duplicate_suite = sample_manifest();
        duplicate_suite
            .conformance_suites
            .push(duplicate_suite.conformance_suites[0].clone());
        assert!(matches!(
            write_manifest(&duplicate_suite),
            Err(PackageManifestError::UnsortedOrDuplicateSet(scope))
                if scope == "conformance suites"
        ));
    }

    #[test]
    fn arbitrary_default_conformance_suite_identity_is_refused() {
        let encoded = write_manifest(&sample_manifest()).unwrap();
        let mut value: Value = serde_json::from_str(&encoded).unwrap();
        value["capabilities"][0]["default_conformance_suite"] = json!("arbitrary");
        let malformed = serde_json::to_string(&value).unwrap();
        assert!(matches!(
            read_manifest(&malformed),
            Err(PackageManifestError::InvalidField { scope, .. })
                if scope == "capability conformance suite"
        ));
    }

    #[test]
    fn dialect_owns_each_declared_value_kind() {
        let mut manifest = sample_manifest();
        manifest.dialects[0].value_kinds[1].id = ValueKindId::new("org.other", "source", "1.0.0");
        assert!(matches!(
            write_manifest(&manifest),
            Err(PackageManifestError::InvalidField { scope, detail })
                if scope.contains("value kind") && detail.contains("not owned")
        ));
    }

    #[test]
    fn schema_is_only_an_optional_opaque_local_resource_reference() {
        let manifest = sample_manifest();
        let schema = &manifest.dialects[0].value_kinds[1];
        assert_eq!(schema.schema.as_ref().unwrap().as_str(), "schema");

        let mut missing = manifest;
        missing.dialects[0].value_kinds[1].schema =
            Some(ResourceName::parse("not-declared").unwrap());
        assert!(matches!(
            write_manifest(&missing),
            Err(PackageManifestError::UnknownResource { scope, .. })
                if scope.contains("schema")
        ));

        let encoded = write_manifest(&sample_manifest()).unwrap();
        let explicit_null = encoded.replacen("\"schema\":\"schema\"", "\"schema\":null", 1);
        assert!(matches!(
            read_manifest(&explicit_null),
            Err(PackageManifestError::Parse(_))
        ));
    }

    #[test]
    fn offer_declaration_has_no_measured_digest_or_offer_identity() {
        let encoded = write_manifest(&sample_manifest()).unwrap();
        let value: Value = serde_json::from_str(&encoded).unwrap();
        let offer = value["implementation_offers"][0].as_object().unwrap();
        assert_eq!(
            offer.keys().cloned().collect::<BTreeSet<_>>(),
            ["artifact", "capability", "implementation"]
                .map(str::to_owned)
                .into_iter()
                .collect()
        );
        assert!(!offer.contains_key("artifact_digest"));
        assert!(!offer.contains_key("offer_id"));
    }

    #[test]
    fn jcs_digest_excludes_only_the_root_digest_and_rejects_number_drift() {
        let manifest = sample_manifest();
        let encoded = write_manifest(&manifest).unwrap();
        let mut value: Value = serde_json::from_str(&encoded).unwrap();
        value["content_digest"] = Value::String(digest('f'));
        let tampered = serde_json::to_string(&value).unwrap();
        assert!(matches!(
            read_manifest(&tampered),
            Err(PackageManifestError::ContentDigestMismatch { .. })
        ));

        let mut unsafe_number = sample_manifest();
        unsafe_number
            .extensions
            .insert("x.unsafe".to_owned(), Value::Number(u64::MAX.into()));
        assert!(matches!(
            PackageManifest::new(
                unsafe_number.package,
                unsafe_number.dependencies,
                unsafe_number.resources,
                unsafe_number.dialects,
                unsafe_number.conformance_suites,
                unsafe_number.capabilities,
                unsafe_number.implementation_offers,
                unsafe_number.extensions,
            ),
            Err(PackageManifestError::CanonicalSemanticDrift)
        ));
    }

    #[test]
    fn jcs_uses_utf16_property_order_instead_of_rust_string_order() {
        let value = json!({
            "\u{e000}": 1,
            "\u{1f600}": 2
        });
        let canonical = canonical_json_bytes(&value).unwrap();
        assert_eq!(String::from_utf8(canonical).unwrap(), "{\"😀\":2,\"\":1}");
    }

    #[test]
    fn legacy_pack_v2_is_explicitly_refused() {
        let legacy = format!(r#"{{"protocol":"{LEGACY_PACK_PROTOCOL}","capabilities":[]}}"#);
        assert_eq!(
            read_manifest(&legacy),
            Err(PackageManifestError::LegacyPackV2)
        );
    }

    #[test]
    fn paths_and_resource_references_are_structural_only_but_fail_closed() {
        let mut unsafe_path = sample_manifest();
        unsafe_path.resources[0].path = "../provider".to_owned();
        assert!(matches!(
            write_manifest(&unsafe_path),
            Err(PackageManifestError::InvalidField { scope, .. }) if scope.contains("path")
        ));

        for windows_prefixed in ["C:/provider", "C:provider"] {
            let mut unsafe_path = sample_manifest();
            unsafe_path.resources[0].path = windows_prefixed.to_owned();
            assert!(matches!(
                write_manifest(&unsafe_path),
                Err(PackageManifestError::InvalidField { scope, .. }) if scope.contains("path")
            ));
        }

        let mut missing_artifact = sample_manifest();
        missing_artifact.implementation_offers[0].artifact =
            ResourceName::parse("missing").unwrap();
        assert!(matches!(
            write_manifest(&missing_artifact),
            Err(PackageManifestError::UnknownResource { scope, .. })
                if scope.contains("implementation offer")
        ));
    }
}
