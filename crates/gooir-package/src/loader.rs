//! Descriptor-anchored copying and validation of one local package directory.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use gooir_capability::protocol::{
    ArtifactDigest, CapabilityOffer, ConformanceSuiteId, OfferId, ProtocolError,
};
use gooir_capability::{CapabilityId, ValueKindId};
use rustix::fs::{Mode, OFlags, open, openat};

use crate::registry::{InstalledPackage, PackageRegistry};
use crate::{
    PackageDigest, PackageId, PackageManifest, PackageManifestError, PackageResource,
    ResourceDigest, ResourceName, read_manifest, sha256_bytes,
};

/// Fixed package manifest name below the supplied directory anchor.
pub const PACKAGE_MANIFEST_FILE: &str = "gooir-package.json";

/// Explicit byte and declaration bounds for one local load.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadLimits {
    pub max_manifest_bytes: u64,
    pub max_resources: usize,
    pub max_resource_bytes: u64,
    pub max_total_resource_bytes: u64,
}

impl Default for LoadLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 4 * 1024 * 1024,
            max_resources: 4_096,
            max_resource_bytes: 256 * 1024 * 1024,
            max_total_resource_bytes: 1024 * 1024 * 1024,
        }
    }
}

/// Exact package-local bytes copied into loader-owned memory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedResource {
    declaration: PackageResource,
    bytes: Arc<[u8]>,
}

impl OwnedResource {
    #[must_use]
    pub fn name(&self) -> &ResourceName {
        &self.declaration.name
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.declaration.path
    }

    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.declaration.media_type
    }

    #[must_use]
    pub fn digest(&self) -> &ResourceDigest {
        &self.declaration.digest
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ValidatedOffer {
    pub(crate) offer: CapabilityOffer,
    pub(crate) artifact: OwnedResource,
}

/// Non-constructible result of copying and validating one local package.
///
/// It owns every byte used to derive resource and offer identities. The source
/// directory need not remain present or unchanged after this value is returned.
#[derive(Clone, Debug)]
pub struct ValidatedPackage {
    pub(crate) manifest: Arc<PackageManifest>,
    pub(crate) manifest_bytes: Arc<[u8]>,
    pub(crate) resources: BTreeMap<ResourceName, OwnedResource>,
    pub(crate) offers: BTreeMap<OfferId, ValidatedOffer>,
    pub(crate) dependencies: Vec<InstalledPackage>,
}

impl ValidatedPackage {
    #[must_use]
    pub fn manifest(&self) -> &PackageManifest {
        &self.manifest
    }

    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    #[must_use]
    pub fn resource(&self, name: &ResourceName) -> Option<&OwnedResource> {
        self.resources.get(name)
    }

    pub fn resources(&self) -> impl Iterator<Item = &OwnedResource> {
        self.resources.values()
    }

    pub fn offers(&self) -> impl Iterator<Item = &CapabilityOffer> {
        self.offers.values().map(|validated| &validated.offer)
    }

    #[must_use]
    pub fn offer_artifact(&self, id: &OfferId) -> Option<&OwnedResource> {
        self.offers.get(id).map(|validated| &validated.artifact)
    }

    pub(crate) fn validate_against(
        &self,
        registry: &PackageRegistry,
    ) -> Result<(), PackageLoadError> {
        self.manifest.validate()?;
        let exact_dependencies = registry.exact_dependencies(&self.manifest.dependencies)?;
        if exact_dependencies.len() != self.dependencies.len()
            || exact_dependencies
                .iter()
                .zip(&self.dependencies)
                .any(|(current, captured)| {
                    current.package_id() != captured.package_id()
                        || current.digest() != captured.digest()
                })
        {
            return Err(PackageLoadError::DependencyHandleMismatch);
        }
        validate_external_ownership(&self.manifest, registry)?;
        for resource in &self.manifest.resources {
            let owned = self.resources.get(&resource.name).ok_or_else(|| {
                PackageLoadError::ResourceMissingAfterValidation(resource.name.clone())
            })?;
            if owned.declaration != *resource
                || owned.bytes.len() as u64 != resource.size
                || sha256_bytes(&owned.bytes) != resource.digest.as_str()
            {
                return Err(PackageLoadError::ResourceChanged(resource.name.clone()));
            }
        }
        for validated in self.offers.values() {
            validated.offer.validate()?;
            if validated.offer.artifact_digest.as_str() != validated.artifact.digest().as_str() {
                return Err(PackageLoadError::OfferArtifactMismatch(
                    validated.offer.offer_id.clone(),
                ));
            }
        }
        Ok(())
    }
}

/// Copies and validates one package rooted at an explicitly supplied local
/// directory and resolves only its exact declared direct dependencies.
///
/// The final directory itself is opened with no-follow, then the fixed
/// manifest and every resource path are traversed one component at a time from
/// retained directory descriptors. Every component is opened no-follow and
/// every final descriptor must be a bounded regular file. The loader accepts
/// hardlinks: it authenticates only the exact copied length and SHA-256 bytes.
///
/// The caller remains responsible for the origin of the supplied directory
/// path and its ancestor namespace. A cooperating or hostile writer may mutate
/// source files concurrently; this API neither locks nor claims source
/// immutability. It retains only copied bytes whose complete value matched the
/// manifest at load time, so later rename, replacement, or mutation cannot
/// alter a returned [`ValidatedPackage`].
///
/// # Errors
///
/// Returns an error for unsafe filesystem entries, exceeded bounds, malformed
/// or mismatched bytes, unavailable exact dependencies, unresolved external
/// ownership, or an offer that cannot be derived exactly.
pub fn load_local_package(
    directory: impl AsRef<Path>,
    dependency_catalog: &PackageRegistry,
    limits: LoadLimits,
) -> Result<ValidatedPackage, PackageLoadError> {
    validate_limits(limits)?;
    let root = open_root(directory.as_ref())?;
    let manifest_file = open_relative_regular(&root, PACKAGE_MANIFEST_FILE, "package manifest")?;
    let manifest_bytes = read_bounded(manifest_file, limits.max_manifest_bytes, None, "manifest")?;
    let manifest_json =
        std::str::from_utf8(&manifest_bytes).map_err(|_| PackageLoadError::ManifestNotUtf8)?;
    let manifest = Arc::new(read_manifest(manifest_json)?);

    if manifest.resources.len() > limits.max_resources {
        return Err(PackageLoadError::ResourceCountExceeded {
            actual: manifest.resources.len(),
            limit: limits.max_resources,
        });
    }
    let total = manifest
        .resources
        .iter()
        .try_fold(0_u64, |total, resource| {
            if resource.size > limits.max_resource_bytes {
                return Err(PackageLoadError::ResourceLimitExceeded {
                    resource: resource.name.clone(),
                    declared: resource.size,
                    limit: limits.max_resource_bytes,
                });
            }
            total
                .checked_add(resource.size)
                .ok_or(PackageLoadError::TotalResourceLimitExceeded {
                    declared: u64::MAX,
                    limit: limits.max_total_resource_bytes,
                })
        })?;
    if total > limits.max_total_resource_bytes {
        return Err(PackageLoadError::TotalResourceLimitExceeded {
            declared: total,
            limit: limits.max_total_resource_bytes,
        });
    }

    let dependencies = dependency_catalog.exact_dependencies(&manifest.dependencies)?;
    validate_external_ownership(&manifest, dependency_catalog)?;

    let mut resources = BTreeMap::new();
    for declaration in &manifest.resources {
        let file = open_relative_regular(&root, &declaration.path, "package resource")?;
        let bytes = read_bounded(
            file,
            limits.max_resource_bytes,
            Some(declaration.size),
            &format!("resource `{}`", declaration.name),
        )?;
        let actual = ResourceDigest::parse(sha256_bytes(&bytes))
            .map_err(|error| PackageLoadError::InternalDigest(error.to_string()))?;
        if actual != declaration.digest {
            return Err(PackageLoadError::ResourceDigestMismatch {
                resource: declaration.name.clone(),
                expected: declaration.digest.clone(),
                actual,
            });
        }
        resources.insert(
            declaration.name.clone(),
            OwnedResource {
                declaration: declaration.clone(),
                bytes: Arc::from(bytes),
            },
        );
    }

    let offers = derive_offers(&manifest, &resources)?;
    let package = ValidatedPackage {
        manifest,
        manifest_bytes: Arc::from(manifest_bytes),
        resources,
        offers,
        dependencies,
    };
    package.validate_against(dependency_catalog)?;
    Ok(package)
}

fn validate_limits(limits: LoadLimits) -> Result<(), PackageLoadError> {
    if limits.max_manifest_bytes == 0
        || limits.max_resources == 0
        || limits.max_resource_bytes == 0
        || limits.max_total_resource_bytes == 0
    {
        return Err(PackageLoadError::InvalidLimits);
    }
    Ok(())
}

fn open_root(path: &Path) -> Result<File, PackageLoadError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| fs_error("package directory", error))?;
    let file = File::from(descriptor);
    if !file
        .metadata()
        .map_err(|error| fs_error("package directory metadata", error))?
        .is_dir()
    {
        return Err(PackageLoadError::NotDirectory);
    }
    Ok(file)
}

fn open_relative_regular(
    root: &File,
    relative: &str,
    scope: &'static str,
) -> Result<File, PackageLoadError> {
    let mut components = relative.split('/').peekable();
    let mut directory = root
        .try_clone()
        .map_err(|error| fs_error("package directory clone", error))?;
    while let Some(component) = components.next() {
        let is_final = components.peek().is_none();
        let flags = OFlags::RDONLY
            | OFlags::NOFOLLOW
            | OFlags::CLOEXEC
            | OFlags::NONBLOCK
            | if is_final {
                OFlags::empty()
            } else {
                OFlags::DIRECTORY
            };
        let descriptor = openat(&directory, component, flags, Mode::empty())
            .map_err(|error| fs_error(scope, error))?;
        let opened = File::from(descriptor);
        let metadata = opened.metadata().map_err(|error| fs_error(scope, error))?;
        if is_final {
            if !metadata.is_file() {
                return Err(PackageLoadError::NotRegularFile {
                    scope: scope.to_owned(),
                });
            }
            return Ok(opened);
        }
        if !metadata.is_dir() {
            return Err(PackageLoadError::NotDirectoryComponent {
                scope: scope.to_owned(),
                component: component.to_owned(),
            });
        }
        directory = opened;
    }
    Err(PackageLoadError::Filesystem {
        scope: scope.to_owned(),
        detail: "empty relative path".to_owned(),
    })
}

fn read_bounded(
    mut file: File,
    limit: u64,
    exact_size: Option<u64>,
    scope: &str,
) -> Result<Vec<u8>, PackageLoadError> {
    let metadata_size = file
        .metadata()
        .map_err(|error| fs_error(scope, error))?
        .len();
    if metadata_size > limit {
        return Err(PackageLoadError::ByteLimitExceeded {
            scope: scope.to_owned(),
            actual: metadata_size,
            limit,
        });
    }
    if let Some(expected) = exact_size
        && metadata_size != expected
    {
        return Err(PackageLoadError::ResourceSizeMismatch {
            scope: scope.to_owned(),
            expected,
            actual: metadata_size,
        });
    }

    let read_limit = exact_size.unwrap_or(limit).saturating_add(1);
    let capacity = usize::try_from(metadata_size.min(read_limit)).map_err(|_| {
        PackageLoadError::ByteLimitExceeded {
            scope: scope.to_owned(),
            actual: metadata_size,
            limit,
        }
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| fs_error(scope, error))?;
    let actual = u64::try_from(bytes.len()).map_err(|_| PackageLoadError::ByteLimitExceeded {
        scope: scope.to_owned(),
        actual: u64::MAX,
        limit,
    })?;
    if actual > limit {
        return Err(PackageLoadError::ByteLimitExceeded {
            scope: scope.to_owned(),
            actual,
            limit,
        });
    }
    if let Some(expected) = exact_size
        && actual != expected
    {
        return Err(PackageLoadError::ResourceSizeMismatch {
            scope: scope.to_owned(),
            expected,
            actual,
        });
    }
    Ok(bytes)
}

fn derive_offers(
    manifest: &PackageManifest,
    resources: &BTreeMap<ResourceName, OwnedResource>,
) -> Result<BTreeMap<OfferId, ValidatedOffer>, PackageLoadError> {
    let mut offers = BTreeMap::new();
    for declaration in &manifest.implementation_offers {
        let artifact = resources.get(&declaration.artifact).ok_or_else(|| {
            PackageLoadError::ResourceMissingAfterValidation(declaration.artifact.clone())
        })?;
        let artifact_digest = ArtifactDigest::parse(artifact.digest().to_string())
            .map_err(|error| PackageLoadError::InternalDigest(error.to_string()))?;
        let offer = CapabilityOffer::new(
            declaration.implementation.clone(),
            artifact_digest,
            declaration.capability.clone(),
            declaration.extensions.clone(),
        )?;
        let offer_id = offer.offer_id.clone();
        if offers
            .insert(
                offer_id.clone(),
                ValidatedOffer {
                    offer,
                    artifact: artifact.clone(),
                },
            )
            .is_some()
        {
            return Err(PackageLoadError::DuplicateDerivedOffer(offer_id));
        }
    }
    Ok(offers)
}

fn validate_external_ownership(
    manifest: &PackageManifest,
    registry: &PackageRegistry,
) -> Result<(), PackageLoadError> {
    let direct_dependencies = manifest
        .dependencies
        .iter()
        .map(|dependency| dependency.package.clone())
        .collect::<BTreeSet<_>>();
    let local_value_kinds = manifest
        .dialects
        .iter()
        .flat_map(|dialect| dialect.value_kinds.iter().map(|kind| kind.id.clone()))
        .collect::<BTreeSet<_>>();
    let local_capabilities = manifest
        .capabilities
        .iter()
        .map(|capability| capability.id.clone())
        .collect::<BTreeSet<_>>();
    let local_conformance_suites = manifest
        .conformance_suites
        .iter()
        .map(|suite| suite.id.clone())
        .collect::<BTreeSet<_>>();

    for capability in &manifest.capabilities {
        let suite =
            ConformanceSuiteId::parse(&capability.default_conformance_suite).map_err(|error| {
                PackageLoadError::Manifest(PackageManifestError::InvalidField {
                    scope: format!("capability `{}` conformance suite", capability.id),
                    detail: error.to_string(),
                })
            })?;
        if !local_conformance_suites.contains(&suite) {
            require_direct_conformance_suite(&suite, registry, &direct_dependencies)?;
        }
        for value_kind in capability
            .input_ports
            .iter()
            .map(|port| &port.value_kind)
            .chain(capability.output_ports.iter().map(|port| &port.value_kind))
        {
            if !local_value_kinds.contains(value_kind) {
                require_direct_value_kind(value_kind, registry, &direct_dependencies)?;
            }
        }
    }
    for declaration in &manifest.implementation_offers {
        if !local_capabilities.contains(&declaration.capability) {
            require_direct_capability(&declaration.capability, registry, &direct_dependencies)?;
        }
    }
    Ok(())
}

fn require_direct_value_kind(
    id: &ValueKindId,
    registry: &PackageRegistry,
    direct: &BTreeSet<PackageId>,
) -> Result<(), PackageLoadError> {
    let Some((owner, _)) = registry.value_kind(id) else {
        return Err(PackageLoadError::UnknownExternalIdentity {
            kind: "value kind",
            identity: id.to_string(),
        });
    };
    require_direct_owner("value kind", id.to_string(), owner, direct)
}

fn require_direct_capability(
    id: &CapabilityId,
    registry: &PackageRegistry,
    direct: &BTreeSet<PackageId>,
) -> Result<(), PackageLoadError> {
    let Some((owner, _)) = registry.capability(id) else {
        return Err(PackageLoadError::UnknownExternalIdentity {
            kind: "capability",
            identity: id.to_string(),
        });
    };
    require_direct_owner("capability", id.to_string(), owner, direct)
}

fn require_direct_conformance_suite(
    id: &ConformanceSuiteId,
    registry: &PackageRegistry,
    direct: &BTreeSet<PackageId>,
) -> Result<(), PackageLoadError> {
    let Some((owner, _)) = registry.conformance_suite(id) else {
        return Err(PackageLoadError::UnknownExternalIdentity {
            kind: "conformance suite",
            identity: id.to_string(),
        });
    };
    require_direct_owner("conformance suite", id.to_string(), owner, direct)
}

fn require_direct_owner(
    kind: &'static str,
    identity: String,
    owner: &PackageId,
    direct: &BTreeSet<PackageId>,
) -> Result<(), PackageLoadError> {
    if !direct.contains(owner) {
        return Err(PackageLoadError::IdentityNotFromDirectDependency {
            kind,
            identity,
            owner: owner.clone(),
        });
    }
    Ok(())
}

fn fs_error(scope: &str, error: impl fmt::Display) -> PackageLoadError {
    PackageLoadError::Filesystem {
        scope: scope.to_owned(),
        detail: error.to_string(),
    }
}

/// Local package load or validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackageLoadError {
    InvalidLimits,
    Filesystem {
        scope: String,
        detail: String,
    },
    NotDirectory,
    NotDirectoryComponent {
        scope: String,
        component: String,
    },
    NotRegularFile {
        scope: String,
    },
    ByteLimitExceeded {
        scope: String,
        actual: u64,
        limit: u64,
    },
    ManifestNotUtf8,
    InternalDigest(String),
    Manifest(PackageManifestError),
    ResourceCountExceeded {
        actual: usize,
        limit: usize,
    },
    ResourceLimitExceeded {
        resource: ResourceName,
        declared: u64,
        limit: u64,
    },
    TotalResourceLimitExceeded {
        declared: u64,
        limit: u64,
    },
    ResourceSizeMismatch {
        scope: String,
        expected: u64,
        actual: u64,
    },
    ResourceDigestMismatch {
        resource: ResourceName,
        expected: ResourceDigest,
        actual: ResourceDigest,
    },
    MissingDependency {
        package: PackageId,
        digest: PackageDigest,
    },
    DependencyDigestMismatch {
        package: PackageId,
        expected: PackageDigest,
        actual: PackageDigest,
    },
    DependencyHandleMismatch,
    UnknownExternalIdentity {
        kind: &'static str,
        identity: String,
    },
    IdentityNotFromDirectDependency {
        kind: &'static str,
        identity: String,
        owner: PackageId,
    },
    Offer(ProtocolError),
    DuplicateDerivedOffer(OfferId),
    OfferArtifactMismatch(OfferId),
    ResourceMissingAfterValidation(ResourceName),
    ResourceChanged(ResourceName),
}

impl From<PackageManifestError> for PackageLoadError {
    fn from(error: PackageManifestError) -> Self {
        Self::Manifest(error)
    }
}

impl From<ProtocolError> for PackageLoadError {
    fn from(error: ProtocolError) -> Self {
        Self::Offer(error)
    }
}

impl fmt::Display for PackageLoadError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("package load limits must be positive"),
            Self::Filesystem { scope, detail } => write!(formatter, "{scope}: {detail}"),
            Self::NotDirectory => formatter.write_str("package root is not a directory"),
            Self::NotDirectoryComponent { scope, component } => {
                write!(
                    formatter,
                    "{scope} component `{component}` is not a directory"
                )
            }
            Self::NotRegularFile { scope } => write!(formatter, "{scope} is not a regular file"),
            Self::ByteLimitExceeded {
                scope,
                actual,
                limit,
            } => write!(formatter, "{scope} has {actual} bytes, limit is {limit}"),
            Self::ManifestNotUtf8 => formatter.write_str("package manifest is not UTF-8"),
            Self::InternalDigest(error) => {
                write!(formatter, "internal digest conversion failed: {error}")
            }
            Self::Manifest(error) => write!(formatter, "{error}"),
            Self::ResourceCountExceeded { actual, limit } => {
                write!(
                    formatter,
                    "package declares {actual} resources, limit is {limit}"
                )
            }
            Self::ResourceLimitExceeded {
                resource,
                declared,
                limit,
            } => write!(
                formatter,
                "resource `{resource}` declares {declared} bytes, limit is {limit}"
            ),
            Self::TotalResourceLimitExceeded { declared, limit } => write!(
                formatter,
                "package declares {declared} total resource bytes, limit is {limit}"
            ),
            Self::ResourceSizeMismatch {
                scope,
                expected,
                actual,
            } => write!(
                formatter,
                "{scope} size mismatch: expected {expected}, got {actual}"
            ),
            Self::ResourceDigestMismatch {
                resource,
                expected,
                actual,
            } => write!(
                formatter,
                "resource `{resource}` digest mismatch: expected {expected}, got {actual}"
            ),
            Self::MissingDependency { package, digest } => {
                write!(
                    formatter,
                    "exact dependency `{package}` at {digest} is not installed"
                )
            }
            Self::DependencyDigestMismatch {
                package,
                expected,
                actual,
            } => write!(
                formatter,
                "dependency `{package}` requires {expected}, installed package is {actual}"
            ),
            Self::DependencyHandleMismatch => {
                formatter.write_str("captured dependency handles do not match this registry")
            }
            Self::UnknownExternalIdentity { kind, identity } => {
                write!(formatter, "external {kind} `{identity}` is not installed")
            }
            Self::IdentityNotFromDirectDependency {
                kind,
                identity,
                owner,
            } => write!(
                formatter,
                "external {kind} `{identity}` is owned by non-direct package `{owner}`"
            ),
            Self::Offer(error) => write!(formatter, "cannot derive capability offer: {error}"),
            Self::DuplicateDerivedOffer(offer) => {
                write!(formatter, "multiple declarations derive offer `{offer}`")
            }
            Self::OfferArtifactMismatch(offer) => {
                write!(
                    formatter,
                    "offer `{offer}` is not bound to its owned artifact"
                )
            }
            Self::ResourceMissingAfterValidation(resource) => {
                write!(formatter, "validated resource `{resource}` is missing")
            }
            Self::ResourceChanged(resource) => {
                write!(
                    formatter,
                    "owned resource `{resource}` no longer matches its declaration"
                )
            }
        }
    }
}

impl std::error::Error for PackageLoadError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use gooir_capability::protocol::{ConformanceSuiteId, ImplementationId};
    use gooir_capability::{
        CapabilityId, CapabilitySpec, DialectId, InputPort, OutputPort, PortName, ValueKindId,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::{
        ConformanceSuiteDeclaration, DialectDeclaration, ImplementationOfferDeclaration,
        InstallError, PackageDependency, PackageResource, ValueKindDeclaration, write_manifest,
    };

    const VERSION: &str = "1.0.0";

    fn resource(bytes: &[u8]) -> PackageResource {
        PackageResource {
            name: ResourceName::parse("artifact").unwrap(),
            path: "bin/provider".to_owned(),
            media_type: "application/octet-stream".to_owned(),
            size: bytes.len() as u64,
            digest: ResourceDigest::parse(sha256_bytes(bytes)).unwrap(),
            extensions: BTreeMap::new(),
        }
    }

    fn local_manifest(
        package: &str,
        namespace: &str,
        implementation: &str,
        bytes: &[u8],
    ) -> PackageManifest {
        let dialect = DialectId::new(namespace, VERSION);
        let value_kind = ValueKindId::in_dialect(dialect.clone(), "value");
        let suite =
            ConformanceSuiteId::parse(&format!("{namespace}.conformance/produce@{VERSION}"))
                .unwrap();
        let capability = CapabilitySpec {
            id: CapabilityId::new(namespace, "produce", VERSION),
            input_ports: Vec::new(),
            output_ports: vec![OutputPort::new(
                PortName::parse("value").unwrap(),
                value_kind.clone(),
            )],
            default_conformance_suite: suite.to_string(),
            extensions: BTreeMap::new(),
        };
        PackageManifest::new(
            PackageId::parse(format!("{package}@{VERSION}")).unwrap(),
            Vec::new(),
            vec![resource(bytes)],
            vec![DialectDeclaration {
                id: dialect,
                value_kinds: vec![ValueKindDeclaration {
                    id: value_kind,
                    schema: None,
                    extensions: BTreeMap::new(),
                }],
                extensions: BTreeMap::new(),
            }],
            vec![ConformanceSuiteDeclaration {
                id: suite,
                extensions: BTreeMap::new(),
            }],
            vec![capability.clone()],
            vec![ImplementationOfferDeclaration {
                implementation: ImplementationId::new(implementation, "produce", VERSION),
                capability: capability.id,
                artifact: ResourceName::parse("artifact").unwrap(),
                extensions: BTreeMap::new(),
            }],
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn dependent_manifest(
        package: &str,
        namespace: &str,
        dependency: &InstalledPackage,
        external_kind: &ValueKindId,
        external_capability: &CapabilityId,
        bytes: &[u8],
    ) -> PackageManifest {
        let dialect = DialectId::new(namespace, VERSION);
        let local_kind = ValueKindId::in_dialect(dialect.clone(), "value");
        let suite =
            ConformanceSuiteId::parse(&format!("{namespace}.conformance/convert@{VERSION}"))
                .unwrap();
        let capability = CapabilitySpec {
            id: CapabilityId::new(namespace, "convert", VERSION),
            input_ports: vec![InputPort::complete(
                PortName::parse("input").unwrap(),
                external_kind.clone(),
            )],
            output_ports: vec![OutputPort::new(
                PortName::parse("output").unwrap(),
                local_kind.clone(),
            )],
            default_conformance_suite: suite.to_string(),
            extensions: BTreeMap::new(),
        };
        PackageManifest::new(
            PackageId::parse(format!("{package}@{VERSION}")).unwrap(),
            vec![PackageDependency {
                package: dependency.package_id().clone(),
                digest: dependency.digest().clone(),
                extensions: BTreeMap::new(),
            }],
            vec![resource(bytes)],
            vec![DialectDeclaration {
                id: dialect,
                value_kinds: vec![ValueKindDeclaration {
                    id: local_kind,
                    schema: None,
                    extensions: BTreeMap::new(),
                }],
                extensions: BTreeMap::new(),
            }],
            vec![ConformanceSuiteDeclaration {
                id: suite,
                extensions: BTreeMap::new(),
            }],
            vec![capability],
            vec![ImplementationOfferDeclaration {
                implementation: ImplementationId::new(namespace, "provider", VERSION),
                capability: external_capability.clone(),
                artifact: ResourceName::parse("artifact").unwrap(),
                extensions: BTreeMap::new(),
            }],
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn write_fixture(manifest: &PackageManifest, bytes: &[u8]) -> TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir_all(directory.path().join("bin")).unwrap();
        fs::write(directory.path().join("bin/provider"), bytes).unwrap();
        fs::write(
            directory.path().join(PACKAGE_MANIFEST_FILE),
            write_manifest(manifest).unwrap(),
        )
        .unwrap();
        directory
    }

    fn rebuild(manifest: PackageManifest) -> PackageManifest {
        PackageManifest::new(
            manifest.package,
            manifest.dependencies,
            manifest.resources,
            manifest.dialects,
            manifest.conformance_suites,
            manifest.capabilities,
            manifest.implementation_offers,
            manifest.extensions,
        )
        .unwrap()
    }

    fn load_fixture(
        manifest: &PackageManifest,
        bytes: &[u8],
        registry: &PackageRegistry,
    ) -> ValidatedPackage {
        let fixture = write_fixture(manifest, bytes);
        load_local_package(fixture.path(), registry, LoadLimits::default()).unwrap()
    }

    fn install_local(
        registry: &mut PackageRegistry,
        package: &str,
        namespace: &str,
        implementation: &str,
        bytes: &[u8],
    ) -> InstalledPackage {
        let manifest = local_manifest(package, namespace, implementation, bytes);
        let validated = load_fixture(&manifest, bytes, registry);
        registry.install(validated).unwrap()
    }

    #[test]
    fn exact_bytes_derive_offer_and_survive_source_replacement() {
        let bytes = b"exact provider bytes";
        let manifest = local_manifest(
            "org.example.owner",
            "org.example.owner",
            "org.example.owner.impl",
            bytes,
        );
        let fixture = write_fixture(&manifest, bytes);
        let validated = load_local_package(
            fixture.path(),
            &PackageRegistry::default(),
            LoadLimits::default(),
        )
        .unwrap();
        let offer = validated.offers().next().unwrap().clone();
        assert_eq!(
            offer.artifact_digest.as_str(),
            manifest.resources[0].digest.as_str()
        );
        assert_eq!(
            validated.offer_artifact(&offer.offer_id).unwrap().bytes(),
            bytes
        );

        fs::write(fixture.path().join("bin/provider"), b"replacement").unwrap();
        assert_eq!(
            validated.offer_artifact(&offer.offer_id).unwrap().bytes(),
            bytes
        );

        let mut registry = PackageRegistry::default();
        let installed = registry.install(validated).unwrap();
        let suite = &manifest.conformance_suites[0];
        let (suite_owner, installed_suite) = registry.conformance_suite(&suite.id).unwrap();
        assert_eq!(suite_owner, installed.package_id());
        assert_eq!(installed_suite, suite);
        assert_eq!(
            registry.offer_artifact(&offer.offer_id).unwrap().bytes(),
            bytes
        );
        assert_eq!(
            installed
                .resource(&manifest.resources[0].name)
                .unwrap()
                .bytes(),
            bytes
        );
    }

    #[test]
    fn complete_planning_inventory_is_stable_and_sorted() {
        let mut registry = PackageRegistry::default();
        let later = install_local(
            &mut registry,
            "org.example.later.package",
            "org.example.later",
            "org.example.later.implementation",
            b"later provider",
        );
        let earlier = install_local(
            &mut registry,
            "org.example.earlier.package",
            "org.example.earlier",
            "org.example.earlier.implementation",
            b"earlier provider",
        );

        let capabilities = registry.capabilities().collect::<Vec<_>>();
        assert_eq!(capabilities.len(), 2);
        assert!(capabilities[0].1.id < capabilities[1].1.id);
        assert_eq!(capabilities[0].0, earlier.package_id());
        assert_eq!(capabilities[1].0, later.package_id());
        assert_eq!(
            registry.capability(&capabilities[0].1.id),
            Some(capabilities[0])
        );
        assert_eq!(
            registry.capability(&capabilities[1].1.id),
            Some(capabilities[1])
        );

        let offers = registry.offers().collect::<Vec<_>>();
        assert_eq!(offers.len(), 2);
        assert!(offers[0].offer_id < offers[1].offer_id);
        assert!(offers.iter().all(|offer| {
            registry
                .offer(&offer.offer_id)
                .is_some_and(|installed| installed == *offer)
        }));
    }

    #[test]
    fn an_exact_hardlinked_resource_is_accepted() {
        let bytes = b"hardlinked provider";
        let manifest = local_manifest(
            "org.example.hardlink",
            "org.example.hardlink",
            "org.example.hardlink.impl",
            bytes,
        );
        let fixture = write_fixture(&manifest, bytes);
        let source = fixture.path().join("hardlink-source");
        fs::rename(fixture.path().join("bin/provider"), &source).unwrap();
        fs::hard_link(&source, fixture.path().join("bin/provider")).unwrap();

        let validated = load_local_package(
            fixture.path(),
            &PackageRegistry::default(),
            LoadLimits::default(),
        )
        .unwrap();
        assert_eq!(validated.resources().next().unwrap().bytes(), bytes);
    }

    #[test]
    fn an_open_resource_descriptor_cannot_be_redirected_by_path_replacement() {
        let original = b"original provider";
        let manifest = local_manifest(
            "org.example.descriptor",
            "org.example.descriptor",
            "org.example.descriptor.impl",
            original,
        );
        let fixture = write_fixture(&manifest, original);
        let root = open_root(fixture.path()).unwrap();
        let opened = open_relative_regular(&root, "bin/provider", "test resource").unwrap();
        fs::rename(
            fixture.path().join("bin/provider"),
            fixture.path().join("bin/original-provider"),
        )
        .unwrap();
        fs::write(fixture.path().join("bin/provider"), b"replacement").unwrap();

        assert_eq!(
            read_bounded(
                opened,
                LoadLimits::default().max_resource_bytes,
                Some(original.len() as u64),
                "test resource"
            )
            .unwrap(),
            original
        );
    }

    #[cfg(unix)]
    #[test]
    fn manifest_and_resource_symlinks_are_never_followed() {
        use std::os::unix::fs::symlink;

        let bytes = b"provider";
        let manifest = local_manifest(
            "org.example.links",
            "org.example.links",
            "org.example.links.impl",
            bytes,
        );

        let manifest_fixture = write_fixture(&manifest, bytes);
        let outside_manifest = manifest_fixture.path().join("outside-manifest.json");
        fs::rename(
            manifest_fixture.path().join(PACKAGE_MANIFEST_FILE),
            &outside_manifest,
        )
        .unwrap();
        symlink(
            &outside_manifest,
            manifest_fixture.path().join(PACKAGE_MANIFEST_FILE),
        )
        .unwrap();
        assert!(matches!(
            load_local_package(
                manifest_fixture.path(),
                &PackageRegistry::default(),
                LoadLimits::default()
            ),
            Err(PackageLoadError::Filesystem { .. })
        ));

        let resource_fixture = write_fixture(&manifest, bytes);
        let outside_resource = resource_fixture.path().join("outside-provider");
        fs::rename(
            resource_fixture.path().join("bin/provider"),
            &outside_resource,
        )
        .unwrap();
        symlink(
            &outside_resource,
            resource_fixture.path().join("bin/provider"),
        )
        .unwrap();
        assert!(matches!(
            load_local_package(
                resource_fixture.path(),
                &PackageRegistry::default(),
                LoadLimits::default()
            ),
            Err(PackageLoadError::Filesystem { .. })
        ));

        let component_fixture = write_fixture(&manifest, bytes);
        fs::rename(
            component_fixture.path().join("bin"),
            component_fixture.path().join("real-bin"),
        )
        .unwrap();
        symlink(
            component_fixture.path().join("real-bin"),
            component_fixture.path().join("bin"),
        )
        .unwrap();
        assert!(matches!(
            load_local_package(
                component_fixture.path(),
                &PackageRegistry::default(),
                LoadLimits::default()
            ),
            Err(PackageLoadError::Filesystem { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn fifo_and_directory_resources_fail_without_blocking() {
        use nix::sys::stat::Mode as NixMode;
        use nix::unistd::mkfifo;

        let bytes = b"provider";
        let manifest = local_manifest(
            "org.example.special",
            "org.example.special",
            "org.example.special.impl",
            bytes,
        );
        let directory_fixture = write_fixture(&manifest, bytes);
        fs::remove_file(directory_fixture.path().join("bin/provider")).unwrap();
        fs::create_dir(directory_fixture.path().join("bin/provider")).unwrap();
        assert!(matches!(
            load_local_package(
                directory_fixture.path(),
                &PackageRegistry::default(),
                LoadLimits::default()
            ),
            Err(PackageLoadError::NotRegularFile { .. })
        ));

        let fifo_fixture = write_fixture(&manifest, bytes);
        fs::remove_file(fifo_fixture.path().join("bin/provider")).unwrap();
        mkfifo(
            &fifo_fixture.path().join("bin/provider"),
            NixMode::S_IRUSR | NixMode::S_IWUSR,
        )
        .unwrap();
        assert!(matches!(
            load_local_package(
                fifo_fixture.path(),
                &PackageRegistry::default(),
                LoadLimits::default()
            ),
            Err(PackageLoadError::NotRegularFile { .. })
        ));
    }

    #[test]
    fn short_long_and_over_limit_resources_fail_closed() {
        let expected = b"provider";
        let manifest = local_manifest(
            "org.example.sizes",
            "org.example.sizes",
            "org.example.sizes.impl",
            expected,
        );
        for actual in [&b"short"[..], &b"provider-long"[..]] {
            let fixture = write_fixture(&manifest, actual);
            assert!(matches!(
                load_local_package(
                    fixture.path(),
                    &PackageRegistry::default(),
                    LoadLimits::default()
                ),
                Err(PackageLoadError::ResourceSizeMismatch { .. })
            ));
        }

        let fixture = write_fixture(&manifest, expected);
        let limits = LoadLimits {
            max_resource_bytes: 2,
            ..LoadLimits::default()
        };
        assert!(matches!(
            load_local_package(fixture.path(), &PackageRegistry::default(), limits),
            Err(PackageLoadError::ResourceLimitExceeded { .. })
        ));
    }

    #[test]
    fn only_exact_direct_dependency_exports_resolve() {
        let mut registry = PackageRegistry::default();
        let owner = install_local(
            &mut registry,
            "org.example.dependency",
            "org.example.dependency",
            "org.example.dependency.impl",
            b"dependency",
        );
        let external_kind = owner.manifest().dialects[0].value_kinds[0].id.clone();
        let external_capability = owner.manifest().capabilities[0].id.clone();
        let direct = dependent_manifest(
            "org.example.direct",
            "org.example.direct",
            &owner,
            &external_kind,
            &external_capability,
            b"direct",
        );
        let direct_validated = load_fixture(&direct, b"direct", &registry);
        let direct_installed = registry.install(direct_validated).unwrap();
        assert_eq!(
            direct_installed.dependencies()[0].package_id(),
            owner.package_id()
        );

        let missing_registry = PackageRegistry::default();
        let missing_fixture = write_fixture(&direct, b"direct");
        assert!(matches!(
            load_local_package(
                missing_fixture.path(),
                &missing_registry,
                LoadLimits::default()
            ),
            Err(PackageLoadError::MissingDependency { .. })
        ));

        let mut wrong_digest = direct.clone();
        wrong_digest.dependencies[0].digest =
            PackageDigest::parse(format!("sha256:{}", "f".repeat(64))).unwrap();
        wrong_digest = PackageManifest::new(
            wrong_digest.package,
            wrong_digest.dependencies,
            wrong_digest.resources,
            wrong_digest.dialects,
            wrong_digest.conformance_suites,
            wrong_digest.capabilities,
            wrong_digest.implementation_offers,
            wrong_digest.extensions,
        )
        .unwrap();
        let wrong_fixture = write_fixture(&wrong_digest, b"direct");
        assert!(matches!(
            load_local_package(wrong_fixture.path(), &registry, LoadLimits::default()),
            Err(PackageLoadError::DependencyDigestMismatch { .. })
        ));

        let indirect = dependent_manifest(
            "org.example.indirect",
            "org.example.indirect",
            &direct_installed,
            &external_kind,
            &external_capability,
            b"indirect",
        );
        let indirect_fixture = write_fixture(&indirect, b"indirect");
        assert!(matches!(
            load_local_package(indirect_fixture.path(), &registry, LoadLimits::default()),
            Err(PackageLoadError::IdentityNotFromDirectDependency { .. })
        ));
    }

    #[test]
    fn conformance_suite_references_require_exact_direct_exports() {
        let mut registry = PackageRegistry::default();
        let owner = install_local(
            &mut registry,
            "org.example.suite-owner",
            "org.example.suite-owner",
            "org.example.suite-owner.impl",
            b"suite owner",
        );
        let suite = owner.manifest().conformance_suites[0].id.clone();

        let mut direct = local_manifest(
            "org.example.suite-direct",
            "org.example.suite-direct",
            "org.example.suite-direct.impl",
            b"direct suite consumer",
        );
        direct.dependencies = vec![PackageDependency {
            package: owner.package_id().clone(),
            digest: owner.digest().clone(),
            extensions: BTreeMap::new(),
        }];
        direct.conformance_suites.clear();
        direct.capabilities[0].default_conformance_suite = suite.to_string();
        let direct = rebuild(direct);
        let direct = registry
            .install(load_fixture(&direct, b"direct suite consumer", &registry))
            .unwrap();
        assert_eq!(direct.dependencies()[0].package_id(), owner.package_id());

        let missing_suite = ConformanceSuiteId::parse("org.example.missing/suite@1.0.0").unwrap();
        let mut missing = local_manifest(
            "org.example.suite-missing",
            "org.example.suite-missing",
            "org.example.suite-missing.impl",
            b"missing suite consumer",
        );
        missing.conformance_suites.clear();
        missing.capabilities[0].default_conformance_suite = missing_suite.to_string();
        let missing = rebuild(missing);
        let missing_fixture = write_fixture(&missing, b"missing suite consumer");
        assert!(matches!(
            load_local_package(missing_fixture.path(), &registry, LoadLimits::default()),
            Err(PackageLoadError::UnknownExternalIdentity {
                kind: "conformance suite",
                identity,
            }) if identity == missing_suite.to_string()
        ));

        let mut bridge = local_manifest(
            "org.example.suite-bridge",
            "org.example.suite-bridge",
            "org.example.suite-bridge.impl",
            b"suite bridge",
        );
        bridge.dependencies = vec![PackageDependency {
            package: owner.package_id().clone(),
            digest: owner.digest().clone(),
            extensions: BTreeMap::new(),
        }];
        let bridge = rebuild(bridge);
        let bridge = registry
            .install(load_fixture(&bridge, b"suite bridge", &registry))
            .unwrap();

        let mut transitive = local_manifest(
            "org.example.suite-transitive",
            "org.example.suite-transitive",
            "org.example.suite-transitive.impl",
            b"transitive suite consumer",
        );
        transitive.dependencies = vec![PackageDependency {
            package: bridge.package_id().clone(),
            digest: bridge.digest().clone(),
            extensions: BTreeMap::new(),
        }];
        transitive.conformance_suites.clear();
        transitive.capabilities[0].default_conformance_suite = suite.to_string();
        let transitive = rebuild(transitive);
        let transitive_fixture = write_fixture(&transitive, b"transitive suite consumer");
        assert!(matches!(
            load_local_package(
                transitive_fixture.path(),
                &registry,
                LoadLimits::default()
            ),
            Err(PackageLoadError::IdentityNotFromDirectDependency {
                kind: "conformance suite",
                identity,
                owner: actual_owner,
            }) if identity == suite.to_string() && actual_owner == *owner.package_id()
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn registry_install_is_exact_idempotent_atomic_and_collision_closed() {
        let mut registry = PackageRegistry::default();
        let bytes = b"first";
        let first_manifest = local_manifest(
            "org.example.first",
            "org.example.shared",
            "org.example.shared.impl",
            bytes,
        );
        let first_a = load_fixture(&first_manifest, bytes, &registry);
        let first_b = load_fixture(&first_manifest, bytes, &registry);
        let installed = registry.install(first_a).unwrap();
        let replay = registry.install(first_b).unwrap();
        assert_eq!(installed.package_id(), replay.package_id());
        assert_eq!(installed.digest(), replay.digest());

        let changed_bytes = b"changed";
        let changed_manifest = local_manifest(
            "org.example.first",
            "org.example.changed",
            "org.example.changed.impl",
            changed_bytes,
        );
        let changed = load_fixture(&changed_manifest, changed_bytes, &registry);
        assert!(matches!(
            registry.install(changed),
            Err(InstallError::PackageIdentityCollision { .. })
        ));

        let dialect_collision = local_manifest(
            "org.example.second",
            "org.example.shared",
            "org.example.second.impl",
            b"second",
        );
        let value_kind_collision = load_fixture(&dialect_collision, b"second", &registry);
        assert!(matches!(
            registry.install(value_kind_collision),
            Err(InstallError::OwnershipCollision {
                kind: "value kind",
                ..
            })
        ));

        let mut dialect_collision = dialect_collision;
        dialect_collision.dialects[0].value_kinds[0].id =
            ValueKindId::in_dialect(dialect_collision.dialects[0].id.clone(), "different-value");
        dialect_collision.capabilities[0].output_ports[0].value_kind =
            dialect_collision.dialects[0].value_kinds[0].id.clone();
        dialect_collision = PackageManifest::new(
            dialect_collision.package,
            dialect_collision.dependencies,
            dialect_collision.resources,
            dialect_collision.dialects,
            dialect_collision.conformance_suites,
            dialect_collision.capabilities,
            dialect_collision.implementation_offers,
            dialect_collision.extensions,
        )
        .unwrap();
        let dialect_collision = load_fixture(&dialect_collision, b"second", &registry);
        assert!(matches!(
            registry.install(dialect_collision),
            Err(InstallError::OwnershipCollision {
                kind: "dialect",
                ..
            })
        ));

        let mut suite_collision = local_manifest(
            "org.example.suite-collision",
            "org.example.suite-collision",
            "org.example.suite-collision.impl",
            b"suite collision",
        );
        suite_collision.conformance_suites[0].id =
            installed.manifest().conformance_suites[0].id.clone();
        suite_collision.capabilities[0].default_conformance_suite =
            suite_collision.conformance_suites[0].id.to_string();
        let suite_collision = rebuild(suite_collision);
        let unpublished_dialect = suite_collision.dialects[0].id.clone();
        let suite_collision = load_fixture(&suite_collision, b"suite collision", &registry);
        assert!(matches!(
            registry.install(suite_collision),
            Err(InstallError::OwnershipCollision {
                kind: "conformance suite",
                ..
            })
        ));
        assert!(
            registry.dialect(&unpublished_dialect).is_none(),
            "failed suite collision leaked an earlier declaration"
        );

        let capability_collision = local_manifest(
            "org.example.third",
            "org.example.third",
            "org.example.third.impl",
            b"third",
        );
        let mut capability_collision = capability_collision;
        capability_collision.capabilities[0].id = installed.manifest().capabilities[0].id.clone();
        capability_collision.implementation_offers[0].capability =
            capability_collision.capabilities[0].id.clone();
        capability_collision = PackageManifest::new(
            capability_collision.package,
            capability_collision.dependencies,
            capability_collision.resources,
            capability_collision.dialects,
            capability_collision.conformance_suites,
            capability_collision.capabilities,
            capability_collision.implementation_offers,
            capability_collision.extensions,
        )
        .unwrap();
        let new_dialect = capability_collision.dialects[0].id.clone();
        let capability_collision = load_fixture(&capability_collision, b"third", &registry);
        assert!(matches!(
            registry.install(capability_collision),
            Err(InstallError::OwnershipCollision {
                kind: "capability",
                ..
            })
        ));
        assert!(
            registry.dialect(&new_dialect).is_none(),
            "failed install leaked a dialect"
        );

        let implementation_collision = local_manifest(
            "org.example.fourth",
            "org.example.fourth",
            "org.example.shared.impl",
            b"fourth",
        );
        let implementation_collision =
            load_fixture(&implementation_collision, b"fourth", &registry);
        assert!(matches!(
            registry.install(implementation_collision),
            Err(InstallError::OwnershipCollision {
                kind: "implementation",
                ..
            })
        ));
    }
}
