//! Deployment-image assembly for external GOOIR toolchains.
//!
//! This crate binds already-built provider and attester artifacts to exact
//! package resources without adding a backend concept to the semantic kernel.
//! Provider bindings become ordinary package offers. Attester bindings remain
//! host-owned lock data and never become semantic offers.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use gooir_capability::CapabilityId;
use gooir_capability::authority::{ConformanceAttester, ConformanceAuthority};
use gooir_capability::canonical_digest;
use gooir_capability::protocol::{ArtifactDigest, ConformanceSuiteId, ImplementationId};
use gooir_capability::strict_json;
use gooir_derive::LocalAttesterBinding;
use gooir_package::{
    ImplementationOfferDeclaration, InstallError, InstalledPackage, LoadLimits, PackageDigest,
    PackageId, PackageLoadError, PackageManifest, PackageManifestError, PackageRegistry,
    PackageResource, ResourceDigest, ResourceName, load_local_package, write_manifest,
};
use rustix::fs::{Mode, OFlags, RenameFlags, open, renameat_with};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// Fixed lock filename at the root of a published toolchain image.
pub const TOOLCHAIN_LOCK_FILE: &str = "gooir-toolchain-lock.json";

/// Exact host-local toolchain lock protocol emitted by this crate.
pub const TOOLCHAIN_LOCK_PROTOCOL: &str = "org.gooi.toolchain-lock/v1";

/// Explicit finite bounds for toolchain assembly and loading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToolchainLimits {
    pub max_lock_bytes: u64,
    pub max_packages: usize,
    pub max_attesters: usize,
    pub max_total_image_resource_bytes: u64,
    pub max_total_image_manifest_bytes: u64,
    pub package: LoadLimits,
}

impl Default for ToolchainLimits {
    fn default() -> Self {
        Self {
            max_lock_bytes: 4 * 1024 * 1024,
            max_packages: 4_096,
            max_attesters: 4_096,
            max_total_image_resource_bytes: 1024 * 1024 * 1024,
            max_total_image_manifest_bytes: 64 * 1024 * 1024,
            package: LoadLimits::default(),
        }
    }
}

impl ToolchainLimits {
    fn validate(self) -> Result<(), ToolchainError> {
        if self.max_lock_bytes == 0
            || self.max_packages == 0
            || self.max_attesters == 0
            || self.max_total_image_resource_bytes == 0
            || self.max_total_image_manifest_bytes == 0
            || self.package.max_manifest_bytes == 0
            || self.package.max_resources == 0
            || self.package.max_resource_bytes == 0
            || self.package.max_total_resource_bytes == 0
        {
            return Err(ToolchainError::InvalidLimits);
        }
        Ok(())
    }
}

/// Exact bytes used to populate one package resource.
#[derive(Clone, Debug)]
pub struct ResourceInput {
    name: ResourceName,
    path: String,
    media_type: String,
    source: ResourceSource,
    extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug)]
enum ResourceSource {
    File(PathBuf),
    Bytes(Vec<u8>),
}

impl ResourceInput {
    /// Declares a resource whose bytes will be copied from one explicit regular file.
    #[must_use]
    pub fn file(
        name: ResourceName,
        path: impl Into<String>,
        media_type: impl Into<String>,
        source: impl Into<PathBuf>,
    ) -> Self {
        Self {
            name,
            path: path.into(),
            media_type: media_type.into(),
            source: ResourceSource::File(source.into()),
            extensions: BTreeMap::new(),
        }
    }

    /// Declares a resource backed by caller-owned bytes.
    #[must_use]
    pub fn bytes(
        name: ResourceName,
        path: impl Into<String>,
        media_type: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            name,
            path: path.into(),
            media_type: media_type.into(),
            source: ResourceSource::Bytes(bytes.into()),
            extensions: BTreeMap::new(),
        }
    }

    /// Preserves explicitly authored package-resource extension data.
    #[must_use]
    pub fn with_extensions(mut self, extensions: BTreeMap<String, Value>) -> Self {
        self.extensions = extensions;
        self
    }
}

#[derive(Clone, Debug)]
struct ProviderBinding {
    implementation: ImplementationId,
    capability: CapabilityId,
    artifact: ResourceName,
    extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug)]
struct AttesterRecipe {
    suite: ConformanceSuiteId,
    implementation: ImplementationId,
    artifact: ResourceName,
    attester_extensions: BTreeMap<String, Value>,
    authority_extensions: BTreeMap<String, Value>,
}

/// One offer-free semantic manifest plus deployment-time artifact bindings.
#[derive(Clone, Debug)]
pub struct PackageRecipe {
    relative_directory: String,
    base: PackageManifest,
    resources: BTreeMap<ResourceName, ResourceInput>,
    providers: Vec<ProviderBinding>,
    attesters: Vec<AttesterRecipe>,
}

impl PackageRecipe {
    /// Starts a deployment recipe from an exact offer-free package manifest.
    ///
    /// Existing resource declarations are permitted, but exact bytes for every
    /// one must be supplied through [`Self::with_resource`].
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest is invalid, already contains offers,
    /// or the package directory is not a safe single path component.
    pub fn from_manifest(
        relative_directory: impl Into<String>,
        manifest: PackageManifest,
    ) -> Result<Self, ToolchainError> {
        manifest.validate().map_err(ToolchainError::Manifest)?;
        if !manifest.implementation_offers.is_empty() {
            return Err(ToolchainError::ManifestAlreadyOffers(
                manifest.package.clone(),
            ));
        }
        let relative_directory = relative_directory.into();
        validate_package_directory(&relative_directory)?;
        Ok(Self {
            relative_directory,
            base: manifest,
            resources: BTreeMap::new(),
            providers: Vec::new(),
            attesters: Vec::new(),
        })
    }

    /// Adds exact resource bytes to this package recipe.
    ///
    /// # Errors
    ///
    /// Returns an error when another input already uses the resource name.
    pub fn with_resource(mut self, resource: ResourceInput) -> Result<Self, ToolchainError> {
        if self.resources.contains_key(&resource.name) {
            return Err(ToolchainError::DuplicateResource(resource.name));
        }
        self.resources.insert(resource.name.clone(), resource);
        Ok(self)
    }

    /// Binds one implementation to a measured resource as an ordinary package offer.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identifiers or an exact duplicate binding.
    pub fn with_provider(
        self,
        implementation: ImplementationId,
        capability: CapabilityId,
        artifact: ResourceName,
    ) -> Result<Self, ToolchainError> {
        self.with_provider_extensions(implementation, capability, artifact, BTreeMap::new())
    }

    /// Binds one provider and preserves its explicitly authored offer extensions.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identifiers or an exact duplicate binding.
    /// Package assembly also rejects reserved or otherwise invalid extensions.
    pub fn with_provider_extensions(
        mut self,
        implementation: ImplementationId,
        capability: CapabilityId,
        artifact: ResourceName,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ToolchainError> {
        if !implementation.is_well_formed() || !capability.is_well_formed() {
            return Err(ToolchainError::InvalidBinding(
                "provider implementation or capability is malformed".to_owned(),
            ));
        }
        if self.providers.iter().any(|binding| {
            binding.implementation == implementation
                && binding.capability == capability
                && binding.artifact == artifact
        }) {
            return Err(ToolchainError::DuplicateProviderBinding {
                implementation: implementation.to_string(),
                capability: capability.to_string(),
                artifact: artifact.to_string(),
            });
        }
        self.providers.push(ProviderBinding {
            implementation,
            capability,
            artifact,
            extensions,
        });
        Ok(self)
    }

    /// Records one host-owned independent attester binding.
    ///
    /// This declaration is written only to the toolchain lock. It does not add
    /// an implementation offer to the package manifest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identifiers or an exact duplicate binding.
    pub fn with_attester(
        self,
        suite: ConformanceSuiteId,
        implementation: ImplementationId,
        artifact: ResourceName,
    ) -> Result<Self, ToolchainError> {
        self.with_attester_extensions(
            suite,
            implementation,
            artifact,
            BTreeMap::new(),
            BTreeMap::new(),
        )
    }

    /// Records one attester with explicit attester and authority extensions.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identifiers or an exact duplicate binding.
    /// Authority construction also rejects reserved or otherwise invalid extensions.
    pub fn with_attester_extensions(
        mut self,
        suite: ConformanceSuiteId,
        implementation: ImplementationId,
        artifact: ResourceName,
        attester_extensions: BTreeMap<String, Value>,
        authority_extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ToolchainError> {
        if !suite.is_well_formed() || !implementation.is_well_formed() {
            return Err(ToolchainError::InvalidBinding(
                "attester suite or implementation is malformed".to_owned(),
            ));
        }
        if self.attesters.iter().any(|binding| {
            binding.suite == suite
                && binding.implementation == implementation
                && binding.artifact == artifact
        }) {
            return Err(ToolchainError::DuplicateAttesterRecipe {
                suite: suite.to_string(),
                implementation: implementation.to_string(),
                artifact: artifact.to_string(),
            });
        }
        self.attesters.push(AttesterRecipe {
            suite,
            implementation,
            artifact,
            attester_extensions,
            authority_extensions,
        });
        Ok(self)
    }
}

/// Builder for one independently reloadable, atomic, create-only toolchain image.
#[derive(Clone, Debug, Default)]
pub struct ToolchainImageBuilder {
    packages: Vec<PackageRecipe>,
}

impl ToolchainImageBuilder {
    /// Starts an empty toolchain image.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            packages: Vec::new(),
        }
    }

    /// Adds one package in exact dependency installation order.
    ///
    /// # Errors
    ///
    /// Returns an error when a package identity or output directory is repeated.
    pub fn with_package(mut self, recipe: PackageRecipe) -> Result<Self, ToolchainError> {
        if self
            .packages
            .iter()
            .any(|existing| existing.base.package == recipe.base.package)
        {
            return Err(ToolchainError::DuplicatePackage(
                recipe.base.package.clone(),
            ));
        }
        if self
            .packages
            .iter()
            .any(|existing| existing.relative_directory == recipe.relative_directory)
        {
            return Err(ToolchainError::DuplicatePackageDirectory(
                recipe.relative_directory,
            ));
        }
        self.packages.push(recipe);
        Ok(self)
    }

    /// Stages, independently reloads, and atomically publishes this image.
    ///
    /// The destination must not exist. Resources are written and synchronized
    /// before each package manifest, and the lock is written last.
    ///
    /// # Errors
    ///
    /// Returns an error when validation, bounded assembly, independent reload,
    /// pre-commit synchronization, or create-only publication fails. Once the
    /// atomic rename commits, parent-directory sync failure is returned as
    /// [`PublicationDurability::Uncertain`], not as an error.
    pub fn publish_create(
        self,
        destination: impl AsRef<Path>,
        limits: ToolchainLimits,
    ) -> Result<ToolchainPublication, ToolchainError> {
        limits.validate()?;
        if self.packages.is_empty() {
            return Err(ToolchainError::EmptyImage);
        }
        if self.packages.len() > limits.max_packages {
            return Err(ToolchainError::PackageLimitExceeded {
                actual: self.packages.len(),
                limit: limits.max_packages,
            });
        }
        let destination = destination.as_ref();
        ensure_absent(destination)?;
        let parent = output_parent(destination)?;
        let staging = tempfile::Builder::new()
            .prefix(".gooir-toolchain-")
            .tempdir_in(parent)
            .map_err(|source| io_error("create private staging directory", parent, source))?;
        fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700)).map_err(
            |source| io_error("set staging directory permissions", staging.path(), source),
        )?;

        let lock = stage_image(staging.path(), self.packages, limits)?;
        let independently_loaded = InstalledToolchain::load(staging.path(), limits)?;
        if independently_loaded.lock != lock {
            return Err(ToolchainError::Invariant(
                "independent staging reload produced a different lock".to_owned(),
            ));
        }
        sync_directory(staging.path())?;
        let durability = publish_staging(staging, destination)?;
        Ok(ToolchainPublication { lock, durability })
    }
}

/// Result of a committed create-only toolchain publication.
#[must_use = "publication durability must be inspected after the atomic commit"]
#[derive(Clone, Debug, PartialEq)]
pub struct ToolchainPublication {
    lock: ToolchainLock,
    durability: PublicationDurability,
}

impl ToolchainPublication {
    /// Exact lock independently verified before the atomic publication commit.
    #[must_use]
    pub const fn lock(&self) -> &ToolchainLock {
        &self.lock
    }

    /// Parent-directory synchronization result after the commit point.
    #[must_use]
    pub const fn durability(&self) -> &PublicationDurability {
        &self.durability
    }

    /// Consumes the report and returns the exact published lock.
    #[must_use]
    pub fn into_lock(self) -> ToolchainLock {
        self.lock
    }
}

/// Honest post-commit synchronization status for a published image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationDurability {
    /// Synchronizing the destination parent directory returned successfully.
    ///
    /// This does not claim stronger power-loss guarantees than the host
    /// filesystem supplies.
    DirectorySynchronized,
    /// Atomic publication committed, but parent-directory synchronization failed.
    Uncertain { detail: String },
}

/// RFC 8785/SHA-256 identity of one complete toolchain lock body.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ToolchainLockDigest(String);

impl ToolchainLockDigest {
    /// Parses an exact lowercase SHA-256 identity.
    ///
    /// # Errors
    ///
    /// Returns an error unless the value is `sha256:` followed by 64 lowercase
    /// hexadecimal characters.
    pub fn parse(value: impl Into<String>) -> Result<Self, ToolchainError> {
        let value = value.into();
        if is_sha256(&value) {
            Ok(Self(value))
        } else {
            Err(ToolchainError::InvalidLockDigest(value))
        }
    }

    /// Returns the exact display identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ToolchainLockDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ToolchainLockDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// One exact package directory fixed by a toolchain lock.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedPackage {
    pub package: PackageId,
    pub digest: PackageDigest,
    pub relative_directory: String,
}

/// Host-owned binding from one independent authority to copied package bytes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttesterArtifactBinding {
    pub authority: ConformanceAuthority,
    pub package: PackageId,
    pub package_digest: PackageDigest,
    pub resource: ResourceName,
    pub resource_digest: ResourceDigest,
}

impl AttesterArtifactBinding {
    /// Converts this exact lock entry to the bounded local stdio host binding.
    #[must_use]
    pub fn local_stdio_binding(&self) -> LocalAttesterBinding {
        LocalAttesterBinding {
            authority: self.authority.clone(),
            package: self.package.clone(),
            resource: self.resource.clone(),
        }
    }
}

/// Canonical host-owned deployment lock for exact packages and attesters.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainLock {
    pub protocol: String,
    pub content_digest: ToolchainLockDigest,
    pub packages: Vec<LockedPackage>,
    pub attesters: Vec<AttesterArtifactBinding>,
}

#[derive(Serialize)]
struct LockBody<'lock> {
    protocol: &'lock str,
    packages: &'lock [LockedPackage],
    attesters: &'lock [AttesterArtifactBinding],
}

impl ToolchainLock {
    fn new(
        packages: Vec<LockedPackage>,
        mut attesters: Vec<AttesterArtifactBinding>,
    ) -> Result<Self, ToolchainError> {
        attesters.sort_by_key(attester_key);
        let protocol = TOOLCHAIN_LOCK_PROTOCOL.to_owned();
        let digest = canonical_digest(&LockBody {
            protocol: &protocol,
            packages: &packages,
            attesters: &attesters,
        })
        .map_err(ToolchainError::Serialization)?;
        let lock = Self {
            protocol,
            content_digest: ToolchainLockDigest::parse(digest)?,
            packages,
            attesters,
        };
        lock.validate()?;
        Ok(lock)
    }

    /// Validates all lock coordinates and its canonical content identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the protocol, package coordinates, attester
    /// bindings, canonical ordering, or content digest is invalid.
    pub fn validate(&self) -> Result<(), ToolchainError> {
        if self.protocol != TOOLCHAIN_LOCK_PROTOCOL {
            return Err(ToolchainError::LockProtocolMismatch {
                actual: self.protocol.clone(),
            });
        }
        if self.packages.is_empty() {
            return Err(ToolchainError::EmptyImage);
        }
        let mut package_ids = BTreeSet::new();
        let mut directories = BTreeSet::new();
        for package in &self.packages {
            validate_package_directory(&package.relative_directory)?;
            if !package_ids.insert(package.package.clone()) {
                return Err(ToolchainError::DuplicatePackage(package.package.clone()));
            }
            if !directories.insert(package.relative_directory.clone()) {
                return Err(ToolchainError::DuplicatePackageDirectory(
                    package.relative_directory.clone(),
                ));
            }
        }

        let mut previous = None;
        let mut authorities = BTreeSet::new();
        for binding in &self.attesters {
            binding
                .authority
                .validate()
                .map_err(|error| ToolchainError::InvalidBinding(error.to_string()))?;
            let Some(package) = self
                .packages
                .iter()
                .find(|package| package.package == binding.package)
            else {
                return Err(ToolchainError::UnknownAttesterPackage(
                    binding.package.clone(),
                ));
            };
            if package.digest != binding.package_digest {
                return Err(ToolchainError::AttesterPackageDigestMismatch {
                    package: binding.package.clone(),
                });
            }
            if binding.resource_digest.as_str()
                != binding.authority.attester.artifact_digest.as_str()
            {
                return Err(ToolchainError::AttesterResourceDigestMismatch {
                    package: binding.package.clone(),
                    resource: binding.resource.clone(),
                });
            }
            let key = attester_key(binding);
            if previous.as_ref().is_some_and(|previous| previous >= &key) {
                return Err(ToolchainError::AttestersNotCanonical);
            }
            let authority_key = (
                binding.authority.suite.to_string(),
                binding.authority.attester.implementation.to_string(),
                binding.authority.attester.artifact_digest.to_string(),
            );
            if !authorities.insert(authority_key.clone()) {
                return Err(ToolchainError::DuplicateAttesterAuthority {
                    suite: authority_key.0,
                    implementation: authority_key.1,
                    artifact_digest: authority_key.2,
                });
            }
            previous = Some(key);
        }

        let expected = canonical_digest(&LockBody {
            protocol: &self.protocol,
            packages: &self.packages,
            attesters: &self.attesters,
        })
        .map_err(ToolchainError::Serialization)?;
        if self.content_digest.as_str() != expected {
            return Err(ToolchainError::LockDigestMismatch {
                expected,
                actual: self.content_digest.to_string(),
            });
        }
        Ok(())
    }

    /// Encodes this lock as canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when lock validation or canonical serialization fails.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, ToolchainError> {
        self.validate()?;
        serde_json_canonicalizer::to_vec(self)
            .map_err(|error| ToolchainError::Serialization(error.to_string()))
    }

    /// Strictly decodes and validates one complete lock document.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid JSON, unknown fields, or an invalid lock.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ToolchainError> {
        let lock: Self = strict_json::from_slice(bytes)
            .map_err(|error| ToolchainError::LockJson(error.to_string()))?;
        lock.validate()?;
        Ok(lock)
    }
}

/// Immutable exact package inventory reconstructed from a published image.
#[derive(Clone, Debug)]
pub struct InstalledToolchain {
    registry: PackageRegistry,
    lock: ToolchainLock,
    local_attesters: Vec<LocalAttesterBinding>,
}

impl InstalledToolchain {
    /// Independently loads every exact package and attester named by the lock.
    ///
    /// # Errors
    ///
    /// Returns an error when bounded lock reading, strict validation, exact
    /// package loading, registry installation, or attester validation fails.
    pub fn load(root: impl AsRef<Path>, limits: ToolchainLimits) -> Result<Self, ToolchainError> {
        limits.validate()?;
        let root = root.as_ref();
        let lock_bytes = read_regular_file(
            &root.join(TOOLCHAIN_LOCK_FILE),
            limits.max_lock_bytes,
            "toolchain lock",
        )?;
        let lock = ToolchainLock::from_json(&lock_bytes)?;
        if lock.packages.len() > limits.max_packages {
            return Err(ToolchainError::PackageLimitExceeded {
                actual: lock.packages.len(),
                limit: limits.max_packages,
            });
        }
        if lock.attesters.len() > limits.max_attesters {
            return Err(ToolchainError::AttesterLimitExceeded {
                actual: lock.attesters.len(),
                limit: limits.max_attesters,
            });
        }

        let registry = load_locked_packages(root, &lock, limits)?;

        let mut local_attesters = Vec::with_capacity(lock.attesters.len());
        for binding in &lock.attesters {
            let package = registry
                .package(&binding.package)
                .ok_or_else(|| ToolchainError::UnknownAttesterPackage(binding.package.clone()))?;
            if package.digest() != &binding.package_digest {
                return Err(ToolchainError::AttesterPackageDigestMismatch {
                    package: binding.package.clone(),
                });
            }
            let resource = registry
                .resource(&binding.package, &binding.resource)
                .ok_or_else(|| ToolchainError::MissingAttesterResource {
                    package: binding.package.clone(),
                    resource: binding.resource.clone(),
                })?;
            if resource.digest() != &binding.resource_digest
                || resource.digest().as_str() != binding.authority.attester.artifact_digest.as_str()
            {
                return Err(ToolchainError::AttesterResourceDigestMismatch {
                    package: binding.package.clone(),
                    resource: binding.resource.clone(),
                });
            }
            local_attesters.push(binding.local_stdio_binding());
        }
        validate_independence(&registry, &local_attesters)?;
        Ok(Self {
            registry,
            lock,
            local_attesters,
        })
    }

    /// The exact immutable installed package inventory.
    #[must_use]
    pub const fn registry(&self) -> &PackageRegistry {
        &self.registry
    }

    /// The independently validated deployment lock.
    #[must_use]
    pub const fn lock(&self) -> &ToolchainLock {
        &self.lock
    }

    /// Exact bindings consumable by [`gooir_derive::LocalStdioHost`].
    #[must_use]
    pub fn local_attester_bindings(&self) -> &[LocalAttesterBinding] {
        &self.local_attesters
    }
}

fn load_locked_packages(
    root: &Path,
    lock: &ToolchainLock,
    limits: ToolchainLimits,
) -> Result<PackageRegistry, ToolchainError> {
    let mut registry = PackageRegistry::default();
    let mut total_resource_bytes = 0_u64;
    let mut total_manifest_bytes = 0_u64;
    for expected in &lock.packages {
        let package_limits = package_limits_with_remaining(
            limits.package,
            limits
                .max_total_image_resource_bytes
                .saturating_sub(total_resource_bytes),
            limits
                .max_total_image_manifest_bytes
                .saturating_sub(total_manifest_bytes),
        );
        let loaded = load_local_package(
            root.join(&expected.relative_directory),
            &registry,
            package_limits,
        )
        .map_err(ToolchainError::PackageLoad)?;
        if loaded.manifest().package != expected.package
            || loaded.manifest().content_digest != expected.digest
        {
            return Err(ToolchainError::LockedPackageMismatch {
                expected: expected.package.clone(),
                actual: loaded.manifest().package.clone(),
            });
        }
        total_resource_bytes = total_resource_bytes
            .checked_add(checked_byte_total(
                loaded.resources().map(|resource| resource.bytes().len()),
                "installed image resource length overflowed",
            )?)
            .ok_or_else(|| {
                ToolchainError::Invariant("installed image resource length overflowed".to_owned())
            })?;
        if total_resource_bytes > limits.max_total_image_resource_bytes {
            return Err(ToolchainError::ImageResourceBytesExceeded {
                actual: total_resource_bytes,
                limit: limits.max_total_image_resource_bytes,
            });
        }
        total_manifest_bytes = total_manifest_bytes
            .checked_add(u64::try_from(loaded.manifest_bytes().len()).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                ToolchainError::Invariant("installed image manifest length overflowed".to_owned())
            })?;
        if total_manifest_bytes > limits.max_total_image_manifest_bytes {
            return Err(ToolchainError::ImageManifestBytesExceeded {
                actual: total_manifest_bytes,
                limit: limits.max_total_image_manifest_bytes,
            });
        }
        registry.install(loaded).map_err(ToolchainError::Install)?;
    }
    Ok(registry)
}

#[derive(Debug)]
struct MeasuredResource {
    declaration: PackageResource,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct AssembledPackage {
    relative_directory: String,
    manifest: PackageManifest,
    resources: BTreeMap<ResourceName, MeasuredResource>,
    attesters: Vec<AttesterRecipe>,
}

fn stage_image(
    root: &Path,
    recipes: Vec<PackageRecipe>,
    limits: ToolchainLimits,
) -> Result<ToolchainLock, ToolchainError> {
    let mut registry = PackageRegistry::default();
    let mut locked_packages = Vec::with_capacity(recipes.len());
    let mut pending_attesters = Vec::new();
    let mut total_resource_bytes = 0_u64;
    let mut total_manifest_bytes = 0_u64;
    for recipe in recipes {
        let remaining_resources = limits
            .max_total_image_resource_bytes
            .saturating_sub(total_resource_bytes);
        let remaining_manifests = limits
            .max_total_image_manifest_bytes
            .saturating_sub(total_manifest_bytes);
        let package_limits =
            package_limits_with_remaining(limits.package, remaining_resources, remaining_manifests);
        let assembled = assemble_package(recipe, package_limits)?;
        let package_resource_bytes = checked_byte_total(
            assembled
                .resources
                .values()
                .map(|resource| resource.bytes.len()),
            "assembled image resource length overflowed",
        )?;
        total_resource_bytes = total_resource_bytes
            .checked_add(package_resource_bytes)
            .ok_or_else(|| {
                ToolchainError::Invariant("assembled image resource length overflowed".to_owned())
            })?;
        if total_resource_bytes > limits.max_total_image_resource_bytes {
            return Err(ToolchainError::ImageResourceBytesExceeded {
                actual: total_resource_bytes,
                limit: limits.max_total_image_resource_bytes,
            });
        }
        let manifest_size = u64::try_from(
            write_manifest(&assembled.manifest)
                .map_err(ToolchainError::Manifest)?
                .len(),
        )
        .unwrap_or(u64::MAX);
        total_manifest_bytes =
            total_manifest_bytes
                .checked_add(manifest_size)
                .ok_or_else(|| {
                    ToolchainError::Invariant(
                        "assembled image manifest length overflowed".to_owned(),
                    )
                })?;
        if total_manifest_bytes > limits.max_total_image_manifest_bytes {
            return Err(ToolchainError::ImageManifestBytesExceeded {
                actual: total_manifest_bytes,
                limit: limits.max_total_image_manifest_bytes,
            });
        }
        if pending_attesters.len() + assembled.attesters.len() > limits.max_attesters {
            return Err(ToolchainError::AttesterLimitExceeded {
                actual: pending_attesters.len() + assembled.attesters.len(),
                limit: limits.max_attesters,
            });
        }
        write_package(root, &assembled)?;
        let loaded = load_local_package(
            root.join(&assembled.relative_directory),
            &registry,
            package_limits,
        )
        .map_err(ToolchainError::PackageLoad)?;
        if loaded.manifest() != &assembled.manifest {
            return Err(ToolchainError::Invariant(
                "staged package differs from its assembled manifest".to_owned(),
            ));
        }
        let installed = registry.install(loaded).map_err(ToolchainError::Install)?;
        locked_packages.push(LockedPackage {
            package: installed.package_id().clone(),
            digest: installed.digest().clone(),
            relative_directory: assembled.relative_directory,
        });
        for attester in assembled.attesters {
            pending_attesters.push((installed.clone(), attester));
        }
    }

    let locked_attesters = lock_attesters(pending_attesters)?;
    let local_attesters = locked_attesters
        .iter()
        .map(AttesterArtifactBinding::local_stdio_binding)
        .collect::<Vec<_>>();
    validate_independence(&registry, &local_attesters)?;

    let lock = ToolchainLock::new(locked_packages, locked_attesters)?;
    let lock_bytes = lock.to_canonical_json()?;
    let lock_size = u64::try_from(lock_bytes.len()).unwrap_or(u64::MAX);
    if lock_size > limits.max_lock_bytes {
        return Err(ToolchainError::LockBytesExceeded {
            actual: lock_size,
            limit: limits.max_lock_bytes,
        });
    }
    write_new_file(&root.join(TOOLCHAIN_LOCK_FILE), &lock_bytes, 0o400)?;
    Ok(lock)
}

fn lock_attesters(
    pending: Vec<(InstalledPackage, AttesterRecipe)>,
) -> Result<Vec<AttesterArtifactBinding>, ToolchainError> {
    let mut locked = Vec::with_capacity(pending.len());
    for (package, recipe) in pending {
        let resource = package.resource(&recipe.artifact).ok_or_else(|| {
            ToolchainError::MissingAttesterResource {
                package: package.package_id().clone(),
                resource: recipe.artifact.clone(),
            }
        })?;
        let artifact_digest = ArtifactDigest::parse(resource.digest().to_string())
            .map_err(|error| ToolchainError::InvalidBinding(error.to_string()))?;
        let authority = ConformanceAuthority::new(
            recipe.suite,
            ConformanceAttester::new(
                recipe.implementation,
                artifact_digest,
                recipe.attester_extensions,
            )
            .map_err(|error| ToolchainError::InvalidBinding(error.to_string()))?,
            recipe.authority_extensions,
        )
        .map_err(|error| ToolchainError::InvalidBinding(error.to_string()))?;
        locked.push(AttesterArtifactBinding {
            authority,
            package: package.package_id().clone(),
            package_digest: package.digest().clone(),
            resource: resource.name().clone(),
            resource_digest: resource.digest().clone(),
        });
    }
    Ok(locked)
}

#[allow(clippy::too_many_lines)]
fn assemble_package(
    recipe: PackageRecipe,
    limits: LoadLimits,
) -> Result<AssembledPackage, ToolchainError> {
    if recipe.resources.len() > limits.max_resources {
        return Err(ToolchainError::ResourceLimitExceeded {
            package: recipe.base.package.clone(),
            actual: recipe.resources.len(),
            limit: limits.max_resources,
        });
    }
    let existing = recipe
        .base
        .resources
        .iter()
        .map(|resource| (resource.name.clone(), resource))
        .collect::<BTreeMap<_, _>>();
    for name in existing.keys() {
        if !recipe.resources.contains_key(name) {
            return Err(ToolchainError::MissingResourceInput(name.clone()));
        }
    }

    let mut total = 0_u64;
    let mut paths = BTreeSet::new();
    let mut measured = BTreeMap::new();
    for (name, input) in recipe.resources {
        if !paths.insert(input.path.clone()) {
            return Err(ToolchainError::DuplicateResourcePath(input.path));
        }
        let bytes = match input.source {
            ResourceSource::File(source) => {
                read_regular_file(&source, limits.max_resource_bytes, "resource source")?
            }
            ResourceSource::Bytes(bytes) => {
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limits.max_resource_bytes {
                    return Err(ToolchainError::ResourceBytesExceeded {
                        resource: name.clone(),
                        limit: limits.max_resource_bytes,
                    });
                }
                bytes
            }
        };
        let size = u64::try_from(bytes.len()).map_err(|_| {
            ToolchainError::Invariant("resource length cannot be represented as u64".to_owned())
        })?;
        total = total.checked_add(size).ok_or_else(|| {
            ToolchainError::Invariant("aggregate resource length overflowed".to_owned())
        })?;
        if total > limits.max_total_resource_bytes {
            return Err(ToolchainError::TotalResourceBytesExceeded {
                package: recipe.base.package.clone(),
                limit: limits.max_total_resource_bytes,
            });
        }
        let declaration = PackageResource {
            name: name.clone(),
            path: input.path,
            media_type: input.media_type,
            size,
            digest: ResourceDigest::parse(sha256_identity(&bytes))
                .map_err(|error| ToolchainError::InvalidBinding(error.to_string()))?,
            extensions: input.extensions,
        };
        if existing
            .get(&name)
            .is_some_and(|expected| *expected != &declaration)
        {
            return Err(ToolchainError::DeclaredResourceMismatch(name));
        }
        measured.insert(
            declaration.name.clone(),
            MeasuredResource { declaration, bytes },
        );
    }

    for provider in &recipe.providers {
        if !measured.contains_key(&provider.artifact) {
            return Err(ToolchainError::UnknownBindingResource(
                provider.artifact.clone(),
            ));
        }
    }
    for attester in &recipe.attesters {
        if !measured.contains_key(&attester.artifact) {
            return Err(ToolchainError::UnknownBindingResource(
                attester.artifact.clone(),
            ));
        }
    }

    let mut offers = recipe
        .providers
        .into_iter()
        .map(|binding| ImplementationOfferDeclaration {
            implementation: binding.implementation,
            capability: binding.capability,
            artifact: binding.artifact,
            extensions: binding.extensions,
        })
        .collect::<Vec<_>>();
    offers.sort_by(|left, right| {
        (&left.capability, &left.implementation, &left.artifact).cmp(&(
            &right.capability,
            &right.implementation,
            &right.artifact,
        ))
    });
    let resources = measured
        .values()
        .map(|resource| resource.declaration.clone())
        .collect();
    let manifest = PackageManifest::new(
        recipe.base.package,
        recipe.base.dependencies,
        resources,
        recipe.base.dialects,
        recipe.base.conformance_suites,
        recipe.base.capabilities,
        offers,
        recipe.base.extensions,
    )
    .map_err(ToolchainError::Manifest)?;
    Ok(AssembledPackage {
        relative_directory: recipe.relative_directory,
        manifest,
        resources: measured,
        attesters: recipe.attesters,
    })
}

fn write_package(root: &Path, package: &AssembledPackage) -> Result<(), ToolchainError> {
    let package_root = root.join(&package.relative_directory);
    create_directory(&package_root, 0o700)?;
    for resource in package.resources.values() {
        let path = package_root.join(&resource.declaration.path);
        if let Some(parent) = path.parent() {
            create_directory_tree(&package_root, parent)?;
        }
        write_new_file(&path, &resource.bytes, 0o400)?;
        if let Some(parent) = path.parent() {
            sync_directory(parent)?;
        }
    }
    write_new_file(
        &package_root.join(gooir_package::PACKAGE_MANIFEST_FILE),
        write_manifest(&package.manifest)
            .map_err(ToolchainError::Manifest)?
            .as_bytes(),
        0o400,
    )?;
    sync_directory(&package_root)
}

fn validate_independence(
    registry: &PackageRegistry,
    attesters: &[LocalAttesterBinding],
) -> Result<(), ToolchainError> {
    for attester in attesters {
        for offer in registry.offers() {
            if offer.implementation == attester.authority.attester.implementation
                || offer.artifact_digest == attester.authority.attester.artifact_digest
            {
                return Err(ToolchainError::AttesterNotIndependent {
                    capability: offer.capability.to_string(),
                    implementation: offer.implementation.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn attester_key(binding: &AttesterArtifactBinding) -> (String, String, String, String, String) {
    (
        binding.authority.suite.to_string(),
        binding.authority.attester.implementation.to_string(),
        binding.authority.attester.artifact_digest.to_string(),
        binding.package.to_string(),
        binding.resource.to_string(),
    )
}

fn validate_package_directory(directory: &str) -> Result<(), ToolchainError> {
    if directory.is_empty()
        || directory.len() > 255
        || directory.starts_with('/')
        || directory.contains('/')
        || directory.contains('\\')
        || directory.chars().any(char::is_control)
        || matches!(directory, "." | "..")
        || has_windows_drive_prefix(directory)
    {
        return Err(ToolchainError::UnsafeRelativePath(directory.to_owned()));
    }
    Ok(())
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn package_limits_with_remaining(
    limits: LoadLimits,
    remaining_resources: u64,
    remaining_manifests: u64,
) -> LoadLimits {
    let remaining_resources = remaining_resources.max(1);
    LoadLimits {
        max_manifest_bytes: limits.max_manifest_bytes.min(remaining_manifests.max(1)),
        max_resources: limits.max_resources,
        max_resource_bytes: limits.max_resource_bytes.min(remaining_resources),
        max_total_resource_bytes: limits.max_total_resource_bytes.min(remaining_resources),
    }
}

fn checked_byte_total(
    sizes: impl IntoIterator<Item = usize>,
    overflow_message: &'static str,
) -> Result<u64, ToolchainError> {
    sizes.into_iter().try_fold(0_u64, |total, size| {
        total
            .checked_add(u64::try_from(size).unwrap_or(u64::MAX))
            .ok_or_else(|| ToolchainError::Invariant(overflow_message.to_owned()))
    })
}

fn read_regular_file(
    path: &Path,
    limit: u64,
    scope: &'static str,
) -> Result<Vec<u8>, ToolchainError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| ToolchainError::Filesystem {
        action: "open bounded regular file",
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect bounded regular file", path, source))?;
    if !metadata.is_file() {
        return Err(ToolchainError::NotRegularFile {
            scope,
            path: path.to_path_buf(),
        });
    }
    if metadata.len() > limit {
        return Err(ToolchainError::FileLimitExceeded {
            scope,
            path: path.to_path_buf(),
            actual: metadata.len(),
            limit,
        });
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        ToolchainError::Invariant("file length cannot be represented in memory".to_owned())
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read bounded regular file", path, source))?;
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > limit {
        return Err(ToolchainError::FileLimitExceeded {
            scope,
            path: path.to_path_buf(),
            actual,
            limit,
        });
    }
    if actual != metadata.len() {
        return Err(ToolchainError::FileChanged(path.to_path_buf()));
    }
    Ok(bytes)
}

fn create_directory_tree(root: &Path, directory: &Path) -> Result<(), ToolchainError> {
    let relative = directory.strip_prefix(root).map_err(|_| {
        ToolchainError::Invariant("resource parent escaped its package root".to_owned())
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        if !current.exists() {
            create_directory(&current, 0o700)?;
        }
    }
    Ok(())
}

fn create_directory(path: &Path, mode: u32) -> Result<(), ToolchainError> {
    fs::create_dir(path).map_err(|source| io_error("create directory", path, source))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|source| io_error("set directory permissions", path, source))
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ToolchainError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create image file", path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write image file", path, source))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|source| io_error("set image file permissions", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("synchronize image file", path, source))
}

fn ensure_absent(path: &Path) -> Result<(), ToolchainError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ToolchainError::DestinationExists(path.to_path_buf())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspect destination", path, source)),
    }
}

fn output_parent(output: &Path) -> Result<&Path, ToolchainError> {
    if output.file_name().is_none() {
        return Err(ToolchainError::InvalidDestination(output.to_path_buf()));
    }
    match output.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => Ok(parent),
        Some(_) | None => Ok(Path::new(".")),
    }
}

fn publish_staging(
    staging: tempfile::TempDir,
    output: &Path,
) -> Result<PublicationDurability, ToolchainError> {
    let staging_path = staging.path().to_path_buf();
    let parent_path = output_parent(output)?;
    if output_parent(&staging_path)? != parent_path {
        return Err(ToolchainError::Invariant(
            "staging and destination roots are not siblings".to_owned(),
        ));
    }
    let staging_name = staging_path
        .file_name()
        .ok_or_else(|| ToolchainError::InvalidDestination(staging_path.clone()))?;
    let output_name = output
        .file_name()
        .ok_or_else(|| ToolchainError::InvalidDestination(output.to_path_buf()))?;
    let parent_descriptor = open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| ToolchainError::Filesystem {
        action: "open destination parent",
        path: parent_path.to_path_buf(),
        detail: error.to_string(),
    })?;
    let parent = File::from(parent_descriptor);
    if let Err(error) = renameat_with(
        &parent,
        staging_name,
        &parent,
        output_name,
        RenameFlags::NOREPLACE,
    ) {
        if fs::symlink_metadata(output).is_ok() {
            return Err(ToolchainError::DestinationExists(output.to_path_buf()));
        }
        return Err(ToolchainError::Filesystem {
            action: "atomically publish toolchain image",
            path: output.to_path_buf(),
            detail: error.to_string(),
        });
    }
    let _published = staging.keep();
    Ok(match parent.sync_all() {
        Ok(()) => PublicationDurability::DirectorySynchronized,
        Err(error) => PublicationDurability::Uncertain {
            detail: format!(
                "could not synchronize destination parent {}: {error}",
                parent_path.display()
            ),
        },
    })
}

fn sync_directory(path: &Path) -> Result<(), ToolchainError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| ToolchainError::Filesystem {
        action: "open directory for synchronization",
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;
    File::from(descriptor)
        .sync_all()
        .map_err(|source| io_error("synchronize directory", path, source))
}

fn sha256_identity(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn io_error(action: &'static str, path: &Path, source: std::io::Error) -> ToolchainError {
    ToolchainError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

/// Failure to assemble, publish, or independently load a toolchain image.
#[derive(Debug)]
pub enum ToolchainError {
    InvalidLimits,
    EmptyImage,
    UnsafeRelativePath(String),
    ManifestAlreadyOffers(PackageId),
    DuplicatePackage(PackageId),
    DuplicatePackageDirectory(String),
    DuplicateResource(ResourceName),
    DuplicateResourcePath(String),
    MissingResourceInput(ResourceName),
    DeclaredResourceMismatch(ResourceName),
    UnknownBindingResource(ResourceName),
    DuplicateProviderBinding {
        implementation: String,
        capability: String,
        artifact: String,
    },
    DuplicateAttesterRecipe {
        suite: String,
        implementation: String,
        artifact: String,
    },
    DuplicateAttesterAuthority {
        suite: String,
        implementation: String,
        artifact_digest: String,
    },
    InvalidBinding(String),
    ResourceLimitExceeded {
        package: PackageId,
        actual: usize,
        limit: usize,
    },
    ResourceBytesExceeded {
        resource: ResourceName,
        limit: u64,
    },
    TotalResourceBytesExceeded {
        package: PackageId,
        limit: u64,
    },
    PackageLimitExceeded {
        actual: usize,
        limit: usize,
    },
    AttesterLimitExceeded {
        actual: usize,
        limit: usize,
    },
    ImageResourceBytesExceeded {
        actual: u64,
        limit: u64,
    },
    ImageManifestBytesExceeded {
        actual: u64,
        limit: u64,
    },
    LockBytesExceeded {
        actual: u64,
        limit: u64,
    },
    InvalidLockDigest(String),
    LockProtocolMismatch {
        actual: String,
    },
    LockDigestMismatch {
        expected: String,
        actual: String,
    },
    AttestersNotCanonical,
    UnknownAttesterPackage(PackageId),
    MissingAttesterResource {
        package: PackageId,
        resource: ResourceName,
    },
    AttesterPackageDigestMismatch {
        package: PackageId,
    },
    AttesterResourceDigestMismatch {
        package: PackageId,
        resource: ResourceName,
    },
    AttesterNotIndependent {
        capability: String,
        implementation: String,
    },
    LockedPackageMismatch {
        expected: PackageId,
        actual: PackageId,
    },
    DestinationExists(PathBuf),
    InvalidDestination(PathBuf),
    NotRegularFile {
        scope: &'static str,
        path: PathBuf,
    },
    FileLimitExceeded {
        scope: &'static str,
        path: PathBuf,
        actual: u64,
        limit: u64,
    },
    FileChanged(PathBuf),
    Manifest(PackageManifestError),
    PackageLoad(PackageLoadError),
    Install(InstallError),
    LockJson(String),
    Serialization(String),
    Filesystem {
        action: &'static str,
        path: PathBuf,
        detail: String,
    },
    Io {
        action: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    Invariant(String),
}

impl fmt::Display for ToolchainError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("toolchain limits must be positive"),
            Self::EmptyImage => formatter.write_str("toolchain image must contain a package"),
            Self::UnsafeRelativePath(path) => {
                write!(formatter, "`{path}` is not a safe package directory")
            }
            Self::ManifestAlreadyOffers(package) => {
                write!(formatter, "package {package} is not offer-free")
            }
            Self::DuplicatePackage(package) => write!(formatter, "duplicate package {package}"),
            Self::DuplicatePackageDirectory(directory) => {
                write!(formatter, "duplicate package directory `{directory}`")
            }
            Self::DuplicateResource(resource) => write!(formatter, "duplicate resource {resource}"),
            Self::DuplicateResourcePath(path) => {
                write!(formatter, "duplicate resource path `{path}`")
            }
            Self::MissingResourceInput(resource) => {
                write!(
                    formatter,
                    "declared resource {resource} has no supplied bytes"
                )
            }
            Self::DeclaredResourceMismatch(resource) => {
                write!(
                    formatter,
                    "measured resource {resource} differs from its declaration"
                )
            }
            Self::UnknownBindingResource(resource) => {
                write!(formatter, "binding names unknown resource {resource}")
            }
            Self::DuplicateProviderBinding {
                implementation,
                capability,
                artifact,
            } => write!(
                formatter,
                "duplicate provider binding {implementation} for {capability} through {artifact}"
            ),
            Self::DuplicateAttesterRecipe {
                suite,
                implementation,
                artifact,
            } => write!(
                formatter,
                "duplicate attester binding {implementation} for {suite} through {artifact}"
            ),
            Self::DuplicateAttesterAuthority {
                suite,
                implementation,
                artifact_digest,
            } => write!(
                formatter,
                "duplicate attester authority {implementation} for {suite} at {artifact_digest}"
            ),
            Self::InvalidBinding(detail) => write!(formatter, "invalid artifact binding: {detail}"),
            Self::ResourceLimitExceeded {
                package,
                actual,
                limit,
            } => write!(
                formatter,
                "package {package} has {actual} resource inputs, exceeding {limit}"
            ),
            Self::ResourceBytesExceeded { resource, limit } => {
                write!(formatter, "resource {resource} exceeds {limit} bytes")
            }
            Self::TotalResourceBytesExceeded { package, limit } => write!(
                formatter,
                "package {package} resources exceed aggregate limit {limit}"
            ),
            Self::PackageLimitExceeded { actual, limit } => {
                write!(
                    formatter,
                    "toolchain has {actual} packages, exceeding {limit}"
                )
            }
            Self::AttesterLimitExceeded { actual, limit } => {
                write!(
                    formatter,
                    "toolchain has {actual} attesters, exceeding {limit}"
                )
            }
            Self::ImageResourceBytesExceeded { actual, limit } => write!(
                formatter,
                "toolchain resources total {actual} bytes, exceeding image limit {limit}"
            ),
            Self::ImageManifestBytesExceeded { actual, limit } => write!(
                formatter,
                "toolchain manifests total {actual} bytes, exceeding image limit {limit}"
            ),
            Self::LockBytesExceeded { actual, limit } => write!(
                formatter,
                "toolchain lock is {actual} bytes, exceeding {limit}"
            ),
            Self::InvalidLockDigest(digest) => write!(formatter, "invalid lock digest `{digest}`"),
            Self::LockProtocolMismatch { actual } => write!(
                formatter,
                "toolchain lock protocol `{actual}` is not `{TOOLCHAIN_LOCK_PROTOCOL}`"
            ),
            Self::LockDigestMismatch { expected, actual } => write!(
                formatter,
                "toolchain lock digest mismatch: expected {expected}, got {actual}"
            ),
            Self::AttestersNotCanonical => {
                formatter.write_str("toolchain attester bindings are not canonical")
            }
            Self::UnknownAttesterPackage(package) => {
                write!(formatter, "attester package {package} is not locked")
            }
            Self::MissingAttesterResource { package, resource } => {
                write!(
                    formatter,
                    "attester resource {package}/{resource} is unavailable"
                )
            }
            Self::AttesterPackageDigestMismatch { package } => {
                write!(formatter, "attester package {package} changed digest")
            }
            Self::AttesterResourceDigestMismatch { package, resource } => {
                write!(
                    formatter,
                    "attester resource {package}/{resource} changed digest"
                )
            }
            Self::AttesterNotIndependent {
                capability,
                implementation,
            } => write!(
                formatter,
                "attester is not independent of provider {implementation} for {capability}"
            ),
            Self::LockedPackageMismatch { expected, actual } => write!(
                formatter,
                "locked package {expected} was substituted by {actual}"
            ),
            Self::DestinationExists(path) => {
                write!(formatter, "destination {} already exists", path.display())
            }
            Self::InvalidDestination(path) => {
                write!(formatter, "invalid destination {}", path.display())
            }
            Self::NotRegularFile { scope, path } => {
                write!(
                    formatter,
                    "{scope} {} is not a regular file",
                    path.display()
                )
            }
            Self::FileLimitExceeded {
                scope,
                path,
                actual,
                limit,
            } => write!(
                formatter,
                "{scope} {} is {actual} bytes, exceeding {limit}",
                path.display()
            ),
            Self::FileChanged(path) => {
                write!(
                    formatter,
                    "file {} changed while being read",
                    path.display()
                )
            }
            Self::Manifest(error) => write!(formatter, "package manifest failed: {error}"),
            Self::PackageLoad(error) => write!(formatter, "package load failed: {error}"),
            Self::Install(error) => write!(formatter, "package install failed: {error}"),
            Self::LockJson(detail) => write!(formatter, "toolchain lock JSON failed: {detail}"),
            Self::Serialization(detail) => write!(formatter, "canonical JSON failed: {detail}"),
            Self::Filesystem {
                action,
                path,
                detail,
            } => {
                write!(formatter, "could not {action} {}: {detail}", path.display())
            }
            Self::Io {
                action,
                path,
                source,
            } => {
                write!(formatter, "could not {action} {}: {source}", path.display())
            }
            Self::Invariant(detail) => formatter.write_str(detail),
        }
    }
}

impl Error for ToolchainError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Manifest(error) => Some(error),
            Self::PackageLoad(error) => Some(error),
            Self::Install(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
