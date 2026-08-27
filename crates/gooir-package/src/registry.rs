//! Atomic in-memory admission of already validated package bytes.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use gooir_capability::protocol::{CapabilityOffer, ConformanceSuiteId, ImplementationId, OfferId};
use gooir_capability::{CapabilityId, CapabilitySpec, DialectId, ValueKindId};

use crate::loader::{OwnedResource, ValidatedPackage};
use crate::{
    ConformanceSuiteDeclaration, DialectDeclaration, PackageDigest, PackageId, PackageManifest,
    ResourceName, ValueKindDeclaration,
};

#[derive(Clone, Debug)]
struct OwnedDeclaration<T> {
    owner: PackageId,
    declaration: T,
}

#[derive(Clone, Debug)]
struct InstalledOffer {
    offer: CapabilityOffer,
    artifact: OwnedResource,
}

#[derive(Clone, Debug)]
struct InstalledPackageData {
    manifest: Arc<PackageManifest>,
    manifest_bytes: Arc<[u8]>,
    resources: BTreeMap<ResourceName, OwnedResource>,
    dependencies: Vec<InstalledPackage>,
}

/// Non-forgeable handle to one exact package already installed in a registry.
#[derive(Clone, Debug)]
pub struct InstalledPackage(Arc<InstalledPackageData>);

impl InstalledPackage {
    /// Exact semantic manifest whose resources were copied before installation.
    #[must_use]
    pub fn manifest(&self) -> &PackageManifest {
        &self.0.manifest
    }

    /// Exact package identity.
    #[must_use]
    pub fn package_id(&self) -> &PackageId {
        &self.0.manifest.package
    }

    /// Exact manifest content digest.
    #[must_use]
    pub fn digest(&self) -> &PackageDigest {
        &self.0.manifest.content_digest
    }

    /// Exact manifest bytes copied by the loader.
    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.0.manifest_bytes
    }

    /// One package-local resource retained as owned bytes.
    #[must_use]
    pub fn resource(&self, name: &ResourceName) -> Option<&OwnedResource> {
        self.0.resources.get(name)
    }

    /// Exact direct dependency handles captured at load time.
    #[must_use]
    pub fn dependencies(&self) -> &[InstalledPackage] {
        &self.0.dependencies
    }
}

/// Monotonic in-memory index of validated package availability.
///
/// Installation establishes ownership and availability only. This registry
/// performs no discovery, selection, execution, conformance, or admission and
/// has no uninstall operation.
#[derive(Clone, Debug, Default)]
pub struct PackageRegistry {
    packages: BTreeMap<PackageId, InstalledPackage>,
    resources: BTreeMap<(PackageId, ResourceName), OwnedResource>,
    dialects: BTreeMap<DialectId, OwnedDeclaration<DialectDeclaration>>,
    value_kinds: BTreeMap<ValueKindId, OwnedDeclaration<ValueKindDeclaration>>,
    conformance_suites: BTreeMap<ConformanceSuiteId, OwnedDeclaration<ConformanceSuiteDeclaration>>,
    capabilities: BTreeMap<CapabilityId, OwnedDeclaration<CapabilitySpec>>,
    implementations: BTreeMap<ImplementationId, PackageId>,
    offers: BTreeMap<OfferId, InstalledOffer>,
}

impl PackageRegistry {
    /// Atomically installs one validated package.
    ///
    /// Reinstalling the same package identity and digest is exactly idempotent.
    /// Every collision and dependency check completes against a cloned index
    /// before `self` is replaced, so an error cannot publish a partial package.
    ///
    /// # Errors
    ///
    /// Returns an error when a dependency handle is unavailable, the package
    /// identity names different content, an exported identity is already owned
    /// by another package, or two declarations collapse to one offer identity.
    pub fn install(&mut self, package: ValidatedPackage) -> Result<InstalledPackage, InstallError> {
        package
            .validate_against(self)
            .map_err(InstallError::InvalidPackage)?;

        let package_id = package.manifest.package.clone();
        let package_digest = package.manifest.content_digest.clone();
        if let Some(existing) = self.packages.get(&package_id) {
            if existing.digest() == &package_digest {
                return Ok(existing.clone());
            }
            return Err(InstallError::PackageIdentityCollision {
                package: package_id,
                installed: existing.digest().clone(),
                proposed: package_digest,
            });
        }

        let mut next = self.clone();
        next.install_new(package)?;
        let installed = next
            .packages
            .get(&package_id)
            .ok_or(InstallError::PublicationInvariant)?
            .clone();
        *self = next;
        Ok(installed)
    }

    fn install_new(&mut self, package: ValidatedPackage) -> Result<(), InstallError> {
        let owner = package.manifest.package.clone();
        self.preflight_ownership(&package, &owner)?;

        let installed = InstalledPackage(Arc::new(InstalledPackageData {
            manifest: Arc::clone(&package.manifest),
            manifest_bytes: Arc::clone(&package.manifest_bytes),
            resources: package.resources.clone(),
            dependencies: package.dependencies.clone(),
        }));

        for (name, resource) in &package.resources {
            self.resources
                .insert((owner.clone(), name.clone()), resource.clone());
        }
        for dialect in &package.manifest.dialects {
            self.dialects.insert(
                dialect.id.clone(),
                OwnedDeclaration {
                    owner: owner.clone(),
                    declaration: dialect.clone(),
                },
            );
            for value_kind in &dialect.value_kinds {
                self.value_kinds.insert(
                    value_kind.id.clone(),
                    OwnedDeclaration {
                        owner: owner.clone(),
                        declaration: value_kind.clone(),
                    },
                );
            }
        }
        for suite in &package.manifest.conformance_suites {
            self.conformance_suites.insert(
                suite.id.clone(),
                OwnedDeclaration {
                    owner: owner.clone(),
                    declaration: suite.clone(),
                },
            );
        }
        for capability in &package.manifest.capabilities {
            self.capabilities.insert(
                capability.id.clone(),
                OwnedDeclaration {
                    owner: owner.clone(),
                    declaration: capability.clone(),
                },
            );
        }
        for declaration in &package.manifest.implementation_offers {
            self.implementations
                .insert(declaration.implementation.clone(), owner.clone());
        }
        for (offer_id, validated) in package.offers {
            self.offers.insert(
                offer_id,
                InstalledOffer {
                    offer: validated.offer,
                    artifact: validated.artifact,
                },
            );
        }
        self.packages.insert(owner, installed);
        Ok(())
    }

    fn preflight_ownership(
        &self,
        package: &ValidatedPackage,
        owner: &PackageId,
    ) -> Result<(), InstallError> {
        for dialect in &package.manifest.dialects {
            for value_kind in &dialect.value_kinds {
                ensure_owner_available(&self.value_kinds, &value_kind.id, owner, "value kind")?;
            }
        }
        for dialect in &package.manifest.dialects {
            ensure_owner_available(&self.dialects, &dialect.id, owner, "dialect")?;
        }
        for suite in &package.manifest.conformance_suites {
            ensure_owner_available(
                &self.conformance_suites,
                &suite.id,
                owner,
                "conformance suite",
            )?;
        }
        for capability in &package.manifest.capabilities {
            ensure_owner_available(&self.capabilities, &capability.id, owner, "capability")?;
        }
        for declaration in &package.manifest.implementation_offers {
            if let Some(installed_owner) = self.implementations.get(&declaration.implementation)
                && installed_owner != owner
            {
                return Err(InstallError::OwnershipCollision {
                    kind: "implementation",
                    identity: declaration.implementation.to_string(),
                    installed_owner: installed_owner.clone(),
                    proposed_owner: owner.clone(),
                });
            }
        }

        let mut local_offer_ids = BTreeMap::new();
        for (offer_id, validated) in &package.offers {
            if self.offers.contains_key(offer_id)
                || local_offer_ids
                    .insert(offer_id.clone(), validated.artifact.name().clone())
                    .is_some()
            {
                return Err(InstallError::OfferIdentityCollision(offer_id.clone()));
            }
        }
        Ok(())
    }

    /// Looks up an exact installed package.
    #[must_use]
    pub fn package(&self, package: &PackageId) -> Option<&InstalledPackage> {
        self.packages.get(package)
    }

    /// Looks up exact owned resource bytes by package-local name.
    #[must_use]
    pub fn resource(&self, package: &PackageId, name: &ResourceName) -> Option<&OwnedResource> {
        self.resources.get(&(package.clone(), name.clone()))
    }

    /// Returns the owning package and declaration for one dialect.
    #[must_use]
    pub fn dialect(&self, id: &DialectId) -> Option<(&PackageId, &DialectDeclaration)> {
        self.dialects
            .get(id)
            .map(|entry| (&entry.owner, &entry.declaration))
    }

    /// Returns the owning package and declaration for one value kind.
    #[must_use]
    pub fn value_kind(&self, id: &ValueKindId) -> Option<(&PackageId, &ValueKindDeclaration)> {
        self.value_kinds
            .get(id)
            .map(|entry| (&entry.owner, &entry.declaration))
    }

    /// Returns the owning package and declaration for one conformance suite.
    #[must_use]
    pub fn conformance_suite(
        &self,
        id: &ConformanceSuiteId,
    ) -> Option<(&PackageId, &ConformanceSuiteDeclaration)> {
        self.conformance_suites
            .get(id)
            .map(|entry| (&entry.owner, &entry.declaration))
    }

    /// Returns the owning package and declaration for one capability.
    #[must_use]
    pub fn capability(&self, id: &CapabilityId) -> Option<(&PackageId, &CapabilitySpec)> {
        self.capabilities
            .get(id)
            .map(|entry| (&entry.owner, &entry.declaration))
    }

    /// Iterates over every installed capability and its exact owning package,
    /// in capability-identity order.
    ///
    /// This is complete installed availability, not discovery, ranking, or
    /// implementation selection.
    pub fn capabilities(&self) -> impl Iterator<Item = (&PackageId, &CapabilitySpec)> {
        self.capabilities
            .values()
            .map(|entry| (&entry.owner, &entry.declaration))
    }

    /// Returns the package that owns one implementation identity.
    #[must_use]
    pub fn implementation_owner(&self, id: &ImplementationId) -> Option<&PackageId> {
        self.implementations.get(id)
    }

    /// Returns one exact derived availability offer.
    #[must_use]
    pub fn offer(&self, id: &OfferId) -> Option<&CapabilityOffer> {
        self.offers.get(id).map(|installed| &installed.offer)
    }

    /// Iterates over every exact installed implementation offer in offer-ID
    /// order. The iterator does not select or rank an implementation.
    pub fn offers(&self) -> impl Iterator<Item = &CapabilityOffer> {
        self.offers.values().map(|installed| &installed.offer)
    }

    /// Returns the owned bytes bound to one exact offer ID.
    #[must_use]
    pub fn offer_artifact(&self, id: &OfferId) -> Option<&OwnedResource> {
        self.offers.get(id).map(|installed| &installed.artifact)
    }

    pub(crate) fn exact_dependencies(
        &self,
        dependencies: &[crate::PackageDependency],
    ) -> Result<Vec<InstalledPackage>, crate::PackageLoadError> {
        dependencies
            .iter()
            .map(|dependency| {
                let installed = self.packages.get(&dependency.package).ok_or_else(|| {
                    crate::PackageLoadError::MissingDependency {
                        package: dependency.package.clone(),
                        digest: dependency.digest.clone(),
                    }
                })?;
                if installed.digest() != &dependency.digest {
                    return Err(crate::PackageLoadError::DependencyDigestMismatch {
                        package: dependency.package.clone(),
                        expected: dependency.digest.clone(),
                        actual: installed.digest().clone(),
                    });
                }
                Ok(installed.clone())
            })
            .collect()
    }
}

fn ensure_owner_available<K: Ord + fmt::Display, T>(
    index: &BTreeMap<K, OwnedDeclaration<T>>,
    identity: &K,
    proposed_owner: &PackageId,
    kind: &'static str,
) -> Result<(), InstallError> {
    if let Some(existing) = index.get(identity)
        && &existing.owner != proposed_owner
    {
        return Err(InstallError::OwnershipCollision {
            kind,
            identity: identity.to_string(),
            installed_owner: existing.owner.clone(),
            proposed_owner: proposed_owner.clone(),
        });
    }
    Ok(())
}

/// Atomic registry installation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstallError {
    InvalidPackage(crate::PackageLoadError),
    PackageIdentityCollision {
        package: PackageId,
        installed: PackageDigest,
        proposed: PackageDigest,
    },
    OwnershipCollision {
        kind: &'static str,
        identity: String,
        installed_owner: PackageId,
        proposed_owner: PackageId,
    },
    OfferIdentityCollision(OfferId),
    PublicationInvariant,
}

impl fmt::Display for InstallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPackage(error) => write!(formatter, "package is not installable: {error}"),
            Self::PackageIdentityCollision {
                package,
                installed,
                proposed,
            } => write!(
                formatter,
                "package `{package}` is already installed as {installed}, not {proposed}"
            ),
            Self::OwnershipCollision {
                kind,
                identity,
                installed_owner,
                proposed_owner,
            } => write!(
                formatter,
                "{kind} `{identity}` is owned by `{installed_owner}`, not `{proposed_owner}`"
            ),
            Self::OfferIdentityCollision(offer) => {
                write!(
                    formatter,
                    "offer identity `{offer}` is already installed or ambiguous"
                )
            }
            Self::PublicationInvariant => {
                formatter.write_str("atomic install did not publish the validated package")
            }
        }
    }
}

impl std::error::Error for InstallError {}
