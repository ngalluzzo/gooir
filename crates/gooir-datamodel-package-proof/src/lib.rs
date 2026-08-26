//! Content-addressed four-package proof for the external authored-data-model path.
//!
//! The stager consumes two already-final native executables. It never invokes a
//! compiler, package manager, or Cargo, and it never appends a manifest to an
//! executable. Instead it copies the exact measured bytes into two target-
//! qualified packages. Package resources are written before the package
//! manifest. A complete, independently verified tree is published with one
//! atomic no-replace rename, and a pre-existing output root is always refused.
//!
//! The verifier independently installs the vocabulary, contract, producer, and
//! attester packages through `org.gooi.package/v1`. It proves the semantic
//! planner has an explicit need before the producer is installed, can link the
//! exact measured producer offer afterwards, and is unchanged when the
//! resource-only attester package is installed. Process execution, admission,
//! and trust remain responsibilities of the later execution host.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::num::NonZeroUsize;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use gooir_author_data_model_contract::{
    AUTHORED_SPEC_SCHEMA_BYTES, AUTHORED_SPEC_SCHEMA_PATH, AuthoredSpec,
    author_data_model_capability_id, author_data_model_spec, author_data_model_suite_id,
    authored_entity_spec_value_kind, package_manifest as contract_manifest,
};
use gooir_capability::protocol::{
    AdmittedFactRef, ArtifactDigest, AuthorityRecordId, CapabilityOffer, LinkedInput,
};
use gooir_capability::{Fact, PortName};
use gooir_package::{
    ImplementationOfferDeclaration, InstallError, InstalledPackage, LoadLimits, OwnedResource,
    PackageDependency, PackageDigest, PackageId, PackageLoadError, PackageManifest,
    PackageManifestError, PackageRegistry, PackageResource, ResourceDigest, ResourceName,
    load_local_package, read_manifest, write_manifest,
};
use gooir_planning::{InvocationLink, PlanLimits, PlanningError, SemanticPlan, SemanticPlanner};
use rustix::fs::{Mode, OFlags, RenameFlags, open, renameat_with};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Exact proof report protocol. It describes a host-local deployment lock; it
/// is not a GOOIR semantic or package protocol.
pub const PROOF_REPORT_PROTOCOL: &str = "org.gooi.proof.data-model-external-packages/v1";

/// Target-qualified package containing the final entity-spec provider bytes.
pub const PROVIDER_PACKAGE: &str =
    "org.gooi.implementation.entity_spec_rust.aarch64_apple_darwin@1.1.0";

/// Target-qualified package containing the final independent attester bytes.
pub const ATTESTER_PACKAGE: &str =
    "org.gooi.attester.author_data_model_tasks_entities_oracle.aarch64_apple_darwin@1.1.0";

/// Package-local resource name of the provider executable.
pub const PROVIDER_RESOURCE: &str = "provider-executable";

/// Package-local path of the provider executable.
pub const PROVIDER_RESOURCE_PATH: &str = "bin/author_data_model_provider";

/// Package-local resource name of the attester executable.
pub const ATTESTER_RESOURCE: &str = "attester-executable";

/// Package-local path of the attester executable.
pub const ATTESTER_RESOURCE_PATH: &str = "bin/gooir-datamodel-conformance";

const VOCABULARY_DIRECTORY: &str = "01-data-model-vocabulary";
const CONTRACT_DIRECTORY: &str = "02-author-data-model-contract";
const PROVIDER_DIRECTORY: &str = "03-entity-spec-provider-aarch64-apple-darwin";
const ATTESTER_DIRECTORY: &str = "04-tasks-entities-attester-aarch64-apple-darwin";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_RESOURCE_BYTES: u64 = 256 * 1024 * 1024;

/// Inputs to one staging operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageRequest {
    pub provider_binary: PathBuf,
    pub attester_binary: PathBuf,
    pub output_root: PathBuf,
}

/// Exact installed coordinates for one package resource.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceCoordinate {
    pub name: ResourceName,
    pub path: String,
    pub media_type: String,
    pub size: u64,
    pub digest: ResourceDigest,
}

/// Exact installed coordinates for one package and its copied resources.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PackageCoordinate {
    pub package: PackageId,
    pub digest: PackageDigest,
    pub relative_directory: String,
    pub resources: Vec<ResourceCoordinate>,
}

/// Host-owned deployment lock for the independently measured attester.
///
/// This tuple is deliberately proof-local. It does not extend the package
/// manifest, select an attester through the semantic planner, or claim trust.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AttesterDeploymentLock {
    pub suite: String,
    pub implementation: String,
    pub package: PackageId,
    pub package_digest: PackageDigest,
    pub resource: ResourceName,
    pub resource_digest: ResourceDigest,
}

/// Evidence derived from installing and planning over the staged packages.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProofReport {
    pub protocol: String,
    pub installation_order: Vec<PackageId>,
    pub packages: Vec<PackageCoordinate>,
    pub capability: String,
    pub contract_only_need: String,
    pub contract_only_plan_id: String,
    pub provider_plan_id: String,
    pub post_attester_plan_id: String,
    pub provider_implementation: String,
    pub provider_offer_id: String,
    pub provider_invocation_id: String,
    pub attester: AttesterDeploymentLock,
}

/// Fully owned result of independently loading and verifying one exact package set.
///
/// The installed registry retains the copied manifest and resource bytes, so
/// callers do not need to keep the source package directories present. The
/// registry itself remains private: an external execution host can resolve only
/// the exact provider binding established by this proof and an attester resource
/// named by the proof's explicit deployment lock.
#[derive(Clone, Debug)]
pub struct VerifiedPackageSet {
    registry: PackageRegistry,
    report: ProofReport,
    provider_offer: CapabilityOffer,
    provider_artifact: OwnedResource,
}

impl VerifiedPackageSet {
    /// Exact report derived from the installed package set.
    #[must_use]
    pub fn report(&self) -> &ProofReport {
        &self.report
    }

    /// Consumes the owned package set and returns its compatibility report.
    #[must_use]
    pub fn into_report(self) -> ProofReport {
        self.report
    }

    /// Exact verified provider offer selected by this package proof.
    #[must_use]
    pub fn provider_offer(&self) -> &CapabilityOffer {
        &self.provider_offer
    }

    /// Package-owned executable bytes bound to the exact provider offer.
    #[must_use]
    pub fn provider_artifact(&self) -> &OwnedResource {
        &self.provider_artifact
    }

    /// Constructs a bounded planner from the exact verified installed inventory.
    ///
    /// The registry remains private, while the returned planner can plan and
    /// link caller-selected invocations against precisely the package set that
    /// produced [`Self::report`].
    ///
    /// # Errors
    ///
    /// Refuses any installed inventory that exceeds the caller's explicit
    /// planning bounds or has become internally inconsistent.
    pub fn planner(&self, limits: PlanLimits) -> Result<SemanticPlanner, PlanningError> {
        SemanticPlanner::from_registry(&self.registry, limits)
    }

    /// Resolves the independently packaged attester only through its complete
    /// host-owned deployment lock.
    ///
    /// This performs no semantic discovery. A caller must present the exact
    /// suite, implementation, package, package digest, resource, and resource
    /// digest recorded by [`Self::report`]. Any changed coordinate is refused.
    #[must_use]
    pub fn attester_resource(&self, deployment: &AttesterDeploymentLock) -> Option<&OwnedResource> {
        if deployment != &self.report.attester {
            return None;
        }
        let package = self.registry.package(&deployment.package)?;
        if package.digest() != &deployment.package_digest {
            return None;
        }
        let resource = self
            .registry
            .resource(&deployment.package, &deployment.resource)?;
        (resource.digest() == &deployment.resource_digest).then_some(resource)
    }
}

/// Stages the exact supplied executable bytes and verifies the resulting
/// four-package graph without ever launching the executables.
///
/// Each supplied final binary is opened and consumed exactly once. All later
/// validation reads only the staged, package-owned copies. The output root must
/// not exist; a partial prior attempt is intentionally not overwritten.
///
/// # Errors
///
/// Refuses an existing output root, a non-regular or non-executable source,
/// oversized bytes, invalid package construction, unsafe filesystem state, or
/// any failed installation/planning invariant.
pub fn stage(request: StageRequest) -> Result<ProofReport, ProofError> {
    let StageRequest {
        provider_binary,
        attester_binary,
        output_root,
    } = request;
    ensure_output_absent(&output_root)?;

    let provider_bytes = read_final_binary(&provider_binary)?;
    let attester_bytes = read_final_binary(&attester_binary)?;
    if sha256_identity(&provider_bytes) == sha256_identity(&attester_bytes) {
        return Err(ProofError::Invariant(
            "provider and attester executable digests must be distinct".to_owned(),
        ));
    }

    let parent = output_parent(&output_root)?;
    let staging = tempfile::Builder::new()
        .prefix(".gooir-datamodel-packages-")
        .tempdir_in(parent)
        .map_err(|source| ProofError::Io {
            action: "create private staging directory",
            path: parent.to_path_buf(),
            source,
        })?;
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700)).map_err(|source| {
        ProofError::Io {
            action: "set staging directory permissions",
            path: staging.path().to_path_buf(),
            source,
        }
    })?;

    let staged_report = stage_packages(staging.path(), &provider_bytes, &attester_bytes)?;
    let independently_verified = verify(staging.path())?;
    if staged_report != independently_verified {
        return Err(ProofError::Invariant(
            "independent staging verification produced a different deployment lock".to_owned(),
        ));
    }
    sync_directory(staging.path())?;
    publish_staging(staging, &output_root)?;

    let published_report = verify(&output_root)?;
    if published_report != independently_verified {
        return Err(ProofError::Invariant(
            "published package graph differs from the independently verified staging graph"
                .to_owned(),
        ));
    }
    Ok(published_report)
}

fn stage_packages(
    root: &Path,
    provider_bytes: &[u8],
    attester_bytes: &[u8],
) -> Result<ProofReport, ProofError> {
    let mut registry = PackageRegistry::default();

    let vocabulary_manifest =
        read_manifest(semantics_data_model_v1::PACKAGE_MANIFEST).map_err(ProofError::Manifest)?;
    let vocabulary = write_load_install(
        root,
        VOCABULARY_DIRECTORY,
        &vocabulary_manifest,
        &[],
        &mut registry,
    )?;

    let contract = contract_manifest(&vocabulary).map_err(|error| {
        ProofError::Invariant(format!("could not bind contract package: {error}"))
    })?;
    let contract = write_load_install(
        root,
        CONTRACT_DIRECTORY,
        &contract,
        &[ResourceBytes {
            path: AUTHORED_SPEC_SCHEMA_PATH,
            bytes: AUTHORED_SPEC_SCHEMA_BYTES,
            executable: false,
        }],
        &mut registry,
    )?;

    let contract_only_plan = plan_authoring(&registry)?;
    assert_contract_only_need(&contract_only_plan)?;

    let provider = provider_manifest(&contract, provider_bytes)?;
    let provider = write_load_install(
        root,
        PROVIDER_DIRECTORY,
        &provider,
        &[ResourceBytes {
            path: PROVIDER_RESOURCE_PATH,
            bytes: provider_bytes,
            executable: true,
        }],
        &mut registry,
    )?;

    let provider_planner = planner(&registry)?;
    let provider_plan = provider_planner
        .plan(
            [authored_entity_spec_value_kind()],
            semantics_data_model_v1::model_contract(),
        )
        .map_err(ProofError::Planning)?;
    let invocation = link_synthetic_invocation(&provider_planner, &provider_plan)?;

    let attester = attester_manifest(&contract, attester_bytes)?;
    let attester = write_load_install(
        root,
        ATTESTER_DIRECTORY,
        &attester,
        &[ResourceBytes {
            path: ATTESTER_RESOURCE_PATH,
            bytes: attester_bytes,
            executable: true,
        }],
        &mut registry,
    )?;

    build_report(
        InstalledProof {
            registry: &registry,
            vocabulary: &vocabulary,
            contract: &contract,
            provider: &provider,
            attester: &attester,
        },
        PlanningProof {
            contract_only: &contract_only_plan,
            provider: &provider_plan,
            invocation: &invocation,
        },
    )
}

/// Independently reloads and verifies a staged four-package proof.
///
/// Packages are loaded and installed only in dependency order. The report is
/// derived from the copied manifest/resource bytes rather than from a receipt
/// emitted by [`stage`].
///
/// # Errors
///
/// Refuses any loader, dependency, digest, offer, planner, link, or proof
/// invariant failure.
pub fn verify(root: impl AsRef<Path>) -> Result<ProofReport, ProofError> {
    verify_package_set(root).map(VerifiedPackageSet::into_report)
}

/// Independently loads, installs, and verifies an owned four-package proof.
///
/// Unlike [`verify`], this retains the complete installed registry so an
/// external execution host can use the exact verified executable bytes after
/// the package directories disappear. Only the proof-bound provider and the
/// explicitly locked attester are exposed.
///
/// # Errors
///
/// Refuses any loader, dependency, digest, offer, planner, link, or proof
/// invariant failure.
pub fn verify_package_set(root: impl AsRef<Path>) -> Result<VerifiedPackageSet, ProofError> {
    let root = root.as_ref();
    let mut registry = PackageRegistry::default();

    let vocabulary = load_install(root, VOCABULARY_DIRECTORY, &mut registry)?;
    let contract = load_install(root, CONTRACT_DIRECTORY, &mut registry)?;
    let contract_only_plan = plan_authoring(&registry)?;
    assert_contract_only_need(&contract_only_plan)?;

    let provider = load_install(root, PROVIDER_DIRECTORY, &mut registry)?;
    let provider_planner = planner(&registry)?;
    let provider_plan = provider_planner
        .plan(
            [authored_entity_spec_value_kind()],
            semantics_data_model_v1::model_contract(),
        )
        .map_err(ProofError::Planning)?;
    let invocation = link_synthetic_invocation(&provider_planner, &provider_plan)?;

    let attester = load_install(root, ATTESTER_DIRECTORY, &mut registry)?;
    let report = build_report(
        InstalledProof {
            registry: &registry,
            vocabulary: &vocabulary,
            contract: &contract,
            provider: &provider,
            attester: &attester,
        },
        PlanningProof {
            contract_only: &contract_only_plan,
            provider: &provider_plan,
            invocation: &invocation,
        },
    )?;
    let provider_offer = exact_provider_offer(&registry)?.clone();
    let provider_artifact = registry
        .offer_artifact(&provider_offer.offer_id)
        .ok_or_else(|| {
            ProofError::Invariant(
                "verified provider offer did not retain its package-owned artifact".to_owned(),
            )
        })?
        .clone();
    Ok(VerifiedPackageSet {
        registry,
        report,
        provider_offer,
        provider_artifact,
    })
}

#[derive(Clone, Copy)]
struct InstalledProof<'installed> {
    registry: &'installed PackageRegistry,
    vocabulary: &'installed InstalledPackage,
    contract: &'installed InstalledPackage,
    provider: &'installed InstalledPackage,
    attester: &'installed InstalledPackage,
}

#[derive(Clone, Copy)]
struct PlanningProof<'planned> {
    contract_only: &'planned SemanticPlan,
    provider: &'planned SemanticPlan,
    invocation: &'planned gooir_capability::protocol::CapabilityInvocation,
}

fn build_report(
    installed: InstalledProof<'_>,
    planning: PlanningProof<'_>,
) -> Result<ProofReport, ProofError> {
    validate_package_graph(installed)?;
    let bindings = validate_planning_bindings(installed, planning)?;
    let vocabulary = installed.vocabulary;
    let contract = installed.contract;
    let provider = installed.provider;
    let attester = installed.attester;
    let contract_only_plan = planning.contract_only;
    let provider_plan = planning.provider;
    let invocation = planning.invocation;

    let packages = vec![
        package_coordinate(vocabulary, VOCABULARY_DIRECTORY),
        package_coordinate(contract, CONTRACT_DIRECTORY),
        package_coordinate(provider, PROVIDER_DIRECTORY),
        package_coordinate(attester, ATTESTER_DIRECTORY),
    ];
    let installation_order = packages
        .iter()
        .map(|coordinate| coordinate.package.clone())
        .collect();
    Ok(ProofReport {
        protocol: PROOF_REPORT_PROTOCOL.to_owned(),
        installation_order,
        packages,
        capability: author_data_model_capability_id().to_string(),
        contract_only_need: author_data_model_capability_id().to_string(),
        contract_only_plan_id: contract_only_plan.plan_id.to_string(),
        provider_plan_id: provider_plan.plan_id.to_string(),
        post_attester_plan_id: bindings.post_attester_plan.plan_id.to_string(),
        provider_implementation: gooir_datamodel_pack::neutral::implementation_id().to_string(),
        provider_offer_id: bindings.offer.offer_id.to_string(),
        provider_invocation_id: invocation.invocation_id.to_string(),
        attester: AttesterDeploymentLock {
            suite: author_data_model_suite_id().to_string(),
            implementation: gooir_datamodel_conformance::implementation_id().to_string(),
            package: attester.package_id().clone(),
            package_digest: attester.digest().clone(),
            resource: bindings.attester_resource.name,
            resource_digest: bindings.attester_resource.digest,
        },
    })
}

fn validate_package_graph(installed: InstalledProof<'_>) -> Result<(), ProofError> {
    let vocabulary = installed.vocabulary;
    let contract = installed.contract;
    let provider = installed.provider;
    let attester = installed.attester;
    assert_exact_package_shape(
        vocabulary,
        semantics_data_model_v1::VOCABULARY_PACKAGE,
        0,
        0,
    )?;
    assert_exact_package_shape(
        contract,
        gooir_author_data_model_contract::CONTRACT_PACKAGE,
        1,
        0,
    )?;
    assert_exact_package_shape(provider, PROVIDER_PACKAGE, 1, 1)?;
    assert_exact_package_shape(attester, ATTESTER_PACKAGE, 1, 0)?;
    assert_exact_contract_dependency(provider, contract)?;
    assert_exact_contract_dependency(attester, contract)?;

    let expected_vocabulary =
        read_manifest(semantics_data_model_v1::PACKAGE_MANIFEST).map_err(ProofError::Manifest)?;
    assert_exact_manifest(vocabulary, &expected_vocabulary, "vocabulary")?;
    let expected_contract = contract_manifest(vocabulary).map_err(|error| {
        ProofError::Invariant(format!("could not reconstruct contract package: {error}"))
    })?;
    assert_exact_manifest(contract, &expected_contract, "contract")?;
    let expected_provider = provider_manifest(
        contract,
        retained_resource_bytes(provider, PROVIDER_RESOURCE)?,
    )?;
    assert_exact_manifest(provider, &expected_provider, "provider")?;
    let expected_attester = attester_manifest(
        contract,
        retained_resource_bytes(attester, ATTESTER_RESOURCE)?,
    )?;
    assert_exact_manifest(attester, &expected_attester, "attester")?;

    if !provider.manifest().capabilities.is_empty()
        || !provider.manifest().dialects.is_empty()
        || !provider.manifest().conformance_suites.is_empty()
        || !attester.manifest().capabilities.is_empty()
        || !attester.manifest().dialects.is_empty()
        || !attester.manifest().conformance_suites.is_empty()
    {
        return Err(ProofError::Invariant(
            "provider and attester packages must not redefine contract semantics".to_owned(),
        ));
    }
    Ok(())
}

struct VerifiedBindings<'installed> {
    post_attester_plan: SemanticPlan,
    offer: &'installed gooir_capability::protocol::CapabilityOffer,
    attester_resource: ExactResource,
}

fn validate_planning_bindings<'installed>(
    installed: InstalledProof<'installed>,
    planning: PlanningProof<'_>,
) -> Result<VerifiedBindings<'installed>, ProofError> {
    let post_attester_plan = plan_authoring(installed.registry)?;
    if &post_attester_plan != planning.provider {
        return Err(ProofError::Invariant(
            "installing the resource-only attester changed the semantic plan".to_owned(),
        ));
    }

    let provider_resource = exact_resource(installed.provider, PROVIDER_RESOURCE)?;
    let attester_resource = exact_resource(installed.attester, ATTESTER_RESOURCE)?;
    if provider_resource.digest == attester_resource.digest
        || gooir_datamodel_pack::neutral::implementation_id()
            == gooir_datamodel_conformance::implementation_id()
    {
        return Err(ProofError::Invariant(
            "provider and attester must have distinct implementation and artifact identities"
                .to_owned(),
        ));
    }
    let offer = exact_provider_offer(installed.registry)?;
    if offer.artifact_digest.as_str() != provider_resource.digest.as_str() {
        return Err(ProofError::Invariant(
            "provider offer is not bound to the installed provider resource digest".to_owned(),
        ));
    }
    let expected_offer = gooir_capability::protocol::CapabilityOffer::new(
        gooir_datamodel_pack::neutral::implementation_id(),
        ArtifactDigest::parse(provider_resource.digest.to_string())
            .map_err(|error| ProofError::Invariant(error.to_string()))?,
        author_data_model_capability_id(),
        BTreeMap::new(),
    )
    .map_err(ProofError::Protocol)?;
    if offer != &expected_offer {
        return Err(ProofError::Invariant(
            "installed provider offer was not derived from the measured bytes".to_owned(),
        ));
    }

    if planning.invocation.selection.offer != *offer
        || planning.invocation.specification != author_data_model_spec()
        || planning.invocation.conformance_suite != author_data_model_suite_id()
    {
        return Err(ProofError::Invariant(
            "linked invocation does not preserve the exact contract and selected offer".to_owned(),
        ));
    }
    Ok(VerifiedBindings {
        post_attester_plan,
        offer,
        attester_resource,
    })
}

fn provider_manifest(
    contract: &InstalledPackage,
    bytes: &[u8],
) -> Result<PackageManifest, ProofError> {
    PackageManifest::new(
        package_id(PROVIDER_PACKAGE)?,
        vec![dependency(contract)],
        vec![executable_resource(
            PROVIDER_RESOURCE,
            PROVIDER_RESOURCE_PATH,
            bytes,
        )?],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![ImplementationOfferDeclaration {
            implementation: gooir_datamodel_pack::neutral::implementation_id(),
            capability: author_data_model_capability_id(),
            artifact: resource_name(PROVIDER_RESOURCE)?,
            extensions: BTreeMap::new(),
        }],
        BTreeMap::new(),
    )
    .map_err(ProofError::Manifest)
}

fn attester_manifest(
    contract: &InstalledPackage,
    bytes: &[u8],
) -> Result<PackageManifest, ProofError> {
    PackageManifest::new(
        package_id(ATTESTER_PACKAGE)?,
        vec![dependency(contract)],
        vec![executable_resource(
            ATTESTER_RESOURCE,
            ATTESTER_RESOURCE_PATH,
            bytes,
        )?],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        BTreeMap::new(),
    )
    .map_err(ProofError::Manifest)
}

fn executable_resource(
    name: &str,
    path: &str,
    bytes: &[u8],
) -> Result<PackageResource, ProofError> {
    Ok(PackageResource {
        name: resource_name(name)?,
        path: path.to_owned(),
        media_type: "application/octet-stream".to_owned(),
        size: u64::try_from(bytes.len()).map_err(|_| {
            ProofError::Invariant("resource length cannot be represented as u64".to_owned())
        })?,
        digest: ResourceDigest::parse(sha256_identity(bytes))
            .map_err(|error| ProofError::Invariant(error.to_string()))?,
        extensions: BTreeMap::new(),
    })
}

fn dependency(package: &InstalledPackage) -> PackageDependency {
    PackageDependency {
        package: package.package_id().clone(),
        digest: package.digest().clone(),
        extensions: BTreeMap::new(),
    }
}

fn package_id(value: &str) -> Result<PackageId, ProofError> {
    PackageId::parse(value).map_err(|error| ProofError::Invariant(error.to_string()))
}

fn resource_name(value: &str) -> Result<ResourceName, ProofError> {
    ResourceName::parse(value).map_err(|error| ProofError::Invariant(error.to_string()))
}

fn read_final_binary(path: &Path) -> Result<Vec<u8>, ProofError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| ProofError::Filesystem {
        action: "open final executable",
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|error| ProofError::Io {
        action: "inspect final executable",
        path: path.to_path_buf(),
        source: error,
    })?;
    if !metadata.is_file() {
        return Err(ProofError::InvalidBinary {
            path: path.to_path_buf(),
            detail: "not a regular file".to_owned(),
        });
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(ProofError::InvalidBinary {
            path: path.to_path_buf(),
            detail: "no executable mode bit is set".to_owned(),
        });
    }
    if metadata.len() > MAX_RESOURCE_BYTES {
        return Err(ProofError::InvalidBinary {
            path: path.to_path_buf(),
            detail: format!(
                "declared length {} exceeds {} bytes",
                metadata.len(),
                MAX_RESOURCE_BYTES
            ),
        });
    }

    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| {
        ProofError::InvalidBinary {
            path: path.to_path_buf(),
            detail: "binary length cannot be represented in memory".to_owned(),
        }
    })?);
    Read::by_ref(&mut file)
        .take(MAX_RESOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ProofError::Io {
            action: "read final executable",
            path: path.to_path_buf(),
            source: error,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != metadata.len() {
        return Err(ProofError::InvalidBinary {
            path: path.to_path_buf(),
            detail: "binary changed length while it was being read".to_owned(),
        });
    }
    Ok(bytes)
}

struct ResourceBytes<'bytes> {
    path: &'static str,
    bytes: &'bytes [u8],
    executable: bool,
}

fn ensure_output_absent(path: &Path) -> Result<(), ProofError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ProofError::OutputRootExists(path.to_path_buf())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ProofError::Io {
            action: "inspect output root",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn output_parent(output: &Path) -> Result<&Path, ProofError> {
    if output.file_name().is_none() {
        return Err(ProofError::InvalidOutputRoot(output.to_path_buf()));
    }
    match output.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => Ok(parent),
        Some(_) | None => Ok(Path::new(".")),
    }
}

fn publish_staging(staging: tempfile::TempDir, output: &Path) -> Result<(), ProofError> {
    let staging_path = staging.path().to_path_buf();
    let parent_path = output_parent(output)?;
    let staging_parent = output_parent(&staging_path)?;
    if staging_parent != parent_path {
        return Err(ProofError::Invariant(
            "private staging and output roots are not siblings".to_owned(),
        ));
    }
    let staging_name = staging_path
        .file_name()
        .ok_or_else(|| ProofError::InvalidOutputRoot(staging_path.clone()))?;
    let output_name = output
        .file_name()
        .ok_or_else(|| ProofError::InvalidOutputRoot(output.to_path_buf()))?;
    let parent_descriptor = open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| ProofError::Filesystem {
        action: "open output parent directory",
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
            return Err(ProofError::OutputRootExists(output.to_path_buf()));
        }
        return Err(ProofError::Filesystem {
            action: "atomically publish staged packages",
            path: output.to_path_buf(),
            detail: error.to_string(),
        });
    }
    let _disarmed_staging_path = staging.keep();
    parent.sync_all().map_err(|source| ProofError::Io {
        action: "synchronize output parent directory",
        path: parent_path.to_path_buf(),
        source,
    })
}

fn sync_directory(path: &Path) -> Result<(), ProofError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| ProofError::Filesystem {
        action: "open package directory for synchronization",
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;
    File::from(descriptor)
        .sync_all()
        .map_err(|source| ProofError::Io {
            action: "synchronize package directory",
            path: path.to_path_buf(),
            source,
        })
}

fn write_load_install(
    root: &Path,
    directory: &str,
    manifest: &PackageManifest,
    resources: &[ResourceBytes<'_>],
    registry: &mut PackageRegistry,
) -> Result<InstalledPackage, ProofError> {
    let package_root = root.join(directory);
    create_directory(&package_root, 0o700)?;
    for resource in resources {
        write_resource(&package_root, resource)?;
    }
    write_new_file(
        &package_root.join(gooir_package::PACKAGE_MANIFEST_FILE),
        write_manifest(manifest)
            .map_err(ProofError::Manifest)?
            .as_bytes(),
        0o400,
    )?;
    sync_directory(&package_root)?;
    load_install(root, directory, registry)
}

fn write_resource(root: &Path, resource: &ResourceBytes<'_>) -> Result<(), ProofError> {
    let path = root.join(resource.path);
    if let Some(parent) = path.parent() {
        create_directory_tree(root, parent)?;
    }
    write_new_file(
        &path,
        resource.bytes,
        if resource.executable { 0o500 } else { 0o400 },
    )?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn create_directory_tree(root: &Path, directory: &Path) -> Result<(), ProofError> {
    let relative = directory.strip_prefix(root).map_err(|_| {
        ProofError::Invariant("resource parent escaped its package root".to_owned())
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

fn create_directory(path: &Path, mode: u32) -> Result<(), ProofError> {
    fs::create_dir(path).map_err(|error| ProofError::Io {
        action: "create directory",
        path: path.to_path_buf(),
        source: error,
    })?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| ProofError::Io {
        action: "set directory permissions",
        path: path.to_path_buf(),
        source: error,
    })
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ProofError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| ProofError::Io {
            action: "create package file",
            path: path.to_path_buf(),
            source: error,
        })?;
    file.write_all(bytes).map_err(|error| ProofError::Io {
        action: "write package file",
        path: path.to_path_buf(),
        source: error,
    })?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| {
        ProofError::Io {
            action: "set package file permissions",
            path: path.to_path_buf(),
            source: error,
        }
    })?;
    file.sync_all().map_err(|error| ProofError::Io {
        action: "synchronize package file",
        path: path.to_path_buf(),
        source: error,
    })
}

fn load_install(
    root: &Path,
    directory: &str,
    registry: &mut PackageRegistry,
) -> Result<InstalledPackage, ProofError> {
    let package = load_local_package(root.join(directory), registry, load_limits())
        .map_err(ProofError::Load)?;
    registry.install(package).map_err(ProofError::Install)
}

fn load_limits() -> LoadLimits {
    LoadLimits {
        max_manifest_bytes: MAX_MANIFEST_BYTES,
        max_resources: 4,
        max_resource_bytes: MAX_RESOURCE_BYTES,
        max_total_resource_bytes: MAX_RESOURCE_BYTES,
    }
}

fn planning_limits() -> PlanLimits {
    let bound = NonZeroUsize::new(16).expect("the fixed planning bound is nonzero");
    PlanLimits {
        max_capabilities: bound,
        max_value_kinds: bound,
        max_ports_per_capability: bound,
        max_total_ports: bound,
        max_offers_per_capability: bound,
        max_total_offers: bound,
    }
}

fn planner(registry: &PackageRegistry) -> Result<SemanticPlanner, ProofError> {
    SemanticPlanner::from_registry(registry, planning_limits()).map_err(ProofError::Planning)
}

fn plan_authoring(registry: &PackageRegistry) -> Result<SemanticPlan, ProofError> {
    planner(registry)?
        .plan(
            [authored_entity_spec_value_kind()],
            semantics_data_model_v1::model_contract(),
        )
        .map_err(ProofError::Planning)
}

fn assert_contract_only_need(plan: &SemanticPlan) -> Result<(), ProofError> {
    let needs: Vec<_> = plan.needs().map(|need| need.id.clone()).collect();
    if plan.capabilities.len() != 1
        || needs != vec![author_data_model_capability_id()]
        || !plan.capabilities[0].offers.is_empty()
        || plan.capabilities[0].specification != author_data_model_spec()
    {
        return Err(ProofError::Invariant(
            "contract-only graph did not expose exactly one providerless authoring need".to_owned(),
        ));
    }
    Ok(())
}

fn link_synthetic_invocation(
    planner: &SemanticPlanner,
    plan: &SemanticPlan,
) -> Result<gooir_capability::protocol::CapabilityInvocation, ProofError> {
    let offer = plan
        .capabilities
        .iter()
        .find(|planned| planned.specification.id == author_data_model_capability_id())
        .and_then(|planned| match planned.offers.as_slice() {
            [offer] => Some(offer),
            _ => None,
        })
        .ok_or_else(|| {
            ProofError::Invariant(
                "provider graph did not expose exactly one authoring offer".to_owned(),
            )
        })?;
    let source = Fact::new(
        authored_entity_spec_value_kind(),
        serde_json::to_value(AuthoredSpec {
            origin: "proof:synthetic-link-input".to_owned(),
            text: "entity Proof { id uuid pk }\n".to_owned(),
        })
        .map_err(ProofError::Serialization)?,
    )
    .map_err(|error| ProofError::Invariant(error.to_string()))?;
    let admitted = AdmittedFactRef::new(
        source.id.clone(),
        AuthorityRecordId::parse(format!("sha256:{}", "a".repeat(64)))
            .map_err(|error| ProofError::Invariant(error.to_string()))?,
        BTreeMap::new(),
    )
    .map_err(ProofError::Protocol)?;
    let input = LinkedInput::new(
        PortName::parse("source").map_err(|error| ProofError::Invariant(error.to_string()))?,
        admitted,
        source,
        BTreeMap::new(),
    )
    .map_err(ProofError::Protocol)?;
    planner
        .link_invocation(
            plan,
            InvocationLink {
                capability: &author_data_model_capability_id(),
                offer: &offer.offer_id,
                selection_extensions: BTreeMap::new(),
                inputs: vec![input],
                conformance_suite: author_data_model_suite_id(),
                invocation_extensions: BTreeMap::new(),
            },
        )
        .map_err(ProofError::Planning)
}

fn exact_provider_offer(
    registry: &PackageRegistry,
) -> Result<&gooir_capability::protocol::CapabilityOffer, ProofError> {
    let implementation = gooir_datamodel_pack::neutral::implementation_id();
    let capability = author_data_model_capability_id();
    let matches: Vec<_> = registry
        .offers()
        .filter(|offer| offer.implementation == implementation && offer.capability == capability)
        .collect();
    match matches.as_slice() {
        [offer] => Ok(*offer),
        _ => Err(ProofError::Invariant(format!(
            "expected one installed provider offer, found {}",
            matches.len()
        ))),
    }
}

fn assert_exact_package_shape(
    installed: &InstalledPackage,
    expected_id: &str,
    resources: usize,
    offers: usize,
) -> Result<(), ProofError> {
    if installed.package_id().as_str() != expected_id
        || installed.manifest().resources.len() != resources
        || installed.manifest().implementation_offers.len() != offers
    {
        return Err(ProofError::Invariant(format!(
            "installed package {} has the wrong proof shape",
            installed.package_id()
        )));
    }
    Ok(())
}

fn assert_exact_manifest(
    installed: &InstalledPackage,
    expected: &PackageManifest,
    role: &str,
) -> Result<(), ProofError> {
    if installed.manifest() != expected {
        return Err(ProofError::Invariant(format!(
            "installed {role} manifest differs from the exact reconstructed package"
        )));
    }
    Ok(())
}

fn assert_exact_contract_dependency(
    installed: &InstalledPackage,
    contract: &InstalledPackage,
) -> Result<(), ProofError> {
    let expected = dependency(contract);
    if installed.manifest().dependencies != vec![expected] {
        return Err(ProofError::Invariant(format!(
            "package {} does not depend exactly on the contract package",
            installed.package_id()
        )));
    }
    Ok(())
}

#[derive(Clone)]
struct ExactResource {
    name: ResourceName,
    digest: ResourceDigest,
}

fn retained_resource_bytes<'installed>(
    installed: &'installed InstalledPackage,
    expected_name: &str,
) -> Result<&'installed [u8], ProofError> {
    let name = resource_name(expected_name)?;
    installed
        .resource(&name)
        .map(gooir_package::OwnedResource::bytes)
        .ok_or_else(|| {
            ProofError::Invariant(format!(
                "package {} did not retain resource {name}",
                installed.package_id()
            ))
        })
}

fn exact_resource(
    installed: &InstalledPackage,
    expected_name: &str,
) -> Result<ExactResource, ProofError> {
    let name = resource_name(expected_name)?;
    let declaration = installed
        .manifest()
        .resources
        .iter()
        .find(|resource| resource.name == name)
        .ok_or_else(|| {
            ProofError::Invariant(format!(
                "package {} lacks resource {name}",
                installed.package_id()
            ))
        })?;
    let copied = installed.resource(&name).ok_or_else(|| {
        ProofError::Invariant(format!(
            "package {} did not retain resource {name}",
            installed.package_id()
        ))
    })?;
    if copied.digest() != &declaration.digest
        || sha256_identity(copied.bytes()) != declaration.digest.as_str()
    {
        return Err(ProofError::Invariant(format!(
            "resource {name} is not bound to its copied bytes"
        )));
    }
    Ok(ExactResource {
        name,
        digest: declaration.digest.clone(),
    })
}

fn package_coordinate(installed: &InstalledPackage, relative_directory: &str) -> PackageCoordinate {
    PackageCoordinate {
        package: installed.package_id().clone(),
        digest: installed.digest().clone(),
        relative_directory: relative_directory.to_owned(),
        resources: installed
            .manifest()
            .resources
            .iter()
            .map(|resource| ResourceCoordinate {
                name: resource.name.clone(),
                path: resource.path.clone(),
                media_type: resource.media_type.clone(),
                size: resource.size,
                digest: resource.digest.clone(),
            })
            .collect(),
    }
}

fn sha256_identity(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut identity = String::with_capacity(71);
    identity.push_str("sha256:");
    for byte in digest {
        use fmt::Write as _;
        write!(identity, "{byte:02x}").expect("writing to a string cannot fail");
    }
    identity
}

/// Failure to stage or verify the exact four-package proof.
#[derive(Debug)]
pub enum ProofError {
    OutputRootExists(PathBuf),
    InvalidOutputRoot(PathBuf),
    InvalidBinary {
        path: PathBuf,
        detail: String,
    },
    Io {
        action: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    Filesystem {
        action: &'static str,
        path: PathBuf,
        detail: String,
    },
    Manifest(PackageManifestError),
    Load(PackageLoadError),
    Install(InstallError),
    Planning(PlanningError),
    Protocol(gooir_capability::protocol::ProtocolError),
    Serialization(serde_json::Error),
    Invariant(String),
}

impl fmt::Display for ProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputRootExists(path) => write!(
                formatter,
                "refusing to overwrite existing output root {}",
                path.display()
            ),
            Self::InvalidOutputRoot(path) => {
                write!(formatter, "invalid output root {}", path.display())
            }
            Self::InvalidBinary { path, detail } => {
                write!(
                    formatter,
                    "invalid final binary {}: {detail}",
                    path.display()
                )
            }
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "could not {action} {}: {source}", path.display()),
            Self::Filesystem {
                action,
                path,
                detail,
            } => write!(formatter, "could not {action} {}: {detail}", path.display()),
            Self::Manifest(error) => write!(formatter, "package manifest failed: {error}"),
            Self::Load(error) => write!(formatter, "package load failed: {error}"),
            Self::Install(error) => write!(formatter, "package install failed: {error}"),
            Self::Planning(error) => write!(formatter, "semantic planning failed: {error}"),
            Self::Protocol(error) => write!(formatter, "capability protocol failed: {error}"),
            Self::Serialization(error) => write!(formatter, "JSON serialization failed: {error}"),
            Self::Invariant(detail) => write!(formatter, "proof invariant failed: {detail}"),
        }
    }
}

impl Error for ProofError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Manifest(error) => Some(error),
            Self::Load(error) => Some(error),
            Self::Install(error) => Some(error),
            Self::Planning(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::OutputRootExists(_)
            | Self::InvalidOutputRoot(_)
            | Self::InvalidBinary { .. }
            | Self::Filesystem { .. }
            | Self::Invariant(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn executable(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write synthetic executable");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("mark synthetic bytes executable");
    }

    #[test]
    fn stages_and_reverifies_four_exact_packages_without_executing_children() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let provider_source = temporary.path().join("provider-final");
        let attester_source = temporary.path().join("attester-final");
        let provider_bytes = b"synthetic final provider executable bytes";
        let attester_bytes = b"synthetic final independent attester executable bytes";
        executable(&provider_source, provider_bytes);
        executable(&attester_source, attester_bytes);
        let output = temporary.path().join("packages");

        let staged = stage(StageRequest {
            provider_binary: provider_source,
            attester_binary: attester_source,
            output_root: output.clone(),
        })
        .expect("stage proof");
        let verified = verify(&output).expect("independently verify proof");

        assert_eq!(staged, verified);
        assert_eq!(staged.installation_order.len(), 4);
        assert_eq!(
            staged.contract_only_need,
            author_data_model_capability_id().to_string()
        );
        assert_ne!(staged.contract_only_plan_id, staged.provider_plan_id);
        assert_eq!(staged.provider_plan_id, staged.post_attester_plan_id);
        assert_eq!(
            fs::read(output.join(PROVIDER_DIRECTORY).join(PROVIDER_RESOURCE_PATH))
                .expect("staged provider"),
            provider_bytes
        );
        assert_eq!(
            fs::read(output.join(ATTESTER_DIRECTORY).join(ATTESTER_RESOURCE_PATH))
                .expect("staged attester"),
            attester_bytes
        );
        assert_eq!(
            staged.attester.implementation,
            gooir_datamodel_conformance::implementation_id().to_string()
        );
    }

    #[test]
    fn refuses_to_overwrite_a_complete_or_partial_output_root() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let provider = temporary.path().join("provider-final");
        let attester = temporary.path().join("attester-final");
        executable(&provider, b"provider bytes");
        executable(&attester, b"different attester bytes");
        let output = temporary.path().join("existing");
        fs::create_dir(&output).expect("existing output");
        fs::write(output.join("keep"), b"operator data").expect("existing data");

        let error = stage(StageRequest {
            provider_binary: provider,
            attester_binary: attester,
            output_root: output.clone(),
        })
        .expect_err("existing output must be refused");

        assert!(matches!(error, ProofError::OutputRootExists(path) if path == output));
        assert_eq!(
            fs::read(output.join("keep")).expect("preserved"),
            b"operator data"
        );
    }

    #[test]
    fn atomic_publication_does_not_replace_a_racing_target() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let staging = tempfile::Builder::new()
            .prefix("private-staging-")
            .tempdir_in(temporary.path())
            .expect("private staging directory");
        let staging_path = staging.path().to_path_buf();
        let output = temporary.path().join("published");
        fs::write(staging.path().join("staged"), b"staged data").expect("staged data");
        fs::create_dir(&output).expect("racing output directory");
        fs::write(output.join("keep"), b"operator data").expect("operator data");

        let error = publish_staging(staging, &output).expect_err("target must not be replaced");

        assert!(matches!(error, ProofError::OutputRootExists(path) if path == output));
        assert!(
            !staging_path.exists(),
            "failed private staging is cleaned up"
        );
        assert_eq!(
            fs::read(output.join("keep")).expect("output preserved"),
            b"operator data"
        );
    }

    #[test]
    fn broken_symlink_output_is_an_existing_operator_path() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let provider = temporary.path().join("provider-final");
        let attester = temporary.path().join("attester-final");
        executable(&provider, b"provider bytes");
        executable(&attester, b"different attester bytes");
        let output = temporary.path().join("published");
        std::os::unix::fs::symlink("missing-target", &output).expect("broken symlink");

        let error = stage(StageRequest {
            provider_binary: provider,
            attester_binary: attester,
            output_root: output.clone(),
        })
        .expect_err("broken symlink must be refused");

        assert!(matches!(error, ProofError::OutputRootExists(path) if path == output));
        assert_eq!(
            fs::read_link(&output).expect("symlink preserved"),
            PathBuf::from("missing-target")
        );
    }

    #[test]
    fn verifier_rejects_changed_staged_executable_bytes() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let provider = temporary.path().join("provider-final");
        let attester = temporary.path().join("attester-final");
        executable(&provider, b"provider bytes");
        executable(&attester, b"different attester bytes");
        let output = temporary.path().join("packages");
        stage(StageRequest {
            provider_binary: provider,
            attester_binary: attester,
            output_root: output.clone(),
        })
        .expect("stage proof");

        let staged_provider = output.join(PROVIDER_DIRECTORY).join(PROVIDER_RESOURCE_PATH);
        fs::set_permissions(&staged_provider, fs::Permissions::from_mode(0o700))
            .expect("make test mutation possible");
        fs::write(&staged_provider, b"tampered provider bytes").expect("mutate staged resource");

        let error = verify(&output).expect_err("resource mutation must fail closed");
        assert!(matches!(error, ProofError::Load(_)));
    }

    #[test]
    fn verifier_rejects_a_self_consistent_rewritten_provider_manifest() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let provider = temporary.path().join("provider-final");
        let attester = temporary.path().join("attester-final");
        executable(&provider, b"provider bytes");
        executable(&attester, b"different attester bytes");
        let output = temporary.path().join("packages");
        stage(StageRequest {
            provider_binary: provider,
            attester_binary: attester,
            output_root: output.clone(),
        })
        .expect("stage proof");

        let manifest_path = output
            .join(PROVIDER_DIRECTORY)
            .join(gooir_package::PACKAGE_MANIFEST_FILE);
        let original = read_manifest(
            &fs::read_to_string(&manifest_path).expect("read installed provider manifest"),
        )
        .expect("parse installed provider manifest");
        let changed = PackageManifest::new(
            original.package,
            original.dependencies,
            original.resources,
            original.dialects,
            original.conformance_suites,
            original.capabilities,
            original.implementation_offers,
            BTreeMap::from([(
                "org.gooi.test.coordinated-rewrite".to_owned(),
                serde_json::json!(true),
            )]),
        )
        .expect("self-consistent alternate provider manifest");
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600))
            .expect("make manifest writable for mutation");
        fs::write(
            &manifest_path,
            write_manifest(&changed).expect("serialize changed manifest"),
        )
        .expect("rewrite provider manifest");

        let error = verify(&output).expect_err("coordinated manifest rewrite must fail closed");
        assert!(matches!(
            error,
            ProofError::Invariant(detail) if detail.contains("exact reconstructed package")
        ));
    }

    #[test]
    fn verifier_rejects_a_self_consistent_self_attesting_artifact() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let provider = temporary.path().join("provider-final");
        let attester = temporary.path().join("attester-final");
        executable(&provider, b"provider bytes");
        executable(&attester, b"different attester bytes");
        let output = temporary.path().join("packages");
        stage(StageRequest {
            provider_binary: provider,
            attester_binary: attester,
            output_root: output.clone(),
        })
        .expect("stage proof");

        let provider_bytes = fs::read(output.join(PROVIDER_DIRECTORY).join(PROVIDER_RESOURCE_PATH))
            .expect("read installed provider bytes");
        let mut registry = PackageRegistry::default();
        let _vocabulary =
            load_install(&output, VOCABULARY_DIRECTORY, &mut registry).expect("install vocabulary");
        let contract =
            load_install(&output, CONTRACT_DIRECTORY, &mut registry).expect("install contract");
        let rewritten_manifest =
            attester_manifest(&contract, &provider_bytes).expect("rewritten attester manifest");
        let attester_root = output.join(ATTESTER_DIRECTORY);
        let attester_resource = attester_root.join(ATTESTER_RESOURCE_PATH);
        let attester_manifest_path = attester_root.join(gooir_package::PACKAGE_MANIFEST_FILE);
        fs::set_permissions(&attester_resource, fs::Permissions::from_mode(0o700))
            .expect("make attester writable for mutation");
        fs::write(&attester_resource, &provider_bytes).expect("rewrite attester bytes");
        fs::set_permissions(&attester_manifest_path, fs::Permissions::from_mode(0o600))
            .expect("make attester manifest writable for mutation");
        fs::write(
            &attester_manifest_path,
            write_manifest(&rewritten_manifest).expect("serialize rewritten attester manifest"),
        )
        .expect("rewrite attester manifest");

        let error = verify(&output).expect_err("self-attesting artifact must fail closed");
        assert!(matches!(
            error,
            ProofError::Invariant(detail)
                if detail.contains("distinct implementation and artifact identities")
        ));
    }

    #[test]
    fn source_binaries_must_be_distinct_regular_executables() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let provider = temporary.path().join("provider-final");
        let attester = temporary.path().join("attester-final");
        executable(&provider, b"same bytes");
        executable(&attester, b"same bytes");

        let error = stage(StageRequest {
            provider_binary: provider,
            attester_binary: attester,
            output_root: temporary.path().join("packages"),
        })
        .expect_err("self-attesting artifact identity must be refused");
        assert!(matches!(error, ProofError::Invariant(_)));
    }

    #[test]
    fn verified_set_resolves_the_exact_offer_to_its_owned_provider_bytes() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let provider = temporary.path().join("provider-final");
        let attester = temporary.path().join("attester-final");
        let provider_bytes = b"provider bytes retained behind exact offer";
        executable(&provider, provider_bytes);
        executable(&attester, b"distinct attester bytes");
        let output = temporary.path().join("packages");
        stage(StageRequest {
            provider_binary: provider,
            attester_binary: attester,
            output_root: output.clone(),
        })
        .expect("stage proof");

        let verified = verify_package_set(&output).expect("verify owned package set");
        let offer = verified.provider_offer();
        let artifact = verified.provider_artifact();

        assert_eq!(
            offer.offer_id.to_string(),
            verified.report().provider_offer_id
        );
        assert_eq!(offer.artifact_digest.as_str(), artifact.digest().as_str());
        assert_eq!(artifact.name().as_str(), PROVIDER_RESOURCE);
        assert_eq!(artifact.bytes(), provider_bytes);
        let planner = verified
            .planner(planning_limits())
            .expect("planner from verified inventory");
        let plan = planner
            .plan(
                [authored_entity_spec_value_kind()],
                semantics_data_model_v1::model_contract(),
            )
            .expect("plan verified authoring capability");
        assert_eq!(plan.capabilities.len(), 1);
        assert_eq!(plan.capabilities[0].offers, vec![offer.clone()]);
    }

    #[test]
    fn verified_set_resolves_attester_only_through_its_explicit_deployment_lock() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let provider = temporary.path().join("provider-final");
        let attester = temporary.path().join("attester-final");
        let attester_bytes = b"attester bytes retained behind deployment lock";
        executable(&provider, b"distinct provider bytes");
        executable(&attester, attester_bytes);
        let output = temporary.path().join("packages");
        stage(StageRequest {
            provider_binary: provider,
            attester_binary: attester,
            output_root: output.clone(),
        })
        .expect("stage proof");

        let verified = verify_package_set(&output).expect("verify owned package set");
        let deployment = verified.report().attester.clone();
        let resource = verified
            .attester_resource(&deployment)
            .expect("resolve exact deployment lock");
        assert_eq!(resource.name(), &deployment.resource);
        assert_eq!(resource.digest(), &deployment.resource_digest);
        assert_eq!(resource.bytes(), attester_bytes);

        let mut altered = deployment;
        altered.implementation.push_str(".altered");
        assert!(
            verified.attester_resource(&altered).is_none(),
            "a changed deployment coordinate must not discover an attester"
        );
    }

    #[test]
    fn verified_set_owns_executable_bytes_after_source_packages_disappear() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let provider = temporary.path().join("provider-final");
        let attester = temporary.path().join("attester-final");
        let provider_bytes = b"provider bytes surviving source removal";
        let attester_bytes = b"attester bytes surviving source removal";
        executable(&provider, provider_bytes);
        executable(&attester, attester_bytes);
        let output = temporary.path().join("packages");
        stage(StageRequest {
            provider_binary: provider,
            attester_binary: attester,
            output_root: output.clone(),
        })
        .expect("stage proof");

        let verified = verify_package_set(&output).expect("verify owned package set");
        let report = verified.report().clone();
        let deployment = report.attester.clone();
        fs::remove_dir_all(&output).expect("remove package source directories");

        assert!(!output.exists());
        assert_eq!(verified.report(), &report);
        assert_eq!(verified.provider_artifact().bytes(), provider_bytes);
        assert_eq!(
            verified
                .attester_resource(&deployment)
                .expect("resolve retained attester")
                .bytes(),
            attester_bytes
        );
    }

    #[test]
    fn compatibility_verifier_rejects_an_altered_provider_package_coordinate() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let provider = temporary.path().join("provider-final");
        let attester = temporary.path().join("attester-final");
        executable(&provider, b"provider bytes");
        executable(&attester, b"distinct attester bytes");
        let output = temporary.path().join("packages");
        stage(StageRequest {
            provider_binary: provider,
            attester_binary: attester,
            output_root: output.clone(),
        })
        .expect("stage proof");

        let manifest_path = output
            .join(PROVIDER_DIRECTORY)
            .join(gooir_package::PACKAGE_MANIFEST_FILE);
        let original = read_manifest(
            &fs::read_to_string(&manifest_path).expect("read installed provider manifest"),
        )
        .expect("parse installed provider manifest");
        let altered = PackageManifest::new(
            package_id("org.gooi.implementation.entity_spec_rust.altered_target@1.1.0")
                .expect("altered exact package coordinate"),
            original.dependencies,
            original.resources,
            original.dialects,
            original.conformance_suites,
            original.capabilities,
            original.implementation_offers,
            original.extensions,
        )
        .expect("self-consistent alternate package coordinate");
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600))
            .expect("make manifest writable for mutation");
        fs::write(
            &manifest_path,
            write_manifest(&altered).expect("serialize altered manifest"),
        )
        .expect("rewrite provider manifest");

        let error = verify(&output).expect_err("altered coordinate must fail common verification");
        assert!(matches!(
            error,
            ProofError::Invariant(detail) if detail.contains("wrong proof shape")
        ));
    }
}
