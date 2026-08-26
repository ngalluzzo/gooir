//! Content-addressed packages for the Fleetd direct-conversation native artifacts.
//!
//! This proof consumes three already-final native command files, copies their
//! exact bytes into independently installable packages, and derives the two
//! provider offers through the public package API. The attester remains a
//! resource-only package resolved through an exact host-owned lock. Native
//! runtime qualification and execution deliberately remain outside this crate.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::num::NonZeroUsize;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use fleetd_direct_conversation_contract::{
    AgentId, CONTRACT_PACKAGE, DIRECT_CONVERSATION_REF_SCHEMA_BYTES,
    DIRECT_CONVERSATION_REF_SCHEMA_PATH, DIRECT_PAIR_INTENT_SCHEMA_BYTES,
    DIRECT_PAIR_INTENT_SCHEMA_PATH, DeliveryMode, DirectMember, DirectPairIntent, FleetdTarget,
    direct_conversation_ref_suite_id, direct_conversation_ref_value_kind,
    direct_pair_intent_value_kind, intent_port_name, open_or_resolve_capability_id,
    package_manifest as contract_manifest,
};
use gooir_capability::protocol::{
    AdmittedFactRef, AuthorityRecordId, CapabilityOffer, ImplementationId, LinkedInput,
    ProtocolError,
};
use gooir_package::{
    ImplementationOfferDeclaration, InstallError, InstalledPackage, LoadLimits, OwnedResource,
    PackageDependency, PackageDigest, PackageId, PackageLoadError, PackageManifest,
    PackageManifestError, PackageRegistry, PackageResource, ResourceDigest, ResourceName,
    load_local_package, write_manifest,
};
use gooir_planning::{InvocationLink, PlanLimits, PlanningError, SemanticPlan, SemanticPlanner};
use rustix::fs::{Mode, OFlags, RenameFlags, open, renameat_with};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Proof-local report protocol. It is not a package or semantic protocol.
pub const PROOF_REPORT_PROTOCOL: &str =
    "org.gooi.proof.fleetd-direct-conversation-native-packages/v1";

/// Runtime-target-specific Reqwest provider package for this proof.
pub const REQWEST_PACKAGE: &str =
    "dev.fleetd.implementation.direct_conversation_reqwest.aarch64_apple_darwin@0.1.0";

/// Runtime-target-specific Ureq provider package for this proof.
pub const UREQ_PACKAGE: &str =
    "dev.fleetd.implementation.direct_conversation_ureq.aarch64_apple_darwin@0.1.0";

/// Runtime-target-specific attester package for this proof.
pub const ATTESTER_PACKAGE: &str =
    "dev.fleetd.attester.direct_conversation_ref.aarch64_apple_darwin@0.1.0";

pub const REQWEST_RESOURCE: &str = "reqwest-provider-native-command";
pub const UREQ_RESOURCE: &str = "ureq-provider-native-command";
pub const ATTESTER_RESOURCE: &str = "direct-conversation-attester-native-command";

pub const REQWEST_RESOURCE_PATH: &str = "bin/fleetd-direct-conversation-reqwest-provider";
pub const UREQ_RESOURCE_PATH: &str = "bin/fleetd-direct-conversation-ureq-provider";
pub const ATTESTER_RESOURCE_PATH: &str = "bin/fleetd-direct-conversation-attester";

const CONTRACT_DIRECTORY: &str = "01-direct-conversation-contract";
const REQWEST_DIRECTORY: &str = "02-reqwest-provider-aarch64-apple-darwin";
const UREQ_DIRECTORY: &str = "03-ureq-provider-aarch64-apple-darwin";
const ATTESTER_DIRECTORY: &str = "04-attester-aarch64-apple-darwin";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_NATIVE_COMMAND_BYTES: u64 = 64 * 1024 * 1024;

/// Final artifact paths and fresh output location for one staging operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageRequest {
    pub reqwest_command: PathBuf,
    pub ureq_command: PathBuf,
    pub attester_command: PathBuf,
    pub output_root: PathBuf,
}

/// Exact installed coordinates for one opaque package resource.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceCoordinate {
    pub name: ResourceName,
    pub path: String,
    pub media_type: String,
    pub size: u64,
    pub digest: ResourceDigest,
}

/// Exact installed coordinates for one independently installable package.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PackageCoordinate {
    pub package: PackageId,
    pub digest: PackageDigest,
    pub relative_directory: String,
    pub resources: Vec<ResourceCoordinate>,
}

/// Complete package-owned binding for one selectable provider artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderPackageBinding {
    pub implementation: String,
    pub offer_id: String,
    pub invocation_id: String,
    pub package: PackageId,
    pub package_digest: PackageDigest,
    pub resource: ResourceName,
    pub resource_digest: ResourceDigest,
}

/// Complete proof-host lock for the independently packaged attester resource.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AttesterDeploymentLock {
    pub suite: String,
    pub implementation: String,
    pub package: PackageId,
    pub package_digest: PackageDigest,
    pub resource: ResourceName,
    pub resource_digest: ResourceDigest,
}

/// Evidence reconstructed from exact installed package bytes and planning.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProofReport {
    pub protocol: String,
    pub installation_order: Vec<PackageId>,
    pub packages: Vec<PackageCoordinate>,
    pub contract_only_plan_id: String,
    pub provider_plan_id: String,
    pub post_attester_plan_id: String,
    pub providers: Vec<ProviderPackageBinding>,
    pub attester: AttesterDeploymentLock,
}

/// Owned result of independently loading and verifying the complete package set.
#[derive(Clone, Debug)]
pub struct VerifiedPackageSet {
    registry: PackageRegistry,
    report: ProofReport,
}

impl VerifiedPackageSet {
    #[must_use]
    pub const fn report(&self) -> &ProofReport {
        &self.report
    }

    #[must_use]
    pub fn into_report(self) -> ProofReport {
        self.report
    }

    /// Constructs a planner over the exact verified package inventory.
    ///
    /// # Errors
    ///
    /// Refuses an inventory outside the caller's explicit bounds.
    pub fn planner(&self, limits: PlanLimits) -> Result<SemanticPlanner, PlanningError> {
        SemanticPlanner::from_registry(&self.registry, limits)
    }

    /// Resolves one provider offer only through its complete report binding.
    #[must_use]
    pub fn provider_offer(&self, binding: &ProviderPackageBinding) -> Option<&CapabilityOffer> {
        if !self.report.providers.contains(binding) {
            return None;
        }
        self.registry
            .offers()
            .find(|offer| offer.offer_id.to_string() == binding.offer_id)
    }

    /// Resolves package-owned provider bytes only through their complete lock.
    #[must_use]
    pub fn provider_artifact(&self, binding: &ProviderPackageBinding) -> Option<&OwnedResource> {
        let offer = self.provider_offer(binding)?;
        if offer.implementation.to_string() != binding.implementation
            || offer.artifact_digest.as_str() != binding.resource_digest.as_str()
        {
            return None;
        }
        self.locked_resource(
            &binding.package,
            &binding.package_digest,
            &binding.resource,
            &binding.resource_digest,
        )
    }

    /// Resolves the resource-only attester through its complete deployment lock.
    #[must_use]
    pub fn attester_resource(&self, lock: &AttesterDeploymentLock) -> Option<&OwnedResource> {
        if lock != &self.report.attester
            || lock.suite != direct_conversation_ref_suite_id().to_string()
            || lock.implementation
                != fleetd_direct_conversation_attester::implementation_id().to_string()
        {
            return None;
        }
        self.locked_resource(
            &lock.package,
            &lock.package_digest,
            &lock.resource,
            &lock.resource_digest,
        )
    }

    fn locked_resource(
        &self,
        package: &PackageId,
        package_digest: &PackageDigest,
        resource: &ResourceName,
        resource_digest: &ResourceDigest,
    ) -> Option<&OwnedResource> {
        let installed = self.registry.package(package)?;
        if installed.digest() != package_digest {
            return None;
        }
        let retained = self.registry.resource(package, resource)?;
        (retained.digest() == resource_digest).then_some(retained)
    }
}

/// Copies three final opaque command artifacts into a fresh package tree.
///
/// This function deliberately does not execute or qualify the native commands.
/// The later proof host binds a native runtime and materializes only these
/// verified bytes.
///
/// # Errors
///
/// Refuses unsafe artifact inputs, an existing output root, invalid package
/// construction, failed installation/planning invariants, or publication races.
pub fn stage(request: StageRequest) -> Result<ProofReport, ProofError> {
    let StageRequest {
        reqwest_command,
        ureq_command,
        attester_command,
        output_root,
    } = request;
    ensure_output_absent(&output_root)?;
    let reqwest_bytes = read_final_command(&reqwest_command)?;
    let ureq_bytes = read_final_command(&ureq_command)?;
    let attester_bytes = read_final_command(&attester_command)?;
    ensure_distinct_artifacts([&reqwest_bytes, &ureq_bytes, &attester_bytes])?;

    let parent = output_parent(&output_root)?;
    let staging = tempfile::Builder::new()
        .prefix(".gooir-fleetd-direct-conversation-packages-")
        .tempdir_in(parent)
        .map_err(|source| io_error("create private staging directory", parent, source))?;
    fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error("set staging directory permissions", staging.path(), source))?;

    let staged = stage_packages(staging.path(), &reqwest_bytes, &ureq_bytes, &attester_bytes)?;
    let independently_verified = verify(staging.path())?;
    if staged != independently_verified {
        return Err(invariant(
            "independent staging verification produced a different package report",
        ));
    }
    sync_directory(staging.path())?;
    publish_staging(staging, &output_root)?;
    let published = verify(&output_root)?;
    if published != independently_verified {
        return Err(invariant(
            "published package graph differs from the independently verified graph",
        ));
    }
    Ok(published)
}

/// Independently reloads and verifies one staged package tree.
///
/// # Errors
///
/// Refuses any loader, dependency, digest, offer, planner, link, or exact-shape
/// invariant failure.
pub fn verify(root: impl AsRef<Path>) -> Result<ProofReport, ProofError> {
    verify_package_set(root).map(VerifiedPackageSet::into_report)
}

/// Independently reloads the package set and retains all copied artifact bytes.
///
/// # Errors
///
/// Refuses any package or planning invariant failure.
pub fn verify_package_set(root: impl AsRef<Path>) -> Result<VerifiedPackageSet, ProofError> {
    let root = root.as_ref();
    let mut registry = PackageRegistry::default();
    let contract = load_install(root, CONTRACT_DIRECTORY, &mut registry)?;
    let contract_only_plan = plan_route(&registry)?;
    assert_contract_only_need(&contract_only_plan)?;

    let reqwest = load_install(root, REQWEST_DIRECTORY, &mut registry)?;
    let ureq = load_install(root, UREQ_DIRECTORY, &mut registry)?;
    let provider_plan = plan_route(&registry)?;
    let attester = load_install(root, ATTESTER_DIRECTORY, &mut registry)?;
    let post_attester_plan = plan_route(&registry)?;

    let report = build_report(
        InstalledSet {
            registry: &registry,
            contract: &contract,
            reqwest: &reqwest,
            ureq: &ureq,
            attester: &attester,
        },
        PlanningSet {
            contract_only: &contract_only_plan,
            providers: &provider_plan,
            post_attester: &post_attester_plan,
        },
    )?;
    Ok(VerifiedPackageSet { registry, report })
}

fn stage_packages(
    root: &Path,
    reqwest_bytes: &[u8],
    ureq_bytes: &[u8],
    attester_bytes: &[u8],
) -> Result<ProofReport, ProofError> {
    let mut registry = PackageRegistry::default();
    let contract_manifest = contract_manifest()
        .map_err(|error| invariant(format!("could not construct contract package: {error}")))?;
    let contract = write_load_install(
        root,
        CONTRACT_DIRECTORY,
        &contract_manifest,
        &[
            ResourceBytes {
                path: DIRECT_CONVERSATION_REF_SCHEMA_PATH,
                bytes: DIRECT_CONVERSATION_REF_SCHEMA_BYTES,
            },
            ResourceBytes {
                path: DIRECT_PAIR_INTENT_SCHEMA_PATH,
                bytes: DIRECT_PAIR_INTENT_SCHEMA_BYTES,
            },
        ],
        &mut registry,
    )?;
    let contract_only_plan = plan_route(&registry)?;
    assert_contract_only_need(&contract_only_plan)?;

    let reqwest_manifest = provider_manifest(
        REQWEST_PACKAGE,
        REQWEST_RESOURCE,
        REQWEST_RESOURCE_PATH,
        reqwest_bytes,
        &contract,
        fleetd_direct_conversation_reqwest_provider::implementation_id(),
    )?;
    let reqwest = write_load_install(
        root,
        REQWEST_DIRECTORY,
        &reqwest_manifest,
        &[ResourceBytes {
            path: REQWEST_RESOURCE_PATH,
            bytes: reqwest_bytes,
        }],
        &mut registry,
    )?;
    let ureq_manifest = provider_manifest(
        UREQ_PACKAGE,
        UREQ_RESOURCE,
        UREQ_RESOURCE_PATH,
        ureq_bytes,
        &contract,
        fleetd_direct_conversation_ureq_provider::implementation_id(),
    )?;
    let ureq = write_load_install(
        root,
        UREQ_DIRECTORY,
        &ureq_manifest,
        &[ResourceBytes {
            path: UREQ_RESOURCE_PATH,
            bytes: ureq_bytes,
        }],
        &mut registry,
    )?;
    let provider_plan = plan_route(&registry)?;

    let attester_manifest = attester_manifest(attester_bytes, &contract)?;
    let attester = write_load_install(
        root,
        ATTESTER_DIRECTORY,
        &attester_manifest,
        &[ResourceBytes {
            path: ATTESTER_RESOURCE_PATH,
            bytes: attester_bytes,
        }],
        &mut registry,
    )?;
    let post_attester_plan = plan_route(&registry)?;
    build_report(
        InstalledSet {
            registry: &registry,
            contract: &contract,
            reqwest: &reqwest,
            ureq: &ureq,
            attester: &attester,
        },
        PlanningSet {
            contract_only: &contract_only_plan,
            providers: &provider_plan,
            post_attester: &post_attester_plan,
        },
    )
}

#[derive(Clone, Copy)]
struct InstalledSet<'installed> {
    registry: &'installed PackageRegistry,
    contract: &'installed InstalledPackage,
    reqwest: &'installed InstalledPackage,
    ureq: &'installed InstalledPackage,
    attester: &'installed InstalledPackage,
}

#[derive(Clone, Copy)]
struct PlanningSet<'planned> {
    contract_only: &'planned SemanticPlan,
    providers: &'planned SemanticPlan,
    post_attester: &'planned SemanticPlan,
}

fn build_report(
    installed: InstalledSet<'_>,
    plans: PlanningSet<'_>,
) -> Result<ProofReport, ProofError> {
    validate_package_graph(installed)?;
    assert_contract_only_need(plans.contract_only)?;
    assert_two_provider_plan(plans.providers)?;
    if plans.providers != plans.post_attester {
        return Err(invariant(
            "installing the resource-only attester changed the semantic plan",
        ));
    }

    let planner = planner(installed.registry)?;
    let linked = plans.providers.capabilities[0]
        .offers
        .iter()
        .map(|offer| {
            let invocation = link_synthetic_invocation(&planner, plans.providers, offer)?;
            let package = match &offer.implementation {
                implementation
                    if implementation
                        == &fleetd_direct_conversation_reqwest_provider::implementation_id() =>
                {
                    installed.reqwest
                }
                implementation
                    if implementation
                        == &fleetd_direct_conversation_ureq_provider::implementation_id() =>
                {
                    installed.ureq
                }
                _ => {
                    return Err(invariant(
                        "plan contains an unexpected provider implementation",
                    ));
                }
            };
            let resource = exact_single_resource(package)?;
            if offer.artifact_digest.as_str() != resource.digest.as_str() {
                return Err(invariant(
                    "provider offer is not bound to its package-owned artifact",
                ));
            }
            Ok(ProviderPackageBinding {
                implementation: offer.implementation.to_string(),
                offer_id: offer.offer_id.to_string(),
                invocation_id: invocation.invocation_id.to_string(),
                package: package.package_id().clone(),
                package_digest: package.digest().clone(),
                resource: resource.name,
                resource_digest: resource.digest,
            })
        })
        .collect::<Result<Vec<_>, ProofError>>()?;
    if linked.len() != 2 || linked[0].invocation_id == linked[1].invocation_id {
        return Err(invariant(
            "the two explicit provider selections did not yield distinct invocations",
        ));
    }

    let attester_resource = exact_single_resource(installed.attester)?;
    let packages = vec![
        package_coordinate(installed.contract, CONTRACT_DIRECTORY),
        package_coordinate(installed.reqwest, REQWEST_DIRECTORY),
        package_coordinate(installed.ureq, UREQ_DIRECTORY),
        package_coordinate(installed.attester, ATTESTER_DIRECTORY),
    ];
    let installation_order = packages
        .iter()
        .map(|coordinate| coordinate.package.clone())
        .collect();
    Ok(ProofReport {
        protocol: PROOF_REPORT_PROTOCOL.to_owned(),
        installation_order,
        packages,
        contract_only_plan_id: plans.contract_only.plan_id.to_string(),
        provider_plan_id: plans.providers.plan_id.to_string(),
        post_attester_plan_id: plans.post_attester.plan_id.to_string(),
        providers: linked,
        attester: AttesterDeploymentLock {
            suite: direct_conversation_ref_suite_id().to_string(),
            implementation: fleetd_direct_conversation_attester::implementation_id().to_string(),
            package: installed.attester.package_id().clone(),
            package_digest: installed.attester.digest().clone(),
            resource: attester_resource.name,
            resource_digest: attester_resource.digest,
        },
    })
}

fn validate_package_graph(installed: InstalledSet<'_>) -> Result<(), ProofError> {
    assert_exact_shape(installed.contract, CONTRACT_PACKAGE, 2, 0)?;
    assert_exact_shape(installed.reqwest, REQWEST_PACKAGE, 1, 1)?;
    assert_exact_shape(installed.ureq, UREQ_PACKAGE, 1, 1)?;
    assert_exact_shape(installed.attester, ATTESTER_PACKAGE, 1, 0)?;
    assert_exact_dependency(installed.reqwest, installed.contract)?;
    assert_exact_dependency(installed.ureq, installed.contract)?;
    assert_exact_dependency(installed.attester, installed.contract)?;

    let expected_contract = contract_manifest()
        .map_err(|error| invariant(format!("could not reconstruct contract package: {error}")))?;
    assert_exact_manifest(installed.contract, &expected_contract, "contract")?;
    let reqwest_bytes = retained_resource_bytes(installed.reqwest, REQWEST_RESOURCE)?;
    let ureq_bytes = retained_resource_bytes(installed.ureq, UREQ_RESOURCE)?;
    let attester_bytes = retained_resource_bytes(installed.attester, ATTESTER_RESOURCE)?;
    ensure_distinct_artifacts([reqwest_bytes, ureq_bytes, attester_bytes])?;
    let expected_reqwest = provider_manifest(
        REQWEST_PACKAGE,
        REQWEST_RESOURCE,
        REQWEST_RESOURCE_PATH,
        reqwest_bytes,
        installed.contract,
        fleetd_direct_conversation_reqwest_provider::implementation_id(),
    )?;
    let expected_ureq = provider_manifest(
        UREQ_PACKAGE,
        UREQ_RESOURCE,
        UREQ_RESOURCE_PATH,
        ureq_bytes,
        installed.contract,
        fleetd_direct_conversation_ureq_provider::implementation_id(),
    )?;
    let expected_attester = attester_manifest(attester_bytes, installed.contract)?;
    assert_exact_manifest(installed.reqwest, &expected_reqwest, "Reqwest provider")?;
    assert_exact_manifest(installed.ureq, &expected_ureq, "Ureq provider")?;
    assert_exact_manifest(installed.attester, &expected_attester, "attester")?;

    for (role, package) in [
        ("Reqwest provider", installed.reqwest),
        ("Ureq provider", installed.ureq),
        ("attester", installed.attester),
    ] {
        if !package.manifest().dialects.is_empty()
            || !package.manifest().conformance_suites.is_empty()
            || !package.manifest().capabilities.is_empty()
        {
            return Err(invariant(format!(
                "{role} package redefines contract semantics"
            )));
        }
        if package.manifest().resources[0].media_type != "application/octet-stream" {
            return Err(invariant(format!(
                "{role} package resource is not opaque application/octet-stream"
            )));
        }
    }
    Ok(())
}

fn provider_manifest(
    package: &str,
    resource: &str,
    path: &str,
    bytes: &[u8],
    contract: &InstalledPackage,
    implementation: ImplementationId,
) -> Result<PackageManifest, ProofError> {
    PackageManifest::new(
        package_id(package)?,
        vec![dependency(contract)],
        vec![native_resource(resource, path, bytes)?],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![ImplementationOfferDeclaration {
            implementation,
            capability: open_or_resolve_capability_id(),
            artifact: resource_name(resource)?,
            extensions: BTreeMap::new(),
        }],
        BTreeMap::new(),
    )
    .map_err(ProofError::Manifest)
}

fn attester_manifest(
    bytes: &[u8],
    contract: &InstalledPackage,
) -> Result<PackageManifest, ProofError> {
    PackageManifest::new(
        package_id(ATTESTER_PACKAGE)?,
        vec![dependency(contract)],
        vec![native_resource(
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

fn native_resource(name: &str, path: &str, bytes: &[u8]) -> Result<PackageResource, ProofError> {
    Ok(PackageResource {
        name: resource_name(name)?,
        path: path.to_owned(),
        media_type: "application/octet-stream".to_owned(),
        size: u64::try_from(bytes.len())
            .map_err(|_| invariant("native artifact length cannot be represented as u64"))?,
        digest: ResourceDigest::parse(sha256_identity(bytes))
            .map_err(|error| invariant(error.to_string()))?,
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
    PackageId::parse(value).map_err(|error| invariant(error.to_string()))
}

fn resource_name(value: &str) -> Result<ResourceName, ProofError> {
    ResourceName::parse(value).map_err(|error| invariant(error.to_string()))
}

fn planner(registry: &PackageRegistry) -> Result<SemanticPlanner, ProofError> {
    SemanticPlanner::from_registry(registry, planning_limits()).map_err(ProofError::Planning)
}

fn plan_route(registry: &PackageRegistry) -> Result<SemanticPlan, ProofError> {
    planner(registry)?
        .plan(
            [direct_pair_intent_value_kind()],
            direct_conversation_ref_value_kind(),
        )
        .map_err(ProofError::Planning)
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

fn assert_contract_only_need(plan: &SemanticPlan) -> Result<(), ProofError> {
    let needs: Vec<_> = plan.needs().map(|need| need.id.clone()).collect();
    if plan.capabilities.len() != 1
        || plan.capabilities[0].specification.id != open_or_resolve_capability_id()
        || !plan.capabilities[0].offers.is_empty()
        || needs != vec![open_or_resolve_capability_id()]
    {
        return Err(invariant(
            "contract-only package graph does not expose exactly one providerless need",
        ));
    }
    Ok(())
}

fn assert_two_provider_plan(plan: &SemanticPlan) -> Result<(), ProofError> {
    let [capability] = plan.capabilities.as_slice() else {
        return Err(invariant(
            "provider plan does not contain exactly one capability",
        ));
    };
    let mut implementations: Vec<_> = capability
        .offers
        .iter()
        .map(|offer| offer.implementation.clone())
        .collect();
    implementations.sort();
    let mut expected = vec![
        fleetd_direct_conversation_reqwest_provider::implementation_id(),
        fleetd_direct_conversation_ureq_provider::implementation_id(),
    ];
    expected.sort();
    if capability.specification.id != open_or_resolve_capability_id()
        || implementations != expected
        || plan.needs().next().is_some()
    {
        return Err(invariant(
            "provider plan does not retain exactly both native client offers",
        ));
    }
    Ok(())
}

fn link_synthetic_invocation(
    planner: &SemanticPlanner,
    plan: &SemanticPlan,
    offer: &CapabilityOffer,
) -> Result<gooir_capability::protocol::CapabilityInvocation, ProofError> {
    let intent = DirectPairIntent::new(
        FleetdTarget::parse("fleetd:package-proof")
            .map_err(|error| invariant(error.to_string()))?,
        [
            DirectMember::new(
                AgentId::parse("agent-a").map_err(|error| invariant(error.to_string()))?,
                DeliveryMode::Inbox,
            ),
            DirectMember::new(
                AgentId::parse("agent-b").map_err(|error| invariant(error.to_string()))?,
                DeliveryMode::StreamOnly,
            ),
        ],
    )
    .map_err(|error| invariant(error.to_string()))?;
    let fact = intent
        .to_fact()
        .map_err(|error| invariant(error.to_string()))?;
    let admitted = AdmittedFactRef::new(
        fact.id.clone(),
        AuthorityRecordId::parse(format!("sha256:{}", "1".repeat(64)))
            .map_err(|error| invariant(error.to_string()))?,
        BTreeMap::new(),
    )
    .map_err(ProofError::Protocol)?;
    let input = LinkedInput::new(intent_port_name(), admitted, fact, BTreeMap::new())
        .map_err(ProofError::Protocol)?;
    planner
        .link_invocation(
            plan,
            InvocationLink {
                capability: &open_or_resolve_capability_id(),
                offer: &offer.offer_id,
                selection_extensions: BTreeMap::new(),
                inputs: vec![input],
                conformance_suite: direct_conversation_ref_suite_id(),
                invocation_extensions: BTreeMap::new(),
            },
        )
        .map_err(ProofError::Planning)
}

fn assert_exact_shape(
    package: &InstalledPackage,
    expected_id: &str,
    resources: usize,
    offers: usize,
) -> Result<(), ProofError> {
    if package.package_id().as_str() != expected_id
        || package.manifest().resources.len() != resources
        || package.manifest().implementation_offers.len() != offers
    {
        return Err(invariant(format!(
            "installed package {} has the wrong proof shape",
            package.package_id()
        )));
    }
    Ok(())
}

fn assert_exact_dependency(
    package: &InstalledPackage,
    contract: &InstalledPackage,
) -> Result<(), ProofError> {
    if package.manifest().dependencies != vec![dependency(contract)] {
        return Err(invariant(format!(
            "package {} does not depend exactly on the contract package",
            package.package_id()
        )));
    }
    Ok(())
}

fn assert_exact_manifest(
    package: &InstalledPackage,
    expected: &PackageManifest,
    role: &str,
) -> Result<(), ProofError> {
    if package.manifest() != expected {
        return Err(invariant(format!(
            "installed {role} manifest differs from exact reconstruction"
        )));
    }
    Ok(())
}

#[derive(Clone)]
struct ExactResource {
    name: ResourceName,
    digest: ResourceDigest,
}

fn exact_single_resource(package: &InstalledPackage) -> Result<ExactResource, ProofError> {
    let [declaration] = package.manifest().resources.as_slice() else {
        return Err(invariant(format!(
            "package {} does not contain exactly one resource",
            package.package_id()
        )));
    };
    let copied = package
        .resource(&declaration.name)
        .ok_or_else(|| invariant("installed package did not retain its resource"))?;
    if copied.digest() != &declaration.digest
        || copied.media_type() != "application/octet-stream"
        || sha256_identity(copied.bytes()) != declaration.digest.as_str()
    {
        return Err(invariant(
            "installed opaque resource is not bound to its copied bytes",
        ));
    }
    Ok(ExactResource {
        name: declaration.name.clone(),
        digest: declaration.digest.clone(),
    })
}

fn retained_resource_bytes<'installed>(
    package: &'installed InstalledPackage,
    expected_name: &str,
) -> Result<&'installed [u8], ProofError> {
    let name = resource_name(expected_name)?;
    package
        .resource(&name)
        .map(OwnedResource::bytes)
        .ok_or_else(|| invariant(format!("package {} lacks {name}", package.package_id())))
}

fn package_coordinate(package: &InstalledPackage, directory: &str) -> PackageCoordinate {
    PackageCoordinate {
        package: package.package_id().clone(),
        digest: package.digest().clone(),
        relative_directory: directory.to_owned(),
        resources: package
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

fn ensure_distinct_artifacts<const N: usize>(artifacts: [&[u8]; N]) -> Result<(), ProofError> {
    let mut digests = artifacts
        .iter()
        .map(|bytes| sha256_identity(bytes))
        .collect::<Vec<_>>();
    digests.sort();
    digests.dedup();
    if digests.len() != N {
        return Err(invariant(
            "native artifact digests must be pairwise distinct",
        ));
    }
    Ok(())
}

fn read_final_command(path: &Path) -> Result<Vec<u8>, ProofError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| ProofError::Filesystem {
        action: "open final native command",
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect final native command", path, source))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_NATIVE_COMMAND_BYTES {
        return Err(invariant(format!(
            "native command {} is not one nonempty bounded regular file",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .map_err(|_| invariant("native command length does not fit memory"))?,
    );
    Read::by_ref(&mut file)
        .take(MAX_NATIVE_COMMAND_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read final native command", path, source))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != metadata.len() {
        return Err(invariant(format!(
            "native command {} changed length while being read",
            path.display()
        )));
    }
    Ok(bytes)
}

struct ResourceBytes<'bytes> {
    path: &'static str,
    bytes: &'bytes [u8],
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
        max_resources: 2,
        max_resource_bytes: MAX_NATIVE_COMMAND_BYTES,
        max_total_resource_bytes: MAX_NATIVE_COMMAND_BYTES * 2,
    }
}

fn write_resource(root: &Path, resource: &ResourceBytes<'_>) -> Result<(), ProofError> {
    let path = root.join(resource.path);
    if let Some(parent) = path.parent() {
        create_directory_tree(root, parent)?;
    }
    write_new_file(&path, resource.bytes, 0o400)?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn create_directory_tree(root: &Path, directory: &Path) -> Result<(), ProofError> {
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| invariant("resource parent escaped its package root"))?;
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
    fs::create_dir(path).map_err(|source| io_error("create directory", path, source))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|source| io_error("set directory permissions", path, source))
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ProofError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create package file", path, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error("write package file", path, source))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|source| io_error("set package file permissions", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("synchronize package file", path, source))
}

fn ensure_output_absent(path: &Path) -> Result<(), ProofError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ProofError::OutputRootExists(path.to_path_buf())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspect output root", path, source)),
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
    if output_parent(&staging_path)? != parent_path {
        return Err(invariant("staging and output roots are not siblings"));
    }
    let staging_name = staging_path
        .file_name()
        .ok_or_else(|| ProofError::InvalidOutputRoot(staging_path.clone()))?;
    let output_name = output
        .file_name()
        .ok_or_else(|| ProofError::InvalidOutputRoot(output.to_path_buf()))?;
    let descriptor = open(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| ProofError::Filesystem {
        action: "open output parent directory",
        path: parent_path.to_path_buf(),
        detail: error.to_string(),
    })?;
    let parent = File::from(descriptor);
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
    let _published = staging.keep();
    parent
        .sync_all()
        .map_err(|source| io_error("synchronize output parent", parent_path, source))
}

fn sync_directory(path: &Path) -> Result<(), ProofError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| ProofError::Filesystem {
        action: "open directory for synchronization",
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;
    File::from(descriptor)
        .sync_all()
        .map_err(|source| io_error("synchronize directory", path, source))
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

fn invariant(detail: impl Into<String>) -> ProofError {
    ProofError::Invariant(detail.into())
}

fn io_error(action: &'static str, path: &Path, source: std::io::Error) -> ProofError {
    ProofError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

/// Failure to stage or verify the exact native artifact package set.
#[derive(Debug)]
pub enum ProofError {
    Invariant(String),
    Manifest(PackageManifestError),
    Load(PackageLoadError),
    Install(InstallError),
    Planning(PlanningError),
    Protocol(ProtocolError),
    OutputRootExists(PathBuf),
    InvalidOutputRoot(PathBuf),
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
}

impl fmt::Display for ProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invariant(detail) => write!(formatter, "proof invariant failed: {detail}"),
            Self::Manifest(error) => write!(formatter, "package manifest failed: {error}"),
            Self::Load(error) => write!(formatter, "package load failed: {error}"),
            Self::Install(error) => write!(formatter, "package install failed: {error}"),
            Self::Planning(error) => write!(formatter, "planning failed: {error}"),
            Self::Protocol(error) => write!(formatter, "capability protocol failed: {error}"),
            Self::OutputRootExists(path) => {
                write!(formatter, "output root already exists: {}", path.display())
            }
            Self::InvalidOutputRoot(path) => {
                write!(formatter, "invalid output root: {}", path.display())
            }
            Self::Filesystem {
                action,
                path,
                detail,
            } => write!(formatter, "could not {action} {}: {detail}", path.display()),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "could not {action} {}: {source}", path.display()),
        }
    }
}

impl Error for ProofError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Manifest(error) => Some(error),
            Self::Load(error) => Some(error),
            Self::Install(error) => Some(error),
            Self::Planning(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::Invariant(_)
            | Self::OutputRootExists(_)
            | Self::InvalidOutputRoot(_)
            | Self::Filesystem { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const REQWEST_BYTES: &[u8] = b"opaque reqwest native command bytes\0v1";
    const UREQ_BYTES: &[u8] = b"opaque ureq native command bytes\0v1";
    const ATTESTER_BYTES: &[u8] = b"opaque attester native command bytes\0v1";

    struct Fixture {
        _temporary: tempfile::TempDir,
        reqwest: PathBuf,
        ureq: PathBuf,
        attester: PathBuf,
        output: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().expect("temporary directory");
            let reqwest = temporary.path().join("reqwest-command");
            let ureq = temporary.path().join("ureq-command");
            let attester = temporary.path().join("attester-command");
            let output = temporary.path().join("packages");
            fs::write(&reqwest, REQWEST_BYTES).expect("Reqwest source");
            fs::write(&ureq, UREQ_BYTES).expect("Ureq source");
            fs::write(&attester, ATTESTER_BYTES).expect("attester source");
            Self {
                _temporary: temporary,
                reqwest,
                ureq,
                attester,
                output,
            }
        }

        fn request(&self) -> StageRequest {
            StageRequest {
                reqwest_command: self.reqwest.clone(),
                ureq_command: self.ureq.clone(),
                attester_command: self.attester.clone(),
                output_root: self.output.clone(),
            }
        }
    }

    #[test]
    fn stages_four_exact_packages_and_retains_two_explicit_provider_selections() {
        let fixture = Fixture::new();
        let report = stage(fixture.request()).expect("stage package proof");
        assert_eq!(report.protocol, PROOF_REPORT_PROTOCOL);
        assert_eq!(report.packages.len(), 4);
        assert_eq!(report.providers.len(), 2);
        assert_ne!(report.contract_only_plan_id, report.provider_plan_id);
        assert_eq!(report.provider_plan_id, report.post_attester_plan_id);
        assert_ne!(
            report.providers[0].invocation_id,
            report.providers[1].invocation_id
        );
        assert_eq!(
            report
                .providers
                .iter()
                .map(|provider| provider.implementation.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                fleetd_direct_conversation_reqwest_provider::implementation_id().to_string(),
                fleetd_direct_conversation_ureq_provider::implementation_id().to_string(),
            ])
        );
        for package in &report.packages[1..] {
            assert_eq!(package.resources.len(), 1);
            assert_eq!(package.resources[0].media_type, "application/octet-stream");
        }

        let verified = verify_package_set(&fixture.output).expect("verify owned package set");
        assert_eq!(verified.report(), &report);
        for binding in &report.providers {
            let offer = verified
                .provider_offer(binding)
                .expect("locked provider offer");
            let artifact = verified
                .provider_artifact(binding)
                .expect("locked provider artifact");
            assert_eq!(offer.artifact_digest.as_str(), artifact.digest().as_str());
            let expected = if binding.implementation
                == fleetd_direct_conversation_reqwest_provider::implementation_id().to_string()
            {
                REQWEST_BYTES
            } else {
                UREQ_BYTES
            };
            assert_eq!(artifact.bytes(), expected);
        }
        assert_eq!(
            verified
                .attester_resource(&report.attester)
                .expect("locked attester")
                .bytes(),
            ATTESTER_BYTES
        );
    }

    #[test]
    fn each_artifact_installs_over_only_the_exact_contract_dependency() {
        for role in ["reqwest", "ureq", "attester"] {
            let temporary = tempfile::tempdir().expect("temporary package root");
            let mut registry = PackageRegistry::default();
            let contract = install_contract(temporary.path(), &mut registry);
            let contract_only = plan_route(&registry).expect("contract-only plan");
            assert_contract_only_need(&contract_only).expect("providerless need");

            let installed = match role {
                "reqwest" => {
                    let manifest = provider_manifest(
                        REQWEST_PACKAGE,
                        REQWEST_RESOURCE,
                        REQWEST_RESOURCE_PATH,
                        REQWEST_BYTES,
                        &contract,
                        fleetd_direct_conversation_reqwest_provider::implementation_id(),
                    )
                    .expect("Reqwest manifest");
                    write_load_install(
                        temporary.path(),
                        "reqwest",
                        &manifest,
                        &[ResourceBytes {
                            path: REQWEST_RESOURCE_PATH,
                            bytes: REQWEST_BYTES,
                        }],
                        &mut registry,
                    )
                    .expect("install Reqwest")
                }
                "ureq" => {
                    let manifest = provider_manifest(
                        UREQ_PACKAGE,
                        UREQ_RESOURCE,
                        UREQ_RESOURCE_PATH,
                        UREQ_BYTES,
                        &contract,
                        fleetd_direct_conversation_ureq_provider::implementation_id(),
                    )
                    .expect("Ureq manifest");
                    write_load_install(
                        temporary.path(),
                        "ureq",
                        &manifest,
                        &[ResourceBytes {
                            path: UREQ_RESOURCE_PATH,
                            bytes: UREQ_BYTES,
                        }],
                        &mut registry,
                    )
                    .expect("install Ureq")
                }
                "attester" => {
                    let manifest =
                        attester_manifest(ATTESTER_BYTES, &contract).expect("attester manifest");
                    write_load_install(
                        temporary.path(),
                        "attester",
                        &manifest,
                        &[ResourceBytes {
                            path: ATTESTER_RESOURCE_PATH,
                            bytes: ATTESTER_BYTES,
                        }],
                        &mut registry,
                    )
                    .expect("install attester")
                }
                _ => unreachable!(),
            };
            assert_eq!(
                installed.manifest().dependencies,
                vec![dependency(&contract)]
            );
            assert!(installed.manifest().dialects.is_empty());
            assert!(installed.manifest().conformance_suites.is_empty());
            assert!(installed.manifest().capabilities.is_empty());
            assert_eq!(installed.manifest().resources.len(), 1);
            assert_eq!(
                installed.manifest().resources[0].media_type,
                "application/octet-stream"
            );
            let plan = plan_route(&registry).expect("post-install plan");
            if role == "attester" {
                assert_eq!(plan, contract_only);
                assert!(installed.manifest().implementation_offers.is_empty());
            } else {
                assert_eq!(plan.capabilities[0].offers.len(), 1);
                assert!(plan.needs().next().is_none());
            }
        }
    }

    #[test]
    fn provider_install_order_is_not_a_selection_policy() {
        let forward = install_two_provider_plan(false);
        let reverse = install_two_provider_plan(true);
        assert_eq!(forward, reverse);
        assert_two_provider_plan(&forward).expect("two-provider plan");

        let mut opposite_offer_order = forward;
        opposite_offer_order.capabilities[0].offers.reverse();
        assert_two_provider_plan(&opposite_offer_order)
            .expect("provider-set assertion is independent of offer identity order");
    }

    #[test]
    fn complete_locks_fail_closed_and_owned_bytes_survive_source_removal() {
        let fixture = Fixture::new();
        stage(fixture.request()).expect("stage package proof");
        let verified = verify_package_set(&fixture.output).expect("verify package set");
        fs::remove_file(&fixture.reqwest).expect("remove Reqwest source");
        fs::remove_file(&fixture.ureq).expect("remove Ureq source");
        fs::remove_file(&fixture.attester).expect("remove attester source");
        fs::remove_dir_all(&fixture.output).expect("remove staged package tree");

        assert_eq!(
            verified
                .provider_artifact(&verified.report().providers[0])
                .expect("owned provider bytes")
                .digest()
                .as_str(),
            verified.report().providers[0].resource_digest.as_str()
        );
        assert_eq!(
            verified
                .attester_resource(&verified.report().attester)
                .expect("owned attester bytes")
                .bytes(),
            ATTESTER_BYTES
        );

        let mut provider_substitution = verified.report().providers[0].clone();
        provider_substitution.resource_digest =
            ResourceDigest::parse(format!("sha256:{}", "f".repeat(64))).expect("digest");
        assert!(verified.provider_offer(&provider_substitution).is_none());
        assert!(verified.provider_artifact(&provider_substitution).is_none());

        let mut attester_substitution = verified.report().attester.clone();
        attester_substitution.suite = "dev.fleetd.conformance/other@0.1.0".to_owned();
        assert!(verified.attester_resource(&attester_substitution).is_none());
    }

    #[test]
    fn changed_artifact_and_dependency_manifest_fail_closed() {
        let artifact_fixture = Fixture::new();
        stage(artifact_fixture.request()).expect("stage artifact fixture");
        let artifact_path = artifact_fixture
            .output
            .join(REQWEST_DIRECTORY)
            .join(REQWEST_RESOURCE_PATH);
        make_writable(&artifact_path);
        fs::write(&artifact_path, b"changed bytes").expect("change artifact");
        assert!(matches!(
            verify(&artifact_fixture.output),
            Err(ProofError::Load(_))
        ));

        let dependency_fixture = Fixture::new();
        stage(dependency_fixture.request()).expect("stage dependency fixture");
        let manifest_path = dependency_fixture
            .output
            .join(REQWEST_DIRECTORY)
            .join(gooir_package::PACKAGE_MANIFEST_FILE);
        let invalid = PackageManifest::new(
            package_id(REQWEST_PACKAGE).expect("package ID"),
            Vec::new(),
            vec![
                native_resource(REQWEST_RESOURCE, REQWEST_RESOURCE_PATH, REQWEST_BYTES)
                    .expect("resource"),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![ImplementationOfferDeclaration {
                implementation: fleetd_direct_conversation_reqwest_provider::implementation_id(),
                capability: open_or_resolve_capability_id(),
                artifact: resource_name(REQWEST_RESOURCE).expect("resource name"),
                extensions: BTreeMap::new(),
            }],
            BTreeMap::new(),
        )
        .expect("self-consistent but unbound manifest");
        make_writable(&manifest_path);
        fs::write(
            &manifest_path,
            write_manifest(&invalid).expect("manifest JSON"),
        )
        .expect("replace manifest");
        assert!(matches!(
            verify(&dependency_fixture.output),
            Err(ProofError::Load(_))
        ));
    }

    #[test]
    fn staging_refuses_aliasing_and_an_existing_output() {
        let aliasing = Fixture::new();
        fs::write(&aliasing.ureq, REQWEST_BYTES).expect("alias bytes");
        assert!(matches!(
            stage(aliasing.request()),
            Err(ProofError::Invariant(detail)) if detail.contains("pairwise distinct")
        ));

        let existing = Fixture::new();
        fs::create_dir(&existing.output).expect("existing output");
        assert!(matches!(
            stage(existing.request()),
            Err(ProofError::OutputRootExists(_))
        ));
    }

    fn install_contract(root: &Path, registry: &mut PackageRegistry) -> InstalledPackage {
        let manifest = contract_manifest().expect("contract manifest");
        write_load_install(
            root,
            "contract",
            &manifest,
            &[
                ResourceBytes {
                    path: DIRECT_CONVERSATION_REF_SCHEMA_PATH,
                    bytes: DIRECT_CONVERSATION_REF_SCHEMA_BYTES,
                },
                ResourceBytes {
                    path: DIRECT_PAIR_INTENT_SCHEMA_PATH,
                    bytes: DIRECT_PAIR_INTENT_SCHEMA_BYTES,
                },
            ],
            registry,
        )
        .expect("install contract")
    }

    fn install_two_provider_plan(reverse: bool) -> SemanticPlan {
        let temporary = tempfile::tempdir().expect("package root");
        let mut registry = PackageRegistry::default();
        let contract = install_contract(temporary.path(), &mut registry);
        let reqwest = provider_manifest(
            REQWEST_PACKAGE,
            REQWEST_RESOURCE,
            REQWEST_RESOURCE_PATH,
            REQWEST_BYTES,
            &contract,
            fleetd_direct_conversation_reqwest_provider::implementation_id(),
        )
        .expect("Reqwest manifest");
        let ureq = provider_manifest(
            UREQ_PACKAGE,
            UREQ_RESOURCE,
            UREQ_RESOURCE_PATH,
            UREQ_BYTES,
            &contract,
            fleetd_direct_conversation_ureq_provider::implementation_id(),
        )
        .expect("Ureq manifest");
        let installs = if reverse {
            [
                (
                    "ureq",
                    &ureq,
                    ResourceBytes {
                        path: UREQ_RESOURCE_PATH,
                        bytes: UREQ_BYTES,
                    },
                ),
                (
                    "reqwest",
                    &reqwest,
                    ResourceBytes {
                        path: REQWEST_RESOURCE_PATH,
                        bytes: REQWEST_BYTES,
                    },
                ),
            ]
        } else {
            [
                (
                    "reqwest",
                    &reqwest,
                    ResourceBytes {
                        path: REQWEST_RESOURCE_PATH,
                        bytes: REQWEST_BYTES,
                    },
                ),
                (
                    "ureq",
                    &ureq,
                    ResourceBytes {
                        path: UREQ_RESOURCE_PATH,
                        bytes: UREQ_BYTES,
                    },
                ),
            ]
        };
        for (directory, manifest, resource) in installs {
            write_load_install(
                temporary.path(),
                directory,
                manifest,
                &[resource],
                &mut registry,
            )
            .expect("install provider");
        }
        plan_route(&registry).expect("provider plan")
    }

    fn make_writable(path: &Path) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("writable fixture");
    }
}
