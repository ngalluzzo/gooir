use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::Path;

use gooir_capability::authority::{
    AdmissionAuthorityId, AdmissionPolicy, AssessmentOutcome, ConformanceAssessment,
    ConformanceAttester, ConformanceAuthority, ConformanceCheck, ObservationAuthority,
    ObservationSourceId, SourceObservation,
};
use gooir_capability::protocol::{
    ArtifactDigest, CapabilityCandidate, CapabilityInvocation, CapabilityResult,
    ConformanceSuiteId, EvidenceDigest, EvidenceKindId, EvidenceRef, ImplementationId, NamedOutput,
};
use gooir_capability::{
    CapabilityId, CapabilitySpec, Fact, FactId, InputPort, OutputPort, PortName, ValueKindId,
};
use gooir_derive::{CompilerDriver, DerivationHost, DerivationLimits};
use gooir_file_tree_build::{FileTreeBuildAnswer, FileTreeBuildDriver, FileTreeBuildError};
use gooir_file_tree_materializer::{
    AdmittedFileTree, ConflictPolicy, FileTreeMaterializer, LocalFileTreeMaterializer,
    LocalMaterializationLimits, LocalMaterializationPolicy,
};
use gooir_file_tree_v1::{FileEntry, FileTree, dialect_id, file_tree_value_kind};
use gooir_package::{
    ConformanceSuiteDeclaration, DialectDeclaration, ImplementationOfferDeclaration, LoadLimits,
    PackageId, PackageManifest, PackageRegistry, PackageResource, ResourceDigest, ResourceName,
    ValueKindDeclaration, load_local_package, write_manifest,
};
use gooir_planning::PlanLimits;
use serde_json::json;
use sha2::{Digest as _, Sha256};

const VERSION: &str = "1.0.0";
const PROVIDER_BYTES: &[u8] = b"in-memory file-tree provider fixture";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostBehavior {
    Produce,
    FailInvocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostError;

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("in-memory derivation host failed")
    }
}

impl Error for HostError {}

#[derive(Debug)]
struct FileTreeHost {
    behavior: HostBehavior,
    invocations: usize,
    assessments: usize,
}

impl FileTreeHost {
    fn producing() -> Self {
        Self {
            behavior: HostBehavior::Produce,
            invocations: 0,
            assessments: 0,
        }
    }

    fn failing() -> Self {
        Self {
            behavior: HostBehavior::FailInvocation,
            ..Self::producing()
        }
    }
}

impl DerivationHost for FileTreeHost {
    type Error = HostError;

    fn invoke(
        &mut self,
        invocation: &CapabilityInvocation,
    ) -> Result<CapabilityResult, Self::Error> {
        self.invocations += 1;
        if self.behavior == HostBehavior::FailInvocation {
            return Err(HostError);
        }
        let [output] = invocation.specification.output_ports.as_slice() else {
            return Err(HostError);
        };
        if output.value_kind != file_tree_value_kind() {
            return Err(HostError);
        }
        let tree = FileTree::new(vec![
            FileEntry::new("README.md", "text/markdown", b"generated\n".to_vec())
                .map_err(|_| HostError)?,
            FileEntry::new(
                "src/data.bin",
                "application/octet-stream",
                vec![0, 159, 146, 150],
            )
            .map_err(|_| HostError)?,
        ])
        .map_err(|_| HostError)?;
        let fact = Fact::new(file_tree_value_kind(), serde_json::to_value(tree).unwrap())
            .map_err(|_| HostError)?;
        CapabilityResult::produced(
            invocation,
            vec![
                NamedOutput::new(output.name.clone(), fact, BTreeMap::new())
                    .map_err(|_| HostError)?,
            ],
            BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
        )
        .map_err(|_| HostError)
    }

    fn assess(
        &mut self,
        invocation: &CapabilityInvocation,
        result: &CapabilityResult,
        candidate: &CapabilityCandidate,
        authority: &ConformanceAuthority,
    ) -> Result<ConformanceAssessment, Self::Error> {
        self.assessments += 1;
        ConformanceAssessment::new(
            invocation,
            result,
            candidate,
            authority.clone(),
            BTreeMap::from([(
                "exact-file-tree".to_owned(),
                ConformanceCheck::new(AssessmentOutcome::Passed, Vec::new(), BTreeMap::new())
                    .map_err(|_| HostError)?,
            )]),
            Vec::new(),
            BTreeMap::new(),
        )
        .map_err(|_| HostError)
    }
}

struct Fixture {
    registry: PackageRegistry,
    source: SourceObservation,
    source_authority: ObservationAuthority,
    attester: ConformanceAuthority,
}

impl Fixture {
    fn new(source_extensions: BTreeMap<String, serde_json::Value>) -> Self {
        let source_fact = Fact::new(source_kind(), json!({"model": "example"})).unwrap();
        let source_authority = ObservationAuthority::new(
            ObservationSourceId::new("test.source", "fixture", VERSION),
            ImplementationId::new("test.observer", "memory", VERSION),
            ArtifactDigest::parse(sha('c')).unwrap(),
            source_fact.value_kind.clone(),
            evidence_kind(),
            source_extensions,
        )
        .unwrap();
        let source = SourceObservation::new(
            source_fact,
            source_authority.clone(),
            EvidenceRef::new(
                evidence_kind(),
                EvidenceDigest::parse(sha('d')).unwrap(),
                "memory://build-driver-source",
                BTreeMap::new(),
            )
            .unwrap(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let attester = ConformanceAuthority::new(
            suite(),
            ConformanceAttester::new(
                ImplementationId::new("test.attester", "independent", VERSION),
                ArtifactDigest::parse(sha('e')).unwrap(),
                BTreeMap::new(),
            )
            .unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        Self {
            registry: package_registry(),
            source,
            source_authority,
            attester,
        }
    }

    fn policy(&self, accept_source: bool) -> AdmissionPolicy {
        AdmissionPolicy::new(
            AdmissionAuthorityId::new("test.admission", "build", VERSION),
            vec![self.attester.clone()],
            if accept_source {
                vec![self.source_authority.clone()]
            } else {
                Vec::new()
            },
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn compiler(
        &self,
        host: FileTreeHost,
        accept_source: bool,
        attesters: impl IntoIterator<Item = ConformanceAuthority>,
    ) -> CompilerDriver<FileTreeHost> {
        CompilerDriver::new(
            &self.registry,
            self.policy(accept_source),
            attesters,
            host,
            derivation_limits(),
        )
        .unwrap()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TestReceipt {
    fact_id: FactId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TestMaterializerError;

impl fmt::Display for TestMaterializerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected materializer failure")
    }
}

impl Error for TestMaterializerError {}

#[derive(Debug, Default)]
struct CountingMaterializer {
    calls: usize,
    fail: bool,
}

impl FileTreeMaterializer for CountingMaterializer {
    type Destination = Path;
    type Policy = ();
    type Receipt = TestReceipt;
    type Error = TestMaterializerError;

    fn materialize(
        &mut self,
        artifact: &AdmittedFileTree,
        _destination: &Path,
        _policy: &Self::Policy,
    ) -> Result<Self::Receipt, Self::Error> {
        self.calls += 1;
        if self.fail {
            Err(TestMaterializerError)
        } else {
            Ok(TestReceipt {
                fact_id: artifact.fact_id().clone(),
            })
        }
    }
}

#[test]
fn produced_build_publishes_physical_files_and_binds_both_receipts() {
    let fixture = Fixture::new(BTreeMap::new());
    let compiler = fixture.compiler(FileTreeHost::producing(), true, [fixture.attester.clone()]);
    let mut driver = FileTreeBuildDriver::new(compiler, LocalFileTreeMaterializer::new());
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("generated");

    let answer = driver
        .build(
            [fixture.source],
            &destination,
            &local_materialization_policy(),
        )
        .unwrap();

    let FileTreeBuildAnswer::Materialized(materialized) = answer else {
        panic!("expected a physically materialized build")
    };
    assert_eq!(
        fs::read(destination.join("README.md")).unwrap(),
        b"generated\n"
    );
    assert_eq!(
        fs::read(destination.join("src/data.bin")).unwrap(),
        vec![0, 159, 146, 150]
    );
    assert_eq!(
        materialized.receipt.fact_id(),
        &materialized.produced.target.fact_id
    );
    assert_eq!(
        materialized.receipt.authority_record_id(),
        &materialized.produced.target.authority_record_id
    );
    let resolved = driver
        .compiler()
        .ledger()
        .resolve(&materialized.produced.target)
        .unwrap();
    assert_eq!(resolved.fact.id, materialized.produced.target.fact_id);
    assert_eq!(driver.compiler().host().invocations, 1);
    assert_eq!(driver.compiler().host().assessments, 1);
}

#[test]
fn every_nonproduced_semantic_answer_bypasses_materialization() {
    let blocked_fixture = Fixture::new(BTreeMap::new());
    let mut blocked = FileTreeBuildDriver::new(
        blocked_fixture.compiler(FileTreeHost::producing(), true, []),
        CountingMaterializer::default(),
    );
    assert!(matches!(
        blocked
            .build([blocked_fixture.source], Path::new("unused"), &())
            .unwrap(),
        FileTreeBuildAnswer::Blocked(_)
    ));
    assert_eq!(blocked.materializer().calls, 0);

    let unreachable_fixture = Fixture::new(BTreeMap::new());
    let empty_registry = PackageRegistry::default();
    let compiler = CompilerDriver::new(
        &empty_registry,
        unreachable_fixture.policy(true),
        [unreachable_fixture.attester.clone()],
        FileTreeHost::producing(),
        derivation_limits(),
    )
    .unwrap();
    let mut unreachable = FileTreeBuildDriver::new(compiler, CountingMaterializer::default());
    assert!(matches!(
        unreachable
            .build([unreachable_fixture.source], Path::new("unused"), &())
            .unwrap(),
        FileTreeBuildAnswer::Unreachable(_)
    ));
    assert_eq!(unreachable.materializer().calls, 0);

    let refused_fixture = Fixture::new(BTreeMap::new());
    let mut refused = FileTreeBuildDriver::new(
        refused_fixture.compiler(
            FileTreeHost::producing(),
            false,
            [refused_fixture.attester.clone()],
        ),
        CountingMaterializer::default(),
    );
    assert!(matches!(
        refused
            .build([refused_fixture.source], Path::new("unused"), &())
            .unwrap(),
        FileTreeBuildAnswer::Refused(_)
    ));
    assert_eq!(refused.materializer().calls, 0);

    let failed_fixture = Fixture::new(BTreeMap::new());
    let mut failed = FileTreeBuildDriver::new(
        failed_fixture.compiler(
            FileTreeHost::failing(),
            true,
            [failed_fixture.attester.clone()],
        ),
        CountingMaterializer::default(),
    );
    assert!(matches!(
        failed
            .build([failed_fixture.source], Path::new("unused"), &())
            .unwrap(),
        FileTreeBuildAnswer::Failed(_)
    ));
    assert_eq!(failed.materializer().calls, 0);
}

#[test]
fn artifact_gate_refusal_retains_produced_answer_without_materializer_effects() {
    let fixture = Fixture::new(BTreeMap::from([(
        "org.example/source-semantics".to_owned(),
        json!(true),
    )]));
    let compiler = fixture.compiler(FileTreeHost::producing(), true, [fixture.attester.clone()]);
    let mut driver = FileTreeBuildDriver::new(compiler, CountingMaterializer::default());

    let error = driver
        .build([fixture.source], Path::new("unused"), &())
        .unwrap_err();

    assert!(matches!(
        error,
        FileTreeBuildError::ArtifactAdmission { .. }
    ));
    assert_eq!(driver.materializer().calls, 0);
    driver
        .compiler()
        .ledger()
        .resolve(&error.produced().target)
        .unwrap();
}

#[test]
fn materializer_failure_retains_the_exact_admitted_product() {
    let fixture = Fixture::new(BTreeMap::new());
    let compiler = fixture.compiler(FileTreeHost::producing(), true, [fixture.attester.clone()]);
    let materializer = CountingMaterializer {
        fail: true,
        ..CountingMaterializer::default()
    };
    let mut driver = FileTreeBuildDriver::new(compiler, materializer);

    let error = driver
        .build([fixture.source], Path::new("unused"), &())
        .unwrap_err();

    assert!(matches!(error, FileTreeBuildError::Materialization { .. }));
    assert_eq!(driver.materializer().calls, 1);
    let resolved = driver
        .compiler()
        .ledger()
        .resolve(&error.produced().target)
        .unwrap();
    assert_eq!(resolved.fact.id, error.produced().target.fact_id);
}

#[test]
fn build_answer_remedies_remain_distinct() {
    let fixture = Fixture::new(BTreeMap::new());
    let mut blocked = FileTreeBuildDriver::new(
        fixture.compiler(FileTreeHost::producing(), true, []),
        CountingMaterializer::default(),
    );
    let answer = blocked
        .build([fixture.source], Path::new("unused"), &())
        .unwrap();

    assert_eq!(
        answer.remedy(),
        "supply the missing implementation or attester"
    );
}

fn package_registry() -> PackageRegistry {
    let mut dialects = vec![
        DialectDeclaration {
            id: dialect_id(),
            value_kinds: vec![ValueKindDeclaration {
                id: file_tree_value_kind(),
                schema: None,
                extensions: BTreeMap::new(),
            }],
            extensions: BTreeMap::new(),
        },
        DialectDeclaration {
            id: source_kind().dialect(),
            value_kinds: vec![ValueKindDeclaration {
                id: source_kind(),
                schema: None,
                extensions: BTreeMap::new(),
            }],
            extensions: BTreeMap::new(),
        },
    ];
    dialects.sort_by(|left, right| left.id.cmp(&right.id));
    let manifest = PackageManifest::new(
        PackageId::parse("test.file-tree-builder@1.0.0").unwrap(),
        Vec::new(),
        vec![PackageResource {
            name: ResourceName::parse("provider").unwrap(),
            path: "provider.bin".to_owned(),
            media_type: "application/octet-stream".to_owned(),
            size: u64::try_from(PROVIDER_BYTES.len()).unwrap(),
            digest: ResourceDigest::parse(raw_digest(PROVIDER_BYTES)).unwrap(),
            extensions: BTreeMap::new(),
        }],
        dialects,
        vec![ConformanceSuiteDeclaration {
            id: suite(),
            extensions: BTreeMap::new(),
        }],
        vec![CapabilitySpec {
            id: capability(),
            input_ports: vec![InputPort::complete(port("source"), source_kind())],
            output_ports: vec![OutputPort::new(port("tree"), file_tree_value_kind())],
            default_conformance_suite: suite().to_string(),
            extensions: BTreeMap::new(),
        }],
        vec![ImplementationOfferDeclaration {
            implementation: ImplementationId::new("test.provider", "file-tree", VERSION),
            capability: capability(),
            artifact: ResourceName::parse("provider").unwrap(),
            extensions: BTreeMap::new(),
        }],
        BTreeMap::new(),
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join(gooir_package::PACKAGE_MANIFEST_FILE),
        write_manifest(&manifest).unwrap(),
    )
    .unwrap();
    fs::write(directory.path().join("provider.bin"), PROVIDER_BYTES).unwrap();
    let package = load_local_package(
        directory.path(),
        &PackageRegistry::default(),
        LoadLimits::default(),
    )
    .unwrap();
    let mut registry = PackageRegistry::default();
    registry.install(package).unwrap();
    registry
}

fn local_materialization_policy() -> LocalMaterializationPolicy {
    LocalMaterializationPolicy::new(
        ConflictPolicy::RefuseExisting,
        0o750,
        0o640,
        LocalMaterializationLimits {
            max_files: NonZeroUsize::new(8).unwrap(),
            max_directories: NonZeroUsize::new(8).unwrap(),
            max_file_bytes: NonZeroU64::new(1_024).unwrap(),
            max_total_bytes: NonZeroU64::new(4_096).unwrap(),
        },
    )
    .unwrap()
}

fn derivation_limits() -> DerivationLimits {
    let bounded = NonZeroUsize::new(16).unwrap();
    DerivationLimits {
        planning: PlanLimits {
            max_capabilities: bounded,
            max_value_kinds: bounded,
            max_ports_per_capability: bounded,
            max_total_ports: bounded,
            max_offers_per_capability: bounded,
            max_total_offers: bounded,
        },
        max_inputs: bounded,
        max_attesters: bounded,
    }
}

fn source_kind() -> ValueKindId {
    ValueKindId::new("test.source", "model", VERSION)
}

fn capability() -> CapabilityId {
    CapabilityId::new("test.capability", "build-file-tree", VERSION)
}

fn suite() -> ConformanceSuiteId {
    ConformanceSuiteId::new("test.conformance", "file-tree", VERSION)
}

fn evidence_kind() -> EvidenceKindId {
    EvidenceKindId::new("test.evidence", "source", VERSION)
}

fn port(name: &str) -> PortName {
    PortName::parse(name).unwrap()
}

fn sha(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn raw_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{digest:x}")
}
