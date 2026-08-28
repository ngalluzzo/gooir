use std::cell::Cell;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::num::NonZeroUsize;

use gooir_capability::authority::{
    AdmissionAuthorityId, AdmissionPolicy, AssessmentOutcome, AuthorityBasis,
    ConformanceAssessment, ConformanceAttester, ConformanceAuthority, ConformanceCheck,
    ObservationAuthority, ObservationSourceId, SourceObservation,
};
use gooir_capability::protocol::{
    ArtifactDigest, CapabilityCandidate, CapabilityInvocation, CapabilityResult,
    ConformanceSuiteId, EvidenceDigest, EvidenceKindId, EvidenceRef, ImplementationId, NamedOutput,
};
use gooir_capability::{
    CapabilityId, CapabilitySpec, Fact, InputPort, OutputPort, PortName, ValueKindId,
};
use gooir_derive::{
    Answer, COMPLETE_SELECTION_EXTENSION, CompilerDriver, DerivationHost, DerivationLimits,
    FailureStage, LocalAttesterBinding, LocalStdioHost, LocalStdioLimits, Refusal,
};
use gooir_package::{
    ConformanceSuiteDeclaration, DialectDeclaration, ImplementationOfferDeclaration, LoadLimits,
    PackageId, PackageManifest, PackageRegistry, PackageResource, ResourceDigest, ResourceName,
    ValueKindDeclaration, load_local_package, write_manifest,
};
use gooir_planning::{PlanLimits, RouteOutputRef};
use serde_json::json;
use sha2::{Digest as _, Sha256};

const VERSION: &str = "1.0.0";
const FIRST_ARTIFACT: &[u8] = br"#!/usr/bin/python3
import hashlib, json, sys

def identity(document, field):
    value = dict(document)
    del value[field]
    canonical = json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode()
    return 'sha256:' + hashlib.sha256(canonical).hexdigest()

invocation = json.load(sys.stdin)
source = invocation['inputs'][0]['fact']['payload']['value']
declaration = invocation['specification']['output_ports'][0]
fact_body = {'value_kind': declaration['value_kind'], 'payload': {'value': source + 1}}
fact = {'id': identity({'id': '', **fact_body}, 'id'), **fact_body}
result = {
    'result_id': '',
    'protocol': 'org.gooi.capability.result/v1',
    'invocation_id': invocation['invocation_id'],
    'outcome': {'status': 'produced', 'outputs': [{'port': declaration['name'], 'fact': fact}]},
    'evidence': []
}
result['result_id'] = identity(result, 'result_id')
json.dump(result, sys.stdout, ensure_ascii=False, separators=(',', ':'))
";
const SECOND_ARTIFACT: &[u8] = br"#!/usr/bin/python3
import hashlib, json, sys

def identity(document, field):
    value = dict(document)
    del value[field]
    canonical = json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode()
    return 'sha256:' + hashlib.sha256(canonical).hexdigest()

invocation = json.load(sys.stdin)
source = invocation['inputs'][0]['fact']['payload']['value']
declaration = invocation['specification']['output_ports'][0]
fact_body = {'value_kind': declaration['value_kind'], 'payload': {'value': source + 1}}
fact = {'id': identity({'id': '', **fact_body}, 'id'), **fact_body}
result = {
    'result_id': '',
    'protocol': 'org.gooi.capability.result/v1',
    'invocation_id': invocation['invocation_id'],
    'outcome': {'status': 'produced', 'outputs': [{'port': declaration['name'], 'fact': fact}]},
    'evidence': []
}
result['result_id'] = identity(result, 'result_id')
json.dump(result, sys.stdout, ensure_ascii=False, separators=(',', ':'))
";
const ATTESTER_ARTIFACT: &[u8] = br"#!/usr/bin/python3
import hashlib, json, sys

def identity(document, field):
    value = dict(document)
    del value[field]
    canonical = json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode()
    return 'sha256:' + hashlib.sha256(canonical).hexdigest()

request = json.load(sys.stdin)
assessment = {
    'assessment_id': '',
    'protocol': 'org.gooi.authority.conformance-assessment/v1',
    'invocation_id': request['invocation']['invocation_id'],
    'result_id': request['result']['result_id'],
    'candidate_id': request['candidate']['candidate_id'],
    'authority': request['authority'],
    'outcome': 'passed',
    'checks': {'semantic': {'outcome': 'passed', 'evidence': []}},
    'evidence': []
}
assessment['assessment_id'] = identity(assessment, 'assessment_id')
json.dump(assessment, sys.stdout, ensure_ascii=False, separators=(',', ':'))
";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostBehavior {
    Produce,
    FailInvocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostError;

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("host fixture failed")
    }
}

impl Error for HostError {}

#[derive(Debug)]
struct RecordingHost {
    behavior: HostBehavior,
    invocations: Vec<CapabilityInvocation>,
    assessments: usize,
}

impl RecordingHost {
    fn producing() -> Self {
        Self {
            behavior: HostBehavior::Produce,
            invocations: Vec::new(),
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

impl DerivationHost for RecordingHost {
    type Error = HostError;

    fn invoke(
        &mut self,
        invocation: &CapabilityInvocation,
    ) -> Result<CapabilityResult, Self::Error> {
        self.invocations.push(invocation.clone());
        if self.behavior == HostBehavior::FailInvocation {
            return Err(HostError);
        }
        let [input] = invocation.inputs.as_slice() else {
            return Err(HostError);
        };
        let value = input.fact.payload["value"].as_u64().ok_or(HostError)?;
        let [output] = invocation.specification.output_ports.as_slice() else {
            return Err(HostError);
        };
        let fact = Fact::new(output.value_kind.clone(), json!({"value": value + 1}))
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
                "exact".to_owned(),
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
    policy: AdmissionPolicy,
    source: SourceObservation,
    attester: ConformanceAuthority,
}

impl Fixture {
    fn new(accept_attester: bool) -> Self {
        let registry = package_registry();
        let source_fact = Fact::new(value_kind("source"), json!({"value": 1})).unwrap();
        let observation_authority = ObservationAuthority::new(
            ObservationSourceId::new("test.source", "fixture", VERSION),
            ImplementationId::new("test.observer", "memory", VERSION),
            artifact('c'),
            source_fact.value_kind.clone(),
            EvidenceKindId::new("test.evidence", "source", VERSION),
            BTreeMap::new(),
        )
        .unwrap();
        let source = SourceObservation::new(
            source_fact,
            observation_authority.clone(),
            EvidenceRef::new(
                EvidenceKindId::new("test.evidence", "source", VERSION),
                EvidenceDigest::parse(sha('d')).unwrap(),
                "memory://compiler-driver-source",
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
                ArtifactDigest::parse(raw_digest(ATTESTER_ARTIFACT)).unwrap(),
                BTreeMap::new(),
            )
            .unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        let policy = AdmissionPolicy::new(
            AdmissionAuthorityId::new("test.admission", "local", VERSION),
            if accept_attester {
                vec![attester.clone()]
            } else {
                Vec::new()
            },
            vec![observation_authority],
            BTreeMap::new(),
        )
        .unwrap();
        Self {
            registry,
            policy,
            source,
            attester,
        }
    }

    fn driver(
        &self,
        host: RecordingHost,
        attesters: impl IntoIterator<Item = ConformanceAuthority>,
    ) -> CompilerDriver<RecordingHost> {
        CompilerDriver::new(
            &self.registry,
            self.policy.clone(),
            attesters,
            host,
            limits(),
        )
        .unwrap()
    }

    fn local_driver(&self) -> CompilerDriver<LocalStdioHost> {
        let binding = LocalAttesterBinding {
            authority: self.attester.clone(),
            package: PackageId::parse("test.compiler-driver@1.0.0").unwrap(),
            resource: ResourceName::parse("attester").unwrap(),
        };
        let host = LocalStdioHost::new(&self.registry, [binding], local_limits()).unwrap();
        let authorities = host.authorities().cloned().collect::<Vec<_>>();
        CompilerDriver::new(
            &self.registry,
            self.policy.clone(),
            authorities,
            host,
            limits(),
        )
        .unwrap()
    }
}

#[test]
fn multi_hop_compile_uses_installed_offers_linking_host_assessment_and_admission() {
    let fixture = Fixture::new(true);
    let mut installed_artifacts = fixture
        .registry
        .offers()
        .map(|offer| {
            fixture
                .registry
                .offer_artifact(&offer.offer_id)
                .expect("every installed offer retains copied bytes")
                .bytes()
                .to_vec()
        })
        .collect::<Vec<_>>();
    installed_artifacts.sort();
    let mut expected_artifacts = vec![FIRST_ARTIFACT.to_vec(), SECOND_ARTIFACT.to_vec()];
    expected_artifacts.sort();
    assert_eq!(installed_artifacts, expected_artifacts);

    let mut driver = fixture.local_driver();
    let answer = driver.compile(value_kind("target"), [fixture.source.clone()]);

    let Answer::Produced(produced) = answer else {
        panic!("expected an admitted multi-hop target")
    };
    assert_eq!(produced.admitted.len(), 2);
    let invocations = produced
        .admitted
        .iter()
        .map(|authority| match &authority.basis {
            AuthorityBasis::Derived { invocation, .. } => invocation.as_ref(),
            AuthorityBasis::Source { .. } => panic!("produced outputs must have derived authority"),
        })
        .collect::<Vec<_>>();
    assert_eq!(invocations.len(), 2);
    assert_eq!(invocations[0].specification.id, capability("first"));
    assert_eq!(invocations[1].specification.id, capability("second"));
    for invocation in &invocations {
        assert_eq!(
            invocation
                .selection
                .extensions
                .get(COMPLETE_SELECTION_EXTENSION),
            Some(&json!(produced.selection_id.as_str()))
        );
        assert_eq!(
            fixture.registry.offer(&invocation.selection.offer.offer_id),
            Some(&invocation.selection.offer)
        );
    }

    let linked_intermediate = &invocations[1].inputs[0];
    let resolved_intermediate = driver
        .ledger()
        .resolve(&linked_intermediate.admitted)
        .unwrap();
    assert_eq!(resolved_intermediate.fact, &linked_intermediate.fact);
    assert!(matches!(
        resolved_intermediate.authority.basis,
        AuthorityBasis::Derived { .. }
    ));
    for authority in &produced.admitted {
        authority.validate().unwrap();
        let AuthorityBasis::Derived {
            invocation,
            result,
            candidate,
            assessment,
            ..
        } = &authority.basis
        else {
            panic!("compiled outputs require derived authority")
        };
        assert_eq!(assessment.authority, fixture.attester);
        assert_ne!(
            assessment.authority.attester.implementation,
            invocation.selection.offer.implementation
        );
        assert_ne!(
            assessment.authority.attester.artifact_digest,
            invocation.selection.offer.artifact_digest
        );
        assessment
            .validate_against(invocation, result, candidate)
            .unwrap();
    }
    let resolved_target = driver.ledger().resolve(&produced.target).unwrap();
    assert_eq!(resolved_target.fact.value_kind, value_kind("target"));
    assert_eq!(resolved_target.fact.payload, json!({"value": 3}));
}

#[test]
fn compiler_driver_accepts_an_exact_capability_output_goal() {
    let fixture = Fixture::new(true);
    let mut driver = fixture.driver(RecordingHost::producing(), [fixture.attester.clone()]);
    let target = RouteOutputRef {
        capability: capability("second"),
        output_port: port("result"),
        extensions: BTreeMap::new(),
    };

    let answer = driver.compile_output(target.clone(), [fixture.source.clone()]);

    let Answer::Produced(produced) = answer else {
        panic!("expected the exact capability output to be admitted")
    };
    assert_eq!(
        produced
            .admitted
            .last()
            .and_then(|authority| match &authority.basis {
                AuthorityBasis::Derived { invocation, .. } => Some(&invocation.specification.id),
                AuthorityBasis::Source { .. } => None,
            }),
        Some(&target.capability)
    );
    let blocked_fixture = Fixture::new(true);
    let mut blocked_driver = blocked_fixture.driver(RecordingHost::producing(), []);
    let blocked = blocked_driver.compile_output(
        RouteOutputRef {
            capability: capability("second"),
            output_port: port("result"),
            extensions: BTreeMap::new(),
        },
        [blocked_fixture.source],
    );
    let Answer::Blocked(blocked) = blocked else {
        panic!("the requested output must remain blocked without an attester")
    };
    assert_eq!(blocked.blockage.target_alternatives.len(), 1);
    assert_eq!(
        blocked.blockage.target_alternatives[0].capability,
        capability("second")
    );
    assert!(blocked_driver.host().invocations.is_empty());
}

#[test]
fn compiler_driver_preserves_all_five_terminal_outcomes() {
    let produced_fixture = Fixture::new(true);
    let mut produced_driver = produced_fixture.driver(
        RecordingHost::producing(),
        [produced_fixture.attester.clone()],
    );
    let produced = produced_driver.compile(value_kind("target"), [produced_fixture.source.clone()]);
    assert!(matches!(produced, Answer::Produced(_)));

    let blocked_fixture = Fixture::new(true);
    let mut blocked_driver = blocked_fixture.driver(RecordingHost::producing(), []);
    let blocked = blocked_driver.compile(value_kind("target"), [blocked_fixture.source.clone()]);
    assert!(matches!(blocked, Answer::Blocked(_)));
    assert!(blocked_driver.host().invocations.is_empty());

    let unreachable_fixture = Fixture::new(true);
    let mut unreachable_driver = unreachable_fixture.driver(
        RecordingHost::producing(),
        [unreachable_fixture.attester.clone()],
    );
    let unreachable = unreachable_driver.compile(
        value_kind("unreachable"),
        [unreachable_fixture.source.clone()],
    );
    assert!(matches!(unreachable, Answer::Unreachable(_)));
    assert!(unreachable_driver.host().invocations.is_empty());

    let refused_fixture = Fixture::new(false);
    let mut refused_driver = refused_fixture.driver(
        RecordingHost::producing(),
        [refused_fixture.attester.clone()],
    );
    let refused = refused_driver.compile(value_kind("target"), [refused_fixture.source.clone()]);
    assert!(matches!(
        refused,
        Answer::Refused(ref reason)
            if matches!(reason.as_ref(), Refusal::AdmissionPolicy { decision: None, .. })
    ));
    assert!(refused_driver.host().invocations.is_empty());

    let failed_fixture = Fixture::new(true);
    let mut failed_driver =
        failed_fixture.driver(RecordingHost::failing(), [failed_fixture.attester.clone()]);
    let failed = failed_driver.compile(value_kind("target"), [failed_fixture.source.clone()]);
    assert!(matches!(
        failed,
        Answer::Failed(ref detail) if detail.stage == FailureStage::ProviderHost
    ));
    assert_eq!(failed_driver.host().invocations.len(), 1);
    assert_eq!(failed_driver.host().assessments, 0);

    assert_eq!(
        [
            produced.remedy(),
            blocked.remedy(),
            unreachable.remedy(),
            refused.remedy(),
            failed.remedy(),
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len(),
        5
    );
}

#[test]
fn withheld_source_is_a_refusal_and_does_not_mutate_the_driver_ledger() {
    let fixture = Fixture::new(true);
    let deny_sources = AdmissionPolicy::new(
        fixture.policy.decision_authority.clone(),
        fixture.policy.accepted_conformance.clone(),
        Vec::new(),
        BTreeMap::new(),
    )
    .unwrap();
    let mut driver = CompilerDriver::new(
        &fixture.registry,
        deny_sources,
        [fixture.attester],
        RecordingHost::producing(),
        limits(),
    )
    .unwrap();

    let answer = driver.compile(value_kind("target"), [fixture.source]);

    assert!(matches!(
        answer,
        Answer::Refused(reason)
            if matches!(*reason, Refusal::AdmissionPolicy { decision: Some(_), .. })
    ));
    assert!(driver.ledger().export().unwrap().facts.is_empty());
    assert!(driver.host().invocations.is_empty());
}

#[test]
fn input_limit_stops_at_first_excess_without_effects_or_ledger_mutation() {
    let fixture = Fixture::new(true);
    let mut bounded = limits();
    bounded.max_inputs = NonZeroUsize::new(1).unwrap();
    let mut driver = CompilerDriver::new(
        &fixture.registry,
        fixture.policy.clone(),
        [fixture.attester.clone()],
        RecordingHost::producing(),
        bounded,
    )
    .unwrap();
    let before = serde_json::to_vec(&driver.ledger().export().unwrap()).unwrap();

    let two = driver.compile(
        value_kind("target"),
        [fixture.source.clone(), fixture.source.clone()],
    );

    assert!(matches!(
        two,
        Answer::Refused(reason)
            if matches!(*reason, Refusal::InvalidRequest { ref detail }
                if detail.contains("exceeds configured input limit 1"))
    ));
    assert_eq!(
        serde_json::to_vec(&driver.ledger().export().unwrap()).unwrap(),
        before
    );
    assert!(driver.host().invocations.is_empty());
    assert_eq!(driver.host().assessments, 0);

    let pulls = Cell::new(0);
    let continuing = driver.compile(
        value_kind("target"),
        std::iter::repeat(fixture.source.clone()).inspect(|_| {
            pulls.set(pulls.get() + 1);
        }),
    );

    assert!(matches!(
        continuing,
        Answer::Refused(reason)
            if matches!(*reason, Refusal::InvalidRequest { .. })
    ));
    assert_eq!(
        serde_json::to_vec(&driver.ledger().export().unwrap()).unwrap(),
        before
    );
    assert!(driver.host().invocations.is_empty());
    assert_eq!(driver.host().assessments, 0);
    assert_eq!(pulls.get(), 2, "the driver must pull only max_inputs + 1");
}

#[test]
fn local_host_rejects_an_attester_resource_not_bound_to_its_complete_authority() {
    let fixture = Fixture::new(true);
    let binding = LocalAttesterBinding {
        authority: fixture.attester,
        package: PackageId::parse("test.compiler-driver@1.0.0").unwrap(),
        resource: ResourceName::parse("first-provider").unwrap(),
    };

    let error = LocalStdioHost::new(&fixture.registry, [binding], local_limits()).unwrap_err();

    assert!(matches!(
        error,
        gooir_derive::LocalStdioError::AttesterArtifactDigestMismatch { .. }
    ));
}

fn package_registry() -> PackageRegistry {
    let first = capability_spec("first", "source", "intermediate");
    let second = capability_spec("second", "intermediate", "target");
    let resources = vec![
        package_resource("attester", "attester", ATTESTER_ARTIFACT),
        package_resource("first-provider", "first-provider.bin", FIRST_ARTIFACT),
        package_resource("second-provider", "second-provider.bin", SECOND_ARTIFACT),
    ];
    let manifest = PackageManifest::new(
        PackageId::parse("test.compiler-driver@1.0.0").unwrap(),
        Vec::new(),
        resources,
        vec![DialectDeclaration {
            id: value_kind("source").dialect(),
            value_kinds: ["intermediate", "source", "target"]
                .into_iter()
                .map(|name| ValueKindDeclaration {
                    id: value_kind(name),
                    schema: None,
                    extensions: BTreeMap::new(),
                })
                .collect(),
            extensions: BTreeMap::new(),
        }],
        vec![ConformanceSuiteDeclaration {
            id: suite(),
            extensions: BTreeMap::new(),
        }],
        vec![first, second],
        vec![
            ImplementationOfferDeclaration {
                implementation: implementation("first"),
                capability: capability("first"),
                artifact: ResourceName::parse("first-provider").unwrap(),
                extensions: BTreeMap::new(),
            },
            ImplementationOfferDeclaration {
                implementation: implementation("second"),
                capability: capability("second"),
                artifact: ResourceName::parse("second-provider").unwrap(),
                extensions: BTreeMap::new(),
            },
        ],
        BTreeMap::new(),
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join(gooir_package::PACKAGE_MANIFEST_FILE),
        write_manifest(&manifest).unwrap(),
    )
    .unwrap();
    fs::write(directory.path().join("first-provider.bin"), FIRST_ARTIFACT).unwrap();
    fs::write(directory.path().join("attester"), ATTESTER_ARTIFACT).unwrap();
    fs::write(
        directory.path().join("second-provider.bin"),
        SECOND_ARTIFACT,
    )
    .unwrap();
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

fn capability_spec(name: &str, input: &str, output: &str) -> CapabilitySpec {
    CapabilitySpec {
        id: capability(name),
        input_ports: vec![InputPort::complete(port("source"), value_kind(input))],
        output_ports: vec![OutputPort::new(port("result"), value_kind(output))],
        default_conformance_suite: suite().to_string(),
        extensions: BTreeMap::new(),
    }
}

fn package_resource(name: &str, path: &str, bytes: &[u8]) -> PackageResource {
    PackageResource {
        name: ResourceName::parse(name).unwrap(),
        path: path.to_owned(),
        media_type: "application/octet-stream".to_owned(),
        size: u64::try_from(bytes.len()).unwrap(),
        digest: ResourceDigest::parse(raw_digest(bytes)).unwrap(),
        extensions: BTreeMap::new(),
    }
}

fn value_kind(name: &str) -> ValueKindId {
    ValueKindId::new("test.value", name, VERSION)
}

fn capability(name: &str) -> CapabilityId {
    CapabilityId::new("test.capability", name, VERSION)
}

fn implementation(name: &str) -> ImplementationId {
    ImplementationId::new("test.provider", name, VERSION)
}

fn suite() -> ConformanceSuiteId {
    ConformanceSuiteId::new("test.conformance", "exact", VERSION)
}

fn port(name: &str) -> PortName {
    PortName::parse(name).unwrap()
}

fn artifact(byte: char) -> ArtifactDigest {
    ArtifactDigest::parse(sha(byte)).unwrap()
}

fn sha(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn raw_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{digest:x}")
}

fn limits() -> DerivationLimits {
    let bounded = NonZeroUsize::new(32).unwrap();
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

fn local_limits() -> LocalStdioLimits {
    LocalStdioLimits {
        max_stdin_bytes: NonZeroUsize::new(1024 * 1024).unwrap(),
        max_stdout_bytes: NonZeroUsize::new(1024 * 1024).unwrap(),
        max_stderr_bytes: NonZeroUsize::new(64 * 1024).unwrap(),
        timeout_milliseconds: std::num::NonZeroU64::new(5_000).unwrap(),
    }
}
