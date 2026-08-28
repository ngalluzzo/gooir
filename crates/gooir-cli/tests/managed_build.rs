#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::collections::BTreeMap;
use std::fs;
use std::process::{Command, Output};

use gooir_artifact_sdk::{
    PublicationOutcome, PublicationReceipt, content_set_contract, package_manifest,
};
use gooir_capability::authority::{
    AdmissionAuthorityId, AdmissionPolicy, ConformanceAttester, ConformanceAuthority,
    ObservationAuthority, ObservationSourceId,
};
use gooir_capability::protocol::{
    ArtifactDigest, ConformanceSuiteId, EvidenceKindId, ImplementationId,
};
use gooir_capability::{
    CapabilityId, CapabilitySpec, InputPort, OutputPort, PortName, ValueKindId,
};
use gooir_package::{
    ConformanceSuiteDeclaration, PackageManifest, ResourceName, ValueKindDeclaration,
};
use gooir_toolchain::{
    PackageRecipe, PublicationDurability, ResourceInput, ToolchainImageBuilder, ToolchainLimits,
};
use sha2::{Digest as _, Sha256};

const VERSION: &str = "1.0.0";
const PROVIDER: &[u8] = br"#!/usr/bin/python3
import base64, hashlib, json, sys

def identity(document, field):
    value = dict(document)
    del value[field]
    canonical = json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode()
    return 'sha256:' + hashlib.sha256(canonical).hexdigest()

invocation = json.load(sys.stdin)
source = base64.b64decode(invocation['inputs'][0]['fact']['payload']['files'][0]['content'])
declaration = invocation['specification']['output_ports'][0]
generated = base64.b64encode(b'generated:' + source).decode()
fact_body = {
    'value_kind': declaration['value_kind'],
    'payload': {'files': [{'path': 'generated.txt', 'content': generated}]}
}
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
const ATTESTER: &[u8] = br"#!/usr/bin/python3
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

struct Fixture {
    temporary: tempfile::TempDir,
    capability: CapabilityId,
    source_authority: ObservationAuthority,
    accepted_policy: AdmissionPolicy,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let capability = CapabilityId::new("org.example.generator", "files", VERSION);
        let suite = ConformanceSuiteId::new("org.example.generator", "exact", VERSION);
        let provider_implementation =
            ImplementationId::new("org.example.provider", "files", VERSION);
        let attester_implementation =
            ImplementationId::new("org.example.attester", "exact", VERSION);
        let provider_resource = ResourceName::parse("provider").unwrap();
        let attester_resource = ResourceName::parse("attester").unwrap();
        let contract = package_manifest();
        let mut dialects = contract.dialects;
        let wrong_kind = ValueKindId::new("org.gooi.artifact.content_set", "not-content", VERSION);
        dialects[0].value_kinds.push(ValueKindDeclaration {
            id: wrong_kind.clone(),
            schema: None,
            extensions: BTreeMap::new(),
        });
        dialects[0]
            .value_kinds
            .sort_by(|left, right| left.id.cmp(&right.id));
        let wrong_capability = CapabilityId::new("org.example.generator", "wrong", VERSION);
        let manifest = PackageManifest::new(
            contract.package,
            Vec::new(),
            Vec::new(),
            dialects,
            vec![ConformanceSuiteDeclaration {
                id: suite.clone(),
                extensions: BTreeMap::new(),
            }],
            vec![
                CapabilitySpec {
                    id: capability.clone(),
                    input_ports: vec![InputPort::complete(
                        PortName::parse("source").unwrap(),
                        content_set_contract(),
                    )],
                    output_ports: vec![OutputPort::new(
                        PortName::parse("files").unwrap(),
                        content_set_contract(),
                    )],
                    default_conformance_suite: suite.to_string(),
                    extensions: BTreeMap::new(),
                },
                CapabilitySpec {
                    id: wrong_capability,
                    input_ports: vec![InputPort::complete(
                        PortName::parse("source").unwrap(),
                        content_set_contract(),
                    )],
                    output_ports: vec![OutputPort::new(
                        PortName::parse("value").unwrap(),
                        wrong_kind,
                    )],
                    default_conformance_suite: suite.to_string(),
                    extensions: BTreeMap::new(),
                },
            ],
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let recipe = PackageRecipe::from_manifest("generator", manifest)
            .unwrap()
            .with_resource(ResourceInput::bytes(
                provider_resource.clone(),
                "bin/provider",
                "application/octet-stream",
                PROVIDER,
            ))
            .unwrap()
            .with_resource(ResourceInput::bytes(
                attester_resource.clone(),
                "bin/attester",
                "application/octet-stream",
                ATTESTER,
            ))
            .unwrap()
            .with_provider(
                provider_implementation,
                capability.clone(),
                provider_resource,
            )
            .unwrap()
            .with_attester(
                suite.clone(),
                attester_implementation.clone(),
                attester_resource,
            )
            .unwrap();
        let publication = ToolchainImageBuilder::new()
            .with_package(recipe)
            .unwrap()
            .publish_create(
                temporary.path().join("toolchain"),
                ToolchainLimits::default(),
            )
            .unwrap();
        assert!(matches!(
            publication.durability(),
            PublicationDurability::DirectorySynchronized | PublicationDurability::Uncertain { .. }
        ));

        let source_authority = ObservationAuthority::new(
            ObservationSourceId::new("org.example.source", "spec", VERSION),
            ImplementationId::new("org.example.observer", "files", VERSION),
            artifact_digest(b"explicit-observer-claim"),
            content_set_contract(),
            EvidenceKindId::new("org.gooi.cli.evidence", "raw-file-sha256", "1.0.0"),
            BTreeMap::new(),
        )
        .unwrap();
        let conformance = ConformanceAuthority::new(
            suite,
            ConformanceAttester::new(
                attester_implementation,
                artifact_digest(ATTESTER),
                BTreeMap::new(),
            )
            .unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        let accepted_policy = AdmissionPolicy::new(
            AdmissionAuthorityId::new("org.example.admission", "local", VERSION),
            vec![conformance],
            vec![source_authority.clone()],
            BTreeMap::new(),
        )
        .unwrap();
        fs::write(temporary.path().join("spec.bin"), b"first").unwrap();
        write_json(
            &temporary.path().join("source-authority.json"),
            &source_authority,
        );
        write_json(
            &temporary.path().join("accepted-policy.json"),
            &accepted_policy,
        );
        Self {
            temporary,
            capability,
            source_authority,
            accepted_policy,
        }
    }

    fn run(&self, output: &str, policy: &str, capability: &str, port: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_gooir"))
            .current_dir(self.temporary.path())
            .args([
                "build",
                capability,
                port,
                "--toolchain",
                self.temporary.path().join("toolchain").to_str().unwrap(),
                "--source",
                "spec.bin",
                "--source-authority",
                self.temporary
                    .path()
                    .join("source-authority.json")
                    .to_str()
                    .unwrap(),
                "--policy",
                self.temporary.path().join(policy).to_str().unwrap(),
                "--output",
                output,
                "--output-id",
                "org.example.generated@1.0.0",
                "--stdin-bytes",
                "1048576",
                "--stdout-bytes",
                "1048576",
                "--stderr-bytes",
                "1048576",
                "--timeout-ms",
                "30000",
                "--json",
            ])
            .output()
            .unwrap()
    }

    fn accepted(&self, output: &str) -> Output {
        self.run(
            output,
            "accepted-policy.json",
            &self.capability.to_string(),
            "files",
        )
    }
}

#[test]
fn exact_content_set_output_builds_repeats_replaces_and_refuses_drift() {
    let fixture = Fixture::new();
    let created = fixture.accepted("generated");
    assert_success(&created);
    let receipt: PublicationReceipt = serde_json::from_slice(&created.stdout).unwrap();
    assert!(matches!(receipt.outcome, PublicationOutcome::Created));
    assert_eq!(
        fs::read(fixture.temporary.path().join("generated/generated.txt")).unwrap(),
        b"generated:first"
    );

    let unchanged = fixture.accepted("generated");
    assert_success(&unchanged);
    let receipt: PublicationReceipt = serde_json::from_slice(&unchanged.stdout).unwrap();
    assert!(matches!(
        receipt.outcome,
        PublicationOutcome::Unchanged { .. }
    ));

    fs::write(fixture.temporary.path().join("spec.bin"), b"second").unwrap();
    let replaced = fixture.accepted("generated");
    assert_success(&replaced);
    let receipt: PublicationReceipt = serde_json::from_slice(&replaced.stdout).unwrap();
    assert!(matches!(
        receipt.outcome,
        PublicationOutcome::Replaced { .. }
    ));
    assert_eq!(
        fs::read(fixture.temporary.path().join("generated/generated.txt")).unwrap(),
        b"generated:second"
    );

    fs::write(
        fixture.temporary.path().join("generated/generated.txt"),
        b"user edit",
    )
    .unwrap();
    let drift = fixture.accepted("generated");
    assert!(!drift.status.success());
    assert!(
        String::from_utf8_lossy(&drift.stderr).contains("drifted"),
        "{}",
        String::from_utf8_lossy(&drift.stderr)
    );
    assert_eq!(
        fs::read(fixture.temporary.path().join("generated/generated.txt")).unwrap(),
        b"user edit"
    );
}

#[test]
fn preflight_and_source_admission_failures_create_no_output() {
    let fixture = Fixture::new();
    let unknown = fixture.run(
        "unknown-output",
        "accepted-policy.json",
        "org.example.missing/generator@1.0.0",
        "files",
    );
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("is not installed"));
    assert!(!fixture.temporary.path().join("unknown-output").exists());

    let wrong_kind = fixture.run(
        "wrong-kind-output",
        "accepted-policy.json",
        "org.example.generator/wrong@1.0.0",
        "value",
    );
    assert!(!wrong_kind.status.success());
    assert!(
        String::from_utf8_lossy(&wrong_kind.stderr)
            .contains("not org.gooi.artifact.content_set/set@1.0.0")
    );
    assert!(!fixture.temporary.path().join("wrong-kind-output").exists());

    let denied = AdmissionPolicy::new(
        fixture.accepted_policy.decision_authority.clone(),
        fixture.accepted_policy.accepted_conformance.clone(),
        Vec::new(),
        BTreeMap::new(),
    )
    .unwrap();
    write_json(
        &fixture.temporary.path().join("denied-policy.json"),
        &denied,
    );
    let refusal = fixture.run(
        "denied-output",
        "denied-policy.json",
        &fixture.capability.to_string(),
        "files",
    );
    assert!(!refusal.status.success());
    assert!(String::from_utf8_lossy(&refusal.stdout).contains("admission_policy"));
    assert!(!fixture.temporary.path().join("denied-output").exists());

    let mut wrong_authority = fixture.source_authority.clone();
    wrong_authority.evidence_kind = EvidenceKindId::new("org.example.evidence", "wrong", VERSION);
    write_json(
        &fixture.temporary.path().join("source-authority.json"),
        &wrong_authority,
    );
    let mismatch = fixture.run(
        "mismatch-output",
        "accepted-policy.json",
        &fixture.capability.to_string(),
        "files",
    );
    assert!(!mismatch.status.success());
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("evidence kind must be"));
    assert!(!fixture.temporary.path().join("mismatch-output").exists());
}

fn artifact_digest(bytes: &[u8]) -> ArtifactDigest {
    ArtifactDigest::parse(format!("sha256:{:x}", Sha256::digest(bytes))).unwrap()
}

fn write_json(path: &std::path::Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
