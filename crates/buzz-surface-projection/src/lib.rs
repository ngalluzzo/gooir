//! Buzz-native projection into generic software-surface claims.
//!
//! The projection is deliberately product-specific. Its output is ordinary
//! GOOIR operations carrying exact semantic-contract claims, so downstream
//! analysis never depends on a Buzz lifter or native dialect.

use buzz_cli_lifter::{CommandNode, CommandTreeLift, NativeCompleteness as CliCompleteness};
use buzz_protocol_lifter::{
    NativeCompleteness as ProtocolCompleteness, ProtocolLift, SourceArtifact, SourceSpan,
};
use buzz_relay_lifter::{
    IngestDecisionKind, NativeCompleteness as RelayCompleteness, RelayIngestLift,
};
use buzz_surface_profile::{BUZZ_REVISION, SOURCE_SCOPE_ID, kind_identity};
use gooir_analysis::{EvidenceAdmissionFailure, EvidenceTrustPolicy};
use gooir_core::{Claim, ConformanceEvidence, ContractId, Evidence, Operation, Program, SourceRef};
use semantics_software_surface_v1::{
    ArtifactRole, CoverageCompleteness, CoverageProblem, CoverageWitness, ExtractorId,
    RelationKind, SurfaceRelation, coverage_witness_contract, relation_contract,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;

pub const DIALECT: &str = "org.gooi.dialect.buzz_surface_projection@0.1.0";
pub const AUTHORITY: &str = "github:block/buzz";
pub const LOCAL_ATTESTER: &str = "gooir:pinned-local-analysis-host";
pub const CONFORMANCE_SUITE: &str =
    "org.gooi.conformance.buzz_surface_projection.claim_binding@1.0.0";
pub const KIND_ARTIFACT: &str = "crates/buzz-core/src/kind.rs";
pub const RELAY_ARTIFACT: &str = "crates/buzz-relay/src/handlers/ingest.rs";
pub const PUSH_LEASE_ARTIFACT: &str = "crates/buzz-relay/src/handlers/push_lease.rs";
pub const CLI_ARTIFACT: &str = "crates/buzz-cli/src/lib.rs";
pub const KIND_SHA256: &str =
    "sha256:74533cfc1ac016dcb1a83279c2b06f93807f29489604cdccefc46b645acfce97";
pub const RELAY_SHA256: &str =
    "sha256:6f5ecbac1056c64ce161e72bc9d4b0fabc2c8d8648fb41b3812a655121f194a5";
pub const PUSH_LEASE_SHA256: &str =
    "sha256:297f7f59a7e141cdd5acf3a2ba6395ed4a34035050fab4d17d698d043b389ce0";
pub const CLI_SHA256: &str =
    "sha256:a4a6829515e23851822ce5b1c3e7b341c32e2997b17b3b4f74f8aad994ab6310";
pub const PROTOCOL_LIFT_DOCUMENT_SHA256: &str =
    "sha256:b6e82cee8d19e6eff421cd38a85f1d240a1f483c7ce40ea87bba5ed7f0c9d290";
pub const RELAY_LIFT_DOCUMENT_SHA256: &str =
    "sha256:ace236222ab94cccf1c70e384883b51e3d2df9506c9c4cdd49524058b9ebf5b7";
pub const CLI_LIFT_DOCUMENT_SHA256: &str =
    "sha256:053f343a9cd354487cd1a945f5ca94f69483030ad6bc9ef0f2443631f0fb6a91";

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PinnedSurface {
    pub program: Program,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionError {
    SourceMismatch {
        component: String,
        field: String,
        expected: String,
        actual: String,
    },
    ProtocolSourceMismatch,
    NativeDocumentMismatch {
        component: String,
        expected: String,
        actual: String,
    },
    Serialization(String),
    InvalidClaim {
        operation_id: String,
        reason: String,
    },
    Admission {
        operation_id: String,
        reason: EvidenceAdmissionFailure,
    },
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceMismatch {
                component,
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "{component} {field} mismatch: expected {expected}, got {actual}"
            ),
            Self::ProtocolSourceMismatch => formatter.write_str(
                "relay lift does not reference the exact protocol source used by the protocol lift",
            ),
            Self::NativeDocumentMismatch {
                component,
                expected,
                actual,
            } => write!(
                formatter,
                "{component} native lift document mismatch: expected {expected}, got {actual}"
            ),
            Self::Serialization(error) => {
                write!(formatter, "projection serialization failed: {error}")
            }
            Self::InvalidClaim {
                operation_id,
                reason,
            } => write!(
                formatter,
                "claim {operation_id} failed local validation: {reason}"
            ),
            Self::Admission {
                operation_id,
                reason,
            } => write!(
                formatter,
                "claim {operation_id} could not be admitted: {reason:?}"
            ),
        }
    }
}

impl std::error::Error for ProjectionError {}

/// Pins exact reviewed native-lift document bytes before deserialization, then
/// projects them without implicitly trusting the resulting claims.
pub fn project_pinned_job_surface(
    protocol_document: &[u8],
    relay_document: &[u8],
    cli_document: &[u8],
) -> Result<PinnedSurface, ProjectionError> {
    validate_native_document("protocol", protocol_document, PROTOCOL_LIFT_DOCUMENT_SHA256)?;
    validate_native_document("relay", relay_document, RELAY_LIFT_DOCUMENT_SHA256)?;
    validate_native_document("cli", cli_document, CLI_LIFT_DOCUMENT_SHA256)?;

    let protocol: ProtocolLift = serde_json::from_slice(protocol_document)
        .map_err(|error| ProjectionError::Serialization(error.to_string()))?;
    let relay: RelayIngestLift = serde_json::from_slice(relay_document)
        .map_err(|error| ProjectionError::Serialization(error.to_string()))?;
    let cli: CommandTreeLift = serde_json::from_slice(cli_document)
        .map_err(|error| ProjectionError::Serialization(error.to_string()))?;
    project_reviewed_job_surface(&protocol, &relay, &cli)
}

fn project_reviewed_job_surface(
    protocol: &ProtocolLift,
    relay: &RelayIngestLift,
    cli: &CommandTreeLift,
) -> Result<PinnedSurface, ProjectionError> {
    validate_source("protocol", &protocol.source, KIND_ARTIFACT, KIND_SHA256)?;
    validate_source("relay", &relay.source, RELAY_ARTIFACT, RELAY_SHA256)?;
    validate_source(
        "relay push lease",
        &relay.push_lease_source,
        PUSH_LEASE_ARTIFACT,
        PUSH_LEASE_SHA256,
    )?;
    if relay.push_lease_constant.is_none() {
        return Err(ProjectionError::SourceMismatch {
            component: "relay push lease".to_owned(),
            field: "constant".to_owned(),
            expected: "direct KIND_PUSH_LEASE declaration".to_owned(),
            actual: "missing".to_owned(),
        });
    }
    validate_source("cli", &cli.source, CLI_ARTIFACT, CLI_SHA256)?;
    if relay.protocol_source != protocol.source {
        return Err(ProjectionError::ProtocolSourceMismatch);
    }

    let mut operations = Vec::new();
    for declaration in &protocol.job_kinds {
        let object = kind_identity(declaration.value);
        let source = source_ref(
            &protocol.source,
            format_span("declaration", &declaration.declaration),
        );
        operations.push(relation_operation(
            format!("buzz-protocol:declares:{}", declaration.value),
            "protocol_declaration",
            SurfaceRelation {
                subject: "buzz-protocol:agent-job".to_owned(),
                relation: RelationKind::Declares,
                object: object.clone(),
                role: ArtifactRole::Production,
                scope_id: SOURCE_SCOPE_ID.to_owned(),
            },
            source.clone(),
        )?);
        if declaration.registered {
            operations.push(relation_operation(
                format!("buzz-protocol:registers:{}", declaration.value),
                "protocol_registration",
                SurfaceRelation {
                    subject: "buzz-core:event-kind-registry".to_owned(),
                    relation: RelationKind::Registers,
                    object,
                    role: ArtifactRole::Production,
                    scope_id: SOURCE_SCOPE_ID.to_owned(),
                },
                source,
            )?);
        }
    }

    let relay_span = format!(
        "scope_function={}; fallback={}; gate_call={}",
        format_span("lines", &relay.scope_function),
        format_span("lines", &relay.fallback),
        format_span("lines", &relay.gate_call)
    );
    for decision in &relay.job_decisions {
        let relation = match decision.decision {
            IngestDecisionKind::Accepted => Some(RelationKind::Accepts),
            IngestDecisionKind::Rejected => Some(RelationKind::Rejects),
            IngestDecisionKind::Unknown => None,
        };
        if let Some(relation) = relation {
            operations.push(relation_operation(
                format!("buzz-relay:ingest:{}", decision.value),
                "relay_ingest_decision",
                SurfaceRelation {
                    subject: "buzz-relay:client-ingest".to_owned(),
                    relation,
                    object: kind_identity(decision.value),
                    role: ArtifactRole::Production,
                    scope_id: SOURCE_SCOPE_ID.to_owned(),
                },
                source_ref(&relay.source, relay_span.clone()),
            )?);
        }
    }

    if cli.coverage.completeness == CliCompleteness::Exhaustive {
        for (index, command) in cli
            .commands
            .iter()
            .filter(|command| command_mentions_job_protocol(command))
            .enumerate()
        {
            operations.push(relation_operation(
                format!("buzz-cli:exposes-job-protocol:{index}"),
                "cli_command",
                SurfaceRelation {
                    subject: "buzz-cli:command-tree".to_owned(),
                    relation: RelationKind::Exposes,
                    object: "protocol:buzz-agent-job".to_owned(),
                    role: ArtifactRole::Production,
                    scope_id: SOURCE_SCOPE_ID.to_owned(),
                },
                source_ref(
                    &cli.source,
                    format!(
                        "command={}; {}",
                        command.path.join(" "),
                        format_span("declaration", &command.declaration)
                    ),
                ),
            )?);
        }
    }

    operations.push(coverage_operation(
        "coverage:protocol_registry",
        protocol_coverage(protocol),
        source_ref(&protocol.source, "registry=ALL_KINDS".to_owned()),
    )?);
    operations.push(coverage_operation(
        "coverage:relay_ingest_allowlist",
        relay_coverage(relay),
        source_ref(&relay.source, relay_span),
    )?);
    operations.push(coverage_operation(
        "coverage:cli_command_tree",
        cli_coverage(cli),
        source_ref(
            &cli.source,
            format!(
                "parser={}; command_field={}",
                format_span("lines", &cli.parser_struct),
                format_span("lines", &cli.command_field)
            ),
        ),
    )?);

    Ok(PinnedSurface {
        program: Program::new(operations),
    })
}

/// Validates the local claim-binding attestations and admits exact tuples.
///
/// This is a checked local host policy, not cryptographic verification. It is
/// intentionally limited to the pinned Buzz authority, revision, artifacts,
/// and source digests above.
pub fn admit_pinned_surface(
    surface: &PinnedSurface,
) -> Result<EvidenceTrustPolicy, ProjectionError> {
    let expected = embedded_pinned_surface()?;
    if surface != &expected {
        return Err(ProjectionError::InvalidClaim {
            operation_id: "<surface>".to_owned(),
            reason: "surface differs from the projection of the embedded reviewed native lifts"
                .to_owned(),
        });
    }
    let subject_digest = projection_subject_digest();
    let mut policy = EvidenceTrustPolicy::default();
    for operation in &surface.program.operations {
        if operation.claims.len() != 1 {
            return Err(ProjectionError::InvalidClaim {
                operation_id: operation.id.clone(),
                reason: "each projected operation must carry exactly one claim".to_owned(),
            });
        }
        let claim = &operation.claims[0];
        validate_claim_source(operation, claim)?;
        let Some(conformance) = &claim.evidence.conformance else {
            return Err(ProjectionError::InvalidClaim {
                operation_id: operation.id.clone(),
                reason: "verified claim has no conformance record".to_owned(),
            });
        };
        if conformance.attester != LOCAL_ATTESTER
            || conformance.suite != CONFORMANCE_SUITE
            || conformance.subject_digest != subject_digest
        {
            return Err(ProjectionError::InvalidClaim {
                operation_id: operation.id.clone(),
                reason:
                    "attester, suite, or projection subject digest is not the active pinned policy"
                        .to_owned(),
            });
        }
        let expected_result = result_digest(
            &operation.id,
            &claim.contract,
            &claim.payload,
            &claim.evidence.source,
            &subject_digest,
        )?;
        if conformance.result_digest != expected_result {
            return Err(ProjectionError::InvalidClaim {
                operation_id: operation.id.clone(),
                reason: "conformance result digest does not bind the exact claim".to_owned(),
            });
        }
        policy
            .admit_claim(operation, claim)
            .map_err(|reason| ProjectionError::Admission {
                operation_id: operation.id.clone(),
                reason,
            })?;
    }
    Ok(policy)
}

fn embedded_pinned_surface() -> Result<PinnedSurface, ProjectionError> {
    project_pinned_job_surface(
        include_bytes!("../../../fixtures/buzz/desktop-v0.5.18/job-protocol.lift.json"),
        include_bytes!("../../../fixtures/buzz/desktop-v0.5.18/job-relay.lift.json"),
        include_bytes!("../../../fixtures/buzz/desktop-v0.5.18/job-cli.lift.json"),
    )
}

fn validate_source(
    component: &str,
    source: &SourceArtifact,
    artifact: &str,
    digest: &str,
) -> Result<(), ProjectionError> {
    for (field, expected, actual) in [
        ("authority", AUTHORITY, source.authority.as_str()),
        ("artifact", artifact, source.artifact.as_str()),
        ("revision", BUZZ_REVISION, source.revision.as_str()),
        ("sha256", digest, source.sha256.as_str()),
    ] {
        if actual != expected {
            return Err(ProjectionError::SourceMismatch {
                component: component.to_owned(),
                field: field.to_owned(),
                expected: expected.to_owned(),
                actual: actual.to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_native_document(
    component: &str,
    bytes: &[u8],
    expected: &str,
) -> Result<(), ProjectionError> {
    let actual = sha256(bytes);
    if actual == expected {
        Ok(())
    } else {
        Err(ProjectionError::NativeDocumentMismatch {
            component: component.to_owned(),
            expected: expected.to_owned(),
            actual,
        })
    }
}

fn validate_claim_source(operation: &Operation, claim: &Claim) -> Result<(), ProjectionError> {
    if pinned_source_digest(&claim.evidence.source.artifact).is_none() {
        let artifact = &claim.evidence.source.artifact;
        return Err(ProjectionError::InvalidClaim {
            operation_id: operation.id.clone(),
            reason: format!("artifact {artifact} is outside the pinned source policy"),
        });
    }
    if claim.evidence.source.authority != AUTHORITY
        || claim.evidence.source.revision != BUZZ_REVISION
    {
        return Err(ProjectionError::InvalidClaim {
            operation_id: operation.id.clone(),
            reason: "source authority or revision is outside the pinned policy".to_owned(),
        });
    }
    let Some(conformance) = &claim.evidence.conformance else {
        return Err(ProjectionError::InvalidClaim {
            operation_id: operation.id.clone(),
            reason: "claim has no conformance record".to_owned(),
        });
    };
    if conformance.result_digest.is_empty() {
        return Err(ProjectionError::InvalidClaim {
            operation_id: operation.id.clone(),
            reason: "claim contains an empty pinned digest".to_owned(),
        });
    }
    Ok(())
}

fn relation_operation(
    id: String,
    name: &str,
    relation: SurfaceRelation,
    source: SourceRef,
) -> Result<Operation, ProjectionError> {
    claim_operation(id, name, relation_contract(), &relation, source)
}

fn coverage_operation(
    id: &str,
    witness: CoverageWitness,
    source: SourceRef,
) -> Result<Operation, ProjectionError> {
    claim_operation(
        id.to_owned(),
        "coverage_witness",
        coverage_witness_contract(),
        &witness,
        source,
    )
}

fn claim_operation<T: Serialize>(
    id: String,
    name: &str,
    contract: ContractId,
    payload: &T,
    source: SourceRef,
) -> Result<Operation, ProjectionError> {
    let payload = serde_json::to_value(payload)
        .map_err(|error| ProjectionError::Serialization(error.to_string()))?;
    let subject_digest = projection_subject_digest();
    let result_digest = result_digest(&id, &contract, &payload, &source, &subject_digest)?;
    let claim = Claim::new(
        contract,
        payload,
        Evidence::verified(
            source,
            ConformanceEvidence::new(
                LOCAL_ATTESTER,
                CONFORMANCE_SUITE,
                subject_digest,
                result_digest,
            ),
        ),
    );
    Ok(Operation::new(id, DIALECT, name).with_claim(claim))
}

#[derive(Serialize)]
struct LocalConformanceResult<'a> {
    operation_id: &'a str,
    contract: &'a ContractId,
    payload: &'a serde_json::Value,
    source: &'a SourceRef,
    source_digest: &'a str,
    subject_digest: &'a str,
}

fn result_digest(
    operation_id: &str,
    contract: &ContractId,
    payload: &serde_json::Value,
    source: &SourceRef,
    subject_digest: &str,
) -> Result<String, ProjectionError> {
    let source_digest =
        pinned_source_digest(&source.artifact).ok_or_else(|| ProjectionError::InvalidClaim {
            operation_id: operation_id.to_owned(),
            reason: format!(
                "artifact {} is outside the pinned source policy",
                source.artifact
            ),
        })?;
    let result = LocalConformanceResult {
        operation_id,
        contract,
        payload,
        source,
        source_digest,
        subject_digest,
    };
    let bytes = serde_json::to_vec(&result)
        .map_err(|error| ProjectionError::Serialization(error.to_string()))?;
    Ok(sha256(&bytes))
}

fn pinned_source_digest(artifact: &str) -> Option<&'static str> {
    match artifact {
        KIND_ARTIFACT => Some(KIND_SHA256),
        RELAY_ARTIFACT => Some(RELAY_SHA256),
        CLI_ARTIFACT => Some(CLI_SHA256),
        _ => None,
    }
}

fn projection_subject_digest() -> String {
    sha256(include_bytes!("lib.rs"))
}

fn protocol_coverage(protocol: &ProtocolLift) -> CoverageWitness {
    CoverageWitness {
        build_scope_id: SOURCE_SCOPE_ID.to_owned(),
        extractor: ExtractorId {
            package: protocol.coverage.extractor_package.clone(),
            version: protocol.coverage.extractor_version.clone(),
            config_digest: sha256(protocol.source.sha256.as_bytes()),
        },
        source_roots: vec!["crates/buzz-core/src".to_owned()],
        mechanism: "protocol_kind_registry".to_owned(),
        completeness: map_protocol_completeness(protocol.coverage.completeness),
        included_artifacts: protocol.coverage.included_artifacts.clone(),
        excluded_artifacts: Vec::new(),
        failed_artifacts: Vec::new(),
        unresolved_expansions: protocol
            .coverage
            .unresolved_macros
            .iter()
            .map(|reason| CoverageProblem {
                artifact: protocol.source.artifact.clone(),
                reason: reason.clone(),
            })
            .collect(),
    }
}

fn relay_coverage(relay: &RelayIngestLift) -> CoverageWitness {
    CoverageWitness {
        build_scope_id: SOURCE_SCOPE_ID.to_owned(),
        extractor: ExtractorId {
            package: relay.coverage.extractor_package.clone(),
            version: relay.coverage.extractor_version.clone(),
            config_digest: sha256(
                format!(
                    "{}\n{}\n{}",
                    relay.source.sha256,
                    relay.protocol_source.sha256,
                    relay.push_lease_source.sha256
                )
                .as_bytes(),
            ),
        },
        source_roots: vec![
            "crates/buzz-core/src".to_owned(),
            "crates/buzz-relay/src/handlers".to_owned(),
        ],
        mechanism: "relay_ingest_allowlist".to_owned(),
        completeness: map_relay_completeness(relay.coverage.completeness),
        included_artifacts: relay.coverage.included_artifacts.clone(),
        excluded_artifacts: Vec::new(),
        failed_artifacts: Vec::new(),
        unresolved_expansions: relay
            .coverage
            .unresolved
            .iter()
            .map(|reason| CoverageProblem {
                artifact: relay.source.artifact.clone(),
                reason: reason.clone(),
            })
            .collect(),
    }
}

fn cli_coverage(cli: &CommandTreeLift) -> CoverageWitness {
    CoverageWitness {
        build_scope_id: SOURCE_SCOPE_ID.to_owned(),
        extractor: ExtractorId {
            package: cli.coverage.extractor_package.clone(),
            version: cli.coverage.extractor_version.clone(),
            config_digest: sha256(cli.source.sha256.as_bytes()),
        },
        source_roots: vec!["crates/buzz-cli/src".to_owned()],
        mechanism: "cli_command_tree".to_owned(),
        completeness: map_cli_completeness(cli.coverage.completeness),
        included_artifacts: cli.coverage.included_artifacts.clone(),
        excluded_artifacts: Vec::new(),
        failed_artifacts: Vec::new(),
        unresolved_expansions: cli
            .coverage
            .unresolved
            .iter()
            .map(|reason| CoverageProblem {
                artifact: cli.source.artifact.clone(),
                reason: reason.clone(),
            })
            .collect(),
    }
}

fn command_mentions_job_protocol(command: &CommandNode) -> bool {
    command
        .path
        .iter()
        .chain(&command.aliases)
        .any(|segment| segment.eq_ignore_ascii_case("job") || segment.eq_ignore_ascii_case("jobs"))
}

fn map_protocol_completeness(completeness: ProtocolCompleteness) -> CoverageCompleteness {
    match completeness {
        ProtocolCompleteness::Exhaustive => CoverageCompleteness::Exhaustive,
        ProtocolCompleteness::Partial => CoverageCompleteness::Partial,
    }
}

fn map_relay_completeness(completeness: RelayCompleteness) -> CoverageCompleteness {
    match completeness {
        RelayCompleteness::Exhaustive => CoverageCompleteness::Exhaustive,
        RelayCompleteness::Partial => CoverageCompleteness::Partial,
    }
}

fn map_cli_completeness(completeness: CliCompleteness) -> CoverageCompleteness {
    match completeness {
        CliCompleteness::Exhaustive => CoverageCompleteness::Exhaustive,
        CliCompleteness::Partial => CoverageCompleteness::Partial,
    }
}

fn source_ref(source: &SourceArtifact, span: String) -> SourceRef {
    SourceRef::new(&source.authority, &source.artifact, &source.revision).with_span(span)
}

fn format_span(label: &str, span: &SourceSpan) -> String {
    format!(
        "{label}:{}-{} (bytes {}-{})",
        span.line_start, span.line_end, span.byte_start, span.byte_end
    )
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(7 + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use buzz_surface_profile::job_surface_profile;
    use gooir_analysis::SemanticResolver;
    use semantics_software_surface_v1::{CoverageCompleteness, RelationKind};
    use surface_completeness_analysis::{SurfaceCompletenessAnalyzer, SurfaceFindingLevel};

    use super::{admit_pinned_surface, project_pinned_job_surface, project_reviewed_job_surface};

    fn pinned_documents() -> (&'static [u8], &'static [u8], &'static [u8]) {
        (
            include_bytes!("../../../fixtures/buzz/desktop-v0.5.18/job-protocol.lift.json"),
            include_bytes!("../../../fixtures/buzz/desktop-v0.5.18/job-relay.lift.json"),
            include_bytes!("../../../fixtures/buzz/desktop-v0.5.18/job-cli.lift.json"),
        )
    }

    #[test]
    fn pinned_native_lifts_project_without_trusting_the_staging_snapshot() {
        let (protocol, relay, cli) = pinned_documents();
        let surface =
            project_pinned_job_surface(protocol, relay, cli).expect("pinned native lifts project");

        let relations = surface
            .program
            .operations
            .iter()
            .filter_map(|operation| operation.claims.first())
            .filter(|claim| claim.contract == semantics_software_surface_v1::relation_contract())
            .map(|claim| {
                serde_json::from_value::<semantics_software_surface_v1::SurfaceRelation>(
                    claim.payload.clone(),
                )
                .expect("relation payload is valid")
            })
            .collect::<Vec<_>>();

        assert_eq!(
            relations
                .iter()
                .filter(|relation| relation.relation == RelationKind::Rejects)
                .count(),
            6
        );
        assert_eq!(
            relations
                .iter()
                .filter(|relation| relation.relation == RelationKind::Declares)
                .count(),
            6
        );
        assert!(
            relations
                .iter()
                .all(|relation| relation.relation != RelationKind::Exposes)
        );
    }

    #[test]
    fn default_deny_keeps_all_projected_results_unknown() {
        let (protocol, relay, cli) = pinned_documents();
        let surface =
            project_pinned_job_surface(protocol, relay, cli).expect("pinned native lifts project");
        let report = SurfaceCompletenessAnalyzer::new(SemanticResolver::default())
            .analyze(&surface.program, &job_surface_profile());

        assert_eq!(report.findings.len(), 14);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.level == SurfaceFindingLevel::Unknown)
        );
    }

    #[test]
    fn pinned_policy_yields_six_rejections_one_cli_gap_and_scoped_unknowns() {
        let (protocol, relay, cli) = pinned_documents();
        let surface =
            project_pinned_job_surface(protocol, relay, cli).expect("pinned native lifts project");
        let policy = admit_pinned_surface(&surface).expect("pinned claims are locally admitted");
        let report = SurfaceCompletenessAnalyzer::new(SemanticResolver::with_trust_policy(policy))
            .analyze(&surface.program, &job_surface_profile());

        assert_eq!(report.findings.len(), 14);
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.code == "surface.contradicted")
                .count(),
            6
        );
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.code == "surface.missing_relation")
                .count(),
            1
        );
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|finding| finding.code == "surface.coverage_incomplete")
                .count(),
            7
        );
        assert!(
            report
                .findings
                .iter()
                .filter(|finding| { finding.code == "surface.contradicted" })
                .all(|finding| {
                    finding
                        .relation_basis
                        .iter()
                        .any(|basis| basis.relation.relation == RelationKind::Declares)
                        && finding.relation_basis.iter().any(|basis| {
                            basis.relation.relation == RelationKind::Rejects
                                && basis.source.span.as_deref().is_some_and(|span| {
                                    span.contains("fallback=lines:453-453")
                                        && span.contains("gate_call=lines:2157-2157")
                                })
                        })
                })
        );
        let cli_gap = report
            .findings
            .iter()
            .find(|finding| finding.requirement_id == "cli-exposes-job-protocol")
            .expect("CLI finding exists");
        assert_eq!(cli_gap.code, "surface.missing_relation");
        assert!(cli_gap.coverage_basis.iter().any(|basis| {
            basis.witness.mechanism == "cli_command_tree"
                && basis.witness.completeness == CoverageCompleteness::Exhaustive
        }));

        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/buzz/desktop-v0.5.18/job-surface.analysis.json"
        ))
        .expect("analysis golden is valid JSON");
        assert_eq!(
            serde_json::to_value(&report).expect("analysis report serializes"),
            expected
        );
    }

    #[test]
    fn mutating_a_projected_payload_invalidates_local_admission() {
        let (protocol, relay, cli) = pinned_documents();
        let mut surface =
            project_pinned_job_surface(protocol, relay, cli).expect("pinned native lifts project");
        surface.program.operations[0].claims[0].payload["subject"] =
            serde_json::json!("forged-subject");

        let error = admit_pinned_surface(&surface).expect_err("mutation must not retain trust");

        assert!(error.to_string().contains("differs from the projection"));
    }

    #[test]
    fn changing_a_native_result_without_changing_its_source_digest_is_rejected() {
        let (protocol, relay, cli) = pinned_documents();
        let relay = String::from_utf8(relay.to_vec())
            .expect("relay fixture is UTF-8")
            .replacen(
                "\"decision\": \"rejected\"",
                "\"decision\": \"accepted\"",
                1,
            );

        let error = project_pinned_job_surface(protocol, relay.as_bytes(), cli)
            .expect_err("mutated native result must not project under the pinned policy");

        assert!(
            error
                .to_string()
                .contains("relay native lift document mismatch")
        );
    }

    #[test]
    fn unknown_top_level_native_document_fields_are_rejected_before_parsing() {
        let (protocol, relay, cli) = pinned_documents();
        let cli = String::from_utf8(cli.to_vec())
            .expect("CLI fixture is UTF-8")
            .replacen(
                "  \"root_enum\":",
                "  \"future_metadata\": {},\n  \"root_enum\":",
                1,
            );

        let error = project_pinned_job_surface(protocol, relay, cli.as_bytes())
            .expect_err("an unknown top-level field changes the reviewed document");

        assert!(
            error
                .to_string()
                .contains("cli native lift document mismatch")
        );
    }

    #[test]
    fn unknown_nested_coverage_fields_are_rejected_before_parsing() {
        let (protocol, relay, cli) = pinned_documents();
        let cli = String::from_utf8(cli.to_vec())
            .expect("CLI fixture is UTF-8")
            .replacen(
                "    \"unresolved\": []\n",
                "    \"unresolved\": [],\n    \"future_failed_artifacts\": [{\"artifact\": \"generated.rs\", \"reason\": \"unreadable\"}]\n",
                1,
            );

        let error = project_pinned_job_surface(protocol, relay, cli.as_bytes())
            .expect_err("an unknown nested field changes the reviewed document");

        assert!(
            error
                .to_string()
                .contains("cli native lift document mismatch")
        );
    }

    #[test]
    fn typed_relay_projection_requires_the_pinned_push_lease_declaration() {
        let (protocol, relay, cli) = pinned_documents();
        let protocol: buzz_protocol_lifter::ProtocolLift =
            serde_json::from_slice(protocol).expect("protocol fixture is valid");
        let mut relay: buzz_relay_lifter::RelayIngestLift =
            serde_json::from_slice(relay).expect("relay fixture is valid");
        let cli: buzz_cli_lifter::CommandTreeLift =
            serde_json::from_slice(cli).expect("CLI fixture is valid");

        relay.push_lease_source.sha256 = "sha256:changed".to_owned();
        let source_error = project_reviewed_job_surface(&protocol, &relay, &cli)
            .expect_err("alternate push source must not project");
        assert!(
            source_error
                .to_string()
                .contains("relay push lease sha256 mismatch")
        );

        relay.push_lease_source.sha256 = super::PUSH_LEASE_SHA256.to_owned();
        relay.push_lease_constant = None;
        let declaration_error = project_reviewed_job_surface(&protocol, &relay, &cli)
            .expect_err("missing push declaration must not project");
        assert!(
            declaration_error
                .to_string()
                .contains("relay push lease constant mismatch")
        );
    }

    #[test]
    fn partial_cli_lifts_cannot_emit_positive_command_relations() {
        let (protocol, relay, cli) = pinned_documents();
        let protocol: buzz_protocol_lifter::ProtocolLift =
            serde_json::from_slice(protocol).expect("protocol fixture is valid");
        let relay: buzz_relay_lifter::RelayIngestLift =
            serde_json::from_slice(relay).expect("relay fixture is valid");
        let mut cli: buzz_cli_lifter::CommandTreeLift =
            serde_json::from_slice(cli).expect("CLI fixture is valid");
        cli.commands[0].path = vec!["job".to_owned()];
        cli.coverage.completeness = buzz_cli_lifter::NativeCompleteness::Partial;

        let surface = project_reviewed_job_surface(&protocol, &relay, &cli)
            .expect("typed reviewed inputs remain projectable in this unit test");

        assert!(surface.program.operations.iter().all(|operation| {
            operation.claims.iter().all(|claim| {
                claim.contract != semantics_software_surface_v1::relation_contract()
                    || serde_json::from_value::<semantics_software_surface_v1::SurfaceRelation>(
                        claim.payload.clone(),
                    )
                    .expect("relation payload is valid")
                    .relation
                        != RelationKind::Exposes
            })
        }));
    }
}
