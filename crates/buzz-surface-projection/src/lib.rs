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
pub const CLI_ARTIFACT: &str = "crates/buzz-cli/src/lib.rs";
pub const KIND_SHA256: &str =
    "sha256:74533cfc1ac016dcb1a83279c2b06f93807f29489604cdccefc46b645acfce97";
pub const RELAY_SHA256: &str =
    "sha256:6f5ecbac1056c64ce161e72bc9d4b0fabc2c8d8648fb41b3812a655121f194a5";
pub const CLI_SHA256: &str =
    "sha256:a4a6829515e23851822ce5b1c3e7b341c32e2997b17b3b4f74f8aad994ab6310";
pub const PROTOCOL_LIFT_SHA256: &str =
    "sha256:fa8a3756180d8b09d5309772b8a0cdaf481999a186d81cc0f6d403b99365bb91";
pub const RELAY_LIFT_SHA256: &str =
    "sha256:511fc2b6a14487a29433caa6bce70141b8fbd29ad208f4a2d93dae42d478b784";
pub const CLI_LIFT_SHA256: &str =
    "sha256:2e2c208b427bcc8a9a50aaba8932c4ef84b779cde4735266b393a5238fa52ad7";

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
    NativeResultMismatch {
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
            Self::NativeResultMismatch {
                component,
                expected,
                actual,
            } => write!(
                formatter,
                "{component} native lift mismatch: expected {expected}, got {actual}"
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

/// Projects exact pinned native lifts without implicitly trusting them.
pub fn project_pinned_job_surface(
    protocol: &ProtocolLift,
    relay: &RelayIngestLift,
    cli: &CommandTreeLift,
) -> Result<PinnedSurface, ProjectionError> {
    validate_source("protocol", &protocol.source, KIND_ARTIFACT, KIND_SHA256)?;
    validate_source("relay", &relay.source, RELAY_ARTIFACT, RELAY_SHA256)?;
    validate_source("cli", &cli.source, CLI_ARTIFACT, CLI_SHA256)?;
    validate_native_result("protocol", protocol, PROTOCOL_LIFT_SHA256)?;
    validate_native_result("relay", relay, RELAY_LIFT_SHA256)?;
    validate_native_result("cli", cli, CLI_LIFT_SHA256)?;
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
    let protocol: ProtocolLift = serde_json::from_str(include_str!(
        "../../../fixtures/buzz/desktop-v0.5.18/job-protocol.lift.json"
    ))
    .map_err(|error| ProjectionError::Serialization(error.to_string()))?;
    let relay: RelayIngestLift = serde_json::from_str(include_str!(
        "../../../fixtures/buzz/desktop-v0.5.18/job-relay.lift.json"
    ))
    .map_err(|error| ProjectionError::Serialization(error.to_string()))?;
    let cli: CommandTreeLift = serde_json::from_str(include_str!(
        "../../../fixtures/buzz/desktop-v0.5.18/job-cli.lift.json"
    ))
    .map_err(|error| ProjectionError::Serialization(error.to_string()))?;
    project_pinned_job_surface(&protocol, &relay, &cli)
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

fn validate_native_result<T: Serialize>(
    component: &str,
    lift: &T,
    expected: &str,
) -> Result<(), ProjectionError> {
    let bytes = serde_json::to_vec(lift)
        .map_err(|error| ProjectionError::Serialization(error.to_string()))?;
    let actual = sha256(&bytes);
    if actual == expected {
        Ok(())
    } else {
        Err(ProjectionError::NativeResultMismatch {
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
                format!("{}\n{}", relay.source.sha256, relay.protocol_source.sha256).as_bytes(),
            ),
        },
        source_roots: vec!["crates/buzz-relay/src/handlers".to_owned()],
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

    use super::{admit_pinned_surface, project_pinned_job_surface};

    fn pinned_inputs() -> (
        buzz_protocol_lifter::ProtocolLift,
        buzz_relay_lifter::RelayIngestLift,
        buzz_cli_lifter::CommandTreeLift,
    ) {
        (
            serde_json::from_str(include_str!(
                "../../../fixtures/buzz/desktop-v0.5.18/job-protocol.lift.json"
            ))
            .expect("protocol lift fixture is valid"),
            serde_json::from_str(include_str!(
                "../../../fixtures/buzz/desktop-v0.5.18/job-relay.lift.json"
            ))
            .expect("relay lift fixture is valid"),
            serde_json::from_str(include_str!(
                "../../../fixtures/buzz/desktop-v0.5.18/job-cli.lift.json"
            ))
            .expect("CLI lift fixture is valid"),
        )
    }

    #[test]
    fn pinned_native_lifts_project_without_trusting_the_staging_snapshot() {
        let (protocol, relay, cli) = pinned_inputs();
        let surface = project_pinned_job_surface(&protocol, &relay, &cli)
            .expect("pinned native lifts project");

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
        let (protocol, relay, cli) = pinned_inputs();
        let surface = project_pinned_job_surface(&protocol, &relay, &cli)
            .expect("pinned native lifts project");
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
        let (protocol, relay, cli) = pinned_inputs();
        let surface = project_pinned_job_surface(&protocol, &relay, &cli)
            .expect("pinned native lifts project");
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
        let (protocol, relay, cli) = pinned_inputs();
        let mut surface = project_pinned_job_surface(&protocol, &relay, &cli)
            .expect("pinned native lifts project");
        surface.program.operations[0].claims[0].payload["subject"] =
            serde_json::json!("forged-subject");

        let error = admit_pinned_surface(&surface).expect_err("mutation must not retain trust");

        assert!(error.to_string().contains("differs from the projection"));
    }

    #[test]
    fn changing_a_native_result_without_changing_its_source_digest_is_rejected() {
        let (protocol, mut relay, cli) = pinned_inputs();
        relay.job_decisions[0].decision = buzz_relay_lifter::IngestDecisionKind::Accepted;

        let error = project_pinned_job_surface(&protocol, &relay, &cli)
            .expect_err("mutated native result must not project under the pinned policy");

        assert!(error.to_string().contains("relay native lift mismatch"));
    }
}
