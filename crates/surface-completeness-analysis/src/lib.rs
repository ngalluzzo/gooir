//! Generic completeness analysis over the software-surface contracts.
//!
//! Product expectations arrive as a profile. Native dialect identity and
//! product-specific source shapes never enter the decision procedure.

use gooir_analysis::{ClaimResolution, EvidenceTrustFailure, SemanticResolver};
use gooir_core::{Operation, Program, SourceRef};
use semantics_software_surface_v1::{
    CoverageWitness, RelationKind, SurfaceProfile, SurfaceRelation, SurfaceRequirement,
    coverage_witness_contract, relation_contract,
};
use serde::{Deserialize, Serialize};

pub const ANALYZER_ID: &str = "org.gooi.analysis.surface_completeness@1.0.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceFindingLevel {
    Error,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelationBasis {
    pub operation_id: String,
    pub relation: SurfaceRelation,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CoverageBasis {
    pub operation_id: String,
    pub witness: CoverageWitness,
    pub source: SourceRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SurfaceFinding {
    pub code: String,
    pub level: SurfaceFindingLevel,
    pub requirement_id: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relation_basis: Vec<RelationBasis>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage_basis: Vec<CoverageBasis>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SurfaceAnalysisReport {
    pub analyzer: String,
    pub profile: String,
    pub profile_version: String,
    pub findings: Vec<SurfaceFinding>,
}

impl SurfaceAnalysisReport {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

pub struct SurfaceCompletenessAnalyzer {
    resolver: SemanticResolver,
}

impl SurfaceCompletenessAnalyzer {
    pub fn new(resolver: SemanticResolver) -> Self {
        Self { resolver }
    }

    pub fn analyze(&self, program: &Program, profile: &SurfaceProfile) -> SurfaceAnalysisReport {
        let facts = ResolvedFacts::from_program(&self.resolver, program);
        let findings = profile
            .requirements
            .iter()
            .filter_map(|requirement| analyze_requirement(requirement, &facts))
            .collect();

        SurfaceAnalysisReport {
            analyzer: ANALYZER_ID.to_owned(),
            profile: profile.id.clone(),
            profile_version: profile.version.clone(),
            findings,
        }
    }
}

#[derive(Default)]
struct ResolvedFacts {
    relations: Vec<RelationBasis>,
    coverage: Vec<CoverageBasis>,
    untrusted_relations: Vec<UntrustedRelation>,
    untrusted_coverage: Vec<UntrustedCoverage>,
    invalid_claims: Vec<InvalidClaim>,
}

struct InvalidClaim {
    operation_id: String,
    reason: String,
}

struct UntrustedRelation {
    relation: SurfaceRelation,
    source: SourceRef,
    reason: EvidenceTrustFailure,
}

struct UntrustedCoverage {
    witness: CoverageWitness,
    source: SourceRef,
    reason: EvidenceTrustFailure,
}

impl ResolvedFacts {
    fn from_program(resolver: &SemanticResolver, program: &Program) -> Self {
        let mut facts = Self::default();
        for operation in &program.operations {
            collect_operation_facts(resolver, operation, &mut facts);
        }
        facts
    }
}

fn collect_operation_facts(
    resolver: &SemanticResolver,
    operation: &Operation,
    facts: &mut ResolvedFacts,
) {
    match resolver.resolve(operation, &relation_contract()) {
        ClaimResolution::Trusted(claim) => match serde_json::from_value(claim.payload) {
            Ok(relation) => facts.relations.push(RelationBasis {
                operation_id: operation.id.clone(),
                relation,
                source: claim.evidence.source,
            }),
            Err(error) => facts.invalid_claims.push(InvalidClaim {
                operation_id: operation.id.clone(),
                reason: format!("invalid trusted relation payload: {error}"),
            }),
        },
        ClaimResolution::Untrusted { claim, reason } => {
            match serde_json::from_value(claim.payload) {
                Ok(relation) => facts.untrusted_relations.push(UntrustedRelation {
                    relation,
                    source: claim.evidence.source,
                    reason,
                }),
                Err(error) => facts.invalid_claims.push(InvalidClaim {
                    operation_id: operation.id.clone(),
                    reason: format!("invalid untrusted relation payload: {error}"),
                }),
            }
        }
        resolution if operation_has_contract(operation, &relation_contract()) => {
            facts.invalid_claims.push(InvalidClaim {
                operation_id: operation.id.clone(),
                reason: format!("relation claim did not resolve: {resolution:?}"),
            });
        }
        _ => {}
    }

    match resolver.resolve(operation, &coverage_witness_contract()) {
        ClaimResolution::Trusted(claim) => match serde_json::from_value(claim.payload) {
            Ok(witness) => facts.coverage.push(CoverageBasis {
                operation_id: operation.id.clone(),
                witness,
                source: claim.evidence.source,
            }),
            Err(error) => facts.invalid_claims.push(InvalidClaim {
                operation_id: operation.id.clone(),
                reason: format!("invalid trusted coverage payload: {error}"),
            }),
        },
        ClaimResolution::Untrusted { claim, reason } => {
            match serde_json::from_value(claim.payload) {
                Ok(witness) => facts.untrusted_coverage.push(UntrustedCoverage {
                    witness,
                    source: claim.evidence.source,
                    reason,
                }),
                Err(error) => facts.invalid_claims.push(InvalidClaim {
                    operation_id: operation.id.clone(),
                    reason: format!("invalid untrusted coverage payload: {error}"),
                }),
            }
        }
        resolution if operation_has_contract(operation, &coverage_witness_contract()) => {
            facts.invalid_claims.push(InvalidClaim {
                operation_id: operation.id.clone(),
                reason: format!("coverage claim did not resolve: {resolution:?}"),
            });
        }
        _ => {}
    }

    for region in &operation.regions {
        for child in region {
            collect_operation_facts(resolver, child, facts);
        }
    }
}

fn operation_has_contract(operation: &Operation, contract: &gooir_core::ContractId) -> bool {
    operation
        .claims
        .iter()
        .any(|claim| claim.contract == *contract)
}

fn analyze_requirement(
    requirement: &SurfaceRequirement,
    facts: &ResolvedFacts,
) -> Option<SurfaceFinding> {
    if !facts.invalid_claims.is_empty() {
        return Some(SurfaceFinding {
            code: "surface.invalid_input".to_owned(),
            level: SurfaceFindingLevel::Unknown,
            requirement_id: requirement.id.clone(),
            message: format!(
                "{} remains unknown because contract inputs are invalid: {}",
                describe_requirement(requirement),
                facts
                    .invalid_claims
                    .iter()
                    .map(|claim| format!("{} ({})", claim.operation_id, claim.reason))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            relation_basis: Vec::new(),
            coverage_basis: Vec::new(),
        });
    }
    let matches = facts
        .relations
        .iter()
        .filter(|basis| basis.relation.satisfies(requirement))
        .cloned()
        .collect::<Vec<_>>();
    let contradictions = facts
        .relations
        .iter()
        .filter(|basis| basis.relation.contradicts(requirement))
        .cloned()
        .collect::<Vec<_>>();
    let untrusted = facts
        .untrusted_relations
        .iter()
        .filter(|basis| {
            basis.relation.satisfies(requirement) || basis.relation.contradicts(requirement)
        })
        .collect::<Vec<_>>();

    if !untrusted.is_empty() {
        return Some(SurfaceFinding {
            code: "surface.untrusted_relation".to_owned(),
            level: SurfaceFindingLevel::Unknown,
            requirement_id: requirement.id.clone(),
            message: format!(
                "{} remains unknown: {} relevant transported claim(s) were not admitted ({})",
                describe_requirement(requirement),
                untrusted.len(),
                untrusted
                    .iter()
                    .map(|basis| format!(
                        "{}:{} ({:?})",
                        basis.source.artifact,
                        basis.source.span.as_deref().unwrap_or("unscoped"),
                        basis.reason
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            relation_basis: Vec::new(),
            coverage_basis: Vec::new(),
        });
    }

    if !matches.is_empty() && !contradictions.is_empty() {
        let mut relation_basis = matches;
        relation_basis.extend(contradictions);
        return Some(SurfaceFinding {
            code: "surface.conflicting_relations".to_owned(),
            level: SurfaceFindingLevel::Unknown,
            requirement_id: requirement.id.clone(),
            message: format!(
                "{} remains unknown: admitted claims both establish and contradict the required relation",
                describe_requirement(requirement)
            ),
            relation_basis,
            coverage_basis: Vec::new(),
        });
    }

    if !matches.is_empty() {
        return None;
    }

    if !contradictions.is_empty() {
        let mut relation_basis = contradictions;
        relation_basis.extend(declaration_basis(requirement, facts));
        return Some(SurfaceFinding {
            code: "surface.contradicted".to_owned(),
            level: SurfaceFindingLevel::Error,
            requirement_id: requirement.id.clone(),
            message: format!(
                "{} is contradicted by an admitted opposite relation in exact scope {}",
                describe_requirement(requirement),
                requirement.scope_id
            ),
            relation_basis,
            coverage_basis: Vec::new(),
        });
    }

    if requirement.required_coverage_mechanisms.is_empty() {
        return Some(SurfaceFinding {
            code: "surface.coverage_incomplete".to_owned(),
            level: SurfaceFindingLevel::Unknown,
            requirement_id: requirement.id.clone(),
            message: format!(
                "{} remains unknown in exact scope {}: the profile names no exhaustive coverage mechanism for absence",
                describe_requirement(requirement),
                requirement.scope_id
            ),
            relation_basis: declaration_basis(requirement, facts),
            coverage_basis: Vec::new(),
        });
    }

    let mut coverage_basis = Vec::new();
    let mut missing_mechanisms = Vec::new();
    let mut untrusted_mechanisms = Vec::new();
    for mechanism in &requirement.required_coverage_mechanisms {
        let candidates = facts
            .coverage
            .iter()
            .filter(|basis| {
                basis.witness.build_scope_id == requirement.scope_id
                    && basis.witness.mechanism == *mechanism
            })
            .cloned()
            .collect::<Vec<_>>();
        if let Some(supporting) = candidates
            .iter()
            .find(|basis| {
                basis
                    .witness
                    .supports_absence_for(&requirement.scope_id, mechanism)
            })
            .cloned()
        {
            coverage_basis.push(supporting);
            continue;
        }
        coverage_basis.extend(candidates);
        if facts.untrusted_coverage.iter().any(|basis| {
            basis.witness.build_scope_id == requirement.scope_id
                && basis.witness.mechanism == *mechanism
        }) {
            untrusted_mechanisms.push(mechanism.clone());
        } else {
            missing_mechanisms.push(mechanism.clone());
        }
    }

    if missing_mechanisms.is_empty() && untrusted_mechanisms.is_empty() {
        let roots = coverage_basis
            .iter()
            .flat_map(|basis| basis.witness.source_roots.iter().cloned())
            .collect::<Vec<_>>();
        let artifacts = coverage_basis
            .iter()
            .flat_map(|basis| basis.witness.included_artifacts.iter().cloned())
            .collect::<Vec<_>>();
        return Some(SurfaceFinding {
            code: "surface.missing_relation".to_owned(),
            level: SurfaceFindingLevel::Error,
            requirement_id: requirement.id.clone(),
            message: format!(
                "{} was not found in exact scope {}; exhaustive roots [{}], included artifacts [{}]",
                describe_requirement(requirement),
                requirement.scope_id,
                roots.join(", "),
                artifacts.join(", ")
            ),
            relation_basis: declaration_basis(requirement, facts),
            coverage_basis,
        });
    }

    let partial = coverage_basis
        .iter()
        .map(|basis| {
            format!(
                "{} via {}@{} is {:?}",
                basis.witness.mechanism,
                basis.witness.extractor.package,
                basis.witness.extractor.version,
                basis.witness.completeness
            )
        })
        .collect::<Vec<_>>();
    let untrusted_details = facts
        .untrusted_coverage
        .iter()
        .filter(|basis| {
            untrusted_mechanisms
                .iter()
                .any(|mechanism| mechanism == &basis.witness.mechanism)
        })
        .map(|basis| {
            format!(
                "{} at {} ({:?})",
                basis.witness.mechanism, basis.source.artifact, basis.reason
            )
        })
        .collect::<Vec<_>>();
    Some(SurfaceFinding {
        code: "surface.coverage_incomplete".to_owned(),
        level: SurfaceFindingLevel::Unknown,
        requirement_id: requirement.id.clone(),
        message: format!(
            "{} remains unknown in exact scope {}: missing exhaustive mechanisms [{}]; untrusted mechanisms [{}]; observed partial coverage [{}]; untrusted evidence [{}]",
            describe_requirement(requirement),
            requirement.scope_id,
            missing_mechanisms.join(", "),
            untrusted_mechanisms.join(", "),
            partial.join(", "),
            untrusted_details.join(", ")
        ),
        relation_basis: declaration_basis(requirement, facts),
        coverage_basis,
    })
}

fn declaration_basis(
    requirement: &SurfaceRequirement,
    facts: &ResolvedFacts,
) -> Vec<RelationBasis> {
    facts
        .relations
        .iter()
        .filter(|basis| {
            basis.relation.object == requirement.object
                && basis.relation.relation == RelationKind::Declares
                && basis.relation.scope_id == requirement.scope_id
        })
        .cloned()
        .collect()
}

fn describe_requirement(requirement: &SurfaceRequirement) -> String {
    format!(
        "requirement {} ({:?} {:?} {} -> {})",
        requirement.id,
        requirement.role,
        requirement.relation,
        requirement.subject,
        requirement.object
    )
}

#[cfg(test)]
mod tests {
    use gooir_analysis::{EvidenceTrustPolicy, SemanticResolver};
    use gooir_core::{Claim, ConformanceEvidence, Evidence, Operation, Program, SourceRef};
    use semantics_software_surface_v1::{
        ArtifactRole, CoverageCompleteness, CoverageWitness, ExtractorId, RelationKind,
        SurfaceProfile, SurfaceRelation, SurfaceRequirement, coverage_witness_contract,
        relation_contract,
    };

    use super::{SurfaceCompletenessAnalyzer, SurfaceFindingLevel};

    fn claim_operation<T: serde::Serialize>(
        id: &str,
        contract: gooir_core::ContractId,
        payload: &T,
    ) -> Operation {
        let source = SourceRef::new("fixture", format!("{id}.json"), "revision");
        let claim = Claim::new(
            contract,
            serde_json::to_value(payload).expect("fixture serializes"),
            Evidence::verified(
                source,
                ConformanceEvidence::new(
                    "fixture-host",
                    "fixture-suite@1",
                    "sha256:subject",
                    format!("sha256:{id}"),
                ),
            ),
        );
        Operation::new(id, "unfamiliar.native", "fact").with_claim(claim)
    }

    fn requirement() -> SurfaceRequirement {
        SurfaceRequirement {
            id: "required-edge".to_owned(),
            subject: "producer".to_owned(),
            relation: RelationKind::Produces,
            object: "event:1".to_owned(),
            role: ArtifactRole::Production,
            scope_id: "scope".to_owned(),
            required_coverage_mechanisms: vec!["producer_inventory".to_owned()],
        }
    }

    fn analyze(program: &Program, admit: bool) -> super::SurfaceAnalysisReport {
        let mut policy = EvidenceTrustPolicy::default();
        if admit {
            for operation in &program.operations {
                for claim in &operation.claims {
                    policy
                        .admit_claim(operation, claim)
                        .expect("fixture claim can be admitted");
                }
            }
        }
        SurfaceCompletenessAnalyzer::new(SemanticResolver::with_trust_policy(policy)).analyze(
            program,
            &SurfaceProfile {
                id: "profile".to_owned(),
                version: "1".to_owned(),
                requirements: vec![requirement()],
            },
        )
    }

    #[test]
    fn exhaustive_trusted_coverage_turns_absence_into_a_scoped_error() {
        let witness = CoverageWitness {
            build_scope_id: "scope".to_owned(),
            extractor: ExtractorId {
                package: "inventory".to_owned(),
                version: "1".to_owned(),
                config_digest: "sha256:config".to_owned(),
            },
            source_roots: vec!["src".to_owned()],
            mechanism: "producer_inventory".to_owned(),
            completeness: CoverageCompleteness::Exhaustive,
            included_artifacts: vec!["src/lib.rs".to_owned()],
            excluded_artifacts: Vec::new(),
            failed_artifacts: Vec::new(),
            unresolved_expansions: Vec::new(),
        };
        let program = Program::new(vec![claim_operation(
            "coverage",
            coverage_witness_contract(),
            &witness,
        )]);

        let report = analyze(&program, true);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].code, "surface.missing_relation");
        assert_eq!(report.findings[0].level, SurfaceFindingLevel::Error);
        assert!(report.findings[0].message.contains("exact scope scope"));
        assert!(report.findings[0].message.contains("src/lib.rs"));
    }

    #[test]
    fn unadmitted_coverage_cannot_prove_a_negative() {
        let witness = CoverageWitness {
            build_scope_id: "scope".to_owned(),
            extractor: ExtractorId {
                package: "inventory".to_owned(),
                version: "1".to_owned(),
                config_digest: "sha256:config".to_owned(),
            },
            source_roots: vec!["src".to_owned()],
            mechanism: "producer_inventory".to_owned(),
            completeness: CoverageCompleteness::Exhaustive,
            included_artifacts: vec!["src/lib.rs".to_owned()],
            excluded_artifacts: Vec::new(),
            failed_artifacts: Vec::new(),
            unresolved_expansions: Vec::new(),
        };
        let program = Program::new(vec![claim_operation(
            "coverage",
            coverage_witness_contract(),
            &witness,
        )]);

        let report = analyze(&program, false);

        assert_eq!(report.findings[0].code, "surface.coverage_incomplete");
        assert_eq!(report.findings[0].level, SurfaceFindingLevel::Unknown);
    }

    #[test]
    fn opposite_trusted_relation_is_an_explicit_contradiction() {
        let relation = SurfaceRelation {
            subject: "producer".to_owned(),
            relation: RelationKind::Rejects,
            object: "event:1".to_owned(),
            role: ArtifactRole::Production,
            scope_id: "scope".to_owned(),
        };
        let mut expected = requirement();
        expected.relation = RelationKind::Accepts;
        let program = Program::new(vec![claim_operation(
            "relation",
            relation_contract(),
            &relation,
        )]);
        let mut policy = EvidenceTrustPolicy::default();
        policy
            .admit_claim(&program.operations[0], &program.operations[0].claims[0])
            .expect("fixture claim can be admitted");
        let report = SurfaceCompletenessAnalyzer::new(SemanticResolver::with_trust_policy(policy))
            .analyze(
                &program,
                &SurfaceProfile {
                    id: "profile".to_owned(),
                    version: "1".to_owned(),
                    requirements: vec![expected],
                },
            );

        assert_eq!(report.findings[0].code, "surface.contradicted");
        assert_eq!(report.findings[0].level, SurfaceFindingLevel::Error);
    }

    #[test]
    fn malformed_trusted_claim_cannot_be_reinterpreted_as_absence() {
        let malformed = claim_operation(
            "malformed",
            relation_contract(),
            &serde_json::json!({"unexpected": true}),
        );
        let witness = CoverageWitness {
            build_scope_id: "scope".to_owned(),
            extractor: ExtractorId {
                package: "inventory".to_owned(),
                version: "1".to_owned(),
                config_digest: "sha256:config".to_owned(),
            },
            source_roots: vec!["src".to_owned()],
            mechanism: "producer_inventory".to_owned(),
            completeness: CoverageCompleteness::Exhaustive,
            included_artifacts: vec!["src/lib.rs".to_owned()],
            excluded_artifacts: Vec::new(),
            failed_artifacts: Vec::new(),
            unresolved_expansions: Vec::new(),
        };
        let coverage = claim_operation("coverage", coverage_witness_contract(), &witness);
        let program = Program::new(vec![malformed, coverage]);
        let mut policy = EvidenceTrustPolicy::default();
        for operation in &program.operations {
            policy
                .admit_claim(operation, &operation.claims[0])
                .expect("fixture claim can be admitted");
        }
        let report = SurfaceCompletenessAnalyzer::new(SemanticResolver::with_trust_policy(policy))
            .analyze(
                &program,
                &SurfaceProfile {
                    id: "profile".to_owned(),
                    version: "1".to_owned(),
                    requirements: vec![requirement()],
                },
            );

        assert_eq!(report.findings[0].code, "surface.invalid_input");
        assert_eq!(report.findings[0].level, SurfaceFindingLevel::Unknown);
    }

    #[test]
    fn equivalent_contract_graphs_ignore_native_dialect_identity() {
        let relation = SurfaceRelation {
            subject: "producer".to_owned(),
            relation: RelationKind::Produces,
            object: "event:1".to_owned(),
            role: ArtifactRole::Production,
            scope_id: "scope".to_owned(),
        };
        let canonical = Program::new(vec![claim_operation(
            "relation",
            relation_contract(),
            &relation,
        )]);
        let mut unfamiliar = canonical.clone();
        unfamiliar.operations[0].dialect = "vendor.unfamiliar".to_owned();
        unfamiliar.operations[0].name = "opaque_fact".to_owned();
        unfamiliar.operations[0]
            .attributes
            .insert("opaque".to_owned(), serde_json::json!([1, 2, 3]));

        assert_eq!(analyze(&canonical, true), analyze(&unfamiliar, true));
        assert!(analyze(&canonical, true).is_clean());
    }
}
