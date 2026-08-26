//! Versioned semantic contracts for relating software surfaces.
//!
//! The vocabulary is intentionally generic. Product-specific expectations
//! belong in profile packages, while native lifters remain authoritative for
//! the facts they project into these relations.

use gooir_identity::{DialectId, ValueKindId};
use serde::{Deserialize, Serialize};

pub const PACKAGE: &str = "org.gooi.semantics.software_surface";
pub const VERSION: &str = "1.0.0";

/// Exact identity of the vocabulary family governing these value kinds.
pub fn dialect_id() -> DialectId {
    DialectId::new(PACKAGE, VERSION)
}

pub fn relation_contract() -> ValueKindId {
    ValueKindId::in_dialect(dialect_id(), "relation")
}

pub fn requirement_contract() -> ValueKindId {
    ValueKindId::in_dialect(dialect_id(), "requirement")
}

pub fn coverage_witness_contract() -> ValueKindId {
    ValueKindId::in_dialect(dialect_id(), "coverage_witness")
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    Declares,
    Registers,
    Constructs,
    Exposes,
    Accepts,
    Rejects,
    Produces,
    Dispatches,
    Persists,
    Queries,
    Renders,
    Tests,
    Mocks,
    Documents,
    Requires,
}

impl RelationKind {
    pub fn contradicts(self, expected: Self) -> bool {
        matches!(
            (self, expected),
            (Self::Accepts, Self::Rejects) | (Self::Rejects, Self::Accepts)
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    Production,
    Test,
    Mock,
    Documentation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SurfaceRelation {
    pub subject: String,
    pub relation: RelationKind,
    pub object: String,
    pub role: ArtifactRole,
    pub scope_id: String,
}

impl SurfaceRelation {
    pub fn satisfies(&self, requirement: &SurfaceRequirement) -> bool {
        self.subject == requirement.subject
            && self.relation == requirement.relation
            && self.object == requirement.object
            && self.role == requirement.role
            && self.scope_id == requirement.scope_id
    }

    pub fn contradicts(&self, requirement: &SurfaceRequirement) -> bool {
        self.subject == requirement.subject
            && self.relation.contradicts(requirement.relation)
            && self.object == requirement.object
            && self.role == requirement.role
            && self.scope_id == requirement.scope_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SurfaceRequirement {
    pub id: String,
    pub subject: String,
    pub relation: RelationKind,
    pub object: String,
    pub role: ArtifactRole,
    pub scope_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_coverage_mechanisms: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SurfaceProfile {
    pub id: String,
    pub version: String,
    pub requirements: Vec<SurfaceRequirement>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageCompleteness {
    Exhaustive,
    Partial,
    BestEffort,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExtractorId {
    pub package: String,
    pub version: String,
    pub config_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CoverageProblem {
    pub artifact: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CoverageWitness {
    pub build_scope_id: String,
    pub extractor: ExtractorId,
    pub source_roots: Vec<String>,
    pub mechanism: String,
    pub completeness: CoverageCompleteness,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub included_artifacts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_artifacts: Vec<CoverageProblem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed_artifacts: Vec<CoverageProblem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved_expansions: Vec<CoverageProblem>,
}

impl CoverageWitness {
    pub fn supports_absence_for(&self, scope_id: &str, mechanism: &str) -> bool {
        self.build_scope_id == scope_id
            && self.mechanism == mechanism
            && self.completeness == CoverageCompleteness::Exhaustive
            && !self.source_roots.is_empty()
            && !self.included_artifacts.is_empty()
            && self.excluded_artifacts.is_empty()
            && self.failed_artifacts.is_empty()
            && self.unresolved_expansions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactRole, CoverageCompleteness, CoverageProblem, CoverageWitness, ExtractorId,
        RelationKind, SurfaceRelation, SurfaceRequirement, coverage_witness_contract, dialect_id,
        relation_contract, requirement_contract,
    };

    #[test]
    fn value_kinds_share_one_exact_software_surface_dialect() {
        for kind in [
            relation_contract(),
            requirement_contract(),
            coverage_witness_contract(),
        ] {
            assert_eq!(kind.dialect(), dialect_id());
        }
        assert_ne!(relation_contract(), requirement_contract());
    }

    fn production_requirement(relation: RelationKind) -> SurfaceRequirement {
        SurfaceRequirement {
            id: "require-relay-acceptance".to_owned(),
            subject: "buzz-relay:ingest".to_owned(),
            relation,
            object: "nostr-kind:43003".to_owned(),
            role: ArtifactRole::Production,
            scope_id: "buzz:desktop-v0.5.18".to_owned(),
            required_coverage_mechanisms: Vec::new(),
        }
    }

    #[test]
    fn mock_relation_cannot_satisfy_a_production_requirement() {
        let relation = SurfaceRelation {
            subject: "buzz-desktop:e2e-bridge".to_owned(),
            relation: RelationKind::Produces,
            object: "nostr-kind:43003".to_owned(),
            role: ArtifactRole::Mock,
            scope_id: "buzz:desktop-v0.5.18".to_owned(),
        };

        assert!(!relation.satisfies(&production_requirement(RelationKind::Produces)));
    }

    #[test]
    fn explicit_rejection_contradicts_required_acceptance() {
        let relation = SurfaceRelation {
            subject: "buzz-relay:ingest".to_owned(),
            relation: RelationKind::Rejects,
            object: "nostr-kind:43003".to_owned(),
            role: ArtifactRole::Production,
            scope_id: "buzz:desktop-v0.5.18".to_owned(),
        };

        assert!(relation.contradicts(&production_requirement(RelationKind::Accepts)));
    }

    #[test]
    fn only_gap_free_exhaustive_coverage_supports_absence() {
        let mut witness = CoverageWitness {
            build_scope_id: "scope".to_owned(),
            extractor: ExtractorId {
                package: "fixture-lifter".to_owned(),
                version: "1.0.0".to_owned(),
                config_digest: "sha256:fixture".to_owned(),
            },
            source_roots: vec!["src".to_owned()],
            mechanism: "literal-builder".to_owned(),
            completeness: CoverageCompleteness::Exhaustive,
            included_artifacts: vec!["src/lib.rs".to_owned()],
            excluded_artifacts: Vec::new(),
            failed_artifacts: Vec::new(),
            unresolved_expansions: Vec::new(),
        };

        assert!(witness.supports_absence_for("scope", "literal-builder"));

        witness.unresolved_expansions.push(CoverageProblem {
            artifact: "src/lib.rs".to_owned(),
            reason: "macro expansion unavailable".to_owned(),
        });

        assert!(!witness.supports_absence_for("scope", "literal-builder"));

        witness.unresolved_expansions.clear();
        witness.included_artifacts.clear();
        assert!(!witness.supports_absence_for("scope", "literal-builder"));
    }
}
