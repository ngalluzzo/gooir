//! Buzz-specific expectations and a pinned native relation snapshot.
//!
//! This crate owns Buzz vocabulary and product expectations. The generic
//! software-surface contract and future analyzer do not depend on it.

use semantics_software_surface_v1::{
    ArtifactRole, CoverageWitness, RelationKind, SurfaceProfile, SurfaceRelation,
    SurfaceRequirement,
};
use serde::{Deserialize, Serialize};

pub const BUZZ_REVISION: &str = "39f8b46935736334cdd7045a4e4b5d7eb1a33888";
pub const BUZZ_SOURCE_TAG: &str = "desktop-v0.5.18";
pub const SOURCE_SCOPE_ID: &str = "buzz:desktop-v0.5.18:source";
pub const JOB_KINDS: [u32; 6] = [43001, 43002, 43003, 43004, 43005, 43006];

pub fn kind_identity(kind: u32) -> String {
    format!("nostr-kind:{kind}")
}

pub fn job_surface_profile() -> SurfaceProfile {
    let mut requirements = Vec::new();

    for kind in JOB_KINDS {
        let object = kind_identity(kind);
        requirements.push(SurfaceRequirement {
            id: format!("relay-accepts-{kind}"),
            subject: "buzz-relay:client-ingest".to_owned(),
            relation: RelationKind::Accepts,
            object: object.clone(),
            role: ArtifactRole::Production,
            scope_id: SOURCE_SCOPE_ID.to_owned(),
            required_coverage_mechanisms: vec!["relay_ingest_allowlist".to_owned()],
        });
        requirements.push(SurfaceRequirement {
            id: format!("sdk-constructs-{kind}"),
            subject: "buzz-sdk:builders".to_owned(),
            relation: RelationKind::Constructs,
            object,
            role: ArtifactRole::Production,
            scope_id: SOURCE_SCOPE_ID.to_owned(),
            required_coverage_mechanisms: vec!["sdk_builder_inventory".to_owned()],
        });
    }

    requirements.push(SurfaceRequirement {
        id: "cli-exposes-job-protocol".to_owned(),
        subject: "buzz-cli:command-tree".to_owned(),
        relation: RelationKind::Exposes,
        object: "protocol:buzz-agent-job".to_owned(),
        role: ArtifactRole::Production,
        scope_id: SOURCE_SCOPE_ID.to_owned(),
        required_coverage_mechanisms: vec!["cli_command_tree".to_owned()],
    });
    requirements.push(SurfaceRequirement {
        id: "runtime-dispatches-job-request".to_owned(),
        subject: "buzz-agent-runtime:dispatcher".to_owned(),
        relation: RelationKind::Dispatches,
        object: kind_identity(43001),
        role: ArtifactRole::Production,
        scope_id: SOURCE_SCOPE_ID.to_owned(),
        required_coverage_mechanisms: vec!["agent_runtime_dispatch".to_owned()],
    });

    SurfaceProfile {
        id: "org.gooi.profile.buzz.agent_job_surface".to_owned(),
        version: "1.0.0".to_owned(),
        requirements,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotAuthority {
    pub authority: String,
    pub repository: String,
    pub revision: String,
    pub source_tag: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotScope {
    pub id: String,
    pub product_profile: String,
    pub cargo_lock_sha256: String,
    pub rust_toolchain: String,
    pub feature_and_target_selection: String,
    pub source_roots: Vec<String>,
    pub test_roots: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotEvidenceKind {
    Declared,
    StaticInferred,
    RuntimeObserved,
    Mock,
    Documentation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotLocation {
    pub artifact: String,
    pub artifact_sha256: String,
    pub byte_start: u64,
    pub byte_end: u64,
    pub line_start: u32,
    pub line_end: u32,
    pub symbol: Option<String>,
    pub compilation_instance: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotEvidence {
    pub kind: SnapshotEvidenceKind,
    pub locations: Vec<SnapshotLocation>,
    pub note: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnapshotFactGroup {
    pub subject: String,
    pub relations: Vec<RelationKind>,
    pub objects: Vec<String>,
    pub role: ArtifactRole,
    pub evidence: SnapshotEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SurfaceSnapshot {
    pub snapshot_version: String,
    pub authority: SnapshotAuthority,
    pub scope: SnapshotScope,
    pub fact_groups: Vec<SnapshotFactGroup>,
    pub coverage: Vec<CoverageWitness>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotRelationRecord {
    pub semantic: SurfaceRelation,
    pub evidence: SnapshotEvidence,
}

impl SurfaceSnapshot {
    pub fn expanded_relations(&self) -> Vec<SnapshotRelationRecord> {
        let mut relations = Vec::new();
        for group in &self.fact_groups {
            for relation in &group.relations {
                for object in &group.objects {
                    relations.push(SnapshotRelationRecord {
                        semantic: SurfaceRelation {
                            subject: group.subject.clone(),
                            relation: *relation,
                            object: object.clone(),
                            role: group.role,
                            scope_id: self.scope.id.clone(),
                        },
                        evidence: group.evidence.clone(),
                    });
                }
            }
        }
        relations
    }
}

pub fn pinned_job_surface_snapshot() -> Result<SurfaceSnapshot, serde_json::Error> {
    serde_json::from_str(include_str!(
        "../../../fixtures/buzz/desktop-v0.5.18/job-surface.json"
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use semantics_software_surface_v1::{ArtifactRole, RelationKind};

    use super::{
        BUZZ_REVISION, JOB_KINDS, SOURCE_SCOPE_ID, SnapshotEvidenceKind, job_surface_profile,
        kind_identity, pinned_job_surface_snapshot,
    };

    #[test]
    fn pinned_snapshot_preserves_the_exact_source_authority() {
        let snapshot = pinned_job_surface_snapshot().expect("fixture is valid");

        assert_eq!(snapshot.authority.revision, BUZZ_REVISION);
        assert_eq!(snapshot.scope.id, SOURCE_SCOPE_ID);
        assert_eq!(snapshot.scope.feature_and_target_selection, "unresolved");
    }

    #[test]
    fn snapshot_expands_the_expected_positive_and_rejection_relations() {
        let snapshot = pinned_job_surface_snapshot().expect("fixture is valid");
        let relations = snapshot.expanded_relations();

        let rejected = relations
            .iter()
            .filter(|record| {
                record.semantic.subject == "buzz-relay:client-ingest"
                    && record.semantic.relation == RelationKind::Rejects
                    && record.semantic.role == ArtifactRole::Production
            })
            .map(|record| record.semantic.object.clone())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            rejected,
            JOB_KINDS
                .into_iter()
                .map(kind_identity)
                .collect::<BTreeSet<_>>()
        );

        let database_queries = relations
            .iter()
            .filter(|record| {
                record.semantic.subject == "buzz-db:activity-feed"
                    && record.semantic.relation == RelationKind::Queries
            })
            .map(|record| record.semantic.object.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            database_queries,
            [43001, 43003, 43004]
                .into_iter()
                .map(kind_identity)
                .collect::<BTreeSet<_>>()
        );

        let rejection = relations
            .iter()
            .find(|record| record.semantic.relation == RelationKind::Rejects)
            .expect("fixture includes the relay rejection");
        assert_eq!(
            rejection.evidence.kind,
            SnapshotEvidenceKind::StaticInferred
        );
        assert_eq!(
            rejection.evidence.locations[0].artifact_sha256,
            "sha256:6f5ecbac1056c64ce161e72bc9d4b0fabc2c8d8648fb41b3812a655121f194a5"
        );
    }

    #[test]
    fn mock_producer_does_not_satisfy_a_production_requirement() {
        let snapshot = pinned_job_surface_snapshot().expect("fixture is valid");
        let relations = snapshot.expanded_relations();
        let mock = relations
            .iter()
            .find(|record| record.semantic.relation == RelationKind::Mocks)
            .expect("fixture includes the desktop mock");
        let requirement = semantics_software_surface_v1::SurfaceRequirement {
            id: "production-progress-producer".to_owned(),
            subject: mock.semantic.subject.clone(),
            relation: RelationKind::Produces,
            object: kind_identity(43003),
            role: ArtifactRole::Production,
            scope_id: SOURCE_SCOPE_ID.to_owned(),
            required_coverage_mechanisms: Vec::new(),
        };

        assert!(!mock.semantic.satisfies(&requirement));
    }

    #[test]
    fn profile_requires_every_job_kind_at_the_relay_and_sdk_boundaries() {
        let profile = job_surface_profile();

        assert_eq!(profile.requirements.len(), 14);
        for kind in JOB_KINDS {
            let identity = kind_identity(kind);
            assert!(profile.requirements.iter().any(|requirement| {
                requirement.subject == "buzz-relay:client-ingest"
                    && requirement.relation == RelationKind::Accepts
                    && requirement.object == identity
            }));
            assert!(profile.requirements.iter().any(|requirement| {
                requirement.subject == "buzz-sdk:builders"
                    && requirement.relation == RelationKind::Constructs
                    && requirement.object == identity
            }));
        }
    }

    #[test]
    fn only_the_closed_relay_allowlist_supports_absence_in_the_staging_snapshot() {
        let snapshot = pinned_job_surface_snapshot().expect("fixture is valid");

        assert!(snapshot.coverage.iter().any(|witness| {
            witness.supports_absence_for(SOURCE_SCOPE_ID, "relay_ingest_allowlist")
        }));
        assert!(!snapshot.coverage.iter().any(|witness| {
            witness.supports_absence_for(SOURCE_SCOPE_ID, "sdk_builder_inventory")
        }));
    }
}
