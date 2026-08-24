//! Phase 0 invariant: two structurally unlike authorities describing the same
//! system converge on the neutral waist, with every divergence either absent or
//! accounted for by a recorded defeat.
//!
//! This is the falsifier for the waist's design. If a future vocabulary or
//! lifter change makes two real authorities disagree, this fails.

use std::{fs, path::PathBuf};

use data_model_convergence::{Divergence, compare};

const APPS: [&str; 4] = [
    "umami-software_umami",
    "lukevella_rallly",
    "ghostfolio_ghostfolio",
    "documenso_documenso",
];

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("fixtures/datamodel")
}

struct Case {
    app: &'static str,
    left: lift_defeasible::Defeasible<semantics_data_model_v1::DataModel>,
    right: lift_defeasible::Defeasible<semantics_data_model_v1::DataModel>,
    report: data_model_convergence::Report,
}

fn cases() -> Vec<Case> {
    let base = fixtures();
    APPS.iter()
        .map(|app| {
            let p = fs::read_to_string(base.join(format!("prisma/{app}.prisma")))
                .expect("prisma fixture");
            let c = fs::read_to_string(base.join(format!("catalog/{app}.catalog.json")))
                .expect("catalog fixture");
            let left = prisma_schema_lifter::lift_prisma_schema(&p);
            let right = postgres_catalog_lifter::lift_catalog(&c).expect("catalog parses");
            let report = compare(&left.value, &right.value);
            Case {
                app,
                left,
                right,
                report,
            }
        })
        .collect()
}

#[test]
fn every_app_pairs_a_schema_with_a_catalog() {
    let cases = cases();
    assert_eq!(cases.len(), 4);
    for c in &cases {
        assert!(c.left.value.entities.len() >= 19, "{}", c.app);
        assert!(c.right.value.entities.len() >= 19, "{}", c.app);
    }
}

#[test]
fn the_two_authorities_agree_on_which_fields_exist() {
    for c in cases() {
        assert_eq!(
            c.report.field_divergences(),
            0,
            "{}: fields diverged -- the waist's edge-not-field commitment is failing",
            c.app
        );
    }
}

#[test]
fn the_two_authorities_agree_on_every_comparable_field_attribute() {
    let mut compared = 0;
    for c in cases() {
        let diverged: Vec<&Divergence> = c
            .report
            .divergences
            .iter()
            .filter(|d| matches!(d, Divergence::Attribute { .. }))
            .collect();
        assert!(
            diverged.is_empty(),
            "{}: {} attribute divergence(s): {:?}",
            c.app,
            diverged.len(),
            diverged
        );
        compared += c.report.compared_attributes;
    }
    assert!(
        compared > 6_000,
        "expected a substantial comparison surface, got {compared}"
    );
}

#[test]
fn compound_uniqueness_agrees() {
    for c in cases() {
        assert_eq!(c.report.unique_set_divergences(), 0, "{}", c.app);
    }
}

#[test]
fn entity_and_relation_divergence_is_always_accounted_for_by_a_defeat() {
    for c in cases() {
        let unexplained = c.report.entity_divergences() + c.report.relation_divergences();
        if unexplained > 0 {
            let defeats = c.left.defeats.len() + c.right.defeats.len();
            assert!(
                defeats > 0,
                "{}: {} entity/relation divergence(s) with no recorded defeat -- \
                 an unexplained divergence is a silent unsoundness",
                c.app,
                unexplained
            );
        }
    }
}

#[test]
fn every_relation_names_fields_that_exist_on_its_entities() {
    for c in cases() {
        for (label, model) in [("prisma", &c.left.value), ("catalog", &c.right.value)] {
            for rel in &model.relations {
                let from = model
                    .entity(&rel.from_entity)
                    .unwrap_or_else(|| panic!("{}/{label}: missing {}", c.app, rel.from_entity));
                for f in &rel.from_fields {
                    assert!(
                        from.field(f).is_some(),
                        "{}/{label}: relation {} -> {} names field `{f}`, which {} does not have",
                        c.app,
                        rel.from_entity,
                        rel.to_entity,
                        rel.from_entity
                    );
                }
                if let Some(to) = model.entity(&rel.to_entity) {
                    for f in &rel.to_fields {
                        assert!(
                            to.field(f).is_some(),
                            "{}/{label}: relation {} -> {} references field `{f}`, which {} does not have",
                            c.app,
                            rel.from_entity,
                            rel.to_entity,
                            rel.to_entity
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn no_lift_claims_exhaustiveness_without_naming_its_defeater_set() {
    for c in cases() {
        assert!(!c.left.defeater_set.is_empty(), "{}", c.app);
        assert!(!c.right.defeater_set.is_empty(), "{}", c.app);
    }
}
