//! The round-trip law.
//!
//! `lift(lower(lift(X))) == lift(X)`
//!
//! The lowering is not required to reproduce X's text -- the waist is lossier
//! than Prisma on purpose. What must hold is that a model, once in the waist,
//! survives a trip through the target and back unchanged. That is a law reality
//! checks for free, and it is what this project uses instead of hand-authored
//! constraints on its own middle.

use std::{fs, path::PathBuf};

use prisma_schema_lowering::lower_to_prisma;
use semantics_data_model_v1::DataModel;

const APPS: [&str; 4] = [
    "umami-software_umami",
    "lukevella_rallly",
    "ghostfolio_ghostfolio",
    "documenso_documenso",
];

fn fixture(app: &str) -> String {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("fixtures/datamodel/prisma");
    fs::read_to_string(base.join(format!("{app}.prisma"))).expect("prisma fixture")
}

fn sorted(mut m: DataModel) -> DataModel {
    m.entities.sort_by(|a, b| a.name.cmp(&b.name));
    for e in &mut m.entities {
        e.fields.sort_by(|a, b| a.name.cmp(&b.name));
        for s in &mut e.unique_sets {
            s.sort();
        }
        e.unique_sets.sort();
    }
    m.relations.sort_by(|a, b| {
        (&a.from_entity, &a.to_entity, &a.from_fields).cmp(&(
            &b.from_entity,
            &b.to_entity,
            &b.from_fields,
        ))
    });
    m
}

#[test]
fn the_waist_survives_a_trip_through_prisma_and_back() {
    let mut total_fields = 0usize;
    let mut total_relations = 0usize;
    for app in APPS {
        let w1 = prisma_schema_lifter::lift_prisma_schema(&fixture(app)).value;
        let lowered = lower_to_prisma(&w1);
        let w2 = prisma_schema_lifter::lift_prisma_schema(&lowered.source).value;

        // Guard against a vacuous pass: the comparison surface must be real,
        // and the lowered text must genuinely differ from the source.
        assert!(
            w1.entities.len() >= 19,
            "{app}: only {} entities lifted",
            w1.entities.len()
        );
        let fields: usize = w1.entities.iter().map(|e| e.fields.len()).sum();
        assert!(fields >= 100, "{app}: only {fields} fields lifted");
        total_fields += fields;
        total_relations += w1.relations.len();
        assert_ne!(
            lowered.source.trim(),
            fixture(app).trim(),
            "{app}: lowering reproduced its input, so the trip proves nothing"
        );

        let (a, b) = (sorted(w1), sorted(w2));

        let a_names: Vec<&String> = a.entities.iter().map(|e| &e.name).collect();
        let b_names: Vec<&String> = b.entities.iter().map(|e| &e.name).collect();
        assert_eq!(a_names, b_names, "{app}: entity set changed");

        for (ea, eb) in a.entities.iter().zip(&b.entities) {
            let fa: Vec<&String> = ea.fields.iter().map(|f| &f.name).collect();
            let fb: Vec<&String> = eb.fields.iter().map(|f| &f.name).collect();
            assert_eq!(fa, fb, "{app}: fields changed on {}", ea.name);
            for (x, y) in ea.fields.iter().zip(&eb.fields) {
                assert_eq!(x, y, "{app}: field {}.{} changed", ea.name, x.name);
            }
            assert_eq!(
                ea.unique_sets, eb.unique_sets,
                "{app}: unique sets changed on {}",
                ea.name
            );
        }

        assert_eq!(
            a.relations.len(),
            b.relations.len(),
            "{app}: relation count changed"
        );
        for (x, y) in a.relations.iter().zip(&b.relations) {
            assert_eq!(x, y, "{app}: relation changed");
        }
    }
    assert!(
        total_fields > 1_000 && total_relations > 100,
        "the law must hold over a substantial surface, saw {total_fields} fields \
         and {total_relations} relations"
    );
}

#[test]
fn the_lowering_reports_what_the_waist_could_not_supply() {
    // A round trip that holds does not mean the output is faithful to the
    // original source. Anything the waist cannot carry must be declared.
    let w = prisma_schema_lifter::lift_prisma_schema(&fixture("documenso_documenso")).value;
    let lowered = lower_to_prisma(&w);
    assert!(
        !lowered.lossy.is_empty(),
        "a lowering from a lossy waist must declare what it filled in"
    );
}
