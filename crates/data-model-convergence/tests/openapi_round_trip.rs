//! The OpenAPI CRUD surface: a target from a different modelling tradition.
//!
//! JSON documents have no primary keys, no unique constraints and no foreign
//! keys, so this exercises whether the waist is genuinely neutral or quietly
//! relational. What the target cannot carry must come back as `Unknown` -- not
//! as a wrong answer.

use std::{collections::BTreeSet, fs, path::PathBuf};

use data_model_convergence::compare;
use serde_json::Value;

const APPS: [&str; 4] = [
    "umami-software_umami",
    "lukevella_rallly",
    "ghostfolio_ghostfolio",
    "documenso_documenso",
];

fn waist(app: &str) -> semantics_data_model_v1::DataModel {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("fixtures/datamodel/prisma");
    let src = fs::read_to_string(base.join(format!("{app}.prisma"))).expect("prisma fixture");
    prisma_schema_lifter::lift_prisma_schema(&src).value
}

fn collect_refs(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::Object(m) => {
            for (k, val) in m {
                if k == "$ref" {
                    if let Some(s) = val.as_str() {
                        out.insert(s.to_owned());
                    }
                } else {
                    collect_refs(val, out);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_refs(x, out)),
        _ => {}
    }
}

#[test]
fn every_reference_in_the_emitted_document_resolves() {
    for app in APPS {
        let doc = openapi_lowering::lower_to_openapi(&waist(app)).document;
        let schemas = doc["components"]["schemas"]
            .as_object()
            .expect("schemas object");
        let mut refs = BTreeSet::new();
        collect_refs(&doc, &mut refs);
        assert!(!refs.is_empty(), "{app}: document contains no references");
        for r in refs {
            let name = r
                .strip_prefix("#/components/schemas/")
                .unwrap_or_else(|| panic!("{app}: unsupported $ref {r}"));
            assert!(schemas.contains_key(name), "{app}: dangling $ref {r}");
        }
    }
}

#[test]
fn every_required_property_exists_and_operation_ids_are_unique() {
    for app in APPS {
        let doc = openapi_lowering::lower_to_openapi(&waist(app)).document;
        for (name, schema) in doc["components"]["schemas"].as_object().unwrap() {
            let props = schema.get("properties").and_then(Value::as_object);
            for r in schema
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let key = r.as_str().expect("required entry is a string");
                assert!(
                    props.map(|p| p.contains_key(key)).unwrap_or(false),
                    "{app}: {name} requires `{key}`, which is not a property"
                );
            }
        }
        let mut ids = BTreeSet::new();
        for (path, ops) in doc["paths"].as_object().unwrap() {
            for (verb, op) in ops.as_object().unwrap() {
                if verb == "parameters" {
                    continue;
                }
                let id = op["operationId"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{app}: {path} {verb} has no operationId"));
                assert!(
                    ids.insert(id.to_owned()),
                    "{app}: duplicate operationId {id}"
                );
            }
        }
    }
}

#[test]
fn a_create_request_never_requires_a_server_supplied_value() {
    use semantics_data_model_v1::{DefaultOrigin, Presence};
    for app in APPS {
        let w = waist(app);
        let doc = openapi_lowering::lower_to_openapi(&w).document;
        for e in &w.entities {
            let create = &doc["components"]["schemas"][format!("{}Create", e.name)];
            let required: Vec<&str> = create
                .get("required")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            for f in &e.fields {
                let server_supplied = matches!(
                    f.default,
                    DefaultOrigin::Database | DefaultOrigin::Application
                );
                if server_supplied {
                    assert!(
                        !required.contains(&f.name.as_str()),
                        "{app}: {}Create requires server-supplied `{}`",
                        e.name,
                        f.name
                    );
                }
                // A field that is always present when read must be required on read.
                if f.nullable == Presence::Required {
                    let read = &doc["components"]["schemas"][&e.name];
                    let read_required: Vec<&str> = read
                        .get("required")
                        .and_then(Value::as_array)
                        .map(|a| a.iter().filter_map(Value::as_str).collect())
                        .unwrap_or_default();
                    assert!(
                        read_required.contains(&f.name.as_str()),
                        "{app}: {} omits always-present `{}` from required",
                        e.name,
                        f.name
                    );
                }
            }
        }
    }
}

#[test]
fn what_the_target_cannot_express_returns_unknown_not_a_wrong_answer() {
    use semantics_data_model_v1::{DefaultOrigin, Tri};
    for app in APPS {
        let w1 = waist(app);
        let doc = openapi_lowering::lower_to_openapi(&w1).document;
        let w2 = openapi_lifter::lift_document(&doc);

        for e in &w2.value.entities {
            for f in &e.fields {
                assert_eq!(f.identity, Tri::Unknown, "{app}: {}.{}", e.name, f.name);
                assert_eq!(f.unique, Tri::Unknown, "{app}: {}.{}", e.name, f.name);
                assert_eq!(
                    f.default,
                    DefaultOrigin::Unknown,
                    "{app}: {}.{}",
                    e.name,
                    f.name
                );
            }
        }
        assert!(
            w2.value.relations.is_empty(),
            "{app}: a document authority cannot establish relations"
        );
        assert!(!w2.is_exhaustive(), "{app}: losses must be declared");
    }
}

#[test]
fn shapes_and_domains_survive_the_document_round_trip() {
    let mut compared = 0usize;
    for app in APPS {
        let w1 = waist(app);
        let doc = openapi_lowering::lower_to_openapi(&w1).document;
        let w2 = openapi_lifter::lift_document(&doc);
        let r = compare(&w1, &w2.value);

        assert_eq!(w1.entities.len(), w2.value.entities.len(), "{app}");
        assert_eq!(r.field_divergences(), 0, "{app}: field set changed");
        let attr: Vec<_> = r
            .divergences
            .iter()
            .filter(|d| matches!(d, data_model_convergence::Divergence::Attribute { .. }))
            .collect();
        assert!(attr.is_empty(), "{app}: {attr:?}");
        compared += r.compared_attributes;
    }
    assert!(compared > 4_000, "thin comparison surface: {compared}");
}
