//! waist -> OpenAPI CRUD surface -> waist, plus structural checks on the
//! emitted document. A non-relational target: what it cannot carry is the point.

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

/// Collects every `$ref` target in the document.
fn refs(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::Object(m) => {
            for (k, val) in m {
                if k == "$ref" {
                    if let Some(s) = val.as_str() {
                        out.insert(s.to_owned());
                    }
                } else {
                    refs(val, out);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| refs(x, out)),
        _ => {}
    }
}

/// Structural invariants that must hold regardless of what the waist contained.
fn structural_problems(doc: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let schemas = doc
        .get("components")
        .and_then(|c| c.get("schemas"))
        .and_then(Value::as_object);

    let mut found = BTreeSet::new();
    refs(doc, &mut found);
    for r in &found {
        let Some(name) = r.strip_prefix("#/components/schemas/") else {
            problems.push(format!("unsupported $ref form: {r}"));
            continue;
        };
        if schemas.map(|s| !s.contains_key(name)).unwrap_or(true) {
            problems.push(format!("dangling $ref: {r}"));
        }
    }

    if let Some(schemas) = schemas {
        for (name, schema) in schemas {
            let props = schema.get("properties").and_then(Value::as_object);
            if let Some(req) = schema.get("required").and_then(Value::as_array) {
                for r in req {
                    let Some(key) = r.as_str() else { continue };
                    if props.map(|p| !p.contains_key(key)).unwrap_or(true) {
                        problems.push(format!("{name}: required `{key}` is not a property"));
                    }
                }
            }
        }
    }

    // Every operation needs a unique operationId.
    let mut ids: BTreeSet<String> = BTreeSet::new();
    if let Some(paths) = doc.get("paths").and_then(Value::as_object) {
        for (p, ops) in paths {
            for (verb, op) in ops.as_object().into_iter().flatten() {
                if verb == "parameters" {
                    continue;
                }
                match op.get("operationId").and_then(Value::as_str) {
                    None => problems.push(format!("{p} {verb}: no operationId")),
                    Some(id) => {
                        if !ids.insert(id.to_owned()) {
                            problems.push(format!("duplicate operationId {id}"));
                        }
                    }
                }
            }
        }
    }
    problems
}

fn main() {
    println!("waist -> OpenAPI CRUD surface -> waist   (a non-relational target)\n");
    for app in APPS {
        let w1 = waist(app);
        let lowered = openapi_lowering::lower_to_openapi(&w1);
        let problems = structural_problems(&lowered.value);
        let w2 = openapi_lifter::lift_document(&lowered.value);
        let r = compare(&w1, &w2.value);

        let ops = lowered
            .value
            .get("paths")
            .and_then(Value::as_object)
            .map(|p| {
                p.values()
                    .filter_map(Value::as_object)
                    .map(|o| o.keys().filter(|k| *k != "parameters").count())
                    .sum::<usize>()
            })
            .unwrap_or(0);
        let schemas = lowered.value["components"]["schemas"]
            .as_object()
            .map(|s| s.len())
            .unwrap_or(0);

        println!("== {app}");
        println!(
            "   emitted    {} schemas, {} operations, {} bytes",
            schemas,
            ops,
            serde_json::to_string(&lowered.value)
                .map(|s| s.len())
                .unwrap_or(0)
        );
        println!(
            "   structure  {}",
            if problems.is_empty() {
                "valid: refs resolve, required present, operationIds unique".to_owned()
            } else {
                format!("{} PROBLEM(S): {:?}", problems.len(), problems)
            }
        );
        println!(
            "   round trip ent {}->{} field_div={} attr_div={}/{} rel {}->{} auth_limited={}",
            w1.entities.len(),
            w2.value.entities.len(),
            r.field_divergences(),
            r.attribute_divergences(),
            r.compared_attributes,
            w1.relations.len(),
            w2.value.relations.len(),
            r.authority_limited
        );
        let mut hist: std::collections::BTreeMap<String, usize> = Default::default();
        for d in &r.divergences {
            if let data_model_convergence::Divergence::Attribute {
                attribute,
                left,
                right,
                ..
            } = d
            {
                *hist
                    .entry(format!("{attribute}: {left} -> {right}"))
                    .or_default() += 1;
            }
        }
        let mut top: Vec<_> = hist.into_iter().collect();
        top.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        for (k, n) in top.iter().take(6) {
            println!("     {n:>4}x {k}");
        }
        println!("   lossy      {} declared", lowered.defeats.len());
        println!();
    }
}
