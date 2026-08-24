//! Drives the store round trip: waist -> DDL -> a real database -> catalog ->
//! waist. PostgreSQL sits in the middle as an independent implementation, so a
//! symmetric mistake in my own lifter/lowerer pair cannot survive it.

use std::{fs, path::PathBuf};

use data_model_convergence::compare;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("fixtures/datamodel")
}

fn waist_from_prisma(app: &str) -> semantics_data_model_v1::DataModel {
    let src = fs::read_to_string(fixtures().join(format!("prisma/{app}.prisma")))
        .expect("prisma fixture");
    prisma_schema_lifter::lift_prisma_schema(&src).value
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("emit") => {
            let app = args.get(1).ok_or("usage: emit <app>")?;
            let lowered = sql_ddl_lowering::lower_to_postgres_ddl(&waist_from_prisma(app));
            print!("{}", lowered.ddl);
            eprintln!("lossy records: {}", lowered.lossy.len());
            Ok(())
        }
        Some("emit-spec") => {
            let path = args.get(1).ok_or("usage: emit-spec <file.entities>")?;
            let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            let spec = entity_spec::parse_entity_spec(&text);
            for d in &spec.defeats {
                eprintln!("defeat [{:?}] {}: {}", d.kind, d.subject, d.reason);
            }
            let lowered = sql_ddl_lowering::lower_to_postgres_ddl(&spec.value);
            print!("{}", lowered.ddl);
            eprintln!("lossy records: {}", lowered.lossy.len());
            Ok(())
        }
        Some("compare-spec") => {
            let path = args
                .get(1)
                .ok_or("usage: compare-spec <file.entities> <catalog.json>")?;
            let cat = args
                .get(2)
                .ok_or("usage: compare-spec <file.entities> <catalog.json>")?;
            let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            let original = entity_spec::parse_entity_spec(&text).value;
            let json = fs::read_to_string(cat).map_err(|e| format!("{cat}: {e}"))?;
            let returned = postgres_catalog_lifter::lift_catalog(&json)?;
            let r = compare(&original, &returned.value);
            println!(
                "{path:<26} ent {}->{} | field_div={} attr_div={}/{} unique_set_div={} rel {}->{} rel_div={} auth_limited={}",
                original.entities.len(),
                returned.value.entities.len(),
                r.field_divergences(),
                r.attribute_divergences(),
                r.compared_attributes,
                r.unique_set_divergences(),
                original.relations.len(),
                returned.value.relations.len(),
                r.relation_divergences(),
                r.authority_limited
            );
            for d in &r.divergences {
                println!("    {d:?}");
            }
            Ok(())
        }
        Some("compare") => {
            let app = args.get(1).ok_or("usage: compare <app> <catalog.json>")?;
            let path = args.get(2).ok_or("usage: compare <app> <catalog.json>")?;
            let original = waist_from_prisma(app);
            let json = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            let returned = postgres_catalog_lifter::lift_catalog(&json)?;
            let r = compare(&original, &returned.value);
            println!(
                "{app:<30} ent {}->{} | field_div={} attr_div={}/{} unique_set_div={} rel {}->{} rel_div={} auth_limited={}",
                original.entities.len(),
                returned.value.entities.len(),
                r.field_divergences(),
                r.attribute_divergences(),
                r.compared_attributes,
                r.unique_set_divergences(),
                original.relations.len(),
                returned.value.relations.len(),
                r.relation_divergences(),
                r.authority_limited
            );
            for d in &r.divergences {
                println!("    {d:?}");
            }
            Ok(())
        }
        _ => Err("usage: [emit|compare] <app> [catalog.json]".to_owned()),
    }
}
