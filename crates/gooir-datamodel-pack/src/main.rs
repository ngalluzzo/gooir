//! Plans and executes derivations from one hand-written `.entities` file.
//!
//! The point is that authoring is no longer a separate command with its own
//! pipeline: it is a source fact, and everything downstream of the data model
//! becomes reachable by planning rather than by wiring.

use std::{fs, path::PathBuf};

use gooir_capability::{CapabilityRegistry, DerivationPlan, FactInstance, FactType};
use gooir_datamodel_pack::{
    OpenApiArtifact, SqlArtifact, authored_entity_spec_fact, authored_fact, data_model_fact,
    openapi_surface_fact, postgres_ddl_fact, register, typescript_types_fact,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let path: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: gooir-datamodel-check <file.entities>")?;
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;

    let mut registry = CapabilityRegistry::default();
    register(&mut registry).map_err(|e| e.to_string())?;

    let source = authored_fact(path.display().to_string(), &text).map_err(|e| e.to_string())?;

    println!("authored source");
    println!("  {}", source.id);
    println!("  {} bytes of {}", text.len(), path.display());
    println!(
        "\nregistry: {} capability(ies), {} provider(s)",
        registry.specs().count(),
        registry.provider_descriptors().len()
    );

    for target in [
        data_model_fact(),
        postgres_ddl_fact(),
        openapi_surface_fact(),
        typescript_types_fact(),
    ] {
        report(&registry, &source, &target)?;
    }
    Ok(())
}

fn report(
    registry: &CapabilityRegistry,
    source: &FactInstance,
    target: &FactType,
) -> Result<(), String> {
    println!("\n== target {target}");
    let plan: DerivationPlan = registry
        .plan([authored_entity_spec_fact()], target)
        .map_err(|e| e.to_string())?;
    let route: Vec<String> = plan
        .steps
        .iter()
        .map(|s| {
            format!(
                "{}{}",
                s.capability.name,
                if s.provider.is_some() {
                    ""
                } else {
                    " (no provider)"
                }
            )
        })
        .collect();
    println!("   route      {}", route.join(" -> "));

    if !plan.is_executable() {
        for need in &plan.needs {
            println!("   NEED       {}", need.capability);
            for r in &need.requires {
                println!("     requires {} ({:?})", r.fact, r.acceptance);
            }
            for p in &need.produces {
                println!("     produces {p}");
            }
            println!("     suite    {}", need.conformance_suite);
            println!("     reason   {}", need.reason);
        }
        println!("   -> assignable as a work contract; nothing is silently missing");
        return Ok(());
    }

    let report = registry
        .execute(&plan, vec![source.clone()])
        .map_err(|e| e.to_string())?;
    let produced = &report.target;
    println!("   produced   {}", produced.id);
    println!("   coverage   {:?}", produced.coverage);
    println!("   facts      {} in the chain", report.facts.len());

    if produced.fact_type == postgres_ddl_fact() {
        let artifact: SqlArtifact =
            serde_json::from_value(produced.payload.clone()).map_err(|e| e.to_string())?;
        let tables = artifact.ddl.matches("CREATE TABLE").count();
        let types = artifact.ddl.matches("CREATE TYPE").count();
        let keys = artifact.ddl.matches("FOREIGN KEY").count();
        println!(
            "   artifact   {} bytes: {tables} table(s), {types} enum type(s), {keys} foreign key(s)",
            artifact.ddl.len()
        );
    }
    if produced.fact_type == openapi_surface_fact() {
        let artifact: OpenApiArtifact =
            serde_json::from_value(produced.payload.clone()).map_err(|e| e.to_string())?;
        let paths = artifact.document["paths"]
            .as_object()
            .map(|p| p.len())
            .unwrap_or(0);
        let schemas = artifact.document["components"]["schemas"]
            .as_object()
            .map(|s| s.len())
            .unwrap_or(0);
        println!("   artifact   {paths} path(s), {schemas} schema(s)");
    }
    Ok(())
}
