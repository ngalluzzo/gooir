use fleetd_capability_pack::{
    api_rust_source_fact, delivery_rust_source_fact, model_rust_source_fact, openapi_source_fact,
    registry, runnable_web_artifact_fact, source_fact, terminal_surface, terminal_target_ir_fact,
    web_surface, web_target_ir_fact,
};
use fleetd_control_lifter::{API_ARTIFACT, DELIVERY_ARTIFACT, MODEL_ARTIFACT, OPENAPI_ARTIFACT};
use gooir_capability::{
    CapabilityNeed, CapabilitySpec, DerivationPlan, FactCoverage, FactDerivation, FactInstance,
    FactType, ProviderDescriptor,
};
use serde::Serialize;
use std::{
    env,
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Serialize)]
struct CapabilityDogfoodReport {
    authority: String,
    revision: String,
    capabilities: Vec<CapabilitySpec>,
    providers: Vec<ProviderDescriptor>,
    web_plan: DerivationPlan,
    web_plan_executable: bool,
    terminal_plan: DerivationPlan,
    terminal_plan_executable: bool,
    runnable_web_plan: DerivationPlan,
    runnable_web_plan_executable: bool,
    capability_needs: Vec<CapabilityNeed>,
    web_target: fleetd_surface_lowering::WebSurface,
    terminal_target: fleetd_surface_lowering::TerminalSurface,
    semantic_fingerprints_equal: bool,
    web_derivation: Vec<FactSummary>,
}

#[derive(Serialize)]
struct FactSummary {
    id: String,
    fact_type: FactType,
    coverage: FactCoverage,
    derivation: FactDerivation,
}

fn main() -> Result<(), Box<dyn Error>> {
    let root = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: fleetd-capability-check <fleetd-repository>")?;
    let revision = git_output(&root, &["rev-parse", "HEAD"])?;
    require_clean_sources(&root)?;
    let authority = format!("git:{}", root.display());
    let initial = vec![
        source_fact(
            openapi_source_fact(),
            &authority,
            OPENAPI_ARTIFACT,
            &revision,
            read(&root, OPENAPI_ARTIFACT)?,
        )?,
        source_fact(
            api_rust_source_fact(),
            &authority,
            API_ARTIFACT,
            &revision,
            read(&root, API_ARTIFACT)?,
        )?,
        source_fact(
            model_rust_source_fact(),
            &authority,
            MODEL_ARTIFACT,
            &revision,
            read(&root, MODEL_ARTIFACT)?,
        )?,
        source_fact(
            delivery_rust_source_fact(),
            &authority,
            DELIVERY_ARTIFACT,
            &revision,
            read(&root, DELIVERY_ARTIFACT)?,
        )?,
    ];
    let initial_types = initial
        .iter()
        .map(|fact| fact.fact_type.clone())
        .collect::<Vec<_>>();
    let registry = registry()?;
    let web_plan = registry.plan(initial_types.clone(), &web_target_ir_fact())?;
    let terminal_plan = registry.plan(initial_types.clone(), &terminal_target_ir_fact())?;
    let runnable_web_plan = registry.plan(initial_types, &runnable_web_artifact_fact())?;
    let web_execution = registry.execute(&web_plan, initial.clone())?;
    let terminal_execution = registry.execute(&terminal_plan, initial)?;
    let web = web_surface(&web_execution.target).map_err(io::Error::other)?;
    let terminal = terminal_surface(&terminal_execution.target).map_err(io::Error::other)?;
    let semantic_fingerprints_equal = web.semantic_fingerprint() == terminal.semantic_fingerprint();
    let capability_needs = runnable_web_plan.needs.clone();
    let web_plan_executable = web_plan.is_executable();
    let terminal_plan_executable = terminal_plan.is_executable();
    let runnable_web_plan_executable = runnable_web_plan.is_executable();
    let report = CapabilityDogfoodReport {
        authority,
        revision,
        capabilities: registry.specs().cloned().collect(),
        providers: registry.provider_descriptors(),
        web_plan,
        web_plan_executable,
        terminal_plan,
        terminal_plan_executable,
        runnable_web_plan,
        runnable_web_plan_executable,
        capability_needs,
        web_target: web,
        terminal_target: terminal,
        semantic_fingerprints_equal,
        web_derivation: web_execution
            .facts
            .into_iter()
            .map(FactSummary::from)
            .collect(),
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

impl From<FactInstance> for FactSummary {
    fn from(fact: FactInstance) -> Self {
        Self {
            id: fact.id,
            fact_type: fact.fact_type,
            coverage: fact.coverage,
            derivation: fact.derivation,
        }
    }
}

fn read(root: &Path, artifact: &str) -> Result<String, Box<dyn Error>> {
    Ok(fs::read_to_string(root.join(artifact))?)
}

fn git_output(root: &Path, args: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn require_clean_sources(root: &Path) -> Result<(), Box<dyn Error>> {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["diff", "--quiet", "HEAD", "--"])
        .args([
            OPENAPI_ARTIFACT,
            API_ARTIFACT,
            MODEL_ARTIFACT,
            DELIVERY_ARTIFACT,
        ])
        .status()?;
    if !status.success() {
        return Err(
            "Fleetd capability inputs differ from HEAD; commit or restore them before lifting"
                .into(),
        );
    }
    Ok(())
}
