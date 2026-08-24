use fleetd_control_lifter::{
    API_ARTIFACT, DELIVERY_ARTIFACT, FleetdControlSources, MODEL_ARTIFACT, OPENAPI_ARTIFACT,
    lift_fleetd_control,
};
use fleetd_control_projection::project_blocked_delivery_review;
use openapi_lifter::lift_openapi;
use serde::Serialize;
use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Serialize)]
struct DogfoodReport<T, U, V, W, X> {
    authority: String,
    revision: String,
    data_model: T,
    native_control: fleetd_control_lifter::FleetdControlLift,
    blocked_delivery_review: U,
    interaction_plan: V,
    web_target: W,
    terminal_target: X,
}

fn main() -> Result<(), Box<dyn Error>> {
    let root = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: fleetd-control-check <fleetd-repository>")?;
    let revision = git_output(&root, &["rev-parse", "HEAD"])?;
    require_clean_sources(&root)?;

    let openapi = read(&root, OPENAPI_ARTIFACT)?;
    let api = read(&root, API_ARTIFACT)?;
    let model = read(&root, MODEL_ARTIFACT)?;
    let delivery = read(&root, DELIVERY_ARTIFACT)?;
    let authority = format!("git:{}", root.display());
    let native = lift_fleetd_control(
        FleetdControlSources {
            openapi: &openapi,
            api_rust: &api,
            model_rust: &model,
            delivery_rust: &delivery,
        },
        &authority,
        &revision,
    )?;
    let control = project_blocked_delivery_review(&native);
    let data = lift_openapi(&openapi)?;
    let interaction = fleetd_interaction_plan::derive_blocked_delivery_plan(&data, &control);
    let web = fleetd_surface_lowering::lower_web(&interaction, &native)?;
    let terminal = fleetd_surface_lowering::lower_terminal(&interaction, &native)?;

    let report = DogfoodReport {
        authority,
        revision,
        data_model: data,
        native_control: native,
        blocked_delivery_review: control,
        interaction_plan: interaction,
        web_target: web,
        terminal_target: terminal,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
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
            "Fleetd control sources differ from HEAD; commit or restore them before lifting".into(),
        );
    }
    Ok(())
}
