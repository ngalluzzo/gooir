use std::{env, fs, process};

use buzz_surface_profile::job_surface_profile;
use buzz_surface_projection::{admit_pinned_surface, project_pinned_job_surface};
use gooir_analysis::SemanticResolver;
use surface_completeness_analysis::SurfaceCompletenessAnalyzer;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let protocol_path = arguments.next().ok_or_else(usage)?;
    let relay_path = arguments.next().ok_or_else(usage)?;
    let cli_path = arguments.next().ok_or_else(usage)?;
    if arguments.next().is_some() {
        return Err(usage());
    }

    let protocol: buzz_protocol_lifter::ProtocolLift = read_json(&protocol_path)?;
    let relay: buzz_relay_lifter::RelayIngestLift = read_json(&relay_path)?;
    let cli: buzz_cli_lifter::CommandTreeLift = read_json(&cli_path)?;
    let surface = project_pinned_job_surface(&protocol, &relay, &cli)
        .map_err(|error| format!("failed to project pinned surface: {error}"))?;
    let policy = admit_pinned_surface(&surface)
        .map_err(|error| format!("failed to admit pinned surface: {error}"))?;
    let report = SurfaceCompletenessAnalyzer::new(SemanticResolver::with_trust_policy(policy))
        .analyze(&surface.program, &job_surface_profile());
    let output = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("failed to serialize analysis: {error}"))?;
    println!("{output}");
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("failed to parse {path}: {error}"))
}

fn usage() -> String {
    "usage: buzz-surface-check <protocol-lift-json> <relay-lift-json> <cli-lift-json>".to_owned()
}
