//! Thin stdin/stdout boundary for the fixture-scoped data-model attester.

use std::io::{self, Read as _};

use gooir_datamodel_conformance::AssessmentRequest;

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: AssessmentRequest = serde_json::from_str(&input)?;
    let assessment = request.assess()?;
    serde_json::to_writer(io::stdout().lock(), &assessment)?;
    println!();
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("tasks.entities conformance refused input: {error}");
        std::process::exit(1);
    }
}
