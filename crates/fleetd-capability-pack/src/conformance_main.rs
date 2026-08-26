use std::{env, error::Error, fs, path::PathBuf};

use fleetd_capability_pack::{
    RunnableWebConformanceProvider, registry, runnable_web_artifact_fact,
};
use gooir_capability::{
    AdmissionPolicy, CapabilityCandidate, CapabilityConformanceProvider, CapabilityRequest,
    DerivationPlan, FactType, verify_and_admit,
};
use serde::Serialize;

#[derive(Serialize)]
struct Report {
    admission: gooir_capability::CapabilityAdmission,
    replanned: DerivationPlan,
    replan_fully_provided: bool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let repository = PathBuf::from(arguments.next().ok_or(
        "usage: fleetd-runnable-web-conformance <fleetd-repository> <request.json> <candidate.json>",
    )?);
    let request_path = PathBuf::from(arguments.next().ok_or("missing request path")?);
    let candidate_path = PathBuf::from(arguments.next().ok_or("missing candidate path")?);
    if arguments.next().is_some() {
        return Err("unexpected extra arguments".into());
    }
    let request: CapabilityRequest = serde_json::from_slice(&fs::read(request_path)?)?;
    let candidate: CapabilityCandidate = serde_json::from_slice(&fs::read(candidate_path)?)?;
    let verifier = RunnableWebConformanceProvider::new(repository);

    // This command *is* the host, so it states which attester it accepts
    // rather than accepting whichever one it was handed. The exact identity,
    // suite, and implementation digest bind together: admitting an identity
    // alone would let a different build inherit the decision.
    let mut policy = AdmissionPolicy::default();
    policy.admit_attester(verifier.descriptor());

    let admission = verify_and_admit(&request, &candidate, &verifier, &policy)?;
    if let Some(reason) = admission.withheld {
        eprintln!("facts withheld: {reason:?}");
    }
    let mut available = request
        .body
        .inputs
        .iter()
        .map(|fact| fact.fact_type.clone())
        .collect::<Vec<FactType>>();
    available.extend(admission.facts.iter().map(|fact| fact.fact_type.clone()));
    let replanned = registry()?.plan(available, &runnable_web_artifact_fact())?;
    let report = Report {
        replan_fully_provided: replanned.has_provider_for_every_step(),
        replanned,
        admission,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
