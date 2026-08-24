//! What the `gooir` Python SDK guarantees, observed from the host's side.
//!
//! These run the real interpreter over the real protocol, because an SDK's
//! promises are only worth what the host actually receives. The promise under
//! test is the one a provider must not be able to break: **coverage is derived
//! from what was lost, never declared.**

use std::path::PathBuf;

use gooir_capability::{
    CapabilityId, CapabilityProvider, CapabilitySpec, FactCoverage, FactInstance, FactType,
    Requirement,
};
use gooir_plugin_process::ProcessProvider;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn source() -> FactType {
    FactType::new("test.fact", "source", "1.0.0")
}
fn produced() -> FactType {
    FactType::new("test.fact", "produced", "1.0.0")
}

fn spec() -> CapabilitySpec {
    CapabilitySpec {
        id: CapabilityId::new("test.capability", "make", "1.0.0"),
        requires: vec![Requirement::complete(source())],
        produces: vec![produced()],
        default_conformance_suite: "test.suite@1.0.0".to_owned(),
    }
}

fn input() -> Vec<FactInstance> {
    vec![
        FactInstance::initial(
            source(),
            FactCoverage::Complete,
            serde_json::json!({"n": 21}),
            "test",
        )
        .expect("initial fact"),
    ]
}

/// The same fact as `input`, but wrapped the way a fact produced by another
/// provider actually arrives.
fn enveloped_input() -> Vec<FactInstance> {
    vec![
        FactInstance::initial(
            source(),
            FactCoverage::Complete,
            serde_json::json!({
                "value": {"n": 21},
                "defeater_set": "upstream.defeaters@1.0.0",
                "defeats": [],
            }),
            "test",
        )
        .expect("initial fact"),
    ]
}

fn run(name: &str) -> Result<Vec<gooir_capability::ProducedFact>, String> {
    run_on(name, input())
}

fn run_on(
    name: &str,
    inputs: Vec<FactInstance>,
) -> Result<Vec<gooir_capability::ProducedFact>, String> {
    ProcessProvider::load(fixture(name))
        .expect("manifest loads")
        .invoke(&spec(), &inputs)
}

#[test]
fn a_provider_on_the_sdk_is_one_function_and_the_host_cannot_tell() {
    let outputs = run("sdk_clean.json").expect("plugin answers");
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].fact_type, produced());
    assert_eq!(outputs[0].coverage, FactCoverage::Complete);
    assert_eq!(outputs[0].payload["value"]["doubled"], 42);
    // The envelope is the SDK's, not the author's: the same shape every
    // in-process lowering produces.
    assert_eq!(outputs[0].payload["defeater_set"], "test.defeaters@1.0.0");
}

#[test]
fn a_defeat_recorded_after_the_output_still_makes_it_partial() {
    let outputs = run("sdk_late_defeat.json").expect("plugin answers");
    assert_eq!(
        outputs[0].coverage,
        FactCoverage::Partial,
        "coverage is a property of the invocation, so it cannot be banked \
         before the provider admits what it lost"
    );
    assert_eq!(outputs[0].payload["defeats"][0]["subject"], "n");
}

#[test]
fn a_missing_input_is_an_answer_rather_than_a_crashed_process() {
    let error = run("sdk_absent_input.json").expect_err("must fail");
    assert!(error.contains("test.fact/never_supplied@1.0.0"), "{error}");
    assert!(
        !error.contains("Traceback"),
        "a provider fault must reach the host as a report, not a stack: {error}"
    );
}

#[test]
fn a_defeat_kind_the_kernel_does_not_know_is_refused_at_the_source() {
    let error = run("sdk_invented_kind.json").expect_err("must fail");
    assert!(error.contains("probably_fine"), "{error}");
    // Refusing here matters: an unknown kind names no remedy, and the five
    // kinds each imply a different one.
    assert!(error.contains("not_looked"), "{error}");
}

#[test]
fn producing_nothing_without_reporting_a_failure_is_itself_a_failure() {
    let error = run("sdk_produced_nothing.json").expect_err("must fail");
    assert!(error.contains("produced nothing"), "{error}");
}

#[test]
fn an_input_arriving_in_an_envelope_is_handed_over_as_its_value() {
    // Every fact a provider produces is enveloped, so most inputs are too.
    // A provider that had to unwrap by hand would eventually forget, and the
    // failure would look like an empty model rather than a mistake.
    let outputs = run_on("sdk_clean.json", enveloped_input()).expect("plugin answers");
    assert_eq!(outputs[0].payload["value"]["doubled"], 42);
}
