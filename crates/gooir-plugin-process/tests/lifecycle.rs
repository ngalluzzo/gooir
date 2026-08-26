//! Every way a separate program can misbehave, and what the host does about it.
//!
//! A provider that is a process can crash, hang, lie, or answer a question it
//! was not asked. None of those may become a silent success.

use std::{path::PathBuf, time::Duration};

use gooir_capability::{
    CapabilityId, CapabilityProvider, CapabilityRegistry, CapabilitySpec, FactCoverage,
    FactInstance, FactType, InputPort, OutputPort, PortName,
};
use gooir_plugin_process::{PluginError, ProcessProvider};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn capability() -> CapabilityId {
    CapabilityId::new("test.capability", "make", "1.0.0")
}
fn source() -> FactType {
    FactType::new("test.fact", "source", "1.0.0")
}
fn produced() -> FactType {
    FactType::new("test.fact", "produced", "1.0.0")
}

fn spec() -> CapabilitySpec {
    CapabilitySpec {
        id: capability(),
        input_ports: vec![InputPort::complete(
            PortName::parse("source").unwrap(),
            source(),
        )],
        output_ports: vec![OutputPort::new(
            PortName::parse("result").unwrap(),
            produced(),
        )],
        default_conformance_suite: "test.suite@1.0.0".to_owned(),
        extensions: Default::default(),
    }
}

fn input() -> Vec<FactInstance> {
    vec![
        FactInstance::initial(
            source(),
            FactCoverage::Complete,
            serde_json::json!({"n": 1}),
            "test",
        )
        .expect("initial fact"),
    ]
}

fn provider(name: &str) -> ProcessProvider {
    ProcessProvider::load(fixture(name)).expect("manifest loads")
}

#[test]
fn a_program_that_answers_correctly_is_an_ordinary_provider() {
    let outputs = provider("good.json")
        .invoke(&spec(), &input())
        .expect("plugin answers");
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0].fact_type, produced());
}

#[test]
fn the_host_measures_the_digest_rather_than_believing_the_manifest() {
    let declared = provider("good.json");
    let digest = declared.descriptor().implementation_digest;
    assert!(digest.starts_with("sha256:"));
    assert_eq!(declared.covered_files(), 1);

    // Same manifest, different implementation bytes: different identity.
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::copy(fixture("good.json"), dir.path().join("good.json")).unwrap();
    let mut source = std::fs::read_to_string(fixture("good.py")).unwrap();
    source.push_str("\n# a change to the implementation\n");
    std::fs::write(dir.path().join("good.py"), source).unwrap();

    let altered = ProcessProvider::load(dir.path().join("good.json")).expect("loads");
    assert_ne!(
        altered.descriptor().implementation_digest,
        digest,
        "changed code must not inherit an admission decision made about other code"
    );
}

#[test]
fn a_manifest_declaring_another_protocol_is_refused_before_anything_runs() {
    let error =
        ProcessProvider::load(fixture("bad_protocol_manifest.json")).expect_err("must refuse");
    assert!(
        matches!(error, PluginError::ProtocolMismatch { .. }),
        "{error}"
    );
}

#[test]
fn a_declared_implementation_file_that_is_absent_is_refused() {
    let error = ProcessProvider::load(fixture("missing_file.json")).expect_err("must refuse");
    assert!(
        matches!(error, PluginError::MissingImplementationFile(_)),
        "{error}"
    );
}

#[test]
fn a_crash_becomes_a_provider_error_carrying_its_first_stderr_line() {
    let error = provider("crashes.json")
        .invoke(&spec(), &input())
        .expect_err("must fail");
    assert!(error.contains("exited 9"), "{error}");
    assert!(error.contains("something went wrong"), "{error}");
    assert!(
        !error.contains("second line"),
        "one line, not a dump: {error}"
    );
}

#[test]
fn unparseable_output_is_an_error_not_an_empty_success() {
    let error = provider("garbage.json")
        .invoke(&spec(), &input())
        .expect_err("must fail");
    assert!(error.contains("not valid"), "{error}");
}

#[test]
fn a_plugin_reporting_its_own_failure_is_surfaced_verbatim() {
    let error = provider("reports_error.json")
        .invoke(&spec(), &input())
        .expect_err("must fail");
    assert!(error.contains("cannot do that"), "{error}");
}

#[test]
fn answering_a_different_protocol_is_refused() {
    let error = provider("wrong_protocol.json")
        .invoke(&spec(), &input())
        .expect_err("must fail");
    assert!(error.contains("protocol"), "{error}");
}

#[test]
fn neither_outputs_nor_an_error_is_itself_an_error() {
    let error = provider("silent.json")
        .invoke(&spec(), &input())
        .expect_err("must fail");
    assert!(error.contains("neither"), "{error}");
}

#[test]
fn a_hung_plugin_does_not_hang_the_host() {
    let error = provider("hangs.json")
        .with_timeout(Duration::from_millis(300))
        .invoke(&spec(), &input())
        .expect_err("must time out");
    assert!(error.contains("exceeded"), "{error}");
}

/// The adapter deliberately does not judge which outputs are correct. The
/// registry does, exactly as it does for an in-process provider.
#[test]
fn a_plugin_answering_the_wrong_fact_is_rejected_by_the_registry() {
    let mut registry = CapabilityRegistry::default();
    registry.register_spec(spec()).expect("spec");
    registry
        .register_provider(provider("wrong_output.json"))
        .expect("provider");

    let plan = registry.plan([source()], &produced()).expect("route");
    let error = registry
        .execute(&plan, input())
        .expect_err("wrong outputs must not be admitted");
    let text = format!("{error:?}");
    assert!(
        text.contains("Output") || text.to_lowercase().contains("output"),
        "{text}"
    );
}
