//! The diagnostic is generic: these graphs contain no real fact meanings.

use gooir_capability::{
    CapabilityId, CapabilityProvider, CapabilityRegistry, CapabilitySpec, FactCoverage,
    FactInstance, FactType, InputPort, OutputPort, PortName, ProducedFact, ProviderDescriptor,
    ProviderId,
};
use gooir_doctor::diagnose;

fn fact(name: &str) -> FactType {
    FactType::new("test.fact", name, "1.0.0")
}
fn cap(name: &str) -> CapabilityId {
    CapabilityId::new("test.capability", name, "1.0.0")
}
fn port(name: &str) -> PortName {
    PortName::parse(name).unwrap()
}

struct Noop(CapabilityId, FactType);

impl CapabilityProvider for Noop {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: ProviderId::new("test.provider", &self.0.name, "1.0.0"),
            capability: self.0.clone(),
            implementation_digest: format!("sha256:{}", "0".repeat(64)),
        }
    }
    fn invoke(&self, _: &CapabilitySpec, _: &[FactInstance]) -> Result<Vec<ProducedFact>, String> {
        Ok(vec![ProducedFact {
            fact_type: self.1.clone(),
            coverage: FactCoverage::Complete,
            payload: serde_json::Value::Null,
        }])
    }
}

fn spec(id: CapabilityId, from: &str, to: &str) -> CapabilitySpec {
    CapabilitySpec {
        id,
        input_ports: vec![InputPort::complete(port("source"), fact(from))],
        output_ports: vec![OutputPort::new(port("result"), fact(to))],
        default_conformance_suite: "test/suite@1.0.0".to_owned(),
        extensions: Default::default(),
    }
}

#[test]
fn a_fully_provided_chain_reports_nothing_blocking() {
    let mut r = CapabilityRegistry::default();
    r.register_spec(spec(cap("a_to_b"), "a", "b")).unwrap();
    r.register_provider(Noop(cap("a_to_b"), fact("b"))).unwrap();

    let report = diagnose(&r);
    assert_eq!(report.capabilities, 1);
    assert_eq!(report.providers, 1);
    assert_eq!(report.blocking(), 0);
    assert_eq!(report.open_needs(), 0);
    assert_eq!(report.roots.len(), 1, "`a` must be supplied");
    assert_eq!(report.roots[0].fact, fact("a"));
    assert_eq!(report.terminals.len(), 1, "`b` is the answer");
    assert!(report.terminals[0].fully_provided);
}

#[test]
fn repeated_kind_route_is_reported_as_provider_coverage_not_obtainability() {
    let mut r = CapabilityRegistry::default();
    let repeated = CapabilitySpec {
        id: cap("compare_to_b"),
        input_ports: vec![
            InputPort::complete(port("left"), fact("a")),
            InputPort::complete(port("right"), fact("a")),
        ],
        output_ports: vec![OutputPort::new(port("result"), fact("b"))],
        default_conformance_suite: "test/suite@1.0.0".to_owned(),
        extensions: Default::default(),
    };
    r.register_spec(repeated).unwrap();
    r.register_provider(Noop(cap("compare_to_b"), fact("b")))
        .unwrap();

    let report = diagnose(&r);
    assert!(report.terminals[0].fully_provided);
    let rendered = report.to_string();
    assert!(
        rendered.contains("terminal provider coverage"),
        "{rendered}"
    );
    assert!(rendered.contains("provided"), "{rendered}");
    assert!(!rendered.contains("you can obtain"), "{rendered}");
}

#[test]
fn a_provider_less_capability_is_an_open_need_not_a_failure() {
    let mut r = CapabilityRegistry::default();
    r.register_spec(spec(cap("a_to_b"), "a", "b")).unwrap();
    r.register_provider(Noop(cap("a_to_b"), fact("b"))).unwrap();
    r.register_spec(spec(cap("b_to_c"), "b", "c")).unwrap();

    let report = diagnose(&r);
    assert_eq!(report.open_needs(), 1);
    let terminal = report
        .terminals
        .iter()
        .find(|t| t.fact == fact("c"))
        .expect("c is a terminal");
    assert!(!terminal.fully_provided);
    assert_eq!(terminal.blocked_by, vec![cap("b_to_c")]);
    assert_eq!(
        report.blocking(),
        0,
        "a terminal blocked only by a declared need is accounted for"
    );
}

#[test]
fn a_fact_with_no_route_is_blocking() {
    let mut r = CapabilityRegistry::default();
    r.register_spec(spec(cap("a_to_b"), "a", "b")).unwrap();
    r.register_provider(Noop(cap("a_to_b"), fact("b"))).unwrap();
    // requires `x`, which nothing supplies and nothing produces... but a
    // requirement makes `x` a root, so instead orphan the *output* by
    // requiring a fact only this capability produces.
    r.register_spec(CapabilitySpec {
        id: cap("cycle"),
        input_ports: vec![InputPort::complete(port("source"), fact("z"))],
        output_ports: vec![OutputPort::new(port("result"), fact("z"))],
        default_conformance_suite: "test/suite@1.0.0".to_owned(),
        extensions: Default::default(),
    })
    .unwrap();

    let report = diagnose(&r);
    assert!(
        report.unreachable.iter().any(|u| u.fact == fact("z")),
        "a fact that only produces itself cannot be reached: {:?}",
        report.unreachable
    );
    assert!(report.blocking() >= 1);
}

#[test]
fn two_capabilities_producing_one_fact_are_reported_as_multiple_routes() {
    let mut r = CapabilityRegistry::default();
    r.register_spec(spec(cap("a_to_m"), "a", "m")).unwrap();
    r.register_provider(Noop(cap("a_to_m"), fact("m"))).unwrap();
    r.register_spec(spec(cap("k_to_m"), "k", "m")).unwrap();
    r.register_provider(Noop(cap("k_to_m"), fact("m"))).unwrap();

    let report = diagnose(&r);
    assert_eq!(report.ambiguous.len(), 1);
    assert_eq!(report.ambiguous[0].fact, fact("m"));
    assert_eq!(report.ambiguous[0].produced_by.len(), 2);
}

#[test]
fn every_registered_provider_is_unadmitted_until_conformance_runs() {
    let mut r = CapabilityRegistry::default();
    r.register_spec(spec(cap("a_to_b"), "a", "b")).unwrap();
    r.register_provider(Noop(cap("a_to_b"), fact("b"))).unwrap();

    let report = diagnose(&r);
    assert_eq!(report.unadmitted.len(), 1);
    assert_eq!(report.unadmitted[0].conformance_suite, "test/suite@1.0.0");
}
