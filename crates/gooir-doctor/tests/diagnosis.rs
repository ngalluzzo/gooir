//! The diagnostic is generic: these graphs contain no real fact meanings.

use gooir_capability::{
    CapabilityId, CapabilityProvider, CapabilityRegistry, CapabilitySpec, FactCoverage,
    FactInstance, FactType, ProducedFact, ProviderDescriptor, ProviderId, Requirement,
};
use gooir_doctor::diagnose;

fn fact(name: &str) -> FactType {
    FactType::new("test.fact", name, "1.0.0")
}
fn cap(name: &str) -> CapabilityId {
    CapabilityId::new("test.capability", name, "1.0.0")
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
        requires: vec![Requirement::complete(fact(from))],
        produces: vec![fact(to)],
        conformance_suite: "test.suite@1.0.0".to_owned(),
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
    assert!(report.terminals[0].obtainable);
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
    assert!(!terminal.obtainable);
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
        requires: vec![Requirement::complete(fact("z"))],
        produces: vec![fact("z")],
        conformance_suite: "test.suite@1.0.0".to_owned(),
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
    assert_eq!(report.unadmitted[0].conformance_suite, "test.suite@1.0.0");
}
