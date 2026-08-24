//! The authoring surface as a capability, and its interchangeability with a
//! lifted authority.

use gooir_capability::{CapabilityRegistry, FactCoverage, FactDerivation};
use gooir_datamodel_pack::{
    AuthoredSpec, authored_entity_spec_fact, authored_fact, data_model_fact, openapi_surface_fact,
    postgres_ddl_fact, register, typescript_types_fact,
};

const SPEC: &str = "\
entity Team
  id   uuid pk = uuid
  name text unique

entity Member
  id     uuid pk = uuid
  email  text unique
  teamId -> Team
";

fn registry() -> CapabilityRegistry {
    let mut r = CapabilityRegistry::default();
    register(&mut r).expect("pack registers");
    r
}

#[test]
fn an_authored_specification_is_an_ordinary_source_fact() {
    let source = authored_fact("test.entities", SPEC).expect("initial fact");
    assert_eq!(source.fact_type, authored_entity_spec_fact());
    assert_eq!(source.coverage, FactCoverage::Complete);
    assert!(matches!(source.derivation, FactDerivation::Initial { .. }));
    let decoded: AuthoredSpec = serde_json::from_value(source.payload.clone()).expect("payload");
    assert_eq!(decoded.origin, "test.entities");
}

#[test]
fn the_authored_route_to_the_waist_is_planned_not_wired() {
    let r = registry();
    let plan = r
        .plan([authored_entity_spec_fact()], &data_model_fact())
        .expect("data model is reachable");
    assert!(plan.is_executable());
    assert_eq!(plan.steps.len(), 1);

    let report = r
        .execute(&plan, vec![authored_fact("t", SPEC).expect("fact")])
        .expect("execution succeeds");
    assert_eq!(report.target.fact_type, data_model_fact());
    assert_eq!(report.target.coverage, FactCoverage::Complete);
}

#[test]
fn a_produced_artifact_carries_its_chain_back_to_the_authored_text() {
    let r = registry();
    let source = authored_fact("t", SPEC).expect("fact");
    let plan = r
        .plan([authored_entity_spec_fact()], &postgres_ddl_fact())
        .expect("ddl reachable");
    let report = r.execute(&plan, vec![source.clone()]).expect("execute");

    // the artifact names its inputs, which name theirs, back to the text
    let FactDerivation::Produced { inputs, .. } = &report.target.derivation else {
        panic!("expected a produced derivation");
    };
    let model_id = inputs.first().expect("one input");
    let model = report
        .facts
        .iter()
        .find(|f| &f.id == model_id)
        .expect("input fact is in the report");
    let FactDerivation::Produced { inputs, .. } = &model.derivation else {
        panic!("expected the model to be produced too");
    };
    assert_eq!(inputs.first(), Some(&source.id), "chain reaches the author");
}

#[test]
fn a_specification_with_an_unresolved_defeat_cannot_be_lowered() {
    // `geography` is not a domain the waist models, so the parse is partial.
    let partial = "entity A\n  id uuid pk\n  where geography\n";
    let r = registry();
    let source = authored_fact("t", partial).expect("fact");
    let plan = r
        .plan([authored_entity_spec_fact()], &postgres_ddl_fact())
        .expect("route exists");
    assert!(plan.is_executable(), "a typed route exists regardless");

    // Planning proves a route; execution still refuses a partial fact on a
    // complete-only edge.
    let error = r
        .execute(&plan, vec![source])
        .expect_err("a partial model must not reach a complete-only lowering");
    let text = error.to_string();
    assert!(
        text.contains("partial") || text.contains("Partial"),
        "unexpected error: {text}"
    );
}

#[test]
fn an_uninstalled_lowering_becomes_an_exact_assignable_need() {
    let r = registry();
    let plan = r
        .plan([authored_entity_spec_fact()], &typescript_types_fact())
        .expect("the route is known even with no provider");
    assert!(!plan.is_executable());
    assert_eq!(plan.needs.len(), 1);
    let need = &plan.needs[0];
    assert_eq!(need.produces, vec![typescript_types_fact()]);
    assert_eq!(need.requires[0].fact, data_model_fact());
    assert!(!need.conformance_suite.is_empty(), "a need names its suite");
}

#[test]
fn openapi_lowering_declares_what_a_document_cannot_carry() {
    let r = registry();
    let plan = r
        .plan([authored_entity_spec_fact()], &openapi_surface_fact())
        .expect("reachable");
    let report = r
        .execute(&plan, vec![authored_fact("t", SPEC).expect("fact")])
        .expect("execute");
    // JSON Schema cannot express identity, uniqueness, defaults or relations,
    // so the artifact is honestly partial rather than silently lossless.
    assert_eq!(report.target.coverage, FactCoverage::Partial);
}

/// The neutral pack and the product pack must name the same data-model fact, or
/// an authored specification and a lifted document would populate two
/// unrelated graphs that merely look alike.
#[test]
fn the_data_model_fact_identity_agrees_with_the_product_pack() {
    assert_eq!(data_model_fact(), fleetd_capability_pack::data_model_fact());
}

/// One registry, two ways in. This is the interchangeability claim: whatever
/// consumes the waist does not care whether a person wrote it or a lifter
/// derived it from software that already exists.
#[test]
fn authored_and_lifted_sources_reach_the_same_waist_fact() {
    let mut r = CapabilityRegistry::default();
    register(&mut r).expect("neutral pack");
    fleetd_capability_pack::register_specs(&mut r).expect("product specs");
    fleetd_capability_pack::register_providers(&mut r).expect("product providers");

    let from_authored = r
        .plan([authored_entity_spec_fact()], &data_model_fact())
        .expect("authored route");
    let from_lifted = r
        .plan(
            [fleetd_capability_pack::openapi_source_fact()],
            &data_model_fact(),
        )
        .expect("lifted route");

    assert!(from_authored.is_executable());
    assert!(from_lifted.is_executable());
    assert_eq!(from_authored.target, from_lifted.target);
    assert_ne!(
        from_authored.steps, from_lifted.steps,
        "the same fact, reached by different capabilities"
    );
}
