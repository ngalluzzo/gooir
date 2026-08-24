//! The authoring surface as a capability, and its interchangeability with a
//! lifted authority.

use gooir_capability::{CapabilityRegistry, FactCoverage, FactDerivation};
use gooir_datamodel_pack::{
    AuthoredSpec, authored_entity_spec_fact, authored_fact, data_model_fact, openapi_surface_fact,
    postgres_ddl_fact, register, typescript_types_fact,
};
use lift_defeasible::Defeasible;

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

#[test]
fn the_checked_in_example_exercises_the_whole_authored_graph() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root");
    let path = root.join("examples/tasks.entities");
    let text = std::fs::read_to_string(&path).expect("checked-in example");
    let source = authored_fact(path.display().to_string(), &text).expect("source fact");
    let r = registry();

    let model_plan = r
        .plan([authored_entity_spec_fact()], &data_model_fact())
        .expect("data model route");
    let model = r
        .execute(&model_plan, vec![source.clone()])
        .expect("data model execution");
    assert_eq!(model.target.coverage, FactCoverage::Complete);
    let model: Defeasible<semantics_data_model_v1::DataModel> =
        serde_json::from_value(model.target.payload).expect("data model payload");
    assert_eq!(model.value.entities.len(), 3);

    let ddl_plan = r
        .plan([authored_entity_spec_fact()], &postgres_ddl_fact())
        .expect("DDL route");
    let ddl = r
        .execute(&ddl_plan, vec![source.clone()])
        .expect("DDL execution");
    assert_eq!(ddl.target.coverage, FactCoverage::Complete);
    let ddl: Defeasible<String> = serde_json::from_value(ddl.target.payload).expect("DDL payload");
    assert_eq!(ddl.value.matches("CREATE TABLE").count(), 3);
    assert_eq!(ddl.value.matches("CREATE TYPE").count(), 1);
    assert_eq!(ddl.value.matches("FOREIGN KEY").count(), 3);

    let openapi_plan = r
        .plan([authored_entity_spec_fact()], &openapi_surface_fact())
        .expect("OpenAPI route");
    let openapi = r
        .execute(&openapi_plan, vec![source])
        .expect("OpenAPI execution");
    assert_eq!(openapi.target.coverage, FactCoverage::Partial);
    let openapi: Defeasible<serde_json::Value> =
        serde_json::from_value(openapi.target.payload).expect("OpenAPI payload");
    assert_eq!(openapi.value["paths"].as_object().unwrap().len(), 6);
    assert_eq!(
        openapi.value["components"]["schemas"]
            .as_object()
            .unwrap()
            .len(),
        13
    );

    let missing = r
        .plan([authored_entity_spec_fact()], &typescript_types_fact())
        .expect("TypeScript route");
    assert!(!missing.is_executable());
    assert_eq!(missing.needs.len(), 1);
    assert_eq!(missing.needs[0].produces, vec![typescript_types_fact()]);
}
