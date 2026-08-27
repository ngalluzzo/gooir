use std::collections::BTreeMap;
use std::fs;
use std::num::NonZeroUsize;
use std::path::Path;

use gooir_author_data_model_contract::{
    AUTHORED_SPEC_SCHEMA_BYTES, AUTHORED_SPEC_SCHEMA_PATH, AuthoredSpec, ContractPackageError,
    author_data_model_capability_id, author_data_model_spec, authored_entity_spec_value_kind,
    package_manifest,
};
use gooir_package::{
    LoadLimits, PackageManifest, PackageRegistry, load_local_package, read_manifest, write_manifest,
};
use gooir_planning::{PlanLimits, SemanticPlanner};
use serde_json::{Value, json};
use tempfile::TempDir;

#[test]
fn authored_spec_schema_and_rust_payload_accept_the_same_shape() {
    let schema: Value = serde_json::from_slice(AUTHORED_SPEC_SCHEMA_BYTES).expect("schema JSON");
    let validator = jsonschema::validator_for(&schema).expect("valid JSON Schema");

    let authored = AuthoredSpec {
        origin: "git:blob:abc#examples/tasks.entities".to_owned(),
        text: "entity Task { id: uuid }\n".to_owned(),
    };
    let document = serde_json::to_value(&authored).expect("serialize payload");
    assert!(validator.is_valid(&document));
    assert_eq!(
        serde_json::from_value::<AuthoredSpec>(document).expect("deserialize payload"),
        authored
    );

    for invalid in [
        json!({"origin": "source"}),
        json!({"text": "entity Task {}"}),
        json!({"origin": 1, "text": "entity Task {}"}),
        json!({"origin": "source", "text": 1}),
        json!({"origin": "source", "text": "", "invented": true}),
        json!([]),
    ] {
        assert!(!validator.is_valid(&invalid), "schema accepted {invalid}");
        assert!(
            serde_json::from_value::<AuthoredSpec>(invalid.clone()).is_err(),
            "Rust payload accepted {invalid}"
        );
    }
}

#[test]
fn checked_vocabulary_manifest_owns_only_the_exact_data_model_vocabulary() {
    let manifest = read_manifest(semantics_data_model_v1::PACKAGE_MANIFEST).expect("manifest");
    assert_eq!(
        manifest.package.to_string(),
        semantics_data_model_v1::VOCABULARY_PACKAGE
    );
    assert!(manifest.dependencies.is_empty());
    assert!(manifest.resources.is_empty());
    assert!(manifest.conformance_suites.is_empty());
    assert!(manifest.capabilities.is_empty());
    assert!(manifest.implementation_offers.is_empty());
    assert_eq!(manifest.dialects.len(), 1);
    assert_eq!(
        manifest.dialects[0].id,
        semantics_data_model_v1::dialect_id()
    );
    assert_eq!(
        manifest.dialects[0]
            .value_kinds
            .iter()
            .map(|declaration| declaration.id.clone())
            .collect::<Vec<_>>(),
        vec![
            semantics_data_model_v1::entity_contract(),
            semantics_data_model_v1::model_contract(),
            semantics_data_model_v1::relation_contract(),
        ]
    );
}

#[test]
fn contract_only_install_plans_one_explicit_provider_need() {
    let (registry, contract_directory) = install_contract_only();
    let contract_manifest = read_manifest(
        &fs::read_to_string(contract_directory.path().join("gooir-package.json"))
            .expect("contract manifest"),
    )
    .expect("valid contract manifest");

    assert_eq!(
        contract_manifest.capabilities,
        vec![author_data_model_spec()]
    );
    assert!(contract_manifest.implementation_offers.is_empty());
    assert_eq!(contract_manifest.dependencies.len(), 1);
    assert_eq!(contract_manifest.resources.len(), 1);
    assert_eq!(contract_manifest.dialects.len(), 1);
    assert_eq!(contract_manifest.conformance_suites.len(), 1);

    let planner = SemanticPlanner::from_registry(&registry, planning_limits()).expect("planner");
    let plan = planner
        .plan(
            [authored_entity_spec_value_kind()],
            semantics_data_model_v1::model_contract(),
        )
        .expect("reachable declared capability");

    assert_eq!(plan.capabilities.len(), 1);
    assert_eq!(
        plan.capabilities[0].specification.id,
        author_data_model_capability_id()
    );
    assert!(plan.capabilities[0].offers.is_empty());
    assert_eq!(
        plan.needs().map(|need| need.id.clone()).collect::<Vec<_>>(),
        vec![author_data_model_capability_id()]
    );
}

#[test]
fn contract_dependency_refuses_same_package_coordinate_with_different_content() {
    let original = read_manifest(semantics_data_model_v1::PACKAGE_MANIFEST).expect("manifest");
    let changed = PackageManifest::new(
        original.package,
        original.dependencies,
        original.resources,
        original.dialects,
        original.conformance_suites,
        original.capabilities,
        original.implementation_offers,
        BTreeMap::from([("org.gooi.test.variant".to_owned(), json!("changed"))]),
    )
    .expect("structurally valid alternate bytes");
    let directory = tempfile::tempdir().expect("alternate vocabulary directory");
    fs::write(
        directory.path().join("gooir-package.json"),
        write_manifest(&changed).expect("alternate manifest"),
    )
    .expect("write alternate manifest");
    let mut registry = PackageRegistry::default();
    let loaded = load_local_package(directory.path(), &registry, LoadLimits::default())
        .expect("load alternate vocabulary");
    let installed = registry
        .install(loaded)
        .expect("install alternate vocabulary");

    assert!(matches!(
        package_manifest(&installed),
        Err(ContractPackageError::UnexpectedVocabularyDigest { .. })
    ));
}

fn install_contract_only() -> (PackageRegistry, TempDir) {
    let mut registry = PackageRegistry::default();
    let vocabulary_directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .join("semantics-data-model-v1");
    let vocabulary = load_local_package(&vocabulary_directory, &registry, LoadLimits::default())
        .expect("load vocabulary");
    let vocabulary = registry.install(vocabulary).expect("install vocabulary");

    let contract_directory = tempfile::tempdir().expect("contract package directory");
    let schema_path = contract_directory.path().join(AUTHORED_SPEC_SCHEMA_PATH);
    fs::create_dir_all(schema_path.parent().expect("schema parent")).expect("schema directory");
    fs::write(&schema_path, AUTHORED_SPEC_SCHEMA_BYTES).expect("schema resource");
    fs::write(
        contract_directory.path().join("gooir-package.json"),
        write_manifest(&package_manifest(&vocabulary).expect("contract manifest"))
            .expect("serialize contract manifest"),
    )
    .expect("write contract manifest");

    let contract = load_local_package(contract_directory.path(), &registry, LoadLimits::default())
        .expect("load contract package");
    registry
        .install(contract)
        .expect("install contract package");
    (registry, contract_directory)
}

fn planning_limits() -> PlanLimits {
    let bound = NonZeroUsize::new(32).expect("non-zero");
    PlanLimits {
        max_capabilities: bound,
        max_value_kinds: bound,
        max_ports_per_capability: bound,
        max_total_ports: bound,
        max_offers_per_capability: bound,
        max_total_offers: bound,
    }
}
