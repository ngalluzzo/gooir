//! The legacy lowering manifest is the declaration; its accessors are
//! conveniences over it. The authoring contract is composed separately.
//!
//! Two places naming one identity is exactly the drift this project removes, so
//! nothing here is allowed to disagree.

use gooir_capability::{CapabilityPack, read_pack};
use gooir_datamodel_pack as pack;

fn manifest() -> CapabilityPack {
    read_pack(pack::MANIFEST).expect("pack.json is valid")
}

#[test]
fn every_capability_accessor_is_declared_by_the_manifest() {
    let declared: Vec<String> = manifest()
        .capabilities
        .iter()
        .map(|c| c.id.to_string())
        .collect();
    for accessor in [
        pack::postgres_ddl_capability(),
        pack::openapi_surface_capability(),
        pack::typescript_types_capability(),
    ] {
        assert!(
            declared.contains(&accessor.to_string()),
            "`{accessor}` is named in code but not in pack.json"
        );
    }
    assert_eq!(declared.len(), 3, "and the manifest declares no others");
    assert!(
        !declared.contains(&pack::author_data_model_capability().to_string()),
        "the separately governed authoring contract must not be redeclared"
    );
}

#[test]
fn every_fact_accessor_is_mentioned_by_the_manifest() {
    let specs = read_pack(pack::MANIFEST).expect("manifest reads");
    let mentioned: Vec<String> = specs
        .capabilities
        .iter()
        .flat_map(|s| {
            s.output_ports
                .iter()
                .map(|port| port.value_kind.to_string())
                .chain(s.input_ports.iter().map(|port| port.value_kind.to_string()))
        })
        .collect();
    for accessor in [
        pack::data_model_fact(),
        pack::postgres_ddl_fact(),
        pack::openapi_surface_fact(),
        pack::typescript_types_fact(),
    ] {
        assert!(
            mentioned.contains(&accessor.to_string()),
            "`{accessor}` is named in code but no capability mentions it"
        );
    }
}

#[test]
fn registration_composes_the_external_authoring_contract_with_legacy_lowerings() {
    let mut registry = gooir_capability::CapabilityRegistry::default();
    pack::register_specs(&mut registry).expect("specs register");
    let registered: Vec<_> = registry.specs().map(|spec| spec.id.clone()).collect();
    assert_eq!(registered.len(), 4);
    assert!(registered.contains(&pack::author_data_model_capability()));
    let authoring_spec = gooir_author_data_model_contract::author_data_model_spec();
    assert_eq!(
        registry
            .specs()
            .find(|spec| spec.id == pack::author_data_model_capability()),
        Some(&authoring_spec)
    );
}

/// Providers stay code, but which capability each claims must be installed.
#[test]
fn every_registered_provider_implements_a_declared_capability() {
    let mut registry = gooir_capability::CapabilityRegistry::default();
    pack::register(&mut registry).expect("pack registers");
    let declared: Vec<String> = registry.specs().map(|spec| spec.id.to_string()).collect();
    for descriptor in registry.provider_descriptors() {
        assert!(
            declared.contains(&descriptor.capability.to_string()),
            "provider `{}` implements `{}`, which registration did not install",
            descriptor.id,
            descriptor.capability
        );
    }
}
