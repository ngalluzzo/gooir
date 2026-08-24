//! The manifest is the declaration; the accessors are conveniences over it.
//!
//! Two places naming one identity is exactly the drift this project removes, so
//! nothing here is allowed to disagree.

use gooir_capability::{PackManifest, read_pack};
use gooir_datamodel_pack as pack;

fn manifest() -> PackManifest {
    serde_json::from_str(pack::MANIFEST).expect("pack.json is valid")
}

#[test]
fn every_capability_accessor_is_declared_by_the_manifest() {
    let declared: Vec<String> = manifest()
        .capabilities
        .iter()
        .map(|c| c.id.clone())
        .collect();
    for accessor in [
        pack::author_data_model_capability(),
        pack::postgres_ddl_capability(),
        pack::openapi_surface_capability(),
        pack::typescript_types_capability(),
    ] {
        assert!(
            declared.contains(&accessor.to_string()),
            "`{accessor}` is named in code but not in pack.json"
        );
    }
    assert_eq!(declared.len(), 4, "and the manifest declares no others");
}

#[test]
fn every_fact_accessor_is_mentioned_by_the_manifest() {
    let specs = read_pack(pack::MANIFEST).expect("manifest reads");
    let mentioned: Vec<String> = specs
        .iter()
        .flat_map(|s| {
            s.produces
                .iter()
                .map(ToString::to_string)
                .chain(s.requires.iter().map(|r| r.fact.to_string()))
        })
        .collect();
    for accessor in [
        pack::authored_entity_spec_fact(),
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

/// Providers stay code, but which capability each claims must be declared.
#[test]
fn every_registered_provider_implements_a_declared_capability() {
    let mut registry = gooir_capability::CapabilityRegistry::default();
    pack::register(&mut registry).expect("pack registers");
    let declared: Vec<String> = manifest()
        .capabilities
        .iter()
        .map(|c| c.id.clone())
        .collect();
    for descriptor in registry.provider_descriptors() {
        assert!(
            declared.contains(&descriptor.capability.to_string()),
            "provider `{}` implements `{}`, which pack.json does not declare",
            descriptor.id,
            descriptor.capability
        );
    }
}
