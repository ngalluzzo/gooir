//! The manifest declares this pack's graph; the accessors are conveniences.
//! Neither may drift from the other.

use fleetd_capability_pack as pack;
use gooir_capability::{CapabilityRegistry, read_pack};

fn declared_capabilities() -> Vec<String> {
    let manifest = read_pack(pack::MANIFEST).expect("pack.json is valid");
    manifest
        .capabilities
        .into_iter()
        .map(|c| c.id.to_string())
        .collect()
}

#[test]
fn every_capability_accessor_is_declared_by_the_manifest() {
    let declared = declared_capabilities();
    for accessor in [
        pack::openapi_data_capability(),
        pack::fleetd_native_capability(),
        pack::fleetd_control_projection_capability(),
        pack::fleetd_interaction_capability(),
        pack::web_target_capability(),
        pack::terminal_target_capability(),
        pack::runnable_web_capability(),
    ] {
        assert!(
            declared.contains(&accessor.to_string()),
            "`{accessor}` is named in code but not in pack.json"
        );
    }
    assert_eq!(declared.len(), 7, "and the manifest declares no others");
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
        pack::openapi_source_fact(),
        pack::api_rust_source_fact(),
        pack::model_rust_source_fact(),
        pack::delivery_rust_source_fact(),
        pack::data_model_fact(),
        pack::fleetd_control_native_fact(),
        pack::fleetd_control_fact(),
        pack::fleetd_interaction_fact(),
        pack::web_target_ir_fact(),
        pack::terminal_target_ir_fact(),
        pack::runnable_web_artifact_fact(),
    ] {
        assert!(
            mentioned.contains(&accessor.to_string()),
            "`{accessor}` is named in code but no capability mentions it"
        );
    }
}

#[test]
fn every_registered_provider_implements_a_declared_capability() {
    let mut registry = CapabilityRegistry::default();
    pack::register_specs(&mut registry).expect("specs");
    pack::register_providers(&mut registry).expect("providers");
    let declared = declared_capabilities();
    for descriptor in registry.provider_descriptors() {
        assert!(
            declared.contains(&descriptor.capability.to_string()),
            "provider `{}` implements `{}`, which pack.json does not declare",
            descriptor.id,
            descriptor.capability
        );
    }
}

/// The runnable-web capability is declared with no provider on purpose. That is
/// data now, so the intent survives without a comment in Rust to explain it.
#[test]
fn the_declared_graph_still_leaves_one_capability_open() {
    let mut registry = CapabilityRegistry::default();
    pack::register_specs(&mut registry).expect("specs");
    pack::register_providers(&mut registry).expect("providers");
    let implemented: Vec<String> = registry
        .provider_descriptors()
        .into_iter()
        .map(|d| d.capability.to_string())
        .collect();
    assert!(!implemented.contains(&pack::runnable_web_capability().to_string()));
}
