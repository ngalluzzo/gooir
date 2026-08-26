//! One registry, two ways into the waist.
//!
//! This test lives here because this is the crate that depends on both packs.
//! Whatever consumes the data model does not care whether a person wrote it or
//! a lifter derived it from software that already exists.

use gooir_capability::CapabilityRegistry;

#[test]
fn authored_and_lifted_sources_reach_the_same_waist_fact() {
    let mut registry = CapabilityRegistry::default();
    gooir_datamodel_pack::register(&mut registry).expect("neutral pack");
    fleetd_capability_pack::register_specs(&mut registry).expect("product specs");
    fleetd_capability_pack::register_providers(&mut registry).expect("product providers");

    let target = fleetd_capability_pack::data_model_fact();
    let from_authored = registry
        .plan([gooir_datamodel_pack::authored_entity_spec_fact()], &target)
        .expect("authored route");
    let from_lifted = registry
        .plan([fleetd_capability_pack::openapi_source_fact()], &target)
        .expect("lifted route");

    assert!(from_authored.has_provider_for_every_step());
    assert!(from_lifted.has_provider_for_every_step());
    assert_eq!(from_authored.target, from_lifted.target);
    assert_ne!(
        from_authored.steps, from_lifted.steps,
        "the same fact, reached by different capabilities"
    );
}

#[test]
fn the_data_model_identity_comes_from_the_waist_itself() {
    let fact = fleetd_capability_pack::data_model_fact();
    assert_eq!(fact.package, semantics_data_model_v1::PACKAGE);
    assert_eq!(fact.name, semantics_data_model_v1::MODEL);
    assert_eq!(fact.version, semantics_data_model_v1::VERSION);
    assert!(fact.is_well_formed());
}
