//! Neutral capability pack for the data-model family.
//!
//! This package owns the canonical fact and capability identities for
//! *authoring* a data model and lowering it to concrete artifacts. Unlike
//! `fleetd-capability-pack`, nothing here is product-specific: no product
//! names, no control semantics, no interaction concepts.
//!
//! Folding the authoring surface in this way makes a hand-written `.entities`
//! file an ordinary source fact. It reaches the same `DataModel` fact that a
//! lifted OpenAPI document reaches, so anything downstream of the data model
//! becomes available to an author who has no software yet — which is the whole
//! point of the front door, expressed as a derivation instead of a bespoke
//! command.

use gooir_capability::{
    CapabilityId, CapabilityRegistry, FactCoverage, FactInstance, FactType, PackManifestError,
    ProviderId, RegistryError, register_pack,
};
use lift_defeasible::Defeasible;
use semantics_data_model_v1::DataModel;
use serde::{Deserialize, Serialize};

pub const PACK_VERSION: &str = "0.1.0";

// ---------------------------------------------------------------- fact types

/// Text a person wrote by hand. The only source fact in this pack that is not
/// derived from existing software.
pub fn authored_entity_spec_fact() -> FactType {
    FactType::new("org.gooi.source.authored", "entity_spec", "0.1.0")
}

/// The neutral data-model waist, carried as `Defeasible<DataModel>`.
///
/// Canonical, and built from the waist's own constants so the value has one
/// source. `fleetd-capability-pack` imports this function rather than
/// re-declaring the identity.
pub fn data_model_fact() -> FactType {
    FactType::new(
        semantics_data_model_v1::PACKAGE,
        semantics_data_model_v1::MODEL,
        semantics_data_model_v1::VERSION,
    )
}

pub fn postgres_ddl_fact() -> FactType {
    FactType::new("org.gooi.artifact.sql", "postgres_ddl", "0.1.0")
}

pub fn openapi_surface_fact() -> FactType {
    FactType::new("org.gooi.artifact.openapi", "crud_surface", "0.1.0")
}

/// Declared with no provider on purpose. An author asking for typed clients
/// receives an exact machine-readable need rather than silence.
pub fn typescript_types_fact() -> FactType {
    FactType::new("org.gooi.artifact.typescript", "model_types", "0.1.0")
}

// -------------------------------------------------------------- capabilities

pub fn author_data_model_capability() -> CapabilityId {
    CapabilityId::new("org.gooi.capability", "author_data_model", "0.1.0")
}

pub fn postgres_ddl_capability() -> CapabilityId {
    CapabilityId::new("org.gooi.capability", "lower_postgres_ddl", "0.1.0")
}

pub fn openapi_surface_capability() -> CapabilityId {
    CapabilityId::new("org.gooi.capability", "lower_openapi_crud_surface", "0.1.0")
}

pub fn typescript_types_capability() -> CapabilityId {
    CapabilityId::new("org.gooi.capability", "lower_typescript_types", "0.1.0")
}

// ------------------------------------------------------------------ payloads

/// A hand-written specification and where it came from.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthoredSpec {
    pub origin: String,
    pub text: String,
}

// ----------------------------------------------------------------- providers

/// Bytes that identify this pack's implementation. `include_bytes!` resolves
/// against this file, which is why the SDK takes the bytes rather than the
/// paths.
fn implementation(name: &str) -> String {
    gooir_provider::digest(&[
        include_bytes!("lib.rs"),
        include_bytes!("../Cargo.toml"),
        include_bytes!("../../../Cargo.lock"),
        name.as_bytes(),
    ])
}

// -------------------------------------------------------------- registration

/// The capabilities this pack declares, as data.
pub const MANIFEST: &str = include_str!("../pack.json");

pub fn register_specs(registry: &mut CapabilityRegistry) -> Result<(), PackManifestError> {
    register_pack(registry, MANIFEST)
}

/// Each provider is one function. The fact types it consumes and produces are
/// declared once, in `pack.json`, and the SDK reads them from the capability.
pub fn register_providers(registry: &mut CapabilityRegistry) -> Result<(), RegistryError> {
    gooir_provider::register_transform(
        registry,
        ProviderId::new(
            gooir_provider::IN_PROCESS,
            "authored_entity_spec",
            PACK_VERSION,
        ),
        author_data_model_capability(),
        implementation("authored_entity_spec"),
        |spec: AuthoredSpec| entity_spec::parse_entity_spec(&spec.text),
    )?;
    gooir_provider::register_transform(
        registry,
        ProviderId::new(gooir_provider::IN_PROCESS, "postgres_ddl", PACK_VERSION),
        postgres_ddl_capability(),
        implementation("postgres_ddl"),
        |model: Defeasible<DataModel>| sql_ddl_lowering::lower_to_postgres_ddl(&model.value),
    )?;
    gooir_provider::register_transform(
        registry,
        ProviderId::new(
            gooir_provider::IN_PROCESS,
            "openapi_crud_surface",
            PACK_VERSION,
        ),
        openapi_surface_capability(),
        implementation("openapi_crud_surface"),
        |model: Defeasible<DataModel>| openapi_lowering::lower_to_openapi(&model.value),
    )?;
    Ok(())
}

/// Specs and providers together.
pub fn register(registry: &mut CapabilityRegistry) -> Result<(), PackManifestError> {
    register_specs(registry)?;
    register_providers(registry).map_err(PackManifestError::Registry)
}

/// An authored specification as an initial fact.
pub fn authored_fact(
    origin: impl Into<String>,
    text: impl Into<String>,
) -> Result<FactInstance, RegistryError> {
    let spec = AuthoredSpec {
        origin: origin.into(),
        text: text.into(),
    };
    let payload = serde_json::to_value(&spec)
        .map_err(|error| RegistryError::Serialization(error.to_string()))?;
    let origin = format!("authored:{}", spec.origin);
    FactInstance::initial(
        authored_entity_spec_fact(),
        FactCoverage::Complete,
        payload,
        origin,
    )
}
