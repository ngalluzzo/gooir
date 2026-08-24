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
    CapabilityId, CapabilityProvider, CapabilityRegistry, CapabilitySpec, FactCoverage,
    FactInstance, FactType, ProducedFact, ProviderDescriptor, ProviderId, RegistryError,
    Requirement,
};
use lift_defeasible::Defeasible;
use semantics_data_model_v1::DataModel;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const PACK_VERSION: &str = "0.1.0";

// ---------------------------------------------------------------- fact types

/// Text a person wrote by hand. The only source fact in this pack that is not
/// derived from existing software.
pub fn authored_entity_spec_fact() -> FactType {
    FactType::new("org.gooi.source.authored", "entity_spec", "0.1.0")
}

/// The neutral data-model waist, carried as `Defeasible<DataModel>`.
///
/// This identity is canonical here. `fleetd-capability-pack` declares the same
/// identity so that a lifted OpenAPI document and an authored spec produce the
/// *same* fact; a test asserts the two declarations agree.
pub fn data_model_fact() -> FactType {
    FactType::new("org.gooi.semantics.data_model", "model", "1.0.0")
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

/// What a lowering could not supply from the waist. Mirrored here because the
/// lowering crates deliberately do not depend on serialization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LossyRecord {
    pub subject: String,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SqlArtifact {
    pub dialect: String,
    pub ddl: String,
    pub lossy: Vec<LossyRecord>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OpenApiArtifact {
    pub document: Value,
    pub lossy: Vec<LossyRecord>,
}

// ----------------------------------------------------------------- providers

struct AuthoredSpecProvider;

impl CapabilityProvider for AuthoredSpecProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        descriptor("authored_entity_spec", author_data_model_capability())
    }

    fn invoke(
        &self,
        _: &CapabilitySpec,
        inputs: &[FactInstance],
    ) -> Result<Vec<ProducedFact>, String> {
        let spec: AuthoredSpec = input(inputs, &authored_entity_spec_fact())?;
        let parsed = entity_spec::parse_entity_spec(&spec.text);
        Ok(vec![produced(
            data_model_fact(),
            coverage(parsed.is_exhaustive()),
            &parsed,
        )?])
    }
}

struct PostgresDdlProvider;

impl CapabilityProvider for PostgresDdlProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        descriptor("postgres_ddl", postgres_ddl_capability())
    }

    fn invoke(
        &self,
        _: &CapabilitySpec,
        inputs: &[FactInstance],
    ) -> Result<Vec<ProducedFact>, String> {
        let model: Defeasible<DataModel> = input(inputs, &data_model_fact())?;
        let lowered = sql_ddl_lowering::lower_to_postgres_ddl(&model.value);
        let lossy: Vec<LossyRecord> = lowered
            .lossy
            .iter()
            .map(|l| LossyRecord {
                subject: l.subject.clone(),
                detail: l.detail.clone(),
            })
            .collect();
        let artifact = SqlArtifact {
            dialect: "postgresql".to_owned(),
            ddl: lowered.ddl,
            lossy,
        };
        let complete = artifact.lossy.is_empty();
        Ok(vec![produced(
            postgres_ddl_fact(),
            coverage(complete),
            &artifact,
        )?])
    }
}

struct OpenApiSurfaceProvider;

impl CapabilityProvider for OpenApiSurfaceProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        descriptor("openapi_crud_surface", openapi_surface_capability())
    }

    fn invoke(
        &self,
        _: &CapabilitySpec,
        inputs: &[FactInstance],
    ) -> Result<Vec<ProducedFact>, String> {
        let model: Defeasible<DataModel> = input(inputs, &data_model_fact())?;
        let lowered = openapi_lowering::lower_to_openapi(&model.value);
        let lossy: Vec<LossyRecord> = lowered
            .lossy
            .iter()
            .map(|l| LossyRecord {
                subject: l.subject.clone(),
                detail: l.detail.clone(),
            })
            .collect();
        let artifact = OpenApiArtifact {
            document: lowered.document,
            lossy,
        };
        let complete = artifact.lossy.is_empty();
        Ok(vec![produced(
            openapi_surface_fact(),
            coverage(complete),
            &artifact,
        )?])
    }
}

// -------------------------------------------------------------- registration

pub fn register_specs(registry: &mut CapabilityRegistry) -> Result<(), RegistryError> {
    let specs = [
        CapabilitySpec {
            id: author_data_model_capability(),
            requires: vec![Requirement::complete(authored_entity_spec_fact())],
            produces: vec![data_model_fact()],
            conformance_suite: "org.gooi.conformance.authored_data_model@0.1.0".to_owned(),
        },
        CapabilitySpec {
            id: postgres_ddl_capability(),
            requires: vec![Requirement::complete(data_model_fact())],
            produces: vec![postgres_ddl_fact()],
            conformance_suite: "org.gooi.conformance.postgres_ddl@0.1.0".to_owned(),
        },
        CapabilitySpec {
            id: openapi_surface_capability(),
            requires: vec![Requirement::complete(data_model_fact())],
            produces: vec![openapi_surface_fact()],
            conformance_suite: "org.gooi.conformance.openapi_crud_surface@0.1.0".to_owned(),
        },
        // Intentionally provider-less. Asking for typed clients yields an exact
        // need that an external generator or agent seat can be assigned.
        CapabilitySpec {
            id: typescript_types_capability(),
            requires: vec![Requirement::complete(data_model_fact())],
            produces: vec![typescript_types_fact()],
            conformance_suite: "org.gooi.conformance.typescript_model_types@0.1.0".to_owned(),
        },
    ];
    for spec in specs {
        registry.register_spec(spec)?;
    }
    Ok(())
}

pub fn register_providers(registry: &mut CapabilityRegistry) -> Result<(), RegistryError> {
    registry.register_provider(AuthoredSpecProvider)?;
    registry.register_provider(PostgresDdlProvider)?;
    registry.register_provider(OpenApiSurfaceProvider)?;
    Ok(())
}

/// Specs and providers together.
pub fn register(registry: &mut CapabilityRegistry) -> Result<(), RegistryError> {
    register_specs(registry)?;
    register_providers(registry)
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

// ------------------------------------------------------------------- helpers

fn descriptor(name: &str, capability: CapabilityId) -> ProviderDescriptor {
    ProviderDescriptor {
        id: ProviderId::new("org.gooi.provider.in_process", name, PACK_VERSION),
        capability,
        implementation_digest: implementation_digest(name),
    }
}

fn implementation_digest(provider_name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(include_bytes!("lib.rs"));
    hasher.update(include_bytes!("../Cargo.toml"));
    hasher.update(include_bytes!("../../../Cargo.lock"));
    hasher.update(provider_name.as_bytes());
    let digest = hasher.finalize();
    let mut output = String::with_capacity(7 + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn input<T: DeserializeOwned>(inputs: &[FactInstance], fact: &FactType) -> Result<T, String> {
    let instance = inputs
        .iter()
        .find(|input| &input.fact_type == fact)
        .ok_or_else(|| format!("input {fact} is missing"))?;
    serde_json::from_value(instance.payload.clone()).map_err(|error| error.to_string())
}

fn produced<T: Serialize>(
    fact_type: FactType,
    coverage: FactCoverage,
    value: &T,
) -> Result<ProducedFact, String> {
    Ok(ProducedFact {
        fact_type,
        coverage,
        payload: serde_json::to_value(value).map_err(|error| error.to_string())?,
    })
}

fn coverage(exhaustive: bool) -> FactCoverage {
    if exhaustive {
        FactCoverage::Complete
    } else {
        FactCoverage::Partial
    }
}
