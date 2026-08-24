//! In-process capability providers for the first Fleetd/GOOIR dogfood chain.
//!
//! This package is deliberately product-specific. It demonstrates discovery
//! and execution through the generic capability registry without claiming an
//! out-of-process plugin protocol or stable generic Interaction dialect.

use fleetd_control_lifter::{
    FleetdControlLift, FleetdControlSources, NativeCompleteness, lift_fleetd_control,
};
use fleetd_control_projection::project_blocked_delivery_review;
use fleetd_interaction_plan::{BlockedDeliveryInteractionPlan, derive_blocked_delivery_plan};
use fleetd_surface_lowering::{TerminalSurface, WebSurface, lower_terminal, lower_web};
use gooir_capability::{
    CapabilityId, CapabilityProvider, CapabilityRegistry, CapabilitySpec, FactCoverage,
    FactInstance, FactType, ProducedFact, ProviderDescriptor, ProviderId, RegistryError,
    Requirement,
};
use lift_defeasible::Defeasible;
use openapi_lifter::lift_openapi;
use semantics_data_model_v1::DataModel;
use semantics_fleetd_control_v0::BlockedDeliveryReview;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const PACK_VERSION: &str = "0.1.0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceDocument {
    pub authority: String,
    pub artifact: String,
    pub revision: String,
    pub text: String,
}

pub fn openapi_source_fact() -> FactType {
    FactType::new("dev.fleetd.source", "openapi", "1.0.0")
}

pub fn api_rust_source_fact() -> FactType {
    FactType::new("dev.fleetd.source", "api_rust", "0.1.0")
}

pub fn model_rust_source_fact() -> FactType {
    FactType::new("dev.fleetd.source", "model_rust", "0.1.0")
}

pub fn delivery_rust_source_fact() -> FactType {
    FactType::new("dev.fleetd.source", "delivery_rust", "0.1.0")
}

pub fn data_model_fact() -> FactType {
    FactType::new("org.gooi.semantics.data_model", "model", "1.0.0")
}

pub fn fleetd_control_native_fact() -> FactType {
    FactType::new("dev.fleetd.dialect.control_native", "review", "0.1.0")
}

pub fn fleetd_control_fact() -> FactType {
    FactType::new(
        "dev.fleetd.semantics.control",
        "blocked_delivery_review",
        "0.1.0",
    )
}

pub fn fleetd_interaction_fact() -> FactType {
    FactType::new(
        "dev.fleetd.semantics.interaction",
        "blocked_delivery_review",
        "0.1.0",
    )
}

pub fn web_target_ir_fact() -> FactType {
    FactType::new("org.gooi.target.web", "fleetd_blocked_delivery", "0.1.0")
}

pub fn terminal_target_ir_fact() -> FactType {
    FactType::new(
        "org.gooi.target.terminal",
        "fleetd_blocked_delivery",
        "0.1.0",
    )
}

pub fn runnable_web_artifact_fact() -> FactType {
    FactType::new("org.gooi.artifact.web", "runnable_fleetd_surface", "0.1.0")
}

pub fn openapi_data_capability() -> CapabilityId {
    CapabilityId::new("org.gooi.capability", "lift_openapi_data_model", "0.1.0")
}

pub fn fleetd_native_capability() -> CapabilityId {
    CapabilityId::new("dev.fleetd.capability", "lift_control_native", "0.1.0")
}

pub fn fleetd_control_projection_capability() -> CapabilityId {
    CapabilityId::new("dev.fleetd.capability", "project_control", "0.1.0")
}

pub fn fleetd_interaction_capability() -> CapabilityId {
    CapabilityId::new("dev.fleetd.capability", "compose_interaction", "0.1.0")
}

pub fn web_target_capability() -> CapabilityId {
    CapabilityId::new("dev.fleetd.capability", "lower_web_target_ir", "0.1.0")
}

pub fn terminal_target_capability() -> CapabilityId {
    CapabilityId::new("dev.fleetd.capability", "lower_terminal_target_ir", "0.1.0")
}

pub fn runnable_web_capability() -> CapabilityId {
    CapabilityId::new(
        "dev.fleetd.capability",
        "generate_runnable_web_surface",
        "0.1.0",
    )
}

pub fn register_specs(registry: &mut CapabilityRegistry) -> Result<(), RegistryError> {
    let specs = [
        CapabilitySpec {
            id: openapi_data_capability(),
            requires: vec![Requirement::complete(openapi_source_fact())],
            produces: vec![data_model_fact()],
            conformance_suite: "org.gooi.conformance.openapi_data_model@0.1.0".to_owned(),
        },
        CapabilitySpec {
            id: fleetd_native_capability(),
            requires: vec![
                Requirement::complete(openapi_source_fact()),
                Requirement::complete(api_rust_source_fact()),
                Requirement::complete(model_rust_source_fact()),
                Requirement::complete(delivery_rust_source_fact()),
            ],
            produces: vec![fleetd_control_native_fact()],
            conformance_suite: "dev.fleetd.conformance.control_native@0.1.0".to_owned(),
        },
        CapabilitySpec {
            id: fleetd_control_projection_capability(),
            requires: vec![Requirement::partial_allowed(fleetd_control_native_fact())],
            produces: vec![fleetd_control_fact()],
            conformance_suite: "dev.fleetd.conformance.control_projection@0.1.0".to_owned(),
        },
        CapabilitySpec {
            id: fleetd_interaction_capability(),
            requires: vec![
                Requirement::partial_allowed(data_model_fact()),
                Requirement::partial_allowed(fleetd_control_fact()),
            ],
            produces: vec![fleetd_interaction_fact()],
            conformance_suite: "dev.fleetd.conformance.interaction_projection@0.1.0".to_owned(),
        },
        CapabilitySpec {
            id: web_target_capability(),
            requires: vec![
                Requirement::complete(fleetd_interaction_fact()),
                Requirement::complete(fleetd_control_native_fact()),
            ],
            produces: vec![web_target_ir_fact()],
            conformance_suite: "dev.fleetd.conformance.web_target_ir@0.1.0".to_owned(),
        },
        CapabilitySpec {
            id: terminal_target_capability(),
            requires: vec![
                Requirement::complete(fleetd_interaction_fact()),
                Requirement::complete(fleetd_control_native_fact()),
            ],
            produces: vec![terminal_target_ir_fact()],
            conformance_suite: "dev.fleetd.conformance.terminal_target_ir@0.1.0".to_owned(),
        },
        // This specification intentionally has no provider. It is the first
        // machine-readable capability need for Fleetd to assign.
        CapabilitySpec {
            id: runnable_web_capability(),
            requires: vec![Requirement::complete(web_target_ir_fact())],
            produces: vec![runnable_web_artifact_fact()],
            conformance_suite: "dev.fleetd.conformance.runnable_web_surface@0.1.0".to_owned(),
        },
    ];
    for spec in specs {
        registry.register_spec(spec)?;
    }
    Ok(())
}

pub fn register_providers(registry: &mut CapabilityRegistry) -> Result<(), RegistryError> {
    registry.register_provider(OpenApiDataProvider)?;
    registry.register_provider(FleetdNativeProvider)?;
    registry.register_provider(FleetdControlProjectionProvider)?;
    registry.register_provider(FleetdInteractionProvider)?;
    registry.register_provider(WebTargetProvider)?;
    registry.register_provider(TerminalTargetProvider)?;
    Ok(())
}

pub fn registry() -> Result<CapabilityRegistry, RegistryError> {
    let mut registry = CapabilityRegistry::default();
    register_specs(&mut registry)?;
    register_providers(&mut registry)?;
    Ok(registry)
}

pub fn source_fact(
    fact_type: FactType,
    authority: impl Into<String>,
    artifact: impl Into<String>,
    revision: impl Into<String>,
    text: impl Into<String>,
) -> Result<FactInstance, RegistryError> {
    let source = SourceDocument {
        authority: authority.into(),
        artifact: artifact.into(),
        revision: revision.into(),
        text: text.into(),
    };
    let origin = format!(
        "{}:{}@{}",
        source.authority, source.artifact, source.revision
    );
    FactInstance::initial(
        fact_type,
        FactCoverage::Complete,
        serialize(&source)?,
        origin,
    )
}

struct OpenApiDataProvider;
struct FleetdNativeProvider;
struct FleetdControlProjectionProvider;
struct FleetdInteractionProvider;
struct WebTargetProvider;
struct TerminalTargetProvider;

impl CapabilityProvider for OpenApiDataProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        descriptor("openapi_data", openapi_data_capability())
    }

    fn invoke(
        &self,
        _: &CapabilitySpec,
        inputs: &[FactInstance],
    ) -> Result<Vec<ProducedFact>, String> {
        let source: SourceDocument = input(inputs, &openapi_source_fact())?;
        let lifted = lift_openapi(&source.text)?;
        Ok(vec![produced(
            data_model_fact(),
            coverage(lifted.is_exhaustive()),
            &lifted,
        )?])
    }
}

impl CapabilityProvider for FleetdNativeProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        descriptor("fleetd_control_native", fleetd_native_capability())
    }

    fn invoke(
        &self,
        _: &CapabilitySpec,
        inputs: &[FactInstance],
    ) -> Result<Vec<ProducedFact>, String> {
        let openapi: SourceDocument = input(inputs, &openapi_source_fact())?;
        let api: SourceDocument = input(inputs, &api_rust_source_fact())?;
        let model: SourceDocument = input(inputs, &model_rust_source_fact())?;
        let delivery: SourceDocument = input(inputs, &delivery_rust_source_fact())?;
        require_same_source(&[&openapi, &api, &model, &delivery])?;
        let lifted = lift_fleetd_control(
            FleetdControlSources {
                openapi: &openapi.text,
                api_rust: &api.text,
                model_rust: &model.text,
                delivery_rust: &delivery.text,
            },
            &openapi.authority,
            &openapi.revision,
        )
        .map_err(|error| error.to_string())?;
        let complete = lifted.coverage.completeness == NativeCompleteness::Exhaustive;
        Ok(vec![produced(
            fleetd_control_native_fact(),
            coverage(complete),
            &lifted,
        )?])
    }
}

impl CapabilityProvider for FleetdControlProjectionProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        descriptor(
            "fleetd_control_projection",
            fleetd_control_projection_capability(),
        )
    }

    fn invoke(
        &self,
        _: &CapabilitySpec,
        inputs: &[FactInstance],
    ) -> Result<Vec<ProducedFact>, String> {
        let native: FleetdControlLift = input(inputs, &fleetd_control_native_fact())?;
        let projected = project_blocked_delivery_review(&native);
        Ok(vec![produced(
            fleetd_control_fact(),
            coverage(projected.is_exhaustive()),
            &projected,
        )?])
    }
}

impl CapabilityProvider for FleetdInteractionProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        descriptor("fleetd_interaction", fleetd_interaction_capability())
    }

    fn invoke(
        &self,
        _: &CapabilitySpec,
        inputs: &[FactInstance],
    ) -> Result<Vec<ProducedFact>, String> {
        let data: Defeasible<DataModel> = input(inputs, &data_model_fact())?;
        let control: Defeasible<BlockedDeliveryReview> = input(inputs, &fleetd_control_fact())?;
        let interaction = derive_blocked_delivery_plan(&data, &control);
        Ok(vec![produced(
            fleetd_interaction_fact(),
            coverage(interaction.is_exhaustive()),
            &interaction,
        )?])
    }
}

impl CapabilityProvider for WebTargetProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        descriptor("fleetd_web_target", web_target_capability())
    }

    fn invoke(
        &self,
        _: &CapabilitySpec,
        inputs: &[FactInstance],
    ) -> Result<Vec<ProducedFact>, String> {
        let interaction: Defeasible<BlockedDeliveryInteractionPlan> =
            input(inputs, &fleetd_interaction_fact())?;
        let native: FleetdControlLift = input(inputs, &fleetd_control_native_fact())?;
        let target = lower_web(&interaction, &native).map_err(|error| error.to_string())?;
        Ok(vec![produced(
            web_target_ir_fact(),
            FactCoverage::Complete,
            &target,
        )?])
    }
}

impl CapabilityProvider for TerminalTargetProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        descriptor("fleetd_terminal_target", terminal_target_capability())
    }

    fn invoke(
        &self,
        _: &CapabilitySpec,
        inputs: &[FactInstance],
    ) -> Result<Vec<ProducedFact>, String> {
        let interaction: Defeasible<BlockedDeliveryInteractionPlan> =
            input(inputs, &fleetd_interaction_fact())?;
        let native: FleetdControlLift = input(inputs, &fleetd_control_native_fact())?;
        let target = lower_terminal(&interaction, &native).map_err(|error| error.to_string())?;
        Ok(vec![produced(
            terminal_target_ir_fact(),
            FactCoverage::Complete,
            &target,
        )?])
    }
}

pub fn web_surface(fact: &FactInstance) -> Result<WebSurface, String> {
    decode(&fact.payload)
}

pub fn terminal_surface(fact: &FactInstance) -> Result<TerminalSurface, String> {
    decode(&fact.payload)
}

fn descriptor(name: &str, capability: CapabilityId) -> ProviderDescriptor {
    ProviderDescriptor {
        id: ProviderId::new("dev.fleetd.provider.in_process", name, PACK_VERSION),
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
    decode(&instance.payload)
}

fn decode<T: DeserializeOwned>(value: &Value) -> Result<T, String> {
    serde_json::from_value(value.clone()).map_err(|error| error.to_string())
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

fn serialize<T: Serialize>(value: &T) -> Result<Value, RegistryError> {
    serde_json::to_value(value).map_err(|error| RegistryError::Serialization(error.to_string()))
}

fn coverage(exhaustive: bool) -> FactCoverage {
    if exhaustive {
        FactCoverage::Complete
    } else {
        FactCoverage::Partial
    }
}

fn require_same_source(sources: &[&SourceDocument]) -> Result<(), String> {
    let Some(first) = sources.first() else {
        return Err("source bundle is empty".to_owned());
    };
    if sources
        .iter()
        .any(|source| source.authority != first.authority || source.revision != first.revision)
    {
        return Err("Fleetd source artifacts do not share one authority and revision".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gooir_capability::FactDerivation;

    #[test]
    fn current_chain_is_discoverable_and_runnable_web_is_a_provider_need() {
        let registry = registry().unwrap();
        let sources = [
            openapi_source_fact(),
            api_rust_source_fact(),
            model_rust_source_fact(),
            delivery_rust_source_fact(),
        ];

        let web = registry
            .plan(sources.clone(), &web_target_ir_fact())
            .unwrap();
        let runnable = registry
            .plan(sources, &runnable_web_artifact_fact())
            .unwrap();

        assert!(web.is_executable());
        assert_eq!(web.steps.len(), 5);
        assert!(!runnable.is_executable());
        assert_eq!(runnable.needs.len(), 1);
        assert_eq!(runnable.needs[0].capability, runnable_web_capability());
    }

    #[test]
    fn source_fact_binds_exact_revision_into_its_identity() {
        let first =
            source_fact(openapi_source_fact(), "fleetd", "openapi.json", "a", "{}").unwrap();
        let second =
            source_fact(openapi_source_fact(), "fleetd", "openapi.json", "b", "{}").unwrap();

        assert_ne!(first.id, second.id);
        assert!(matches!(first.derivation, FactDerivation::Initial { .. }));
    }
}
