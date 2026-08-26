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
    FactInstance, FactType, PackManifestError, ProducedFact, ProviderDescriptor, ProviderId,
    RegistryError, register_pack,
};
use lift_defeasible::Defeasible;
use openapi_lifter::lift_openapi;
use semantics_data_model_v1::DataModel;
use semantics_fleetd_control_v0::BlockedDeliveryReview;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

mod conformance;

pub use conformance::{
    ArtifactFile, GitArtifactSource, RUNNABLE_WEB_ARTIFACT_SCHEMA, RunnableWebArtifact,
    RunnableWebConformanceProvider,
};

pub const PACK_VERSION: &str = "0.2.0";

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

/// Re-exported from the neutral pack. Declaring it twice would let an authored
/// specification and a lifted document populate two graphs that merely look
/// alike.
pub use gooir_datamodel_pack::data_model_fact;

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
    CapabilityId::new("org.gooi.capability", "lift_openapi_data_model", "0.2.0")
}

pub fn fleetd_native_capability() -> CapabilityId {
    CapabilityId::new("dev.fleetd.capability", "lift_control_native", "0.2.0")
}

pub fn fleetd_control_projection_capability() -> CapabilityId {
    CapabilityId::new("dev.fleetd.capability", "project_control", "0.2.0")
}

pub fn fleetd_interaction_capability() -> CapabilityId {
    CapabilityId::new("dev.fleetd.capability", "compose_interaction", "0.2.0")
}

pub fn web_target_capability() -> CapabilityId {
    CapabilityId::new("dev.fleetd.capability", "lower_web_target_ir", "0.2.0")
}

pub fn terminal_target_capability() -> CapabilityId {
    CapabilityId::new("dev.fleetd.capability", "lower_terminal_target_ir", "0.2.0")
}

pub fn runnable_web_capability() -> CapabilityId {
    CapabilityId::new(
        "dev.fleetd.capability",
        "generate_runnable_web_surface",
        "0.2.0",
    )
}

/// The capabilities this pack declares, as data.
pub const MANIFEST: &str = include_str!("../pack.json");

pub fn register_specs(registry: &mut CapabilityRegistry) -> Result<(), PackManifestError> {
    register_pack(registry, MANIFEST)
}

pub fn register_providers(registry: &mut CapabilityRegistry) -> Result<(), RegistryError> {
    gooir_provider::register_transform(
        registry,
        provider_id("openapi_data"),
        openapi_data_capability(),
        implementation("openapi_data"),
        |source: SourceDocument| lift_openapi(&source.text),
    )?;
    registry.register_provider(FleetdNativeProvider)?;
    gooir_provider::register_transform(
        registry,
        provider_id("fleetd_control_projection"),
        fleetd_control_projection_capability(),
        implementation("fleetd_control_projection"),
        |native: FleetdControlLift| project_blocked_delivery_review(&native),
    )?;
    registry.register_provider(FleetdInteractionProvider)?;
    registry.register_provider(WebTargetProvider)?;
    registry.register_provider(TerminalTargetProvider)?;
    Ok(())
}

pub fn registry() -> Result<CapabilityRegistry, PackManifestError> {
    let mut registry = CapabilityRegistry::default();
    register_specs(&mut registry)?;
    register_providers(&mut registry).map_err(PackManifestError::Registry)?;
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

struct FleetdNativeProvider;
struct FleetdInteractionProvider;
struct WebTargetProvider;
struct TerminalTargetProvider;

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

/// This pack publishes providers under its own package. The identity appears in
/// the derivation of every fact they produce, so it is this pack's to choose.
fn provider_id(name: &str) -> ProviderId {
    ProviderId::new("dev.fleetd.provider.in_process", name, PACK_VERSION)
}

fn implementation(name: &str) -> String {
    gooir_provider::digest(&[
        include_bytes!("lib.rs"),
        include_bytes!("../Cargo.toml"),
        include_bytes!("../../../Cargo.lock"),
        name.as_bytes(),
    ])
}

fn descriptor(name: &str, capability: CapabilityId) -> ProviderDescriptor {
    ProviderDescriptor {
        id: provider_id(name),
        capability,
        implementation_digest: implementation(name),
    }
}

fn input<T: serde::de::DeserializeOwned>(
    inputs: &[FactInstance],
    fact: &FactType,
) -> Result<T, String> {
    gooir_provider::input(inputs, fact)
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

fn decode<T: DeserializeOwned>(value: &Value) -> Result<T, String> {
    serde_json::from_value(value.clone()).map_err(|error| error.to_string())
}

fn serialize<T: Serialize>(value: &T) -> Result<Value, RegistryError> {
    serde_json::to_value(value).map_err(|error| RegistryError::Serialization(error.to_string()))
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

        assert!(web.has_provider_for_every_step());
        assert_eq!(web.steps.len(), 5);
        assert!(!runnable.has_provider_for_every_step());
        assert_eq!(runnable.needs.len(), 1);
        assert_eq!(
            runnable.needs[0].specification.id,
            runnable_web_capability()
        );
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
