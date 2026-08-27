//! Writing a capability provider.
//!
//! [`neutral`] is the established 0.1 authoring surface for package-backed
//! providers that consume and produce the v1 neutral protocol. It keeps exact
//! contract validation at the boundary while reducing an implementation to
//! typed named inputs and outputs. Execution, artifact measurement,
//! conformance, and admission remain external-host responsibilities.
//!
//! The top-level registration helpers below are the older in-process
//! compatibility surface. New package-backed providers should use
//! [`neutral::Provider`].
//!
//! # Legacy in-process adapter
//!
//! A provider's job is one transformation. Everything around it — decoding the
//! input fact, deciding coverage, wrapping the output, describing itself — is
//! the same every time, and was written five times over before this existed.
//!
//! The manifest already declares what a capability requires and produces
//! ([0023](../../../docs/DECISIONS/0023_PACK_MANIFEST.md)), and `invoke`
//! already receives that spec. So a provider never restates its fact types: it
//! is handed the input its capability declares, and its result is published as
//! the output its capability declares.
//!
//! **Coverage is derived, never supplied.** A provider that could set its own
//! coverage could claim completeness it did not earn, which is the one thing a
//! `Defeasible` result exists to prevent.

use std::marker::PhantomData;

use gooir_capability::{
    CapabilityId, CapabilityProvider, CapabilityRegistry, CapabilitySpec, FactCoverage,
    FactInstance, FactType, ProducedFact, ProviderDescriptor, ProviderId, RegistryError,
};
use lift_defeasible::Defeasible;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

pub mod neutral;

/// Package under which in-process providers are identified.
pub const IN_PROCESS: &str = "org.gooi.provider.in_process";

/// A digest over the bytes that constitute an implementation.
///
/// Callers pass their own source and manifest bytes, because `include_bytes!`
/// resolves against the file that writes it. This is a registration
/// fingerprint, not a reproducible-build attestation of a dependency closure.
pub fn digest(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let finished = hasher.finalize();
    let mut out = String::with_capacity(7 + finished.len() * 2);
    out.push_str("sha256:");
    for byte in finished {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decodes the payload of one named input fact.
pub fn input<T: DeserializeOwned>(inputs: &[FactInstance], fact: &FactType) -> Result<T, String> {
    let instance = inputs
        .iter()
        .find(|candidate| &candidate.fact_type == fact)
        .ok_or_else(|| format!("input {fact} is missing"))?;
    serde_json::from_value(instance.payload.clone()).map_err(|error| error.to_string())
}

/// Publishes a defeasible result as a fact, taking coverage from its defeats.
pub fn publish<T: Serialize>(
    fact_type: FactType,
    result: &Defeasible<T>,
) -> Result<ProducedFact, String> {
    Ok(ProducedFact {
        fact_type,
        coverage: if result.is_exhaustive() {
            FactCoverage::Complete
        } else {
            FactCoverage::Partial
        },
        payload: serde_json::to_value(result).map_err(|error| error.to_string())?,
    })
}

/// What a transformation may hand back.
///
/// A lift that cannot parse its input has not produced a partial result — it
/// has produced nothing — so a fallible transformation is a real shape, not a
/// lapse. Accepting only `Defeasible<O>` would push every fallible lift back to
/// hand-written plumbing, which is exactly what this crate exists to delete.
pub trait Outcome<O> {
    fn into_defeasible(self) -> Result<Defeasible<O>, String>;
}

impl<O> Outcome<O> for Defeasible<O> {
    fn into_defeasible(self) -> Result<Defeasible<O>, String> {
        Ok(self)
    }
}

impl<O, E: std::fmt::Display> Outcome<O> for Result<Defeasible<O>, E> {
    fn into_defeasible(self) -> Result<Defeasible<O>, String> {
        self.map_err(|error| error.to_string())
    }
}

/// A provider that turns one declared input into one declared output.
struct Transform<I, O, F> {
    descriptor: ProviderDescriptor,
    run: F,
    shape: PhantomData<fn(I) -> O>,
}

impl<I, O, R, F> CapabilityProvider for Transform<I, O, F>
where
    I: DeserializeOwned + Send + Sync,
    O: Serialize + Send + Sync,
    R: Outcome<O>,
    F: Fn(I) -> R + Send + Sync,
{
    fn descriptor(&self) -> ProviderDescriptor {
        self.descriptor.clone()
    }

    fn invoke(
        &self,
        capability: &CapabilitySpec,
        inputs: &[FactInstance],
    ) -> Result<Vec<ProducedFact>, String> {
        let wanted = match capability.input_ports.as_slice() {
            [only] => only.value_kind.clone(),
            _ => return Err("a transform needs exactly one declared input port".to_owned()),
        };
        let produces = match capability.output_ports.as_slice() {
            [only] => only.value_kind.clone(),
            _ => return Err("a transform produces exactly one output port".to_owned()),
        };
        let decoded: I = input(inputs, &wanted)?;
        let result = (self.run)(decoded).into_defeasible()?;
        Ok(vec![publish(produces, &result)?])
    }
}

/// Registers a one-in, one-out provider.
///
/// The fact types come from the capability's own declaration, so they are named
/// once — in the manifest — rather than again here.
///
/// The identity is the caller's, not the SDK's. A provider belongs to whoever
/// publishes it, and its identity appears in the derivation of every fact it
/// produces; an SDK inventing one would rename other people's evidence.
pub fn register_transform<I, O, R, F>(
    registry: &mut CapabilityRegistry,
    id: ProviderId,
    capability: CapabilityId,
    implementation: String,
    run: F,
) -> Result<(), RegistryError>
where
    I: DeserializeOwned + Send + Sync + 'static,
    O: Serialize + Send + Sync + 'static,
    R: Outcome<O>,
    F: Fn(I) -> R + Send + Sync + 'static,
{
    registry.register_provider(Transform {
        descriptor: ProviderDescriptor {
            id,
            capability,
            implementation_digest: implementation,
        },
        run,
        shape: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use gooir_capability::{FactAcceptance, InputPort, OutputPort, PortName, read_pack};
    use lift_defeasible::{Defeat, DefeatKind};

    const PACK: &str = r#"{
      "protocol": "org.gooi.pack/v2",
      "capabilities": [{
        "id": "test.capability/double@1.0.0",
        "input_ports": [{ "name": "number", "value_kind": "test.fact/number@1.0.0", "acceptance": "complete_only" }],
        "output_ports": [{ "name": "result", "value_kind": "test.fact/doubled@1.0.0" }],
        "default_conformance_suite": "test.suite/double@1.0.0"
      }]
    }"#;

    fn registry_with(
        run: impl Fn(u32) -> Defeasible<u32> + Send + Sync + 'static,
    ) -> CapabilityRegistry {
        let mut registry = CapabilityRegistry::default();
        for spec in read_pack(PACK).unwrap().capabilities {
            registry.register_spec(spec).unwrap();
        }
        register_transform(
            &mut registry,
            ProviderId::new(IN_PROCESS, "double", "1.0.0"),
            CapabilityId::new("test.capability", "double", "1.0.0"),
            digest(&[b"implementation"]),
            run,
        )
        .unwrap();
        registry
    }

    fn number(value: u32) -> FactInstance {
        FactInstance::initial(
            FactType::new("test.fact", "number", "1.0.0"),
            FactCoverage::Complete,
            serde_json::json!(value),
            "test",
        )
        .unwrap()
    }

    #[test]
    fn a_transform_is_written_as_one_function() {
        let registry = registry_with(|n: u32| Defeasible::new(n * 2, "test/defeaters@1"));
        let target = FactType::new("test.fact", "doubled", "1.0.0");
        let plan = registry
            .plan([FactType::new("test.fact", "number", "1.0.0")], &target)
            .unwrap();
        let report = registry.execute(&plan, vec![number(21)]).unwrap();
        assert_eq!(report.target.payload["value"], 42);
        assert_eq!(report.target.coverage, FactCoverage::Complete);
    }

    /// The one affordance that matters: a provider cannot claim completeness it
    /// did not earn, because it never states coverage at all.
    #[test]
    fn a_recorded_defeat_makes_the_output_partial_without_being_asked() {
        let registry = registry_with(|n: u32| {
            let mut out = Defeasible::new(n * 2, "test/defeaters@1");
            out.defeat(Defeat::new(DefeatKind::LookedAndBlocked, "n", "too large"));
            out
        });
        let target = FactType::new("test.fact", "doubled", "1.0.0");
        let plan = registry
            .plan([FactType::new("test.fact", "number", "1.0.0")], &target)
            .unwrap();
        let report = registry.execute(&plan, vec![number(21)]).unwrap();
        assert_eq!(report.target.coverage, FactCoverage::Partial);
        assert_eq!(report.target.payload["defeats"][0]["subject"], "n");
    }

    #[test]
    fn a_capability_with_several_inputs_is_refused_rather_than_guessed() {
        let mut registry = CapabilityRegistry::default();
        registry
            .register_spec(CapabilitySpec {
                id: CapabilityId::new("test.capability", "double", "1.0.0"),
                input_ports: vec![
                    InputPort {
                        name: PortName::parse("number").unwrap(),
                        value_kind: FactType::new("test.fact", "number", "1.0.0"),
                        acceptance: FactAcceptance::CompleteOnly,
                        extensions: Default::default(),
                    },
                    InputPort {
                        name: PortName::parse("other").unwrap(),
                        value_kind: FactType::new("test.fact", "other", "1.0.0"),
                        acceptance: FactAcceptance::CompleteOnly,
                        extensions: Default::default(),
                    },
                ],
                output_ports: vec![OutputPort::new(
                    PortName::parse("result").unwrap(),
                    FactType::new("test.fact", "doubled", "1.0.0"),
                )],
                default_conformance_suite: "test.suite/double@1.0.0".to_owned(),
                extensions: Default::default(),
            })
            .unwrap();
        register_transform(
            &mut registry,
            ProviderId::new(IN_PROCESS, "double", "1.0.0"),
            CapabilityId::new("test.capability", "double", "1.0.0"),
            digest(&[b"x"]),
            |n: u32| Defeasible::new(n, "test/defeaters@1"),
        )
        .unwrap();

        let target = FactType::new("test.fact", "doubled", "1.0.0");
        let plan = registry
            .plan(
                [
                    FactType::new("test.fact", "number", "1.0.0"),
                    FactType::new("test.fact", "other", "1.0.0"),
                ],
                &target,
            )
            .unwrap();
        let error = registry
            .execute(
                &plan,
                vec![
                    number(1),
                    FactInstance::initial(
                        FactType::new("test.fact", "other", "1.0.0"),
                        FactCoverage::Complete,
                        serde_json::json!(0),
                        "test",
                    )
                    .unwrap(),
                ],
            )
            .expect_err("a transform must not silently pick one of several inputs");
        assert!(format!("{error:?}").contains("exactly one"), "{error:?}");
    }

    #[test]
    fn a_digest_changes_with_the_bytes_it_covers() {
        assert_ne!(digest(&[b"a"]), digest(&[b"b"]));
        assert_eq!(digest(&[b"a", b"b"]), digest(&[b"ab"]));
    }
}
