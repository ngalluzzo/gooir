//! Semantically agnostic capability planning and in-process execution.
//!
//! A capability is a typed promise over exact fact identities. A provider is
//! one implementation of that promise. The planner understands neither the
//! meanings of facts nor domain verbs such as lift, analyze, or lower; it only
//! constructs derivations over multi-input capability edges.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::{error::Error, fmt};

macro_rules! exact_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
        pub struct $name {
            pub package: String,
            pub name: String,
            pub version: String,
        }

        impl $name {
            pub fn new(
                package: impl Into<String>,
                name: impl Into<String>,
                version: impl Into<String>,
            ) -> Self {
                Self {
                    package: package.into(),
                    name: name.into(),
                    version: version.into(),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}/{}@{}", self.package, self.name, self.version)
            }
        }
    };
}

exact_id!(FactType);
exact_id!(CapabilityId);
exact_id!(ProviderId);

/// Whether an input may carry unresolved defeats.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactAcceptance {
    CompleteOnly,
    PartialAllowed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Requirement {
    pub fact: FactType,
    pub acceptance: FactAcceptance,
}

impl Requirement {
    pub fn complete(fact: FactType) -> Self {
        Self {
            fact,
            acceptance: FactAcceptance::CompleteOnly,
        }
    }

    pub fn partial_allowed(fact: FactType) -> Self {
        Self {
            fact,
            acceptance: FactAcceptance::PartialAllowed,
        }
    }
}

/// One versioned transformation contract. `requires` is a conjunction, making
/// each capability a hyperedge rather than a simple graph edge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilitySpec {
    pub id: CapabilityId,
    pub requires: Vec<Requirement>,
    pub produces: Vec<FactType>,
    /// Exact suite a provider must eventually pass before its outputs may be
    /// admitted as trusted. Registration alone is not conformance.
    pub conformance_suite: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderDescriptor {
    pub id: ProviderId,
    pub capability: CapabilityId,
    /// Digest of the installed implementation artifact or source closure.
    pub implementation_digest: String,
}

/// Coverage is not trust. `Complete` means only that no defeater fired under
/// the producing capability's named mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactCoverage {
    Complete,
    Partial,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FactDerivation {
    Initial {
        origin: String,
    },
    Produced {
        capability: CapabilityId,
        provider: ProviderId,
        inputs: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FactInstance {
    pub id: String,
    pub fact_type: FactType,
    pub coverage: FactCoverage,
    pub payload: Value,
    pub derivation: FactDerivation,
}

impl FactInstance {
    pub fn initial(
        fact_type: FactType,
        coverage: FactCoverage,
        payload: Value,
        origin: impl Into<String>,
    ) -> Result<Self, RegistryError> {
        let derivation = FactDerivation::Initial {
            origin: origin.into(),
        };
        let id = fact_digest(&fact_type, coverage, &payload, &derivation)?;
        Ok(Self {
            id,
            fact_type,
            coverage,
            payload,
            derivation,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProducedFact {
    pub fact_type: FactType,
    pub coverage: FactCoverage,
    pub payload: Value,
}

pub trait CapabilityProvider: Send + Sync {
    fn descriptor(&self) -> ProviderDescriptor;

    fn invoke(
        &self,
        capability: &CapabilitySpec,
        inputs: &[FactInstance],
    ) -> Result<Vec<ProducedFact>, String>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlanStep {
    pub capability: CapabilityId,
    pub provider: Option<ProviderId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityNeed {
    pub capability: CapabilityId,
    pub requires: Vec<Requirement>,
    pub produces: Vec<FactType>,
    pub conformance_suite: String,
    pub reason: String,
}

/// The digest-bearing provider-neutral portion of one exact capability
/// invocation. Authority, ownership, deadlines, and settlement belong to the
/// orchestrator that durably consumes this request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityRequestBody {
    pub capability: CapabilityId,
    pub requires: Vec<Requirement>,
    pub inputs: Vec<FactInstance>,
    pub produces: Vec<FactType>,
    pub conformance_suite: String,
}

/// A missing capability bound to exact input fact instances. This is the
/// provider-neutral handoff from derivation planning to an orchestrator; it is
/// not itself a lease, authority grant, provider selection, or accepted result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityRequest {
    pub request_id: String,
    #[serde(flatten)]
    pub body: CapabilityRequestBody,
}

impl CapabilityRequest {
    pub fn bind(
        need: &CapabilityNeed,
        inputs: Vec<FactInstance>,
    ) -> Result<Self, CapabilityRequestError> {
        let mut required = need
            .requires
            .iter()
            .map(|requirement| (requirement.fact.clone(), requirement))
            .collect::<BTreeMap<_, _>>();
        if required.len() != need.requires.len() {
            return Err(CapabilityRequestError::InvalidNeed(
                "duplicate required fact identity".to_owned(),
            ));
        }
        let mut seen = BTreeSet::new();
        for input in &inputs {
            if !seen.insert(input.fact_type.clone()) {
                return Err(CapabilityRequestError::DuplicateInput(
                    input.fact_type.clone(),
                ));
            }
            let requirement = required
                .remove(&input.fact_type)
                .ok_or_else(|| CapabilityRequestError::UnexpectedInput(input.fact_type.clone()))?;
            if requirement.acceptance == FactAcceptance::CompleteOnly
                && input.coverage == FactCoverage::Partial
            {
                return Err(CapabilityRequestError::PartialInputRejected(
                    input.fact_type.clone(),
                ));
            }
        }
        if let Some(missing) = required.into_keys().next() {
            return Err(CapabilityRequestError::MissingInput(missing));
        }
        if need.produces.is_empty() {
            return Err(CapabilityRequestError::InvalidNeed(
                "produced fact set is empty".to_owned(),
            ));
        }
        let body = CapabilityRequestBody {
            capability: need.capability.clone(),
            requires: need.requires.clone(),
            inputs,
            produces: need.produces.clone(),
            conformance_suite: need.conformance_suite.clone(),
        };
        let request_id = request_digest(&body)?;
        Ok(Self { request_id, body })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DerivationPlan {
    pub target: FactType,
    pub steps: Vec<PlanStep>,
    pub needs: Vec<CapabilityNeed>,
}

impl DerivationPlan {
    pub fn is_executable(&self) -> bool {
        self.needs.is_empty() && self.steps.iter().all(|step| step.provider.is_some())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExecutionReport {
    pub target: FactInstance,
    pub facts: Vec<FactInstance>,
    pub steps: Vec<PlanStep>,
}

#[derive(Default)]
pub struct CapabilityRegistry {
    specs: BTreeMap<CapabilityId, CapabilitySpec>,
    providers: BTreeMap<ProviderId, Box<dyn CapabilityProvider>>,
    providers_by_capability: BTreeMap<CapabilityId, BTreeSet<ProviderId>>,
}

impl CapabilityRegistry {
    pub fn register_spec(&mut self, spec: CapabilitySpec) -> Result<(), RegistryError> {
        validate_spec(&spec)?;
        if self.specs.contains_key(&spec.id) {
            return Err(RegistryError::DuplicateCapability(spec.id));
        }
        self.specs.insert(spec.id.clone(), spec);
        Ok(())
    }

    pub fn register_provider(
        &mut self,
        provider: impl CapabilityProvider + 'static,
    ) -> Result<(), RegistryError> {
        let descriptor = provider.descriptor();
        validate_provider(&descriptor)?;
        if !self.specs.contains_key(&descriptor.capability) {
            return Err(RegistryError::UnknownCapability(
                descriptor.capability.clone(),
            ));
        }
        if self.providers.contains_key(&descriptor.id) {
            return Err(RegistryError::DuplicateProvider(descriptor.id));
        }
        self.providers_by_capability
            .entry(descriptor.capability.clone())
            .or_default()
            .insert(descriptor.id.clone());
        self.providers.insert(descriptor.id, Box::new(provider));
        Ok(())
    }

    pub fn specs(&self) -> impl Iterator<Item = &CapabilitySpec> {
        self.specs.values()
    }

    pub fn provider_descriptors(&self) -> Vec<ProviderDescriptor> {
        self.providers
            .values()
            .map(|provider| provider.descriptor())
            .collect()
    }

    pub fn plan(
        &self,
        initial: impl IntoIterator<Item = FactType>,
        target: &FactType,
    ) -> Result<DerivationPlan, PlanError> {
        let mut candidates = initial
            .into_iter()
            .map(|fact| (fact, Candidate::default()))
            .collect::<BTreeMap<_, _>>();

        let mut changed = true;
        while changed {
            changed = false;
            for spec in self.specs.values() {
                let Some(candidate) = candidate_for(spec, &candidates, self) else {
                    continue;
                };
                for output in &spec.produces {
                    let replace = candidates
                        .get(output)
                        .is_none_or(|existing| candidate.score() < existing.score());
                    if replace {
                        candidates.insert(output.clone(), candidate.clone());
                        changed = true;
                    }
                }
            }
        }

        let candidate = candidates
            .get(target)
            .ok_or_else(|| PlanError::Unreachable(target.clone()))?;
        let steps = candidate.steps.clone();
        let needs = steps
            .iter()
            .filter(|step| step.provider.is_none())
            .map(|step| {
                let spec = self
                    .specs
                    .get(&step.capability)
                    .expect("planned capability remains registered");
                CapabilityNeed {
                    capability: spec.id.clone(),
                    requires: spec.requires.clone(),
                    produces: spec.produces.clone(),
                    conformance_suite: spec.conformance_suite.clone(),
                    reason: "no installed provider implements this exact capability".to_owned(),
                }
            })
            .collect();
        Ok(DerivationPlan {
            target: target.clone(),
            steps,
            needs,
        })
    }

    pub fn execute(
        &self,
        plan: &DerivationPlan,
        initial: Vec<FactInstance>,
    ) -> Result<ExecutionReport, ExecutionError> {
        if !plan.is_executable() {
            return Err(ExecutionError::PlanNotExecutable(plan.needs.clone()));
        }
        let mut facts = BTreeMap::new();
        for fact in initial {
            if facts.insert(fact.fact_type.clone(), fact).is_some() {
                return Err(ExecutionError::AmbiguousInput);
            }
        }

        for step in &plan.steps {
            let spec = self
                .specs
                .get(&step.capability)
                .ok_or_else(|| ExecutionError::RegistryChanged(step.capability.clone()))?;
            let provider_id = step
                .provider
                .as_ref()
                .ok_or_else(|| ExecutionError::PlanNotExecutable(plan.needs.clone()))?;
            let provider = self
                .providers
                .get(provider_id)
                .ok_or_else(|| ExecutionError::ProviderUnavailable(provider_id.clone()))?;
            let mut inputs = Vec::with_capacity(spec.requires.len());
            for requirement in &spec.requires {
                let fact = facts
                    .get(&requirement.fact)
                    .ok_or_else(|| ExecutionError::MissingInput(requirement.fact.clone()))?;
                if requirement.acceptance == FactAcceptance::CompleteOnly
                    && fact.coverage == FactCoverage::Partial
                {
                    return Err(ExecutionError::PartialInputRejected {
                        capability: Box::new(spec.id.clone()),
                        fact: Box::new(requirement.fact.clone()),
                    });
                }
                inputs.push(fact.clone());
            }

            let produced =
                provider
                    .invoke(spec, &inputs)
                    .map_err(|error| ExecutionError::ProviderFailed {
                        provider: provider_id.clone(),
                        error,
                    })?;
            validate_outputs(spec, &produced)?;
            let input_ids = inputs
                .iter()
                .map(|fact| fact.id.clone())
                .collect::<Vec<_>>();
            for output in produced {
                let derivation = FactDerivation::Produced {
                    capability: spec.id.clone(),
                    provider: provider_id.clone(),
                    inputs: input_ids.clone(),
                };
                let id = fact_digest(
                    &output.fact_type,
                    output.coverage,
                    &output.payload,
                    &derivation,
                )
                .map_err(ExecutionError::Registry)?;
                facts.insert(
                    output.fact_type.clone(),
                    FactInstance {
                        id,
                        fact_type: output.fact_type,
                        coverage: output.coverage,
                        payload: output.payload,
                        derivation,
                    },
                );
            }
        }

        let target = facts
            .get(&plan.target)
            .cloned()
            .ok_or_else(|| ExecutionError::MissingTarget(plan.target.clone()))?;
        Ok(ExecutionReport {
            target,
            facts: facts.into_values().collect(),
            steps: plan.steps.clone(),
        })
    }
}

#[derive(Clone, Default)]
struct Candidate {
    steps: Vec<PlanStep>,
}

impl Candidate {
    fn score(&self) -> (usize, usize, String) {
        let missing = self
            .steps
            .iter()
            .filter(|step| step.provider.is_none())
            .count();
        let identity = self
            .steps
            .iter()
            .map(|step| step.capability.to_string())
            .collect::<Vec<_>>()
            .join("|");
        (missing, self.steps.len(), identity)
    }
}

fn candidate_for(
    spec: &CapabilitySpec,
    candidates: &BTreeMap<FactType, Candidate>,
    registry: &CapabilityRegistry,
) -> Option<Candidate> {
    let mut steps = Vec::new();
    for requirement in &spec.requires {
        let requirement_candidate = candidates.get(&requirement.fact)?;
        for step in &requirement_candidate.steps {
            if !steps
                .iter()
                .any(|existing: &PlanStep| existing.capability == step.capability)
            {
                steps.push(step.clone());
            }
        }
    }
    let provider = registry
        .providers_by_capability
        .get(&spec.id)
        .and_then(|providers| providers.first())
        .cloned();
    steps.push(PlanStep {
        capability: spec.id.clone(),
        provider,
    });
    Some(Candidate { steps })
}

fn validate_spec(spec: &CapabilitySpec) -> Result<(), RegistryError> {
    if spec.produces.is_empty() {
        return Err(RegistryError::InvalidCapability {
            capability: spec.id.clone(),
            reason: "a capability must produce at least one fact".to_owned(),
        });
    }
    if spec.conformance_suite.trim().is_empty() {
        return Err(RegistryError::InvalidCapability {
            capability: spec.id.clone(),
            reason: "a capability must name an exact conformance suite".to_owned(),
        });
    }
    let required = spec
        .requires
        .iter()
        .map(|requirement| &requirement.fact)
        .collect::<BTreeSet<_>>();
    if required.len() != spec.requires.len() {
        return Err(RegistryError::InvalidCapability {
            capability: spec.id.clone(),
            reason: "duplicate input fact identity".to_owned(),
        });
    }
    let produced = spec.produces.iter().collect::<BTreeSet<_>>();
    if produced.len() != spec.produces.len() {
        return Err(RegistryError::InvalidCapability {
            capability: spec.id.clone(),
            reason: "duplicate output fact identity".to_owned(),
        });
    }
    Ok(())
}

fn validate_provider(descriptor: &ProviderDescriptor) -> Result<(), RegistryError> {
    if !descriptor.implementation_digest.starts_with("sha256:") {
        return Err(RegistryError::InvalidProvider {
            provider: descriptor.id.clone(),
            reason: "implementation digest must be a sha256 identity".to_owned(),
        });
    }
    Ok(())
}

fn validate_outputs(spec: &CapabilitySpec, outputs: &[ProducedFact]) -> Result<(), ExecutionError> {
    let actual = outputs
        .iter()
        .map(|output| output.fact_type.clone())
        .collect::<Vec<_>>();
    let actual_set = actual.iter().collect::<BTreeSet<_>>();
    let expected_set = spec.produces.iter().collect::<BTreeSet<_>>();
    if actual.len() != actual_set.len() || actual_set != expected_set {
        return Err(ExecutionError::OutputContractViolation {
            capability: spec.id.clone(),
            expected: spec.produces.clone(),
            actual,
        });
    }
    Ok(())
}

fn fact_digest(
    fact_type: &FactType,
    coverage: FactCoverage,
    payload: &Value,
    derivation: &FactDerivation,
) -> Result<String, RegistryError> {
    let bytes = serde_json::to_vec(&(fact_type, coverage, payload, derivation))
        .map_err(|error| RegistryError::Serialization(error.to_string()))?;
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(7 + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}

fn request_digest(body: &CapabilityRequestBody) -> Result<String, CapabilityRequestError> {
    let bytes = serde_json_canonicalizer::to_vec(body)
        .map_err(|error| CapabilityRequestError::Serialization(error.to_string()))?;
    Ok(sha256_identity(&bytes))
}

fn sha256_identity(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(7 + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    DuplicateCapability(CapabilityId),
    DuplicateProvider(ProviderId),
    UnknownCapability(CapabilityId),
    InvalidCapability {
        capability: CapabilityId,
        reason: String,
    },
    InvalidProvider {
        provider: ProviderId,
        reason: String,
    },
    Serialization(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityRequestError {
    InvalidNeed(String),
    DuplicateInput(FactType),
    UnexpectedInput(FactType),
    MissingInput(FactType),
    PartialInputRejected(FactType),
    Serialization(String),
}

impl fmt::Display for CapabilityRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for CapabilityRequestError {}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RegistryError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanError {
    Unreachable(FactType),
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PlanError {}

#[derive(Clone, Debug, PartialEq)]
pub enum ExecutionError {
    PlanNotExecutable(Vec<CapabilityNeed>),
    AmbiguousInput,
    RegistryChanged(CapabilityId),
    ProviderUnavailable(ProviderId),
    MissingInput(FactType),
    PartialInputRejected {
        capability: Box<CapabilityId>,
        fact: Box<FactType>,
    },
    ProviderFailed {
        provider: ProviderId,
        error: String,
    },
    OutputContractViolation {
        capability: CapabilityId,
        expected: Vec<FactType>,
        actual: Vec<FactType>,
    },
    MissingTarget(FactType),
    Registry(RegistryError),
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for ExecutionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fact(name: &str) -> FactType {
        FactType::new("test", name, "1")
    }

    fn capability(
        name: &str,
        requires: Vec<Requirement>,
        produces: Vec<FactType>,
    ) -> CapabilitySpec {
        CapabilitySpec {
            id: CapabilityId::new("test", name, "1"),
            requires,
            produces,
            conformance_suite: format!("test/{name}@1"),
        }
    }

    struct CopyProvider {
        descriptor: ProviderDescriptor,
        output: FactType,
        coverage: FactCoverage,
    }

    impl CapabilityProvider for CopyProvider {
        fn descriptor(&self) -> ProviderDescriptor {
            self.descriptor.clone()
        }

        fn invoke(
            &self,
            _: &CapabilitySpec,
            inputs: &[FactInstance],
        ) -> Result<Vec<ProducedFact>, String> {
            Ok(vec![ProducedFact {
                fact_type: self.output.clone(),
                coverage: self.coverage,
                payload: json!({"inputs": inputs.iter().map(|input| &input.id).collect::<Vec<_>>() }),
            }])
        }
    }

    fn register_copy(registry: &mut CapabilityRegistry, spec: &CapabilitySpec, output: FactType) {
        registry
            .register_provider(CopyProvider {
                descriptor: ProviderDescriptor {
                    id: ProviderId::new("test.provider", &spec.id.name, "1"),
                    capability: spec.id.clone(),
                    implementation_digest: format!("sha256:{:064}", spec.id.name.len()),
                },
                output,
                coverage: FactCoverage::Complete,
            })
            .unwrap();
    }

    #[test]
    fn multi_input_capabilities_are_planned_as_hyperedges() {
        let a = fact("a");
        let b = fact("b");
        let c = fact("c");
        let spec = capability(
            "compose",
            vec![
                Requirement::complete(a.clone()),
                Requirement::complete(b.clone()),
            ],
            vec![c.clone()],
        );
        let mut registry = CapabilityRegistry::default();
        registry.register_spec(spec.clone()).unwrap();
        register_copy(&mut registry, &spec, c.clone());

        assert!(registry.plan([a.clone()], &c).is_err());
        let plan = registry.plan([a, b], &c).unwrap();
        assert!(plan.is_executable());
        assert_eq!(plan.steps.len(), 1);
    }

    #[test]
    fn absent_provider_becomes_a_machine_readable_capability_need() {
        let source = fact("source");
        let target = fact("target");
        let spec = capability(
            "missing",
            vec![Requirement::complete(source.clone())],
            vec![target.clone()],
        );
        let mut registry = CapabilityRegistry::default();
        registry.register_spec(spec.clone()).unwrap();

        let plan = registry.plan([source], &target).unwrap();

        assert!(!plan.is_executable());
        assert_eq!(plan.needs.len(), 1);
        assert_eq!(plan.needs[0].capability, spec.id);
    }

    #[test]
    fn exact_versions_do_not_match_implicitly() {
        let source_v1 = FactType::new("test", "source", "1");
        let source_v2 = FactType::new("test", "source", "2");
        let target = fact("target");
        let spec = capability(
            "exact",
            vec![Requirement::complete(source_v1)],
            vec![target.clone()],
        );
        let mut registry = CapabilityRegistry::default();
        registry.register_spec(spec).unwrap();

        assert_eq!(
            registry.plan([source_v2], &target),
            Err(PlanError::Unreachable(target))
        );
    }

    #[test]
    fn execution_binds_provenance_to_capability_provider_and_inputs() {
        let source = fact("source");
        let target = fact("target");
        let spec = capability(
            "copy",
            vec![Requirement::complete(source.clone())],
            vec![target.clone()],
        );
        let mut registry = CapabilityRegistry::default();
        registry.register_spec(spec.clone()).unwrap();
        register_copy(&mut registry, &spec, target.clone());
        let plan = registry.plan([source.clone()], &target).unwrap();
        let input = FactInstance::initial(
            source,
            FactCoverage::Complete,
            json!({"value": 1}),
            "fixture",
        )
        .unwrap();

        let report = registry.execute(&plan, vec![input.clone()]).unwrap();

        let FactDerivation::Produced {
            capability,
            provider: _,
            inputs,
        } = &report.target.derivation
        else {
            panic!("target is produced");
        };
        assert_eq!(capability, &spec.id);
        assert_eq!(inputs, &vec![input.id]);
    }

    #[test]
    fn complete_only_requirement_rejects_partial_input() {
        let source = fact("source");
        let target = fact("target");
        let spec = capability(
            "copy",
            vec![Requirement::complete(source.clone())],
            vec![target.clone()],
        );
        let mut registry = CapabilityRegistry::default();
        registry.register_spec(spec.clone()).unwrap();
        register_copy(&mut registry, &spec, target.clone());
        let plan = registry.plan([source.clone()], &target).unwrap();
        let input = FactInstance::initial(
            source.clone(),
            FactCoverage::Partial,
            json!(null),
            "fixture",
        )
        .unwrap();

        assert_eq!(
            registry.execute(&plan, vec![input]),
            Err(ExecutionError::PartialInputRejected {
                capability: Box::new(spec.id),
                fact: Box::new(source),
            })
        );
    }

    #[test]
    fn capability_request_binds_need_to_exact_input_fact() {
        let source = fact("source");
        let target = fact("target");
        let need = CapabilityNeed {
            capability: CapabilityId::new("test", "generate", "1"),
            requires: vec![Requirement::complete(source.clone())],
            produces: vec![target],
            conformance_suite: "test/generate@1".to_owned(),
            reason: "no provider".to_owned(),
        };
        let first = FactInstance::initial(
            source.clone(),
            FactCoverage::Complete,
            json!({"value": 1}),
            "fixture@1",
        )
        .unwrap();
        let second = FactInstance::initial(
            source,
            FactCoverage::Complete,
            json!({"value": 2}),
            "fixture@1",
        )
        .unwrap();

        let first_request = CapabilityRequest::bind(&need, vec![first.clone()]).unwrap();
        let replay = CapabilityRequest::bind(&need, vec![first]).unwrap();
        let changed = CapabilityRequest::bind(&need, vec![second]).unwrap();

        assert_eq!(first_request.request_id, replay.request_id);
        assert_ne!(first_request.request_id, changed.request_id);
        assert_eq!(first_request.body.capability, need.capability);
        assert_eq!(first_request.body.inputs.len(), 1);
    }
}
