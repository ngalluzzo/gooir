//! The product-facing derivation request and five terminal answers.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroUsize;

use gooir_capability::authority::{
    AdmissionDecision, AdmissionLedger, AdmissionPolicy, AuthorityRecord, ConformanceAuthority,
};
use gooir_capability::protocol::{
    AdmittedFactRef, CapabilityFailure, CapabilityInvocation, ConformanceSuiteId, LinkedInput,
};
use gooir_capability::{CapabilityId, Fact, PortName, ValueKindId, canonical_digest};
use gooir_package::PackageRegistry;
use gooir_planning::{
    AvailableOffer, BlockedRouteAnalysis, InvocationLink, PlanLimits, PlanningError,
    PlanningScopeDigest, RouteSelection, RouteValueSource, SelectedRoute, SelectedRouteStep,
    SemanticPlan, SemanticPlanner,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AdmittedOutput, DerivationHost, LinkedInvocationError, LinkedInvocationOutcome,
    WithheldDerivation, run_linked_invocation,
};

/// Bounds for one product-facing derivation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerivationLimits {
    pub planning: PlanLimits,
    pub max_inputs: NonZeroUsize,
    pub max_attesters: NonZeroUsize,
}

/// One exact host-available conformance inventory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttesterInventory {
    pub authorities: Vec<ConformanceAuthority>,
}

impl AttesterInventory {
    /// Constructs a canonical exact inventory within a caller-selected bound.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or duplicate authority, a serialization
    /// failure while establishing exact identity, or a bound violation.
    pub fn new(
        authorities: impl IntoIterator<Item = ConformanceAuthority>,
        max_attesters: NonZeroUsize,
    ) -> Result<Self, FacadeError> {
        let mut exact = BTreeMap::new();
        for authority in authorities {
            authority
                .validate()
                .map_err(|error| FacadeError::InvalidAttester(error.to_string()))?;
            let identity = canonical_digest(&authority).map_err(FacadeError::Serialization)?;
            if exact.contains_key(&identity) {
                return Err(FacadeError::DuplicateAttester);
            }
            if exact.len() == max_attesters.get() {
                return Err(FacadeError::LimitExceeded {
                    resource: "attesters",
                    limit: max_attesters.get(),
                });
            }
            exact.insert(identity, authority);
        }
        Ok(Self {
            authorities: exact.into_values().collect(),
        })
    }
}

/// One derivation question at the product door.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DerivationRequest {
    pub target: ValueKindId,
    pub inputs: Vec<AdmittedFactRef>,
    pub selection: DerivationSelection,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// Caller-owned selection policy for one request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum DerivationSelection {
    UniqueOnly {
        #[serde(default, flatten)]
        extensions: BTreeMap<String, Value>,
    },
    Explicit {
        selection: Box<ExplicitSelection>,
        #[serde(default, flatten)]
        extensions: BTreeMap<String, Value>,
    },
}

/// Exact request-input binding for one selected initial route dependency.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InitialBinding {
    pub capability: CapabilityId,
    pub input_port: PortName,
    pub admitted: AdmittedFactRef,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// Exact attester choice for one selected capability step.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SelectedAttester {
    pub capability: CapabilityId,
    pub authority: ConformanceAuthority,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// Complete caller-selected coordinates for an explicit derivation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExplicitSelection {
    pub route: SelectedRoute,
    pub initial_bindings: Vec<InitialBinding>,
    pub target_input: Option<AdmittedFactRef>,
    pub attesters: Vec<SelectedAttester>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// One admitted product answer. Every fact remains inside its authority chain.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProducedAnswer {
    pub target: AdmittedFactRef,
    pub admitted: Vec<AuthorityRecord>,
}

/// One exact missing independent attester.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttesterNeed {
    pub capability: CapabilityId,
    pub suite: ConformanceSuiteId,
}

/// Existing semantic routes whose available implementations cannot yet run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlockedAnswer {
    pub plan: SemanticPlan,
    pub selected_route: Option<SelectedRoute>,
    pub implementation: Option<BlockedRouteAnalysis>,
    pub missing_attesters: Vec<AttesterNeed>,
}

/// No declared semantic route reaches this target.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UnreachableAnswer {
    pub target: ValueKindId,
    pub initial_value_kinds: Vec<ValueKindId>,
    pub planning_scope_digest: PlanningScopeDigest,
    pub detail: String,
}

/// A request or policy refusal before an admitted target existed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Refusal {
    InvalidRequest {
        detail: String,
    },
    InvalidSelection {
        detail: String,
    },
    AmbiguousSelection {
        detail: String,
        alternatives: Vec<String>,
    },
    AdmissionPolicy {
        decision: Option<Box<AdmissionDecision>>,
        detail: String,
    },
}

/// Exact stage that prevented one fixed selection from producing a target.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureStage {
    Linking,
    ProviderHost,
    ProviderResult,
    ProviderUnable,
    AttesterHost,
    Assessment,
    Conformance,
    Admission,
}

/// Failure after route and implementation selection were fixed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FailedAnswer {
    pub route: SelectedRoute,
    pub capability: Option<CapabilityId>,
    pub stage: FailureStage,
    pub detail: String,
    pub provider_failure: Option<CapabilityFailure>,
    pub conformance: Option<WithheldDerivation>,
    pub admitted: Vec<AuthorityRecord>,
}

/// The five product outcomes and their distinct remedies.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "answer", content = "detail", rename_all = "snake_case")]
pub enum Answer {
    Produced(Box<ProducedAnswer>),
    Blocked(Box<BlockedAnswer>),
    Unreachable(Box<UnreachableAnswer>),
    Refused(Box<Refusal>),
    Failed(Box<FailedAnswer>),
}

impl Answer {
    #[must_use]
    pub const fn remedy(&self) -> &'static str {
        match self {
            Self::Produced(_) => "use the admitted fact and its exact authority",
            Self::Blocked(_) => "supply the missing implementation or attester",
            Self::Unreachable(_) => "declare a semantic capability route",
            Self::Refused(_) => "fix the request, selection, or admission policy",
            Self::Failed(_) => "inspect the fixed attempt and repair its failing stage",
        }
    }
}

/// Reusable façade bound to one immutable installed planning inventory.
#[derive(Clone, Debug)]
pub struct DerivationFacade {
    planner: SemanticPlanner,
    limits: DerivationLimits,
}

impl DerivationFacade {
    /// Constructs the façade before accepting a request.
    ///
    /// # Errors
    ///
    /// Returns an error when the installed package registry cannot form one
    /// exact, bounded semantic-planning inventory.
    pub fn new(registry: &PackageRegistry, limits: DerivationLimits) -> Result<Self, FacadeError> {
        let planner = SemanticPlanner::from_registry(registry, limits.planning)
            .map_err(FacadeError::Planning)?;
        Ok(Self { planner, limits })
    }

    /// Answers one request without collapsing any terminal outcome into `Err`.
    pub fn answer<H>(
        &self,
        ledger: &mut AdmissionLedger,
        policy: &AdmissionPolicy,
        attesters: &AttesterInventory,
        host: &mut H,
        request: &DerivationRequest,
    ) -> Answer
    where
        H: DerivationHost,
        H::Error: fmt::Display,
    {
        match self.prepare(ledger, policy, attesters, request) {
            Preparation::Answer(answer) => answer,
            Preparation::Ready(prepared) => self.execute(ledger, policy, host, &prepared),
        }
    }

    fn prepare(
        &self,
        ledger: &AdmissionLedger,
        policy: &AdmissionPolicy,
        attesters: &AttesterInventory,
        request: &DerivationRequest,
    ) -> Preparation {
        let inputs = match self.resolve_request(ledger, policy, attesters, request) {
            Ok(inputs) => inputs,
            Err(refusal) => return refused(refusal),
        };
        let initial_value_kinds = inputs
            .iter()
            .map(|input| input.fact.value_kind.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let plan = match self
            .planner
            .plan(initial_value_kinds.clone(), request.target.clone())
        {
            Ok(plan) => plan,
            Err(PlanningError::Unreachable(_)) => {
                return Preparation::Answer(Answer::Unreachable(Box::new(UnreachableAnswer {
                    target: request.target.clone(),
                    initial_value_kinds,
                    planning_scope_digest: self.planner.scope_digest().clone(),
                    detail: "no declared semantic route reaches the target".to_owned(),
                })));
            }
            Err(error) => {
                return refused(Refusal::InvalidRequest {
                    detail: error.to_string(),
                });
            }
        };

        match &request.selection {
            DerivationSelection::UniqueOnly { extensions } => {
                if !extensions.is_empty() {
                    return refused(Refusal::InvalidSelection {
                        detail: "unique-only selection carries unsupported extensions".to_owned(),
                    });
                }
                self.prepare_unique(plan, inputs, policy, attesters)
            }
            DerivationSelection::Explicit {
                selection,
                extensions,
            } => {
                if !extensions.is_empty() || !selection.extensions.is_empty() {
                    return refused(Refusal::InvalidSelection {
                        detail: "explicit selection carries unsupported extensions".to_owned(),
                    });
                }
                self.prepare_explicit(plan, inputs, policy, attesters, selection)
            }
        }
    }

    fn resolve_request(
        &self,
        ledger: &AdmissionLedger,
        policy: &AdmissionPolicy,
        attesters: &AttesterInventory,
        request: &DerivationRequest,
    ) -> Result<Vec<ResolvedInput>, Refusal> {
        if !request.target.is_well_formed() {
            return Err(Refusal::InvalidRequest {
                detail: "target value kind is not exact".to_owned(),
            });
        }
        if !request.extensions.is_empty() {
            return Err(Refusal::InvalidRequest {
                detail: "request carries unsupported extensions".to_owned(),
            });
        }
        if request.inputs.len() > self.limits.max_inputs.get() {
            return Err(Refusal::InvalidRequest {
                detail: format!(
                    "input count {} exceeds configured limit {}",
                    request.inputs.len(),
                    self.limits.max_inputs
                ),
            });
        }
        if attesters.authorities.len() > self.limits.max_attesters.get() {
            return Err(Refusal::InvalidRequest {
                detail: "attester inventory exceeds the façade limit".to_owned(),
            });
        }
        policy.validate().map_err(|error| Refusal::InvalidRequest {
            detail: error.to_string(),
        })?;

        let mut seen = BTreeSet::new();
        let mut resolved = Vec::with_capacity(request.inputs.len());
        for reference in &request.inputs {
            let key = (
                reference.fact_id.to_string(),
                reference.authority_record_id.to_string(),
            );
            if !seen.insert(key) {
                return Err(Refusal::InvalidRequest {
                    detail: "the same exact admitted input appears more than once".to_owned(),
                });
            }
            let value = ledger
                .resolve(reference)
                .map_err(|error| Refusal::InvalidRequest {
                    detail: error.to_string(),
                })?;
            resolved.push(ResolvedInput {
                reference: reference.clone(),
                fact: value.fact.clone(),
            });
        }
        Ok(resolved)
    }

    fn prepare_unique(
        &self,
        plan: SemanticPlan,
        inputs: Vec<ResolvedInput>,
        policy: &AdmissionPolicy,
        attesters: &AttesterInventory,
    ) -> Preparation {
        let (available_offers, policy_eligible_offers) =
            match eligible_offers(&plan, policy, attesters) {
                Ok(offers) => offers,
                Err(refusal) => return refused(refusal),
            };
        let route = match self.planner.select_route_with_available_offers(
            &plan,
            &policy_eligible_offers,
            RouteSelection::UniqueOnly,
        ) {
            Ok(route) => route,
            Err(PlanningError::AllRoutesBlocked(_)) => {
                match self.planner.select_route_with_available_offers(
                    &plan,
                    &available_offers,
                    RouteSelection::UniqueOnly,
                ) {
                    Err(PlanningError::AllRoutesBlocked(implementation)) => {
                        let missing_attesters =
                            blocked_attester_needs(&plan, &implementation, &available_offers);
                        return Preparation::Answer(Answer::Blocked(Box::new(BlockedAnswer {
                            plan,
                            selected_route: None,
                            implementation: Some(*implementation),
                            missing_attesters,
                        })));
                    }
                    Ok(_)
                    | Err(
                        PlanningError::AmbiguousCapabilityRoute | PlanningError::AmbiguousOffer(_),
                    ) => {
                        return refused(Refusal::AdmissionPolicy {
                            decision: None,
                            detail: "available complete selections are ineligible under the admission policy"
                                .to_owned(),
                        });
                    }
                    Err(error) => {
                        return refused(Refusal::InvalidSelection {
                            detail: error.to_string(),
                        });
                    }
                }
            }
            Err(PlanningError::AmbiguousCapabilityRoute | PlanningError::AmbiguousOffer(_)) => {
                return refused(Refusal::AmbiguousSelection {
                    detail:
                        "more than one complete policy-eligible route or implementation offer is available"
                            .to_owned(),
                    alternatives: plan_alternatives(&plan),
                });
            }
            Err(error) => {
                return refused(Refusal::InvalidSelection {
                    detail: error.to_string(),
                });
            }
        };

        let bindings = match unique_bindings(&route, &inputs) {
            Ok(bindings) => bindings,
            Err(refusal) => return refused(refusal),
        };
        let target_input = match unique_target_input(&route, &inputs) {
            Ok(target) => target,
            Err(refusal) => return refused(refusal),
        };
        let selected_attesters = match select_unique_attesters(&plan, &route, policy, attesters) {
            Ok(selected) => selected,
            Err(refusal) => return refused(refusal),
        };
        Preparation::Ready(Box::new(PreparedDerivation {
            plan,
            route,
            inputs,
            bindings,
            target_input,
            attesters: selected_attesters,
        }))
    }

    fn prepare_explicit(
        &self,
        plan: SemanticPlan,
        inputs: Vec<ResolvedInput>,
        policy: &AdmissionPolicy,
        inventory: &AttesterInventory,
        explicit: &ExplicitSelection,
    ) -> Preparation {
        if let Err(error) = explicit.route.validate(&plan, self.limits.planning) {
            return refused(Refusal::InvalidSelection {
                detail: error.to_string(),
            });
        }
        if explicit
            .initial_bindings
            .iter()
            .any(|binding| !binding.extensions.is_empty())
            || explicit
                .attesters
                .iter()
                .any(|attester| !attester.extensions.is_empty())
        {
            return refused(Refusal::InvalidSelection {
                detail: "explicit selection contains unsupported extensions".to_owned(),
            });
        }
        if let Err(detail) = validate_explicit_bindings(&explicit.route, &inputs, explicit) {
            return refused(Refusal::InvalidSelection { detail });
        }
        if let Err(detail) = validate_explicit_attesters(&plan, inventory, explicit) {
            return refused(Refusal::InvalidSelection { detail });
        }
        if let Some(rejected) = explicit
            .attesters
            .iter()
            .find(|selected| !policy.accepted_conformance.contains(&selected.authority))
        {
            return refused(Refusal::AdmissionPolicy {
                decision: None,
                detail: format!(
                    "admission policy rejects the selected attester for {}",
                    rejected.capability
                ),
            });
        }
        Preparation::Ready(Box::new(PreparedDerivation {
            plan,
            route: explicit.route.clone(),
            inputs,
            bindings: explicit.initial_bindings.clone(),
            target_input: explicit.target_input.clone(),
            attesters: explicit.attesters.clone(),
        }))
    }

    fn execute<H>(
        &self,
        ledger: &mut AdmissionLedger,
        policy: &AdmissionPolicy,
        host: &mut H,
        prepared: &PreparedDerivation,
    ) -> Answer
    where
        H: DerivationHost,
        H::Error: fmt::Display,
    {
        let mut produced = BTreeMap::<(CapabilityId, PortName), AdmittedOutput>::new();
        let mut admitted = Vec::new();
        for step in &prepared.route.steps {
            let outputs = match self.execute_step(
                ledger,
                policy,
                host,
                step,
                StepContext {
                    prepared,
                    produced: &produced,
                    admitted: &admitted,
                },
            ) {
                Ok(outputs) => outputs,
                Err(answer) => return answer,
            };
            for output in outputs {
                admitted.push(output.authority.clone());
                produced.insert((step.capability.clone(), output.port.clone()), output);
            }
        }

        let target = match &prepared.route.target {
            RouteValueSource::Initial { .. } => prepared.target_input.clone(),
            RouteValueSource::CapabilityOutput {
                capability,
                output_port,
                ..
            } => produced
                .get(&(capability.clone(), output_port.clone()))
                .map(|output| reference_for(&output.authority)),
        };
        let Some(target) = target else {
            return failed(
                &prepared.route,
                prepared.route.steps.last().map(|step| &step.capability),
                FailureStage::Admission,
                "selected target was not admitted".to_owned(),
                None,
                None,
                admitted,
            );
        };
        let resolved = match ledger.resolve(&target) {
            Ok(resolved) => resolved,
            Err(error) => {
                return failed(
                    &prepared.route,
                    prepared.route.steps.last().map(|step| &step.capability),
                    FailureStage::Admission,
                    error.to_string(),
                    None,
                    None,
                    admitted,
                );
            }
        };
        if prepared.route.steps.is_empty() {
            admitted.push(resolved.authority.clone());
        }
        Answer::Produced(Box::new(ProducedAnswer { target, admitted }))
    }

    fn execute_step<H>(
        &self,
        ledger: &mut AdmissionLedger,
        policy: &AdmissionPolicy,
        host: &mut H,
        step: &SelectedRouteStep,
        context: StepContext<'_>,
    ) -> Result<Vec<AdmittedOutput>, Answer>
    where
        H: DerivationHost,
        H::Error: fmt::Display,
    {
        let attester = context
            .prepared
            .attesters
            .iter()
            .find(|attester| attester.capability == step.capability)
            .ok_or_else(|| {
                failed(
                    &context.prepared.route,
                    Some(&step.capability),
                    FailureStage::Linking,
                    "selected attester is absent".to_owned(),
                    None,
                    None,
                    context.admitted.to_vec(),
                )
            })?;
        let invocation = self
            .link_step(
                context.prepared,
                step,
                context.produced,
                &attester.authority.suite,
            )
            .map_err(|(stage, detail)| {
                failed(
                    &context.prepared.route,
                    Some(&step.capability),
                    stage,
                    detail,
                    None,
                    None,
                    context.admitted.to_vec(),
                )
            })?;
        match run_linked_invocation(ledger, policy, &invocation, &attester.authority, host) {
            Ok(LinkedInvocationOutcome::Admitted(admission)) => Ok(admission.outputs),
            Ok(LinkedInvocationOutcome::AuthorityNotAccepted(withheld)) => {
                Err(Answer::Refused(Box::new(Refusal::AdmissionPolicy {
                    decision: Some(Box::new(withheld.decision)),
                    detail: "a passing candidate was withheld by the admission policy".to_owned(),
                })))
            }
            Ok(LinkedInvocationOutcome::ProviderUnable(provider_failure)) => Err(failed(
                &context.prepared.route,
                Some(&step.capability),
                FailureStage::ProviderUnable,
                "provider returned a typed inability".to_owned(),
                Some(*provider_failure),
                None,
                context.admitted.to_vec(),
            )),
            Ok(
                LinkedInvocationOutcome::ConformanceFailed(withheld)
                | LinkedInvocationOutcome::ConformanceIndeterminate(withheld),
            ) => Err(failed(
                &context.prepared.route,
                Some(&step.capability),
                FailureStage::Conformance,
                "independent conformance did not pass".to_owned(),
                None,
                Some(*withheld),
                context.admitted.to_vec(),
            )),
            Err(error) => {
                let (stage, detail) = linked_error(&error);
                Err(failed(
                    &context.prepared.route,
                    Some(&step.capability),
                    stage,
                    detail,
                    None,
                    None,
                    context.admitted.to_vec(),
                ))
            }
        }
    }

    fn link_step(
        &self,
        prepared: &PreparedDerivation,
        step: &SelectedRouteStep,
        produced: &BTreeMap<(CapabilityId, PortName), AdmittedOutput>,
        suite: &ConformanceSuiteId,
    ) -> Result<CapabilityInvocation, (FailureStage, String)> {
        planned_capability(&prepared.plan, &step.capability).ok_or_else(|| {
            (
                FailureStage::Linking,
                "selected capability left the exact plan".to_owned(),
            )
        })?;
        let mut linked_inputs = Vec::with_capacity(step.inputs.len());
        for dependency in &step.inputs {
            let source = match &dependency.source {
                RouteValueSource::Initial { .. } => prepared
                    .bindings
                    .iter()
                    .find(|binding| {
                        binding.capability == step.capability
                            && binding.input_port == dependency.input_port
                    })
                    .and_then(|binding| {
                        prepared
                            .inputs
                            .iter()
                            .find(|input| input.reference == binding.admitted)
                            .map(|input| (input.reference.clone(), input.fact.clone()))
                    }),
                RouteValueSource::CapabilityOutput {
                    capability,
                    output_port,
                    ..
                } => produced
                    .get(&(capability.clone(), output_port.clone()))
                    .map(|output| {
                        (
                            reference_for(&output.authority),
                            output.authority.fact.clone(),
                        )
                    }),
            };
            let (reference, fact) = source.ok_or_else(|| {
                (
                    FailureStage::Linking,
                    format!("selected input {} is not admitted", dependency.input_port),
                )
            })?;
            let input = LinkedInput::new(
                dependency.input_port.clone(),
                reference,
                fact,
                BTreeMap::new(),
            )
            .map_err(|error| (FailureStage::Linking, error.to_string()))?;
            linked_inputs.push(input);
        }
        self.planner
            .link_invocation(
                &prepared.plan,
                InvocationLink {
                    capability: &step.capability,
                    offer: &step.offer,
                    selection_extensions: BTreeMap::new(),
                    inputs: linked_inputs,
                    conformance_suite: suite.clone(),
                    invocation_extensions: BTreeMap::new(),
                },
            )
            .map_err(|error| (FailureStage::Linking, error.to_string()))
    }
}

#[derive(Debug)]
pub enum FacadeError {
    Planning(PlanningError),
    InvalidAttester(String),
    DuplicateAttester,
    LimitExceeded {
        resource: &'static str,
        limit: usize,
    },
    Serialization(String),
}

impl fmt::Display for FacadeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Planning(error) => error.fmt(formatter),
            Self::InvalidAttester(error) => write!(formatter, "invalid attester: {error}"),
            Self::DuplicateAttester => {
                formatter.write_str("attester inventory contains a duplicate")
            }
            Self::LimitExceeded { resource, limit } => {
                write!(
                    formatter,
                    "{resource} inventory exceeds configured limit {limit}"
                )
            }
            Self::Serialization(error) => write!(formatter, "inventory identity failed: {error}"),
        }
    }
}

impl std::error::Error for FacadeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Planning(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct ResolvedInput {
    reference: AdmittedFactRef,
    fact: Fact,
}

struct PreparedDerivation {
    plan: SemanticPlan,
    route: SelectedRoute,
    inputs: Vec<ResolvedInput>,
    bindings: Vec<InitialBinding>,
    target_input: Option<AdmittedFactRef>,
    attesters: Vec<SelectedAttester>,
}

#[derive(Clone, Copy)]
struct StepContext<'derivation> {
    prepared: &'derivation PreparedDerivation,
    produced: &'derivation BTreeMap<(CapabilityId, PortName), AdmittedOutput>,
    admitted: &'derivation [AuthorityRecord],
}

enum Preparation {
    Answer(Answer),
    Ready(Box<PreparedDerivation>),
}

fn refused(refusal: Refusal) -> Preparation {
    Preparation::Answer(Answer::Refused(Box::new(refusal)))
}

fn planned_capability<'plan>(
    plan: &'plan SemanticPlan,
    capability: &CapabilityId,
) -> Option<&'plan gooir_planning::PlannedCapability> {
    plan.capabilities
        .binary_search_by(|planned| planned.specification.id.cmp(capability))
        .ok()
        .map(|index| &plan.capabilities[index])
}

fn unique_bindings(
    route: &SelectedRoute,
    inputs: &[ResolvedInput],
) -> Result<Vec<InitialBinding>, Refusal> {
    let mut bindings = Vec::new();
    for step in &route.steps {
        for dependency in &step.inputs {
            let RouteValueSource::Initial { value_kind, .. } = &dependency.source else {
                continue;
            };
            let matching = inputs
                .iter()
                .filter(|input| &input.fact.value_kind == value_kind)
                .collect::<Vec<_>>();
            let [input] = matching.as_slice() else {
                return if matching.is_empty() {
                    Err(Refusal::InvalidSelection {
                        detail: format!("no admitted input supplies {value_kind}"),
                    })
                } else {
                    Err(Refusal::AmbiguousSelection {
                        detail: format!("more than one admitted input supplies {value_kind}"),
                        alternatives: matching
                            .iter()
                            .map(|input| {
                                format!(
                                    "{}+{}",
                                    input.reference.fact_id, input.reference.authority_record_id
                                )
                            })
                            .collect(),
                    })
                };
            };
            bindings.push(InitialBinding {
                capability: step.capability.clone(),
                input_port: dependency.input_port.clone(),
                admitted: input.reference.clone(),
                extensions: BTreeMap::new(),
            });
        }
    }
    Ok(bindings)
}

fn unique_target_input(
    route: &SelectedRoute,
    inputs: &[ResolvedInput],
) -> Result<Option<AdmittedFactRef>, Refusal> {
    let RouteValueSource::Initial { value_kind, .. } = &route.target else {
        return Ok(None);
    };
    let matching = inputs
        .iter()
        .filter(|input| &input.fact.value_kind == value_kind)
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [input] => Ok(Some(input.reference.clone())),
        [] => Err(Refusal::InvalidSelection {
            detail: format!("no admitted input supplies target {value_kind}"),
        }),
        _ => Err(Refusal::AmbiguousSelection {
            detail: format!("more than one admitted input supplies target {value_kind}"),
            alternatives: matching
                .iter()
                .map(|input| {
                    format!(
                        "{}+{}",
                        input.reference.fact_id, input.reference.authority_record_id
                    )
                })
                .collect(),
        }),
    }
}

fn select_unique_attesters(
    plan: &SemanticPlan,
    route: &SelectedRoute,
    policy: &AdmissionPolicy,
    inventory: &AttesterInventory,
) -> Result<Vec<SelectedAttester>, Refusal> {
    let mut selected = Vec::with_capacity(route.steps.len());
    for step in &route.steps {
        let planned = planned_capability(plan, &step.capability).ok_or_else(|| {
            Refusal::InvalidSelection {
                detail: format!("selected capability {} left the plan", step.capability),
            }
        })?;
        let suite = ConformanceSuiteId::parse(&planned.specification.default_conformance_suite)
            .map_err(|error| Refusal::InvalidSelection {
                detail: error.to_string(),
            })?;
        let accepted = independent_attesters(inventory, &suite, planned, &step.offer)
            .into_iter()
            .filter(|authority| policy.accepted_conformance.contains(*authority))
            .collect::<Vec<_>>();
        match accepted.as_slice() {
            [authority] => selected.push(SelectedAttester {
                capability: step.capability.clone(),
                authority: (*authority).clone(),
                extensions: BTreeMap::new(),
            }),
            [] => {
                return Err(Refusal::AdmissionPolicy {
                    decision: None,
                    detail: format!(
                        "admission policy accepts no available independent attester for {}",
                        step.capability,
                    ),
                });
            }
            _ => {
                return Err(Refusal::AmbiguousSelection {
                    detail: format!(
                        "more than one accepted attester is available for {}",
                        step.capability
                    ),
                    alternatives: accepted
                        .iter()
                        .filter_map(|authority| canonical_digest(*authority).ok())
                        .collect(),
                });
            }
        }
    }
    Ok(selected)
}

fn eligible_offers(
    plan: &SemanticPlan,
    policy: &AdmissionPolicy,
    attesters: &AttesterInventory,
) -> Result<(BTreeSet<AvailableOffer>, BTreeSet<AvailableOffer>), Refusal> {
    let mut available = BTreeSet::new();
    let mut policy_eligible = BTreeSet::new();
    for planned in &plan.capabilities {
        let suite = ConformanceSuiteId::parse(&planned.specification.default_conformance_suite)
            .map_err(|error| Refusal::InvalidSelection {
                detail: error.to_string(),
            })?;
        for offer in &planned.offers {
            let identity = AvailableOffer {
                capability: planned.specification.id.clone(),
                offer: offer.offer_id.clone(),
            };
            let exact = independent_attesters(attesters, &suite, planned, &offer.offer_id);
            if !exact.is_empty() {
                available.insert(identity.clone());
            }
            if exact
                .iter()
                .any(|authority| policy.accepted_conformance.contains(*authority))
            {
                policy_eligible.insert(identity);
            }
        }
    }
    Ok((available, policy_eligible))
}

fn blocked_attester_needs(
    plan: &SemanticPlan,
    blockage: &BlockedRouteAnalysis,
    available_offers: &BTreeSet<AvailableOffer>,
) -> Vec<AttesterNeed> {
    blockage
        .nodes
        .iter()
        .filter_map(|node| {
            let planned = planned_capability(plan, &node.capability)?;
            if planned.offers.is_empty()
                || planned.offers.iter().any(|offer| {
                    available_offers.contains(&AvailableOffer {
                        capability: node.capability.clone(),
                        offer: offer.offer_id.clone(),
                    })
                })
            {
                return None;
            }
            ConformanceSuiteId::parse(&planned.specification.default_conformance_suite)
                .ok()
                .map(|suite| AttesterNeed {
                    capability: node.capability.clone(),
                    suite,
                })
        })
        .collect()
}

fn independent_attesters<'inventory>(
    inventory: &'inventory AttesterInventory,
    suite: &ConformanceSuiteId,
    planned: &gooir_planning::PlannedCapability,
    offer_id: &gooir_capability::protocol::OfferId,
) -> Vec<&'inventory ConformanceAuthority> {
    let selected = planned
        .offers
        .iter()
        .find(|offer| &offer.offer_id == offer_id);
    inventory
        .authorities
        .iter()
        .filter(|authority| &authority.suite == suite)
        .filter(|authority| {
            selected.is_some_and(|offer| {
                authority.attester.implementation != offer.implementation
                    && authority.attester.artifact_digest != offer.artifact_digest
            })
        })
        .collect()
}

fn validate_explicit_bindings(
    route: &SelectedRoute,
    inputs: &[ResolvedInput],
    explicit: &ExplicitSelection,
) -> Result<(), String> {
    let expected = route
        .steps
        .iter()
        .flat_map(|step| {
            step.inputs
                .iter()
                .filter(|input| matches!(input.source, RouteValueSource::Initial { .. }))
                .map(|input| (step.capability.clone(), input.input_port.clone()))
        })
        .collect::<BTreeSet<_>>();
    let actual = explicit
        .initial_bindings
        .iter()
        .map(|binding| (binding.capability.clone(), binding.input_port.clone()))
        .collect::<BTreeSet<_>>();
    if expected != actual || actual.len() != explicit.initial_bindings.len() {
        return Err("explicit initial bindings do not exactly match the selected route".to_owned());
    }
    for binding in &explicit.initial_bindings {
        let expected_kind = route
            .steps
            .iter()
            .find(|step| step.capability == binding.capability)
            .and_then(|step| {
                step.inputs
                    .iter()
                    .find(|input| input.input_port == binding.input_port)
            })
            .and_then(|input| match &input.source {
                RouteValueSource::Initial { value_kind, .. } => Some(value_kind),
                RouteValueSource::CapabilityOutput { .. } => None,
            })
            .ok_or_else(|| "explicit binding does not name an initial route input".to_owned())?;
        if !inputs.iter().any(|input| {
            input.reference == binding.admitted && &input.fact.value_kind == expected_kind
        }) {
            return Err(format!(
                "explicit binding {}/{} names an absent authority or the wrong value kind",
                binding.capability, binding.input_port
            ));
        }
    }
    match &route.target {
        RouteValueSource::Initial { value_kind, .. } => {
            let Some(reference) = &explicit.target_input else {
                return Err("explicit initial target has no exact input binding".to_owned());
            };
            if !inputs
                .iter()
                .any(|input| input.reference == *reference && input.fact.value_kind == *value_kind)
            {
                return Err("explicit target input is absent or has the wrong kind".to_owned());
            }
        }
        RouteValueSource::CapabilityOutput { .. } if explicit.target_input.is_some() => {
            return Err("derived target unexpectedly carries an initial binding".to_owned());
        }
        RouteValueSource::CapabilityOutput { .. } => {}
    }
    Ok(())
}

fn validate_explicit_attesters(
    plan: &SemanticPlan,
    inventory: &AttesterInventory,
    explicit: &ExplicitSelection,
) -> Result<(), String> {
    let expected = explicit
        .route
        .steps
        .iter()
        .map(|step| step.capability.clone())
        .collect::<BTreeSet<_>>();
    let actual = explicit
        .attesters
        .iter()
        .map(|attester| attester.capability.clone())
        .collect::<BTreeSet<_>>();
    if expected != actual || actual.len() != explicit.attesters.len() {
        return Err("explicit attesters do not exactly cover the selected route".to_owned());
    }
    for selected in &explicit.attesters {
        if !inventory.authorities.contains(&selected.authority) {
            return Err(format!(
                "selected attester for {} is unavailable",
                selected.capability
            ));
        }
        let planned = planned_capability(plan, &selected.capability)
            .ok_or_else(|| format!("selected capability {} left the plan", selected.capability))?;
        let step = explicit
            .route
            .steps
            .iter()
            .find(|step| step.capability == selected.capability)
            .ok_or_else(|| "selected attester has no route step".to_owned())?;
        let offer = planned
            .offers
            .iter()
            .find(|offer| offer.offer_id == step.offer)
            .ok_or_else(|| "selected route offer left the plan".to_owned())?;
        if selected.authority.attester.implementation == offer.implementation
            || selected.authority.attester.artifact_digest == offer.artifact_digest
        {
            return Err(format!(
                "selected attester for {} is not independent of the provider",
                selected.capability
            ));
        }
    }
    Ok(())
}

fn plan_alternatives(plan: &SemanticPlan) -> Vec<String> {
    plan.capabilities
        .iter()
        .flat_map(|planned| {
            if planned.offers.is_empty() {
                vec![planned.specification.id.to_string()]
            } else {
                planned
                    .offers
                    .iter()
                    .map(|offer| format!("{}+{}", planned.specification.id, offer.offer_id))
                    .collect()
            }
        })
        .collect()
}

fn reference_for(authority: &AuthorityRecord) -> AdmittedFactRef {
    AdmittedFactRef {
        fact_id: authority.fact.id.clone(),
        authority_record_id: authority.authority_record_id.clone(),
        extensions: BTreeMap::new(),
    }
}

fn failed(
    route: &SelectedRoute,
    capability: Option<&CapabilityId>,
    stage: FailureStage,
    detail: String,
    provider_failure: Option<CapabilityFailure>,
    conformance: Option<WithheldDerivation>,
    admitted: Vec<AuthorityRecord>,
) -> Answer {
    Answer::Failed(Box::new(FailedAnswer {
        route: route.clone(),
        capability: capability.cloned(),
        stage,
        detail,
        provider_failure,
        conformance,
        admitted,
    }))
}

fn linked_error<E: fmt::Display>(error: &LinkedInvocationError<E>) -> (FailureStage, String) {
    let stage = match error {
        LinkedInvocationError::HostInvocation(_) => FailureStage::ProviderHost,
        LinkedInvocationError::InvalidHostResult(_) => FailureStage::ProviderResult,
        LinkedInvocationError::HostAssessment(_) => FailureStage::AttesterHost,
        LinkedInvocationError::InvalidHostAssessment(_)
        | LinkedInvocationError::SubstitutedAttester { .. }
        | LinkedInvocationError::InvalidAttester(_) => FailureStage::Assessment,
        LinkedInvocationError::Admission(_)
        | LinkedInvocationError::AdmissionReturnedSourceLink
        | LinkedInvocationError::AdmittedOutputUnresolvable { .. }
        | LinkedInvocationError::UnexpectedAdmissionDecision(_) => FailureStage::Admission,
        LinkedInvocationError::InvalidInvocation(_)
        | LinkedInvocationError::InvalidPolicy(_)
        | LinkedInvocationError::UnresolvedInput { .. }
        | LinkedInvocationError::SubstitutedInput { .. }
        | LinkedInvocationError::InvalidInputAuthority { .. } => FailureStage::Linking,
    };
    (stage, error.to_string())
}
