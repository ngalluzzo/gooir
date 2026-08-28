//! Bounded type-level planning over exact installed GOOIR declarations.
//!
//! A plan is a finite AND/OR graph slice from caller-held value kinds to one
//! requested value kind. It preserves every reachable capability route and
//! every installed implementation offer for each retained capability. It does
//! not choose a route, choose an offer, resolve admitted facts, execute an
//! implementation, establish conformance, or admit a result.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroUsize;

use gooir_capability::protocol::{
    CapabilityInvocation, CapabilityOffer, ConformanceSuiteId, ImplementationSelection,
    LinkedInput, OfferId, ProtocolError,
};
use gooir_capability::{CapabilityId, CapabilitySpec, PortName, ValueKindId, canonical_digest};
use gooir_package::PackageRegistry;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Exact versioned semantic-plan protocol emitted by this crate.
pub const SEMANTIC_PLAN_PROTOCOL: &str = "org.gooi.capability.plan/v1";

/// Exact versioned selected-route protocol emitted by this crate.
pub const SELECTED_ROUTE_PROTOCOL: &str = "org.gooi.capability.route/v1";

/// Exact versioned blocked-route analysis emitted by this crate.
pub const BLOCKED_ROUTE_PROTOCOL: &str = "org.gooi.capability.route-blockage/v1";

macro_rules! sha256_identity {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Parses an exact lowercase SHA-256 identity.
            ///
            /// # Errors
            ///
            /// Refuses every noncanonical digest spelling.
            pub fn parse(value: impl Into<String>) -> Result<Self, DigestParseError> {
                let value = value.into();
                if is_sha256(&value) {
                    Ok(Self(value))
                } else {
                    Err(DigestParseError(value))
                }
            }

            /// Returns the exact digest spelling.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

sha256_identity! {
    /// Content identity of one exact semantic plan.
    PlanId
}

sha256_identity! {
    /// Content identity of one exact selected route and its offer choices.
    RouteId
}

sha256_identity! {
    /// Digest of the complete specification and offer inventory considered.
    PlanningScopeDigest
}

/// The deliberately narrow route-selection operation supported by this crate.
///
/// It never ranks alternatives. Selection succeeds only when the plan has one
/// complete executable route and every step on that route has one exact offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteSelection {
    UniqueOnly,
}

/// One installed offer that a caller has established is available for route
/// selection in its external execution context.
///
/// Availability is deliberately supplied by the caller. The planner can
/// prove that the offer belongs to the exact inventory, but it cannot infer
/// whether an external host can execute or independently attest it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AvailableOffer {
    pub capability: CapabilityId,
    pub offer: OfferId,
}

/// Exact source of one value consumed or returned by a selected route.
///
/// Initial values remain type-level. Exact facts and their authority records
/// enter later through [`SemanticPlanner::link_invocation`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum RouteValueSource {
    Initial {
        value_kind: ValueKindId,
        #[serde(default, flatten)]
        extensions: BTreeMap<String, Value>,
    },
    CapabilityOutput {
        capability: CapabilityId,
        output_port: PortName,
        #[serde(default, flatten)]
        extensions: BTreeMap<String, Value>,
    },
}

/// One exact named input-port dependency of a selected capability step.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RouteInputDependency {
    pub input_port: PortName,
    pub source: RouteValueSource,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// One capability on a route and its exact implementation offer choice.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SelectedRouteStep {
    pub capability: CapabilityId,
    pub offer: OfferId,
    pub inputs: Vec<RouteInputDependency>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// One complete, deterministic, type-level route through a [`SemanticPlan`].
///
/// Steps are in canonical dependency order. The document carries no facts,
/// authority decisions, execution state, or admission claims.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SelectedRoute {
    pub route_id: RouteId,
    pub protocol: String,
    pub plan_id: PlanId,
    pub target: RouteValueSource,
    pub steps: Vec<SelectedRouteStep>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// One exact capability output that can supply a blocked input or target.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RouteOutputRef {
    pub capability: CapabilityId,
    pub output_port: PortName,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// One named input that is unavailable in the offer-aware graph.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlockedRouteInput {
    pub input_port: PortName,
    pub value_kind: ValueKindId,
    pub producer_alternatives: Vec<RouteOutputRef>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// One capability alternative that cannot currently execute.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlockedRouteNode {
    pub capability: CapabilityId,
    pub missing_offer: bool,
    pub blocked_inputs: Vec<BlockedRouteInput>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// Bounded AND/OR blockage information for a plan whose target has no
/// executable route.
///
/// The graph shares capability nodes instead of enumerating every route.
/// `missing_needs` contains the complete declarations that need an offer;
/// named input edges retain the route branches on which each need occurs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlockedRouteAnalysis {
    pub protocol: String,
    pub plan_id: PlanId,
    pub target_value_kind: ValueKindId,
    pub target_alternatives: Vec<RouteOutputRef>,
    pub nodes: Vec<BlockedRouteNode>,
    pub missing_needs: Vec<CapabilitySpec>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// A malformed digest identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestParseError(String);

impl fmt::Display for DigestParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "`{}` is not an exact lowercase SHA-256 identity",
            self.0
        )
    }
}

impl std::error::Error for DigestParseError {}

/// Explicit finite bounds for one planner inventory.
///
/// There is deliberately no default. A host must choose the amount of
/// ecosystem material it is willing to inspect as one exact planning scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlanLimits {
    pub max_capabilities: NonZeroUsize,
    pub max_value_kinds: NonZeroUsize,
    pub max_ports_per_capability: NonZeroUsize,
    pub max_total_ports: NonZeroUsize,
    pub max_offers_per_capability: NonZeroUsize,
    pub max_total_offers: NonZeroUsize,
}

/// Caller-owned coordinates and exact inputs for one explicit link operation.
///
/// This is an in-memory substrate argument, not a serialized semantic
/// protocol. The resulting [`CapabilityInvocation`] is the portable document.
#[derive(Debug)]
pub struct InvocationLink<'identity> {
    /// Exact capability selected from the plan.
    pub capability: &'identity CapabilityId,
    /// Exact installed offer selected from that capability's alternatives.
    pub offer: &'identity OfferId,
    /// Caller-understood implementation-selection extension data.
    pub selection_extensions: BTreeMap<String, Value>,
    /// Exact named fact and authority-record references.
    pub inputs: Vec<LinkedInput>,
    /// Exact conformance obligation for the invocation.
    pub conformance_suite: ConformanceSuiteId,
    /// Caller-understood invocation extension data.
    pub invocation_extensions: BTreeMap<String, Value>,
}

/// One relevant capability and every installed offer that implements it.
///
/// An empty `offers` vector is an explicit ecosystem need. It is not silently
/// removed from the graph merely because no implementation is installed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PlannedCapability {
    pub specification: CapabilitySpec,
    pub offers: Vec<CapabilityOffer>,
    /// Unknown plan-node data survives round trips but prevents linking until
    /// a caller installs code that understands it.
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// One content-identified finite graph slice and its exact inventory scope.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SemanticPlan {
    pub plan_id: PlanId,
    pub protocol: String,
    pub planning_scope_digest: PlanningScopeDigest,
    pub initial_value_kinds: Vec<ValueKindId>,
    pub target_value_kind: ValueKindId,
    /// Optional exact capability output requested by the caller.
    ///
    /// When absent, the plan retains the original value-kind query semantics.
    /// When present, this coordinate is the root of the graph slice even when
    /// the same value kind is already available as an initial value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_output: Option<RouteOutputRef>,
    pub capabilities: Vec<PlannedCapability>,
    /// Unknown plan-root data survives round trips but prevents linking until
    /// a caller installs code that understands it.
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl SemanticPlan {
    /// Revalidates the bounded graph slice and its content identity.
    ///
    /// Scope completeness is established when [`SemanticPlanner`] constructs
    /// the plan from a complete inventory. This method proves that the
    /// resulting document has not changed; it cannot recreate omitted external
    /// inventory from a digest alone.
    ///
    /// # Errors
    ///
    /// Refuses invalid declarations, offers, ordering, reachability,
    /// extensions that shadow known fields, or a changed plan identity.
    pub fn validate(&self, limits: PlanLimits) -> Result<(), PlanningError> {
        self.validate_limits(limits)?;
        self.validate_structure()?;
        let expected = plan_digest(self)?;
        if self.plan_id.as_str() != expected {
            return Err(PlanningError::PlanIdentityMismatch {
                expected,
                actual: self.plan_id.to_string(),
            });
        }
        Ok(())
    }

    /// Selects a complete type-level route without ranking any alternative.
    ///
    /// [`RouteSelection::UniqueOnly`] succeeds only when exactly one
    /// executable capability/output-port route exists and every capability on
    /// it has exactly one offer. Providerless alternatives are ignored only
    /// when another complete route does not depend on them.
    ///
    /// # Errors
    ///
    /// Refuses an invalid or extension-augmented plan, a fully blocked plan,
    /// more than one complete route, or more than one offer on the sole route.
    pub fn select_route(
        &self,
        selection: RouteSelection,
        limits: PlanLimits,
    ) -> Result<SelectedRoute, PlanningError> {
        self.validate(limits)?;
        if !self.extensions.is_empty() {
            return Err(PlanningError::UnsupportedPlanExtensions);
        }
        if let Some(planned) = self
            .capabilities
            .iter()
            .find(|planned| !planned.extensions.is_empty())
        {
            return Err(PlanningError::UnsupportedPlanNodeExtensions(
                planned.specification.id.clone(),
            ));
        }
        if self
            .target_output
            .as_ref()
            .is_some_and(|target| !target.extensions.is_empty())
        {
            return Err(PlanningError::UnsupportedTargetExtensions);
        }
        match selection {
            RouteSelection::UniqueOnly => select_unique_route(self),
        }
    }

    fn validate_limits(&self, limits: PlanLimits) -> Result<(), PlanningError> {
        require_limit(
            "plan capabilities",
            self.capabilities.len(),
            limits.max_capabilities,
        )?;
        require_limit(
            "plan initial value kinds",
            self.initial_value_kinds.len(),
            limits.max_value_kinds,
        )?;

        let mut value_kinds = BTreeSet::new();
        let mut total_ports = 0_usize;
        let mut total_offers = 0_usize;
        for value_kind in &self.initial_value_kinds {
            insert_bounded_value_kind(&mut value_kinds, value_kind, limits.max_value_kinds)?;
        }
        insert_bounded_value_kind(
            &mut value_kinds,
            &self.target_value_kind,
            limits.max_value_kinds,
        )?;
        for planned in &self.capabilities {
            let ports = planned
                .specification
                .input_ports
                .len()
                .checked_add(planned.specification.output_ports.len())
                .ok_or(PlanningError::LimitOverflow("plan total ports"))?;
            require_limit(
                "plan ports per capability",
                ports,
                limits.max_ports_per_capability,
            )?;
            total_ports = total_ports
                .checked_add(ports)
                .ok_or(PlanningError::LimitOverflow("plan total ports"))?;
            require_limit("plan total ports", total_ports, limits.max_total_ports)?;
            require_limit(
                "plan offers per capability",
                planned.offers.len(),
                limits.max_offers_per_capability,
            )?;
            total_offers = total_offers
                .checked_add(planned.offers.len())
                .ok_or(PlanningError::LimitOverflow("plan total offers"))?;
            require_limit("plan total offers", total_offers, limits.max_total_offers)?;
            for input in &planned.specification.input_ports {
                insert_bounded_value_kind(
                    &mut value_kinds,
                    &input.value_kind,
                    limits.max_value_kinds,
                )?;
            }
            for output in &planned.specification.output_ports {
                insert_bounded_value_kind(
                    &mut value_kinds,
                    &output.value_kind,
                    limits.max_value_kinds,
                )?;
            }
        }
        Ok(())
    }

    /// Capabilities in this plan that currently have no installed offer.
    ///
    /// These are explicit needs in alternate graph branches; their presence
    /// does not claim that every route to the target is blocked.
    pub fn needs(&self) -> impl Iterator<Item = &CapabilitySpec> {
        self.capabilities
            .iter()
            .filter(|planned| planned.offers.is_empty())
            .map(|planned| &planned.specification)
    }

    fn planned_capability(
        &self,
        capability: &CapabilityId,
    ) -> Result<&PlannedCapability, PlanningError> {
        self.capabilities
            .binary_search_by(|item| item.specification.id.cmp(capability))
            .ok()
            .map(|index| &self.capabilities[index])
            .ok_or_else(|| PlanningError::CapabilityNotPlanned(capability.clone()))
    }

    fn validate_structure(&self) -> Result<(), PlanningError> {
        if self.protocol != SEMANTIC_PLAN_PROTOCOL {
            return Err(PlanningError::ProtocolMismatch {
                actual: self.protocol.clone(),
            });
        }
        validate_extensions(
            "semantic plan",
            &self.extensions,
            &[
                "plan_id",
                "protocol",
                "planning_scope_digest",
                "initial_value_kinds",
                "target_value_kind",
                "target_output",
                "capabilities",
            ],
        )?;
        validate_sorted_value_kinds(&self.initial_value_kinds)?;
        if !self.target_value_kind.is_well_formed() {
            return Err(PlanningError::InvalidValueKind(
                self.target_value_kind.clone(),
            ));
        }

        if let Some(target) = &self.target_output {
            validate_extensions(
                "semantic plan target output",
                &target.extensions,
                &["capability", "output_port"],
            )?;
        }

        let mut previous = None;
        let mut specifications = BTreeMap::new();
        for planned in &self.capabilities {
            planned.specification.validate().map_err(|error| {
                PlanningError::InvalidSpecification {
                    capability: planned.specification.id.clone(),
                    detail: error.to_string(),
                }
            })?;
            if previous.is_some_and(|prior: &CapabilityId| prior >= &planned.specification.id) {
                return Err(PlanningError::NonCanonicalCapabilityOrder);
            }
            previous = Some(&planned.specification.id);
            validate_extensions(
                "planned capability",
                &planned.extensions,
                &["specification", "offers"],
            )?;
            let mut previous_offer = None;
            for offer in &planned.offers {
                offer
                    .validate()
                    .map_err(|error| PlanningError::InvalidOffer {
                        offer: offer.offer_id.clone(),
                        detail: error.to_string(),
                    })?;
                if offer.capability != planned.specification.id {
                    return Err(PlanningError::OfferCapabilityMismatch {
                        offer: offer.offer_id.clone(),
                        expected: Box::new(planned.specification.id.clone()),
                        actual: Box::new(offer.capability.clone()),
                    });
                }
                if previous_offer.is_some_and(|prior: &OfferId| prior >= &offer.offer_id) {
                    return Err(PlanningError::NonCanonicalOfferOrder(
                        planned.specification.id.clone(),
                    ));
                }
                previous_offer = Some(&offer.offer_id);
            }
            specifications.insert(
                planned.specification.id.clone(),
                planned.specification.clone(),
            );
        }

        validate_graph_slice(self, &specifications)
    }
}

impl SelectedRoute {
    /// Revalidates this route against the exact plan it selects from.
    ///
    /// Validation checks the plan and route content identities, exact offer
    /// membership, named input-port dependencies, output coordinates,
    /// canonical dependency order, and the absence of unused steps.
    ///
    /// # Errors
    ///
    /// Refuses every mismatch, substitution, noncanonical ordering, dangling
    /// dependency, type mismatch, unused step, or changed route identity.
    pub fn validate(&self, plan: &SemanticPlan, limits: PlanLimits) -> Result<(), PlanningError> {
        plan.validate(limits)?;
        self.validate_structure(plan)?;
        let expected = route_digest(self)?;
        if self.route_id.as_str() != expected {
            return Err(PlanningError::RouteIdentityMismatch {
                expected,
                actual: self.route_id.to_string(),
            });
        }
        Ok(())
    }

    fn validate_structure(&self, plan: &SemanticPlan) -> Result<(), PlanningError> {
        if self.protocol != SELECTED_ROUTE_PROTOCOL {
            return Err(PlanningError::RouteProtocolMismatch {
                actual: self.protocol.clone(),
            });
        }
        if self.plan_id != plan.plan_id {
            return Err(PlanningError::RoutePlanMismatch {
                expected: plan.plan_id.clone(),
                actual: self.plan_id.clone(),
            });
        }
        validate_extensions(
            "selected route",
            &self.extensions,
            &["route_id", "protocol", "plan_id", "target", "steps"],
        )?;

        let planned = plan
            .capabilities
            .iter()
            .map(|capability| (capability.specification.id.clone(), capability))
            .collect::<BTreeMap<_, _>>();
        let mut selected = BTreeMap::new();
        for step in &self.steps {
            validate_extensions(
                &format!("selected route step `{}`", step.capability),
                &step.extensions,
                &["capability", "offer", "inputs"],
            )?;
            let Some(planned_capability) = planned.get(&step.capability) else {
                return Err(PlanningError::CapabilityNotPlanned(step.capability.clone()));
            };
            if selected.contains_key(&step.capability) {
                return Err(PlanningError::DuplicateRouteCapability(
                    step.capability.clone(),
                ));
            }
            if planned_capability
                .offers
                .binary_search_by(|offer| offer.offer_id.cmp(&step.offer))
                .is_err()
            {
                return Err(PlanningError::OfferNotPlanned {
                    capability: step.capability.clone(),
                    offer: step.offer.clone(),
                });
            }
            validate_route_inputs(step, &planned_capability.specification, plan, &selected)?;
            selected.insert(step.capability.clone(), step);
        }

        let expected_order = canonical_step_order(&selected)?;
        let actual_order = self
            .steps
            .iter()
            .map(|step| step.capability.clone())
            .collect::<Vec<_>>();
        if actual_order != expected_order {
            return Err(PlanningError::NonCanonicalRouteStepOrder);
        }
        validate_route_target(&self.target, plan, &selected)?;
        validate_no_unused_steps(&self.target, &selected)?;
        Ok(())
    }
}

/// Immutable complete planning inventory built from exact declarations and
/// offers. Construction performs no discovery or selection.
#[derive(Clone, Debug)]
pub struct SemanticPlanner {
    specifications: BTreeMap<CapabilityId, CapabilitySpec>,
    offers: BTreeMap<CapabilityId, Vec<CapabilityOffer>>,
    value_kinds: BTreeSet<ValueKindId>,
    scope_digest: PlanningScopeDigest,
    limits: PlanLimits,
}

impl SemanticPlanner {
    /// Copies the complete installed capability and offer inventory from a
    /// package registry.
    ///
    /// # Errors
    ///
    /// Refuses invalid or duplicate declarations, orphaned offers, or any
    /// configured bound before returning a partial planner.
    pub fn from_registry(
        registry: &PackageRegistry,
        limits: PlanLimits,
    ) -> Result<Self, PlanningError> {
        Self::new(
            registry
                .capabilities()
                .map(|(_owner, specification)| specification.clone()),
            registry.offers().cloned(),
            limits,
        )
    }

    /// Builds one exact planner from a caller-supplied complete inventory.
    ///
    /// Input order is irrelevant. Duplicate identities are refused rather
    /// than silently normalized.
    ///
    /// # Errors
    ///
    /// Refuses invalid or duplicate declarations, orphaned offers, or any
    /// configured bound before returning a partial planner.
    pub fn new(
        specifications: impl IntoIterator<Item = CapabilitySpec>,
        offers: impl IntoIterator<Item = CapabilityOffer>,
        limits: PlanLimits,
    ) -> Result<Self, PlanningError> {
        let (exact_specifications, value_kinds) = collect_specifications(specifications, limits)?;
        let exact_offers = collect_offers(offers, &exact_specifications, limits)?;
        let by_capability = offers_by_capability(&exact_offers);
        let scope_digest = planning_scope_digest(
            exact_specifications.values().collect(),
            exact_offers.values().collect(),
        )?;
        Ok(Self {
            specifications: exact_specifications,
            offers: by_capability,
            value_kinds,
            scope_digest,
            limits,
        })
    }

    /// Complete exact inventory digest considered by every emitted plan.
    #[must_use]
    pub const fn scope_digest(&self) -> &PlanningScopeDigest {
        &self.scope_digest
    }

    /// Selects a route from a plan produced by this exact inventory snapshot.
    ///
    /// This is the inventory-bound form of [`SemanticPlan::select_route`]. It
    /// additionally refuses a plan whose retained declarations or offer lists
    /// were substituted, removed, or augmented after planning.
    ///
    /// # Errors
    ///
    /// Refuses an invalid plan, an inventory mismatch, ambiguity, or a plan
    /// whose complete routes are all blocked by missing offers.
    pub fn select_route(
        &self,
        plan: &SemanticPlan,
        selection: RouteSelection,
    ) -> Result<SelectedRoute, PlanningError> {
        self.validate_exact_plan(plan)?;
        plan.select_route(selection, self.limits)
    }

    /// Selects a route using only an exact caller-supplied subset of installed
    /// offers while retaining the identity of the complete semantic plan.
    ///
    /// This is the bridge for external availability constraints such as host
    /// launch support or independent attester inventory. The subset cannot add
    /// or alter inventory. Empty or removed choices remain visible as blockage
    /// against the original plan rather than becoming a different plan.
    ///
    /// # Errors
    ///
    /// Refuses an invalid or substituted plan, a subset entry absent from the
    /// plan, ambiguity, or a plan whose routes are all blocked by the supplied
    /// availability subset.
    pub fn select_route_with_available_offers(
        &self,
        plan: &SemanticPlan,
        available_offers: &BTreeSet<AvailableOffer>,
        selection: RouteSelection,
    ) -> Result<SelectedRoute, PlanningError> {
        let routes = self.route_alternatives_with_available_offers(plan, available_offers)?;
        match selection {
            RouteSelection::UniqueOnly => match routes.as_slice() {
                [route] => Ok(route.clone()),
                [first, second] => Err(route_ambiguity(first, second)),
                _ => unreachable!("route alternatives are capped at two"),
            },
        }
    }

    /// Returns up to two exact available route/offer alternatives.
    ///
    /// Two alternatives are sufficient to prove that `UniqueOnly` is
    /// ambiguous without enumerating an exponential graph. Each returned route
    /// remains content-bound to the complete original plan.
    ///
    /// # Errors
    ///
    /// Refuses an invalid or substituted plan, a subset entry absent from the
    /// plan, unsupported extensions, or complete external blockage.
    pub fn route_alternatives_with_available_offers(
        &self,
        plan: &SemanticPlan,
        available_offers: &BTreeSet<AvailableOffer>,
    ) -> Result<Vec<SelectedRoute>, PlanningError> {
        self.validate_exact_plan(plan)?;
        if !plan.extensions.is_empty() {
            return Err(PlanningError::UnsupportedPlanExtensions);
        }
        if let Some(planned) = plan
            .capabilities
            .iter()
            .find(|planned| !planned.extensions.is_empty())
        {
            return Err(PlanningError::UnsupportedPlanNodeExtensions(
                planned.specification.id.clone(),
            ));
        }
        if plan
            .target_output
            .as_ref()
            .is_some_and(|target| !target.extensions.is_empty())
        {
            return Err(PlanningError::UnsupportedTargetExtensions);
        }
        for available in available_offers {
            let planned = plan
                .planned_capability(&available.capability)
                .map_err(|_| PlanningError::CapabilityNotPlanned(available.capability.clone()))?;
            if !planned
                .offers
                .iter()
                .any(|offer| offer.offer_id == available.offer)
            {
                return Err(PlanningError::OfferNotPlanned {
                    capability: available.capability.clone(),
                    offer: available.offer.clone(),
                });
            }
        }
        available_route_alternatives(plan, available_offers)
    }

    fn validate_exact_plan(&self, plan: &SemanticPlan) -> Result<(), PlanningError> {
        plan.validate(self.limits)?;
        if plan.planning_scope_digest != self.scope_digest {
            return Err(PlanningError::PlanningScopeMismatch {
                expected: self.scope_digest.clone(),
                actual: plan.planning_scope_digest.clone(),
            });
        }
        let expected = match &plan.target_output {
            Some(target) => {
                self.plan_output(plan.initial_value_kinds.iter().cloned(), target.clone())?
            }
            None => self.plan(
                plan.initial_value_kinds.iter().cloned(),
                plan.target_value_kind.clone(),
            )?,
        };
        if &expected != plan {
            return Err(PlanningError::PlanInventoryMismatch);
        }
        Ok(())
    }

    /// Explicitly links one exact planned capability and installed offer into
    /// an invocation.
    ///
    /// The planner revalidates the serialized plan against this immutable
    /// inventory snapshot. A plan is inspectable, portable structural data;
    /// it cannot establish by self-assertion that a specification or offer was
    /// actually installed. No route or implementation is chosen implicitly.
    /// The caller must already have resolved each named input's authority
    /// record under its contextual admission policy; this structural linker
    /// preserves those references but does not resolve them.
    ///
    /// # Errors
    ///
    /// Refuses an invalid or extension-augmented plan, a different planning
    /// scope, a specification or offer absent from this exact inventory, an
    /// absent plan alternative, or inputs that do not exactly match the named
    /// ports.
    pub fn link_invocation(
        &self,
        plan: &SemanticPlan,
        link: InvocationLink<'_>,
    ) -> Result<CapabilityInvocation, PlanningError> {
        plan.validate(self.limits)?;
        if plan.planning_scope_digest != self.scope_digest {
            return Err(PlanningError::PlanningScopeMismatch {
                expected: self.scope_digest.clone(),
                actual: plan.planning_scope_digest.clone(),
            });
        }
        if !plan.extensions.is_empty() {
            return Err(PlanningError::UnsupportedPlanExtensions);
        }
        let planned = plan.planned_capability(link.capability)?;
        if !planned.extensions.is_empty() {
            return Err(PlanningError::UnsupportedPlanNodeExtensions(
                link.capability.clone(),
            ));
        }
        let installed_specification = self
            .specifications
            .get(link.capability)
            .ok_or_else(|| PlanningError::CapabilityNotInstalled(link.capability.clone()))?;
        if installed_specification != &planned.specification {
            return Err(PlanningError::SpecificationInventoryMismatch(
                link.capability.clone(),
            ));
        }
        let selected = planned
            .offers
            .binary_search_by(|item| item.offer_id.cmp(link.offer))
            .ok()
            .map(|index| &planned.offers[index])
            .ok_or_else(|| PlanningError::OfferNotPlanned {
                capability: link.capability.clone(),
                offer: link.offer.clone(),
            })?;
        let installed = self
            .offers
            .get(link.capability)
            .and_then(|offers| {
                offers
                    .binary_search_by(|item| item.offer_id.cmp(link.offer))
                    .ok()
                    .map(|index| &offers[index])
            })
            .ok_or_else(|| PlanningError::OfferNotInstalled {
                capability: link.capability.clone(),
                offer: link.offer.clone(),
            })?;
        if installed != selected {
            return Err(PlanningError::OfferInventoryMismatch {
                capability: link.capability.clone(),
                offer: link.offer.clone(),
            });
        }
        let selection = ImplementationSelection::new(installed.clone(), link.selection_extensions)
            .map_err(PlanningError::Invocation)?;
        CapabilityInvocation::new(
            installed_specification.clone(),
            selection,
            link.inputs,
            link.conformance_suite,
            link.invocation_extensions,
        )
        .map_err(PlanningError::Invocation)
    }

    /// Produces one finite AND/OR graph slice without selecting a route or an
    /// implementation.
    ///
    /// A providerless capability remains in the plan with zero offers. A pure
    /// unseeded cycle is unreachable. A seeded cycle is represented at most
    /// once per capability because the result is a graph slice, not an
    /// enumeration of walks.
    ///
    /// # Errors
    ///
    /// Refuses duplicate or invalid initial kinds, configured bounds, and a
    /// target that no declared capability path can reach.
    pub fn plan(
        &self,
        initial_value_kinds: impl IntoIterator<Item = ValueKindId>,
        target_value_kind: ValueKindId,
    ) -> Result<SemanticPlan, PlanningError> {
        self.plan_internal(initial_value_kinds, target_value_kind, None)
    }

    /// Produces one finite graph slice rooted at an exact capability output.
    ///
    /// Unlike a value-kind query, the named capability remains required when
    /// its output kind is already present among the initial values. This lets
    /// independent generators share a portable artifact kind without erasing
    /// the caller's requested generator.
    ///
    /// # Errors
    ///
    /// Refuses an unknown capability or output port, unsupported target
    /// extensions, invalid initial kinds, configured bounds, and an exact
    /// output whose capability is not reachable from the initial kinds.
    pub fn plan_output(
        &self,
        initial_value_kinds: impl IntoIterator<Item = ValueKindId>,
        target: RouteOutputRef,
    ) -> Result<SemanticPlan, PlanningError> {
        if !target.extensions.is_empty() {
            return Err(PlanningError::UnsupportedTargetExtensions);
        }
        let specification = self
            .specifications
            .get(&target.capability)
            .ok_or_else(|| PlanningError::CapabilityNotInstalled(target.capability.clone()))?;
        let output = specification
            .output_ports
            .iter()
            .find(|output| output.name == target.output_port)
            .ok_or_else(|| PlanningError::OutputPortNotInstalled {
                capability: target.capability.clone(),
                output_port: target.output_port.clone(),
            })?;
        self.plan_internal(initial_value_kinds, output.value_kind.clone(), Some(target))
    }

    fn plan_internal(
        &self,
        initial_value_kinds: impl IntoIterator<Item = ValueKindId>,
        target_value_kind: ValueKindId,
        target_output: Option<RouteOutputRef>,
    ) -> Result<SemanticPlan, PlanningError> {
        let mut initial = BTreeSet::new();
        for value_kind in initial_value_kinds {
            if !value_kind.is_well_formed() {
                return Err(PlanningError::InvalidValueKind(value_kind));
            }
            if !initial.insert(value_kind.clone()) {
                return Err(PlanningError::DuplicateInitialValueKind(value_kind));
            }
            require_limit(
                "initial value kinds",
                initial.len(),
                self.limits.max_value_kinds,
            )?;
        }
        if !target_value_kind.is_well_formed() {
            return Err(PlanningError::InvalidValueKind(target_value_kind));
        }
        let mut planning_value_kinds = self.value_kinds.clone();
        for value_kind in &initial {
            insert_bounded_value_kind(
                &mut planning_value_kinds,
                value_kind,
                self.limits.max_value_kinds,
            )?;
        }
        insert_bounded_value_kind(
            &mut planning_value_kinds,
            &target_value_kind,
            self.limits.max_value_kinds,
        )?;

        let relevant = if let Some(target) = &target_output {
            let forward = forward_reachable(&self.specifications, &initial);
            if !forward.contains(&target.capability) {
                return Err(PlanningError::UnreachableOutput {
                    target: Box::new(target.clone()),
                    value_kind: target_value_kind,
                });
            }
            backward_relevant_output(&self.specifications, &forward, &initial, &target.capability)
        } else if initial.contains(&target_value_kind) {
            BTreeSet::new()
        } else {
            let forward = forward_reachable(&self.specifications, &initial);
            let reachable = forward_value_kinds(&self.specifications, &initial, &forward);
            if !reachable.contains(&target_value_kind) {
                return Err(PlanningError::Unreachable(target_value_kind));
            }
            backward_relevant(&self.specifications, &forward, &initial, &target_value_kind)
        };
        let capabilities = relevant
            .iter()
            .map(|id| {
                let specification = self.specifications.get(id).ok_or_else(|| {
                    PlanningError::InventoryInvariant {
                        missing_capability: id.clone(),
                    }
                })?;
                Ok(PlannedCapability {
                    specification: specification.clone(),
                    offers: self.offers.get(id).cloned().unwrap_or_default(),
                    extensions: BTreeMap::new(),
                })
            })
            .collect::<Result<Vec<_>, PlanningError>>()?;
        let mut plan = SemanticPlan {
            plan_id: placeholder_plan_id(),
            protocol: SEMANTIC_PLAN_PROTOCOL.to_owned(),
            planning_scope_digest: self.scope_digest.clone(),
            initial_value_kinds: initial.into_iter().collect(),
            target_value_kind,
            target_output,
            capabilities,
            extensions: BTreeMap::new(),
        };
        plan.validate_structure()?;
        plan.plan_id = PlanId::parse(plan_digest(&plan)?)?;
        Ok(plan)
    }
}

/// Exact planning refusal. No partial plan or selection is returned.
#[derive(Debug)]
pub enum PlanningError {
    InvalidSpecification {
        capability: CapabilityId,
        detail: String,
    },
    DuplicateCapability(CapabilityId),
    InvalidOffer {
        offer: OfferId,
        detail: String,
    },
    DuplicateOffer(OfferId),
    OfferForUnknownCapability {
        offer: OfferId,
        capability: CapabilityId,
    },
    OfferCapabilityMismatch {
        offer: OfferId,
        expected: Box<CapabilityId>,
        actual: Box<CapabilityId>,
    },
    LimitExceeded {
        resource: &'static str,
        capability: Option<CapabilityId>,
        actual: usize,
        limit: usize,
    },
    LimitOverflow(&'static str),
    InvalidValueKind(ValueKindId),
    DuplicateInitialValueKind(ValueKindId),
    Unreachable(ValueKindId),
    UnreachableOutput {
        target: Box<RouteOutputRef>,
        value_kind: ValueKindId,
    },
    PlanningScopeMismatch {
        expected: PlanningScopeDigest,
        actual: PlanningScopeDigest,
    },
    InventoryInvariant {
        missing_capability: CapabilityId,
    },
    ProtocolMismatch {
        actual: String,
    },
    NonCanonicalCapabilityOrder,
    NonCanonicalOfferOrder(CapabilityId),
    InvalidGraphSlice,
    ReservedExtension {
        scope: String,
        key: String,
    },
    PlanIdentityMismatch {
        expected: String,
        actual: String,
    },
    RouteProtocolMismatch {
        actual: String,
    },
    RoutePlanMismatch {
        expected: PlanId,
        actual: PlanId,
    },
    RouteIdentityMismatch {
        expected: String,
        actual: String,
    },
    DuplicateRouteCapability(CapabilityId),
    NonCanonicalRouteStepOrder,
    InvalidRouteInputDependency {
        capability: CapabilityId,
        input_port: PortName,
        detail: String,
    },
    InvalidRouteTarget(String),
    UnusedRouteCapability(CapabilityId),
    AllRoutesBlocked(Box<BlockedRouteAnalysis>),
    AmbiguousCapabilityRoute,
    AmbiguousOffer(CapabilityId),
    PlanInventoryMismatch,
    UnsupportedPlanExtensions,
    UnsupportedPlanNodeExtensions(CapabilityId),
    UnsupportedTargetExtensions,
    CapabilityNotPlanned(CapabilityId),
    CapabilityNotInstalled(CapabilityId),
    OutputPortNotInstalled {
        capability: CapabilityId,
        output_port: PortName,
    },
    SpecificationInventoryMismatch(CapabilityId),
    OfferNotPlanned {
        capability: CapabilityId,
        offer: OfferId,
    },
    OfferNotInstalled {
        capability: CapabilityId,
        offer: OfferId,
    },
    OfferInventoryMismatch {
        capability: CapabilityId,
        offer: OfferId,
    },
    Invocation(ProtocolError),
    Digest(DigestParseError),
    Serialization(String),
}

impl fmt::Display for PlanningError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSpecification { .. }
            | Self::DuplicateCapability(_)
            | Self::InvalidOffer { .. }
            | Self::DuplicateOffer(_)
            | Self::OfferForUnknownCapability { .. }
            | Self::OfferCapabilityMismatch { .. }
            | Self::LimitExceeded { .. }
            | Self::LimitOverflow(_)
            | Self::InvalidValueKind(_)
            | Self::DuplicateInitialValueKind(_)
            | Self::Unreachable(_)
            | Self::UnreachableOutput { .. }
            | Self::InventoryInvariant { .. } => format_inventory_error(self, formatter),
            Self::PlanningScopeMismatch { expected, actual } => write!(
                formatter,
                "semantic plan inventory scope mismatch: expected {expected}, got {actual}"
            ),
            Self::ProtocolMismatch { actual } => {
                write!(formatter, "semantic plan protocol is unsupported: {actual}")
            }
            Self::NonCanonicalCapabilityOrder => formatter
                .write_str("semantic plan capabilities are not in strict capability-ID order"),
            Self::NonCanonicalOfferOrder(capability) => write!(
                formatter,
                "offers for capability {capability} are not in strict offer-ID order"
            ),
            Self::InvalidGraphSlice => formatter.write_str(
                "semantic plan graph slice is not exact, reachable, and target-relevant",
            ),
            Self::ReservedExtension { scope, key } => write!(
                formatter,
                "semantic plan extension `{key}` shadows a known field in {scope}"
            ),
            Self::PlanIdentityMismatch { expected, actual } => write!(
                formatter,
                "semantic plan identity mismatch: expected {expected}, got {actual}"
            ),
            Self::RouteProtocolMismatch { actual } => {
                write!(
                    formatter,
                    "selected-route protocol is unsupported: {actual}"
                )
            }
            Self::RoutePlanMismatch { expected, actual } => write!(
                formatter,
                "selected route names plan {actual}, not exact plan {expected}"
            ),
            Self::RouteIdentityMismatch { expected, actual } => write!(
                formatter,
                "selected-route identity mismatch: expected {expected}, got {actual}"
            ),
            Self::DuplicateRouteCapability(capability) => write!(
                formatter,
                "selected route contains capability {capability} more than once"
            ),
            Self::NonCanonicalRouteStepOrder => {
                formatter.write_str("selected-route steps are not in canonical dependency order")
            }
            Self::InvalidRouteInputDependency {
                capability,
                input_port,
                detail,
            } => write!(
                formatter,
                "selected route input {capability}/{input_port} is invalid: {detail}"
            ),
            Self::InvalidRouteTarget(detail) => {
                write!(formatter, "selected-route target is invalid: {detail}")
            }
            Self::UnusedRouteCapability(capability) => write!(
                formatter,
                "selected route contains unused capability {capability}"
            ),
            Self::AllRoutesBlocked(_) => formatter.write_str(
                "every complete route in the semantic plan is blocked by a missing offer",
            ),
            Self::AmbiguousCapabilityRoute => formatter
                .write_str("semantic plan has more than one complete executable capability route"),
            Self::AmbiguousOffer(capability) => write!(
                formatter,
                "the unique capability route has more than one offer for {capability}"
            ),
            Self::PlanInventoryMismatch => formatter.write_str(
                "semantic plan differs from the exact graph slice for this planning inventory",
            ),
            Self::UnsupportedPlanExtensions => formatter.write_str(
                "semantic plan carries unknown root extensions and cannot be linked safely",
            ),
            Self::UnsupportedPlanNodeExtensions(capability) => write!(
                formatter,
                "planned capability {capability} carries unknown node extensions and cannot be linked safely"
            ),
            Self::UnsupportedTargetExtensions => formatter.write_str(
                "exact target output carries unknown extensions and cannot be selected safely",
            ),
            Self::CapabilityNotPlanned(capability) => write!(
                formatter,
                "capability {capability} is not present in the exact semantic plan"
            ),
            Self::CapabilityNotInstalled(capability) => write!(
                formatter,
                "capability {capability} is not installed in this exact planning inventory"
            ),
            Self::OutputPortNotInstalled {
                capability,
                output_port,
            } => write!(
                formatter,
                "output port {output_port} is not declared by installed capability {capability}"
            ),
            Self::SpecificationInventoryMismatch(capability) => write!(
                formatter,
                "planned capability {capability} differs from this exact planning inventory"
            ),
            Self::OfferNotPlanned { capability, offer } => write!(
                formatter,
                "offer {offer} is not an alternative for planned capability {capability}"
            ),
            Self::OfferNotInstalled { capability, offer } => write!(
                formatter,
                "offer {offer} for capability {capability} is not installed in this exact planning inventory"
            ),
            Self::OfferInventoryMismatch { capability, offer } => write!(
                formatter,
                "planned offer {offer} for capability {capability} differs from this exact planning inventory"
            ),
            Self::Invocation(_) => {
                formatter.write_str("explicit selection could not form one exact linked invocation")
            }
            Self::Digest(error) => error.fmt(formatter),
            Self::Serialization(error) => {
                write!(
                    formatter,
                    "semantic plan could not be canonically encoded: {error}"
                )
            }
        }
    }
}

fn format_inventory_error(
    error: &PlanningError,
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    match error {
        PlanningError::InvalidSpecification { capability, detail } => {
            write!(formatter, "capability {capability} is invalid: {detail}")
        }
        PlanningError::DuplicateCapability(capability) => write!(
            formatter,
            "capability {capability} appeared more than once in the planning inventory"
        ),
        PlanningError::InvalidOffer { offer, detail } => {
            write!(formatter, "offer {offer} is invalid: {detail}")
        }
        PlanningError::DuplicateOffer(offer) => write!(
            formatter,
            "offer {offer} appeared more than once in the planning inventory"
        ),
        PlanningError::OfferForUnknownCapability { offer, capability } => {
            write!(
                formatter,
                "offer {offer} names unknown capability {capability}"
            )
        }
        PlanningError::OfferCapabilityMismatch {
            offer,
            expected,
            actual,
        } => write!(
            formatter,
            "offer {offer} names {actual}, not planned capability {expected}"
        ),
        PlanningError::LimitExceeded {
            resource,
            capability,
            actual,
            limit,
        } => {
            if let Some(capability) = capability {
                write!(
                    formatter,
                    "{resource} count {actual} for capability {capability} exceeds configured limit {limit}"
                )
            } else {
                write!(
                    formatter,
                    "{resource} count {actual} exceeds configured limit {limit}"
                )
            }
        }
        PlanningError::LimitOverflow(resource) => {
            write!(
                formatter,
                "{resource} count overflowed the host representation"
            )
        }
        PlanningError::InvalidValueKind(value_kind) => {
            write!(formatter, "value kind {value_kind} is not exact")
        }
        PlanningError::DuplicateInitialValueKind(value_kind) => {
            write!(
                formatter,
                "initial value kind {value_kind} appeared more than once"
            )
        }
        PlanningError::Unreachable(target) => write!(
            formatter,
            "target value kind {target} is unreachable from the declared capability graph"
        ),
        PlanningError::UnreachableOutput { target, .. } => write!(
            formatter,
            "target capability output {}/{} is unreachable from the declared capability graph",
            target.capability, target.output_port
        ),
        PlanningError::InventoryInvariant { missing_capability } => write!(
            formatter,
            "planner inventory lost relevant capability {missing_capability}"
        ),
        _ => unreachable!("only inventory errors are delegated"),
    }
}

impl std::error::Error for PlanningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invocation(error) => Some(error),
            Self::Digest(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DigestParseError> for PlanningError {
    fn from(error: DigestParseError) -> Self {
        Self::Digest(error)
    }
}

impl PlanningError {
    fn with_capability(self, capability: CapabilityId) -> Self {
        match self {
            Self::LimitExceeded {
                resource,
                actual,
                limit,
                ..
            } => Self::LimitExceeded {
                resource,
                capability: Some(capability),
                actual,
                limit,
            },
            other => other,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum DraftRouteValueSource {
    Initial(ValueKindId),
    CapabilityOutput {
        capability: CapabilityId,
        output_port: PortName,
    },
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DraftRouteInputDependency {
    input_port: PortName,
    source: DraftRouteValueSource,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DraftRouteStep {
    capability: CapabilityId,
    inputs: Vec<DraftRouteInputDependency>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DraftRoute {
    target: DraftRouteValueSource,
    steps: BTreeMap<CapabilityId, DraftRouteStep>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DraftDerivation {
    source: DraftRouteValueSource,
    steps: BTreeMap<CapabilityId, DraftRouteStep>,
}

fn select_unique_route(plan: &SemanticPlan) -> Result<SelectedRoute, PlanningError> {
    let available_offers = plan
        .capabilities
        .iter()
        .flat_map(|planned| {
            planned.offers.iter().map(|offer| AvailableOffer {
                capability: planned.specification.id.clone(),
                offer: offer.offer_id.clone(),
            })
        })
        .collect();
    select_unique_route_with_available_offers(plan, &available_offers)
}

fn select_unique_route_with_available_offers(
    plan: &SemanticPlan,
    available_offers: &BTreeSet<AvailableOffer>,
) -> Result<SelectedRoute, PlanningError> {
    let routes = available_route_alternatives(plan, available_offers)?;
    match routes.as_slice() {
        [route] => Ok(route.clone()),
        [first, second] => Err(route_ambiguity(first, second)),
        _ => unreachable!("route alternatives are capped at two"),
    }
}

fn available_route_alternatives(
    plan: &SemanticPlan,
    available_offers: &BTreeSet<AvailableOffer>,
) -> Result<Vec<SelectedRoute>, PlanningError> {
    let (drafts, available) = available_draft_routes(plan, available_offers)?;

    let planned = plan
        .capabilities
        .iter()
        .map(|capability| (capability.specification.id.clone(), capability))
        .collect::<BTreeMap<_, _>>();
    let mut alternatives = Vec::new();
    for route in drafts {
        let order = canonical_draft_step_order(&route.steps)?;
        let mut step_alternatives = vec![Vec::with_capacity(order.len())];
        for capability in order {
            let draft = route
                .steps
                .get(&capability)
                .ok_or_else(|| PlanningError::CapabilityNotPlanned(capability.clone()))?;
            let planned_capability = planned
                .get(&capability)
                .ok_or_else(|| PlanningError::CapabilityNotPlanned(capability.clone()))?;
            let offers = planned_capability.offers.iter().filter(|offer| {
                available_offers.contains(&AvailableOffer {
                    capability: capability.clone(),
                    offer: offer.offer_id.clone(),
                })
            });
            let mut next = Vec::new();
            for offer in offers {
                let step = SelectedRouteStep {
                    capability: capability.clone(),
                    offer: offer.offer_id.clone(),
                    inputs: draft
                        .inputs
                        .iter()
                        .map(|input| RouteInputDependency {
                            input_port: input.input_port.clone(),
                            source: selected_source(&input.source),
                            extensions: BTreeMap::new(),
                        })
                        .collect(),
                    extensions: BTreeMap::new(),
                };
                for partial in &step_alternatives {
                    let mut steps = partial.clone();
                    steps.push(step.clone());
                    push_distinct_capped(&mut next, steps);
                }
            }
            step_alternatives = next;
        }
        for steps in step_alternatives {
            let mut selected = SelectedRoute {
                route_id: placeholder_route_id(),
                protocol: SELECTED_ROUTE_PROTOCOL.to_owned(),
                plan_id: plan.plan_id.clone(),
                target: selected_source(&route.target),
                steps,
                extensions: BTreeMap::new(),
            };
            selected.validate_structure(plan)?;
            selected.route_id = RouteId::parse(route_digest(&selected)?)?;
            push_distinct_capped(&mut alternatives, selected);
            if alternatives.len() == 2 {
                return Ok(alternatives);
            }
        }
    }
    if alternatives.is_empty() {
        Err(PlanningError::AllRoutesBlocked(Box::new(
            blocked_route_analysis(plan, &available),
        )))
    } else {
        Ok(alternatives)
    }
}

fn available_draft_routes(
    plan: &SemanticPlan,
    available_offers: &BTreeSet<AvailableOffer>,
) -> Result<(Vec<DraftRoute>, BTreeSet<ValueKindId>), PlanningError> {
    let (available, executable) = offer_reachable(plan, available_offers);
    let exact_target_blocked = plan
        .target_output
        .as_ref()
        .is_some_and(|target| !executable.contains(&target.capability));
    if exact_target_blocked
        || (plan.target_output.is_none() && !available.contains(&plan.target_value_kind))
    {
        return Err(PlanningError::AllRoutesBlocked(Box::new(
            blocked_route_analysis(plan, &available),
        )));
    }
    let derivations = match &plan.target_output {
        Some(target) => derive_output(
            plan,
            target,
            &BTreeMap::new(),
            &BTreeSet::new(),
            &executable,
        ),
        None => derive_value(
            plan,
            &plan.target_value_kind,
            &BTreeMap::new(),
            &BTreeSet::new(),
            &executable,
        ),
    };
    let mut drafts = Vec::new();
    for derivation in derivations {
        push_distinct_capped(
            &mut drafts,
            DraftRoute {
                target: derivation.source,
                steps: derivation.steps,
            },
        );
    }
    if drafts.is_empty() {
        Err(PlanningError::AllRoutesBlocked(Box::new(
            blocked_route_analysis(plan, &available),
        )))
    } else {
        Ok((drafts, available))
    }
}

fn route_ambiguity(first: &SelectedRoute, second: &SelectedRoute) -> PlanningError {
    let same_semantic_route = first.target == second.target
        && first.steps.len() == second.steps.len()
        && first.steps.iter().zip(&second.steps).all(|(left, right)| {
            left.capability == right.capability && left.inputs == right.inputs
        });
    if same_semantic_route
        && let Some(step) = first
            .steps
            .iter()
            .zip(&second.steps)
            .find(|(left, right)| left.offer != right.offer)
            .map(|(left, _)| left.capability.clone())
    {
        PlanningError::AmbiguousOffer(step)
    } else {
        PlanningError::AmbiguousCapabilityRoute
    }
}

fn derive_value(
    plan: &SemanticPlan,
    value_kind: &ValueKindId,
    selected: &BTreeMap<CapabilityId, DraftRouteStep>,
    visiting: &BTreeSet<CapabilityId>,
    executable: &BTreeSet<CapabilityId>,
) -> Vec<DraftDerivation> {
    if plan.initial_value_kinds.contains(value_kind) {
        return vec![DraftDerivation {
            source: DraftRouteValueSource::Initial(value_kind.clone()),
            steps: selected.clone(),
        }];
    }

    let mut derivations = Vec::new();
    for planned in &plan.capabilities {
        for output in planned
            .specification
            .output_ports
            .iter()
            .filter(|output| &output.value_kind == value_kind)
        {
            let target = RouteOutputRef {
                capability: planned.specification.id.clone(),
                output_port: output.name.clone(),
                extensions: BTreeMap::new(),
            };
            for derived in derive_output(plan, &target, selected, visiting, executable) {
                push_distinct_capped(&mut derivations, derived);
                if derivations.len() == 2 {
                    return derivations;
                }
            }
        }
    }
    derivations
}

fn derive_output(
    plan: &SemanticPlan,
    target: &RouteOutputRef,
    selected: &BTreeMap<CapabilityId, DraftRouteStep>,
    visiting: &BTreeSet<CapabilityId>,
    executable: &BTreeSet<CapabilityId>,
) -> Vec<DraftDerivation> {
    let Some(planned) = plan
        .capabilities
        .iter()
        .find(|planned| planned.specification.id == target.capability)
    else {
        return Vec::new();
    };
    if !executable.contains(&target.capability)
        || !planned
            .specification
            .output_ports
            .iter()
            .any(|output| output.name == target.output_port)
    {
        return Vec::new();
    }

    let source = DraftRouteValueSource::CapabilityOutput {
        capability: target.capability.clone(),
        output_port: target.output_port.clone(),
    };
    if selected.contains_key(&target.capability) {
        return vec![DraftDerivation {
            source,
            steps: selected.clone(),
        }];
    }
    if visiting.contains(&target.capability) {
        return Vec::new();
    }

    let mut next_visiting = visiting.clone();
    next_visiting.insert(target.capability.clone());
    let mut partials = vec![(selected.clone(), Vec::new())];
    for input in &planned.specification.input_ports {
        let mut next_partials = Vec::new();
        for (partial_steps, partial_inputs) in partials {
            for derived in derive_value(
                plan,
                &input.value_kind,
                &partial_steps,
                &next_visiting,
                executable,
            ) {
                let mut inputs = partial_inputs.clone();
                inputs.push(DraftRouteInputDependency {
                    input_port: input.name.clone(),
                    source: derived.source,
                });
                push_distinct_capped(&mut next_partials, (derived.steps, inputs));
                if next_partials.len() == 2 {
                    break;
                }
            }
            if next_partials.len() == 2 {
                break;
            }
        }
        partials = next_partials;
        if partials.is_empty() {
            break;
        }
    }

    let mut derivations = Vec::new();
    for (mut steps, inputs) in partials {
        steps.insert(
            target.capability.clone(),
            DraftRouteStep {
                capability: target.capability.clone(),
                inputs,
            },
        );
        push_distinct_capped(
            &mut derivations,
            DraftDerivation {
                source: source.clone(),
                steps,
            },
        );
    }
    derivations
}

fn push_distinct_capped<T: PartialEq>(items: &mut Vec<T>, item: T) {
    if items.len() < 2 && !items.contains(&item) {
        items.push(item);
    }
}

fn selected_source(source: &DraftRouteValueSource) -> RouteValueSource {
    match source {
        DraftRouteValueSource::Initial(value_kind) => RouteValueSource::Initial {
            value_kind: value_kind.clone(),
            extensions: BTreeMap::new(),
        },
        DraftRouteValueSource::CapabilityOutput {
            capability,
            output_port,
        } => RouteValueSource::CapabilityOutput {
            capability: capability.clone(),
            output_port: output_port.clone(),
            extensions: BTreeMap::new(),
        },
    }
}

fn validate_route_inputs(
    step: &SelectedRouteStep,
    specification: &CapabilitySpec,
    plan: &SemanticPlan,
    preceding: &BTreeMap<CapabilityId, &SelectedRouteStep>,
) -> Result<(), PlanningError> {
    if step.inputs.len() != specification.input_ports.len() {
        return Err(invalid_route_input(
            &step.capability,
            specification
                .input_ports
                .first()
                .map_or_else(route_placeholder_port, |input| input.name.clone()),
            "input-port set does not match the capability declaration",
        ));
    }
    for (dependency, input) in step.inputs.iter().zip(&specification.input_ports) {
        if dependency.input_port != input.name {
            return Err(invalid_route_input(
                &step.capability,
                dependency.input_port.clone(),
                "input ports are missing or not in declaration order",
            ));
        }
        validate_extensions(
            &format!(
                "selected route input `{}/{}`",
                step.capability, dependency.input_port
            ),
            &dependency.extensions,
            &["input_port", "source"],
        )?;
        validate_source_extensions(&dependency.source, "selected route input source")?;
        let actual = source_value_kind(&dependency.source, plan, preceding).map_err(|detail| {
            invalid_route_input(&step.capability, dependency.input_port.clone(), detail)
        })?;
        if actual != &input.value_kind {
            return Err(invalid_route_input(
                &step.capability,
                dependency.input_port.clone(),
                "dependency value kind does not match the named input port",
            ));
        }
    }
    Ok(())
}

fn validate_route_target(
    target: &RouteValueSource,
    plan: &SemanticPlan,
    selected: &BTreeMap<CapabilityId, &SelectedRouteStep>,
) -> Result<(), PlanningError> {
    validate_source_extensions(target, "selected route target")?;
    let actual =
        source_value_kind(target, plan, selected).map_err(PlanningError::InvalidRouteTarget)?;
    if actual != &plan.target_value_kind {
        return Err(PlanningError::InvalidRouteTarget(
            "target source has the wrong value kind".to_owned(),
        ));
    }
    if let Some(expected) = &plan.target_output {
        let RouteValueSource::CapabilityOutput {
            capability,
            output_port,
            ..
        } = target
        else {
            return Err(PlanningError::InvalidRouteTarget(
                "exact capability-output goal was replaced by an initial value".to_owned(),
            ));
        };
        if capability != &expected.capability || output_port != &expected.output_port {
            return Err(PlanningError::InvalidRouteTarget(
                "selected route does not end at the exact requested capability output".to_owned(),
            ));
        }
    }
    Ok(())
}

fn source_value_kind<'plan>(
    source: &RouteValueSource,
    plan: &'plan SemanticPlan,
    selected: &BTreeMap<CapabilityId, &SelectedRouteStep>,
) -> Result<&'plan ValueKindId, String> {
    match source {
        RouteValueSource::Initial { value_kind, .. } => plan
            .initial_value_kinds
            .binary_search(value_kind)
            .ok()
            .map(|index| &plan.initial_value_kinds[index])
            .ok_or_else(|| "initial value kind is not declared by the plan".to_owned()),
        RouteValueSource::CapabilityOutput {
            capability,
            output_port,
            ..
        } => {
            if !selected.contains_key(capability) {
                return Err(
                    "capability output does not refer to a preceding selected step".to_owned(),
                );
            }
            let planned = plan
                .planned_capability(capability)
                .map_err(|_| "capability output is absent from the plan".to_owned())?;
            planned
                .specification
                .output_ports
                .iter()
                .find(|output| &output.name == output_port)
                .map(|output| &output.value_kind)
                .ok_or_else(|| "output port is absent from the selected capability".to_owned())
        }
    }
}

fn validate_source_extensions(source: &RouteValueSource, scope: &str) -> Result<(), PlanningError> {
    match source {
        RouteValueSource::Initial { extensions, .. } => {
            validate_extensions(scope, extensions, &["source", "value_kind"])
        }
        RouteValueSource::CapabilityOutput { extensions, .. } => {
            validate_extensions(scope, extensions, &["source", "capability", "output_port"])
        }
    }
}

fn canonical_step_order(
    selected: &BTreeMap<CapabilityId, &SelectedRouteStep>,
) -> Result<Vec<CapabilityId>, PlanningError> {
    canonical_order(selected.keys(), |capability| {
        selected
            .get(capability)
            .into_iter()
            .flat_map(|step| &step.inputs)
            .filter_map(|input| match &input.source {
                RouteValueSource::Initial { .. } => None,
                RouteValueSource::CapabilityOutput { capability, .. } => Some(capability.clone()),
            })
            .collect()
    })
}

fn canonical_draft_step_order(
    selected: &BTreeMap<CapabilityId, DraftRouteStep>,
) -> Result<Vec<CapabilityId>, PlanningError> {
    canonical_order(selected.keys(), |capability| {
        selected
            .get(capability)
            .into_iter()
            .flat_map(|step| &step.inputs)
            .filter_map(|input| match &input.source {
                DraftRouteValueSource::Initial(_) => None,
                DraftRouteValueSource::CapabilityOutput { capability, .. } => {
                    Some(capability.clone())
                }
            })
            .collect()
    })
}

fn canonical_order<'capability>(
    capabilities: impl Iterator<Item = &'capability CapabilityId>,
    dependencies: impl Fn(&CapabilityId) -> BTreeSet<CapabilityId>,
) -> Result<Vec<CapabilityId>, PlanningError> {
    let remaining = capabilities.cloned().collect::<BTreeSet<_>>();
    let mut emitted = BTreeSet::new();
    let mut order = Vec::with_capacity(remaining.len());
    while order.len() < remaining.len() {
        let Some(next) = remaining.iter().find(|capability| {
            !emitted.contains(*capability)
                && dependencies(capability)
                    .iter()
                    .all(|dependency| emitted.contains(dependency))
        }) else {
            return Err(PlanningError::NonCanonicalRouteStepOrder);
        };
        emitted.insert(next.clone());
        order.push(next.clone());
    }
    Ok(order)
}

fn validate_no_unused_steps(
    target: &RouteValueSource,
    selected: &BTreeMap<CapabilityId, &SelectedRouteStep>,
) -> Result<(), PlanningError> {
    let mut required = BTreeSet::new();
    if let RouteValueSource::CapabilityOutput { capability, .. } = target {
        required.insert(capability.clone());
    }
    let mut pending = required.iter().cloned().collect::<Vec<_>>();
    while let Some(capability) = pending.pop() {
        let Some(step) = selected.get(&capability) else {
            return Err(PlanningError::InvalidRouteTarget(
                "target dependency is absent from the route".to_owned(),
            ));
        };
        for input in &step.inputs {
            if let RouteValueSource::CapabilityOutput { capability, .. } = &input.source
                && required.insert(capability.clone())
            {
                pending.push(capability.clone());
            }
        }
    }
    if let Some(unused) = selected
        .keys()
        .find(|capability| !required.contains(*capability))
    {
        return Err(PlanningError::UnusedRouteCapability(unused.clone()));
    }
    Ok(())
}

fn invalid_route_input(
    capability: &CapabilityId,
    input_port: PortName,
    detail: impl Into<String>,
) -> PlanningError {
    PlanningError::InvalidRouteInputDependency {
        capability: capability.clone(),
        input_port,
        detail: detail.into(),
    }
}

fn route_placeholder_port() -> PortName {
    PortName::parse("<none>").expect("the route placeholder port is exact")
}

fn offer_reachable(
    plan: &SemanticPlan,
    available_offers: &BTreeSet<AvailableOffer>,
) -> (BTreeSet<ValueKindId>, BTreeSet<CapabilityId>) {
    let mut available = plan
        .initial_value_kinds
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut executable = BTreeSet::new();
    loop {
        let mut changed = false;
        for planned in &plan.capabilities {
            if !planned.offers.iter().any(|offer| {
                available_offers.contains(&AvailableOffer {
                    capability: planned.specification.id.clone(),
                    offer: offer.offer_id.clone(),
                })
            }) || !planned
                .specification
                .input_ports
                .iter()
                .all(|input| available.contains(&input.value_kind))
            {
                continue;
            }
            changed |= executable.insert(planned.specification.id.clone());
            for output in &planned.specification.output_ports {
                changed |= available.insert(output.value_kind.clone());
            }
        }
        if !changed {
            break;
        }
    }
    (available, executable)
}

fn blocked_route_analysis(
    plan: &SemanticPlan,
    available: &BTreeSet<ValueKindId>,
) -> BlockedRouteAnalysis {
    let producer_alternatives = |value_kind: &ValueKindId| {
        plan.capabilities
            .iter()
            .flat_map(|planned| {
                planned
                    .specification
                    .output_ports
                    .iter()
                    .filter(move |output| &output.value_kind == value_kind)
                    .map(|output| RouteOutputRef {
                        capability: planned.specification.id.clone(),
                        output_port: output.name.clone(),
                        extensions: BTreeMap::new(),
                    })
            })
            .collect::<Vec<_>>()
    };

    let target_alternatives = plan.target_output.as_ref().map_or_else(
        || producer_alternatives(&plan.target_value_kind),
        |target| vec![target.clone()],
    );
    let mut blocked_value_kinds = BTreeSet::new();
    let mut pending = Vec::new();
    let mut reached_capabilities = target_alternatives
        .iter()
        .map(|target| target.capability.clone())
        .collect::<BTreeSet<_>>();
    for capability in reached_capabilities.clone() {
        if let Some(planned) = plan
            .capabilities
            .iter()
            .find(|planned| planned.specification.id == capability)
        {
            for input in &planned.specification.input_ports {
                if !available.contains(&input.value_kind)
                    && blocked_value_kinds.insert(input.value_kind.clone())
                {
                    pending.push(input.value_kind.clone());
                }
            }
        }
    }
    while let Some(value_kind) = pending.pop() {
        for planned in &plan.capabilities {
            if !planned
                .specification
                .output_ports
                .iter()
                .any(|output| output.value_kind == value_kind)
                || !reached_capabilities.insert(planned.specification.id.clone())
            {
                continue;
            }
            for input in &planned.specification.input_ports {
                if !available.contains(&input.value_kind)
                    && blocked_value_kinds.insert(input.value_kind.clone())
                {
                    pending.push(input.value_kind.clone());
                }
            }
        }
    }

    BlockedRouteAnalysis {
        protocol: BLOCKED_ROUTE_PROTOCOL.to_owned(),
        plan_id: plan.plan_id.clone(),
        target_value_kind: plan.target_value_kind.clone(),
        target_alternatives,
        nodes: plan
            .capabilities
            .iter()
            .filter(|planned| reached_capabilities.contains(&planned.specification.id))
            .map(|planned| BlockedRouteNode {
                capability: planned.specification.id.clone(),
                missing_offer: planned.offers.is_empty(),
                blocked_inputs: planned
                    .specification
                    .input_ports
                    .iter()
                    .filter(|input| !available.contains(&input.value_kind))
                    .map(|input| BlockedRouteInput {
                        input_port: input.name.clone(),
                        value_kind: input.value_kind.clone(),
                        producer_alternatives: producer_alternatives(&input.value_kind),
                        extensions: BTreeMap::new(),
                    })
                    .collect(),
                extensions: BTreeMap::new(),
            })
            .collect(),
        missing_needs: plan
            .capabilities
            .iter()
            .filter(|planned| {
                planned.offers.is_empty()
                    && reached_capabilities.contains(&planned.specification.id)
            })
            .map(|planned| planned.specification.clone())
            .collect(),
        extensions: BTreeMap::new(),
    }
}

fn collect_specifications(
    specifications: impl IntoIterator<Item = CapabilitySpec>,
    limits: PlanLimits,
) -> Result<
    (
        BTreeMap<CapabilityId, CapabilitySpec>,
        BTreeSet<ValueKindId>,
    ),
    PlanningError,
> {
    let mut exact = BTreeMap::new();
    let mut value_kinds = BTreeSet::new();
    let mut total_ports = 0_usize;
    for specification in specifications {
        let capability_count = exact
            .len()
            .checked_add(1)
            .ok_or(PlanningError::LimitOverflow("capabilities"))?;
        require_limit("capabilities", capability_count, limits.max_capabilities)?;
        specification
            .validate()
            .map_err(|error| PlanningError::InvalidSpecification {
                capability: specification.id.clone(),
                detail: error.to_string(),
            })?;
        let ports = specification
            .input_ports
            .len()
            .checked_add(specification.output_ports.len())
            .ok_or(PlanningError::LimitOverflow("total ports"))?;
        require_limit(
            "ports per capability",
            ports,
            limits.max_ports_per_capability,
        )?;
        total_ports = total_ports
            .checked_add(ports)
            .ok_or(PlanningError::LimitOverflow("total ports"))?;
        require_limit("total ports", total_ports, limits.max_total_ports)?;
        for input in &specification.input_ports {
            insert_bounded_value_kind(&mut value_kinds, &input.value_kind, limits.max_value_kinds)?;
        }
        for output in &specification.output_ports {
            insert_bounded_value_kind(
                &mut value_kinds,
                &output.value_kind,
                limits.max_value_kinds,
            )?;
        }
        let id = specification.id.clone();
        if exact.insert(id.clone(), specification).is_some() {
            return Err(PlanningError::DuplicateCapability(id));
        }
    }
    Ok((exact, value_kinds))
}

fn collect_offers(
    offers: impl IntoIterator<Item = CapabilityOffer>,
    specifications: &BTreeMap<CapabilityId, CapabilitySpec>,
    limits: PlanLimits,
) -> Result<BTreeMap<OfferId, CapabilityOffer>, PlanningError> {
    let mut exact = BTreeMap::new();
    let mut counts = BTreeMap::<CapabilityId, usize>::new();
    for offer in offers {
        let total = exact
            .len()
            .checked_add(1)
            .ok_or(PlanningError::LimitOverflow("total offers"))?;
        require_limit("total offers", total, limits.max_total_offers)?;
        offer
            .validate()
            .map_err(|error| PlanningError::InvalidOffer {
                offer: offer.offer_id.clone(),
                detail: error.to_string(),
            })?;
        if !specifications.contains_key(&offer.capability) {
            return Err(PlanningError::OfferForUnknownCapability {
                offer: offer.offer_id,
                capability: offer.capability,
            });
        }
        let capability_count = counts
            .get(&offer.capability)
            .copied()
            .unwrap_or_default()
            .checked_add(1)
            .ok_or(PlanningError::LimitOverflow("offers per capability"))?;
        require_limit(
            "offers per capability",
            capability_count,
            limits.max_offers_per_capability,
        )
        .map_err(|error| error.with_capability(offer.capability.clone()))?;
        let capability = offer.capability.clone();
        let id = offer.offer_id.clone();
        if exact.insert(id.clone(), offer).is_some() {
            return Err(PlanningError::DuplicateOffer(id));
        }
        counts.insert(capability, capability_count);
    }
    Ok(exact)
}

fn offers_by_capability(
    offers: &BTreeMap<OfferId, CapabilityOffer>,
) -> BTreeMap<CapabilityId, Vec<CapabilityOffer>> {
    let mut grouped = BTreeMap::<CapabilityId, Vec<CapabilityOffer>>::new();
    for offer in offers.values() {
        grouped
            .entry(offer.capability.clone())
            .or_default()
            .push(offer.clone());
    }
    grouped
}

fn forward_reachable(
    specifications: &BTreeMap<CapabilityId, CapabilitySpec>,
    initial: &BTreeSet<ValueKindId>,
) -> BTreeSet<CapabilityId> {
    let mut reachable_kinds = initial.clone();
    let mut reachable_capabilities = BTreeSet::new();
    loop {
        let mut changed = false;
        for (id, specification) in specifications {
            if specification
                .input_ports
                .iter()
                .all(|port| reachable_kinds.contains(&port.value_kind))
            {
                changed |= reachable_capabilities.insert(id.clone());
                for output in &specification.output_ports {
                    changed |= reachable_kinds.insert(output.value_kind.clone());
                }
            }
        }
        if !changed {
            break;
        }
    }
    reachable_capabilities
}

fn forward_value_kinds(
    specifications: &BTreeMap<CapabilityId, CapabilitySpec>,
    initial: &BTreeSet<ValueKindId>,
    reachable_capabilities: &BTreeSet<CapabilityId>,
) -> BTreeSet<ValueKindId> {
    let mut reachable = initial.clone();
    for capability in reachable_capabilities {
        for output in &specifications
            .get(capability)
            .expect("reachable capability belongs to the supplied graph")
            .output_ports
        {
            reachable.insert(output.value_kind.clone());
        }
    }
    reachable
}

fn validate_graph_slice(
    plan: &SemanticPlan,
    specifications: &BTreeMap<CapabilityId, CapabilitySpec>,
) -> Result<(), PlanningError> {
    if plan.target_output.is_none() && plan.initial_value_kinds.contains(&plan.target_value_kind) {
        return if plan.capabilities.is_empty() {
            Ok(())
        } else {
            Err(PlanningError::InvalidGraphSlice)
        };
    }
    let initial = plan.initial_value_kinds.iter().cloned().collect();
    let forward = forward_reachable(specifications, &initial);
    let relevant = if let Some(target) = &plan.target_output {
        let specification = specifications
            .get(&target.capability)
            .ok_or(PlanningError::InvalidGraphSlice)?;
        let output = specification
            .output_ports
            .iter()
            .find(|output| output.name == target.output_port)
            .ok_or(PlanningError::InvalidGraphSlice)?;
        if output.value_kind != plan.target_value_kind || !forward.contains(&target.capability) {
            return Err(PlanningError::InvalidGraphSlice);
        }
        backward_relevant_output(specifications, &forward, &initial, &target.capability)
    } else {
        let reachable_kinds = forward_value_kinds(specifications, &initial, &forward);
        if !reachable_kinds.contains(&plan.target_value_kind) {
            return Err(PlanningError::InvalidGraphSlice);
        }
        backward_relevant(specifications, &forward, &initial, &plan.target_value_kind)
    };
    if relevant.len() != specifications.len()
        || !specifications.keys().all(|id| relevant.contains(id))
    {
        return Err(PlanningError::InvalidGraphSlice);
    }
    Ok(())
}

fn backward_relevant(
    specifications: &BTreeMap<CapabilityId, CapabilitySpec>,
    forward: &BTreeSet<CapabilityId>,
    initial: &BTreeSet<ValueKindId>,
    target: &ValueKindId,
) -> BTreeSet<CapabilityId> {
    let mut required_kinds = BTreeSet::from([target.clone()]);
    let mut relevant = BTreeSet::new();
    loop {
        let mut changed = false;
        for capability in forward {
            let specification = specifications
                .get(capability)
                .expect("forward capability belongs to the supplied graph");
            if specification
                .output_ports
                .iter()
                .any(|output| required_kinds.contains(&output.value_kind))
                && relevant.insert(capability.clone())
            {
                changed = true;
                for input in &specification.input_ports {
                    if !initial.contains(&input.value_kind) {
                        changed |= required_kinds.insert(input.value_kind.clone());
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    relevant
}

fn backward_relevant_output(
    specifications: &BTreeMap<CapabilityId, CapabilitySpec>,
    forward: &BTreeSet<CapabilityId>,
    initial: &BTreeSet<ValueKindId>,
    target: &CapabilityId,
) -> BTreeSet<CapabilityId> {
    let target_specification = specifications
        .get(target)
        .expect("exact target capability belongs to the supplied graph");
    let mut required_kinds = target_specification
        .input_ports
        .iter()
        .filter(|input| !initial.contains(&input.value_kind))
        .map(|input| input.value_kind.clone())
        .collect::<BTreeSet<_>>();
    let mut relevant = BTreeSet::from([target.clone()]);
    loop {
        let mut changed = false;
        for capability in forward {
            let specification = specifications
                .get(capability)
                .expect("forward capability belongs to the supplied graph");
            if specification
                .output_ports
                .iter()
                .any(|output| required_kinds.contains(&output.value_kind))
                && relevant.insert(capability.clone())
            {
                changed = true;
                for input in &specification.input_ports {
                    if !initial.contains(&input.value_kind) {
                        changed |= required_kinds.insert(input.value_kind.clone());
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    relevant
}

fn validate_sorted_value_kinds(value_kinds: &[ValueKindId]) -> Result<(), PlanningError> {
    let mut previous = None;
    for value_kind in value_kinds {
        if !value_kind.is_well_formed() {
            return Err(PlanningError::InvalidValueKind(value_kind.clone()));
        }
        if previous.is_some_and(|prior: &ValueKindId| prior >= value_kind) {
            return Err(PlanningError::InvalidGraphSlice);
        }
        previous = Some(value_kind);
    }
    Ok(())
}

fn validate_extensions(
    scope: &str,
    extensions: &BTreeMap<String, Value>,
    reserved: &[&str],
) -> Result<(), PlanningError> {
    if let Some(key) = reserved.iter().find(|key| extensions.contains_key(**key)) {
        Err(PlanningError::ReservedExtension {
            scope: scope.to_owned(),
            key: (*key).to_owned(),
        })
    } else {
        Ok(())
    }
}

fn require_limit(
    resource: &'static str,
    actual: usize,
    limit: NonZeroUsize,
) -> Result<(), PlanningError> {
    if actual > limit.get() {
        Err(PlanningError::LimitExceeded {
            resource,
            capability: None,
            actual,
            limit: limit.get(),
        })
    } else {
        Ok(())
    }
}

fn insert_bounded_value_kind(
    value_kinds: &mut BTreeSet<ValueKindId>,
    value_kind: &ValueKindId,
    limit: NonZeroUsize,
) -> Result<(), PlanningError> {
    if value_kinds.insert(value_kind.clone()) {
        require_limit("value kinds", value_kinds.len(), limit)?;
    }
    Ok(())
}

#[derive(Serialize)]
struct PlanningScope<'scope> {
    specifications: Vec<&'scope CapabilitySpec>,
    offers: Vec<&'scope CapabilityOffer>,
}

fn planning_scope_digest(
    specifications: Vec<&CapabilitySpec>,
    offers: Vec<&CapabilityOffer>,
) -> Result<PlanningScopeDigest, PlanningError> {
    let digest = canonical_digest(&PlanningScope {
        specifications,
        offers,
    })
    .map_err(PlanningError::Serialization)?;
    PlanningScopeDigest::parse(digest).map_err(Into::into)
}

fn plan_digest(plan: &SemanticPlan) -> Result<String, PlanningError> {
    let mut value = serde_json::to_value(plan)
        .map_err(|error| PlanningError::Serialization(error.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| PlanningError::Serialization("plan is not a JSON object".to_owned()))?
        .remove("plan_id")
        .ok_or_else(|| PlanningError::Serialization("plan omitted plan_id".to_owned()))?;
    canonical_digest(&value).map_err(PlanningError::Serialization)
}

fn route_digest(route: &SelectedRoute) -> Result<String, PlanningError> {
    let mut value = serde_json::to_value(route)
        .map_err(|error| PlanningError::Serialization(error.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| PlanningError::Serialization("route is not a JSON object".to_owned()))?
        .remove("route_id")
        .ok_or_else(|| PlanningError::Serialization("route omitted route_id".to_owned()))?;
    canonical_digest(&value).map_err(PlanningError::Serialization)
}

fn placeholder_plan_id() -> PlanId {
    PlanId::parse(format!("sha256:{}", "0".repeat(64)))
        .expect("the plan identity placeholder is exact")
}

fn placeholder_route_id() -> RouteId {
    RouteId::parse(format!("sha256:{}", "0".repeat(64)))
        .expect("the route identity placeholder is exact")
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(test)]
mod tests {
    use gooir_capability::protocol::{
        AdmittedFactRef, ArtifactDigest, AuthorityRecordId, ImplementationId,
    };
    use gooir_capability::{Fact, FactAcceptance, InputPort, OutputPort, PortName};
    use serde_json::json;

    use super::*;

    const VERSION: &str = "1.0.0";

    fn nonzero(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).unwrap()
    }

    fn limits() -> PlanLimits {
        PlanLimits {
            max_capabilities: nonzero(64),
            max_value_kinds: nonzero(64),
            max_ports_per_capability: nonzero(16),
            max_total_ports: nonzero(256),
            max_offers_per_capability: nonzero(16),
            max_total_offers: nonzero(256),
        }
    }

    fn kind(name: &str) -> ValueKindId {
        ValueKindId::new("org.example.values", name, VERSION)
    }

    fn port(name: &str) -> PortName {
        PortName::parse(name).unwrap()
    }

    fn capability(name: &str) -> CapabilityId {
        CapabilityId::new("org.example.capability", name, VERSION)
    }

    fn suite() -> ConformanceSuiteId {
        ConformanceSuiteId::new("org.example.conformance", "exact", VERSION)
    }

    fn specification(
        name: &str,
        inputs: &[(&str, ValueKindId)],
        outputs: &[(&str, ValueKindId)],
    ) -> CapabilitySpec {
        CapabilitySpec {
            id: capability(name),
            input_ports: inputs
                .iter()
                .map(|(name, value_kind)| InputPort {
                    name: port(name),
                    value_kind: value_kind.clone(),
                    acceptance: FactAcceptance::CompleteOnly,
                    extensions: BTreeMap::new(),
                })
                .collect(),
            output_ports: outputs
                .iter()
                .map(|(name, value_kind)| OutputPort::new(port(name), value_kind.clone()))
                .collect(),
            default_conformance_suite: suite().to_string(),
            extensions: BTreeMap::new(),
        }
    }

    fn sha(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn offer(specification: &CapabilitySpec, name: &str, digest: char) -> CapabilityOffer {
        CapabilityOffer::new(
            ImplementationId::new("org.example.implementation", name, VERSION),
            ArtifactDigest::parse(sha(digest)).unwrap(),
            specification.id.clone(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn linked(name: &str, value_kind: ValueKindId, value: i64, authority: char) -> LinkedInput {
        let fact = Fact::new(value_kind, json!({"value": value})).unwrap();
        let admitted = AdmittedFactRef::new(
            fact.id.clone(),
            AuthorityRecordId::parse(sha(authority)).unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        LinkedInput::new(port(name), admitted, fact, BTreeMap::new()).unwrap()
    }

    fn invocation_link<'identity>(
        capability: &'identity CapabilityId,
        offer: &'identity OfferId,
        inputs: Vec<LinkedInput>,
    ) -> InvocationLink<'identity> {
        InvocationLink {
            capability,
            offer,
            selection_extensions: BTreeMap::new(),
            inputs,
            conformance_suite: suite(),
            invocation_extensions: BTreeMap::new(),
        }
    }

    fn single_edge() -> (CapabilitySpec, CapabilityOffer, CapabilityOffer) {
        let edge = specification(
            "transform",
            &[("source", kind("source"))],
            &[("result", kind("result"))],
        );
        let first = offer(&edge, "first", 'a');
        let second = offer(&edge, "second", 'b');
        (edge, first, second)
    }

    struct MultiBackendFixture {
        planner: SemanticPlanner,
        content_set: ValueKindId,
        read_http: CapabilityId,
        generate_http: CapabilityId,
        read_data_model: CapabilityId,
        generate_sql: CapabilityId,
    }

    fn multi_backend_fixture() -> MultiBackendFixture {
        let content_set = kind("content-set");
        let http_model = kind("http-model");
        let data_model = kind("data-model");
        let read_http = specification(
            "read-http-spec",
            &[("source", content_set.clone())],
            &[("http", http_model.clone())],
        );
        let generate_http = specification(
            "generate-http-routes",
            &[("http", http_model)],
            &[("files", content_set.clone())],
        );
        let read_data_model = specification(
            "read-data-model-spec",
            &[("source", content_set.clone())],
            &[("model", data_model.clone())],
        );
        let generate_sql = specification(
            "generate-sql-migrations",
            &[("model", data_model)],
            &[("files", content_set.clone())],
        );
        let offers = [
            offer(&read_http, "read-http", 'a'),
            offer(&generate_http, "generate-http", 'b'),
            offer(&read_data_model, "read-data-model", 'c'),
            offer(&generate_sql, "generate-sql", 'd'),
        ];
        let ids = (
            read_http.id.clone(),
            generate_http.id.clone(),
            read_data_model.id.clone(),
            generate_sql.id.clone(),
        );
        let planner = SemanticPlanner::new(
            [read_http, generate_http, read_data_model, generate_sql],
            offers,
            limits(),
        )
        .unwrap();
        MultiBackendFixture {
            planner,
            content_set,
            read_http: ids.0,
            generate_http: ids.1,
            read_data_model: ids.2,
            generate_sql: ids.3,
        }
    }

    fn reidentify(plan: &mut SemanticPlan) {
        plan.plan_id = PlanId::parse(plan_digest(plan).unwrap()).unwrap();
    }

    #[test]
    fn insertion_order_is_irrelevant_and_every_offer_survives() {
        let (edge, first, second) = single_edge();
        let forward =
            SemanticPlanner::new([edge.clone()], [first.clone(), second.clone()], limits())
                .unwrap();
        let reverse =
            SemanticPlanner::new([edge], [second.clone(), first.clone()], limits()).unwrap();

        let left = forward.plan([kind("source")], kind("result")).unwrap();
        let right = reverse.plan([kind("source")], kind("result")).unwrap();

        assert_eq!(left, right);
        assert_eq!(left.plan_id, right.plan_id);
        assert_eq!(left.planning_scope_digest, right.planning_scope_digest);
        assert_eq!(left.capabilities.len(), 1);
        assert_eq!(left.capabilities[0].offers.len(), 2);
        assert!(
            left.capabilities[0]
                .offers
                .windows(2)
                .all(|pair| pair[0].offer_id < pair[1].offer_id)
        );
    }

    #[test]
    fn exact_offer_selection_changes_the_linked_invocation() {
        let (edge, first, second) = single_edge();
        let planner =
            SemanticPlanner::new([edge.clone()], [first.clone(), second.clone()], limits())
                .unwrap();
        let plan = planner.plan([kind("source")], kind("result")).unwrap();
        let inputs = || vec![linked("source", kind("source"), 7, '1')];
        let selection_extensions =
            BTreeMap::from([("org.example.selection".to_owned(), json!({"mode": "exact"}))]);
        let invocation_extensions =
            BTreeMap::from([("org.example.invocation".to_owned(), json!(["preserved"]))]);

        let first_invocation = planner
            .link_invocation(
                &plan,
                InvocationLink {
                    capability: &edge.id,
                    offer: &first.offer_id,
                    selection_extensions: selection_extensions.clone(),
                    inputs: inputs(),
                    conformance_suite: suite(),
                    invocation_extensions: invocation_extensions.clone(),
                },
            )
            .unwrap();
        let second_invocation = planner
            .link_invocation(&plan, invocation_link(&edge.id, &second.offer_id, inputs()))
            .unwrap();

        assert_ne!(
            first_invocation.invocation_id,
            second_invocation.invocation_id
        );
        assert_eq!(first_invocation.selection.offer, first);
        assert_eq!(second_invocation.selection.offer, second);
        assert_eq!(first_invocation.selection.extensions, selection_extensions);
        assert_eq!(first_invocation.extensions, invocation_extensions);
    }

    #[test]
    fn stale_or_unlisted_offer_is_refused() {
        let (edge, installed, _) = single_edge();
        let planner = SemanticPlanner::new([edge.clone()], [installed], limits()).unwrap();
        let plan = planner.plan([kind("source")], kind("result")).unwrap();
        let stale = offer(&edge, "stale", 'c');

        let error = planner
            .link_invocation(
                &plan,
                invocation_link(
                    &edge.id,
                    &stale.offer_id,
                    vec![linked("source", kind("source"), 1, '1')],
                ),
            )
            .unwrap_err();

        assert!(matches!(error, PlanningError::OfferNotPlanned { .. }));
    }

    #[test]
    fn diamond_preserves_both_branches_and_prunes_irrelevant_edges() {
        let source = kind("source");
        let left_value = kind("left");
        let right_value = kind("right");
        let result = kind("result");
        let irrelevant = kind("irrelevant");
        let left = specification(
            "left",
            &[("source", source.clone())],
            &[("left", left_value.clone())],
        );
        let right = specification(
            "right",
            &[("source", source.clone())],
            &[("right", right_value.clone())],
        );
        let join = specification(
            "join",
            &[("left", left_value.clone()), ("right", right_value.clone())],
            &[("result", result.clone())],
        );
        let noise = specification(
            "noise",
            &[("source", source.clone())],
            &[("noise", irrelevant)],
        );
        let planner = SemanticPlanner::new(
            [noise, join.clone(), right.clone(), left.clone()],
            Vec::<CapabilityOffer>::new(),
            limits(),
        )
        .unwrap();

        let plan = planner.plan([source], result).unwrap();
        let ids = plan
            .capabilities
            .iter()
            .map(|planned| planned.specification.id.clone())
            .collect::<BTreeSet<_>>();

        assert_eq!(ids, BTreeSet::from([left.id, right.id, join.id]));
    }

    #[test]
    fn alternate_routes_remain_distinct_until_a_caller_chooses() {
        let source = kind("source");
        let result = kind("result");
        let first = specification(
            "first-route",
            &[("source", source.clone())],
            &[("result", result.clone())],
        );
        let second = specification(
            "second-route",
            &[("source", source.clone())],
            &[("result", result.clone())],
        );
        let plan = SemanticPlanner::new(
            [first.clone(), second.clone()],
            [
                offer(&first, "first-route", 'a'),
                offer(&second, "second-route", 'b'),
            ],
            limits(),
        )
        .unwrap()
        .plan([source], result)
        .unwrap();

        assert_eq!(
            plan.capabilities
                .iter()
                .map(|planned| planned.specification.id.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([first.id, second.id])
        );
    }

    #[test]
    fn providerless_edges_remain_as_explicit_needs() {
        let (edge, _, _) = single_edge();
        let plan = SemanticPlanner::new([edge.clone()], Vec::<CapabilityOffer>::new(), limits())
            .unwrap()
            .plan([kind("source")], kind("result"))
            .unwrap();

        assert_eq!(plan.needs().collect::<Vec<_>>(), vec![&edge]);
    }

    #[test]
    fn unseeded_cycles_are_unreachable_and_seeded_cycles_are_finite() {
        let a = kind("a");
        let b = kind("b");
        let b_from_a = specification("b-from-a", &[("a", a.clone())], &[("b", b.clone())]);
        let a_from_b = specification("a-from-b", &[("b", b.clone())], &[("a", a.clone())]);
        let planner = SemanticPlanner::new(
            [a_from_b.clone(), b_from_a.clone()],
            Vec::<CapabilityOffer>::new(),
            limits(),
        )
        .unwrap();

        assert!(matches!(
            planner.plan([kind("outside")], a.clone()),
            Err(PlanningError::Unreachable(_))
        ));

        let seeded = planner.plan([a], b).unwrap();
        assert_eq!(seeded.capabilities.len(), 1);
        assert_eq!(seeded.capabilities[0].specification.id, b_from_a.id);
    }

    #[test]
    fn repeated_value_kinds_remain_distinct_named_inputs() {
        let source = kind("source");
        let result = kind("result");
        let compare = specification(
            "compare",
            &[("left", source.clone()), ("right", source.clone())],
            &[("result", result.clone())],
        );
        let implementation = offer(&compare, "compare", 'd');
        let planner =
            SemanticPlanner::new([compare.clone()], [implementation.clone()], limits()).unwrap();
        let plan = planner.plan([source.clone()], result).unwrap();

        let invocation = planner
            .link_invocation(
                &plan,
                invocation_link(
                    &compare.id,
                    &implementation.offer_id,
                    vec![
                        linked("left", source.clone(), 1, '1'),
                        linked("right", source, 2, '2'),
                    ],
                ),
            )
            .unwrap();

        assert_eq!(invocation.inputs[0].port, port("left"));
        assert_eq!(invocation.inputs[1].port, port("right"));
        assert_ne!(invocation.inputs[0].fact.id, invocation.inputs[1].fact.id);
    }

    #[test]
    fn every_inventory_bound_fails_closed() {
        let source = kind("source");
        let middle = kind("middle");
        let result = kind("result");
        let first = specification(
            "first",
            &[("source", source.clone())],
            &[("middle", middle.clone())],
        );
        let second = specification(
            "second",
            &[("middle", middle)],
            &[("result", result.clone())],
        );

        let mut bounded = limits();
        bounded.max_capabilities = nonzero(1);
        assert_limit(
            &SemanticPlanner::new(
                [first.clone(), second.clone()],
                Vec::<CapabilityOffer>::new(),
                bounded,
            )
            .unwrap_err(),
            "capabilities",
        );

        bounded = limits();
        bounded.max_value_kinds = nonzero(1);
        assert_limit(
            &SemanticPlanner::new([first.clone()], Vec::<CapabilityOffer>::new(), bounded)
                .unwrap_err(),
            "value kinds",
        );

        bounded = limits();
        bounded.max_ports_per_capability = nonzero(1);
        assert_limit(
            &SemanticPlanner::new([first.clone()], Vec::<CapabilityOffer>::new(), bounded)
                .unwrap_err(),
            "ports per capability",
        );

        bounded = limits();
        bounded.max_total_ports = nonzero(3);
        assert_limit(
            &SemanticPlanner::new(
                [first.clone(), second],
                Vec::<CapabilityOffer>::new(),
                bounded,
            )
            .unwrap_err(),
            "total ports",
        );

        let first_offer = offer(&first, "first", 'a');
        let second_offer = offer(&first, "second", 'b');
        bounded = limits();
        bounded.max_total_offers = nonzero(1);
        assert_limit(
            &SemanticPlanner::new(
                [first.clone()],
                [first_offer.clone(), second_offer.clone()],
                bounded,
            )
            .unwrap_err(),
            "total offers",
        );

        bounded = limits();
        bounded.max_offers_per_capability = nonzero(1);
        assert_limit(
            &SemanticPlanner::new([first], [first_offer, second_offer], bounded).unwrap_err(),
            "offers per capability",
        );
    }

    #[test]
    fn iterator_bounds_stop_at_the_first_excess_item() {
        let first = specification("first", &[], &[("value", kind("first"))]);
        let second = specification("second", &[], &[("value", kind("second"))]);
        let mut bounded = limits();
        bounded.max_capabilities = nonzero(1);
        let specifications = [first.clone(), second]
            .into_iter()
            .chain(std::iter::once_with(|| {
                panic!("capability iterator was polled after the first excess item")
            }));
        assert_limit(
            &SemanticPlanner::new(specifications, Vec::<CapabilityOffer>::new(), bounded)
                .unwrap_err(),
            "capabilities",
        );

        let first_offer = offer(&first, "first", 'a');
        let second_offer = offer(&first, "second", 'b');
        bounded = limits();
        bounded.max_total_offers = nonzero(1);
        let offers = [first_offer, second_offer]
            .into_iter()
            .chain(std::iter::once_with(|| {
                panic!("offer iterator was polled after the first excess item")
            }));
        assert_limit(
            &SemanticPlanner::new([first], offers, bounded).unwrap_err(),
            "total offers",
        );

        let result = kind("result");
        let producer = specification("producer", &[], &[("result", result.clone())]);
        bounded = limits();
        bounded.max_value_kinds = nonzero(2);
        let planner =
            SemanticPlanner::new([producer], Vec::<CapabilityOffer>::new(), bounded).unwrap();
        let initial = [kind("first"), kind("second"), kind("third")]
            .into_iter()
            .chain(std::iter::once_with(|| {
                panic!("initial-kind iterator was polled after the first excess item")
            }));
        assert_limit(
            &planner.plan(initial, result).unwrap_err(),
            "initial value kinds",
        );
    }

    #[test]
    fn deserialized_plan_validation_applies_explicit_bounds() {
        let source = kind("source");
        let result = kind("result");
        let first = specification(
            "first-route",
            &[("source", source.clone())],
            &[("result", result.clone())],
        );
        let second = specification(
            "second-route",
            &[("source", source.clone())],
            &[("result", result.clone())],
        );
        let plan = SemanticPlanner::new([first, second], Vec::<CapabilityOffer>::new(), limits())
            .unwrap()
            .plan([source], result)
            .unwrap();
        let mut bounded = limits();
        bounded.max_capabilities = nonzero(1);

        assert_limit(&plan.validate(bounded).unwrap_err(), "plan capabilities");
    }

    #[test]
    fn canonical_identity_rejects_unsafe_json_numbers() {
        let (mut edge, _, _) = single_edge();
        edge.extensions
            .insert("org.example.unsafe".to_owned(), json!(u64::MAX));

        assert!(matches!(
            SemanticPlanner::new([edge], Vec::<CapabilityOffer>::new(), limits()),
            Err(PlanningError::Serialization(_))
        ));

        let (edge, implementation, _) = single_edge();
        let mut plan = SemanticPlanner::new([edge], [implementation], limits())
            .unwrap()
            .plan([kind("source")], kind("result"))
            .unwrap();
        plan.extensions
            .insert("org.example.unsafe".to_owned(), json!(u64::MAX));
        assert!(matches!(
            plan_digest(&plan),
            Err(PlanningError::Serialization(_))
        ));
    }

    #[test]
    fn malformed_default_suite_is_refused_in_inventory_and_wire_plans() {
        let (mut edge, _, _) = single_edge();
        edge.default_conformance_suite = "arbitrary".to_owned();
        assert!(matches!(
            SemanticPlanner::new([edge.clone()], Vec::<CapabilityOffer>::new(), limits()),
            Err(PlanningError::InvalidSpecification { .. })
        ));

        let (valid, implementation, _) = single_edge();
        let mut plan = SemanticPlanner::new([valid], [implementation], limits())
            .unwrap()
            .plan([kind("source")], kind("result"))
            .unwrap();
        plan.capabilities[0].specification = edge;
        assert!(matches!(
            plan.validate(limits()),
            Err(PlanningError::InvalidSpecification { .. })
        ));
    }

    #[test]
    fn linking_revalidates_plan_claims_against_installed_inventory() {
        let (edge, installed, _) = single_edge();
        let planner = SemanticPlanner::new([edge.clone()], [installed.clone()], limits()).unwrap();
        let plan = planner.plan([kind("source")], kind("result")).unwrap();
        let other = offer(&edge, "other", 'c');
        let other_planner =
            SemanticPlanner::new([edge.clone()], [other.clone()], limits()).unwrap();
        assert!(matches!(
            other_planner.link_invocation(
                &plan,
                invocation_link(
                    &edge.id,
                    &installed.offer_id,
                    vec![linked("source", kind("source"), 1, '1')],
                ),
            ),
            Err(PlanningError::PlanningScopeMismatch { .. })
        ));

        let mut forged_offer_plan = plan.clone();
        forged_offer_plan.capabilities[0].offers.push(other.clone());
        forged_offer_plan.capabilities[0]
            .offers
            .sort_by(|left, right| left.offer_id.cmp(&right.offer_id));
        reidentify(&mut forged_offer_plan);
        forged_offer_plan.validate(limits()).unwrap();
        assert!(matches!(
            planner.link_invocation(
                &forged_offer_plan,
                invocation_link(
                    &edge.id,
                    &other.offer_id,
                    vec![linked("source", kind("source"), 1, '1')],
                ),
            ),
            Err(PlanningError::OfferNotInstalled { .. })
        ));

        let mut forged_specification_plan = plan;
        forged_specification_plan.capabilities[0]
            .specification
            .default_conformance_suite =
            ConformanceSuiteId::new("org.example.conformance", "other", VERSION).to_string();
        reidentify(&mut forged_specification_plan);
        forged_specification_plan.validate(limits()).unwrap();
        assert!(matches!(
            planner.link_invocation(
                &forged_specification_plan,
                invocation_link(
                    &edge.id,
                    &installed.offer_id,
                    vec![linked("source", kind("source"), 1, '1')],
                ),
            ),
            Err(PlanningError::SpecificationInventoryMismatch(_))
        ));
    }

    #[test]
    fn planning_request_value_kind_bound_includes_initial_and_target_kinds() {
        let result = kind("result");
        let producer = specification("produce", &[], &[("result", result.clone())]);
        let mut bounded = limits();
        bounded.max_value_kinds = nonzero(2);
        let planner =
            SemanticPlanner::new([producer], Vec::<CapabilityOffer>::new(), bounded).unwrap();

        assert_limit(
            &planner
                .plan([kind("first"), kind("second")], result)
                .unwrap_err(),
            "value kinds",
        );
    }

    #[test]
    fn unknown_extensions_round_trip_and_refuse_unsafe_linking() {
        let (edge, implementation, _) = single_edge();
        let planner =
            SemanticPlanner::new([edge.clone()], [implementation.clone()], limits()).unwrap();
        let mut root_extended = planner.plan([kind("source")], kind("result")).unwrap();
        let plain_id = root_extended.plan_id.clone();
        root_extended.extensions.insert(
            "org.example.future".to_owned(),
            json!({"meaning": [1, 2, 3]}),
        );
        reidentify(&mut root_extended);
        let encoded = serde_json::to_vec(&root_extended).unwrap();
        let decoded: SemanticPlan = serde_json::from_slice(&encoded).unwrap();

        assert_eq!(decoded, root_extended);
        decoded.validate(limits()).unwrap();
        assert_ne!(decoded.plan_id, plain_id);
        assert!(matches!(
            planner.link_invocation(
                &decoded,
                invocation_link(
                    &edge.id,
                    &implementation.offer_id,
                    vec![linked("source", kind("source"), 1, '1')],
                ),
            ),
            Err(PlanningError::UnsupportedPlanExtensions)
        ));
        let available = BTreeSet::from([AvailableOffer {
            capability: edge.id.clone(),
            offer: implementation.offer_id.clone(),
        }]);
        assert!(matches!(
            planner.select_route_with_available_offers(
                &decoded,
                &available,
                RouteSelection::UniqueOnly,
            ),
            Err(PlanningError::UnsupportedPlanExtensions | PlanningError::PlanInventoryMismatch)
        ));

        let mut node_extended = planner.plan([kind("source")], kind("result")).unwrap();
        node_extended.capabilities[0]
            .extensions
            .insert("org.example.node".to_owned(), json!(true));
        reidentify(&mut node_extended);
        node_extended.validate(limits()).unwrap();
        assert!(matches!(
            planner.link_invocation(
                &node_extended,
                invocation_link(
                    &edge.id,
                    &implementation.offer_id,
                    vec![linked("source", kind("source"), 1, '1')],
                ),
            ),
            Err(PlanningError::UnsupportedPlanNodeExtensions(_))
        ));
        assert!(matches!(
            planner.select_route_with_available_offers(
                &node_extended,
                &available,
                RouteSelection::UniqueOnly,
            ),
            Err(PlanningError::UnsupportedPlanNodeExtensions(_)
                | PlanningError::PlanInventoryMismatch)
        ));
    }

    #[test]
    fn plan_identity_detects_mutation() {
        let (edge, implementation, _) = single_edge();
        let mut plan = SemanticPlanner::new([edge], [implementation], limits())
            .unwrap()
            .plan([kind("source")], kind("result"))
            .unwrap();
        plan.planning_scope_digest = PlanningScopeDigest::parse(sha('f')).unwrap();

        assert!(matches!(
            plan.validate(limits()),
            Err(PlanningError::PlanIdentityMismatch { .. })
        ));
    }

    #[test]
    fn initially_available_target_has_an_empty_plan() {
        let (edge, implementation, _) = single_edge();
        let plan = SemanticPlanner::new([edge], [implementation], limits())
            .unwrap()
            .plan([kind("result"), kind("source")], kind("result"))
            .unwrap();

        assert!(plan.capabilities.is_empty());
        plan.validate(limits()).unwrap();
    }

    #[test]
    fn exact_output_goal_runs_one_generator_when_source_and_outputs_share_a_kind() {
        let fixture = multi_backend_fixture();

        let kind_only = fixture
            .planner
            .plan([fixture.content_set.clone()], fixture.content_set.clone())
            .unwrap();
        assert!(kind_only.capabilities.is_empty());
        assert!(
            !serde_json::to_value(&kind_only)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("target_output"),
            "legacy value-kind plans must omit the additive exact target field"
        );

        let http_target = RouteOutputRef {
            capability: fixture.generate_http.clone(),
            output_port: port("files"),
            extensions: BTreeMap::new(),
        };
        let http_plan = fixture
            .planner
            .plan_output([fixture.content_set.clone()], http_target.clone())
            .unwrap();
        assert_eq!(http_plan.target_output, Some(http_target.clone()));
        assert_eq!(
            serde_json::from_slice::<SemanticPlan>(&serde_json::to_vec(&http_plan).unwrap())
                .unwrap(),
            http_plan
        );
        assert_eq!(
            http_plan
                .capabilities
                .iter()
                .map(|planned| planned.specification.id.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([fixture.read_http.clone(), fixture.generate_http.clone()])
        );
        let http_route = fixture
            .planner
            .select_route(&http_plan, RouteSelection::UniqueOnly)
            .unwrap();
        assert_eq!(
            http_route.target,
            RouteValueSource::CapabilityOutput {
                capability: http_target.capability,
                output_port: http_target.output_port,
                extensions: BTreeMap::new(),
            }
        );

        let sql_target = RouteOutputRef {
            capability: fixture.generate_sql.clone(),
            output_port: port("files"),
            extensions: BTreeMap::new(),
        };
        let sql_plan = fixture
            .planner
            .plan_output([fixture.content_set], sql_target.clone())
            .unwrap();
        assert_eq!(
            sql_plan
                .capabilities
                .iter()
                .map(|planned| planned.specification.id.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([fixture.read_data_model, fixture.generate_sql])
        );
        let sql_route = fixture
            .planner
            .select_route(&sql_plan, RouteSelection::UniqueOnly)
            .unwrap();
        assert_eq!(
            sql_route.target,
            RouteValueSource::CapabilityOutput {
                capability: sql_target.capability,
                output_port: sql_target.output_port,
                extensions: BTreeMap::new(),
            }
        );
        assert_ne!(http_plan.plan_id, sql_plan.plan_id);
    }

    #[test]
    fn exact_output_goal_does_not_fall_through_to_an_available_sibling() {
        let source = kind("source");
        let content_set = kind("content-set");
        let requested = specification(
            "requested-generator",
            &[("source", source.clone())],
            &[("files", content_set.clone())],
        );
        let sibling = specification(
            "available-sibling",
            &[("source", source.clone())],
            &[("files", content_set)],
        );
        let planner = SemanticPlanner::new(
            [requested.clone(), sibling.clone()],
            [offer(&sibling, "available-sibling", 'a')],
            limits(),
        )
        .unwrap();
        let target = RouteOutputRef {
            capability: requested.id.clone(),
            output_port: port("files"),
            extensions: BTreeMap::new(),
        };
        let plan = planner.plan_output([source], target.clone()).unwrap();

        let PlanningError::AllRoutesBlocked(blocked) = planner
            .select_route(&plan, RouteSelection::UniqueOnly)
            .unwrap_err()
        else {
            panic!("the exact requested generator must remain blocked")
        };
        assert_eq!(blocked.target_alternatives, vec![target]);
        assert_eq!(blocked.nodes.len(), 1);
        assert_eq!(blocked.nodes[0].capability, requested.id);
        assert!(blocked.nodes[0].missing_offer);
        assert!(
            plan.capabilities
                .iter()
                .all(|planned| planned.specification.id != sibling.id)
        );
    }

    #[test]
    fn unreachable_exact_output_names_the_terminal_even_when_its_kind_is_reachable() {
        let source = kind("source");
        let missing = kind("missing");
        let content_set = kind("content-set");
        let requested = specification(
            "unreachable-generator",
            &[("missing", missing)],
            &[("files", content_set.clone())],
        );
        let sibling = specification(
            "reachable-sibling",
            &[("source", source.clone())],
            &[("files", content_set)],
        );
        let planner = SemanticPlanner::new(
            [requested.clone(), sibling.clone()],
            [
                offer(&requested, "unreachable-generator", 'a'),
                offer(&sibling, "reachable-sibling", 'b'),
            ],
            limits(),
        )
        .unwrap();
        let target = RouteOutputRef {
            capability: requested.id,
            output_port: port("files"),
            extensions: BTreeMap::new(),
        };

        let error = planner.plan_output([source], target.clone()).unwrap_err();

        assert!(matches!(
            &error,
            PlanningError::UnreachableOutput {
                target: actual,
                ..
            } if actual.as_ref() == &target
        ));
        assert!(error.to_string().contains(&target.capability.to_string()));
        assert!(!error.to_string().contains("target value kind"));
    }

    #[test]
    fn exact_output_goal_does_not_invent_a_seed_for_a_pure_cycle() {
        let model = kind("model");
        let content_set = kind("content-set");
        let reader = specification(
            "reader",
            &[("source", content_set.clone())],
            &[("model", model.clone())],
        );
        let generator = specification("generator", &[("model", model)], &[("files", content_set)]);
        let planner = SemanticPlanner::new(
            [reader.clone(), generator.clone()],
            [
                offer(&reader, "reader", 'a'),
                offer(&generator, "generator", 'b'),
            ],
            limits(),
        )
        .unwrap();
        let target = RouteOutputRef {
            capability: generator.id,
            output_port: port("files"),
            extensions: BTreeMap::new(),
        };

        assert!(matches!(
            planner.plan_output([], target),
            Err(PlanningError::UnreachableOutput { .. })
        ));
    }

    #[test]
    fn exact_output_goal_keeps_dependency_route_ambiguity_conservative() {
        let source = kind("source");
        let middle = kind("middle");
        let content_set = kind("content-set");
        let first = specification(
            "first-reader",
            &[("source", source.clone())],
            &[("model", middle.clone())],
        );
        let second = specification(
            "second-reader",
            &[("source", source.clone())],
            &[("model", middle.clone())],
        );
        let generator = specification("generator", &[("model", middle)], &[("files", content_set)]);
        let planner = SemanticPlanner::new(
            [first.clone(), second.clone(), generator.clone()],
            [
                offer(&first, "first-reader", 'a'),
                offer(&second, "second-reader", 'b'),
                offer(&generator, "generator", 'c'),
            ],
            limits(),
        )
        .unwrap();
        let plan = planner
            .plan_output(
                [source],
                RouteOutputRef {
                    capability: generator.id,
                    output_port: port("files"),
                    extensions: BTreeMap::new(),
                },
            )
            .unwrap();

        assert!(matches!(
            planner.select_route(&plan, RouteSelection::UniqueOnly),
            Err(PlanningError::AmbiguousCapabilityRoute)
        ));
    }

    #[test]
    fn exact_output_goal_rejects_unknown_coordinates_and_extensions() {
        let source = kind("source");
        let result = kind("result");
        let generator = specification(
            "generator",
            &[("source", source.clone())],
            &[("files", result)],
        );
        let planner = SemanticPlanner::new(
            [generator.clone()],
            [offer(&generator, "generator", 'a')],
            limits(),
        )
        .unwrap();

        assert!(matches!(
            planner.plan_output(
                [source.clone()],
                RouteOutputRef {
                    capability: capability("unknown"),
                    output_port: port("files"),
                    extensions: BTreeMap::new(),
                }
            ),
            Err(PlanningError::CapabilityNotInstalled(_))
        ));
        assert!(matches!(
            planner.plan_output(
                [source.clone()],
                RouteOutputRef {
                    capability: generator.id.clone(),
                    output_port: port("missing"),
                    extensions: BTreeMap::new(),
                }
            ),
            Err(PlanningError::OutputPortNotInstalled { .. })
        ));
        assert!(matches!(
            planner.plan_output(
                [source],
                RouteOutputRef {
                    capability: generator.id,
                    output_port: port("files"),
                    extensions: BTreeMap::from([("org.example.future".to_owned(), json!(true))]),
                }
            ),
            Err(PlanningError::UnsupportedTargetExtensions)
        ));
    }

    #[test]
    fn same_kind_output_ports_have_distinct_goals_and_reject_substitution() {
        let source = kind("source");
        let result = kind("result");
        let generator = specification(
            "generator",
            &[("source", source.clone())],
            &[("first", result.clone()), ("second", result)],
        );
        let planner = SemanticPlanner::new(
            [generator.clone()],
            [offer(&generator, "generator", 'a')],
            limits(),
        )
        .unwrap();
        let target = |name| RouteOutputRef {
            capability: generator.id.clone(),
            output_port: port(name),
            extensions: BTreeMap::new(),
        };
        let first = planner
            .plan_output([source.clone()], target("first"))
            .unwrap();
        let second = planner.plan_output([source], target("second")).unwrap();
        assert_ne!(first.plan_id, second.plan_id);

        let mut route = planner
            .select_route(&first, RouteSelection::UniqueOnly)
            .unwrap();
        route.target = RouteValueSource::CapabilityOutput {
            capability: generator.id,
            output_port: port("second"),
            extensions: BTreeMap::new(),
        };
        route.route_id = RouteId::parse(route_digest(&route).unwrap()).unwrap();
        assert!(matches!(
            route.validate(&first, limits()),
            Err(PlanningError::InvalidRouteTarget(_))
        ));

        let mut forged = first;
        forged.target_value_kind = kind("other");
        reidentify(&mut forged);
        assert!(matches!(
            forged.validate(limits()),
            Err(PlanningError::InvalidGraphSlice)
        ));
    }

    #[test]
    fn complete_scope_identity_changes_when_irrelevant_inventory_changes() {
        let (edge, implementation, _) = single_edge();
        let base =
            SemanticPlanner::new([edge.clone()], [implementation.clone()], limits()).unwrap();
        let noise = specification(
            "noise",
            &[("source", kind("source"))],
            &[("noise", kind("noise"))],
        );
        let noise_offer = offer(&noise, "noise", 'e');
        let expanded =
            SemanticPlanner::new([edge, noise], [implementation, noise_offer], limits()).unwrap();
        let base_plan = base.plan([kind("source")], kind("result")).unwrap();
        let expanded_plan = expanded.plan([kind("source")], kind("result")).unwrap();

        assert_eq!(base_plan.capabilities, expanded_plan.capabilities);
        assert_ne!(base.scope_digest(), expanded.scope_digest());
        assert_ne!(base_plan.plan_id, expanded_plan.plan_id);
    }

    #[test]
    fn orphaned_offers_are_refused_before_planning() {
        let (edge, _, _) = single_edge();
        let error = SemanticPlanner::new(
            Vec::<CapabilitySpec>::new(),
            [offer(&edge, "orphan", 'e')],
            limits(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            PlanningError::OfferForUnknownCapability { .. }
        ));
    }

    #[test]
    fn unique_only_selects_one_exact_dependency_route() {
        let source = kind("source");
        let middle = kind("middle");
        let result = kind("result");
        let first = specification(
            "first",
            &[("source", source.clone())],
            &[("middle", middle.clone())],
        );
        let second = specification(
            "second",
            &[("left", middle.clone()), ("right", middle)],
            &[("result", result.clone())],
        );
        let first_offer = offer(&first, "first", 'a');
        let second_offer = offer(&second, "second", 'b');
        let planner = SemanticPlanner::new(
            [second.clone(), first.clone()],
            [second_offer.clone(), first_offer.clone()],
            limits(),
        )
        .unwrap();
        let plan = planner.plan([source], result).unwrap();

        let route = planner
            .select_route(&plan, RouteSelection::UniqueOnly)
            .unwrap();

        route.validate(&plan, limits()).unwrap();
        let decoded: SelectedRoute =
            serde_json::from_slice(&serde_json::to_vec(&route).unwrap()).unwrap();
        assert_eq!(decoded, route);
        assert_eq!(
            route
                .steps
                .iter()
                .map(|step| step.capability.clone())
                .collect::<Vec<_>>(),
            vec![first.id, second.id]
        );
        assert_eq!(route.steps[0].offer, first_offer.offer_id);
        assert_eq!(route.steps[1].offer, second_offer.offer_id);
        assert!(matches!(
            route.steps[0].inputs[0].source,
            RouteValueSource::Initial { .. }
        ));
        assert!(matches!(
            route.steps[1].inputs[0].source,
            RouteValueSource::CapabilityOutput { .. }
        ));
        assert_eq!(route.steps[1].inputs[0].input_port, port("left"));
        assert_eq!(route.steps[1].inputs[1].input_port, port("right"));
        assert_eq!(
            route.steps[1].inputs[0].source,
            route.steps[1].inputs[1].source
        );
    }

    #[test]
    fn unique_only_refuses_capability_and_offer_ambiguity() {
        let source = kind("source");
        let result = kind("result");
        let first = specification(
            "first",
            &[("source", source.clone())],
            &[("result", result.clone())],
        );
        let second = specification(
            "second",
            &[("source", source.clone())],
            &[("result", result.clone())],
        );
        let planner = SemanticPlanner::new(
            [first.clone(), second.clone()],
            [offer(&first, "first", 'a'), offer(&second, "second", 'b')],
            limits(),
        )
        .unwrap();
        let plan = planner.plan([source.clone()], result.clone()).unwrap();
        assert!(matches!(
            planner.select_route(&plan, RouteSelection::UniqueOnly),
            Err(PlanningError::AmbiguousCapabilityRoute)
        ));

        let only = specification(
            "only",
            &[("source", source.clone())],
            &[("result", result.clone())],
        );
        let planner = SemanticPlanner::new(
            [only.clone()],
            [offer(&only, "one", 'c'), offer(&only, "two", 'd')],
            limits(),
        )
        .unwrap();
        let plan = planner.plan([source], result).unwrap();
        assert!(matches!(
            planner.select_route(&plan, RouteSelection::UniqueOnly),
            Err(PlanningError::AmbiguousOffer(capability)) if capability == only.id
        ));
    }

    #[test]
    fn caller_availability_filters_selection_without_changing_plan_identity() {
        let source = kind("source");
        let result = kind("result");
        let first = specification(
            "first",
            &[("source", source.clone())],
            &[("result", result.clone())],
        );
        let second = specification(
            "second",
            &[("source", source.clone())],
            &[("result", result.clone())],
        );
        let first_offer = offer(&first, "first", 'a');
        let second_offer = offer(&second, "second", 'b');
        let planner = SemanticPlanner::new(
            [first.clone(), second],
            [first_offer.clone(), second_offer],
            limits(),
        )
        .unwrap();
        let plan = planner.plan([source], result).unwrap();
        let available = BTreeSet::from([AvailableOffer {
            capability: first.id.clone(),
            offer: first_offer.offer_id.clone(),
        }]);

        let selected = planner
            .select_route_with_available_offers(&plan, &available, RouteSelection::UniqueOnly)
            .unwrap();

        assert_eq!(selected.plan_id, plan.plan_id);
        assert_eq!(selected.steps[0].capability, first.id);
        assert_eq!(selected.steps[0].offer, first_offer.offer_id);
        selected.validate(&plan, limits()).unwrap();

        let PlanningError::AllRoutesBlocked(blocked) = planner
            .select_route_with_available_offers(&plan, &BTreeSet::new(), RouteSelection::UniqueOnly)
            .unwrap_err()
        else {
            panic!("expected external availability blockage");
        };
        assert_eq!(blocked.plan_id, plan.plan_id);
        assert!(blocked.nodes.iter().all(|node| !node.missing_offer));
    }

    #[test]
    fn a_blocked_alternative_does_not_hide_one_executable_route() {
        let source = kind("source");
        let result = kind("result");
        let available = specification(
            "available",
            &[("source", source.clone())],
            &[("result", result.clone())],
        );
        let missing = specification(
            "missing",
            &[("source", source.clone())],
            &[("result", result.clone())],
        );
        let available_offer = offer(&available, "available", 'a');
        let planner = SemanticPlanner::new(
            [missing, available.clone()],
            [available_offer.clone()],
            limits(),
        )
        .unwrap();
        let plan = planner.plan([source], result).unwrap();

        let route = planner
            .select_route(&plan, RouteSelection::UniqueOnly)
            .unwrap();
        assert_eq!(route.steps.len(), 1);
        assert_eq!(route.steps[0].capability, available.id);
        assert_eq!(route.steps[0].offer, available_offer.offer_id);
    }

    #[test]
    fn all_blocked_routes_retain_the_bounded_and_or_graph() {
        let source = kind("source");
        let result = kind("result");
        let first = specification(
            "first",
            &[("source", source.clone())],
            &[("result", result.clone())],
        );
        let second = specification(
            "second",
            &[("source", source.clone())],
            &[("result", result.clone())],
        );
        let planner = SemanticPlanner::new(
            [first.clone(), second.clone()],
            Vec::<CapabilityOffer>::new(),
            limits(),
        )
        .unwrap();
        let plan = planner.plan([source], result).unwrap();

        let PlanningError::AllRoutesBlocked(blocked) = planner
            .select_route(&plan, RouteSelection::UniqueOnly)
            .unwrap_err()
        else {
            panic!("expected route-specific blockage");
        };
        assert_eq!(blocked.protocol, BLOCKED_ROUTE_PROTOCOL);
        assert_eq!(blocked.plan_id, plan.plan_id);
        assert_eq!(blocked.target_alternatives.len(), 2);
        assert_eq!(blocked.nodes.len(), 2);
        assert_eq!(blocked.missing_needs, vec![first, second]);
        assert!(blocked.nodes.iter().all(|node| node.missing_offer));
        let decoded: BlockedRouteAnalysis =
            serde_json::from_slice(&serde_json::to_vec(blocked.as_ref()).unwrap()).unwrap();
        assert_eq!(decoded, *blocked);

        let mut extended = decoded;
        extended
            .extensions
            .insert("org.example.blockage".to_owned(), json!({"future": true}));
        extended.nodes[0]
            .extensions
            .insert("org.example.node".to_owned(), json!(1));
        extended.target_alternatives[0]
            .extensions
            .insert("org.example.output".to_owned(), json!([1, 2]));
        let round_trip: BlockedRouteAnalysis =
            serde_json::from_slice(&serde_json::to_vec(&extended).unwrap()).unwrap();
        assert_eq!(round_trip, extended);
    }

    #[test]
    fn blocked_analysis_excludes_providerless_nodes_outside_the_blockage_dag() {
        let source = kind("source");
        let middle = kind("middle");
        let result = kind("result");
        let available = specification(
            "available-middle",
            &[("source", source.clone())],
            &[("middle", middle.clone())],
        );
        let unnecessary = specification(
            "unnecessary-middle",
            &[("source", source.clone())],
            &[("middle", middle.clone())],
        );
        let target = specification(
            "missing-target",
            &[("middle", middle)],
            &[("result", result.clone())],
        );
        let planner = SemanticPlanner::new(
            [unnecessary.clone(), target.clone(), available.clone()],
            [offer(&available, "available-middle", 'a')],
            limits(),
        )
        .unwrap();
        let plan = planner.plan([source], result).unwrap();

        let PlanningError::AllRoutesBlocked(blocked) = planner
            .select_route(&plan, RouteSelection::UniqueOnly)
            .unwrap_err()
        else {
            panic!("expected route-specific blockage");
        };

        assert_eq!(blocked.missing_needs, vec![target.clone()]);
        assert_eq!(blocked.nodes.len(), 1);
        assert_eq!(blocked.nodes[0].capability, target.id);
        assert!(blocked.nodes[0].blocked_inputs.is_empty());
        assert!(
            !blocked
                .missing_needs
                .iter()
                .any(|need| need.id == unnecessary.id)
        );
    }

    #[test]
    fn selected_route_substitution_and_identity_tampering_fail_closed() {
        let (edge, installed, other) = single_edge();
        let planner = SemanticPlanner::new([edge.clone()], [installed.clone()], limits()).unwrap();
        let plan = planner.plan([kind("source")], kind("result")).unwrap();
        let route = planner
            .select_route(&plan, RouteSelection::UniqueOnly)
            .unwrap();

        let mut substituted = route.clone();
        substituted.steps[0].offer = other.offer_id;
        assert!(matches!(
            substituted.validate(&plan, limits()),
            Err(PlanningError::OfferNotPlanned { .. })
        ));

        let mut changed_identity = route;
        changed_identity.route_id = RouteId::parse(sha('f')).unwrap();
        assert!(matches!(
            changed_identity.validate(&plan, limits()),
            Err(PlanningError::RouteIdentityMismatch { .. })
        ));
    }

    #[test]
    fn inventory_bound_selection_rejects_an_omitted_alternative() {
        let source = kind("source");
        let result = kind("result");
        let first = specification(
            "first",
            &[("source", source.clone())],
            &[("result", result.clone())],
        );
        let second = specification(
            "second",
            &[("source", source.clone())],
            &[("result", result.clone())],
        );
        let planner = SemanticPlanner::new(
            [first.clone(), second.clone()],
            [offer(&first, "first", 'a'), offer(&second, "second", 'b')],
            limits(),
        )
        .unwrap();
        let mut plan = planner.plan([source], result).unwrap();
        plan.capabilities
            .retain(|planned| planned.specification.id == first.id);
        reidentify(&mut plan);
        plan.validate(limits()).unwrap();

        assert!(matches!(
            planner.select_route(&plan, RouteSelection::UniqueOnly),
            Err(PlanningError::PlanInventoryMismatch)
        ));
    }

    fn assert_limit(error: &PlanningError, resource: &'static str) {
        assert!(matches!(
            error,
            PlanningError::LimitExceeded {
                resource: actual,
                ..
            } if *actual == resource
        ));
    }
}
