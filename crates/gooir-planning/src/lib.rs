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
use gooir_capability::{CapabilityId, CapabilitySpec, ValueKindId, canonical_digest};
use gooir_package::PackageRegistry;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Exact versioned semantic-plan protocol emitted by this crate.
pub const SEMANTIC_PLAN_PROTOCOL: &str = "org.gooi.capability.plan/v1";

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
    /// Digest of the complete specification and offer inventory considered.
    PlanningScopeDigest
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
                "capabilities",
            ],
        )?;
        validate_sorted_value_kinds(&self.initial_value_kinds)?;
        if !self.target_value_kind.is_well_formed() {
            return Err(PlanningError::InvalidValueKind(
                self.target_value_kind.clone(),
            ));
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

        if self.initial_value_kinds.contains(&self.target_value_kind) {
            if !self.capabilities.is_empty() {
                return Err(PlanningError::InvalidGraphSlice);
            }
            return Ok(());
        }
        let initial = self.initial_value_kinds.iter().cloned().collect();
        let forward = forward_reachable(&specifications, &initial);
        let reachable_kinds = forward_value_kinds(&specifications, &initial, &forward);
        if !reachable_kinds.contains(&self.target_value_kind) {
            return Err(PlanningError::InvalidGraphSlice);
        }
        let relevant =
            backward_relevant(&specifications, &forward, &initial, &self.target_value_kind);
        if relevant.len() != specifications.len()
            || !specifications.keys().all(|id| relevant.contains(id))
        {
            return Err(PlanningError::InvalidGraphSlice);
        }
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

        let relevant = if initial.contains(&target_value_kind) {
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
    UnsupportedPlanExtensions,
    UnsupportedPlanNodeExtensions(CapabilityId),
    CapabilityNotPlanned(CapabilityId),
    CapabilityNotInstalled(CapabilityId),
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
            Self::UnsupportedPlanExtensions => formatter.write_str(
                "semantic plan carries unknown root extensions and cannot be linked safely",
            ),
            Self::UnsupportedPlanNodeExtensions(capability) => write!(
                formatter,
                "planned capability {capability} carries unknown node extensions and cannot be linked safely"
            ),
            Self::CapabilityNotPlanned(capability) => write!(
                formatter,
                "capability {capability} is not present in the exact semantic plan"
            ),
            Self::CapabilityNotInstalled(capability) => write!(
                formatter,
                "capability {capability} is not installed in this exact planning inventory"
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

fn placeholder_plan_id() -> PlanId {
    PlanId::parse(format!("sha256:{}", "0".repeat(64)))
        .expect("the plan identity placeholder is exact")
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
