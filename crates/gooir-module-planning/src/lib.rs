//! Target-independent legalization planning for heterogeneous GOOIR modules.
//!
//! This adapter adds an MLIR-like legality boundary without adding a second
//! transformation graph. A target names one required result and the exact
//! operation kinds allowed to remain; the existing semantic capability graph
//! finds candidate derivations from the kinds present in the module.
//!
//! Candidate planning is deliberately distinct from route binding. Only a
//! bound route identifies exact contained operation occurrences and proves
//! that every illegal occurrence is covered. Neither document is executable:
//! contained operation references carry no admission or authority.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use gooir_capability::strict_json::{self, StrictJsonError};
use gooir_capability::{CapabilityId, Fact, FactId, PortName, ValueKindId, canonical_digest};
use gooir_module_v0::{ModuleError, ModuleFact, SymbolName};
use gooir_planning::{
    PlanLimits, PlanningError, RouteSelection, RouteValueSource, SelectedRoute, SemanticPlan,
    SemanticPlanner,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Exact versioned candidate-plan protocol emitted by this crate.
pub const MODULE_PLAN_PROTOCOL: &str = "org.gooi.module.legalization-plan/v1";

/// Exact versioned route-bound plan protocol emitted by this crate.
pub const BOUND_MODULE_PLAN_PROTOCOL: &str = "org.gooi.module.bound-legalization-plan/v1";

const MAX_LEGAL_VALUE_KINDS: usize = 4_096;
const MAX_OPERATIONS: usize = 4_096;
const MAX_INITIAL_BINDINGS: usize = 16_384;
const MAX_EXTENSIONS_PER_SCOPE: usize = 1_024;
const MAX_EXTENSION_KEY_BYTES: usize = 512;

macro_rules! sha256_identity {
    ($(#[$meta:meta])* $name:ident, $label:literal) => {
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
            pub fn parse(value: impl Into<String>) -> Result<Self, ModulePlanningError> {
                let value = value.into();
                if is_sha256(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModulePlanningError::InvalidDigest {
                        scope: $label,
                        value,
                    })
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
    /// Content identity of one exact candidate module plan.
    ModulePlanId, "module plan ID"
}

sha256_identity! {
    /// Content identity of one exact route-bound module plan.
    BoundModulePlanId, "bound module plan ID"
}

/// Exact legality request supplied by the compiler caller.
///
/// This is request data, not module dialect data. Unknown and unlisted kinds
/// are illegal. Legality never expands to a whole dialect or another version.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LegalityTarget {
    pub required_result: ValueKindId,
    pub legal_operation_kinds: Vec<ValueKindId>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl LegalityTarget {
    /// Constructs a canonical exact target with no extensions.
    ///
    /// # Errors
    ///
    /// Refuses an invalid required result, duplicate legal kinds, configured
    /// bounds, or a required result omitted from the legal set.
    pub fn new(
        required_result: ValueKindId,
        legal_operation_kinds: impl IntoIterator<Item = ValueKindId>,
    ) -> Result<Self, ModulePlanningError> {
        let mut target = Self {
            required_result,
            legal_operation_kinds: legal_operation_kinds.into_iter().collect(),
            extensions: BTreeMap::new(),
        };
        target.legal_operation_kinds.sort();
        target.validate()?;
        Ok(target)
    }

    /// Reports whether one exact operation kind may remain in the final module.
    #[must_use]
    pub fn is_legal(&self, value_kind: &ValueKindId) -> bool {
        self.legal_operation_kinds.binary_search(value_kind).is_ok()
    }

    /// Validates this target's exact canonical allowlist.
    ///
    /// # Errors
    ///
    /// Refuses malformed kinds, duplicates, noncanonical order, bounds, or
    /// extension keys that shadow known fields.
    pub fn validate(&self) -> Result<(), ModulePlanningError> {
        if !self.required_result.is_well_formed() {
            return Err(ModulePlanningError::InvalidValueKind(
                self.required_result.clone(),
            ));
        }
        validate_count(
            "target legal operation kinds",
            self.legal_operation_kinds.len(),
            MAX_LEGAL_VALUE_KINDS,
        )?;
        validate_extensions(
            "legality target",
            &self.extensions,
            &["required_result", "legal_operation_kinds"],
        )?;
        let mut previous: Option<&ValueKindId> = None;
        for value_kind in &self.legal_operation_kinds {
            if !value_kind.is_well_formed() {
                return Err(ModulePlanningError::InvalidValueKind(value_kind.clone()));
            }
            if previous.is_some_and(|prior| prior >= value_kind) {
                return if previous == Some(value_kind) {
                    Err(ModulePlanningError::DuplicateLegalValueKind(
                        value_kind.clone(),
                    ))
                } else {
                    Err(ModulePlanningError::NonCanonical(
                        "target legal operation kinds",
                    ))
                };
            }
            previous = Some(value_kind);
        }
        if !self.is_legal(&self.required_result) {
            return Err(ModulePlanningError::RequiredResultNotLegal(
                self.required_result.clone(),
            ));
        }
        Ok(())
    }
}

/// Exact coordinate of one operation occurrence in one module fact.
///
/// The ordinal remains significant even when two occurrences contain the same
/// fact ID. This is a containment reference only, never an admitted-fact
/// reference or an authority claim.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModuleOperationRef {
    pub module_fact_id: FactId,
    pub ordinal: u32,
    pub fact_id: FactId,
    pub value_kind: ValueKindId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<SymbolName>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// A provider-neutral candidate graph for one exact module and target.
///
/// This document records available operation kinds, not a replacement claim.
/// Duplicate operation occurrences remain explicit in `operations` while the
/// nested semantic planner sees the unique set of available kinds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModulePlan {
    pub plan_id: ModulePlanId,
    pub protocol: String,
    pub source_module: FactId,
    pub target: LegalityTarget,
    pub operations: Vec<ModuleOperationRef>,
    pub semantic_plan: SemanticPlan,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// Result of candidate planning when no route is needed or one was found.
#[derive(Clone, Debug, PartialEq)]
pub enum ModulePlanningOutcome {
    /// The required result is already present and every operation is legal.
    AlreadyLegal {
        source_module: FactId,
        target: LegalityTarget,
    },
    /// A semantic route still needs explicit selection and occurrence binding.
    Planned(Box<ModulePlan>),
}

/// One exact named use of an initial value in a selected capability route.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InitialUse {
    pub capability: CapabilityId,
    pub input_port: PortName,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl InitialUse {
    /// Constructs one exact capability/input-port use with no extensions.
    ///
    /// # Errors
    ///
    /// Refuses a malformed capability or input-port identity.
    pub fn new(
        capability: CapabilityId,
        input_port: PortName,
    ) -> Result<Self, ModulePlanningError> {
        let initial_use = Self {
            capability,
            input_port,
            extensions: BTreeMap::new(),
        };
        validate_initial_use(&initial_use)?;
        Ok(initial_use)
    }
}

/// Caller choice for one ambiguous initial operation occurrence.
#[derive(Clone, Debug, PartialEq)]
pub struct InitialOperationChoice {
    pub initial_use: InitialUse,
    pub operation: ModuleOperationRef,
}

impl InitialOperationChoice {
    /// Chooses one exact contained operation for one selected-route use.
    ///
    /// Membership and type are checked later against the exact candidate plan.
    ///
    /// # Errors
    ///
    /// Refuses malformed coordinates or unsupported extension semantics.
    pub fn new(
        initial_use: InitialUse,
        operation: ModuleOperationRef,
    ) -> Result<Self, ModulePlanningError> {
        validate_initial_use(&initial_use)?;
        if !initial_use.extensions.is_empty() {
            return Err(ModulePlanningError::UnsupportedExtensions("initial use"));
        }
        validate_operation_ref(&operation)?;
        if !operation.extensions.is_empty() {
            return Err(ModulePlanningError::UnsupportedExtensions(
                "module operation reference",
            ));
        }
        Ok(Self {
            initial_use,
            operation,
        })
    }
}

/// Exact occurrence bound to one named initial use in a selected route.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InitialOperationBinding {
    pub initial_use: InitialUse,
    pub operation: ModuleOperationRef,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// Exact type mismatch attached to one selected-route initial use.
#[derive(Clone, Debug, PartialEq)]
pub struct OperationKindMismatchDetail {
    pub initial_use: InitialUse,
    pub expected: ValueKindId,
    pub actual: ValueKindId,
}

/// One selected route with exact occurrence-level legalization coverage.
///
/// An illegal operation is covered only when an initial route use is bound to
/// that exact occurrence. The document does not claim rewriting occurred.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BoundModulePlan {
    pub bound_plan_id: BoundModulePlanId,
    pub protocol: String,
    pub module_plan_id: ModulePlanId,
    pub route: SelectedRoute,
    pub initial_bindings: Vec<InitialOperationBinding>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl ModulePlan {
    /// Revalidates bounded structure and this candidate plan's content identity.
    ///
    /// # Errors
    ///
    /// Refuses malformed targets, occurrence coordinates, semantic plans,
    /// canonical order, extensions, or a changed identity.
    pub fn validate(&self, limits: PlanLimits) -> Result<(), ModulePlanningError> {
        self.validate_structure(limits)?;
        let expected = module_plan_digest(self)?;
        if self.plan_id.as_str() != expected {
            return Err(ModulePlanningError::PlanIdentityMismatch {
                expected,
                actual: self.plan_id.to_string(),
            });
        }
        Ok(())
    }

    /// Revalidates every occurrence against the exact source module fact.
    ///
    /// # Errors
    ///
    /// Refuses a different module fact or any changed, missing, reordered, or
    /// invented operation occurrence.
    pub fn validate_against(
        &self,
        module_fact: &Fact,
        limits: PlanLimits,
    ) -> Result<(), ModulePlanningError> {
        self.validate(limits)?;
        let envelope = ModuleFact::from_fact(module_fact).map_err(ModulePlanningError::Module)?;
        if self.source_module != module_fact.id {
            return Err(ModulePlanningError::SourceModuleMismatch {
                expected: self.source_module.clone(),
                actual: module_fact.id.clone(),
            });
        }
        if self.operations.len() != envelope.module.operations.len() {
            return Err(ModulePlanningError::OperationInventoryMismatch);
        }
        for (ordinal, (operation_ref, operation)) in self
            .operations
            .iter()
            .zip(&envelope.module.operations)
            .enumerate()
        {
            let expected = operation_reference(module_fact, ordinal, operation)?;
            if operation_ref != &expected {
                return Err(ModulePlanningError::OperationInventoryMismatch);
            }
        }
        Ok(())
    }

    fn validate_structure(&self, limits: PlanLimits) -> Result<(), ModulePlanningError> {
        ModulePlanId::parse(self.plan_id.to_string())?;
        parse_fact_id(&self.source_module)?;
        if self.protocol != MODULE_PLAN_PROTOCOL {
            return Err(ModulePlanningError::ProtocolMismatch {
                scope: "module plan",
                actual: self.protocol.clone(),
            });
        }
        validate_extensions(
            "module plan",
            &self.extensions,
            &[
                "plan_id",
                "protocol",
                "source_module",
                "target",
                "operations",
                "semantic_plan",
            ],
        )?;
        self.target.validate()?;
        validate_count("module operations", self.operations.len(), MAX_OPERATIONS)?;
        for (ordinal, operation) in self.operations.iter().enumerate() {
            validate_operation_ref(operation)?;
            if operation.module_fact_id != self.source_module
                || usize::try_from(operation.ordinal).ok() != Some(ordinal)
            {
                return Err(ModulePlanningError::NonCanonical(
                    "module operation references",
                ));
            }
        }
        self.semantic_plan
            .validate(limits)
            .map_err(planning_error)?;
        if self.semantic_plan.target_value_kind != self.target.required_result {
            return Err(ModulePlanningError::SemanticTargetMismatch);
        }
        let available = self
            .operations
            .iter()
            .map(|operation| operation.value_kind.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if self.semantic_plan.initial_value_kinds != available {
            return Err(ModulePlanningError::SemanticInputsMismatch);
        }
        if available.contains(&self.target.required_result) {
            return Err(ModulePlanningError::NoTypeLevelProgress {
                target: self.target.required_result.clone(),
                illegal_operations: illegal_operations(&self.operations, &self.target),
            });
        }
        Ok(())
    }
}

impl BoundModulePlan {
    /// Revalidates this bound plan against its exact candidate plan.
    ///
    /// # Errors
    ///
    /// Refuses route substitutions, ambiguous or mismatched initial bindings,
    /// incomplete illegal-operation coverage, noncanonical order, extensions,
    /// or a changed content identity.
    pub fn validate(
        &self,
        plan: &ModulePlan,
        limits: PlanLimits,
    ) -> Result<(), ModulePlanningError> {
        plan.validate(limits)?;
        self.validate_structure(plan, limits)?;
        let expected = bound_plan_digest(self)?;
        if self.bound_plan_id.as_str() != expected {
            return Err(ModulePlanningError::BoundPlanIdentityMismatch {
                expected,
                actual: self.bound_plan_id.to_string(),
            });
        }
        Ok(())
    }

    /// Establishes that this bound document is ready to be relied upon for the
    /// exact source module and understood protocol version.
    ///
    /// Structural validation preserves unknown extensions for round trips;
    /// readiness refuses them because they may change binding semantics.
    ///
    /// # Errors
    ///
    /// Refuses a changed module, unknown extension semantics, or every
    /// standalone validation failure.
    pub fn validate_ready(
        &self,
        source_module: &Fact,
        plan: &ModulePlan,
        limits: PlanLimits,
    ) -> Result<(), ModulePlanningError> {
        self.validate(plan, limits)?;
        plan.validate_against(source_module, limits)?;
        reject_candidate_extensions(plan)?;
        reject_bound_extensions(self)
    }

    fn validate_structure(
        &self,
        plan: &ModulePlan,
        limits: PlanLimits,
    ) -> Result<(), ModulePlanningError> {
        BoundModulePlanId::parse(self.bound_plan_id.to_string())?;
        if self.protocol != BOUND_MODULE_PLAN_PROTOCOL {
            return Err(ModulePlanningError::ProtocolMismatch {
                scope: "bound module plan",
                actual: self.protocol.clone(),
            });
        }
        if self.module_plan_id != plan.plan_id {
            return Err(ModulePlanningError::ModulePlanMismatch);
        }
        validate_extensions(
            "bound module plan",
            &self.extensions,
            &[
                "bound_plan_id",
                "protocol",
                "module_plan_id",
                "route",
                "initial_bindings",
            ],
        )?;
        self.route
            .validate(&plan.semantic_plan, limits)
            .map_err(planning_error)?;
        if !matches!(self.route.target, RouteValueSource::CapabilityOutput { .. }) {
            return Err(ModulePlanningError::NoTypeLevelProgress {
                target: plan.target.required_result.clone(),
                illegal_operations: illegal_operations(&plan.operations, &plan.target),
            });
        }

        let expected_uses = initial_uses(&self.route)?;
        validate_count(
            "initial operation bindings",
            self.initial_bindings.len(),
            MAX_INITIAL_BINDINGS,
        )?;
        let mut actual_uses = Vec::with_capacity(self.initial_bindings.len());
        for binding in &self.initial_bindings {
            validate_extensions(
                "initial operation binding",
                &binding.extensions,
                &["initial_use", "operation"],
            )?;
            validate_initial_use(&binding.initial_use)?;
            validate_operation_ref(&binding.operation)?;
            if !plan.operations.contains(&binding.operation) {
                return Err(ModulePlanningError::OperationOutsideModule(Box::new(
                    binding.operation.clone(),
                )));
            }
            actual_uses.push(initial_use_key(&binding.initial_use));
        }
        if actual_uses
            != expected_uses
                .iter()
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>()
        {
            return Err(ModulePlanningError::InitialBindingInventoryMismatch);
        }
        for (binding, (_, expected_kind)) in self.initial_bindings.iter().zip(&expected_uses) {
            if &binding.operation.value_kind != expected_kind {
                return Err(ModulePlanningError::OperationKindMismatch(Box::new(
                    OperationKindMismatchDetail {
                        initial_use: binding.initial_use.clone(),
                        expected: expected_kind.clone(),
                        actual: binding.operation.value_kind.clone(),
                    },
                )));
            }
        }

        validate_illegal_coverage(plan, &self.initial_bindings)
    }
}

/// Module-aware adapter over one immutable semantic planning inventory.
#[derive(Clone, Copy, Debug)]
pub struct ModulePlanner<'planner> {
    semantic: &'planner SemanticPlanner,
}

impl<'planner> ModulePlanner<'planner> {
    /// Borrows one exact provider-neutral semantic planning inventory.
    #[must_use]
    pub const fn new(semantic: &'planner SemanticPlanner) -> Self {
        Self { semantic }
    }

    /// Builds a candidate graph from the unique operation kinds in one module.
    ///
    /// # Errors
    ///
    /// Refuses invalid modules or targets, a target carrying unknown planning
    /// semantics, same-kind/no-progress legalization, and every semantic
    /// planning refusal.
    pub fn plan(
        &self,
        source_module: &Fact,
        target: LegalityTarget,
    ) -> Result<ModulePlanningOutcome, ModulePlanningError> {
        let envelope = ModuleFact::from_fact(source_module).map_err(ModulePlanningError::Module)?;
        target.validate()?;
        if !target.extensions.is_empty() {
            return Err(ModulePlanningError::UnsupportedExtensions(
                "legality target",
            ));
        }
        let operations = envelope
            .module
            .operations
            .iter()
            .enumerate()
            .map(|(ordinal, operation)| operation_reference(source_module, ordinal, operation))
            .collect::<Result<Vec<_>, _>>()?;
        let available = operations
            .iter()
            .map(|operation| operation.value_kind.clone())
            .collect::<BTreeSet<_>>();
        let illegal = illegal_operations(&operations, &target);

        if available.contains(&target.required_result) {
            if illegal.is_empty() {
                return Ok(ModulePlanningOutcome::AlreadyLegal {
                    source_module: source_module.id.clone(),
                    target,
                });
            }
            return Err(ModulePlanningError::NoTypeLevelProgress {
                target: target.required_result,
                illegal_operations: illegal,
            });
        }

        let semantic_plan = self
            .semantic
            .plan(available, target.required_result.clone())
            .map_err(planning_error)?;
        let mut plan = ModulePlan {
            plan_id: placeholder_module_plan_id(),
            protocol: MODULE_PLAN_PROTOCOL.to_owned(),
            source_module: source_module.id.clone(),
            target,
            operations,
            semantic_plan,
            extensions: BTreeMap::new(),
        };
        plan.validate_structure(self.semantic.limits())?;
        plan.plan_id = ModulePlanId::parse(module_plan_digest(&plan)?)?;
        plan.validate_against(source_module, self.semantic.limits())?;
        Ok(ModulePlanningOutcome::Planned(Box::new(plan)))
    }

    /// Replans against this exact semantic inventory and module fact.
    ///
    /// # Errors
    ///
    /// Refuses changed inventory, module contents, unsupported extensions, or
    /// any candidate plan this planner would not reproduce exactly.
    pub fn validate_exact_plan(
        &self,
        source_module: &Fact,
        plan: &ModulePlan,
    ) -> Result<(), ModulePlanningError> {
        plan.validate_against(source_module, self.semantic.limits())?;
        reject_candidate_extensions(plan)?;
        let ModulePlanningOutcome::Planned(expected) =
            self.plan(source_module, plan.target.clone())?
        else {
            return Err(ModulePlanningError::PlanInventoryMismatch);
        };
        if expected.as_ref() != plan {
            return Err(ModulePlanningError::PlanInventoryMismatch);
        }
        Ok(())
    }

    /// Selects the unique executable semantic route and binds every initial
    /// use to one exact contained operation occurrence.
    ///
    /// A unique kind occurrence binds automatically. Duplicate occurrences
    /// require an exact caller choice per capability/input-port use. The result
    /// succeeds only when every illegal occurrence is covered by an input use.
    ///
    /// # Errors
    ///
    /// Refuses an invalid candidate, route or offer ambiguity, unknown or
    /// duplicate choices, occurrence ambiguity, type mismatch, and incomplete
    /// illegal-operation coverage.
    pub fn bind_unique_route(
        &self,
        source_module: &Fact,
        plan: &ModulePlan,
        choices: impl IntoIterator<Item = InitialOperationChoice>,
    ) -> Result<BoundModulePlan, ModulePlanningError> {
        self.validate_exact_plan(source_module, plan)?;
        let route = self
            .semantic
            .select_route(&plan.semantic_plan, RouteSelection::UniqueOnly)
            .map_err(planning_error)?;
        let expected_uses = initial_uses(&route)?;
        let bindings = bind_initial_operations(plan, &expected_uses, choices)?;
        let mut bound = BoundModulePlan {
            bound_plan_id: placeholder_bound_plan_id(),
            protocol: BOUND_MODULE_PLAN_PROTOCOL.to_owned(),
            module_plan_id: plan.plan_id.clone(),
            route,
            initial_bindings: bindings,
            extensions: BTreeMap::new(),
        };
        bound.validate_structure(plan, self.semantic.limits())?;
        bound.bound_plan_id = BoundModulePlanId::parse(bound_plan_digest(&bound)?)?;
        bound.validate_ready(source_module, plan, self.semantic.limits())?;
        Ok(bound)
    }

    /// Revalidates a bound route against the exact module and this semantic
    /// inventory, including the unique route/offer selection.
    ///
    /// # Errors
    ///
    /// Refuses source, candidate, route, binding, inventory, or extension
    /// substitution.
    pub fn validate_exact_bound_plan(
        &self,
        source_module: &Fact,
        plan: &ModulePlan,
        bound: &BoundModulePlan,
    ) -> Result<(), ModulePlanningError> {
        self.validate_exact_plan(source_module, plan)?;
        bound.validate_ready(source_module, plan, self.semantic.limits())?;
        let expected_route = self
            .semantic
            .select_route(&plan.semantic_plan, RouteSelection::UniqueOnly)
            .map_err(planning_error)?;
        if bound.route != expected_route {
            return Err(ModulePlanningError::BoundRouteMismatch);
        }
        Ok(())
    }
}

fn bind_initial_operations(
    plan: &ModulePlan,
    expected_uses: &[(InitialUseKey, ValueKindId)],
    choices: impl IntoIterator<Item = InitialOperationChoice>,
) -> Result<Vec<InitialOperationBinding>, ModulePlanningError> {
    let mut choices_by_use = BTreeMap::new();
    for choice in choices {
        validate_initial_use(&choice.initial_use)?;
        if !choice.initial_use.extensions.is_empty() {
            return Err(ModulePlanningError::UnsupportedExtensions("initial use"));
        }
        validate_operation_ref(&choice.operation)?;
        let key = initial_use_key(&choice.initial_use);
        if choices_by_use.insert(key.clone(), choice).is_some() {
            return Err(ModulePlanningError::DuplicateInitialChoice(
                initial_use_from_key(&key),
            ));
        }
    }

    let mut bindings = Vec::with_capacity(expected_uses.len());
    for (key, expected_kind) in expected_uses {
        let initial_use = initial_use_from_key(key);
        let operation = if let Some(choice) = choices_by_use.remove(key) {
            choose_operation(plan, choice, initial_use, expected_kind)?
        } else {
            choose_unique_operation(plan, initial_use, expected_kind)?
        };
        bindings.push(InitialOperationBinding {
            initial_use: initial_use_from_key(key),
            operation,
            extensions: BTreeMap::new(),
        });
    }
    if let Some((key, _choice)) = choices_by_use.into_iter().next() {
        return Err(ModulePlanningError::UnknownInitialUse(
            initial_use_from_key(&key),
        ));
    }
    Ok(bindings)
}

fn choose_operation(
    plan: &ModulePlan,
    choice: InitialOperationChoice,
    initial_use: InitialUse,
    expected_kind: &ValueKindId,
) -> Result<ModuleOperationRef, ModulePlanningError> {
    if !plan.operations.contains(&choice.operation) {
        return Err(ModulePlanningError::OperationOutsideModule(Box::new(
            choice.operation,
        )));
    }
    if choice.operation.value_kind != *expected_kind {
        return Err(ModulePlanningError::OperationKindMismatch(Box::new(
            OperationKindMismatchDetail {
                initial_use,
                expected: expected_kind.clone(),
                actual: choice.operation.value_kind,
            },
        )));
    }
    Ok(choice.operation)
}

fn choose_unique_operation(
    plan: &ModulePlan,
    initial_use: InitialUse,
    expected_kind: &ValueKindId,
) -> Result<ModuleOperationRef, ModulePlanningError> {
    let candidates = plan
        .operations
        .iter()
        .filter(|operation| operation.value_kind == *expected_kind)
        .cloned()
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [only] => Ok(only.clone()),
        [] => Err(ModulePlanningError::InitialBindingInventoryMismatch),
        _ => Err(ModulePlanningError::AmbiguousOperation {
            initial_use: Box::new(initial_use),
            candidates,
        }),
    }
}

/// Reads and validates one standalone candidate module-plan document.
///
/// Duplicate JSON keys are rejected recursively before typed decoding.
///
/// # Errors
///
/// Returns an error for malformed JSON, duplicate keys, or an invalid plan.
pub fn read_module_plan(json: &str, limits: PlanLimits) -> Result<ModulePlan, ModulePlanningError> {
    let plan: ModulePlan = strict_json::from_str(json).map_err(ModulePlanningError::StrictJson)?;
    plan.validate(limits)?;
    Ok(plan)
}

/// Writes one validated candidate module-plan document.
///
/// # Errors
///
/// Returns an error for invalid structure or JSON serialization failure.
pub fn write_module_plan(
    plan: &ModulePlan,
    limits: PlanLimits,
) -> Result<String, ModulePlanningError> {
    plan.validate(limits)?;
    serde_json::to_string(plan)
        .map_err(|error| ModulePlanningError::Serialization(error.to_string()))
}

/// Reads and validates one standalone bound module-plan document.
///
/// # Errors
///
/// Returns an error for malformed JSON, duplicate keys, or a mismatch with the
/// supplied exact candidate plan.
pub fn read_bound_module_plan(
    json: &str,
    plan: &ModulePlan,
    limits: PlanLimits,
) -> Result<BoundModulePlan, ModulePlanningError> {
    let bound: BoundModulePlan =
        strict_json::from_str(json).map_err(ModulePlanningError::StrictJson)?;
    bound.validate(plan, limits)?;
    Ok(bound)
}

/// Writes one validated bound module-plan document.
///
/// # Errors
///
/// Returns an error for invalid structure or JSON serialization failure.
pub fn write_bound_module_plan(
    bound: &BoundModulePlan,
    plan: &ModulePlan,
    limits: PlanLimits,
) -> Result<String, ModulePlanningError> {
    bound.validate(plan, limits)?;
    serde_json::to_string(bound)
        .map_err(|error| ModulePlanningError::Serialization(error.to_string()))
}

/// Exact refusal from module legalization planning or route binding.
#[derive(Debug)]
pub enum ModulePlanningError {
    InvalidDigest {
        scope: &'static str,
        value: String,
    },
    InvalidFactId(String),
    InvalidValueKind(ValueKindId),
    DuplicateLegalValueKind(ValueKindId),
    RequiredResultNotLegal(ValueKindId),
    NoTypeLevelProgress {
        target: ValueKindId,
        illegal_operations: Vec<ModuleOperationRef>,
    },
    ProtocolMismatch {
        scope: &'static str,
        actual: String,
    },
    SourceModuleMismatch {
        expected: FactId,
        actual: FactId,
    },
    OperationInventoryMismatch,
    SemanticTargetMismatch,
    SemanticInputsMismatch,
    ModulePlanMismatch,
    BoundRouteMismatch,
    InitialBindingInventoryMismatch,
    DuplicateInitialChoice(InitialUse),
    UnknownInitialUse(InitialUse),
    OperationOutsideModule(Box<ModuleOperationRef>),
    OperationKindMismatch(Box<OperationKindMismatchDetail>),
    AmbiguousOperation {
        initial_use: Box<InitialUse>,
        candidates: Vec<ModuleOperationRef>,
    },
    UncoveredIllegalOperation(Box<ModuleOperationRef>),
    NonCanonical(&'static str),
    ReservedExtension {
        scope: &'static str,
        key: String,
    },
    InvalidExtensionKey {
        scope: &'static str,
        key: String,
    },
    TooMany {
        scope: &'static str,
        actual: usize,
        maximum: usize,
    },
    UnsupportedExtensions(&'static str),
    PlanIdentityMismatch {
        expected: String,
        actual: String,
    },
    BoundPlanIdentityMismatch {
        expected: String,
        actual: String,
    },
    PlanInventoryMismatch,
    Module(ModuleError),
    Planning(Box<PlanningError>),
    StrictJson(StrictJsonError),
    Serialization(String),
}

impl fmt::Display for ModulePlanningError {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDigest { scope, value } => {
                write!(
                    formatter,
                    "`{value}` is not an exact lowercase SHA-256 {scope}"
                )
            }
            Self::InvalidFactId(detail) => write!(formatter, "invalid fact ID: {detail}"),
            Self::InvalidValueKind(kind) => write!(formatter, "invalid value kind `{kind}`"),
            Self::DuplicateLegalValueKind(kind) => {
                write!(formatter, "duplicate legal operation kind `{kind}`")
            }
            Self::RequiredResultNotLegal(kind) => {
                write!(
                    formatter,
                    "required result `{kind}` is not a legal operation kind"
                )
            }
            Self::NoTypeLevelProgress {
                target,
                illegal_operations,
            } => write!(
                formatter,
                "required result `{target}` is already present while {} illegal operation(s) remain",
                illegal_operations.len()
            ),
            Self::ProtocolMismatch { scope, actual } => {
                write!(formatter, "unsupported {scope} protocol `{actual}`")
            }
            Self::SourceModuleMismatch { expected, actual } => write!(
                formatter,
                "module plan names source `{expected}`, not exact module `{actual}`"
            ),
            Self::OperationInventoryMismatch => formatter.write_str(
                "module operation references do not exactly reproduce the source module",
            ),
            Self::SemanticTargetMismatch => {
                formatter.write_str("semantic plan target differs from the module target")
            }
            Self::SemanticInputsMismatch => formatter.write_str(
                "semantic plan initial kinds differ from the module's available operation kinds",
            ),
            Self::ModulePlanMismatch => {
                formatter.write_str("bound plan names a different candidate module plan")
            }
            Self::BoundRouteMismatch => {
                formatter.write_str("bound plan route differs from the exact unique selected route")
            }
            Self::InitialBindingInventoryMismatch => formatter.write_str(
                "initial operation bindings do not exactly match selected-route initial uses",
            ),
            Self::DuplicateInitialChoice(initial_use) => write!(
                formatter,
                "initial use {}/{} has more than one operation choice",
                initial_use.capability, initial_use.input_port
            ),
            Self::UnknownInitialUse(initial_use) => write!(
                formatter,
                "initial use {}/{} is absent from the selected route",
                initial_use.capability, initial_use.input_port
            ),
            Self::OperationOutsideModule(operation) => write!(
                formatter,
                "operation ordinal {} is absent from the exact source module plan",
                operation.ordinal
            ),
            Self::OperationKindMismatch(detail) => write!(
                formatter,
                "initial use {}/{} expects `{}`, got `{}`",
                detail.initial_use.capability,
                detail.initial_use.input_port,
                detail.expected,
                detail.actual
            ),
            Self::AmbiguousOperation {
                initial_use,
                candidates,
            } => write!(
                formatter,
                "initial use {}/{} matches {} operation occurrences and requires an exact choice",
                initial_use.capability,
                initial_use.input_port,
                candidates.len()
            ),
            Self::UncoveredIllegalOperation(operation) => write!(
                formatter,
                "illegal operation ordinal {} is not covered by the selected route",
                operation.ordinal
            ),
            Self::NonCanonical(scope) => write!(formatter, "{scope} are not canonical"),
            Self::ReservedExtension { scope, key } => {
                write!(formatter, "{scope} extension `{key}` shadows a known field")
            }
            Self::InvalidExtensionKey { scope, key } => {
                write!(formatter, "{scope} extension key `{key}` is invalid")
            }
            Self::TooMany {
                scope,
                actual,
                maximum,
            } => write!(
                formatter,
                "{scope} count {actual} exceeds maximum {maximum}"
            ),
            Self::UnsupportedExtensions(scope) => {
                write!(
                    formatter,
                    "{scope} extensions are not understood for planning"
                )
            }
            Self::PlanIdentityMismatch { expected, actual } => write!(
                formatter,
                "module plan identity mismatch: expected {expected}, got {actual}"
            ),
            Self::BoundPlanIdentityMismatch { expected, actual } => write!(
                formatter,
                "bound module plan identity mismatch: expected {expected}, got {actual}"
            ),
            Self::PlanInventoryMismatch => formatter
                .write_str("module plan differs from the exact plan for this semantic inventory"),
            Self::Module(error) => write!(formatter, "invalid module: {error}"),
            Self::Planning(error) => write!(formatter, "semantic planning failed: {error}"),
            Self::StrictJson(error) => write!(formatter, "invalid module plan JSON: {error}"),
            Self::Serialization(detail) => {
                write!(formatter, "module planning serialization failed: {detail}")
            }
        }
    }
}

impl Error for ModulePlanningError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Module(error) => Some(error),
            Self::Planning(error) => Some(error.as_ref()),
            Self::StrictJson(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PlanningError> for ModulePlanningError {
    fn from(error: PlanningError) -> Self {
        Self::Planning(Box::new(error))
    }
}

fn planning_error(error: PlanningError) -> ModulePlanningError {
    ModulePlanningError::Planning(Box::new(error))
}

fn operation_reference(
    module_fact: &Fact,
    ordinal: usize,
    operation: &gooir_module_v0::ModuleOperation,
) -> Result<ModuleOperationRef, ModulePlanningError> {
    let ordinal = u32::try_from(ordinal).map_err(|_| ModulePlanningError::TooMany {
        scope: "module operations",
        actual: ordinal,
        maximum: u32::MAX as usize,
    })?;
    Ok(ModuleOperationRef {
        module_fact_id: module_fact.id.clone(),
        ordinal,
        fact_id: operation.fact.id.clone(),
        value_kind: operation.fact.value_kind.clone(),
        symbol: operation.symbol.clone(),
        extensions: BTreeMap::new(),
    })
}

fn validate_operation_ref(operation: &ModuleOperationRef) -> Result<(), ModulePlanningError> {
    parse_fact_id(&operation.module_fact_id)?;
    parse_fact_id(&operation.fact_id)?;
    if !operation.value_kind.is_well_formed() {
        return Err(ModulePlanningError::InvalidValueKind(
            operation.value_kind.clone(),
        ));
    }
    if let Some(symbol) = &operation.symbol {
        SymbolName::parse(symbol.to_string()).map_err(ModulePlanningError::Module)?;
    }
    validate_extensions(
        "module operation reference",
        &operation.extensions,
        &[
            "module_fact_id",
            "ordinal",
            "fact_id",
            "value_kind",
            "symbol",
        ],
    )
}

fn validate_initial_use(initial_use: &InitialUse) -> Result<(), ModulePlanningError> {
    if !initial_use.capability.is_well_formed() {
        return Err(ModulePlanningError::Serialization(format!(
            "invalid capability `{}` in initial use",
            initial_use.capability
        )));
    }
    PortName::parse(initial_use.input_port.as_str()).map_err(|error| {
        ModulePlanningError::Serialization(format!("invalid initial input port: {error}"))
    })?;
    validate_extensions(
        "initial use",
        &initial_use.extensions,
        &["capability", "input_port"],
    )
}

type InitialUseKey = (CapabilityId, PortName);

fn initial_use_key(initial_use: &InitialUse) -> InitialUseKey {
    (
        initial_use.capability.clone(),
        initial_use.input_port.clone(),
    )
}

fn initial_use_from_key(key: &InitialUseKey) -> InitialUse {
    InitialUse {
        capability: key.0.clone(),
        input_port: key.1.clone(),
        extensions: BTreeMap::new(),
    }
}

fn initial_uses(
    route: &SelectedRoute,
) -> Result<Vec<(InitialUseKey, ValueKindId)>, ModulePlanningError> {
    let mut uses = BTreeMap::new();
    for step in &route.steps {
        for dependency in &step.inputs {
            if let RouteValueSource::Initial { value_kind, .. } = &dependency.source {
                let key = (step.capability.clone(), dependency.input_port.clone());
                if uses.insert(key.clone(), value_kind.clone()).is_some() {
                    return Err(ModulePlanningError::DuplicateInitialChoice(
                        initial_use_from_key(&key),
                    ));
                }
            }
        }
    }
    Ok(uses.into_iter().collect())
}

fn illegal_operations(
    operations: &[ModuleOperationRef],
    target: &LegalityTarget,
) -> Vec<ModuleOperationRef> {
    operations
        .iter()
        .filter(|operation| !target.is_legal(&operation.value_kind))
        .cloned()
        .collect()
}

fn validate_illegal_coverage(
    plan: &ModulePlan,
    bindings: &[InitialOperationBinding],
) -> Result<(), ModulePlanningError> {
    let covered = bindings
        .iter()
        .map(|binding| binding.operation.ordinal)
        .collect::<BTreeSet<_>>();
    if let Some(operation) = plan.operations.iter().find(|operation| {
        !plan.target.is_legal(&operation.value_kind) && !covered.contains(&operation.ordinal)
    }) {
        return Err(ModulePlanningError::UncoveredIllegalOperation(Box::new(
            operation.clone(),
        )));
    }
    Ok(())
}

fn reject_candidate_extensions(plan: &ModulePlan) -> Result<(), ModulePlanningError> {
    if !plan.extensions.is_empty() {
        return Err(ModulePlanningError::UnsupportedExtensions("module plan"));
    }
    if !plan.target.extensions.is_empty() {
        return Err(ModulePlanningError::UnsupportedExtensions(
            "legality target",
        ));
    }
    if plan
        .operations
        .iter()
        .any(|operation| !operation.extensions.is_empty())
    {
        return Err(ModulePlanningError::UnsupportedExtensions(
            "module operation reference",
        ));
    }
    Ok(())
}

fn reject_bound_extensions(bound: &BoundModulePlan) -> Result<(), ModulePlanningError> {
    if !bound.extensions.is_empty() {
        return Err(ModulePlanningError::UnsupportedExtensions(
            "bound module plan",
        ));
    }
    if route_has_extensions(&bound.route) {
        return Err(ModulePlanningError::UnsupportedExtensions("selected route"));
    }
    for binding in &bound.initial_bindings {
        if !binding.extensions.is_empty() {
            return Err(ModulePlanningError::UnsupportedExtensions(
                "initial operation binding",
            ));
        }
        if !binding.initial_use.extensions.is_empty() {
            return Err(ModulePlanningError::UnsupportedExtensions("initial use"));
        }
        if !binding.operation.extensions.is_empty() {
            return Err(ModulePlanningError::UnsupportedExtensions(
                "module operation reference",
            ));
        }
    }
    Ok(())
}

fn route_has_extensions(route: &SelectedRoute) -> bool {
    !route.extensions.is_empty()
        || route_value_has_extensions(&route.target)
        || route.steps.iter().any(|step| {
            !step.extensions.is_empty()
                || step.inputs.iter().any(|input| {
                    !input.extensions.is_empty() || route_value_has_extensions(&input.source)
                })
        })
}

fn route_value_has_extensions(source: &RouteValueSource) -> bool {
    match source {
        RouteValueSource::Initial { extensions, .. }
        | RouteValueSource::CapabilityOutput { extensions, .. } => !extensions.is_empty(),
    }
}

fn parse_fact_id(fact_id: &FactId) -> Result<(), ModulePlanningError> {
    FactId::parse(fact_id.to_string())
        .map(|_| ())
        .map_err(|error| ModulePlanningError::InvalidFactId(error.to_string()))
}

fn validate_extensions(
    scope: &'static str,
    extensions: &BTreeMap<String, Value>,
    reserved: &[&str],
) -> Result<(), ModulePlanningError> {
    if let Some(key) = reserved.iter().find(|key| extensions.contains_key(**key)) {
        return Err(ModulePlanningError::ReservedExtension {
            scope,
            key: (*key).to_owned(),
        });
    }
    validate_count("extensions", extensions.len(), MAX_EXTENSIONS_PER_SCOPE)?;
    for key in extensions.keys() {
        let namespaced = key
            .split_once('/')
            .is_some_and(|(namespace, name)| !namespace.is_empty() && !name.is_empty());
        if key.len() > MAX_EXTENSION_KEY_BYTES
            || key.trim() != key
            || key.chars().any(char::is_control)
            || !namespaced
        {
            return Err(ModulePlanningError::InvalidExtensionKey {
                scope,
                key: key.clone(),
            });
        }
    }
    Ok(())
}

fn validate_count(
    scope: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), ModulePlanningError> {
    if actual > maximum {
        Err(ModulePlanningError::TooMany {
            scope,
            actual,
            maximum,
        })
    } else {
        Ok(())
    }
}

fn module_plan_digest(plan: &ModulePlan) -> Result<String, ModulePlanningError> {
    document_digest(plan, "plan_id")
}

fn bound_plan_digest(plan: &BoundModulePlan) -> Result<String, ModulePlanningError> {
    document_digest(plan, "bound_plan_id")
}

fn document_digest(
    document: &impl Serialize,
    identity_field: &str,
) -> Result<String, ModulePlanningError> {
    let mut value = serde_json::to_value(document)
        .map_err(|error| ModulePlanningError::Serialization(error.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| ModulePlanningError::Serialization("document is not an object".to_owned()))?
        .remove(identity_field)
        .ok_or_else(|| {
            ModulePlanningError::Serialization(format!(
                "document omitted identity field `{identity_field}`"
            ))
        })?;
    canonical_digest(&value).map_err(ModulePlanningError::Serialization)
}

fn placeholder_module_plan_id() -> ModulePlanId {
    ModulePlanId::parse(format!("sha256:{}", "0".repeat(64)))
        .expect("the module plan identity placeholder is exact")
}

fn placeholder_bound_plan_id() -> BoundModulePlanId {
    BoundModulePlanId::parse(format!("sha256:{}", "0".repeat(64)))
        .expect("the bound plan identity placeholder is exact")
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
    use std::num::NonZeroUsize;

    use gooir_capability::protocol::{ArtifactDigest, CapabilityOffer, ImplementationId};
    use gooir_capability::{CapabilitySpec, DialectId, FactAcceptance, InputPort, OutputPort};
    use gooir_module_v0::{Module, ModuleOperation};
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

    fn symbol(name: &str) -> SymbolName {
        SymbolName::parse(format!("@{name}")).unwrap()
    }

    fn port(name: &str) -> PortName {
        PortName::parse(name).unwrap()
    }

    fn capability(name: &str) -> CapabilityId {
        CapabilityId::new("org.example.capability", name, VERSION)
    }

    fn specification(
        name: &str,
        inputs: &[(&str, ValueKindId)],
        output: ValueKindId,
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
            output_ports: vec![OutputPort::new(port("result"), output)],
            default_conformance_suite: format!("org.example.conformance/exact@{VERSION}"),
            extensions: BTreeMap::new(),
        }
    }

    fn offer(specification: &CapabilitySpec, name: &str, byte: char) -> CapabilityOffer {
        CapabilityOffer::new(
            ImplementationId::new("org.example.implementation", name, VERSION),
            ArtifactDigest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap(),
            specification.id.clone(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn operation(name: &str, value_kind: ValueKindId) -> ModuleOperation {
        ModuleOperation::new(
            Fact::new(value_kind, json!({"name": name})).unwrap(),
            Some(symbol(name)),
            Vec::new(),
        )
        .unwrap()
    }

    fn module(operations: Vec<ModuleOperation>) -> Fact {
        let dialects = operations
            .iter()
            .map(|operation| operation.fact.value_kind.dialect())
            .collect::<BTreeSet<DialectId>>()
            .into_iter()
            .collect();
        Module::new(dialects, operations)
            .unwrap()
            .into_fact()
            .unwrap()
    }

    fn planned(outcome: ModulePlanningOutcome) -> ModulePlan {
        let ModulePlanningOutcome::Planned(plan) = outcome else {
            panic!("expected a candidate module plan");
        };
        *plan
    }

    fn reidentify_plan(plan: &mut ModulePlan) {
        plan.plan_id = ModulePlanId::parse(module_plan_digest(plan).unwrap()).unwrap();
    }

    fn reidentify_bound(bound: &mut BoundModulePlan) {
        bound.bound_plan_id = BoundModulePlanId::parse(bound_plan_digest(bound).unwrap()).unwrap();
    }

    #[test]
    fn multi_hop_route_covers_semantics_and_leaves_business_logic_outside() {
        let http = kind("http_service");
        let bindings = kind("handler_bindings");
        let profile = kind("axum_profile");
        let business = kind("business_operations");
        let axum = kind("axum_program");
        let rust = kind("rust_source_tree");
        let http_to_axum = specification(
            "http_to_axum",
            &[
                ("http", http.clone()),
                ("handlers", bindings.clone()),
                ("profile", profile.clone()),
            ],
            axum.clone(),
        );
        let axum_to_rust = specification("axum_to_rust", &[("program", axum)], rust.clone());
        let planner = SemanticPlanner::new(
            [http_to_axum.clone(), axum_to_rust.clone()],
            [
                offer(&http_to_axum, "http_to_axum", 'a'),
                offer(&axum_to_rust, "axum_to_rust", 'b'),
            ],
            limits(),
        )
        .unwrap();
        let module_fact = module(vec![
            operation("business", business.clone()),
            operation("http", http),
            operation("bindings", bindings),
            operation("profile", profile),
        ]);
        let target = LegalityTarget::new(rust.clone(), [business, rust]).unwrap();
        let module_planner = ModulePlanner::new(&planner);

        let plan = planned(module_planner.plan(&module_fact, target).unwrap());
        assert_eq!(plan.semantic_plan.capabilities.len(), 2);
        assert_eq!(plan.operations.len(), 4);
        module_planner
            .validate_exact_plan(&module_fact, &plan)
            .unwrap();

        let bound = module_planner
            .bind_unique_route(&module_fact, &plan, Vec::new())
            .unwrap();
        assert_eq!(bound.route.steps.len(), 2);
        assert_eq!(bound.initial_bindings.len(), 3);
        assert_eq!(
            bound
                .initial_bindings
                .iter()
                .map(|binding| binding.operation.ordinal)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([1, 2, 3])
        );
        module_planner
            .validate_exact_bound_plan(&module_fact, &plan, &bound)
            .unwrap();

        let plan_json = write_module_plan(&plan, limits()).unwrap();
        assert_eq!(read_module_plan(&plan_json, limits()).unwrap(), plan);
        let bound_json = write_bound_module_plan(&bound, &plan, limits()).unwrap();
        assert_eq!(
            read_bound_module_plan(&bound_json, &plan, limits()).unwrap(),
            bound
        );
    }

    #[test]
    fn duplicate_kinds_bind_by_named_route_use_and_exact_ordinal() {
        let source = kind("source");
        let result = kind("result");
        let pair = specification(
            "pair",
            &[("left", source.clone()), ("right", source.clone())],
            result.clone(),
        );
        let planner =
            SemanticPlanner::new([pair.clone()], [offer(&pair, "pair", 'c')], limits()).unwrap();
        let repeated_fact = Fact::new(source, json!({"same": true})).unwrap();
        let module_fact = module(vec![
            ModuleOperation::new(repeated_fact.clone(), None, Vec::new()).unwrap(),
            ModuleOperation::new(repeated_fact, None, Vec::new()).unwrap(),
        ]);
        let target = LegalityTarget::new(result.clone(), [result]).unwrap();
        let module_planner = ModulePlanner::new(&planner);
        let plan = planned(module_planner.plan(&module_fact, target).unwrap());
        assert_eq!(plan.operations[0].fact_id, plan.operations[1].fact_id);
        assert_ne!(plan.operations[0].ordinal, plan.operations[1].ordinal);

        assert!(matches!(
            module_planner.bind_unique_route(&module_fact, &plan, Vec::new()),
            Err(ModulePlanningError::AmbiguousOperation { .. })
        ));

        let choices = vec![
            InitialOperationChoice::new(
                InitialUse::new(pair.id.clone(), port("left")).unwrap(),
                plan.operations[0].clone(),
            )
            .unwrap(),
            InitialOperationChoice::new(
                InitialUse::new(pair.id, port("right")).unwrap(),
                plan.operations[1].clone(),
            )
            .unwrap(),
        ];
        let bound = module_planner
            .bind_unique_route(&module_fact, &plan, choices)
            .unwrap();
        assert_eq!(
            bound
                .initial_bindings
                .iter()
                .map(|binding| binding.operation.ordinal)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([0, 1])
        );
    }

    #[test]
    fn selected_route_must_cover_every_illegal_occurrence() {
        let source = kind("source");
        let unused = kind("unused_illegal");
        let result = kind("result");
        let edge = specification("lower", &[("source", source.clone())], result.clone());
        let planner =
            SemanticPlanner::new([edge.clone()], [offer(&edge, "lower", 'd')], limits()).unwrap();
        let module_fact = module(vec![
            operation("source", source),
            operation("unused", unused),
        ]);
        let target = LegalityTarget::new(result.clone(), [result]).unwrap();
        let module_planner = ModulePlanner::new(&planner);
        let plan = planned(module_planner.plan(&module_fact, target).unwrap());

        assert!(matches!(
            module_planner.bind_unique_route(&module_fact, &plan, Vec::new()),
            Err(ModulePlanningError::UncoveredIllegalOperation(operation))
                if operation.symbol == Some(symbol("unused"))
        ));
    }

    #[test]
    fn one_initial_use_cannot_cover_two_illegal_occurrences_of_one_kind() {
        let source = kind("source");
        let result = kind("result");
        let edge = specification("lower", &[("source", source.clone())], result.clone());
        let planner =
            SemanticPlanner::new([edge.clone()], [offer(&edge, "lower", 'e')], limits()).unwrap();
        let repeated = Fact::new(source, json!({"same": true})).unwrap();
        let module_fact = module(vec![
            ModuleOperation::new(repeated.clone(), None, Vec::new()).unwrap(),
            ModuleOperation::new(repeated, None, Vec::new()).unwrap(),
        ]);
        let target = LegalityTarget::new(result.clone(), [result]).unwrap();
        let module_planner = ModulePlanner::new(&planner);
        let plan = planned(module_planner.plan(&module_fact, target).unwrap());
        let choice = InitialOperationChoice::new(
            InitialUse::new(edge.id, port("source")).unwrap(),
            plan.operations[0].clone(),
        )
        .unwrap();

        assert!(matches!(
            module_planner.bind_unique_route(&module_fact, &plan, [choice]),
            Err(ModulePlanningError::UncoveredIllegalOperation(operation))
                if operation.ordinal == 1
        ));
    }

    #[test]
    fn binding_revalidates_exact_containment_and_source_module() {
        let source = kind("source");
        let result = kind("result");
        let edge = specification("lower", &[("source", source.clone())], result.clone());
        let planner =
            SemanticPlanner::new([edge.clone()], [offer(&edge, "lower", 'f')], limits()).unwrap();
        let module_fact = module(vec![operation("source", source.clone())]);
        let target = LegalityTarget::new(result.clone(), [result]).unwrap();
        let module_planner = ModulePlanner::new(&planner);
        let plan = planned(module_planner.plan(&module_fact, target).unwrap());

        let mut forged = plan.clone();
        forged.operations[0].fact_id = Fact::new(source.clone(), json!({"forged": true}))
            .unwrap()
            .id;
        reidentify_plan(&mut forged);
        assert!(matches!(
            module_planner.bind_unique_route(&module_fact, &forged, Vec::new()),
            Err(ModulePlanningError::OperationInventoryMismatch)
        ));

        let other_module = module(vec![operation("other", source)]);
        assert!(matches!(
            module_planner.bind_unique_route(&other_module, &plan, Vec::new()),
            Err(ModulePlanningError::SourceModuleMismatch { .. })
        ));
    }

    #[test]
    fn readiness_refuses_unknown_extensions_and_identities_detect_tampering() {
        let source = kind("source");
        let result = kind("result");
        let edge = specification("lower", &[("source", source.clone())], result.clone());
        let planner =
            SemanticPlanner::new([edge.clone()], [offer(&edge, "lower", '1')], limits()).unwrap();
        let module_fact = module(vec![operation("source", source)]);
        let target = LegalityTarget::new(result.clone(), [result]).unwrap();
        let module_planner = ModulePlanner::new(&planner);
        let plan = planned(module_planner.plan(&module_fact, target).unwrap());
        let bound = module_planner
            .bind_unique_route(&module_fact, &plan, Vec::new())
            .unwrap();

        let mut extended_plan = plan.clone();
        extended_plan
            .extensions
            .insert("org.example/future".to_owned(), json!(true));
        reidentify_plan(&mut extended_plan);
        assert!(extended_plan.validate(limits()).is_ok());
        assert!(matches!(
            module_planner.bind_unique_route(&module_fact, &extended_plan, Vec::new()),
            Err(ModulePlanningError::UnsupportedExtensions("module plan"))
        ));

        let mut extended_bound = bound.clone();
        extended_bound
            .extensions
            .insert("org.example/future".to_owned(), json!(true));
        reidentify_bound(&mut extended_bound);
        assert!(extended_bound.validate(&plan, limits()).is_ok());
        assert!(matches!(
            module_planner.validate_exact_bound_plan(&module_fact, &plan, &extended_bound),
            Err(ModulePlanningError::UnsupportedExtensions(
                "bound module plan"
            ))
        ));

        let mut changed_plan_id = plan.clone();
        changed_plan_id.plan_id = placeholder_module_plan_id();
        assert!(matches!(
            changed_plan_id.validate(limits()),
            Err(ModulePlanningError::PlanIdentityMismatch { .. })
        ));
        let mut changed_bound_id = bound.clone();
        changed_bound_id.bound_plan_id = placeholder_bound_plan_id();
        assert!(matches!(
            changed_bound_id.validate(&plan, limits()),
            Err(ModulePlanningError::BoundPlanIdentityMismatch { .. })
        ));

        let json = write_bound_module_plan(&bound, &plan, limits()).unwrap();
        let route_id = format!("\"route_id\":\"{}\"", bound.route.route_id);
        let duplicate = format!("{route_id},{route_id}");
        let malformed = json.replacen(&route_id, &duplicate, 1);
        assert!(matches!(
            read_bound_module_plan(&malformed, &plan, limits()),
            Err(ModulePlanningError::StrictJson(_))
        ));
    }

    #[test]
    fn existing_result_never_masks_illegal_same_kind_work() {
        let source = kind("source");
        let result = kind("result");
        let planner = SemanticPlanner::new(Vec::new(), Vec::new(), limits()).unwrap();
        let module_fact = module(vec![
            operation("source", source),
            operation("result", result.clone()),
        ]);
        let target = LegalityTarget::new(result.clone(), [result.clone()]).unwrap();

        assert!(matches!(
            ModulePlanner::new(&planner).plan(&module_fact, target),
            Err(ModulePlanningError::NoTypeLevelProgress {
                target: actual,
                illegal_operations,
            }) if actual == result && illegal_operations.len() == 1
        ));
    }

    #[test]
    fn already_legal_is_explicit_and_requires_the_result() {
        let result = kind("result");
        let metadata = kind("metadata");
        let planner = SemanticPlanner::new(Vec::new(), Vec::new(), limits()).unwrap();
        let module_fact = module(vec![
            operation("result", result.clone()),
            operation("metadata", metadata.clone()),
        ]);
        let target = LegalityTarget::new(result, [metadata, kind("result")]).unwrap();

        assert!(matches!(
            ModulePlanner::new(&planner).plan(&module_fact, target),
            Ok(ModulePlanningOutcome::AlreadyLegal { .. })
        ));
    }

    #[test]
    fn target_is_exact_and_duplicate_plan_keys_are_rejected() {
        let result = kind("result");
        assert!(matches!(
            LegalityTarget::new(result.clone(), Vec::new()),
            Err(ModulePlanningError::RequiredResultNotLegal(actual)) if actual == result
        ));
        assert!(matches!(
            LegalityTarget::new(result.clone(), [result.clone(), result.clone()]),
            Err(ModulePlanningError::DuplicateLegalValueKind(actual)) if actual == result
        ));

        let malformed = format!(
            "{{\"plan_id\":\"sha256:{}\",\"plan_id\":\"sha256:{}\"}}",
            "0".repeat(64),
            "1".repeat(64)
        );
        assert!(matches!(
            read_module_plan(&malformed, limits()),
            Err(ModulePlanningError::StrictJson(_))
        ));
    }
}
