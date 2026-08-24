//! First multi-target lowering probe for the Fleetd operator surface.
//!
//! These are target IRs, not final React or terminal source generators. They
//! deliberately make presentation choices independently while retaining a
//! normalized semantic fingerprint that must agree across targets.

use fleetd_control_lifter::{FleetdControlLift, NativeApiOperation};
use fleetd_interaction_plan::BlockedDeliveryInteractionPlan;
use lift_defeasible::Defeasible;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HttpBinding {
    pub list_method: String,
    pub list_path: String,
    pub resolve_method: String,
    pub resolve_path_template: String,
    pub selector_parameter: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TargetAction {
    pub name: String,
    pub outcome: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WebAction {
    pub semantic: TargetAction,
    pub control: WebControl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebControl {
    SubmitButton,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WebSurface {
    pub binding: HttpBinding,
    pub record_type: String,
    pub selector_field: String,
    pub table_columns: Vec<String>,
    pub authority: Option<String>,
    pub actions: Vec<WebAction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TerminalAction {
    pub semantic: TargetAction,
    pub key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TerminalSurface {
    pub binding: HttpBinding,
    pub record_type: String,
    pub selector_field: String,
    pub list_columns: Vec<String>,
    pub authority: Option<String>,
    pub action_menu: Vec<TerminalAction>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticFingerprint {
    pub record_type: String,
    pub selector_field: String,
    pub fields: Vec<String>,
    pub authority: Option<String>,
    pub actions: Vec<TargetAction>,
}

impl WebSurface {
    pub fn semantic_fingerprint(&self) -> SemanticFingerprint {
        SemanticFingerprint {
            record_type: self.record_type.clone(),
            selector_field: self.selector_field.clone(),
            fields: self.table_columns.clone(),
            authority: self.authority.clone(),
            actions: self
                .actions
                .iter()
                .map(|action| action.semantic.clone())
                .collect(),
        }
    }
}

impl TerminalSurface {
    pub fn semantic_fingerprint(&self) -> SemanticFingerprint {
        SemanticFingerprint {
            record_type: self.record_type.clone(),
            selector_field: self.selector_field.clone(),
            fields: self.list_columns.clone(),
            authority: self.authority.clone(),
            actions: self
                .action_menu
                .iter()
                .map(|action| action.semantic.clone())
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoweringError {
    UnresolvedSemantics(Vec<String>),
    MissingBinding(&'static str),
    UnsupportedBinding {
        operation: &'static str,
        expected_method: &'static str,
        actual_method: String,
    },
    SelectorNotBound {
        selector: String,
        path: String,
    },
}

impl fmt::Display for LoweringError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnresolvedSemantics(defeats) => {
                write!(
                    formatter,
                    "interaction semantics are unresolved: {}",
                    defeats.join("; ")
                )
            }
            Self::MissingBinding(operation) => write!(formatter, "missing {operation} binding"),
            Self::UnsupportedBinding {
                operation,
                expected_method,
                actual_method,
            } => write!(
                formatter,
                "{operation} requires {expected_method}, found {actual_method}"
            ),
            Self::SelectorNotBound { selector, path } => {
                write!(formatter, "selector {selector} is not bound by {path}")
            }
        }
    }
}

impl std::error::Error for LoweringError {}

pub fn lower_web(
    plan: &Defeasible<BlockedDeliveryInteractionPlan>,
    native: &FleetdControlLift,
) -> Result<WebSurface, LoweringError> {
    require_resolved(plan)?;
    let binding = http_binding(plan, native)?;
    Ok(WebSurface {
        binding,
        record_type: plan.value.record_type.clone(),
        selector_field: plan.value.selector_field.clone(),
        table_columns: plan.value.visible_fields.clone(),
        authority: plan.value.authority.clone(),
        actions: plan
            .value
            .choices
            .iter()
            .map(|choice| WebAction {
                semantic: TargetAction {
                    name: choice.name.clone(),
                    outcome: choice.outcome.clone(),
                },
                control: WebControl::SubmitButton,
            })
            .collect(),
    })
}

pub fn lower_terminal(
    plan: &Defeasible<BlockedDeliveryInteractionPlan>,
    native: &FleetdControlLift,
) -> Result<TerminalSurface, LoweringError> {
    require_resolved(plan)?;
    let binding = http_binding(plan, native)?;
    Ok(TerminalSurface {
        binding,
        record_type: plan.value.record_type.clone(),
        selector_field: plan.value.selector_field.clone(),
        list_columns: plan.value.visible_fields.clone(),
        authority: plan.value.authority.clone(),
        action_menu: plan
            .value
            .choices
            .iter()
            .enumerate()
            .map(|(index, choice)| TerminalAction {
                semantic: TargetAction {
                    name: choice.name.clone(),
                    outcome: choice.outcome.clone(),
                },
                key: (index + 1).to_string(),
            })
            .collect(),
    })
}

fn require_resolved(
    plan: &Defeasible<BlockedDeliveryInteractionPlan>,
) -> Result<(), LoweringError> {
    if plan.is_exhaustive() {
        return Ok(());
    }
    Err(LoweringError::UnresolvedSemantics(
        plan.defeats
            .iter()
            .map(|defeat| format!("{}: {}", defeat.subject, defeat.reason))
            .collect(),
    ))
}

fn http_binding(
    plan: &Defeasible<BlockedDeliveryInteractionPlan>,
    native: &FleetdControlLift,
) -> Result<HttpBinding, LoweringError> {
    let list = native
        .list_operation
        .as_ref()
        .ok_or(LoweringError::MissingBinding("list operation"))?;
    let resolve = native
        .resolve_operation
        .as_ref()
        .ok_or(LoweringError::MissingBinding("resolve operation"))?;
    require_method(list, "GET", "list operation")?;
    require_method(resolve, "POST", "resolve operation")?;
    let selector = native
        .resolution_selector
        .as_ref()
        .ok_or(LoweringError::MissingBinding("resolution selector"))?;
    if selector != &plan.value.selector_field || !resolve.path.contains(&format!("{{{selector}}}"))
    {
        return Err(LoweringError::SelectorNotBound {
            selector: plan.value.selector_field.clone(),
            path: resolve.path.clone(),
        });
    }
    Ok(HttpBinding {
        list_method: list.method.to_ascii_uppercase(),
        list_path: list.path.clone(),
        resolve_method: resolve.method.to_ascii_uppercase(),
        resolve_path_template: resolve.path.clone(),
        selector_parameter: selector.clone(),
    })
}

fn require_method(
    operation: &NativeApiOperation,
    expected: &'static str,
    label: &'static str,
) -> Result<(), LoweringError> {
    if operation.method.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(LoweringError::UnsupportedBinding {
            operation: label,
            expected_method: expected,
            actual_method: operation.method.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleetd_control_lifter::{NativeCompleteness, NativeCoverage, NativeResolution};
    use lift_defeasible::{Defeat, DefeatKind};
    use semantics_fleetd_control_v0::ResolutionChoice;

    fn plan() -> Defeasible<BlockedDeliveryInteractionPlan> {
        Defeasible::new(
            BlockedDeliveryInteractionPlan {
                record_type: "BlockedDelivery".to_owned(),
                selector_field: "block_id".to_owned(),
                visible_fields: vec!["block_id".to_owned(), "reason".to_owned()],
                authority: Some("operator".to_owned()),
                choices: vec![
                    ResolutionChoice {
                        name: "requeue".to_owned(),
                        outcome: Some("pending".to_owned()),
                    },
                    ResolutionChoice {
                        name: "abandon".to_owned(),
                        outcome: Some("dead".to_owned()),
                    },
                ],
            },
            "fixture@1",
        )
    }

    fn native() -> FleetdControlLift {
        FleetdControlLift {
            sources: Vec::new(),
            list_operation: Some(NativeApiOperation {
                operation_id: "listDeliveryBlocks".to_owned(),
                method: "get".to_owned(),
                path: "/v1/delivery-blocks".to_owned(),
            }),
            resolve_operation: Some(NativeApiOperation {
                operation_id: "resolveDeliveryBlock".to_owned(),
                method: "post".to_owned(),
                path: "/v1/delivery-blocks/{block_id}/resolve".to_owned(),
            }),
            blocked_delivery_schema: Some("BlockedDelivery".to_owned()),
            resolution_selector: Some("block_id".to_owned()),
            review_fields: vec!["block_id".to_owned(), "reason".to_owned()],
            list_operator_guarded: true,
            resolve_operator_guarded: true,
            resolution_effects_committed: true,
            resolutions: vec![NativeResolution {
                wire_name: "requeue".to_owned(),
                rust_symbol: Some("Requeue".to_owned()),
                resulting_state: Some("pending".to_owned()),
            }],
            coverage: NativeCoverage {
                extractor_package: "test".to_owned(),
                extractor_version: "1".to_owned(),
                mechanism: "fixture".to_owned(),
                completeness: NativeCompleteness::Exhaustive,
                included_artifacts: Vec::new(),
                unresolved: Vec::new(),
            },
        }
    }

    #[test]
    fn web_and_terminal_lowerings_preserve_the_same_meaning() {
        let plan = plan();
        let native = native();

        let web = lower_web(&plan, &native).expect("web lowers");
        let terminal = lower_terminal(&plan, &native).expect("terminal lowers");

        assert_eq!(web.semantic_fingerprint(), terminal.semantic_fingerprint());
        assert!(
            web.actions
                .iter()
                .all(|action| action.control == WebControl::SubmitButton)
        );
        assert_eq!(
            terminal
                .action_menu
                .iter()
                .map(|action| action.key.as_str())
                .collect::<Vec<_>>(),
            vec!["1", "2"]
        );
    }

    #[test]
    fn unresolved_meaning_cannot_be_lowered_by_either_target() {
        let mut plan = plan();
        plan.defeat(Defeat::new(
            DefeatKind::LookedAndBlocked,
            "blocked_delivery.authority",
            "operator guard is unresolved",
        ));

        assert!(matches!(
            lower_web(&plan, &native()),
            Err(LoweringError::UnresolvedSemantics(_))
        ));
        assert!(matches!(
            lower_terminal(&plan, &native()),
            Err(LoweringError::UnresolvedSemantics(_))
        ));
    }
}
