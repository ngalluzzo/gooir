//! Target-independent interaction probe for Fleetd's blocked-delivery review.
//!
//! The plan composes two semantic dialects: the neutral data-model shape and
//! Fleetd's product-specific control meaning. It deliberately contains no web,
//! terminal, component, or transport constructs. Two target lowerings must
//! exercise it before any of this shape is proposed as a reusable Interaction
//! contract.

use lift_defeasible::{Defeasible, Defeat, DefeatKind};
use semantics_data_model_v1::DataModel;
use semantics_fleetd_control_v0::{BlockedDeliveryReview, ResolutionChoice};
use serde::{Deserialize, Serialize};

pub const DEFEATER_SET: &str = "org.gooi.projection.fleetd_interaction/defeaters@1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockedDeliveryInteractionPlan {
    pub record_type: String,
    pub selector_field: String,
    pub visible_fields: Vec<String>,
    pub authority: Option<String>,
    pub choices: Vec<ResolutionChoice>,
}

pub fn derive_blocked_delivery_plan(
    data: &Defeasible<DataModel>,
    control: &Defeasible<BlockedDeliveryReview>,
) -> Defeasible<BlockedDeliveryInteractionPlan> {
    let mut plan = Defeasible::new(
        BlockedDeliveryInteractionPlan {
            record_type: control.value.record_type.clone().unwrap_or_default(),
            selector_field: control.value.selector_field.clone().unwrap_or_default(),
            visible_fields: control.value.review_fields.clone(),
            authority: control.value.authority.clone(),
            choices: control.value.resolutions.clone(),
        },
        DEFEATER_SET,
    );

    for defeat in &control.defeats {
        plan.defeat(Defeat::new(
            defeat.kind,
            defeat.subject.clone(),
            defeat.reason.clone(),
        ));
    }
    if plan.value.record_type.is_empty() {
        plan.defeat(Defeat::new(
            DefeatKind::SubjectUnresolvable,
            "blocked_delivery.record_type",
            "the control contract did not identify its review record",
        ));
    }
    if plan.value.selector_field.is_empty() {
        plan.defeat(Defeat::new(
            DefeatKind::SubjectUnresolvable,
            "blocked_delivery.selector",
            "the control contract did not identify an exact resolution selector",
        ));
    }
    if plan.value.authority.is_none() {
        plan.defeat(Defeat::new(
            DefeatKind::LookedAndBlocked,
            "blocked_delivery.authority",
            "a target must not expose resolution without established authority",
        ));
    }
    let unknown_choices = plan
        .value
        .choices
        .iter()
        .filter(|choice| choice.outcome.is_none())
        .map(|choice| choice.name.clone())
        .collect::<Vec<_>>();
    for name in unknown_choices {
        plan.defeat(Defeat::new(
            DefeatKind::LookedAndBlocked,
            format!("blocked_delivery.choice.{name}"),
            "a target must not offer a decision whose effect is unknown",
        ));
    }

    if let Some(entity) = data.value.entity(&plan.value.record_type) {
        let record_type = plan.value.record_type.clone();
        let fields = std::iter::once(plan.value.selector_field.clone())
            .chain(plan.value.visible_fields.clone())
            .collect::<Vec<_>>();
        for field in fields {
            if !field.is_empty() && entity.field(&field).is_none() {
                plan.defeat(Defeat::new(
                    DefeatKind::SubjectUnresolvable,
                    format!("{record_type}.{field}"),
                    "the data contract does not provide this required interaction field",
                ));
            }
        }
    } else if !plan.value.record_type.is_empty() {
        plan.defeat(Defeat::new(
            DefeatKind::SubjectUnresolvable,
            plan.value.record_type.clone(),
            "the data contract does not provide the review record",
        ));
    }

    // Data-model defeats about storage identity, uniqueness, defaults, and
    // relations are irrelevant to this read-and-decide projection. Preserve
    // only defeats scoped to the selected record or to resource discovery.
    for defeat in &data.defeats {
        if defeat.subject == "resources"
            || (!plan.value.record_type.is_empty()
                && defeat.subject.starts_with(&plan.value.record_type))
        {
            plan.defeat(Defeat::new(
                defeat.kind,
                defeat.subject.clone(),
                defeat.reason.clone(),
            ));
        }
    }

    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use lift_defeasible::{Completeness, Defeat};
    use semantics_data_model_v1::{
        DefaultOrigin, EntityShape, FieldShape, FieldType, Presence, ScalarType, Tri,
    };

    fn field(name: &str) -> FieldShape {
        FieldShape {
            name: name.to_owned(),
            ty: FieldType::Scalar(ScalarType::Text),
            nullable: Presence::Required,
            list: false,
            identity: Tri::Unknown,
            unique: Tri::Unknown,
            default: DefaultOrigin::Unknown,
            default_value: None,
            enumeration: None,
        }
    }

    fn data() -> Defeasible<DataModel> {
        let mut data = Defeasible::new(
            DataModel {
                entities: vec![EntityShape {
                    name: "BlockedDelivery".to_owned(),
                    fields: ["block_id", "reason", "message"]
                        .into_iter()
                        .map(field)
                        .collect(),
                    unique_sets: Vec::new(),
                }],
                relations: Vec::new(),
            },
            "fixture-data@1",
        );
        data.defeat(Defeat::new(
            DefeatKind::AuthorityCannotExpress,
            "identity",
            "OpenAPI does not describe storage identity",
        ));
        data
    }

    fn control() -> Defeasible<BlockedDeliveryReview> {
        Defeasible::new(
            BlockedDeliveryReview {
                record_type: Some("BlockedDelivery".to_owned()),
                selector_field: Some("block_id".to_owned()),
                review_fields: vec![
                    "block_id".to_owned(),
                    "reason".to_owned(),
                    "message".to_owned(),
                ],
                authority: Some("operator".to_owned()),
                resolutions: vec![
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
            "fixture-control@1",
        )
    }

    #[test]
    fn irrelevant_storage_unknowns_do_not_defeat_an_interaction() {
        let plan = derive_blocked_delivery_plan(&data(), &control());

        assert_eq!(plan.completeness(), Completeness::Exhaustive);
        assert_eq!(plan.value.record_type, "BlockedDelivery");
        assert_eq!(plan.value.selector_field, "block_id");
    }

    #[test]
    fn missing_display_evidence_defeats_both_targets() {
        let mut control = control();
        control.value.review_fields.push("not_in_schema".to_owned());

        let plan = derive_blocked_delivery_plan(&data(), &control);

        assert_eq!(plan.completeness(), Completeness::Partial);
        assert!(
            plan.defeats
                .iter()
                .any(|defeat| defeat.subject == "BlockedDelivery.not_in_schema")
        );
    }

    #[test]
    fn unknown_choice_effect_cannot_become_a_button_or_command() {
        let mut control = control();
        control.value.resolutions[0].outcome = None;

        let plan = derive_blocked_delivery_plan(&data(), &control);

        assert_eq!(plan.completeness(), Completeness::Partial);
        assert!(
            plan.defeats
                .iter()
                .any(|defeat| defeat.subject == "blocked_delivery.choice.requeue")
        );
    }
}
