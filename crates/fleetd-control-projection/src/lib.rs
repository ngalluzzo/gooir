//! Product-specific projection from Fleetd-native observations into Fleetd
//! control semantics.
//!
//! This bridge is intentionally outside both the source lifter and the
//! semantic contract. Downstream consumers never need to know OpenAPI paths,
//! Rust symbols, or SQLite spellings.

use fleetd_control_lifter::FleetdControlLift;
use lift_defeasible::{Defeasible, Defeat, DefeatKind};
use semantics_fleetd_control_v0::{BlockedDeliveryReview, ResolutionChoice};

/// The delivery states this projection is prepared to carry. Vetting lives here
/// rather than in the contract's type, so an unrecognised state can be reported
/// by name instead of collapsing into an anonymous unknown.
pub const VETTED_OUTCOMES: [&str; 2] = ["pending", "dead"];

/// The authority name Fleetd's operator guards establish.
pub const AUTHORITY_OPERATOR: &str = "operator";

pub const DEFEATER_SET: &str = "org.gooi.projection.fleetd_control/defeaters@1";

pub fn project_blocked_delivery_review(
    lifted: &FleetdControlLift,
) -> Defeasible<BlockedDeliveryReview> {
    let authority = if lifted.list_operator_guarded && lifted.resolve_operator_guarded {
        Some(AUTHORITY_OPERATOR.to_owned())
    } else {
        None
    };
    let mut projected = Defeasible::new(
        BlockedDeliveryReview {
            record_type: lifted.blocked_delivery_schema.clone(),
            selector_field: lifted.resolution_selector.clone(),
            review_fields: lifted.review_fields.clone(),
            authority,
            resolutions: Vec::new(),
        },
        DEFEATER_SET,
    );

    for resolution in &lifted.resolutions {
        let outcome = match resolution.resulting_state.as_deref() {
            Some(state) if VETTED_OUTCOMES.contains(&state) => Some(state.to_owned()),
            Some(state) => {
                projected.defeat(Defeat::new(
                    DefeatKind::LookedAndBlocked,
                    format!("resolution:{}.outcome", resolution.wire_name),
                    format!("Fleetd delivery state {state:?} has no meaning in this contract"),
                ));
                None
            }
            None => {
                projected.defeat(Defeat::new(
                    DefeatKind::LookedAndBlocked,
                    format!("resolution:{}.outcome", resolution.wire_name),
                    "the lift established no resulting delivery state".to_owned(),
                ));
                None
            }
        };
        projected.value.resolutions.push(ResolutionChoice {
            name: resolution.wire_name.clone(),
            outcome,
        });
    }

    for reason in &lifted.coverage.unresolved {
        projected.defeat(Defeat::new(
            DefeatKind::LookedAndBlocked,
            "fleetd.blocked_delivery_review",
            reason.clone(),
        ));
    }
    projected
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleetd_control_lifter::{
        NativeApiOperation, NativeCompleteness, NativeCoverage, NativeResolution,
    };
    use lift_defeasible::Completeness;

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
            review_fields: vec![
                "block_id".to_owned(),
                "agent_id".to_owned(),
                "message".to_owned(),
                "attempt".to_owned(),
                "reason".to_owned(),
                "blocked_at_ms".to_owned(),
            ],
            list_operator_guarded: true,
            resolve_operator_guarded: true,
            resolution_effects_committed: true,
            resolutions: vec![
                NativeResolution {
                    wire_name: "requeue".to_owned(),
                    rust_symbol: Some("Requeue".to_owned()),
                    resulting_state: Some("pending".to_owned()),
                },
                NativeResolution {
                    wire_name: "abandon".to_owned(),
                    rust_symbol: Some("Abandon".to_owned()),
                    resulting_state: Some("dead".to_owned()),
                },
            ],
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
    fn exhaustive_native_evidence_projects_without_transport_details() {
        let projected = project_blocked_delivery_review(&native());

        assert_eq!(projected.completeness(), Completeness::Exhaustive);
        assert_eq!(projected.value.authority.as_deref(), Some("operator"));
        assert_eq!(
            projected
                .value
                .resolution("requeue")
                .unwrap()
                .outcome
                .as_deref(),
            Some("pending")
        );
        assert_eq!(
            projected
                .value
                .resolution("abandon")
                .unwrap()
                .outcome
                .as_deref(),
            Some("dead")
        );
    }

    #[test]
    fn missing_guard_and_effects_degrade_instead_of_following_names() {
        let mut lifted = native();
        lifted.list_operator_guarded = false;
        lifted.resolutions[0].resulting_state = None;
        lifted.coverage.completeness = NativeCompleteness::Partial;
        lifted
            .coverage
            .unresolved
            .push("list guard and requeue effect unresolved".to_owned());

        let projected = project_blocked_delivery_review(&lifted);

        assert_eq!(projected.completeness(), Completeness::Partial);
        assert_eq!(projected.value.authority, None);
        assert_eq!(projected.value.resolution("requeue").unwrap().outcome, None);
    }

    /// The vetted set lives in this projection, not in the contract's type, so
    /// an unrecognised state is reported by name rather than collapsing into an
    /// anonymous unknown.
    #[test]
    fn an_unvetted_delivery_state_is_refused_by_name() {
        let mut lifted = native();
        lifted.resolutions[0].resulting_state = Some("quarantined".to_owned());

        let projected = project_blocked_delivery_review(&lifted);

        assert_eq!(projected.value.resolution("requeue").unwrap().outcome, None);
        assert!(
            projected
                .defeats
                .iter()
                .any(|d| d.reason.contains("quarantined")),
            "the observed name must survive into the defeat: {:?}",
            projected.defeats
        );
        assert!(!VETTED_OUTCOMES.contains(&"quarantined"));
    }
}
