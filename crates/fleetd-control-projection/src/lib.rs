//! Product-specific projection from Fleetd-native observations into Fleetd
//! control semantics.
//!
//! This bridge is intentionally outside both the source lifter and the
//! semantic contract. Downstream consumers never need to know OpenAPI paths,
//! Rust symbols, or SQLite spellings.

use fleetd_control_lifter::FleetdControlLift;
use lift_defeasible::{Defeasible, Defeat, DefeatKind};
use semantics_fleetd_control_v0::{
    BlockedDeliveryReview, DeliveryOutcome, ResolutionChoice, ReviewAuthority,
};

pub const DEFEATER_SET: &str = "org.gooi.projection.fleetd_control/defeaters@1";

pub fn project_blocked_delivery_review(
    lifted: &FleetdControlLift,
) -> Defeasible<BlockedDeliveryReview> {
    let authority = if lifted.list_operator_guarded && lifted.resolve_operator_guarded {
        ReviewAuthority::Operator
    } else {
        ReviewAuthority::Unknown
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
            Some("pending") => DeliveryOutcome::Pending,
            Some("dead") => DeliveryOutcome::Dead,
            Some(state) => {
                projected.defeat(Defeat::new(
                    DefeatKind::LookedAndBlocked,
                    format!("resolution:{}.outcome", resolution.wire_name),
                    format!("Fleetd delivery state {state:?} has no meaning in this contract"),
                ));
                DeliveryOutcome::Unknown
            }
            None => DeliveryOutcome::Unknown,
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
        assert_eq!(projected.value.authority, ReviewAuthority::Operator);
        assert_eq!(
            projected.value.resolution("requeue").unwrap().outcome,
            DeliveryOutcome::Pending
        );
        assert_eq!(
            projected.value.resolution("abandon").unwrap().outcome,
            DeliveryOutcome::Dead
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
        assert_eq!(projected.value.authority, ReviewAuthority::Unknown);
        assert_eq!(
            projected.value.resolution("requeue").unwrap().outcome,
            DeliveryOutcome::Unknown
        );
    }
}
