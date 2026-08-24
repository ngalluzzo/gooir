//! Product-specific control semantics for the first Fleetd dogfood slice.
//!
//! This is intentionally *not* a generic workflow or interaction dialect.
//! Fleetd earns the vocabulary here from its own independently observable
//! control behavior. A reusable contract may be extracted only after another
//! product demonstrates the same meaning.

use serde::{Deserialize, Serialize};

pub const PACKAGE: &str = "dev.fleetd.semantics.control";
pub const VERSION: &str = "0.1.0";

/// The principal class allowed to inspect and resolve blocked deliveries.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewAuthority {
    Operator,
    Unknown,
}

/// Fleetd's observable delivery state after applying one resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryOutcome {
    Pending,
    Dead,
    /// The source lift saw the choice but could not establish its effect.
    Unknown,
}

/// One named decision the operator may apply to an unresolved block.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolutionChoice {
    /// Stable wire name from Fleetd's public contract.
    pub name: String,
    pub outcome: DeliveryOutcome,
}

/// Meaning needed to expose Fleetd's blocked-delivery review loop without
/// choosing HTTP, a GUI component library, or a terminal toolkit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockedDeliveryReview {
    /// Public record type returned by the review collection.
    pub record_type: Option<String>,
    /// Field that identifies the exact blocked record being resolved.
    pub selector_field: Option<String>,
    /// Exact fields Fleetd promises to provide for an unresolved block.
    pub review_fields: Vec<String>,
    pub authority: ReviewAuthority,
    pub resolutions: Vec<ResolutionChoice>,
}

impl BlockedDeliveryReview {
    pub fn resolution(&self, name: &str) -> Option<&ResolutionChoice> {
        self.resolutions
            .iter()
            .find(|resolution| resolution.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_contract_contains_no_presentation_or_transport_vocabulary() {
        let review = BlockedDeliveryReview {
            record_type: Some("BlockedDelivery".to_owned()),
            selector_field: Some("block_id".to_owned()),
            review_fields: vec!["reason".to_owned()],
            authority: ReviewAuthority::Operator,
            resolutions: vec![ResolutionChoice {
                name: "requeue".to_owned(),
                outcome: DeliveryOutcome::Pending,
            }],
        };

        let encoded = serde_json::to_string(&review).expect("contract serializes");
        for forbidden in ["react", "component", "page", "http", "terminal", "widget"] {
            assert!(!encoded.contains(forbidden));
        }
    }
}
