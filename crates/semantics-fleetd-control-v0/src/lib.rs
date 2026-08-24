//! Product-specific control semantics for the first Fleetd dogfood slice.
//!
//! This is intentionally *not* a generic workflow or interaction dialect.
//! Fleetd earns the vocabulary here from its own independently observable
//! control behavior. A reusable contract may be extracted only after another
//! product demonstrates the same meaning.

use serde::{Deserialize, Serialize};

pub const PACKAGE: &str = "dev.fleetd.semantics.control";
pub const VERSION: &str = "0.1.0";

/// One named decision the operator may apply to an unresolved block.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolutionChoice {
    /// Stable wire name from Fleetd's public contract.
    pub name: String,
    /// The observable state this resolution produces, by name. `None` means the
    /// source did not establish one.
    pub outcome: Option<String>,
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
    /// The principal class allowed to inspect and resolve, by name.
    ///
    /// `None` means the source did not establish one. This is the same
    /// convention `record_type` and `selector_field` already use, rather than a
    /// second way of saying "not established". Which names are meaningful is
    /// the projection's business, not this type's.
    pub authority: Option<String>,
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

    /// Not-established is one convention across the whole contract, rather than
    /// `Option` for some fields and an `Unknown` variant for others.
    #[test]
    fn every_unestablished_value_is_absent_rather_than_named() {
        let review = BlockedDeliveryReview {
            record_type: None,
            selector_field: None,
            review_fields: Vec::new(),
            authority: None,
            resolutions: vec![ResolutionChoice {
                name: "requeue".to_owned(),
                outcome: None,
            }],
        };
        let encoded = serde_json::to_string(&review).expect("contract serializes");
        assert!(!encoded.contains("unknown"), "{encoded}");
        assert!(encoded.contains("null"), "{encoded}");
    }

    /// The names carried are data, not variants, so an established value is on
    /// the wire exactly as the source spelled it.
    #[test]
    fn an_established_name_is_carried_verbatim() {
        let review = BlockedDeliveryReview {
            record_type: Some("BlockedDelivery".to_owned()),
            selector_field: Some("block_id".to_owned()),
            review_fields: vec!["reason".to_owned()],
            authority: Some("operator".to_owned()),
            resolutions: vec![ResolutionChoice {
                name: "requeue".to_owned(),
                outcome: Some("pending".to_owned()),
            }],
        };
        let encoded = serde_json::to_string(&review).expect("contract serializes");
        assert!(encoded.contains("\"operator\""), "{encoded}");
        assert!(encoded.contains("\"pending\""), "{encoded}");
    }

    #[test]
    fn the_contract_contains_no_presentation_or_transport_vocabulary() {
        let review = BlockedDeliveryReview {
            record_type: Some("BlockedDelivery".to_owned()),
            selector_field: Some("block_id".to_owned()),
            review_fields: vec!["reason".to_owned()],
            authority: Some("operator".to_owned()),
            resolutions: vec![ResolutionChoice {
                name: "requeue".to_owned(),
                outcome: Some("pending".to_owned()),
            }],
        };

        let encoded = serde_json::to_string(&review).expect("contract serializes");
        for forbidden in ["react", "component", "page", "http", "terminal", "widget"] {
            assert!(!encoded.contains(forbidden));
        }
    }
}
