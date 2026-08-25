//! Provisional semantic vocabulary for one narrow interaction observation.
//!
//! Independently governed runtime lineages established only that activating an
//! authority-local action can invoke the handler registered for it. This
//! contract carries exactly that intersection. It does not infer further
//! meaning from the handler or from the absence of an observed outcome.

use gooir_core::ContractId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const PACKAGE: &str = "org.gooi.semantics.interaction_activation";
pub const MODEL: &str = "action_activation";
pub const VERSION: &str = "0.1.0";

/// Exact identity of this provisional semantic contract.
pub fn activation_contract() -> ContractId {
    ContractId::new(PACKAGE, MODEL, VERSION)
}

/// The one activation outcome established by the audited source corpus.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationOutcome {
    InvokesRegisteredHandler,
}

/// One observed relationship between an action and its registered handler.
///
/// `outcome: None` means the authority did not establish an outcome. It never
/// means that activation has no outcome or that invoking the handler is safe.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActionActivation {
    /// Exact claim-local action identity. A projection may recover this from
    /// source or explicitly scope it to its audit; consumers must not case-fold,
    /// trim, or otherwise normalize it when matching identities.
    pub action_id: String,
    pub outcome: Option<ActivationOutcome>,
    /// Unrecognized fields survive transport without being interpreted.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// Why an activation is not a complete instance of this contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationVerificationError {
    BlankActionId,
    OutcomeNotEstablished,
    ReservedExtensionKey,
}

impl ActionActivation {
    /// Checks only obligations this contract actually establishes.
    ///
    /// Verification never fills missing information and never rewrites the
    /// action identity. Extension data is opaque and therefore cannot make an
    /// otherwise incomplete activation complete.
    pub fn verify(&self) -> Result<(), Vec<ActivationVerificationError>> {
        let mut errors = Vec::new();
        if self.action_id.trim().is_empty() {
            errors.push(ActivationVerificationError::BlankActionId);
        }
        if self.outcome.is_none() {
            errors.push(ActivationVerificationError::OutcomeNotEstablished);
        }
        if self.extensions.contains_key("action_id") || self.extensions.contains_key("outcome") {
            errors.push(ActivationVerificationError::ReservedExtensionKey);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// True only when both exact identity and audited outcome are established.
    pub fn is_established(&self) -> bool {
        self.verify().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn established() -> ActionActivation {
        ActionActivation {
            action_id: "counter.increment".to_owned(),
            outcome: Some(ActivationOutcome::InvokesRegisteredHandler),
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn contract_identity_is_exact_and_versioned() {
        assert_eq!(
            activation_contract(),
            ContractId::new(
                "org.gooi.semantics.interaction_activation",
                "action_activation",
                "0.1.0"
            )
        );
    }

    #[test]
    fn established_activation_round_trips() {
        let activation = established();
        let encoded = serde_json::to_value(&activation).expect("activation serializes");
        let decoded: ActionActivation =
            serde_json::from_value(encoded).expect("activation deserializes");

        assert_eq!(decoded, activation);
        assert!(decoded.is_established());
    }

    #[test]
    fn absent_outcome_remains_unknown_and_blocks_verification() {
        let mut activation = established();
        activation.outcome = None;

        assert_eq!(
            activation.verify(),
            Err(vec![ActivationVerificationError::OutcomeNotEstablished])
        );
        assert_eq!(
            serde_json::to_value(activation).expect("unknown outcome serializes")["outcome"],
            Value::Null
        );
    }

    #[test]
    fn blank_identity_and_unknown_outcome_are_both_reported() {
        let activation = ActionActivation {
            action_id: "  ".to_owned(),
            outcome: None,
            extensions: BTreeMap::new(),
        };

        assert_eq!(
            activation.verify(),
            Err(vec![
                ActivationVerificationError::BlankActionId,
                ActivationVerificationError::OutcomeNotEstablished,
            ])
        );
    }

    #[test]
    fn action_identity_is_not_normalized() {
        let mut lower = established();
        let mut upper = established();
        lower.action_id = "counter.increment".to_owned();
        upper.action_id = "Counter.Increment".to_owned();

        assert!(lower.is_established());
        assert!(upper.is_established());
        assert_ne!(lower.action_id, upper.action_id);
    }

    #[test]
    fn unknown_extension_data_round_trips_losslessly() {
        let input = json!({
            "action_id": "counter.increment",
            "outcome": "invokes_registered_handler",
            "vendor_trace": {
                "opaque": true,
                "steps": [1, 2, 3]
            },
            "future_field": "preserve me"
        });

        let activation: ActionActivation =
            serde_json::from_value(input.clone()).expect("extended activation deserializes");
        let output = serde_json::to_value(activation).expect("extended activation serializes");

        assert_eq!(output, input);
    }

    #[test]
    fn an_unrecognized_outcome_is_not_misclassified_as_the_known_outcome() {
        let input = json!({
            "action_id": "counter.increment",
            "outcome": "future_outcome"
        });

        assert!(serde_json::from_value::<ActionActivation>(input).is_err());
    }

    #[test]
    fn extensions_cannot_shadow_contract_fields() {
        let mut activation = established();
        activation
            .extensions
            .insert("action_id".to_owned(), json!("replacement"));

        assert_eq!(
            activation.verify(),
            Err(vec![ActivationVerificationError::ReservedExtensionKey])
        );
    }
}
