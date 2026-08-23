use gooir_core::{Claim, ContractId, Evidence};
use serde_json::{Value, json};

pub const PACKAGE: &str = "org.gooi.semantics.effects";
pub const VERSION: &str = "1.0.0";

pub fn retry_boundary_contract() -> ContractId {
    ContractId::new(PACKAGE, "retry_boundary", VERSION)
}

pub fn external_effect_contract() -> ContractId {
    ContractId::new(PACKAGE, "external_effect", VERSION)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Delivery {
    AtLeastOnce,
    AtMostOnce,
}

impl Delivery {
    fn as_str(self) -> &'static str {
        match self {
            Self::AtLeastOnce => "at_least_once",
            Self::AtMostOnce => "at_most_once",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Repeatability {
    None,
    Idempotent,
    NonIdempotent,
}

impl Repeatability {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Idempotent => "idempotent",
            Self::NonIdempotent => "non_idempotent",
        }
    }
}

pub fn retry_claim(delivery: Delivery, evidence: Evidence) -> Claim {
    Claim::new(
        retry_boundary_contract(),
        json!({"delivery": delivery.as_str()}),
        evidence,
    )
}

pub fn external_effect_claim(repeatability: Repeatability, evidence: Evidence) -> Claim {
    Claim::new(
        external_effect_contract(),
        json!({"repeatability": repeatability.as_str()}),
        evidence,
    )
}

pub fn parse_delivery(payload: &Value) -> Option<Delivery> {
    match payload.get("delivery")?.as_str()? {
        "at_least_once" => Some(Delivery::AtLeastOnce),
        "at_most_once" => Some(Delivery::AtMostOnce),
        _ => None,
    }
}

pub fn parse_repeatability(payload: &Value) -> Option<Repeatability> {
    match payload.get("repeatability")?.as_str()? {
        "none" => Some(Repeatability::None),
        "idempotent" => Some(Repeatability::Idempotent),
        "non_idempotent" => Some(Repeatability::NonIdempotent),
        _ => None,
    }
}
