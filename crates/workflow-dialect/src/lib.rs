use gooir_core::{Evidence, Operation};
use semantics_effects_v1::{Delivery, Repeatability, external_effect_claim, retry_claim};

pub fn retrying_activity(
    id: impl Into<String>,
    delivery: Delivery,
    evidence: Evidence,
    body: Vec<Operation>,
) -> Operation {
    Operation::new(id, "example.workflow", "activity")
        .with_claim(retry_claim(delivery, evidence.clone()))
        .with_claim(external_effect_claim(Repeatability::None, evidence))
        .with_region(body)
}
