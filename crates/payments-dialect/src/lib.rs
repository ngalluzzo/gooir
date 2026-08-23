use gooir_core::{Evidence, Operation};
use semantics_effects_v1::{Repeatability, external_effect_claim};

pub fn charge(
    id: impl Into<String>,
    repeatability: Repeatability,
    evidence: Evidence,
) -> Operation {
    Operation::new(id, "example.payments", "charge")
        .with_claim(external_effect_claim(repeatability, evidence))
}
