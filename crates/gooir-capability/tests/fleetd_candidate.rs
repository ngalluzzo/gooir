use gooir_capability::{
    CapabilityCandidate, CapabilityConformanceProvider, CapabilityRequest, ConformanceCheck,
    ConformanceOutcome, ConformanceProviderDescriptor, ProviderId, verify_and_admit,
};
use serde_json::json;

struct FixtureRunnableWebSuite;

impl CapabilityConformanceProvider for FixtureRunnableWebSuite {
    fn descriptor(&self) -> ConformanceProviderDescriptor {
        ConformanceProviderDescriptor {
            id: ProviderId::new(
                "dev.fleetd.conformance_provider",
                "fixture_runnable_web",
                "0.1.0",
            ),
            suite: "dev.fleetd.conformance.runnable_web_surface@0.1.0".to_owned(),
            implementation_digest: format!("sha256:{}", "c".repeat(64)),
        }
    }

    fn verify(
        &self,
        _: &CapabilityRequest,
        candidate: &CapabilityCandidate,
    ) -> Result<Vec<ConformanceCheck>, String> {
        Ok(vec![ConformanceCheck {
            name: "fixture-is-not-a-runnable-artifact".to_owned(),
            outcome: ConformanceOutcome::Failed,
            evidence: json!({
                "observed": candidate.body.outputs[0].payload,
                "reason": "the cross-repository fixture proves transport only"
            }),
        }])
    }
}

#[test]
fn fleetd_candidate_round_trips_but_cannot_bypass_conformance() {
    let request: CapabilityRequest =
        serde_json::from_str(include_str!("fixtures/fleetd_runnable_web_request.json"))
            .expect("Fleetd request decodes in GOOIR");
    let candidate: CapabilityCandidate =
        serde_json::from_str(include_str!("fixtures/fleetd_runnable_web_candidate.json"))
            .expect("Fleetd candidate decodes in GOOIR");

    request.validate().expect("request identity remains exact");
    candidate
        .validate(&request)
        .expect("Fleetd and GOOIR compute the same candidate identity");
    assert_eq!(
        candidate.candidate_id,
        "sha256:a2262fbc6ce8af0f59b33c0ec67af7cec2398670b1c7ebb837ab8d256beb802e"
    );

    let admission = verify_and_admit(&request, &candidate, &FixtureRunnableWebSuite)
        .expect("failing conformance remains a valid exact result");
    assert_eq!(
        admission.conformance.body.outcome,
        ConformanceOutcome::Failed
    );
    assert!(admission.facts.is_empty());
}
