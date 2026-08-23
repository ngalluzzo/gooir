use gooir_analysis::{
    BridgeRegistry, ClaimBridge, ContractProjection, EvidenceTrustPolicy, FindingLevel,
    SemanticResolver,
};
use gooir_core::{Claim, ConformanceEvidence, ContractId, Evidence, Operation, Program, SourceRef};
use payments_dialect::charge;
use retry_safety_analysis::RetrySafetyAnalyzer;
use semantics_effects_v1::{
    Delivery, Repeatability, external_effect_claim, external_effect_contract,
    retry_boundary_contract, retry_claim,
};
use serde_json::json;
use workflow_dialect::retrying_activity;

fn source(artifact: &str) -> SourceRef {
    SourceRef::new("test-fixture", artifact, "fixture-revision")
}

fn attestation(artifact: &str) -> ConformanceEvidence {
    ConformanceEvidence::new(
        "fixture-attester",
        "effects-v1-conformance@1",
        format!("sha256:{artifact}-subject"),
        format!("sha256:{artifact}-result"),
    )
}

fn verified(artifact: &str) -> Evidence {
    Evidence::verified(source(artifact), attestation(artifact))
}

fn trust_policy(program: &Program) -> EvidenceTrustPolicy {
    let mut policy = EvidenceTrustPolicy::default();
    for operation in &program.operations {
        admit_operation_claims(&mut policy, operation);
    }
    policy
}

fn admit_operation_claims(policy: &mut EvidenceTrustPolicy, operation: &Operation) {
    for claim in &operation.claims {
        if claim.evidence.conformance.is_some() {
            policy
                .admit_claim(operation, claim)
                .expect("fixture admission is valid");
        }
    }
    for region in &operation.regions {
        for child in region {
            admit_operation_claims(policy, child);
        }
    }
}

fn analyzer_trusting(program: &Program) -> RetrySafetyAnalyzer {
    RetrySafetyAnalyzer::with_resolver(SemanticResolver::with_trust_policy(trust_policy(program)))
}

#[test]
fn safe_composition_is_accepted_across_unrelated_dialects() {
    let effect = charge("charge", Repeatability::Idempotent, verified("payments"));
    let workflow = retrying_activity(
        "activity",
        Delivery::AtLeastOnce,
        verified("workflow"),
        vec![effect],
    );

    let program = Program::new(vec![workflow]);
    let report = analyzer_trusting(&program).analyze(&program);

    assert!(report.is_clean());
}

#[test]
fn verified_duplicate_effect_risk_is_rejected() {
    let effect = charge("charge", Repeatability::NonIdempotent, verified("payments"));
    let workflow = retrying_activity(
        "activity",
        Delivery::AtLeastOnce,
        verified("workflow"),
        vec![effect],
    );

    let program = Program::new(vec![workflow]);
    let report = analyzer_trusting(&program).analyze(&program);

    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].level, FindingLevel::Error);
    assert_eq!(report.findings[0].code, "retry.non_idempotent_effect");
}

#[test]
fn unverified_claim_degrades_to_unknown_instead_of_safe() {
    let effect = charge(
        "charge",
        Repeatability::NonIdempotent,
        Evidence::declared(source("payments")),
    );
    let workflow = retrying_activity(
        "activity",
        Delivery::AtLeastOnce,
        verified("workflow"),
        vec![effect],
    );

    let program = Program::new(vec![workflow]);
    let mut policy = EvidenceTrustPolicy::default();
    for claim in &program.operations[0].claims {
        policy
            .admit_claim(&program.operations[0], claim)
            .expect("workflow fixture admission is valid");
    }
    let report = RetrySafetyAnalyzer::with_resolver(SemanticResolver::with_trust_policy(policy))
        .analyze(&program);

    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].level, FindingLevel::Unknown);
    assert_eq!(report.findings[0].code, "retry.effect_safety_unknown");
}

#[test]
fn self_reported_verified_claim_is_unknown_without_policy_admission() {
    let effect = charge("charge", Repeatability::NonIdempotent, verified("payments"));
    let workflow = retrying_activity(
        "activity",
        Delivery::AtLeastOnce,
        verified("workflow"),
        vec![effect],
    );

    let report = RetrySafetyAnalyzer::new().analyze(&Program::new(vec![workflow]));

    assert!(!report.findings.is_empty());
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.level == FindingLevel::Unknown)
    );
}

#[test]
fn changed_contract_version_requires_an_explicit_bridge() {
    let retry_v2 = ContractId::new("org.gooi.semantics.effects", "retry_boundary", "2.0.0");
    let workflow = gooir_core::Operation::new("activity", "alternate.workflow", "activity")
        .with_claim(Claim::new(
            retry_v2,
            json!({"delivery": "at_least_once"}),
            verified("workflow-v2"),
        ))
        .with_claim(external_effect_claim(
            Repeatability::None,
            verified("workflow-v2"),
        ))
        .with_region(vec![charge(
            "charge",
            Repeatability::NonIdempotent,
            verified("payments"),
        )]);

    let program = Program::new(vec![workflow]);
    let report = analyzer_trusting(&program).analyze(&program);

    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].level, FindingLevel::Unknown);
    assert!(report.findings[0].message.contains("explicit bridge"));
}

#[test]
fn explicit_bridge_makes_version_conversion_auditable() {
    let mut bridges = BridgeRegistry::default();
    bridges.register(RetryV2ToV1);

    let retry_v2 = RetryV2ToV1.from();
    let workflow = gooir_core::Operation::new("activity", "alternate.workflow", "activity")
        .with_claim(Claim::new(
            retry_v2,
            json!({"delivery": "at_least_once"}),
            verified("workflow-v2"),
        ))
        .with_claim(external_effect_claim(
            Repeatability::None,
            verified("workflow-v2"),
        ))
        .with_region(vec![charge(
            "charge",
            Repeatability::NonIdempotent,
            verified("payments"),
        )]);

    let program = Program::new(vec![workflow]);
    let resolver = SemanticResolver::with_bridges_and_trust_policy(bridges, trust_policy(&program));
    let report = RetrySafetyAnalyzer::with_resolver(resolver).analyze(&program);

    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].level, FindingLevel::Error);
}

#[test]
fn open_world_projection_is_parametric_over_native_dialect_identity() {
    let canonical = Program::new(vec![retrying_activity(
        "activity",
        Delivery::AtLeastOnce,
        verified("canonical-workflow"),
        vec![charge(
            "effect",
            Repeatability::NonIdempotent,
            verified("canonical-payments"),
        )],
    )]);
    let canonical_report = analyzer_trusting(&canonical).analyze(&canonical);

    let alien = alien_program();
    let mut resolver = SemanticResolver::with_trust_policy(alien_trust_policy(&alien));
    resolver.register_projection(AlienRetryProjection);
    resolver.register_projection(AlienEffectProjection);
    let alien_report = RetrySafetyAnalyzer::with_resolver(resolver).analyze(&alien);

    assert_eq!(normalized(&alien_report), normalized(&canonical_report));
}

#[test]
fn unfamiliar_representation_without_projection_is_unknown() {
    let report = RetrySafetyAnalyzer::new().analyze(&alien_program());

    assert!(!report.findings.is_empty());
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.level == FindingLevel::Unknown)
    );
}

#[test]
fn familiar_looking_decoy_without_contracts_is_unknown() {
    let mut fake_effect = Operation::new("effect", "example.payments", "charge");
    fake_effect
        .attributes
        .insert("repeatability".to_owned(), json!("non_idempotent"));
    let mut fake_retry =
        Operation::new("activity", "example.workflow", "activity").with_region(vec![fake_effect]);
    fake_retry
        .attributes
        .insert("delivery".to_owned(), json!("at_least_once"));

    let report = RetrySafetyAnalyzer::new().analyze(&Program::new(vec![fake_retry]));

    assert!(!report.findings.is_empty());
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.level == FindingLevel::Unknown)
    );
}

fn alien_program() -> Program {
    let mut alien_effect = Operation::new("effect", "random.7f93", "x17");
    alien_effect
        .extensions
        .insert("side_effect_blob".to_owned(), json!([9, 4, 9]));

    let mut alien_retry =
        Operation::new("activity", "random.7f93", "z42").with_region(vec![alien_effect]);
    alien_retry
        .extensions
        .insert("control_blob".to_owned(), json!({"mode": 73}));

    Program::new(vec![alien_retry])
}

fn alien_trust_policy(program: &Program) -> EvidenceTrustPolicy {
    let mut policy = EvidenceTrustPolicy::default();
    for operation in &program.operations {
        admit_alien_projection_claims(&mut policy, operation);
    }
    policy
}

fn admit_alien_projection_claims(policy: &mut EvidenceTrustPolicy, operation: &Operation) {
    for claim in [
        AlienRetryProjection
            .project(operation)
            .expect("retry projection succeeds"),
        AlienEffectProjection
            .project(operation)
            .expect("effect projection succeeds"),
    ]
    .into_iter()
    .flatten()
    {
        policy
            .admit_claim(operation, &claim)
            .expect("projected fixture admission is valid");
    }

    for region in &operation.regions {
        for child in region {
            admit_alien_projection_claims(policy, child);
        }
    }
}

fn normalized(report: &gooir_analysis::AnalysisReport) -> Vec<(String, FindingLevel, String)> {
    report
        .findings
        .iter()
        .map(|finding| {
            (
                finding.code.clone(),
                finding.level.clone(),
                finding.message.clone(),
            )
        })
        .collect()
}

struct AlienRetryProjection;

impl ContractProjection for AlienRetryProjection {
    fn target(&self) -> ContractId {
        retry_boundary_contract()
    }

    fn project(&self, operation: &Operation) -> Result<Option<Claim>, String> {
        if operation.extensions.get("control_blob") == Some(&json!({"mode": 73})) {
            return Ok(Some(retry_claim(
                Delivery::AtLeastOnce,
                verified("alien-control"),
            )));
        }

        Ok(None)
    }
}

struct AlienEffectProjection;

impl ContractProjection for AlienEffectProjection {
    fn target(&self) -> ContractId {
        external_effect_contract()
    }

    fn project(&self, operation: &Operation) -> Result<Option<Claim>, String> {
        if operation.extensions.contains_key("control_blob") {
            return Ok(Some(external_effect_claim(
                Repeatability::None,
                verified("alien-control"),
            )));
        }

        if operation.extensions.get("side_effect_blob") == Some(&json!([9, 4, 9])) {
            return Ok(Some(external_effect_claim(
                Repeatability::NonIdempotent,
                verified("alien-effect"),
            )));
        }

        Ok(None)
    }
}

struct RetryV2ToV1;

impl ClaimBridge for RetryV2ToV1 {
    fn from(&self) -> ContractId {
        ContractId::new("org.gooi.semantics.effects", "retry_boundary", "2.0.0")
    }

    fn to(&self) -> ContractId {
        retry_boundary_contract()
    }

    fn convert(&self, claim: &Claim) -> Result<Claim, String> {
        Ok(Claim::new(
            self.to(),
            claim.payload.clone(),
            claim.evidence.clone(),
        ))
    }
}
