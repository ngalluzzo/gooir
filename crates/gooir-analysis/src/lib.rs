use gooir_core::{Claim, ContractId, EvidenceStatus, Operation, Program};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FindingLevel {
    Error,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub code: String,
    pub level: FindingLevel,
    pub operation_id: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AnalysisReport {
    pub analyzer: String,
    pub findings: Vec<Finding>,
}

impl AnalysisReport {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

pub trait ClaimBridge: Send + Sync {
    fn from(&self) -> ContractId;
    fn to(&self) -> ContractId;
    fn convert(&self, claim: &Claim) -> Result<Claim, String>;
}

/// Late-bound projection from a native operation into one semantic contract.
/// An analyzer consumes only the resulting claim; it never sees projection
/// implementation details.
pub trait ContractProjection: Send + Sync {
    fn target(&self) -> ContractId;
    fn project(&self, operation: &Operation) -> Result<Option<Claim>, String>;
}

#[derive(Default)]
pub struct BridgeRegistry {
    bridges: Vec<Box<dyn ClaimBridge>>,
}

impl BridgeRegistry {
    pub fn register(&mut self, bridge: impl ClaimBridge + 'static) {
        self.bridges.push(Box::new(bridge));
    }
}

#[derive(Default)]
pub struct ProjectionRegistry {
    projections: Vec<Box<dyn ContractProjection>>,
}

impl ProjectionRegistry {
    pub fn register(&mut self, projection: impl ContractProjection + 'static) {
        self.projections.push(Box::new(projection));
    }
}

/// Contextual admission policy for conformance-backed semantic claims.
///
/// The default policy denies all claim bindings. The host constructing a policy
/// is responsible for validating attestation authenticity, authority, source
/// provenance, and the referenced result artifact before admission.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EvidenceTrustPolicy {
    admitted: Vec<AdmittedClaim>,
}

impl EvidenceTrustPolicy {
    /// Admits an attestation bound to one exact operation and semantic claim.
    ///
    /// The host must validate the claim's conformance result and provenance
    /// before calling this method.
    pub fn admit_claim(
        &mut self,
        operation: &Operation,
        claim: &Claim,
    ) -> Result<(), EvidenceAdmissionFailure> {
        if claim.evidence.status != EvidenceStatus::Verified {
            return Err(EvidenceAdmissionFailure::StatusNotVerified);
        }
        if claim.evidence.conformance.is_none() {
            return Err(EvidenceAdmissionFailure::MissingAttestation);
        }

        let admission = AdmittedClaim {
            operation_id: operation.id.clone(),
            claim: claim.clone(),
        };
        if !self.admitted.contains(&admission) {
            self.admitted.push(admission);
        }
        Ok(())
    }

    fn evaluate(&self, operation_id: &str, claim: &Claim) -> EvidenceTrustDecision {
        if claim.evidence.status != EvidenceStatus::Verified {
            return EvidenceTrustDecision::Untrusted(EvidenceTrustFailure::StatusNotVerified);
        }

        let Some(_) = &claim.evidence.conformance else {
            return EvidenceTrustDecision::Untrusted(EvidenceTrustFailure::MissingAttestation);
        };

        let admission = AdmittedClaim {
            operation_id: operation_id.to_owned(),
            claim: claim.clone(),
        };
        if self.admitted.contains(&admission) {
            EvidenceTrustDecision::Trusted
        } else {
            EvidenceTrustDecision::Untrusted(EvidenceTrustFailure::ClaimNotAdmitted)
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct AdmittedClaim {
    operation_id: String,
    claim: Claim,
}

/// Reason an exact claim could not be admitted into a trust policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceAdmissionFailure {
    /// The evidence does not report verified status.
    StatusNotVerified,
    /// Verified status was reported without a conformance attestation.
    MissingAttestation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum EvidenceTrustDecision {
    Trusted,
    Untrusted(EvidenceTrustFailure),
}

/// Reason a claim's evidence was not trusted by the active policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceTrustFailure {
    /// The evidence does not report verified status.
    StatusNotVerified,
    /// Verified status was reported without a conformance attestation.
    MissingAttestation,
    /// The host did not admit the exact operation and semantic claim binding.
    ClaimNotAdmitted,
}

#[derive(Default)]
pub struct SemanticResolver {
    bridges: BridgeRegistry,
    projections: ProjectionRegistry,
    trust_policy: EvidenceTrustPolicy,
}

impl SemanticResolver {
    /// Creates a resolver with bridges and a default-deny trust policy.
    pub fn with_bridges(bridges: BridgeRegistry) -> Self {
        Self {
            bridges,
            projections: ProjectionRegistry::default(),
            trust_policy: EvidenceTrustPolicy::default(),
        }
    }

    /// Creates a resolver with an explicit trust policy and no bridges.
    pub fn with_trust_policy(trust_policy: EvidenceTrustPolicy) -> Self {
        Self {
            bridges: BridgeRegistry::default(),
            projections: ProjectionRegistry::default(),
            trust_policy,
        }
    }

    /// Creates a resolver with explicit bridges and an explicit trust policy.
    pub fn with_bridges_and_trust_policy(
        bridges: BridgeRegistry,
        trust_policy: EvidenceTrustPolicy,
    ) -> Self {
        Self {
            bridges,
            projections: ProjectionRegistry::default(),
            trust_policy,
        }
    }

    pub fn register_bridge(&mut self, bridge: impl ClaimBridge + 'static) {
        self.bridges.register(bridge);
    }

    pub fn register_projection(&mut self, projection: impl ContractProjection + 'static) {
        self.projections.register(projection);
    }

    pub fn resolve(&self, operation: &Operation, expected: &ContractId) -> ClaimResolution {
        let mut claims = operation.claims.clone();

        for projection in &self.projections.projections {
            let target = projection.target();
            if target == *expected || target.is_other_version_of(expected) {
                match projection.project(operation) {
                    Ok(Some(claim)) if claim.contract == target => claims.push(claim),
                    Ok(Some(claim)) => {
                        return ClaimResolution::InvalidProjection(format!(
                            "projection produced {}@{} instead of its declared target {}@{}",
                            claim.contract.name,
                            claim.contract.version,
                            target.name,
                            target.version
                        ));
                    }
                    Ok(None) => {}
                    Err(error) => return ClaimResolution::InvalidProjection(error),
                }
            }
        }

        let exact = claims
            .iter()
            .filter(|claim| claim.contract == *expected)
            .cloned()
            .collect::<Vec<_>>();

        match exact.as_slice() {
            [claim] => return self.classify(&operation.id, claim.clone(), claim),
            claims if claims.len() > 1 => {
                return ClaimResolution::Ambiguous(
                    claims.iter().map(|claim| claim.contract.clone()).collect(),
                );
            }
            _ => {}
        }

        let related = claims
            .iter()
            .filter(|claim| claim.contract.is_other_version_of(expected))
            .collect::<Vec<_>>();

        let mut converted = Vec::new();
        for claim in &related {
            for bridge in &self.bridges.bridges {
                if bridge.from() == claim.contract && bridge.to() == *expected {
                    match bridge.convert(claim) {
                        Ok(converted_claim)
                            if converted_claim.contract == *expected
                                && converted_claim.payload == claim.payload
                                && converted_claim.evidence == claim.evidence =>
                        {
                            converted.push((converted_claim, (*claim).clone()));
                        }
                        Ok(converted_claim)
                            if converted_claim.contract == *expected
                                && converted_claim.evidence != claim.evidence =>
                        {
                            return ClaimResolution::InvalidBridge(
                                "bridge changed claim evidence instead of preserving it".to_owned(),
                            );
                        }
                        Ok(converted_claim) if converted_claim.contract == *expected => {
                            return ClaimResolution::InvalidBridge(
                                "bridge changed claim payload instead of preserving it".to_owned(),
                            );
                        }
                        Ok(converted_claim) => {
                            return ClaimResolution::InvalidBridge(format!(
                                "bridge produced {}@{} instead of {}@{}",
                                converted_claim.contract.name,
                                converted_claim.contract.version,
                                expected.name,
                                expected.version
                            ));
                        }
                        Err(error) => return ClaimResolution::InvalidBridge(error),
                    }
                }
            }
        }

        match converted.as_slice() {
            [(claim, source_claim)] => self.classify(&operation.id, claim.clone(), source_claim),
            claims if claims.len() > 1 => ClaimResolution::Ambiguous(
                claims
                    .iter()
                    .map(|(claim, _)| claim.contract.clone())
                    .collect(),
            ),
            _ if !related.is_empty() => ClaimResolution::VersionMismatch(
                related.iter().map(|claim| claim.contract.clone()).collect(),
            ),
            _ => ClaimResolution::Absent,
        }
    }

    fn classify(
        &self,
        operation_id: &str,
        claim: Claim,
        admission_claim: &Claim,
    ) -> ClaimResolution {
        match self.trust_policy.evaluate(operation_id, admission_claim) {
            EvidenceTrustDecision::Trusted => ClaimResolution::Trusted(claim),
            EvidenceTrustDecision::Untrusted(reason) => {
                ClaimResolution::Untrusted { claim, reason }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ClaimResolution {
    Trusted(Claim),
    Untrusted {
        claim: Claim,
        reason: EvidenceTrustFailure,
    },
    VersionMismatch(Vec<ContractId>),
    Ambiguous(Vec<ContractId>),
    InvalidBridge(String),
    InvalidProjection(String),
    Absent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Legality {
    Legal,
    Pinned { reason: String },
    Unknown { reason: String },
}

/// Target packs provide this semantic decision. The generic traversal only
/// records the exact frontier; it does not know why an operation is legal.
pub trait LegalityOracle {
    fn classify(&self, operation: &Operation) -> Legality;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrontierEntry {
    pub operation_id: String,
    pub path: String,
    pub legality: Legality,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PortabilityFrontier {
    pub entries: Vec<FrontierEntry>,
}

pub fn portability_frontier(
    program: &Program,
    oracle: &impl LegalityOracle,
) -> PortabilityFrontier {
    let mut frontier = PortabilityFrontier::default();

    for (operation_index, operation) in program.operations.iter().enumerate() {
        visit_legality(
            operation,
            format!("operations[{operation_index}]"),
            oracle,
            &mut frontier,
        );
    }

    frontier
}

fn visit_legality(
    operation: &Operation,
    path: String,
    oracle: &impl LegalityOracle,
    frontier: &mut PortabilityFrontier,
) {
    let legality = oracle.classify(operation);
    if legality != Legality::Legal {
        frontier.entries.push(FrontierEntry {
            operation_id: operation.id.clone(),
            path: path.clone(),
            legality,
        });
        return;
    }

    for (region_index, region) in operation.regions.iter().enumerate() {
        for (operation_index, child) in region.iter().enumerate() {
            visit_legality(
                child,
                format!("{path}.regions[{region_index}][{operation_index}]"),
                oracle,
                frontier,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BridgeRegistry, ClaimBridge, ClaimResolution, EvidenceAdmissionFailure,
        EvidenceTrustFailure, EvidenceTrustPolicy, Legality, LegalityOracle, SemanticResolver,
        portability_frontier,
    };
    use gooir_core::{
        Claim, ConformanceEvidence, ContractId, Evidence, EvidenceStatus, Operation, Program,
        SourceRef,
    };
    use serde_json::json;

    fn contract() -> ContractId {
        ContractId::new("org.gooi.test", "capability", "1.0.0")
    }

    fn source() -> SourceRef {
        SourceRef::new("fixture", "fixture.json", "revision")
    }

    fn attestation() -> ConformanceEvidence {
        ConformanceEvidence::new(
            "fixture-attester",
            "fixture-suite@1",
            "sha256:subject",
            "sha256:result",
        )
    }

    fn attested_claim(payload: &str, attestation: ConformanceEvidence) -> Claim {
        Claim::new(
            contract(),
            json!({"value": payload}),
            Evidence::verified(source(), attestation),
        )
    }

    fn operation_with(claims: impl IntoIterator<Item = Claim>) -> Operation {
        claims
            .into_iter()
            .fold(Operation::new("op", "fixture", "op"), |operation, claim| {
                operation.with_claim(claim)
            })
    }

    struct FixtureTarget;

    impl LegalityOracle for FixtureTarget {
        fn classify(&self, operation: &Operation) -> Legality {
            match operation.name.as_str() {
                "portable" => Legality::Legal,
                "target_specific" => Legality::Pinned {
                    reason: "requires target.alpha capability".to_owned(),
                },
                _ => Legality::Unknown {
                    reason: "no installed legality rule".to_owned(),
                },
            }
        }
    }

    #[test]
    fn partial_legality_reports_the_exact_portability_frontier() {
        let program = Program::new(vec![
            Operation::new("root", "fixture", "portable").with_region(vec![
                Operation::new("portable-child", "fixture", "portable"),
                Operation::new("pinned-child", "fixture", "target_specific"),
                Operation::new("opaque-child", "unknown", "opaque"),
            ]),
        ]);

        let frontier = portability_frontier(&program, &FixtureTarget);

        assert_eq!(frontier.entries.len(), 2);
        assert_eq!(frontier.entries[0].operation_id, "pinned-child");
        assert_eq!(frontier.entries[0].path, "operations[0].regions[0][1]");
        assert_eq!(frontier.entries[1].operation_id, "opaque-child");
        assert_eq!(frontier.entries[1].path, "operations[0].regions[0][2]");
        assert!(matches!(
            frontier.entries[1].legality,
            Legality::Unknown { .. }
        ));
    }

    #[test]
    fn self_reported_attestation_is_untrusted_by_default() {
        let operation = operation_with([attested_claim("safe", attestation())]);

        let resolution = SemanticResolver::default().resolve(&operation, &contract());

        assert!(matches!(
            resolution,
            ClaimResolution::Untrusted {
                reason: EvidenceTrustFailure::ClaimNotAdmitted,
                ..
            }
        ));
    }

    #[test]
    fn exact_policy_admission_trusts_the_attested_claim() {
        let evidence = attestation();
        let operation = operation_with([attested_claim("safe", evidence.clone())]);
        let mut policy = EvidenceTrustPolicy::default();
        policy
            .admit_claim(&operation, &operation.claims[0])
            .expect("fixture admission is valid");

        let resolution =
            SemanticResolver::with_trust_policy(policy).resolve(&operation, &contract());

        assert!(matches!(resolution, ClaimResolution::Trusted(_)));
    }

    #[test]
    fn policy_refuses_to_admit_claims_without_verified_attestations() {
        let declared = Claim::new(
            contract(),
            json!({"value": "safe"}),
            Evidence::declared(source()),
        );
        let declared_operation = operation_with([declared]);
        let mut policy = EvidenceTrustPolicy::default();

        assert_eq!(
            policy.admit_claim(&declared_operation, &declared_operation.claims[0]),
            Err(EvidenceAdmissionFailure::StatusNotVerified)
        );

        let mut missing = attested_claim("safe", attestation());
        missing.evidence.conformance = None;
        let missing_operation = operation_with([missing]);
        assert_eq!(
            policy.admit_claim(&missing_operation, &missing_operation.claims[0]),
            Err(EvidenceAdmissionFailure::MissingAttestation)
        );
    }

    #[test]
    fn every_attestation_field_participates_in_exact_admission() {
        let admitted = attestation();
        let admitted_operation = operation_with([attested_claim("safe", admitted.clone())]);
        let mut policy = EvidenceTrustPolicy::default();
        policy
            .admit_claim(&admitted_operation, &admitted_operation.claims[0])
            .expect("fixture admission is valid");

        let mut variants = Vec::new();
        let mut changed = admitted.clone();
        changed.attester = "different-attester".to_owned();
        variants.push(changed);
        let mut changed = admitted.clone();
        changed.suite = "different-suite@1".to_owned();
        variants.push(changed);
        let mut changed = admitted.clone();
        changed.subject_digest = "sha256:different-subject".to_owned();
        variants.push(changed);
        let mut changed = admitted;
        changed.result_digest = "sha256:different-result".to_owned();
        variants.push(changed);

        for variant in variants {
            let operation = operation_with([attested_claim("safe", variant)]);
            let resolution = SemanticResolver::with_trust_policy(policy.clone())
                .resolve(&operation, &contract());

            assert!(matches!(
                resolution,
                ClaimResolution::Untrusted {
                    reason: EvidenceTrustFailure::ClaimNotAdmitted,
                    ..
                }
            ));
        }
    }

    #[test]
    fn admitted_evidence_copied_to_another_payload_is_untrusted() {
        let admitted_operation = operation_with([attested_claim("safe", attestation())]);
        let mut policy = EvidenceTrustPolicy::default();
        policy
            .admit_claim(&admitted_operation, &admitted_operation.claims[0])
            .expect("fixture admission is valid");
        let copied = operation_with([attested_claim("unsafe", attestation())]);

        let resolution = SemanticResolver::with_trust_policy(policy).resolve(&copied, &contract());

        assert!(matches!(
            resolution,
            ClaimResolution::Untrusted {
                reason: EvidenceTrustFailure::ClaimNotAdmitted,
                ..
            }
        ));
    }

    #[test]
    fn admitted_evidence_copied_to_another_operation_is_untrusted() {
        let admitted_operation = operation_with([attested_claim("safe", attestation())]);
        let mut policy = EvidenceTrustPolicy::default();
        policy
            .admit_claim(&admitted_operation, &admitted_operation.claims[0])
            .expect("fixture admission is valid");
        let mut copied = operation_with([attested_claim("safe", attestation())]);
        copied.id = "different-operation".to_owned();

        let resolution = SemanticResolver::with_trust_policy(policy).resolve(&copied, &contract());

        assert!(matches!(
            resolution,
            ClaimResolution::Untrusted {
                reason: EvidenceTrustFailure::ClaimNotAdmitted,
                ..
            }
        ));
    }

    #[test]
    fn admitted_evidence_copied_to_another_source_is_untrusted() {
        let admitted_operation = operation_with([attested_claim("safe", attestation())]);
        let mut policy = EvidenceTrustPolicy::default();
        policy
            .admit_claim(&admitted_operation, &admitted_operation.claims[0])
            .expect("fixture admission is valid");
        let mut copied_claim = attested_claim("safe", attestation());
        copied_claim.evidence.source.revision = "different-revision".to_owned();
        let copied = operation_with([copied_claim]);

        let resolution = SemanticResolver::with_trust_policy(policy).resolve(&copied, &contract());

        assert!(matches!(
            resolution,
            ClaimResolution::Untrusted {
                reason: EvidenceTrustFailure::ClaimNotAdmitted,
                ..
            }
        ));
    }

    #[test]
    fn admitted_evidence_with_changed_status_is_untrusted() {
        let admitted_operation = operation_with([attested_claim("safe", attestation())]);
        let mut policy = EvidenceTrustPolicy::default();
        policy
            .admit_claim(&admitted_operation, &admitted_operation.claims[0])
            .expect("fixture admission is valid");
        let mut copied_claim = admitted_operation.claims[0].clone();
        copied_claim.evidence.status = EvidenceStatus::Declared;
        let copied = operation_with([copied_claim]);

        let resolution = SemanticResolver::with_trust_policy(policy).resolve(&copied, &contract());

        assert!(matches!(
            resolution,
            ClaimResolution::Untrusted {
                reason: EvidenceTrustFailure::StatusNotVerified,
                ..
            }
        ));
    }

    #[test]
    fn admitted_evidence_copied_to_another_contract_needs_a_bridge() {
        let admitted_operation = operation_with([attested_claim("safe", attestation())]);
        let mut policy = EvidenceTrustPolicy::default();
        policy
            .admit_claim(&admitted_operation, &admitted_operation.claims[0])
            .expect("fixture admission is valid");
        let mut copied_claim = admitted_operation.claims[0].clone();
        copied_claim.contract = ContractId::new("org.gooi.test", "capability", "2.0.0");
        let copied = operation_with([copied_claim]);

        let resolution = SemanticResolver::with_trust_policy(policy).resolve(&copied, &contract());

        assert!(matches!(resolution, ClaimResolution::VersionMismatch(_)));
    }

    #[test]
    fn conflicting_claims_remain_ambiguous_even_when_both_are_admitted() {
        let first = ConformanceEvidence::new(
            "fixture-attester",
            "fixture-suite@1",
            "sha256:first-subject",
            "sha256:first-result",
        );
        let second = ConformanceEvidence::new(
            "fixture-attester",
            "fixture-suite@1",
            "sha256:second-subject",
            "sha256:second-result",
        );
        let operation = operation_with([
            attested_claim("safe", first.clone()),
            attested_claim("unsafe", second.clone()),
        ]);
        let mut policy = EvidenceTrustPolicy::default();
        policy
            .admit_claim(&operation, &operation.claims[0])
            .expect("first fixture admission is valid");
        policy
            .admit_claim(&operation, &operation.claims[1])
            .expect("second fixture admission is valid");

        let resolution =
            SemanticResolver::with_trust_policy(policy).resolve(&operation, &contract());

        assert!(matches!(resolution, ClaimResolution::Ambiguous(_)));
    }

    struct EvidenceMintingBridge {
        from: ContractId,
        to: ContractId,
        forged: ConformanceEvidence,
    }

    impl ClaimBridge for EvidenceMintingBridge {
        fn from(&self) -> ContractId {
            self.from.clone()
        }

        fn to(&self) -> ContractId {
            self.to.clone()
        }

        fn convert(&self, claim: &Claim) -> Result<Claim, String> {
            Ok(Claim::new(
                self.to(),
                claim.payload.clone(),
                Evidence::verified(claim.evidence.source.clone(), self.forged.clone()),
            ))
        }
    }

    struct PayloadMutatingBridge {
        from: ContractId,
        to: ContractId,
    }

    impl ClaimBridge for PayloadMutatingBridge {
        fn from(&self) -> ContractId {
            self.from.clone()
        }

        fn to(&self) -> ContractId {
            self.to.clone()
        }

        fn convert(&self, claim: &Claim) -> Result<Claim, String> {
            Ok(Claim::new(
                self.to(),
                json!({"value": "unsafe"}),
                claim.evidence.clone(),
            ))
        }
    }

    #[test]
    fn a_version_bridge_cannot_replace_evidence_to_mint_trust() {
        let from = ContractId::new("org.gooi.test", "capability", "2.0.0");
        let to = contract();
        let original = ConformanceEvidence::new(
            "untrusted-attester",
            "fixture-suite@2",
            "sha256:untrusted-subject",
            "sha256:untrusted-result",
        );
        let forged = attestation();
        let operation = operation_with([Claim::new(
            from.clone(),
            json!({"value": "safe"}),
            Evidence::verified(source(), original),
        )]);
        let mut bridges = BridgeRegistry::default();
        bridges.register(EvidenceMintingBridge {
            from,
            to: to.clone(),
            forged: forged.clone(),
        });
        let mut policy = EvidenceTrustPolicy::default();
        policy
            .admit_claim(&operation, &operation.claims[0])
            .expect("source fixture admission is valid");

        let resolution = SemanticResolver::with_bridges_and_trust_policy(bridges, policy)
            .resolve(&operation, &to);

        assert!(matches!(resolution, ClaimResolution::InvalidBridge(_)));
    }

    #[test]
    fn a_version_bridge_cannot_rewrite_payload_to_launder_trust() {
        let from = ContractId::new("org.gooi.test", "capability", "2.0.0");
        let to = contract();
        let operation = operation_with([Claim::new(
            from.clone(),
            json!({"value": "safe"}),
            Evidence::verified(source(), attestation()),
        )]);
        let mut bridges = BridgeRegistry::default();
        bridges.register(PayloadMutatingBridge {
            from,
            to: to.clone(),
        });
        let mut policy = EvidenceTrustPolicy::default();
        policy
            .admit_claim(&operation, &operation.claims[0])
            .expect("source fixture admission is valid");

        let resolution = SemanticResolver::with_bridges_and_trust_policy(bridges, policy)
            .resolve(&operation, &to);

        assert_eq!(
            resolution,
            ClaimResolution::InvalidBridge(
                "bridge changed claim payload instead of preserving it".to_owned()
            )
        );
    }
}
