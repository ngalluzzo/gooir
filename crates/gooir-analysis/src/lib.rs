use gooir_core::{
    Claim, ConformanceEvidence, ContractId, Evidence, EvidenceStatus, Operation, Program,
};
use std::collections::BTreeSet;

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

/// Contextual admission policy for conformance attestations.
///
/// The default policy denies all attestations. The host constructing a policy
/// is responsible for validating attestation authenticity, authority, and the
/// referenced result artifact before admission.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvidenceTrustPolicy {
    admitted: BTreeSet<ConformanceEvidence>,
}

impl EvidenceTrustPolicy {
    /// Admits one exact attestation after the host validates it.
    pub fn admit(&mut self, attestation: ConformanceEvidence) {
        self.admitted.insert(attestation);
    }

    /// Returns this policy with one exact attestation admitted.
    pub fn with_admitted(mut self, attestation: ConformanceEvidence) -> Self {
        self.admit(attestation);
        self
    }

    fn evaluate(&self, evidence: &Evidence) -> EvidenceTrustDecision {
        if evidence.status != EvidenceStatus::Verified {
            return EvidenceTrustDecision::Untrusted(EvidenceTrustFailure::StatusNotVerified);
        }

        let Some(attestation) = &evidence.conformance else {
            return EvidenceTrustDecision::Untrusted(EvidenceTrustFailure::MissingAttestation);
        };

        if self.admitted.contains(attestation) {
            EvidenceTrustDecision::Trusted
        } else {
            EvidenceTrustDecision::Untrusted(EvidenceTrustFailure::AttestationNotAdmitted)
        }
    }
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
    /// The host did not admit the exact conformance attestation.
    AttestationNotAdmitted,
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
            [claim] => return self.classify(claim.clone()),
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
                                && converted_claim.evidence == claim.evidence =>
                        {
                            converted.push(converted_claim);
                        }
                        Ok(converted_claim) if converted_claim.contract == *expected => {
                            return ClaimResolution::InvalidBridge(
                                "bridge changed claim evidence instead of preserving it".to_owned(),
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
            [claim] => self.classify(claim.clone()),
            claims if claims.len() > 1 => ClaimResolution::Ambiguous(
                claims.iter().map(|claim| claim.contract.clone()).collect(),
            ),
            _ if !related.is_empty() => ClaimResolution::VersionMismatch(
                related.iter().map(|claim| claim.contract.clone()).collect(),
            ),
            _ => ClaimResolution::Absent,
        }
    }

    fn classify(&self, claim: Claim) -> ClaimResolution {
        match self.trust_policy.evaluate(&claim.evidence) {
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
        BridgeRegistry, ClaimBridge, ClaimResolution, EvidenceTrustFailure, EvidenceTrustPolicy,
        Legality, LegalityOracle, SemanticResolver, portability_frontier,
    };
    use gooir_core::{
        Claim, ConformanceEvidence, ContractId, Evidence, Operation, Program, SourceRef,
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
                reason: EvidenceTrustFailure::AttestationNotAdmitted,
                ..
            }
        ));
    }

    #[test]
    fn exact_policy_admission_trusts_the_attested_claim() {
        let evidence = attestation();
        let operation = operation_with([attested_claim("safe", evidence.clone())]);
        let policy = EvidenceTrustPolicy::default().with_admitted(evidence);

        let resolution =
            SemanticResolver::with_trust_policy(policy).resolve(&operation, &contract());

        assert!(matches!(resolution, ClaimResolution::Trusted(_)));
    }

    #[test]
    fn every_attestation_field_participates_in_exact_admission() {
        let admitted = attestation();
        let policy = EvidenceTrustPolicy::default().with_admitted(admitted.clone());

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
                    reason: EvidenceTrustFailure::AttestationNotAdmitted,
                    ..
                }
            ));
        }
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
        let policy = EvidenceTrustPolicy::default()
            .with_admitted(first)
            .with_admitted(second);

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
        let policy = EvidenceTrustPolicy::default().with_admitted(forged);

        let resolution = SemanticResolver::with_bridges_and_trust_policy(bridges, policy)
            .resolve(&operation, &to);

        assert!(matches!(resolution, ClaimResolution::InvalidBridge(_)));
    }
}
