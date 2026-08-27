//! Contextual authority and admission for neutral capability results.
//!
//! The documents in this module never execute capabilities. They establish the
//! complete immutable chain by which one exact observed or produced fact
//! becomes linkable. A bare fact, result, candidate, or observation has no
//! lookup path in [`AdmissionLedger`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::protocol::{
    ArtifactDigest, AuthorityRecordId, CandidateId, CapabilityCandidate, CapabilityInvocation,
    CapabilityOutcome, CapabilityResult, ConformanceSuiteId, EvidenceKindId, EvidenceRef,
    ImplementationId, InvocationId, ProtocolError, ResultId,
};
use crate::{Fact, FactId, PortName, ValueKindId, canonical_digest};

pub const ASSESSMENT_PROTOCOL: &str = "org.gooi.authority.conformance-assessment/v1";
pub const SOURCE_OBSERVATION_PROTOCOL: &str = "org.gooi.authority.source-observation/v1";
pub const ADMISSION_POLICY_PROTOCOL: &str = "org.gooi.authority.admission-policy/v1";
pub const ADMISSION_DECISION_PROTOCOL: &str = "org.gooi.authority.admission-decision/v1";
pub const AUTHORITY_RECORD_PROTOCOL: &str = "org.gooi.authority.record/v1";
pub const ADMISSION_SNAPSHOT_PROTOCOL: &str = "org.gooi.authority.snapshot/v1";

macro_rules! sha256_wrapper {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, AuthorityError> {
                let value = value.into();
                if is_sha256(&value) {
                    Ok(Self(value))
                } else {
                    Err(AuthorityError::InvalidDigest(value))
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

sha256_wrapper! {
    /// Content identity of one independent conformance assessment.
    AssessmentId
}
sha256_wrapper! {
    /// Content identity of one exact external source observation.
    ObservationId
}
sha256_wrapper! {
    /// Content identity of one local admission policy.
    AdmissionPolicyId
}
sha256_wrapper! {
    /// Content identity of one deterministic local admission decision.
    AdmissionDecisionId
}
sha256_wrapper! {
    /// Content identity of an exported admission-ledger snapshot.
    AdmissionSnapshotId
}

gooir_identity::exact_identity! {
    /// Exact identity of the authority responsible for a local admission policy.
    AdmissionAuthorityId
}

gooir_identity::exact_identity! {
    /// Exact identity of an external source observed before semantic derivation.
    ObservationSourceId
}

/// One independently deployed conformance implementation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConformanceAttester {
    pub implementation: ImplementationId,
    pub artifact_digest: ArtifactDigest,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl ConformanceAttester {
    pub fn new(
        implementation: ImplementationId,
        artifact_digest: ArtifactDigest,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, AuthorityError> {
        let attester = Self {
            implementation,
            artifact_digest,
            extensions,
        };
        attester.validate()?;
        Ok(attester)
    }

    pub fn validate(&self) -> Result<(), AuthorityError> {
        validate_exact_id("conformance attester implementation", &self.implementation)?;
        validate_extensions(
            "conformance attester",
            &self.extensions,
            &["implementation", "artifact_digest"],
        )
    }
}

/// The exact suite and implementation whose results a policy may accept.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConformanceAuthority {
    pub suite: ConformanceSuiteId,
    pub attester: ConformanceAttester,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl ConformanceAuthority {
    pub fn new(
        suite: ConformanceSuiteId,
        attester: ConformanceAttester,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, AuthorityError> {
        let authority = Self {
            suite,
            attester,
            extensions,
        };
        authority.validate()?;
        Ok(authority)
    }

    pub fn validate(&self) -> Result<(), AuthorityError> {
        validate_exact_id("conformance suite", &self.suite)?;
        self.attester.validate()?;
        validate_extensions(
            "conformance authority",
            &self.extensions,
            &["suite", "attester"],
        )
    }
}

/// Exact source and ingestion mechanism behind one materialized observation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObservationAuthority {
    pub source: ObservationSourceId,
    pub observer: ImplementationId,
    pub observer_artifact: ArtifactDigest,
    pub value_kind: ValueKindId,
    pub evidence_kind: EvidenceKindId,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl ObservationAuthority {
    pub fn new(
        source: ObservationSourceId,
        observer: ImplementationId,
        observer_artifact: ArtifactDigest,
        value_kind: ValueKindId,
        evidence_kind: EvidenceKindId,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, AuthorityError> {
        let authority = Self {
            source,
            observer,
            observer_artifact,
            value_kind,
            evidence_kind,
            extensions,
        };
        authority.validate()?;
        Ok(authority)
    }

    pub fn validate(&self) -> Result<(), AuthorityError> {
        validate_exact_id("observation source", &self.source)?;
        validate_exact_id("observation implementation", &self.observer)?;
        validate_exact_id("observation value kind", &self.value_kind)?;
        validate_exact_id("observation evidence kind", &self.evidence_kind)?;
        validate_extensions(
            "observation authority",
            &self.extensions,
            &[
                "source",
                "observer",
                "observer_artifact",
                "value_kind",
                "evidence_kind",
            ],
        )
    }
}

/// Untrusted, content-identified claim that an exact fact was materialized from
/// an exact external source. This validates identity and evidence structure,
/// never the semantic meaning or truth of the fact payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SourceObservation {
    pub observation_id: ObservationId,
    pub protocol: String,
    pub fact: Fact,
    pub authority: ObservationAuthority,
    pub primary_evidence: EvidenceRef,
    pub additional_evidence: Vec<EvidenceRef>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl SourceObservation {
    pub fn new(
        fact: Fact,
        authority: ObservationAuthority,
        primary_evidence: EvidenceRef,
        additional_evidence: Vec<EvidenceRef>,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, AuthorityError> {
        let mut observation = Self {
            observation_id: placeholder::<ObservationId>(),
            protocol: SOURCE_OBSERVATION_PROTOCOL.to_owned(),
            fact,
            authority,
            primary_evidence,
            additional_evidence,
            extensions,
        };
        observation.validate_structure()?;
        observation.observation_id =
            ObservationId::parse(document_digest(&observation, "observation_id")?)?;
        Ok(observation)
    }

    pub fn validate(&self) -> Result<(), AuthorityError> {
        self.validate_structure()?;
        validate_content_id(
            "source observation",
            self.observation_id.as_str(),
            &document_digest(self, "observation_id")?,
        )
    }

    fn validate_structure(&self) -> Result<(), AuthorityError> {
        validate_protocol(SOURCE_OBSERVATION_PROTOCOL, &self.protocol)?;
        self.fact
            .validate()
            .map_err(|error| AuthorityError::InvalidDocument {
                document: "source observation fact",
                detail: error.to_string(),
            })?;
        self.authority.validate()?;
        if self.authority.value_kind != self.fact.value_kind {
            return Err(AuthorityError::ObservationValueKindMismatch);
        }
        self.primary_evidence.validate()?;
        if self.authority.evidence_kind != self.primary_evidence.kind {
            return Err(AuthorityError::ObservationEvidenceKindMismatch);
        }
        for evidence in &self.additional_evidence {
            evidence.validate()?;
        }
        validate_extensions(
            "source observation",
            &self.extensions,
            &[
                "observation_id",
                "protocol",
                "fact",
                "authority",
                "primary_evidence",
                "additional_evidence",
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentOutcome {
    Passed,
    Failed,
    Indeterminate,
}

/// One exact check performed by the independent conformance authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConformanceCheck {
    pub outcome: AssessmentOutcome,
    pub evidence: Vec<EvidenceRef>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl ConformanceCheck {
    pub fn new(
        outcome: AssessmentOutcome,
        evidence: Vec<EvidenceRef>,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, AuthorityError> {
        let check = Self {
            outcome,
            evidence,
            extensions,
        };
        check.validate()?;
        Ok(check)
    }

    pub fn validate(&self) -> Result<(), AuthorityError> {
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        validate_extensions(
            "conformance check",
            &self.extensions,
            &["outcome", "evidence"],
        )
    }
}

/// Content-identified, independently produced validation of one exact candidate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConformanceAssessment {
    pub assessment_id: AssessmentId,
    pub protocol: String,
    pub invocation_id: InvocationId,
    pub result_id: ResultId,
    pub candidate_id: CandidateId,
    pub authority: ConformanceAuthority,
    pub outcome: AssessmentOutcome,
    pub checks: BTreeMap<String, ConformanceCheck>,
    pub evidence: Vec<EvidenceRef>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl ConformanceAssessment {
    pub fn new(
        invocation: &CapabilityInvocation,
        result: &CapabilityResult,
        candidate: &CapabilityCandidate,
        authority: ConformanceAuthority,
        checks: BTreeMap<String, ConformanceCheck>,
        evidence: Vec<EvidenceRef>,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, AuthorityError> {
        let outcome = derive_assessment_outcome(&checks)?;
        let mut assessment = Self {
            assessment_id: placeholder::<AssessmentId>(),
            protocol: ASSESSMENT_PROTOCOL.to_owned(),
            invocation_id: invocation.invocation_id.clone(),
            result_id: result.result_id.clone(),
            candidate_id: candidate.candidate_id.clone(),
            authority,
            outcome,
            checks,
            evidence,
            extensions,
        };
        assessment.validate_structure_against(invocation, result, candidate)?;
        assessment.assessment_id =
            AssessmentId::parse(document_digest(&assessment, "assessment_id")?)?;
        Ok(assessment)
    }

    pub fn validate_against(
        &self,
        invocation: &CapabilityInvocation,
        result: &CapabilityResult,
        candidate: &CapabilityCandidate,
    ) -> Result<(), AuthorityError> {
        self.validate_structure_against(invocation, result, candidate)?;
        validate_content_id(
            "conformance assessment",
            self.assessment_id.as_str(),
            &document_digest(self, "assessment_id")?,
        )
    }

    fn validate_structure_against(
        &self,
        invocation: &CapabilityInvocation,
        result: &CapabilityResult,
        candidate: &CapabilityCandidate,
    ) -> Result<(), AuthorityError> {
        validate_protocol(ASSESSMENT_PROTOCOL, &self.protocol)?;
        invocation.validate()?;
        result.validate_against(invocation)?;
        candidate.validate_against(invocation)?;
        if candidate.result != *result {
            return Err(AuthorityError::ResultCandidateMismatch);
        }
        if self.invocation_id != invocation.invocation_id
            || self.result_id != result.result_id
            || self.candidate_id != candidate.candidate_id
        {
            return Err(AuthorityError::AssessmentCorrelationMismatch);
        }
        self.authority.validate()?;
        if self.authority.suite != invocation.conformance_suite {
            return Err(AuthorityError::ConformanceSuiteMismatch);
        }
        let selected = &invocation.selection.offer;
        if self.authority.attester.implementation == selected.implementation
            || self.authority.attester.artifact_digest == selected.artifact_digest
        {
            return Err(AuthorityError::AttesterNotIndependent);
        }
        let expected = derive_assessment_outcome(&self.checks)?;
        if self.outcome != expected {
            return Err(AuthorityError::AssessmentOutcomeMismatch);
        }
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        validate_extensions(
            "conformance assessment",
            &self.extensions,
            &[
                "assessment_id",
                "protocol",
                "invocation_id",
                "result_id",
                "candidate_id",
                "authority",
                "outcome",
                "checks",
                "evidence",
            ],
        )
    }
}

/// A content-identified local allow-list of exact observation and conformance
/// authorities.
///
/// An empty list is the default-deny policy. No authority is inferred from a
/// suite name, an implementation name, or candidate-supplied evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AdmissionPolicy {
    pub policy_id: AdmissionPolicyId,
    pub protocol: String,
    pub decision_authority: AdmissionAuthorityId,
    pub accepted_conformance: Vec<ConformanceAuthority>,
    pub accepted_observations: Vec<ObservationAuthority>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl AdmissionPolicy {
    pub fn deny_all(
        decision_authority: AdmissionAuthorityId,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, AuthorityError> {
        Self::new(decision_authority, Vec::new(), Vec::new(), extensions)
    }

    pub fn new(
        decision_authority: AdmissionAuthorityId,
        accepted_conformance: Vec<ConformanceAuthority>,
        accepted_observations: Vec<ObservationAuthority>,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, AuthorityError> {
        let mut policy = Self {
            policy_id: placeholder::<AdmissionPolicyId>(),
            protocol: ADMISSION_POLICY_PROTOCOL.to_owned(),
            decision_authority,
            accepted_conformance,
            accepted_observations,
            extensions,
        };
        policy.validate_structure()?;
        policy.policy_id = AdmissionPolicyId::parse(document_digest(&policy, "policy_id")?)?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), AuthorityError> {
        self.validate_structure()?;
        validate_content_id(
            "admission policy",
            self.policy_id.as_str(),
            &document_digest(self, "policy_id")?,
        )
    }

    fn accepts_conformance(&self, authority: &ConformanceAuthority) -> bool {
        self.accepted_conformance
            .iter()
            .any(|accepted| accepted == authority)
    }

    fn accepts_observation(&self, authority: &ObservationAuthority) -> bool {
        self.accepted_observations
            .iter()
            .any(|accepted| accepted == authority)
    }

    fn validate_structure(&self) -> Result<(), AuthorityError> {
        validate_protocol(ADMISSION_POLICY_PROTOCOL, &self.protocol)?;
        validate_exact_id("admission decision authority", &self.decision_authority)?;
        let mut seen = BTreeSet::new();
        for authority in &self.accepted_conformance {
            authority.validate()?;
            let bytes = canonical_bytes(authority)?;
            if !seen.insert(bytes) {
                return Err(AuthorityError::DuplicateAcceptedAuthority);
            }
        }
        seen.clear();
        for authority in &self.accepted_observations {
            authority.validate()?;
            let bytes = canonical_bytes(authority)?;
            if !seen.insert(bytes) {
                return Err(AuthorityError::DuplicateAcceptedAuthority);
            }
        }
        validate_extensions(
            "admission policy",
            &self.extensions,
            &[
                "policy_id",
                "protocol",
                "decision_authority",
                "accepted_conformance",
                "accepted_observations",
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDenial {
    AssessmentFailed,
    AssessmentIndeterminate,
    AuthorityNotAccepted,
}

/// The deterministic local verdict over an exact policy and assessment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum AdmissionVerdict {
    Admit {
        #[serde(default, flatten)]
        extensions: BTreeMap<String, Value>,
    },
    Withhold {
        reason: AdmissionDenial,
        #[serde(default, flatten)]
        extensions: BTreeMap<String, Value>,
    },
}

impl AdmissionVerdict {
    fn validate(&self) -> Result<(), AuthorityError> {
        match self {
            Self::Admit { extensions } => {
                validate_extensions("admit verdict", extensions, &["verdict", "reason"])
            }
            Self::Withhold { extensions, .. } => {
                validate_extensions("withhold verdict", extensions, &["verdict", "reason"])
            }
        }
    }

    fn is_admit(&self) -> bool {
        matches!(self, Self::Admit { .. })
    }
}

/// One output named by the local decision, in exact candidate order.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecisionOutput {
    pub port: PortName,
    pub fact_id: FactId,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl DecisionOutput {
    fn validate(&self) -> Result<(), AuthorityError> {
        FactId::parse(self.fact_id.to_string()).map_err(|error| {
            AuthorityError::InvalidDocument {
                document: "admission decision output",
                detail: error.to_string(),
            }
        })?;
        validate_extensions(
            "admission decision output",
            &self.extensions,
            &["port", "fact_id"],
        )
    }
}

/// The exact subject of one local admission decision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "subject", rename_all = "snake_case")]
pub enum AdmissionSubject {
    Observation {
        observation_id: ObservationId,
        fact_id: FactId,
        #[serde(default, flatten)]
        extensions: BTreeMap<String, Value>,
    },
    Candidate {
        assessment_id: AssessmentId,
        candidate_id: CandidateId,
        outputs: Vec<DecisionOutput>,
        #[serde(default, flatten)]
        extensions: BTreeMap<String, Value>,
    },
}

impl AdmissionSubject {
    fn validate(&self) -> Result<(), AuthorityError> {
        match self {
            Self::Observation {
                fact_id,
                extensions,
                ..
            } => {
                FactId::parse(fact_id.to_string()).map_err(|error| {
                    AuthorityError::InvalidDocument {
                        document: "observation admission subject",
                        detail: error.to_string(),
                    }
                })?;
                validate_extensions(
                    "observation admission subject",
                    extensions,
                    &["subject", "observation_id", "fact_id"],
                )
            }
            Self::Candidate {
                outputs,
                extensions,
                ..
            } => {
                for output in outputs {
                    output.validate()?;
                }
                validate_extensions(
                    "candidate admission subject",
                    extensions,
                    &["subject", "assessment_id", "candidate_id", "outputs"],
                )
            }
        }
    }
}

/// Content-identified result of applying one exact local policy to an observed
/// source or a derived candidate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AdmissionDecision {
    pub decision_id: AdmissionDecisionId,
    pub protocol: String,
    pub policy_id: AdmissionPolicyId,
    pub subject: AdmissionSubject,
    pub verdict: AdmissionVerdict,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl AdmissionDecision {
    pub fn validate_candidate(
        &self,
        policy: &AdmissionPolicy,
        invocation: &CapabilityInvocation,
        result: &CapabilityResult,
        candidate: &CapabilityCandidate,
        assessment: &ConformanceAssessment,
    ) -> Result<(), AuthorityError> {
        invocation.validate()?;
        result.validate_against(invocation)?;
        candidate.validate_against(invocation)?;
        if candidate.result != *result {
            return Err(AuthorityError::ResultCandidateMismatch);
        }
        assessment.validate_against(invocation, result, candidate)?;
        self.validate_candidate_structure(policy, assessment, candidate)?;
        validate_content_id(
            "admission decision",
            self.decision_id.as_str(),
            &document_digest(self, "decision_id")?,
        )
    }

    pub fn validate_observation(
        &self,
        policy: &AdmissionPolicy,
        observation: &SourceObservation,
    ) -> Result<(), AuthorityError> {
        self.validate_observation_structure(policy, observation)?;
        validate_content_id(
            "admission decision",
            self.decision_id.as_str(),
            &document_digest(self, "decision_id")?,
        )
    }

    fn derive_candidate(
        policy: &AdmissionPolicy,
        assessment: &ConformanceAssessment,
        candidate: &CapabilityCandidate,
    ) -> Result<Self, AuthorityError> {
        let subject = candidate_subject(assessment, candidate)?;
        let verdict = expected_candidate_verdict(policy, assessment);
        let mut decision = Self {
            decision_id: placeholder::<AdmissionDecisionId>(),
            protocol: ADMISSION_DECISION_PROTOCOL.to_owned(),
            policy_id: policy.policy_id.clone(),
            subject,
            verdict,
            extensions: BTreeMap::new(),
        };
        decision.validate_candidate_structure(policy, assessment, candidate)?;
        decision.decision_id =
            AdmissionDecisionId::parse(document_digest(&decision, "decision_id")?)?;
        Ok(decision)
    }

    fn derive_observation(
        policy: &AdmissionPolicy,
        observation: &SourceObservation,
    ) -> Result<Self, AuthorityError> {
        let subject = AdmissionSubject::Observation {
            observation_id: observation.observation_id.clone(),
            fact_id: observation.fact.id.clone(),
            extensions: BTreeMap::new(),
        };
        let verdict = expected_observation_verdict(policy, observation);
        let mut decision = Self {
            decision_id: placeholder::<AdmissionDecisionId>(),
            protocol: ADMISSION_DECISION_PROTOCOL.to_owned(),
            policy_id: policy.policy_id.clone(),
            subject,
            verdict,
            extensions: BTreeMap::new(),
        };
        decision.validate_observation_structure(policy, observation)?;
        decision.decision_id =
            AdmissionDecisionId::parse(document_digest(&decision, "decision_id")?)?;
        Ok(decision)
    }

    fn validate_candidate_structure(
        &self,
        policy: &AdmissionPolicy,
        assessment: &ConformanceAssessment,
        candidate: &CapabilityCandidate,
    ) -> Result<(), AuthorityError> {
        validate_protocol(ADMISSION_DECISION_PROTOCOL, &self.protocol)?;
        policy.validate()?;
        if self.policy_id != policy.policy_id {
            return Err(AuthorityError::DecisionCorrelationMismatch);
        }
        if !candidate_subject_matches(&self.subject, assessment, candidate)? {
            return Err(AuthorityError::DecisionOutputMismatch);
        }
        self.subject.validate()?;
        self.verdict.validate()?;
        if !same_verdict_kind(
            &self.verdict,
            &expected_candidate_verdict(policy, assessment),
        ) {
            return Err(AuthorityError::DecisionVerdictMismatch);
        }
        self.validate_envelope()
    }

    fn validate_observation_structure(
        &self,
        policy: &AdmissionPolicy,
        observation: &SourceObservation,
    ) -> Result<(), AuthorityError> {
        validate_protocol(ADMISSION_DECISION_PROTOCOL, &self.protocol)?;
        policy.validate()?;
        observation.validate()?;
        if self.policy_id != policy.policy_id
            || !observation_subject_matches(&self.subject, observation)
        {
            return Err(AuthorityError::DecisionCorrelationMismatch);
        }
        self.subject.validate()?;
        self.verdict.validate()?;
        if !same_verdict_kind(
            &self.verdict,
            &expected_observation_verdict(policy, observation),
        ) {
            return Err(AuthorityError::DecisionVerdictMismatch);
        }
        self.validate_envelope()
    }

    fn validate_envelope(&self) -> Result<(), AuthorityError> {
        validate_extensions(
            "admission decision",
            &self.extensions,
            &["decision_id", "protocol", "policy_id", "subject", "verdict"],
        )
    }
}

/// The complete immutable authority chain for one exact fact. Source and
/// derived chains are disjoint and explicit from the first version.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorityRecord {
    pub authority_record_id: AuthorityRecordId,
    pub protocol: String,
    pub fact: Fact,
    pub basis: AuthorityBasis,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// The disjoint basis by which the enclosing fact received authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthorityBasis {
    Source {
        observation: Box<SourceObservation>,
        policy: Box<AdmissionPolicy>,
        decision: Box<AdmissionDecision>,
        #[serde(default, flatten)]
        extensions: BTreeMap<String, Value>,
    },
    Derived {
        output_port: PortName,
        invocation: Box<CapabilityInvocation>,
        result: Box<CapabilityResult>,
        candidate: Box<CapabilityCandidate>,
        assessment: Box<ConformanceAssessment>,
        policy: Box<AdmissionPolicy>,
        decision: Box<AdmissionDecision>,
        #[serde(default, flatten)]
        extensions: BTreeMap<String, Value>,
    },
}

impl AuthorityRecord {
    fn authority_record_id(&self) -> &AuthorityRecordId {
        &self.authority_record_id
    }

    fn fact(&self) -> &Fact {
        &self.fact
    }

    fn decision(&self) -> &AdmissionDecision {
        match &self.basis {
            AuthorityBasis::Source { decision, .. } | AuthorityBasis::Derived { decision, .. } => {
                decision.as_ref()
            }
        }
    }

    fn invocation(&self) -> Option<&CapabilityInvocation> {
        match &self.basis {
            AuthorityBasis::Source { .. } => None,
            AuthorityBasis::Derived { invocation, .. } => Some(invocation.as_ref()),
        }
    }

    pub fn validate(&self) -> Result<(), AuthorityError> {
        self.validate_structure()?;
        validate_content_id(
            "authority record",
            self.authority_record_id().as_str(),
            &document_digest(self, "authority_record_id")?,
        )
    }

    fn new_source(
        observation: SourceObservation,
        policy: AdmissionPolicy,
        decision: AdmissionDecision,
    ) -> Result<Self, AuthorityError> {
        let mut record = Self {
            authority_record_id: placeholder_authority_record_id(),
            protocol: AUTHORITY_RECORD_PROTOCOL.to_owned(),
            fact: observation.fact.clone(),
            basis: AuthorityBasis::Source {
                observation: Box::new(observation),
                policy: Box::new(policy),
                decision: Box::new(decision),
                extensions: BTreeMap::new(),
            },
            extensions: BTreeMap::new(),
        };
        record.validate_structure()?;
        record.authority_record_id =
            AuthorityRecordId::parse(document_digest(&record, "authority_record_id")?)
                .map_err(|error| AuthorityError::InvalidDigest(error.0))?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    fn new_derived(
        output_port: PortName,
        fact: Fact,
        invocation: CapabilityInvocation,
        result: CapabilityResult,
        candidate: CapabilityCandidate,
        assessment: ConformanceAssessment,
        policy: AdmissionPolicy,
        decision: AdmissionDecision,
    ) -> Result<Self, AuthorityError> {
        let mut record = Self {
            authority_record_id: placeholder_authority_record_id(),
            protocol: AUTHORITY_RECORD_PROTOCOL.to_owned(),
            fact,
            basis: AuthorityBasis::Derived {
                output_port,
                invocation: Box::new(invocation),
                result: Box::new(result),
                candidate: Box::new(candidate),
                assessment: Box::new(assessment),
                policy: Box::new(policy),
                decision: Box::new(decision),
                extensions: BTreeMap::new(),
            },
            extensions: BTreeMap::new(),
        };
        record.validate_structure()?;
        record.authority_record_id =
            AuthorityRecordId::parse(document_digest(&record, "authority_record_id")?)
                .map_err(|error| AuthorityError::InvalidDigest(error.0))?;
        Ok(record)
    }

    fn validate_structure(&self) -> Result<(), AuthorityError> {
        validate_protocol(AUTHORITY_RECORD_PROTOCOL, &self.protocol)?;
        self.fact
            .validate()
            .map_err(|error| AuthorityError::InvalidDocument {
                document: "authority record fact",
                detail: error.to_string(),
            })?;
        validate_extensions(
            "authority record",
            &self.extensions,
            &["authority_record_id", "protocol", "fact", "basis"],
        )?;
        match &self.basis {
            AuthorityBasis::Source {
                observation,
                policy,
                decision,
                extensions,
            } => {
                observation.validate()?;
                if self.fact != observation.fact {
                    return Err(AuthorityError::AuthorityOutputMismatch);
                }
                policy.validate()?;
                decision.validate_observation(policy, observation)?;
                if !decision.verdict.is_admit() {
                    return Err(AuthorityError::WithheldRecord);
                }
                validate_extensions(
                    "source authority basis",
                    extensions,
                    &["kind", "observation", "policy", "decision"],
                )
            }
            AuthorityBasis::Derived {
                output_port,
                invocation,
                result,
                candidate,
                assessment,
                policy,
                decision,
                extensions,
            } => {
                invocation.validate()?;
                result.validate_against(invocation)?;
                candidate.validate_against(invocation)?;
                if candidate.result != **result {
                    return Err(AuthorityError::ResultCandidateMismatch);
                }
                assessment.validate_against(invocation, result, candidate)?;
                policy.validate()?;
                decision.validate_candidate(policy, invocation, result, candidate, assessment)?;
                if !decision.verdict.is_admit() {
                    return Err(AuthorityError::WithheldRecord);
                }
                let matching = candidate_outputs(candidate)?
                    .iter()
                    .filter(|output| output.port == *output_port && output.fact == self.fact)
                    .count();
                if matching != 1 {
                    return Err(AuthorityError::AuthorityOutputMismatch);
                }
                validate_extensions(
                    "derived authority basis",
                    extensions,
                    &[
                        "kind",
                        "output_port",
                        "invocation",
                        "result",
                        "candidate",
                        "assessment",
                        "policy",
                        "decision",
                    ],
                )
            }
        }
    }
}

/// A fact and the exact authority record selected by its reference.
#[derive(Clone, Copy, Debug)]
pub struct ResolvedFact<'a> {
    pub fact: &'a Fact,
    pub authority: &'a AuthorityRecord,
}

/// One explicit link created by an atomic admission. Derived links retain their
/// output port; source links have no capability output port.
#[derive(Clone, Debug, PartialEq)]
pub struct AdmittedLink {
    pub port: Option<PortName>,
    pub reference: crate::protocol::AdmittedFactRef,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AdmissionOutcome {
    Admitted {
        decision: AdmissionDecision,
        links: Vec<AdmittedLink>,
    },
    Withheld {
        decision: AdmissionDecision,
    },
}

/// Serializable contextual state. Storage and transport of snapshots are
/// deliberately outside this module.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AdmissionLedger {
    facts: BTreeMap<FactId, Fact>,
    decisions: BTreeMap<AdmissionDecisionId, AdmissionDecision>,
    authorities: BTreeMap<AuthorityRecordId, AuthorityRecord>,
    authorities_by_fact: BTreeMap<FactId, BTreeSet<AuthorityRecordId>>,
}

impl AdmissionLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve only an explicit fact-and-authority pair. There is intentionally
    /// no lookup accepting a bare [`FactId`].
    pub fn resolve(
        &self,
        reference: &crate::protocol::AdmittedFactRef,
    ) -> Result<ResolvedFact<'_>, AuthorityError> {
        reference.validate()?;
        let authority = self
            .authorities
            .get(&reference.authority_record_id)
            .ok_or_else(|| {
                AuthorityError::UnknownAuthority(reference.authority_record_id.clone())
            })?;
        if authority.fact().id != reference.fact_id {
            return Err(AuthorityError::FactReferenceMismatch);
        }
        let fact = self
            .facts
            .get(&reference.fact_id)
            .ok_or_else(|| AuthorityError::MissingFact(reference.fact_id.clone()))?;
        if fact != authority.fact() {
            return Err(AuthorityError::StoredFactMismatch(
                reference.fact_id.clone(),
            ));
        }
        Ok(ResolvedFact { fact, authority })
    }

    /// Return every authority for a fact. Callers must choose one explicitly.
    pub fn authorities_for(&self, fact_id: &FactId) -> Vec<&AuthorityRecord> {
        self.authorities_by_fact
            .get(fact_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.authorities.get(id))
            .collect()
    }

    #[cfg(test)]
    fn fact_count(&self) -> usize {
        self.facts.len()
    }

    #[cfg(test)]
    fn decision_count(&self) -> usize {
        self.decisions.len()
    }

    #[cfg(test)]
    fn authority_count(&self) -> usize {
        self.authorities.len()
    }

    /// Validate and atomically admit one exact materialized source observation.
    pub fn admit_observation(
        &mut self,
        policy: &AdmissionPolicy,
        observation: &SourceObservation,
    ) -> Result<AdmissionOutcome, AuthorityError> {
        policy.validate()?;
        observation.validate()?;
        let decision = AdmissionDecision::derive_observation(policy, observation)?;
        decision.validate_observation(policy, observation)?;
        if !decision.verdict.is_admit() {
            return Ok(AdmissionOutcome::Withheld { decision });
        }
        let record =
            AuthorityRecord::new_source(observation.clone(), policy.clone(), decision.clone())?;
        let link = AdmittedLink {
            port: None,
            reference: crate::protocol::AdmittedFactRef {
                fact_id: observation.fact.id.clone(),
                authority_record_id: record.authority_record_id().clone(),
                extensions: BTreeMap::new(),
            },
        };
        self.commit_admission(decision, vec![record], vec![link])
    }

    /// Validate and atomically admit every output of one exact candidate.
    #[allow(clippy::too_many_lines)]
    pub fn admit_candidate(
        &mut self,
        policy: &AdmissionPolicy,
        invocation: &CapabilityInvocation,
        result: &CapabilityResult,
        candidate: &CapabilityCandidate,
        assessment: &ConformanceAssessment,
    ) -> Result<AdmissionOutcome, AuthorityError> {
        policy.validate()?;
        invocation.validate()?;
        result.validate_against(invocation)?;
        candidate.validate_against(invocation)?;
        if candidate.result != *result {
            return Err(AuthorityError::ResultCandidateMismatch);
        }
        assessment.validate_against(invocation, result, candidate)?;

        for input in &invocation.inputs {
            let resolved = self.resolve(&input.admitted)?;
            if resolved.fact != &input.fact {
                return Err(AuthorityError::LinkedInputMismatch(input.port.clone()));
            }
        }

        let decision = AdmissionDecision::derive_candidate(policy, assessment, candidate)?;
        decision.validate_candidate(policy, invocation, result, candidate, assessment)?;
        if !decision.verdict.is_admit() {
            return Ok(AdmissionOutcome::Withheld { decision });
        }

        let outputs = candidate_outputs(candidate)?;
        let mut records = Vec::with_capacity(outputs.len());
        let mut links = Vec::with_capacity(outputs.len());

        for output in outputs {
            output
                .fact
                .validate()
                .map_err(|error| AuthorityError::InvalidDocument {
                    document: "candidate output fact",
                    detail: error.to_string(),
                })?;
            let record = AuthorityRecord::new_derived(
                output.port.clone(),
                output.fact.clone(),
                invocation.clone(),
                result.clone(),
                candidate.clone(),
                assessment.clone(),
                policy.clone(),
                decision.clone(),
            )?;
            links.push(AdmittedLink {
                port: Some(output.port.clone()),
                reference: crate::protocol::AdmittedFactRef {
                    fact_id: output.fact.id.clone(),
                    authority_record_id: record.authority_record_id().clone(),
                    extensions: BTreeMap::new(),
                },
            });
            records.push(record);
        }

        self.commit_admission(decision, records, links)
    }

    fn commit_admission(
        &mut self,
        decision: AdmissionDecision,
        records: Vec<AuthorityRecord>,
        links: Vec<AdmittedLink>,
    ) -> Result<AdmissionOutcome, AuthorityError> {
        if records.len() != links.len() {
            return Err(AuthorityError::StagedAdmissionMismatch);
        }
        for (record, link) in records.iter().zip(&links) {
            link.reference.validate()?;
            if record.decision() != &decision
                || link.reference.fact_id != record.fact().id
                || link.reference.authority_record_id != *record.authority_record_id()
            {
                return Err(AuthorityError::StagedAdmissionMismatch);
            }
            let expected_port = match &record.basis {
                AuthorityBasis::Source { .. } => None,
                AuthorityBasis::Derived { output_port, .. } => Some(output_port),
            };
            if link.port.as_ref() != expected_port {
                return Err(AuthorityError::StagedAdmissionMismatch);
            }
        }
        let mut staged_facts = BTreeMap::<FactId, Fact>::new();
        let mut staged_authorities = BTreeMap::<AuthorityRecordId, AuthorityRecord>::new();
        for record in records {
            record.validate()?;
            let fact = record.fact();
            if let Some(existing) = self.facts.get(&fact.id)
                && existing != fact
            {
                return Err(AuthorityError::FactCollision(fact.id.clone()));
            }
            if let Some(existing) = staged_facts.get(&fact.id) {
                if existing != fact {
                    return Err(AuthorityError::FactCollision(fact.id.clone()));
                }
            } else {
                staged_facts.insert(fact.id.clone(), fact.clone());
            }
            let id = record.authority_record_id().clone();
            if let Some(existing) = self.authorities.get(&id)
                && existing != &record
            {
                return Err(AuthorityError::AuthorityCollision(id));
            }
            if let Some(existing) = staged_authorities.get(&id) {
                if existing != &record {
                    return Err(AuthorityError::AuthorityCollision(id));
                }
            } else {
                staged_authorities.insert(id, record);
            }
        }
        if let Some(existing) = self.decisions.get(&decision.decision_id)
            && existing != &decision
        {
            return Err(AuthorityError::DecisionCollision(
                decision.decision_id.clone(),
            ));
        }

        // Every fallible operation is complete. The remaining inserts are the
        // single atomic state transition to linkable facts.
        for (id, fact) in staged_facts {
            self.facts.entry(id).or_insert(fact);
        }
        self.decisions
            .entry(decision.decision_id.clone())
            .or_insert_with(|| decision.clone());
        for (id, record) in staged_authorities {
            self.authorities_by_fact
                .entry(record.fact().id.clone())
                .or_default()
                .insert(id.clone());
            self.authorities.entry(id).or_insert(record);
        }

        Ok(AdmissionOutcome::Admitted { decision, links })
    }

    pub fn export(&self) -> Result<AdmissionSnapshot, AuthorityError> {
        self.export_with_extensions(BTreeMap::new())
    }

    pub fn export_with_extensions(
        &self,
        extensions: BTreeMap<String, Value>,
    ) -> Result<AdmissionSnapshot, AuthorityError> {
        let mut snapshot = AdmissionSnapshot {
            snapshot_id: placeholder::<AdmissionSnapshotId>(),
            protocol: ADMISSION_SNAPSHOT_PROTOCOL.to_owned(),
            facts: self.facts.values().cloned().collect(),
            decisions: self.decisions.values().cloned().collect(),
            authority_records: self.authorities.values().cloned().collect(),
            extensions,
        };
        snapshot.validate_structure()?;
        snapshot.snapshot_id =
            AdmissionSnapshotId::parse(document_digest(&snapshot, "snapshot_id")?)?;
        Ok(snapshot)
    }

    /// Rebuild contextual linkability from an exact, self-validating snapshot.
    ///
    /// This proves content identity and ledger closure, not the snapshot's
    /// origin. Selecting and authenticating snapshot bytes remains the external
    /// host's responsibility.
    pub fn rebuild(snapshot: &AdmissionSnapshot) -> Result<Self, AuthorityError> {
        snapshot.validate()?;
        let mut ledger = Self::new();

        for fact in &snapshot.facts {
            if ledger.facts.insert(fact.id.clone(), fact.clone()).is_some() {
                return Err(AuthorityError::FactCollision(fact.id.clone()));
            }
        }
        for decision in &snapshot.decisions {
            if ledger
                .decisions
                .insert(decision.decision_id.clone(), decision.clone())
                .is_some()
            {
                return Err(AuthorityError::DecisionCollision(
                    decision.decision_id.clone(),
                ));
            }
        }
        for record in &snapshot.authority_records {
            let record_id = record.authority_record_id().clone();
            if ledger
                .authorities
                .insert(record_id.clone(), record.clone())
                .is_some()
            {
                return Err(AuthorityError::AuthorityCollision(record_id));
            }
            ledger
                .authorities_by_fact
                .entry(record.fact().id.clone())
                .or_default()
                .insert(record.authority_record_id().clone());
        }

        ledger.validate_rebuilt_state()?;
        Ok(ledger)
    }

    fn validate_rebuilt_state(&self) -> Result<(), AuthorityError> {
        for (id, fact) in &self.facts {
            fact.validate()
                .map_err(|error| AuthorityError::InvalidDocument {
                    document: "snapshot fact",
                    detail: error.to_string(),
                })?;
            let records = self.authorities_by_fact.get(id);
            if records.is_none_or(BTreeSet::is_empty) {
                return Err(AuthorityError::OrphanFact(id.clone()));
            }
        }

        let mut referenced_decisions = BTreeSet::new();
        for record in self.authorities.values() {
            record.validate()?;
            let fact = self
                .facts
                .get(&record.fact().id)
                .ok_or_else(|| AuthorityError::MissingFact(record.fact().id.clone()))?;
            if fact != record.fact() {
                return Err(AuthorityError::StoredFactMismatch(record.fact().id.clone()));
            }
            let decision = self
                .decisions
                .get(&record.decision().decision_id)
                .ok_or_else(|| {
                    AuthorityError::MissingDecision(record.decision().decision_id.clone())
                })?;
            if decision != record.decision() {
                return Err(AuthorityError::StoredDecisionMismatch(
                    record.decision().decision_id.clone(),
                ));
            }
            referenced_decisions.insert(record.decision().decision_id.clone());
        }
        for decision_id in self.decisions.keys() {
            if !referenced_decisions.contains(decision_id) {
                return Err(AuthorityError::OrphanDecision(decision_id.clone()));
            }
        }
        for record in self.authorities.values() {
            if let Some(invocation) = record.invocation() {
                for input in &invocation.inputs {
                    let resolved = self.resolve(&input.admitted)?;
                    if resolved.fact != &input.fact {
                        return Err(AuthorityError::LinkedInputMismatch(input.port.clone()));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Deterministic, content-identified export of admission-ledger state.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AdmissionSnapshot {
    pub snapshot_id: AdmissionSnapshotId,
    pub protocol: String,
    pub facts: Vec<Fact>,
    pub decisions: Vec<AdmissionDecision>,
    pub authority_records: Vec<AuthorityRecord>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl AdmissionSnapshot {
    pub fn validate(&self) -> Result<(), AuthorityError> {
        self.validate_structure()?;
        validate_content_id(
            "admission snapshot",
            self.snapshot_id.as_str(),
            &document_digest(self, "snapshot_id")?,
        )
    }

    fn validate_structure(&self) -> Result<(), AuthorityError> {
        validate_protocol(ADMISSION_SNAPSHOT_PROTOCOL, &self.protocol)?;
        for fact in &self.facts {
            fact.validate()
                .map_err(|error| AuthorityError::InvalidDocument {
                    document: "snapshot fact",
                    detail: error.to_string(),
                })?;
        }
        for record in &self.authority_records {
            record.validate()?;
        }
        validate_extensions(
            "admission snapshot",
            &self.extensions,
            &[
                "snapshot_id",
                "protocol",
                "facts",
                "decisions",
                "authority_records",
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum AuthorityError {
    Protocol(ProtocolError),
    InvalidDigest(String),
    InvalidIdentity {
        field: &'static str,
        value: String,
    },
    ProtocolMismatch {
        expected: &'static str,
        actual: String,
    },
    ReservedExtension {
        scope: String,
        key: String,
    },
    Serialization(String),
    ContentIdentityMismatch {
        document: &'static str,
        expected: String,
        actual: String,
    },
    InvalidDocument {
        document: &'static str,
        detail: String,
    },
    EmptyAssessmentChecks,
    InvalidCheckName(String),
    ObservationValueKindMismatch,
    ObservationEvidenceKindMismatch,
    AssessmentOutcomeMismatch,
    AssessmentCorrelationMismatch,
    ConformanceSuiteMismatch,
    AttesterNotIndependent,
    DuplicateAcceptedAuthority,
    ResultCandidateMismatch,
    DecisionCorrelationMismatch,
    DecisionOutputMismatch,
    DecisionVerdictMismatch,
    WithheldRecord,
    AuthorityOutputMismatch,
    StagedAdmissionMismatch,
    UnknownAuthority(AuthorityRecordId),
    MissingFact(FactId),
    MissingDecision(AdmissionDecisionId),
    FactReferenceMismatch,
    StoredFactMismatch(FactId),
    StoredDecisionMismatch(AdmissionDecisionId),
    LinkedInputMismatch(PortName),
    FactCollision(FactId),
    DecisionCollision(AdmissionDecisionId),
    AuthorityCollision(AuthorityRecordId),
    OrphanFact(FactId),
    OrphanDecision(AdmissionDecisionId),
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for AuthorityError {}

impl From<ProtocolError> for AuthorityError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

fn expected_candidate_verdict(
    policy: &AdmissionPolicy,
    assessment: &ConformanceAssessment,
) -> AdmissionVerdict {
    let reason = match assessment.outcome {
        AssessmentOutcome::Failed => Some(AdmissionDenial::AssessmentFailed),
        AssessmentOutcome::Indeterminate => Some(AdmissionDenial::AssessmentIndeterminate),
        AssessmentOutcome::Passed if !policy.accepts_conformance(&assessment.authority) => {
            Some(AdmissionDenial::AuthorityNotAccepted)
        }
        AssessmentOutcome::Passed => None,
    };
    match reason {
        Some(reason) => AdmissionVerdict::Withhold {
            reason,
            extensions: BTreeMap::new(),
        },
        None => AdmissionVerdict::Admit {
            extensions: BTreeMap::new(),
        },
    }
}

fn expected_observation_verdict(
    policy: &AdmissionPolicy,
    observation: &SourceObservation,
) -> AdmissionVerdict {
    if policy.accepts_observation(&observation.authority) {
        AdmissionVerdict::Admit {
            extensions: BTreeMap::new(),
        }
    } else {
        AdmissionVerdict::Withhold {
            reason: AdmissionDenial::AuthorityNotAccepted,
            extensions: BTreeMap::new(),
        }
    }
}

fn same_verdict_kind(actual: &AdmissionVerdict, expected: &AdmissionVerdict) -> bool {
    match (actual, expected) {
        (AdmissionVerdict::Admit { .. }, AdmissionVerdict::Admit { .. }) => true,
        (
            AdmissionVerdict::Withhold { reason: actual, .. },
            AdmissionVerdict::Withhold {
                reason: expected, ..
            },
        ) => actual == expected,
        _ => false,
    }
}

fn candidate_subject(
    assessment: &ConformanceAssessment,
    candidate: &CapabilityCandidate,
) -> Result<AdmissionSubject, AuthorityError> {
    Ok(AdmissionSubject::Candidate {
        assessment_id: assessment.assessment_id.clone(),
        candidate_id: candidate.candidate_id.clone(),
        outputs: candidate_outputs(candidate)?
            .iter()
            .map(|output| DecisionOutput {
                port: output.port.clone(),
                fact_id: output.fact.id.clone(),
                extensions: BTreeMap::new(),
            })
            .collect(),
        extensions: BTreeMap::new(),
    })
}

fn candidate_subject_matches(
    subject: &AdmissionSubject,
    assessment: &ConformanceAssessment,
    candidate: &CapabilityCandidate,
) -> Result<bool, AuthorityError> {
    let AdmissionSubject::Candidate {
        assessment_id,
        candidate_id,
        outputs,
        ..
    } = subject
    else {
        return Ok(false);
    };
    if assessment_id != &assessment.assessment_id || candidate_id != &candidate.candidate_id {
        return Ok(false);
    }
    let expected = candidate_outputs(candidate)?;
    Ok(outputs.len() == expected.len()
        && outputs.iter().zip(expected).all(|(actual, expected)| {
            actual.port == expected.port && actual.fact_id == expected.fact.id
        }))
}

fn observation_subject_matches(
    subject: &AdmissionSubject,
    observation: &SourceObservation,
) -> bool {
    matches!(
        subject,
        AdmissionSubject::Observation {
            observation_id,
            fact_id,
            ..
        } if observation_id == &observation.observation_id && fact_id == &observation.fact.id
    )
}

fn derive_assessment_outcome(
    checks: &BTreeMap<String, ConformanceCheck>,
) -> Result<AssessmentOutcome, AuthorityError> {
    if checks.is_empty() {
        return Err(AuthorityError::EmptyAssessmentChecks);
    }
    let mut outcome = AssessmentOutcome::Passed;
    for (name, check) in checks {
        if name.is_empty()
            || name.len() > 256
            || name.trim() != name
            || name.chars().any(char::is_control)
        {
            return Err(AuthorityError::InvalidCheckName(name.clone()));
        }
        check.validate()?;
        match check.outcome {
            AssessmentOutcome::Failed => outcome = AssessmentOutcome::Failed,
            AssessmentOutcome::Indeterminate if outcome == AssessmentOutcome::Passed => {
                outcome = AssessmentOutcome::Indeterminate;
            }
            AssessmentOutcome::Passed | AssessmentOutcome::Indeterminate => {}
        }
    }
    Ok(outcome)
}

fn candidate_outputs(
    candidate: &CapabilityCandidate,
) -> Result<&[crate::protocol::NamedOutput], AuthorityError> {
    match &candidate.result.outcome {
        CapabilityOutcome::Produced { outputs, .. } => Ok(outputs),
        CapabilityOutcome::Unable { .. } => Err(AuthorityError::InvalidDocument {
            document: "capability candidate",
            detail: "an unable result cannot be admitted".to_owned(),
        }),
    }
}

fn validate_exact_id<T: ExactSemanticId>(
    field: &'static str,
    value: &T,
) -> Result<(), AuthorityError> {
    if value.is_well_formed() {
        Ok(())
    } else {
        Err(AuthorityError::InvalidIdentity {
            field,
            value: value.render(),
        })
    }
}

trait ExactSemanticId {
    fn is_well_formed(&self) -> bool;
    fn render(&self) -> String;
}

macro_rules! exact_semantic_id_impl {
    ($($type:ty),+ $(,)?) => {
        $(
            impl ExactSemanticId for $type {
                fn is_well_formed(&self) -> bool {
                    <$type>::is_well_formed(self)
                }

                fn render(&self) -> String {
                    self.to_string()
                }
            }
        )+
    };
}

exact_semantic_id_impl!(
    ImplementationId,
    ConformanceSuiteId,
    AdmissionAuthorityId,
    ObservationSourceId,
    ValueKindId,
    EvidenceKindId,
);

fn validate_protocol(expected: &'static str, actual: &str) -> Result<(), AuthorityError> {
    if actual == expected {
        Ok(())
    } else {
        Err(AuthorityError::ProtocolMismatch {
            expected,
            actual: actual.to_owned(),
        })
    }
}

fn validate_extensions(
    scope: &str,
    extensions: &BTreeMap<String, Value>,
    reserved: &[&str],
) -> Result<(), AuthorityError> {
    for key in extensions.keys() {
        if reserved.contains(&key.as_str()) {
            return Err(AuthorityError::ReservedExtension {
                scope: scope.to_owned(),
                key: key.clone(),
            });
        }
    }
    Ok(())
}

fn document_digest<T: Serialize>(
    document: &T,
    identity_field: &str,
) -> Result<String, AuthorityError> {
    let mut value = serde_json::to_value(document)
        .map_err(|error| AuthorityError::Serialization(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| AuthorityError::Serialization("document is not an object".to_owned()))?;
    object.remove(identity_field);
    canonical_digest(&value).map_err(AuthorityError::Serialization)
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, AuthorityError> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|error| AuthorityError::Serialization(error.to_string()))
}

fn validate_content_id(
    document: &'static str,
    actual: &str,
    expected: &str,
) -> Result<(), AuthorityError> {
    if actual == expected {
        Ok(())
    } else {
        Err(AuthorityError::ContentIdentityMismatch {
            document,
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        })
    }
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn placeholder<T>() -> T
where
    T: PlaceholderIdentity,
{
    T::placeholder()
}

trait PlaceholderIdentity {
    fn placeholder() -> Self;
}

macro_rules! impl_placeholder {
    ($($name:ident),+ $(,)?) => {
        $(
            impl PlaceholderIdentity for $name {
                fn placeholder() -> Self {
                    $name::parse(format!("sha256:{}", "0".repeat(64)))
                        .expect("the placeholder is a valid SHA-256 identity")
                }
            }
        )+
    };
}

impl_placeholder!(
    AssessmentId,
    ObservationId,
    AdmissionPolicyId,
    AdmissionDecisionId,
    AdmissionSnapshotId,
);

fn placeholder_authority_record_id() -> AuthorityRecordId {
    AuthorityRecordId::parse(format!("sha256:{}", "0".repeat(64)))
        .expect("the placeholder is a valid SHA-256 identity")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        AdmittedFactRef, CapabilityOffer, EvidenceDigest, ImplementationSelection, LinkedInput,
        NamedOutput,
    };
    use crate::{CapabilityId, CapabilitySpec, FactAcceptance, InputPort, OutputPort};
    use serde_json::json;

    fn sha(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn port(name: &str) -> PortName {
        PortName::parse(name).unwrap()
    }

    fn source_kind() -> ValueKindId {
        ValueKindId::new("test.values", "source", "1.0.0")
    }

    fn output_kind() -> ValueKindId {
        ValueKindId::new("test.values", "output", "1.0.0")
    }

    fn evidence_kind() -> EvidenceKindId {
        EvidenceKindId::new("test.evidence", "source-bytes", "1.0.0")
    }

    fn suite() -> ConformanceSuiteId {
        ConformanceSuiteId::new("test.conformance", "transform", "1.0.0")
    }

    fn evidence(byte: char) -> EvidenceRef {
        EvidenceRef::new(
            evidence_kind(),
            EvidenceDigest::parse(sha(byte)).unwrap(),
            format!("opaque://evidence/{byte}"),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn source_fact(value: i64) -> Fact {
        Fact::new(source_kind(), json!({"value": value})).unwrap()
    }

    fn output_fact(value: i64) -> Fact {
        Fact::new(output_kind(), json!({"value": value})).unwrap()
    }

    fn observation_authority(name: &str, artifact: char) -> ObservationAuthority {
        ObservationAuthority::new(
            ObservationSourceId::new("test.source", name, "1.0.0"),
            ImplementationId::new("test.observer", name, "1.0.0"),
            ArtifactDigest::parse(sha(artifact)).unwrap(),
            source_kind(),
            evidence_kind(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn observation(fact: Fact, name: &str, artifact: char) -> SourceObservation {
        SourceObservation::new(
            fact,
            observation_authority(name, artifact),
            evidence(artifact),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn admission_authority(name: &str) -> AdmissionAuthorityId {
        AdmissionAuthorityId::new("test.admission", name, "1.0.0")
    }

    fn observation_policy(observation: &SourceObservation, name: &str) -> AdmissionPolicy {
        AdmissionPolicy::new(
            admission_authority(name),
            Vec::new(),
            vec![observation.authority.clone()],
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn capability() -> CapabilityId {
        CapabilityId::new("test.capability", "transform", "1.0.0")
    }

    fn specification(output_ports: usize) -> CapabilitySpec {
        CapabilitySpec {
            id: capability(),
            input_ports: vec![InputPort {
                name: port("source"),
                value_kind: source_kind(),
                acceptance: FactAcceptance::CompleteOnly,
                extensions: BTreeMap::new(),
            }],
            output_ports: (0..output_ports)
                .map(|index| OutputPort::new(port(&format!("output-{index}")), output_kind()))
                .collect(),
            default_conformance_suite: suite().to_string(),
            extensions: BTreeMap::new(),
        }
    }

    fn offer() -> CapabilityOffer {
        CapabilityOffer::new(
            ImplementationId::new("test.producer", "transform", "1.0.0"),
            ArtifactDigest::parse(sha('a')).unwrap(),
            capability(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn invocation(
        reference: AdmittedFactRef,
        fact: Fact,
        output_ports: usize,
    ) -> CapabilityInvocation {
        CapabilityInvocation::new(
            specification(output_ports),
            ImplementationSelection::new(offer(), BTreeMap::new()).unwrap(),
            vec![LinkedInput::new(port("source"), reference, fact, BTreeMap::new()).unwrap()],
            suite(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn produced_chain(
        invocation: &CapabilityInvocation,
        values: &[i64],
    ) -> (CapabilityResult, CapabilityCandidate) {
        let outputs = values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                NamedOutput::new(
                    port(&format!("output-{index}")),
                    output_fact(*value),
                    BTreeMap::new(),
                )
                .unwrap()
            })
            .collect();
        let result = CapabilityResult::produced(
            invocation,
            outputs,
            BTreeMap::new(),
            vec![evidence('d')],
            BTreeMap::new(),
        )
        .unwrap();
        let candidate =
            CapabilityCandidate::new(invocation, result.clone(), BTreeMap::new()).unwrap();
        (result, candidate)
    }

    fn conformance_authority() -> ConformanceAuthority {
        ConformanceAuthority::new(
            suite(),
            ConformanceAttester::new(
                ImplementationId::new("test.attester", "transform", "1.0.0"),
                ArtifactDigest::parse(sha('b')).unwrap(),
                BTreeMap::new(),
            )
            .unwrap(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn assessment(
        invocation: &CapabilityInvocation,
        result: &CapabilityResult,
        candidate: &CapabilityCandidate,
        outcome: AssessmentOutcome,
    ) -> ConformanceAssessment {
        ConformanceAssessment::new(
            invocation,
            result,
            candidate,
            conformance_authority(),
            BTreeMap::from([(
                "exact-output".to_owned(),
                ConformanceCheck::new(outcome, vec![evidence('e')], BTreeMap::new()).unwrap(),
            )]),
            vec![evidence('f')],
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn candidate_policy(assessment: &ConformanceAssessment, name: &str) -> AdmissionPolicy {
        AdmissionPolicy::new(
            admission_authority(name),
            vec![assessment.authority.clone()],
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn admitted_links(outcome: AdmissionOutcome) -> Vec<AdmittedLink> {
        let AdmissionOutcome::Admitted { links, .. } = outcome else {
            panic!("fixture must admit")
        };
        links
    }

    fn admit_source(
        ledger: &mut AdmissionLedger,
        observation: &SourceObservation,
        name: &str,
    ) -> AdmittedFactRef {
        admitted_links(
            ledger
                .admit_observation(&observation_policy(observation, name), observation)
                .unwrap(),
        )[0]
        .reference
        .clone()
    }

    fn assert_source_substitution_rejected(
        policy: &AdmissionPolicy,
        observed: &SourceObservation,
        mutate: impl FnOnce(&mut SourceObservation),
    ) {
        let mut value = observed.clone();
        mutate(&mut value);
        let mut ledger = AdmissionLedger::new();
        assert!(ledger.admit_observation(policy, &value).is_err());
        assert_eq!(
            (
                ledger.fact_count(),
                ledger.decision_count(),
                ledger.authority_count(),
            ),
            (0, 0, 0)
        );
    }

    #[test]
    fn bare_documents_never_link_and_default_deny_mutates_nothing() {
        let fact = source_fact(1);
        let fake = AdmittedFactRef::new(
            fact.id.clone(),
            AuthorityRecordId::parse(sha('9')).unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        let mut ledger = AdmissionLedger::new();
        assert!(matches!(
            ledger.resolve(&fake),
            Err(AuthorityError::UnknownAuthority(_))
        ));

        let observed = observation(fact, "workspace", '1');
        let denied =
            AdmissionPolicy::deny_all(admission_authority("deny"), BTreeMap::new()).unwrap();
        let outcome = ledger.admit_observation(&denied, &observed).unwrap();
        assert!(matches!(outcome, AdmissionOutcome::Withheld { .. }));
        assert_eq!(
            (
                ledger.fact_count(),
                ledger.decision_count(),
                ledger.authority_count()
            ),
            (0, 0, 0)
        );
    }

    #[test]
    fn exact_source_replay_is_idempotent_and_authority_is_explicit() {
        let fact = source_fact(1);
        let observed = observation(fact.clone(), "workspace", '1');
        let policy = observation_policy(&observed, "source");
        let mut ledger = AdmissionLedger::new();
        let first = admitted_links(ledger.admit_observation(&policy, &observed).unwrap());
        let replay = admitted_links(ledger.admit_observation(&policy, &observed).unwrap());
        assert_eq!(first, replay);
        assert_eq!(
            (
                ledger.fact_count(),
                ledger.decision_count(),
                ledger.authority_count()
            ),
            (1, 1, 1)
        );
        assert_eq!(ledger.resolve(&first[0].reference).unwrap().fact, &fact);
    }

    #[test]
    fn same_fact_can_have_two_source_authorities_without_implicit_selection() {
        let fact = source_fact(1);
        let first = observation(fact.clone(), "workspace", '1');
        let second = observation(fact.clone(), "operator", '2');
        let mut ledger = AdmissionLedger::new();
        let first_ref = admit_source(&mut ledger, &first, "first");
        let second_ref = admit_source(&mut ledger, &second, "second");
        assert_eq!(first_ref.fact_id, second_ref.fact_id);
        assert_ne!(
            first_ref.authority_record_id,
            second_ref.authority_record_id
        );
        assert_eq!(ledger.fact_count(), 1);
        assert_eq!(ledger.authorities_for(&fact.id).len(), 2);
        assert_eq!(
            ledger.resolve(&first_ref).unwrap().fact,
            ledger.resolve(&second_ref).unwrap().fact
        );
    }

    #[test]
    fn source_substitutions_fail_before_mutation() {
        let observed = observation(source_fact(1), "workspace", '1');
        let policy = observation_policy(&observed, "source");
        assert_source_substitution_rejected(&policy, &observed, |value| {
            value.authority.source = ObservationSourceId::new("test.source", "other", "1.0.0");
        });
        assert_source_substitution_rejected(&policy, &observed, |value| {
            value.authority.observer = ImplementationId::new("test.observer", "other", "1.0.0");
        });
        assert_source_substitution_rejected(&policy, &observed, |value| {
            value.authority.observer_artifact = ArtifactDigest::parse(sha('2')).unwrap();
        });
        assert_source_substitution_rejected(&policy, &observed, |value| {
            value.primary_evidence = evidence('2');
        });
        assert_source_substitution_rejected(&policy, &observed, |value| {
            value.fact = source_fact(2);
        });

        let unaccepted = observation(source_fact(1), "other", '2');
        let mut ledger = AdmissionLedger::new();
        assert!(matches!(
            ledger.admit_observation(&policy, &unaccepted).unwrap(),
            AdmissionOutcome::Withheld { .. }
        ));
        assert_eq!(ledger.authority_count(), 0);
    }

    #[test]
    fn observation_scope_requires_exact_value_and_primary_evidence_kinds() {
        let observed = observation(source_fact(1), "workspace", '1');

        let mut wrong_value_kind = observed.clone();
        wrong_value_kind.authority.value_kind = output_kind();
        wrong_value_kind.observation_id =
            ObservationId::parse(document_digest(&wrong_value_kind, "observation_id").unwrap())
                .unwrap();
        assert!(matches!(
            wrong_value_kind.validate(),
            Err(AuthorityError::ObservationValueKindMismatch)
        ));

        let mut wrong_evidence_kind = observed;
        wrong_evidence_kind.authority.evidence_kind =
            EvidenceKindId::new("test.evidence", "other", "1.0.0");
        wrong_evidence_kind.observation_id =
            ObservationId::parse(document_digest(&wrong_evidence_kind, "observation_id").unwrap())
                .unwrap();
        assert!(matches!(
            wrong_evidence_kind.validate(),
            Err(AuthorityError::ObservationEvidenceKindMismatch)
        ));
    }

    #[test]
    fn source_reference_is_the_only_input_path_to_derived_admission() {
        let fact = source_fact(1);
        let observed = observation(fact.clone(), "workspace", '1');
        let mut ledger = AdmissionLedger::new();
        let source_ref = admit_source(&mut ledger, &observed, "source");
        let invocation = invocation(source_ref.clone(), fact, 2);
        let (result, candidate) = produced_chain(&invocation, &[10, 20]);
        let assessment = assessment(&invocation, &result, &candidate, AssessmentOutcome::Passed);
        let policy = candidate_policy(&assessment, "derived");
        let links = admitted_links(
            ledger
                .admit_candidate(&policy, &invocation, &result, &candidate, &assessment)
                .unwrap(),
        );
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].port, Some(port("output-0")));
        assert!(ledger.resolve(&source_ref).is_ok());
        assert!(ledger.resolve(&links[0].reference).is_ok());
        assert_eq!(
            (
                ledger.fact_count(),
                ledger.decision_count(),
                ledger.authority_count()
            ),
            (3, 2, 3)
        );
    }

    #[test]
    fn unknown_input_authority_and_invalid_second_output_are_atomic() {
        let fact = source_fact(1);
        let unknown = AdmittedFactRef::new(
            fact.id.clone(),
            AuthorityRecordId::parse(sha('9')).unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        let unknown_invocation = invocation(unknown, fact.clone(), 2);
        let (unknown_result, unknown_candidate) = produced_chain(&unknown_invocation, &[10, 20]);
        let unknown_assessment = assessment(
            &unknown_invocation,
            &unknown_result,
            &unknown_candidate,
            AssessmentOutcome::Passed,
        );
        let unknown_policy = candidate_policy(&unknown_assessment, "derived");
        let mut ledger = AdmissionLedger::new();
        assert!(matches!(
            ledger.admit_candidate(
                &unknown_policy,
                &unknown_invocation,
                &unknown_result,
                &unknown_candidate,
                &unknown_assessment,
            ),
            Err(AuthorityError::UnknownAuthority(_))
        ));
        assert_eq!(ledger.authority_count(), 0);

        let observed = observation(fact.clone(), "workspace", '1');
        let source_ref = admit_source(&mut ledger, &observed, "source");
        let invocation = invocation(source_ref, fact, 2);
        let (result, candidate) = produced_chain(&invocation, &[10, 20]);
        let atomic_assessment =
            assessment(&invocation, &result, &candidate, AssessmentOutcome::Passed);
        let atomic_policy = candidate_policy(&atomic_assessment, "atomic");
        let mut invalid_result = result;
        let CapabilityOutcome::Produced { outputs, .. } = &mut invalid_result.outcome else {
            unreachable!()
        };
        outputs[1].fact.payload = json!({"tampered": true});
        let mut invalid_candidate = candidate;
        invalid_candidate.result = invalid_result.clone();
        let before = ledger.clone();
        assert!(
            ledger
                .admit_candidate(
                    &atomic_policy,
                    &invocation,
                    &invalid_result,
                    &invalid_candidate,
                    &atomic_assessment,
                )
                .is_err()
        );
        assert_eq!(ledger, before);

        let (valid_result, valid_candidate) = produced_chain(&invocation, &[10, 20]);
        let valid_assessment = assessment(
            &invocation,
            &valid_result,
            &valid_candidate,
            AssessmentOutcome::Passed,
        );
        let valid_policy = candidate_policy(&valid_assessment, "collision");
        let CapabilityOutcome::Produced { outputs, .. } = &valid_result.outcome else {
            unreachable!()
        };
        let mut colliding = outputs[1].fact.clone();
        colliding.payload = json!({"same-id-different-body": true});
        ledger.facts.insert(colliding.id.clone(), colliding);
        let before_collision = ledger.clone();
        assert!(matches!(
            ledger.admit_candidate(
                &valid_policy,
                &invocation,
                &valid_result,
                &valid_candidate,
                &valid_assessment,
            ),
            Err(AuthorityError::FactCollision(_))
        ));
        assert_eq!(ledger, before_collision);
    }

    #[test]
    fn failed_indeterminate_and_unaccepted_assessments_default_deny() {
        let fact = source_fact(1);
        let observed = observation(fact.clone(), "workspace", '1');
        let mut ledger = AdmissionLedger::new();
        let source_ref = admit_source(&mut ledger, &observed, "source");
        let baseline = ledger.clone();

        for outcome in [AssessmentOutcome::Failed, AssessmentOutcome::Indeterminate] {
            let invocation = invocation(source_ref.clone(), fact.clone(), 1);
            let (result, candidate) = produced_chain(&invocation, &[10]);
            let assessment = assessment(&invocation, &result, &candidate, outcome);
            let policy = candidate_policy(&assessment, "derived");
            assert!(matches!(
                ledger
                    .admit_candidate(&policy, &invocation, &result, &candidate, &assessment)
                    .unwrap(),
                AdmissionOutcome::Withheld { .. }
            ));
            assert_eq!(ledger, baseline);
        }

        let invocation = invocation(source_ref, fact, 1);
        let (result, candidate) = produced_chain(&invocation, &[10]);
        let assessment = assessment(&invocation, &result, &candidate, AssessmentOutcome::Passed);
        let deny = AdmissionPolicy::deny_all(admission_authority("deny"), BTreeMap::new()).unwrap();
        assert!(matches!(
            ledger
                .admit_candidate(&deny, &invocation, &result, &candidate, &assessment)
                .unwrap(),
            AdmissionOutcome::Withheld { .. }
        ));
        assert_eq!(ledger, baseline);
    }

    #[test]
    fn every_derived_chain_substitution_fails_without_mutation() {
        let fact = source_fact(1);
        let observed = observation(fact.clone(), "workspace", '1');
        let mut ledger = AdmissionLedger::new();
        let source_ref = admit_source(&mut ledger, &observed, "source");
        let invocation = invocation(source_ref, fact, 1);
        let (result, candidate) = produced_chain(&invocation, &[10]);
        let assessment = assessment(&invocation, &result, &candidate, AssessmentOutcome::Passed);
        let policy = candidate_policy(&assessment, "derived");
        let baseline = ledger.clone();

        let mut changed_policy = policy.clone();
        changed_policy
            .extensions
            .insert("x.test/substitution".to_owned(), json!(true));
        assert!(
            ledger
                .admit_candidate(
                    &changed_policy,
                    &invocation,
                    &result,
                    &candidate,
                    &assessment,
                )
                .is_err()
        );
        assert_eq!(ledger, baseline);

        let mut changed_invocation = invocation.clone();
        changed_invocation
            .extensions
            .insert("x.test/substitution".to_owned(), json!(true));
        assert!(
            ledger
                .admit_candidate(
                    &policy,
                    &changed_invocation,
                    &result,
                    &candidate,
                    &assessment,
                )
                .is_err()
        );
        assert_eq!(ledger, baseline);

        let mut changed_result = result.clone();
        changed_result
            .extensions
            .insert("x.test/substitution".to_owned(), json!(true));
        assert!(
            ledger
                .admit_candidate(
                    &policy,
                    &invocation,
                    &changed_result,
                    &candidate,
                    &assessment,
                )
                .is_err()
        );
        assert_eq!(ledger, baseline);

        let mut changed_candidate = candidate.clone();
        changed_candidate
            .extensions
            .insert("x.test/substitution".to_owned(), json!(true));
        assert!(
            ledger
                .admit_candidate(
                    &policy,
                    &invocation,
                    &result,
                    &changed_candidate,
                    &assessment,
                )
                .is_err()
        );
        assert_eq!(ledger, baseline);

        let mut changed_assessment = assessment.clone();
        changed_assessment
            .extensions
            .insert("x.test/substitution".to_owned(), json!(true));
        assert!(
            ledger
                .admit_candidate(
                    &policy,
                    &invocation,
                    &result,
                    &candidate,
                    &changed_assessment,
                )
                .is_err()
        );
        assert_eq!(ledger, baseline);

        let mut changed_output_result = result.clone();
        let CapabilityOutcome::Produced { outputs, .. } = &mut changed_output_result.outcome else {
            unreachable!()
        };
        outputs[0].port = port("substituted");
        let mut changed_output_candidate = candidate;
        changed_output_candidate.result = changed_output_result.clone();
        assert!(
            ledger
                .admit_candidate(
                    &policy,
                    &invocation,
                    &changed_output_result,
                    &changed_output_candidate,
                    &assessment,
                )
                .is_err()
        );
        assert_eq!(ledger, baseline);
    }

    #[test]
    fn producer_cannot_supply_its_own_conformance_assessment() {
        let fact = source_fact(1);
        let observed = observation(fact.clone(), "workspace", '1');
        let mut ledger = AdmissionLedger::new();
        let source_ref = admit_source(&mut ledger, &observed, "source");
        let invocation = invocation(source_ref, fact, 1);
        let (result, candidate) = produced_chain(&invocation, &[10]);
        for authority in [
            ConformanceAuthority::new(
                suite(),
                ConformanceAttester::new(
                    invocation.selection.offer.implementation.clone(),
                    ArtifactDigest::parse(sha('b')).unwrap(),
                    BTreeMap::new(),
                )
                .unwrap(),
                BTreeMap::new(),
            )
            .unwrap(),
            ConformanceAuthority::new(
                suite(),
                ConformanceAttester::new(
                    ImplementationId::new("test.attester", "other", "1.0.0"),
                    invocation.selection.offer.artifact_digest.clone(),
                    BTreeMap::new(),
                )
                .unwrap(),
                BTreeMap::new(),
            )
            .unwrap(),
        ] {
            assert!(matches!(
                ConformanceAssessment::new(
                    &invocation,
                    &result,
                    &candidate,
                    authority,
                    BTreeMap::from([(
                        "check".to_owned(),
                        ConformanceCheck::new(
                            AssessmentOutcome::Passed,
                            Vec::new(),
                            BTreeMap::new(),
                        )
                        .unwrap(),
                    )]),
                    Vec::new(),
                    BTreeMap::new(),
                ),
                Err(AuthorityError::AttesterNotIndependent)
            ));
        }
        assert!(matches!(
            ConformanceAssessment::new(
                &invocation,
                &result,
                &candidate,
                conformance_authority(),
                BTreeMap::new(),
                Vec::new(),
                BTreeMap::new(),
            ),
            Err(AuthorityError::EmptyAssessmentChecks)
        ));
    }

    #[test]
    fn changing_only_input_authority_changes_every_downstream_identity() {
        let fact = source_fact(1);
        let first_observation = observation(fact.clone(), "workspace", '1');
        let second_observation = observation(fact.clone(), "operator", '2');
        let mut ledger = AdmissionLedger::new();
        let first_ref = admit_source(&mut ledger, &first_observation, "first");
        let second_ref = admit_source(&mut ledger, &second_observation, "second");

        let first_invocation = invocation(first_ref, fact.clone(), 1);
        let second_invocation = invocation(second_ref, fact, 1);
        assert_ne!(
            first_invocation.invocation_id,
            second_invocation.invocation_id
        );

        let (first_result, first_candidate) = produced_chain(&first_invocation, &[10]);
        let first_assessment = assessment(
            &first_invocation,
            &first_result,
            &first_candidate,
            AssessmentOutcome::Passed,
        );
        let first_policy = candidate_policy(&first_assessment, "derived");
        let first_link = admitted_links(
            ledger
                .admit_candidate(
                    &first_policy,
                    &first_invocation,
                    &first_result,
                    &first_candidate,
                    &first_assessment,
                )
                .unwrap(),
        )[0]
        .reference
        .clone();

        let (second_result, second_candidate) = produced_chain(&second_invocation, &[10]);
        let second_assessment = assessment(
            &second_invocation,
            &second_result,
            &second_candidate,
            AssessmentOutcome::Passed,
        );
        let second_policy = candidate_policy(&second_assessment, "derived");
        let second_link = admitted_links(
            ledger
                .admit_candidate(
                    &second_policy,
                    &second_invocation,
                    &second_result,
                    &second_candidate,
                    &second_assessment,
                )
                .unwrap(),
        )[0]
        .reference
        .clone();

        assert_eq!(first_link.fact_id, second_link.fact_id);
        assert_ne!(first_result.result_id, second_result.result_id);
        assert_ne!(first_candidate.candidate_id, second_candidate.candidate_id);
        assert_ne!(
            first_assessment.assessment_id,
            second_assessment.assessment_id
        );
        assert_ne!(
            first_link.authority_record_id,
            second_link.authority_record_id
        );
        assert_eq!(ledger.authorities_for(&first_link.fact_id).len(), 2);
    }

    #[test]
    fn derived_replay_is_exact_and_snapshot_rebuild_preserves_linkability() {
        let fact = source_fact(1);
        let observed = observation(fact.clone(), "workspace", '1');
        let mut ledger = AdmissionLedger::new();
        let source_ref = admit_source(&mut ledger, &observed, "source");
        let invocation = invocation(source_ref.clone(), fact, 1);
        let (result, candidate) = produced_chain(&invocation, &[10]);
        let assessment = assessment(&invocation, &result, &candidate, AssessmentOutcome::Passed);
        let policy = candidate_policy(&assessment, "derived");
        let first = admitted_links(
            ledger
                .admit_candidate(&policy, &invocation, &result, &candidate, &assessment)
                .unwrap(),
        );
        let counts = (
            ledger.fact_count(),
            ledger.decision_count(),
            ledger.authority_count(),
        );
        let replay = admitted_links(
            ledger
                .admit_candidate(&policy, &invocation, &result, &candidate, &assessment)
                .unwrap(),
        );
        assert_eq!(first, replay);
        assert_eq!(
            counts,
            (
                ledger.fact_count(),
                ledger.decision_count(),
                ledger.authority_count()
            )
        );

        let snapshot = ledger.export().unwrap();
        let encoded = serde_json::to_vec(&snapshot).unwrap();
        let decoded: AdmissionSnapshot = serde_json::from_slice(&encoded).unwrap();
        let rebuilt = AdmissionLedger::rebuild(&decoded).unwrap();
        assert_eq!(ledger, rebuilt);
        assert!(rebuilt.resolve(&source_ref).is_ok());
        assert!(rebuilt.resolve(&first[0].reference).is_ok());
    }

    #[test]
    fn corrupt_source_and_derived_snapshots_are_rejected() {
        let fact = source_fact(1);
        let observed = observation(fact.clone(), "workspace", '1');
        let mut ledger = AdmissionLedger::new();
        let source_ref = admit_source(&mut ledger, &observed, "source");
        let invocation = invocation(source_ref, fact, 1);
        let (result, candidate) = produced_chain(&invocation, &[10]);
        let assessment = assessment(&invocation, &result, &candidate, AssessmentOutcome::Passed);
        let policy = candidate_policy(&assessment, "derived");
        let _ = ledger
            .admit_candidate(&policy, &invocation, &result, &candidate, &assessment)
            .unwrap();

        let snapshot = ledger.export().unwrap();
        let mut corrupt_source = snapshot.clone();
        let source = corrupt_source
            .authority_records
            .iter_mut()
            .find(|record| matches!(&record.basis, AuthorityBasis::Source { .. }))
            .unwrap();
        if let AuthorityBasis::Source { observation, .. } = &mut source.basis {
            observation.primary_evidence = evidence('7');
        }
        rehash_snapshot(&mut corrupt_source);
        assert!(AdmissionLedger::rebuild(&corrupt_source).is_err());

        let mut corrupt_derived = snapshot;
        let derived = corrupt_derived
            .authority_records
            .iter_mut()
            .find(|record| matches!(&record.basis, AuthorityBasis::Derived { .. }))
            .unwrap();
        derived.fact.payload = json!({"tampered": true});
        rehash_snapshot(&mut corrupt_derived);
        assert!(AdmissionLedger::rebuild(&corrupt_derived).is_err());
    }

    #[test]
    fn extensions_round_trip_are_reserved_and_affect_enclosing_identities() {
        let fact = source_fact(1);
        let mut authority_extensions = BTreeMap::new();
        authority_extensions.insert("x.test/authority".to_owned(), json!({"mode": "exact"}));
        let scoped = ObservationAuthority::new(
            ObservationSourceId::new("test.source", "workspace", "1.0.0"),
            ImplementationId::new("test.observer", "workspace", "1.0.0"),
            ArtifactDigest::parse(sha('1')).unwrap(),
            source_kind(),
            evidence_kind(),
            authority_extensions,
        )
        .unwrap();
        let mut evidence_extensions = BTreeMap::new();
        evidence_extensions.insert("x.test/evidence".to_owned(), json!(true));
        let primary = EvidenceRef::new(
            evidence_kind(),
            EvidenceDigest::parse(sha('1')).unwrap(),
            "opaque://evidence/1",
            evidence_extensions,
        )
        .unwrap();
        let mut observation_extensions = BTreeMap::new();
        observation_extensions.insert("x.test/observation".to_owned(), json!([1, 2]));
        let observed =
            SourceObservation::new(fact, scoped, primary, Vec::new(), observation_extensions)
                .unwrap();
        let plain = observation(source_fact(1), "workspace", '1');
        assert_ne!(observed.observation_id, plain.observation_id);

        let mut policy_extensions = BTreeMap::new();
        policy_extensions.insert("x.test/policy".to_owned(), json!("local"));
        let policy = AdmissionPolicy::new(
            admission_authority("source"),
            Vec::new(),
            vec![observed.authority.clone()],
            policy_extensions,
        )
        .unwrap();
        let mut ledger = AdmissionLedger::new();
        let mut link = admitted_links(ledger.admit_observation(&policy, &observed).unwrap());
        let mut snapshot_extensions = BTreeMap::new();
        snapshot_extensions.insert("x.test/snapshot".to_owned(), json!({"v": 1}));
        let mut snapshot = ledger.export_with_extensions(snapshot_extensions).unwrap();
        let (old_decision_id, extended_decision, extended_record_id) = {
            let record = snapshot
                .authority_records
                .iter_mut()
                .find(|record| matches!(&record.basis, AuthorityBasis::Source { .. }))
                .unwrap();
            let AuthorityBasis::Source {
                decision,
                extensions: basis_extensions,
                ..
            } = &mut record.basis
            else {
                unreachable!()
            };
            let old_id = decision.decision_id.clone();
            decision
                .extensions
                .insert("x.test/decision".to_owned(), json!(1));
            let AdmissionSubject::Observation {
                extensions: subject_extensions,
                ..
            } = &mut decision.subject
            else {
                unreachable!()
            };
            subject_extensions.insert("x.test/subject".to_owned(), json!(2));
            match &mut decision.verdict {
                AdmissionVerdict::Admit {
                    extensions: verdict_extensions,
                }
                | AdmissionVerdict::Withhold {
                    extensions: verdict_extensions,
                    ..
                } => {
                    verdict_extensions.insert("x.test/verdict".to_owned(), json!(3));
                }
            }
            rehash_decision(decision);
            basis_extensions.insert("x.test/basis".to_owned(), json!(4));
            let extended = decision.as_ref().clone();
            record
                .extensions
                .insert("x.test/record".to_owned(), json!(5));
            rehash_authority_record(record);
            (old_id, extended, record.authority_record_id().clone())
        };
        *snapshot
            .decisions
            .iter_mut()
            .find(|decision| decision.decision_id == old_decision_id)
            .unwrap() = extended_decision;
        link[0].reference.authority_record_id = extended_record_id;
        rehash_snapshot(&mut snapshot);
        let decoded: AdmissionSnapshot =
            serde_json::from_value(serde_json::to_value(&snapshot).unwrap()).unwrap();
        let rebuilt = AdmissionLedger::rebuild(&decoded).unwrap();
        assert!(rebuilt.resolve(&link[0].reference).is_ok());
        assert_eq!(snapshot, decoded);

        let mut reserved = observed.clone();
        reserved
            .extensions
            .insert("fact".to_owned(), json!({"shadow": true}));
        assert!(matches!(
            reserved.validate(),
            Err(AuthorityError::ReservedExtension { .. })
        ));
    }

    #[test]
    fn derived_extension_scopes_round_trip_without_weakening_exact_outputs() {
        let fact = source_fact(1);
        let observed = observation(fact.clone(), "workspace", '1');
        let mut ledger = AdmissionLedger::new();
        let source_ref = admit_source(&mut ledger, &observed, "source");
        let invocation = invocation(source_ref, fact, 1);
        let (result, candidate) = produced_chain(&invocation, &[10]);

        let attester = ConformanceAttester::new(
            ImplementationId::new("test.attester", "transform", "1.0.0"),
            ArtifactDigest::parse(sha('b')).unwrap(),
            BTreeMap::from([("x.test/attester".to_owned(), json!(1))]),
        )
        .unwrap();
        let authority = ConformanceAuthority::new(
            suite(),
            attester,
            BTreeMap::from([("x.test/conformance-authority".to_owned(), json!(2))]),
        )
        .unwrap();
        let extended_assessment = ConformanceAssessment::new(
            &invocation,
            &result,
            &candidate,
            authority,
            BTreeMap::from([(
                "exact-output".to_owned(),
                ConformanceCheck::new(
                    AssessmentOutcome::Passed,
                    vec![evidence('e')],
                    BTreeMap::from([("x.test/check".to_owned(), json!(3))]),
                )
                .unwrap(),
            )]),
            vec![evidence('f')],
            BTreeMap::from([("x.test/assessment".to_owned(), json!(4))]),
        )
        .unwrap();
        let plain_assessment =
            assessment(&invocation, &result, &candidate, AssessmentOutcome::Passed);
        assert_ne!(
            extended_assessment.assessment_id,
            plain_assessment.assessment_id
        );
        let policy = AdmissionPolicy::new(
            admission_authority("derived"),
            vec![extended_assessment.authority.clone()],
            Vec::new(),
            BTreeMap::from([("x.test/policy".to_owned(), json!(5))]),
        )
        .unwrap();
        let mut links = admitted_links(
            ledger
                .admit_candidate(
                    &policy,
                    &invocation,
                    &result,
                    &candidate,
                    &extended_assessment,
                )
                .unwrap(),
        );
        let mut snapshot = ledger.export().unwrap();
        let (old_decision_id, extended_decision, extended_record_id) = {
            let record = snapshot
                .authority_records
                .iter_mut()
                .find(|record| matches!(&record.basis, AuthorityBasis::Derived { .. }))
                .unwrap();
            let AuthorityBasis::Derived {
                decision,
                extensions: basis_extensions,
                ..
            } = &mut record.basis
            else {
                unreachable!()
            };
            let old_id = decision.decision_id.clone();
            decision
                .extensions
                .insert("x.test/decision".to_owned(), json!(6));
            let AdmissionSubject::Candidate {
                outputs,
                extensions: subject_extensions,
                ..
            } = &mut decision.subject
            else {
                unreachable!()
            };
            subject_extensions.insert("x.test/subject".to_owned(), json!(7));
            outputs[0]
                .extensions
                .insert("x.test/output".to_owned(), json!(8));
            match &mut decision.verdict {
                AdmissionVerdict::Admit {
                    extensions: verdict_extensions,
                }
                | AdmissionVerdict::Withhold {
                    extensions: verdict_extensions,
                    ..
                } => {
                    verdict_extensions.insert("x.test/verdict".to_owned(), json!(9));
                }
            }
            rehash_decision(decision);
            basis_extensions.insert("x.test/basis".to_owned(), json!(10));
            let extended = decision.as_ref().clone();
            record
                .extensions
                .insert("x.test/record".to_owned(), json!(11));
            rehash_authority_record(record);
            (old_id, extended, record.authority_record_id().clone())
        };
        *snapshot
            .decisions
            .iter_mut()
            .find(|decision| decision.decision_id == old_decision_id)
            .unwrap() = extended_decision;
        links[0].reference.authority_record_id = extended_record_id;
        rehash_snapshot(&mut snapshot);

        let decoded: AdmissionSnapshot =
            serde_json::from_value(serde_json::to_value(&snapshot).unwrap()).unwrap();
        let rebuilt = AdmissionLedger::rebuild(&decoded).unwrap();
        assert!(rebuilt.resolve(&links[0].reference).is_ok());
        assert_eq!(snapshot, decoded);
    }

    #[test]
    fn authority_documents_have_no_runtime_or_coverage_semantics() {
        let observed = observation(source_fact(1), "workspace", '1');
        let policy = observation_policy(&observed, "source");
        let mut ledger = AdmissionLedger::new();
        let _ = ledger.admit_observation(&policy, &observed).unwrap();
        let value = serde_json::to_value(ledger.export().unwrap()).unwrap();
        let forbidden = [
            "host",
            "process",
            "command",
            "transport",
            "lease",
            "session",
            "retry",
            "credential",
            "attempt",
            "fleetd",
            "priority",
            "provider",
            "deadline",
            "owner",
            "persistence",
            "coverage",
        ];
        assert_no_forbidden_keys(&value, &forbidden);
    }

    #[test]
    fn authority_digest_deserialization_is_strict() {
        for invalid in [
            "not-a-digest".to_owned(),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "0".repeat(63)),
        ] {
            let encoded = serde_json::to_string(&invalid).unwrap();
            assert!(serde_json::from_str::<AssessmentId>(&encoded).is_err());
            assert!(serde_json::from_str::<ObservationId>(&encoded).is_err());
            assert!(serde_json::from_str::<AdmissionPolicyId>(&encoded).is_err());
            assert!(serde_json::from_str::<AdmissionDecisionId>(&encoded).is_err());
            assert!(serde_json::from_str::<AdmissionSnapshotId>(&encoded).is_err());
        }
    }

    fn rehash_snapshot(snapshot: &mut AdmissionSnapshot) {
        snapshot.snapshot_id = placeholder::<AdmissionSnapshotId>();
        snapshot.snapshot_id =
            AdmissionSnapshotId::parse(document_digest(snapshot, "snapshot_id").unwrap()).unwrap();
    }

    fn rehash_decision(decision: &mut AdmissionDecision) {
        decision.decision_id = placeholder::<AdmissionDecisionId>();
        decision.decision_id =
            AdmissionDecisionId::parse(document_digest(decision, "decision_id").unwrap()).unwrap();
    }

    fn rehash_authority_record(record: &mut AuthorityRecord) {
        record.authority_record_id = placeholder_authority_record_id();
        record.authority_record_id =
            AuthorityRecordId::parse(document_digest(record, "authority_record_id").unwrap())
                .unwrap();
    }

    fn assert_no_forbidden_keys(value: &Value, forbidden: &[&str]) {
        match value {
            Value::Object(object) => {
                for (key, value) in object {
                    assert!(!forbidden.contains(&key.as_str()), "forbidden key `{key}`");
                    assert_no_forbidden_keys(value, forbidden);
                }
            }
            Value::Array(values) => {
                for value in values {
                    assert_no_forbidden_keys(value, forbidden);
                }
            }
            _ => {}
        }
    }
}
