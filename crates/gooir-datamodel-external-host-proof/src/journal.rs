//! Durable, monotonic attempt evidence for the external-host proof.
//!
//! This is a proof-local authority record, not a GOOIR semantic protocol. It
//! binds one attempt to exact invocation, deployment, runtime, and admission
//! inputs; retains every captured execution artifact through terminal state;
//! and exposes only a closed recovery action. Publication is a real serialized
//! compare-and-swap through one stable sibling lock and one retained parent
//! directory descriptor.

#![allow(clippy::module_name_repetitions)]

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, RenameFlags, flock, mkdirat, open, openat,
    renameat_with, unlinkat,
};
use rustix::process::geteuid;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Exact proof-local checkpoint protocol.
pub const CHECKPOINT_PROTOCOL: &str =
    "org.gooi.proof.data-model-external-host-attempt-checkpoint/v2";

const MAX_CHECKPOINT_BYTES: usize = 64 * 1024 * 1024;
const MAX_EXACT_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_RETAINED_EXACT_JSON_DOCUMENTS: usize = 12;
const MAX_CHECKPOINT_FIXED_OVERHEAD: usize = 1024 * 1024;
const MAX_OPAQUE_ID_BYTES: usize = 4 * 1024;
const MAX_SAFE_JSON_INTEGER: u64 = (1_u64 << 53) - 1;
const CHECKPOINT_NAME: &str = "checkpoint.json";
const LOCK_NAME: &str = "lock";
const TEMPORARY_NAME: &str = "checkpoint.next";

// One terminal attempt currently retains at most eleven ExactJson documents:
// five immutable inputs, five monotonic evidence documents, and one resolution.
// The twelfth slot is deliberate schema headroom. Opaque coordinates, field
// names, content identities, and enum tags must fit in the fixed overhead.
const _: () = assert!(
    MAX_RETAINED_EXACT_JSON_DOCUMENTS * MAX_EXACT_JSON_BYTES + MAX_CHECKPOINT_FIXED_OVERHEAD
        <= MAX_CHECKPOINT_BYTES
);

/// A canonical-normal JSON object bound to its RFC 8785/SHA-256 identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactJson {
    pub digest: String,
    pub value: Value,
}

impl ExactJson {
    /// Normalizes and content-identifies one bounded JSON object.
    ///
    /// # Errors
    ///
    /// Refuses non-objects, unsafe I-JSON numbers, values changed by canonical
    /// serialization, oversized documents, or canonicalization failures.
    pub fn new(value: impl Into<Value>) -> Result<Self, JournalError> {
        let value = value.into();
        if !value.is_object() {
            return Err(invalid("exact JSON payload must be an object"));
        }
        validate_json_number_domain(&value)?;
        let canonical = canonical_bytes(&value)?;
        if canonical.len() > MAX_EXACT_JSON_BYTES {
            return Err(invalid(format!(
                "exact JSON payload exceeds {MAX_EXACT_JSON_BYTES} bytes"
            )));
        }
        let normalized: Value = serde_json::from_slice(&canonical)
            .map_err(|error| invalid(format!("canonical JSON could not be reparsed: {error}")))?;
        if !json_semantically_equal(&value, &normalized) {
            return Err(invalid(
                "canonical JSON changes the supplied value outside the I-JSON domain",
            ));
        }
        let exact = Self {
            digest: sha256_identity(&canonical),
            value: normalized,
        };
        exact.validate()?;
        Ok(exact)
    }

    /// Revalidates canonical-normal form and content identity.
    ///
    /// # Errors
    ///
    /// Refuses malformed, non-normal, unsafe, oversized, or identity-drifting
    /// documents.
    pub fn validate(&self) -> Result<(), JournalError> {
        if !self.value.is_object() {
            return Err(invalid("exact JSON payload must be an object"));
        }
        validate_json_number_domain(&self.value)?;
        let canonical = canonical_bytes(&self.value)?;
        if canonical.len() > MAX_EXACT_JSON_BYTES {
            return Err(invalid(format!(
                "exact JSON payload exceeds {MAX_EXACT_JSON_BYTES} bytes"
            )));
        }
        let normalized: Value = serde_json::from_slice(&canonical)
            .map_err(|error| invalid(format!("canonical JSON could not be reparsed: {error}")))?;
        if self.value != normalized {
            return Err(invalid(
                "exact JSON payload is not in canonical-normal form",
            ));
        }
        validate_sha256("exact JSON digest", &self.digest)?;
        let actual = sha256_identity(&canonical);
        if self.digest != actual {
            return Err(JournalError::ContentIdentityMismatch {
                document: "exact JSON payload",
                expected: self.digest.clone(),
                actual,
            });
        }
        Ok(())
    }
}

/// Host-owned lock to one exact installed runtime resource.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentLock {
    pub implementation: String,
    pub package: String,
    pub package_digest: String,
    pub resource: String,
    pub resource_digest: String,
}

impl DeploymentLock {
    /// Constructs one exact opaque deployment coordinate.
    ///
    /// # Errors
    ///
    /// Refuses empty coordinates or malformed SHA-256 identities.
    pub fn new(
        implementation: impl Into<String>,
        package: impl Into<String>,
        package_digest: impl Into<String>,
        resource: impl Into<String>,
        resource_digest: impl Into<String>,
    ) -> Result<Self, JournalError> {
        let lock = Self {
            implementation: implementation.into(),
            package: package.into(),
            package_digest: package_digest.into(),
            resource: resource.into(),
            resource_digest: resource_digest.into(),
        };
        lock.validate()?;
        Ok(lock)
    }

    fn validate(&self) -> Result<(), JournalError> {
        validate_opaque_id("implementation", &self.implementation)?;
        validate_opaque_id("package", &self.package)?;
        validate_sha256("package digest", &self.package_digest)?;
        validate_opaque_id("resource", &self.resource)?;
        validate_sha256("resource digest", &self.resource_digest)
    }
}

/// Immutable, content-identified inputs for one complete attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnboundAttemptInputs {
    pub semantic_plan: ExactJson,
    pub invocation: ExactJson,
    pub baseline_snapshot: ExactJson,
    pub conformance_suite: String,
    pub provider: DeploymentLock,
    pub attester: DeploymentLock,
    pub execution_policy: ExactJson,
    pub admission_policy: ExactJson,
}

/// Immutable, content-identified inputs for one complete attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptInputs {
    pub attempt_id: String,
    pub semantic_plan: ExactJson,
    pub invocation: ExactJson,
    pub baseline_snapshot: ExactJson,
    pub conformance_suite: String,
    pub provider: DeploymentLock,
    pub attester: DeploymentLock,
    pub execution_policy: ExactJson,
    pub admission_policy: ExactJson,
}

impl AttemptInputs {
    /// Binds one attempt to all semantic and runtime authority inputs.
    ///
    /// # Errors
    ///
    /// Refuses invalid children, provider self-attestation, or invalid exact
    /// coordinates.
    pub fn new(unbound: UnboundAttemptInputs) -> Result<Self, JournalError> {
        let mut inputs = Self {
            attempt_id: placeholder_identity(),
            semantic_plan: unbound.semantic_plan,
            invocation: unbound.invocation,
            baseline_snapshot: unbound.baseline_snapshot,
            conformance_suite: unbound.conformance_suite,
            provider: unbound.provider,
            attester: unbound.attester,
            execution_policy: unbound.execution_policy,
            admission_policy: unbound.admission_policy,
        };
        inputs.validate_structure()?;
        inputs.attempt_id = inputs.derived_id()?;
        Ok(inputs)
    }

    /// Revalidates all immutable inputs and their aggregate identity.
    ///
    /// # Errors
    ///
    /// Refuses invalid children or changed aggregate identity.
    pub fn validate(&self) -> Result<(), JournalError> {
        self.validate_structure()?;
        validate_sha256("attempt identity", &self.attempt_id)?;
        let actual = self.derived_id()?;
        if self.attempt_id != actual {
            return Err(JournalError::ContentIdentityMismatch {
                document: "attempt inputs",
                expected: self.attempt_id.clone(),
                actual,
            });
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), JournalError> {
        self.semantic_plan.validate()?;
        self.invocation.validate()?;
        self.baseline_snapshot.validate()?;
        validate_opaque_id("conformance suite", &self.conformance_suite)?;
        self.provider.validate()?;
        self.attester.validate()?;
        self.execution_policy.validate()?;
        self.admission_policy.validate()?;
        if self.provider.implementation == self.attester.implementation
            || self.provider.resource_digest == self.attester.resource_digest
        {
            return Err(invalid(
                "provider and attester locks must identify distinct implementations and resources",
            ));
        }
        Ok(())
    }

    fn derived_id(&self) -> Result<String, JournalError> {
        #[derive(Serialize)]
        struct Body<'a> {
            semantic_plan: &'a ExactJson,
            invocation: &'a ExactJson,
            baseline_snapshot: &'a ExactJson,
            conformance_suite: &'a str,
            provider: &'a DeploymentLock,
            attester: &'a DeploymentLock,
            execution_policy: &'a ExactJson,
            admission_policy: &'a ExactJson,
        }
        document_digest(&Body {
            semantic_plan: &self.semantic_plan,
            invocation: &self.invocation,
            baseline_snapshot: &self.baseline_snapshot,
            conformance_suite: &self.conformance_suite,
            provider: &self.provider,
            attester: &self.attester,
            execution_policy: &self.execution_policy,
            admission_policy: &self.admission_policy,
        })
    }
}

/// Closed durable lifecycle of one external attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptPhase {
    Prepared,
    ProviderArmed,
    ProviderCaptured,
    CandidateReady,
    AttesterArmed,
    AttesterCaptured,
    AssessmentReady,
    Admitted,
    Withheld,
    Unable,
}

impl AttemptPhase {
    /// Whether no later transition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Admitted | Self::Withheld | Self::Unable)
    }
}

/// Evidence retained monotonically as the attempt advances.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptEvidence {
    provider_receipt: Option<ExactJson>,
    candidate: Option<ExactJson>,
    assessment_request: Option<ExactJson>,
    attester_receipt: Option<ExactJson>,
    assessment: Option<ExactJson>,
}

impl AttemptEvidence {
    fn validate(&self) -> Result<(), JournalError> {
        for document in [
            self.provider_receipt.as_ref(),
            self.candidate.as_ref(),
            self.assessment_request.as_ref(),
            self.attester_receipt.as_ref(),
            self.assessment.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            document.validate()?;
        }
        Ok(())
    }
}

/// Final resolution retained alongside all preceding evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttemptResolution {
    Admitted {
        admission_snapshot: ExactJson,
    },
    Withheld {
        decision: ExactJson,
    },
    Unable {
        from: AttemptPhase,
        failure: ExactJson,
    },
}

impl AttemptResolution {
    fn validate(&self) -> Result<(), JournalError> {
        match self {
            Self::Admitted { admission_snapshot } => admission_snapshot.validate(),
            Self::Withheld { decision } => decision.validate(),
            Self::Unable { from, failure } => {
                if !matches!(
                    from,
                    AttemptPhase::Prepared
                        | AttemptPhase::ProviderCaptured
                        | AttemptPhase::CandidateReady
                        | AttemptPhase::AttesterCaptured
                ) {
                    return Err(invalid(
                        "unable resolution must name a definitely non-running phase",
                    ));
                }
                failure.validate()
            }
        }
    }
}

/// Deterministic restart action. There is deliberately no generic retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    RetryProvider,
    ParkProviderUncertain,
    BuildCandidateFromCapture,
    ArmAttester,
    ParkAttesterUncertain,
    BuildAssessmentFromCapture,
    EvaluateAdmission,
    None,
}

/// One content-identified durable attempt checkpoint.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptCheckpoint {
    checkpoint_id: String,
    protocol: String,
    inputs: AttemptInputs,
    phase: AttemptPhase,
    evidence: AttemptEvidence,
    resolution: Option<AttemptResolution>,
}

impl AttemptCheckpoint {
    fn prepared(inputs: AttemptInputs) -> Result<Self, JournalError> {
        Self::from_parts(
            inputs,
            AttemptPhase::Prepared,
            AttemptEvidence::default(),
            None,
        )
    }

    /// Advance from `Prepared` to the durable pre-effect provider arm.
    ///
    /// # Errors
    ///
    /// Refuses any current phase other than `Prepared` or invalid retained state.
    pub fn arm_provider(&self) -> Result<Self, JournalError> {
        self.advance(AttemptPhase::ProviderArmed, self.evidence.clone(), None)
    }

    /// Retain the exact provider runtime receipt before interpreting it.
    ///
    /// # Errors
    ///
    /// Refuses any phase other than `ProviderArmed` or invalid receipt/state.
    pub fn capture_provider(&self, receipt: ExactJson) -> Result<Self, JournalError> {
        let mut evidence = self.evidence.clone();
        evidence.provider_receipt = Some(receipt);
        self.advance(AttemptPhase::ProviderCaptured, evidence, None)
    }

    /// Retain the validated semantic candidate derived from provider capture.
    ///
    /// # Errors
    ///
    /// Refuses any phase other than `ProviderCaptured` or invalid evidence.
    pub fn candidate_ready(&self, candidate: ExactJson) -> Result<Self, JournalError> {
        let mut evidence = self.evidence.clone();
        evidence.candidate = Some(candidate);
        self.advance(AttemptPhase::CandidateReady, evidence, None)
    }

    /// Durably arm the exact assessment request before attester execution.
    ///
    /// # Errors
    ///
    /// Refuses any phase other than `CandidateReady` or invalid evidence.
    pub fn arm_attester(&self, assessment_request: ExactJson) -> Result<Self, JournalError> {
        let mut evidence = self.evidence.clone();
        evidence.assessment_request = Some(assessment_request);
        self.advance(AttemptPhase::AttesterArmed, evidence, None)
    }

    /// Retain the exact attester runtime receipt before interpreting it.
    ///
    /// # Errors
    ///
    /// Refuses any phase other than `AttesterArmed` or invalid receipt/state.
    pub fn capture_attester(&self, receipt: ExactJson) -> Result<Self, JournalError> {
        let mut evidence = self.evidence.clone();
        evidence.attester_receipt = Some(receipt);
        self.advance(AttemptPhase::AttesterCaptured, evidence, None)
    }

    /// Retain the validated assessment derived from attester capture.
    ///
    /// # Errors
    ///
    /// Refuses any phase other than `AttesterCaptured` or invalid evidence.
    pub fn assessment_ready(&self, assessment: ExactJson) -> Result<Self, JournalError> {
        let mut evidence = self.evidence.clone();
        evidence.assessment = Some(assessment);
        self.advance(AttemptPhase::AssessmentReady, evidence, None)
    }

    /// Resolve the complete evidence chain as admitted.
    ///
    /// # Errors
    ///
    /// Refuses any phase other than `AssessmentReady` or invalid evidence.
    pub fn admitted(&self, admission_snapshot: ExactJson) -> Result<Self, JournalError> {
        self.advance(
            AttemptPhase::Admitted,
            self.evidence.clone(),
            Some(AttemptResolution::Admitted { admission_snapshot }),
        )
    }

    /// Resolve the complete evidence chain as withheld.
    ///
    /// # Errors
    ///
    /// Refuses any phase other than `AssessmentReady` or invalid evidence.
    pub fn withheld(&self, decision: ExactJson) -> Result<Self, JournalError> {
        self.advance(
            AttemptPhase::Withheld,
            self.evidence.clone(),
            Some(AttemptResolution::Withheld { decision }),
        )
    }

    /// Resolve a definitely non-running phase as unable.
    ///
    /// # Errors
    ///
    /// Refuses armed, terminal, or otherwise non-resolvable phases.
    pub fn unable(&self, failure: ExactJson) -> Result<Self, JournalError> {
        self.advance(
            AttemptPhase::Unable,
            self.evidence.clone(),
            Some(AttemptResolution::Unable {
                from: self.phase,
                failure,
            }),
        )
    }

    /// Revalidate protocol, immutable inputs, monotonic evidence shape, and ID.
    ///
    /// # Errors
    ///
    /// Refuses any malformed, incompatible, non-monotonic, or identity-drifting state.
    pub fn validate(&self) -> Result<(), JournalError> {
        if self.protocol != CHECKPOINT_PROTOCOL {
            return Err(invalid(format!(
                "unsupported checkpoint protocol `{}`",
                self.protocol
            )));
        }
        self.inputs.validate()?;
        self.evidence.validate()?;
        if let Some(resolution) = &self.resolution {
            resolution.validate()?;
        }
        validate_phase_shape(self.phase, &self.evidence, self.resolution.as_ref())?;
        validate_sha256("checkpoint identity", &self.checkpoint_id)?;
        let actual = self.derived_id()?;
        if self.checkpoint_id != actual {
            return Err(JournalError::ContentIdentityMismatch {
                document: "attempt checkpoint",
                expected: self.checkpoint_id.clone(),
                actual,
            });
        }
        validate_checkpoint_size(self)
    }

    /// Exact checkpoint content identity used for journal CAS.
    #[must_use]
    pub fn checkpoint_id(&self) -> &str {
        &self.checkpoint_id
    }

    /// Immutable attempt inputs.
    #[must_use]
    pub const fn inputs(&self) -> &AttemptInputs {
        &self.inputs
    }

    /// Current closed phase.
    #[must_use]
    pub const fn phase(&self) -> AttemptPhase {
        self.phase
    }

    /// Provider runtime receipt, once captured.
    #[must_use]
    pub const fn provider_receipt(&self) -> Option<&ExactJson> {
        self.evidence.provider_receipt.as_ref()
    }

    /// Candidate, once validated.
    #[must_use]
    pub const fn candidate(&self) -> Option<&ExactJson> {
        self.evidence.candidate.as_ref()
    }

    /// Exact assessment request, once the attester is armed.
    #[must_use]
    pub const fn assessment_request(&self) -> Option<&ExactJson> {
        self.evidence.assessment_request.as_ref()
    }

    /// Attester runtime receipt, once captured.
    #[must_use]
    pub const fn attester_receipt(&self) -> Option<&ExactJson> {
        self.evidence.attester_receipt.as_ref()
    }

    /// Validated assessment, once derived from its receipt.
    #[must_use]
    pub const fn assessment(&self) -> Option<&ExactJson> {
        self.evidence.assessment.as_ref()
    }

    /// Terminal resolution, if any.
    #[must_use]
    pub const fn resolution(&self) -> Option<&AttemptResolution> {
        self.resolution.as_ref()
    }

    /// Conservative action after independently loading this checkpoint.
    #[must_use]
    pub const fn recovery_action(&self) -> RecoveryAction {
        match self.phase {
            AttemptPhase::Prepared => RecoveryAction::RetryProvider,
            AttemptPhase::ProviderArmed => RecoveryAction::ParkProviderUncertain,
            AttemptPhase::ProviderCaptured => RecoveryAction::BuildCandidateFromCapture,
            AttemptPhase::CandidateReady => RecoveryAction::ArmAttester,
            AttemptPhase::AttesterArmed => RecoveryAction::ParkAttesterUncertain,
            AttemptPhase::AttesterCaptured => RecoveryAction::BuildAssessmentFromCapture,
            AttemptPhase::AssessmentReady => RecoveryAction::EvaluateAdmission,
            AttemptPhase::Admitted | AttemptPhase::Withheld | AttemptPhase::Unable => {
                RecoveryAction::None
            }
        }
    }

    fn advance(
        &self,
        phase: AttemptPhase,
        evidence: AttemptEvidence,
        resolution: Option<AttemptResolution>,
    ) -> Result<Self, JournalError> {
        self.validate()?;
        validate_transition(self.phase, phase)?;
        if !evidence_extends(&self.evidence, &evidence) {
            return Err(JournalError::EvidenceChanged);
        }
        Self::from_parts(self.inputs.clone(), phase, evidence, resolution)
    }

    fn from_parts(
        inputs: AttemptInputs,
        phase: AttemptPhase,
        evidence: AttemptEvidence,
        resolution: Option<AttemptResolution>,
    ) -> Result<Self, JournalError> {
        let mut checkpoint = Self {
            checkpoint_id: placeholder_identity(),
            protocol: CHECKPOINT_PROTOCOL.to_owned(),
            inputs,
            phase,
            evidence,
            resolution,
        };
        checkpoint.inputs.validate()?;
        checkpoint.evidence.validate()?;
        if let Some(resolution) = &checkpoint.resolution {
            resolution.validate()?;
        }
        validate_phase_shape(
            checkpoint.phase,
            &checkpoint.evidence,
            checkpoint.resolution.as_ref(),
        )?;
        checkpoint.checkpoint_id = checkpoint.derived_id()?;
        validate_checkpoint_size(&checkpoint)?;
        Ok(checkpoint)
    }

    fn derived_id(&self) -> Result<String, JournalError> {
        #[derive(Serialize)]
        struct Body<'a> {
            protocol: &'a str,
            inputs: &'a AttemptInputs,
            phase: AttemptPhase,
            evidence: &'a AttemptEvidence,
            resolution: Option<&'a AttemptResolution>,
        }
        document_digest(&Body {
            protocol: &self.protocol,
            inputs: &self.inputs,
            phase: self.phase,
            evidence: &self.evidence,
            resolution: self.resolution.as_ref(),
        })
    }
}

fn validate_transition(from: AttemptPhase, to: AttemptPhase) -> Result<(), JournalError> {
    let valid = matches!(
        (from, to),
        (
            AttemptPhase::Prepared,
            AttemptPhase::ProviderArmed | AttemptPhase::Unable
        ) | (AttemptPhase::ProviderArmed, AttemptPhase::ProviderCaptured)
            | (
                AttemptPhase::ProviderCaptured,
                AttemptPhase::CandidateReady | AttemptPhase::Unable
            )
            | (
                AttemptPhase::CandidateReady,
                AttemptPhase::AttesterArmed | AttemptPhase::Unable
            )
            | (AttemptPhase::AttesterArmed, AttemptPhase::AttesterCaptured)
            | (
                AttemptPhase::AttesterCaptured,
                AttemptPhase::AssessmentReady | AttemptPhase::Unable
            )
            | (
                AttemptPhase::AssessmentReady,
                AttemptPhase::Admitted | AttemptPhase::Withheld
            )
    );
    if valid {
        Ok(())
    } else {
        Err(JournalError::InvalidTransition { from, to })
    }
}

fn validate_phase_shape(
    phase: AttemptPhase,
    evidence: &AttemptEvidence,
    resolution: Option<&AttemptResolution>,
) -> Result<(), JournalError> {
    let fields = [
        evidence.provider_receipt.is_some(),
        evidence.candidate.is_some(),
        evidence.assessment_request.is_some(),
        evidence.attester_receipt.is_some(),
        evidence.assessment.is_some(),
    ];
    let expected = match phase {
        AttemptPhase::Prepared | AttemptPhase::ProviderArmed => [false; 5],
        AttemptPhase::ProviderCaptured => [true, false, false, false, false],
        AttemptPhase::CandidateReady => [true, true, false, false, false],
        AttemptPhase::AttesterArmed => [true, true, true, false, false],
        AttemptPhase::AttesterCaptured => [true, true, true, true, false],
        AttemptPhase::AssessmentReady | AttemptPhase::Admitted | AttemptPhase::Withheld => {
            [true; 5]
        }
        AttemptPhase::Unable => match resolution {
            Some(AttemptResolution::Unable { from, .. }) => match from {
                AttemptPhase::Prepared => [false; 5],
                AttemptPhase::ProviderCaptured => [true, false, false, false, false],
                AttemptPhase::CandidateReady => [true, true, false, false, false],
                AttemptPhase::AttesterCaptured => [true, true, true, true, false],
                _ => return Err(invalid("unable resolution names an invalid origin phase")),
            },
            _ => return Err(invalid("unable phase requires one unable resolution")),
        },
    };
    if fields != expected {
        return Err(invalid(format!(
            "phase {phase:?} has an invalid monotonic evidence shape"
        )));
    }

    let resolution_matches = matches!(
        (phase, resolution),
        (
            AttemptPhase::Prepared
                | AttemptPhase::ProviderArmed
                | AttemptPhase::ProviderCaptured
                | AttemptPhase::CandidateReady
                | AttemptPhase::AttesterArmed
                | AttemptPhase::AttesterCaptured
                | AttemptPhase::AssessmentReady,
            None
        ) | (
            AttemptPhase::Admitted,
            Some(AttemptResolution::Admitted { .. })
        ) | (
            AttemptPhase::Withheld,
            Some(AttemptResolution::Withheld { .. })
        ) | (AttemptPhase::Unable, Some(AttemptResolution::Unable { .. }))
    );
    if !resolution_matches {
        return Err(invalid("phase and terminal resolution disagree"));
    }
    Ok(())
}

fn evidence_extends(previous: &AttemptEvidence, next: &AttemptEvidence) -> bool {
    fn unchanged_or_added(previous: Option<&ExactJson>, next: Option<&ExactJson>) -> bool {
        match (previous, next) {
            (None, _) => true,
            (Some(previous), Some(next)) => previous.digest == next.digest,
            (Some(_), None) => false,
        }
    }
    unchanged_or_added(
        previous.provider_receipt.as_ref(),
        next.provider_receipt.as_ref(),
    ) && unchanged_or_added(previous.candidate.as_ref(), next.candidate.as_ref())
        && unchanged_or_added(
            previous.assessment_request.as_ref(),
            next.assessment_request.as_ref(),
        )
        && unchanged_or_added(
            previous.attester_receipt.as_ref(),
            next.attester_receipt.as_ref(),
        )
        && unchanged_or_added(previous.assessment.as_ref(), next.assessment.as_ref())
}

/// One attempt journal isolated in its own owner-only directory.
#[derive(Clone, Debug)]
pub struct AttemptJournal {
    directory_path: PathBuf,
    path: PathBuf,
    directory: Arc<File>,
}

impl AttemptJournal {
    /// Open and retain one private journal directory and stable internal lock.
    ///
    /// The requested directory is created atomically when absent. Its parent is
    /// never created, neither the directory nor its parent may be a final-path
    /// symlink, and the journal directory must be owner-only. Fixed internal
    /// names cannot collide with another journal because every journal has a
    /// distinct directory authority.
    ///
    /// # Errors
    ///
    /// Refuses unsafe paths, filesystem authority, or lock metadata.
    pub fn new(directory_path: impl Into<PathBuf>) -> Result<Self, JournalError> {
        let directory_path = directory_path.into();
        let directory_name = directory_path
            .file_name()
            .ok_or_else(|| {
                invalid_filesystem(&directory_path, "journal path must name one directory")
            })?
            .to_os_string();
        let parent_path = directory_path
            .parent()
            .filter(|value| !value.as_os_str().is_empty());
        let parent_path = parent_path.unwrap_or_else(|| Path::new("."));
        let parent = File::from(
            open(
                parent_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| filesystem("open journal parent", parent_path, &error))?,
        );
        let created = match mkdirat(
            &parent,
            &directory_name,
            Mode::RUSR | Mode::WUSR | Mode::XUSR,
        ) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(error) => {
                return Err(filesystem(
                    "create private journal directory",
                    &directory_path,
                    &error,
                ));
            }
        };
        let directory = File::from(
            openat(
                &parent,
                &directory_name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| {
                filesystem("open private journal directory", &directory_path, &error)
            })?,
        );
        validate_authority_directory(&directory, &directory_path)?;
        if created {
            parent
                .sync_all()
                .map_err(|error| io_error("synchronize journal parent", &directory_path, error))?;
        }
        let path = directory_path.join(CHECKPOINT_NAME);
        let journal = Self {
            directory_path,
            path,
            directory: Arc::new(directory),
        };
        let lock = journal.open_lock()?;
        flock(&lock, FlockOperation::LockExclusive)
            .map_err(|error| filesystem("lock journal authority", &journal.path, &error))?;
        validate_authority_file(&lock, &journal.path, "journal lock")?;
        Ok(journal)
    }

    /// User-facing checkpoint path. Operations remain anchored to the retained
    /// private-directory descriptor rather than resolving this path again.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// User-facing private journal directory.
    #[must_use]
    pub fn directory_path(&self) -> &Path {
        &self.directory_path
    }

    /// Atomically create the required initial `Prepared` checkpoint.
    ///
    /// This API takes immutable inputs rather than an arbitrary checkpoint, so
    /// no caller can first-publish post-effect or terminal state.
    ///
    /// # Errors
    ///
    /// Refuses existing state or any invalid input/publication invariant.
    pub fn create(&self, inputs: AttemptInputs) -> Result<AttemptCheckpoint, JournalError> {
        let checkpoint = AttemptCheckpoint::prepared(inputs)?;
        let _lock = self.exclusive_lock()?;
        match self.load_unlocked() {
            Err(JournalError::Missing(_)) => {}
            Ok(_) => return Err(JournalError::AlreadyExists(self.path.clone())),
            Err(error) => return Err(error),
        }
        self.persist_unlocked(&checkpoint, Publication::Create)?;
        self.verify_unlocked(&checkpoint)?;
        Ok(checkpoint)
    }

    /// Load canonical checkpoint bytes under the stable journal lock.
    ///
    /// # Errors
    ///
    /// Refuses missing, symlinked, hard-linked, permissively writable,
    /// non-canonical, oversized, corrupt, or identity-drifting state.
    pub fn load(&self) -> Result<AttemptCheckpoint, JournalError> {
        let _lock = self.exclusive_lock()?;
        self.load_unlocked()
    }

    /// Atomically compare-and-swap one exact prior checkpoint to one legal next
    /// phase while retaining all prior evidence.
    ///
    /// # Errors
    ///
    /// Refuses stale identities, immutable-input changes, evidence changes,
    /// illegal transitions, or any persistence invariant failure.
    pub fn replace(
        &self,
        expected_checkpoint_id: &str,
        next: &AttemptCheckpoint,
    ) -> Result<(), JournalError> {
        let _lock = self.exclusive_lock()?;
        let current = self.load_unlocked()?;
        if current.checkpoint_id != expected_checkpoint_id {
            return Err(JournalError::StaleCheckpoint {
                expected: expected_checkpoint_id.to_owned(),
                actual: current.checkpoint_id,
            });
        }
        if current.inputs != next.inputs {
            return Err(JournalError::ImmutableInputsChanged);
        }
        next.validate()?;
        validate_transition(current.phase, next.phase)?;
        if !evidence_extends(&current.evidence, &next.evidence) {
            return Err(JournalError::EvidenceChanged);
        }
        self.persist_unlocked(next, Publication::Replace)?;
        self.verify_unlocked(next)
    }

    fn exclusive_lock(&self) -> Result<File, JournalError> {
        let lock = self.open_lock()?;
        flock(&lock, FlockOperation::LockExclusive)
            .map_err(|error| filesystem("lock journal authority", &self.path, &error))?;
        validate_authority_file(&lock, &self.path, "journal lock")?;
        Ok(lock)
    }

    fn open_lock(&self) -> Result<File, JournalError> {
        let lock = File::from(
            openat(
                &*self.directory,
                LOCK_NAME,
                OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|error| filesystem("open stable journal lock", &self.path, &error))?,
        );
        validate_authority_file(&lock, &self.path, "journal lock")?;
        Ok(lock)
    }

    fn load_unlocked(&self) -> Result<AttemptCheckpoint, JournalError> {
        let descriptor = openat(
            &*self.directory,
            CHECKPOINT_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| {
            if error == rustix::io::Errno::NOENT {
                JournalError::Missing(self.path.clone())
            } else {
                filesystem("open checkpoint", &self.path, &error)
            }
        })?;
        let mut file = File::from(descriptor);
        validate_authority_file(&file, &self.path, "checkpoint")?;
        let metadata = file
            .metadata()
            .map_err(|error| io_error("inspect checkpoint", &self.path, error))?;
        if metadata.len() > MAX_CHECKPOINT_BYTES as u64 {
            return Err(invalid_filesystem(
                &self.path,
                format!(
                    "checkpoint length {} exceeds {MAX_CHECKPOINT_BYTES} bytes",
                    metadata.len()
                ),
            ));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| {
            invalid_filesystem(&self.path, "checkpoint length cannot fit in memory")
        })?);
        Read::by_ref(&mut file)
            .take(MAX_CHECKPOINT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("read checkpoint", &self.path, error))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != metadata.len() {
            return Err(invalid_filesystem(
                &self.path,
                "checkpoint changed length while being read",
            ));
        }
        let checkpoint: AttemptCheckpoint =
            serde_json::from_slice(&bytes).map_err(|error| JournalError::Decode {
                path: self.path.clone(),
                detail: error.to_string(),
            })?;
        if bytes != canonical_bytes(&checkpoint)? {
            return Err(JournalError::NonCanonical(self.path.clone()));
        }
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    fn persist_unlocked(
        &self,
        checkpoint: &AttemptCheckpoint,
        publication: Publication,
    ) -> Result<(), JournalError> {
        checkpoint.validate()?;
        let bytes = canonical_bytes(checkpoint)?;
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(invalid(format!(
                "checkpoint exceeds {MAX_CHECKPOINT_BYTES} bytes"
            )));
        }

        match unlinkat(&*self.directory, TEMPORARY_NAME, AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => {
                return Err(filesystem(
                    "remove stale bounded checkpoint sibling",
                    &self.path,
                    &error,
                ));
            }
        }
        let mut temporary = TemporarySibling::create(
            Arc::clone(&self.directory),
            OsString::from(TEMPORARY_NAME),
            &self.path,
        )?;
        temporary
            .file
            .write_all(&bytes)
            .map_err(|error| io_error("write checkpoint sibling", &self.path, error))?;
        temporary
            .file
            .flush()
            .map_err(|error| io_error("flush checkpoint sibling", &self.path, error))?;
        temporary
            .file
            .sync_all()
            .map_err(|error| io_error("synchronize checkpoint sibling", &self.path, error))?;

        let flags = match publication {
            Publication::Create => RenameFlags::NOREPLACE,
            Publication::Replace => RenameFlags::empty(),
        };
        renameat_with(
            &*self.directory,
            TEMPORARY_NAME,
            &*self.directory,
            CHECKPOINT_NAME,
            flags,
        )
        .map_err(|error| {
            if matches!(publication, Publication::Create)
                && matches!(
                    error,
                    rustix::io::Errno::EXIST | rustix::io::Errno::NOTEMPTY
                )
            {
                JournalError::AlreadyExists(self.path.clone())
            } else {
                filesystem("atomically publish checkpoint", &self.path, &error)
            }
        })?;
        temporary.armed = false;
        self.directory
            .sync_all()
            .map_err(|error| io_error("synchronize journal parent", &self.path, error))
    }

    fn verify_unlocked(&self, expected: &AttemptCheckpoint) -> Result<(), JournalError> {
        let actual = self.load_unlocked()?;
        if actual.checkpoint_id != expected.checkpoint_id || actual != *expected {
            return Err(JournalError::PublishedCheckpointMismatch {
                expected: expected.checkpoint_id.clone(),
                actual: actual.checkpoint_id,
            });
        }
        Ok(())
    }
}

fn validate_checkpoint_size(checkpoint: &AttemptCheckpoint) -> Result<(), JournalError> {
    let length = canonical_bytes(checkpoint)?.len();
    if length > MAX_CHECKPOINT_BYTES {
        return Err(invalid(format!(
            "checkpoint length {length} exceeds {MAX_CHECKPOINT_BYTES} bytes"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Publication {
    Create,
    Replace,
}

struct TemporarySibling {
    parent: Arc<File>,
    name: OsString,
    file: File,
    armed: bool,
}

impl TemporarySibling {
    fn create(
        parent: Arc<File>,
        name: OsString,
        display_path: &Path,
    ) -> Result<Self, JournalError> {
        let file = File::from(
            openat(
                &*parent,
                &name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|error| filesystem("create checkpoint sibling", display_path, &error))?,
        );
        validate_authority_file(&file, display_path, "checkpoint sibling")?;
        Ok(Self {
            parent,
            name,
            file,
            armed: true,
        })
    }
}

impl Drop for TemporarySibling {
    fn drop(&mut self) {
        if self.armed {
            let _ignored = unlinkat(&*self.parent, &self.name, AtFlags::empty());
        }
    }
}

fn validate_authority_file(
    file: &File,
    display_path: &Path,
    label: &'static str,
) -> Result<(), JournalError> {
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect authority file", display_path, error))?;
    if !metadata.is_file() {
        return Err(invalid_filesystem(
            display_path,
            format!("{label} is not a regular file"),
        ));
    }
    if metadata.nlink() != 1 {
        return Err(invalid_filesystem(
            display_path,
            format!("{label} must have exactly one filesystem link"),
        ));
    }
    if metadata.uid() != geteuid().as_raw() {
        return Err(invalid_filesystem(
            display_path,
            format!("{label} is not owned by the effective user"),
        ));
    }
    if metadata.mode() & 0o777 != 0o600 {
        return Err(invalid_filesystem(
            display_path,
            format!("{label} permissions must be exactly 0600"),
        ));
    }
    Ok(())
}

fn validate_authority_directory(directory: &File, display_path: &Path) -> Result<(), JournalError> {
    let metadata = directory
        .metadata()
        .map_err(|error| io_error("inspect journal directory", display_path, error))?;
    if !metadata.is_dir() {
        return Err(invalid_filesystem(
            display_path,
            "journal authority is not a directory",
        ));
    }
    if metadata.uid() != geteuid().as_raw() {
        return Err(invalid_filesystem(
            display_path,
            "journal directory is not owned by the effective user",
        ));
    }
    if metadata.mode() & 0o777 != 0o700 {
        return Err(invalid_filesystem(
            display_path,
            "journal directory permissions must be exactly 0700",
        ));
    }
    Ok(())
}

fn validate_json_number_domain(value: &Value) -> Result<(), JournalError> {
    match value {
        Value::Number(number) => {
            if let Some(unsigned) = number.as_u64() {
                if unsigned > MAX_SAFE_JSON_INTEGER {
                    return Err(invalid(format!(
                        "JSON integer {unsigned} exceeds the I-JSON exact integer domain"
                    )));
                }
            } else if let Some(signed) = number.as_i64() {
                if signed.unsigned_abs() > MAX_SAFE_JSON_INTEGER {
                    return Err(invalid(format!(
                        "JSON integer {signed} exceeds the I-JSON exact integer domain"
                    )));
                }
            } else if number.as_f64().is_none_or(|number| !number.is_finite()) {
                return Err(invalid("JSON number is not one finite IEEE-754 value"));
            }
        }
        Value::Array(items) => {
            for item in items {
                validate_json_number_domain(item)?;
            }
        }
        Value::Object(fields) => {
            for item in fields.values() {
                validate_json_number_domain(item)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) => {}
    }
    Ok(())
}

fn json_semantically_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => match (left.as_f64(), right.as_f64()) {
            (Some(left), Some(right)) => {
                left.to_bits() == right.to_bits()
                    || (left.to_bits().trailing_zeros() >= 63
                        && right.to_bits().trailing_zeros() >= 63)
            }
            _ => false,
        },
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| json_semantically_equal(left, right))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, left)| {
                    right
                        .get(key)
                        .is_some_and(|right| json_semantically_equal(left, right))
                })
        }
        _ => left == right,
    }
}

fn validate_opaque_id(label: &'static str, value: &str) -> Result<(), JournalError> {
    if value.is_empty()
        || value.len() > MAX_OPAQUE_ID_BYTES
        || value.trim() != value
        || value.chars().any(char::is_whitespace)
    {
        return Err(invalid(format!(
            "{label} must be one non-empty exact opaque identifier"
        )));
    }
    Ok(())
}

fn validate_sha256(label: &'static str, value: &str) -> Result<(), JournalError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(invalid(format!("{label} must use sha256 identity syntax")));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "{label} must contain 64 lowercase hexadecimal digits"
        )));
    }
    Ok(())
}

fn placeholder_identity() -> String {
    format!("sha256:{}", "0".repeat(64))
}

fn sha256_identity(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn document_digest(value: &impl Serialize) -> Result<String, JournalError> {
    Ok(sha256_identity(&canonical_bytes(value)?))
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, JournalError> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|error| JournalError::Canonicalization(error.to_string()))
}

fn invalid(detail: impl Into<String>) -> JournalError {
    JournalError::InvalidDocument(detail.into())
}

fn invalid_filesystem(path: &Path, detail: impl Into<String>) -> JournalError {
    JournalError::InvalidFilesystemState {
        path: path.to_path_buf(),
        detail: detail.into(),
    }
}

fn filesystem(action: &'static str, path: &Path, error: &impl ToString) -> JournalError {
    JournalError::Filesystem {
        action,
        path: path.to_path_buf(),
        detail: error.to_string(),
    }
}

fn io_error(action: &'static str, path: &Path, source: std::io::Error) -> JournalError {
    JournalError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

/// Closed errors returned by the proof-local checkpoint journal.
#[derive(Debug)]
pub enum JournalError {
    InvalidDocument(String),
    ContentIdentityMismatch {
        document: &'static str,
        expected: String,
        actual: String,
    },
    InvalidTransition {
        from: AttemptPhase,
        to: AttemptPhase,
    },
    EvidenceChanged,
    ImmutableInputsChanged,
    StaleCheckpoint {
        expected: String,
        actual: String,
    },
    PublishedCheckpointMismatch {
        expected: String,
        actual: String,
    },
    Missing(PathBuf),
    AlreadyExists(PathBuf),
    NonCanonical(PathBuf),
    Decode {
        path: PathBuf,
        detail: String,
    },
    Canonicalization(String),
    InvalidFilesystemState {
        path: PathBuf,
        detail: String,
    },
    Filesystem {
        action: &'static str,
        path: PathBuf,
        detail: String,
    },
    Io {
        action: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDocument(detail) => write!(formatter, "invalid checkpoint: {detail}"),
            Self::ContentIdentityMismatch {
                document,
                expected,
                actual,
            } => write!(
                formatter,
                "{document} identity mismatch: expected {expected}, measured {actual}"
            ),
            Self::InvalidTransition { from, to } => {
                write!(
                    formatter,
                    "attempt transition {from:?} -> {to:?} is not permitted"
                )
            }
            Self::EvidenceChanged => {
                formatter.write_str("attempt transition changed or removed retained evidence")
            }
            Self::ImmutableInputsChanged => {
                formatter.write_str("attempt transition changed immutable inputs")
            }
            Self::StaleCheckpoint { expected, actual } => write!(
                formatter,
                "checkpoint compare-and-swap is stale: expected {expected}, found {actual}"
            ),
            Self::PublishedCheckpointMismatch { expected, actual } => write!(
                formatter,
                "published checkpoint mismatch: expected {expected}, loaded {actual}"
            ),
            Self::Missing(path) => write!(formatter, "checkpoint {} is missing", path.display()),
            Self::AlreadyExists(path) => {
                write!(formatter, "checkpoint {} already exists", path.display())
            }
            Self::NonCanonical(path) => write!(
                formatter,
                "checkpoint {} is not canonical JSON",
                path.display()
            ),
            Self::Decode { path, detail } => {
                write!(
                    formatter,
                    "could not decode checkpoint {}: {detail}",
                    path.display()
                )
            }
            Self::Canonicalization(detail) => {
                write!(formatter, "could not canonicalize checkpoint: {detail}")
            }
            Self::InvalidFilesystemState { path, detail } => write!(
                formatter,
                "unsafe checkpoint filesystem state at {}: {detail}",
                path.display()
            ),
            Self::Filesystem {
                action,
                path,
                detail,
            } => write!(formatter, "could not {action} {}: {detail}", path.display()),
            Self::Io {
                action,
                path,
                source,
            } => write!(formatter, "could not {action} {}: {source}", path.display()),
        }
    }
}

impl Error for JournalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn digest(byte: u8) -> String {
        format!("sha256:{}", format!("{byte:02x}").repeat(32))
    }

    fn exact(label: &str) -> ExactJson {
        ExactJson::new(serde_json::json!({ "label": label })).expect("exact JSON")
    }

    fn deployment(name: &str, byte: u8) -> DeploymentLock {
        DeploymentLock::new(
            format!("org.gooi.implementation.{name}@1.0.0"),
            format!("org.gooi.package.{name}@1.0.0"),
            digest(byte),
            format!("{name}-module"),
            digest(byte + 1),
        )
        .expect("deployment lock")
    }

    fn inputs() -> AttemptInputs {
        AttemptInputs::new(UnboundAttemptInputs {
            semantic_plan: exact("semantic-plan"),
            invocation: exact("invocation"),
            baseline_snapshot: exact("baseline-snapshot"),
            conformance_suite: "org.gooi.suite.example@1.0.0".to_owned(),
            provider: deployment("provider", 1),
            attester: deployment("attester", 3),
            execution_policy: exact("execution-policy"),
            admission_policy: exact("admission-policy"),
        })
        .expect("attempt inputs")
    }

    fn journal(temporary: &tempfile::TempDir) -> AttemptJournal {
        AttemptJournal::new(temporary.path().join("attempt.json")).expect("journal authority")
    }

    fn replace(
        journal: &AttemptJournal,
        current: &AttemptCheckpoint,
        next: AttemptCheckpoint,
    ) -> AttemptCheckpoint {
        journal
            .replace(current.checkpoint_id(), &next)
            .expect("replace checkpoint");
        assert_eq!(journal.load().expect("reload checkpoint"), next);
        next
    }

    #[test]
    fn exact_json_normalizes_harmless_numbers_and_rejects_unsafe_integers() {
        let exact = ExactJson::new(serde_json::json!({ "number": 1.0 })).expect("normalize");
        assert_eq!(exact.value, serde_json::json!({ "number": 1 }));
        exact.validate().expect("normal form validates");

        assert!(matches!(
            ExactJson::new(serde_json::json!({ "number": 9_007_199_254_740_993_u64 })),
            Err(JournalError::InvalidDocument(detail)) if detail.contains("I-JSON")
        ));

        let non_normal_value = serde_json::json!({ "number": 1.0 });
        let non_normal = ExactJson {
            digest: sha256_identity(&canonical_bytes(&non_normal_value).expect("canonical")),
            value: non_normal_value,
        };
        assert!(matches!(
            non_normal.validate(),
            Err(JournalError::InvalidDocument(detail)) if detail.contains("canonical-normal")
        ));
    }

    #[test]
    fn creation_publishes_only_prepared_owner_only_state() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let journal = journal(&temporary);

        let checkpoint = journal.create(inputs()).expect("create prepared");

        assert_eq!(checkpoint.phase(), AttemptPhase::Prepared);
        assert_eq!(checkpoint.recovery_action(), RecoveryAction::RetryProvider);
        assert_eq!(journal.load().expect("reload"), checkpoint);
        let metadata = fs::metadata(journal.path()).expect("checkpoint metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        let directory_metadata =
            fs::metadata(journal.directory_path()).expect("journal directory metadata");
        assert_eq!(directory_metadata.permissions().mode() & 0o777, 0o700);
        assert!(matches!(
            journal.create(inputs()),
            Err(JournalError::AlreadyExists(_))
        ));
    }

    #[test]
    fn complete_chain_retains_both_runtime_receipts_in_terminal_state() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let journal = journal(&temporary);
        let prepared = journal.create(inputs()).expect("prepared");
        let provider_armed = replace(&journal, &prepared, prepared.arm_provider().expect("arm"));
        let provider_receipt = exact("provider-receipt");
        let provider_captured = replace(
            &journal,
            &provider_armed,
            provider_armed
                .capture_provider(provider_receipt.clone())
                .expect("capture provider"),
        );
        let candidate = exact("candidate");
        let candidate_ready = replace(
            &journal,
            &provider_captured,
            provider_captured
                .candidate_ready(candidate.clone())
                .expect("candidate"),
        );
        let assessment_request = exact("assessment-request");
        let attester_armed = replace(
            &journal,
            &candidate_ready,
            candidate_ready
                .arm_attester(assessment_request.clone())
                .expect("arm attester"),
        );
        let attester_receipt = exact("attester-receipt");
        let attester_captured = replace(
            &journal,
            &attester_armed,
            attester_armed
                .capture_attester(attester_receipt.clone())
                .expect("capture attester"),
        );
        let assessment = exact("assessment");
        let assessment_ready = replace(
            &journal,
            &attester_captured,
            attester_captured
                .assessment_ready(assessment.clone())
                .expect("assessment"),
        );
        let admitted = replace(
            &journal,
            &assessment_ready,
            assessment_ready
                .admitted(exact("admission-snapshot"))
                .expect("admit"),
        );

        assert_eq!(admitted.phase(), AttemptPhase::Admitted);
        assert_eq!(admitted.provider_receipt(), Some(&provider_receipt));
        assert_eq!(admitted.candidate(), Some(&candidate));
        assert_eq!(admitted.assessment_request(), Some(&assessment_request));
        assert_eq!(admitted.attester_receipt(), Some(&attester_receipt));
        assert_eq!(admitted.assessment(), Some(&assessment));
        assert_eq!(admitted.recovery_action(), RecoveryAction::None);
    }

    #[test]
    fn armed_phases_park_and_cannot_be_erased_as_unable() {
        let inputs = inputs();
        let prepared = AttemptCheckpoint::prepared(inputs).expect("prepared");
        let provider_armed = prepared.arm_provider().expect("provider armed");
        assert_eq!(
            provider_armed.recovery_action(),
            RecoveryAction::ParkProviderUncertain
        );
        assert!(matches!(
            provider_armed.unable(exact("failure")),
            Err(JournalError::InvalidTransition {
                from: AttemptPhase::ProviderArmed,
                to: AttemptPhase::Unable
            })
        ));

        let attester_armed = provider_armed
            .capture_provider(exact("provider-receipt"))
            .expect("provider capture")
            .candidate_ready(exact("candidate"))
            .expect("candidate")
            .arm_attester(exact("assessment-request"))
            .expect("attester armed");
        assert_eq!(
            attester_armed.recovery_action(),
            RecoveryAction::ParkAttesterUncertain
        );
        assert!(matches!(
            attester_armed.unable(exact("failure")),
            Err(JournalError::InvalidTransition {
                from: AttemptPhase::AttesterArmed,
                to: AttemptPhase::Unable
            })
        ));
    }

    #[test]
    fn captured_phases_resume_without_relaunch() {
        let prepared = AttemptCheckpoint::prepared(inputs()).expect("prepared");
        let provider_captured = prepared
            .arm_provider()
            .expect("arm")
            .capture_provider(exact("provider-receipt"))
            .expect("capture");
        assert_eq!(
            provider_captured.recovery_action(),
            RecoveryAction::BuildCandidateFromCapture
        );
        let attester_captured = provider_captured
            .candidate_ready(exact("candidate"))
            .expect("candidate")
            .arm_attester(exact("request"))
            .expect("arm attester")
            .capture_attester(exact("attester-receipt"))
            .expect("capture attester");
        assert_eq!(
            attester_captured.recovery_action(),
            RecoveryAction::BuildAssessmentFromCapture
        );
    }

    #[test]
    fn stable_lock_makes_replace_a_real_compare_and_swap() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let journal = journal(&temporary);
        let prepared = journal.create(inputs()).expect("prepared");
        let next = prepared.arm_provider().expect("arm");
        let barrier = Arc::new(Barrier::new(3));

        let actors: Vec<_> = (0..2)
            .map(|_| {
                let journal = journal.clone();
                let expected = prepared.checkpoint_id().to_owned();
                let next = next.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    journal.replace(&expected, &next)
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = actors
            .into_iter()
            .map(|actor| actor.join().expect("actor"))
            .collect();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(JournalError::StaleCheckpoint { .. })))
                .count(),
            1
        );
        assert_eq!(journal.load().expect("winner"), next);
    }

    #[test]
    fn one_fixed_stale_sibling_is_cleaned_under_lock() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let journal = journal(&temporary);
        let prepared = journal.create(inputs()).expect("prepared");
        let stale = journal.directory_path().join(TEMPORARY_NAME);
        fs::write(&stale, b"crash residue").expect("stale sibling");

        let next = prepared.arm_provider().expect("arm");
        journal
            .replace(prepared.checkpoint_id(), &next)
            .expect("replace after residue");

        assert!(!stale.exists());
        assert_eq!(journal.load().expect("current"), next);
    }

    #[test]
    fn private_directories_make_journal_names_non_interfering() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let first = AttemptJournal::new(temporary.path().join("foo")).expect("first journal");
        // This was the first journal's temporary sidecar name in the rejected
        // shared-directory design. It is now an independent directory.
        let second =
            AttemptJournal::new(temporary.path().join(".foo.next")).expect("second journal");
        let first_prepared = first.create(inputs()).expect("first prepared");
        let second_prepared = second.create(inputs()).expect("second prepared");

        let first_armed = first_prepared.arm_provider().expect("first armed");
        first
            .replace(first_prepared.checkpoint_id(), &first_armed)
            .expect("advance first journal");

        assert_eq!(first.load().expect("first state"), first_armed);
        assert_eq!(second.load().expect("second state"), second_prepared);
        assert!(second.directory_path().is_dir());
    }

    #[test]
    fn maximum_retained_documents_fit_one_terminal_checkpoint() {
        let payload = "x".repeat(MAX_EXACT_JSON_BYTES - 32);
        let near_limit =
            ExactJson::new(serde_json::json!({ "payload": payload })).expect("near-limit JSON");
        let inputs = AttemptInputs::new(UnboundAttemptInputs {
            semantic_plan: near_limit.clone(),
            invocation: near_limit.clone(),
            baseline_snapshot: near_limit.clone(),
            conformance_suite: "org.gooi.suite.example@1.0.0".to_owned(),
            provider: deployment("provider", 1),
            attester: deployment("attester", 3),
            execution_policy: near_limit.clone(),
            admission_policy: near_limit.clone(),
        })
        .expect("maximum attempt inputs");
        let evidence = AttemptEvidence {
            provider_receipt: Some(near_limit.clone()),
            candidate: Some(near_limit.clone()),
            assessment_request: Some(near_limit.clone()),
            attester_receipt: Some(near_limit.clone()),
            assessment: Some(near_limit.clone()),
        };
        let checkpoint = AttemptCheckpoint::from_parts(
            inputs,
            AttemptPhase::Admitted,
            evidence,
            Some(AttemptResolution::Admitted {
                admission_snapshot: near_limit,
            }),
        )
        .expect("maximum terminal checkpoint");
        let length = canonical_bytes(&checkpoint)
            .expect("canonical checkpoint")
            .len();

        assert!(length <= MAX_CHECKPOINT_BYTES);
        assert!(length > 40 * 1024 * 1024);
        checkpoint.validate().expect("maximum checkpoint validates");
    }

    #[test]
    fn maximum_runtime_receipt_fits_one_exact_json_document() {
        use crate::wasm::{RUNTIME_ID, WasmExecutionPolicy, WasmReceipt, WasmTermination};

        let capture_bytes = crate::wasm::MAX_CAPTURE_BYTES;
        let receipt = WasmReceipt {
            runtime: RUNTIME_ID.to_owned(),
            execution_policy: WasmExecutionPolicy {
                timeout_nanoseconds: 1_000_000_000,
                fuel: crate::wasm::MAX_FUEL,
                memory_bytes: 1024 * 1024,
                table_elements: 1024,
                stdout_bytes: u64::try_from(capture_bytes).expect("capture bound fits u64"),
                stderr_bytes: u64::try_from(capture_bytes).expect("capture bound fits u64"),
            },
            module_digest: digest(7),
            stdin_digest: digest(8),
            termination: WasmTermination::Enforced {
                timed_out: false,
                fuel_exhausted: false,
                stdout_limit_reached: true,
                stderr_limit_reached: true,
            },
            stdin_bytes_provided: 5,
            stdout: vec![u8::MAX; capture_bytes],
            stderr: vec![u8::MAX; capture_bytes],
        };

        ExactJson::new(serde_json::to_value(receipt).expect("serialize receipt"))
            .expect("maximum receipt fits exact JSON");
    }

    #[test]
    fn unsafe_checkpoint_links_and_permissions_fail_closed() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let journal = journal(&temporary);
        journal.create(inputs()).expect("prepared");
        let alias = temporary.path().join("checkpoint-alias");
        fs::hard_link(journal.path(), &alias).expect("hard link");
        assert!(matches!(
            journal.load(),
            Err(JournalError::InvalidFilesystemState { detail, .. })
                if detail.contains("exactly one filesystem link")
        ));
        fs::remove_file(alias).expect("remove alias");

        fs::set_permissions(journal.path(), fs::Permissions::from_mode(0o644))
            .expect("make permissive");
        assert!(matches!(
            journal.load(),
            Err(JournalError::InvalidFilesystemState { detail, .. })
                if detail.contains("exactly 0600")
        ));
    }

    #[test]
    fn unknown_corrupt_and_noncanonical_documents_are_refused() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let journal = journal(&temporary);
        journal.create(inputs()).expect("prepared");
        fs::set_permissions(journal.path(), fs::Permissions::from_mode(0o600))
            .expect("writable test checkpoint");

        let mut value: Value =
            serde_json::from_slice(&fs::read(journal.path()).expect("checkpoint bytes"))
                .expect("checkpoint JSON");
        value
            .as_object_mut()
            .expect("object")
            .insert("unknown".to_owned(), Value::Bool(true));
        fs::write(journal.path(), serde_json::to_vec(&value).expect("JSON"))
            .expect("unknown checkpoint");
        assert!(matches!(journal.load(), Err(JournalError::Decode { .. })));

        fs::write(journal.path(), b"{ definitely not JSON").expect("corrupt checkpoint");
        assert!(matches!(journal.load(), Err(JournalError::Decode { .. })));
    }
}
