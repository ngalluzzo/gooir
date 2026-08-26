//! Durable apply/reobserve state for the Fleetd direct-conversation proof.
//!
//! This copies the filesystem publication discipline proven by
//! `gooir-datamodel-external-host-proof` without changing or generalizing that
//! crate. The state machine here is deliberately proof-local: it knows only
//! opaque exact documents, deployment coordinates, a non-secret target lock,
//! and bounded process-receipt evidence. Semantic receipt interpretation is a
//! later driver responsibility.

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

use crate::target::TargetBinding;

/// Exact proof-local checkpoint protocol.
pub const CHECKPOINT_PROTOCOL: &str =
    "org.gooi.proof.fleetd-direct-conversation-external-host-attempt/v1";

/// Fixed proof capacity for each apply or reobserve receipt prefix.
pub const RECEIPT_CAPACITY: usize = 2;

const MAX_CHECKPOINT_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const MAX_EXACT_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_OPAQUE_ID_BYTES: usize = 4 * 1024;
const MAX_SAFE_JSON_INTEGER: u64 = (1_u64 << 53) - 1;
const CHECKPOINT_NAME: &str = "checkpoint.json";
const LOCK_NAME: &str = "lock";
const TEMPORARY_NAME: &str = "checkpoint.next";

/// Canonical-normal JSON object bound to its RFC 8785/SHA-256 identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactJson {
    digest: String,
    value: Value,
}

impl ExactJson {
    /// Construct one bounded exact JSON object.
    ///
    /// # Errors
    ///
    /// Refuses non-objects, unsafe numeric values, canonicalization drift, or
    /// documents beyond the proof bound.
    pub fn new(value: impl Into<Value>) -> Result<Self, JournalError> {
        let value = value.into();
        validate_json_value(&value)?;
        let canonical = canonical_bytes(&value)?;
        if canonical.len() > MAX_EXACT_JSON_BYTES {
            return Err(invalid("exact JSON exceeds the proof bound"));
        }
        let normalized: Value = serde_json::from_slice(&canonical)
            .map_err(|error| invalid(format!("cannot reparse canonical JSON: {error}")))?;
        if value != normalized {
            return Err(invalid("canonical JSON changes the supplied value"));
        }
        let exact = Self {
            digest: sha256_identity(&canonical),
            value: normalized,
        };
        exact.validate()?;
        Ok(exact)
    }

    /// Exact document digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Canonical-normal JSON value.
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }

    /// Revalidate shape, bound, canonical-normal form, and identity.
    ///
    /// # Errors
    ///
    /// Refuses any malformed or identity-drifting document.
    pub fn validate(&self) -> Result<(), JournalError> {
        validate_json_value(&self.value)?;
        let canonical = canonical_bytes(&self.value)?;
        if canonical.len() > MAX_EXACT_JSON_BYTES {
            return Err(invalid("exact JSON exceeds the proof bound"));
        }
        let normalized: Value = serde_json::from_slice(&canonical)
            .map_err(|error| invalid(format!("cannot reparse canonical JSON: {error}")))?;
        if self.value != normalized {
            return Err(invalid("exact JSON is not canonical-normal"));
        }
        validate_sha256("exact JSON digest", &self.digest)?;
        let actual = sha256_identity(&canonical);
        if actual != self.digest {
            return Err(JournalError::ContentIdentityMismatch {
                document: "exact JSON",
                expected: self.digest.clone(),
                actual,
            });
        }
        Ok(())
    }
}

/// Exact installed command resource selected for one role.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentLock {
    implementation: String,
    package: String,
    package_digest: String,
    resource: String,
    resource_digest: String,
}

impl DeploymentLock {
    /// Construct one exact installed deployment coordinate.
    ///
    /// # Errors
    ///
    /// Refuses empty coordinates and malformed digests.
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

    /// Selected implementation identity.
    #[must_use]
    pub fn implementation(&self) -> &str {
        &self.implementation
    }

    /// Installed package identity.
    #[must_use]
    pub fn package(&self) -> &str {
        &self.package
    }

    /// Exact installed package digest.
    #[must_use]
    pub fn package_digest(&self) -> &str {
        &self.package_digest
    }

    /// Exact resource name within the installed package.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Exact installed resource digest.
    #[must_use]
    pub fn resource_digest(&self) -> &str {
        &self.resource_digest
    }

    fn validate(&self) -> Result<(), JournalError> {
        validate_opaque("implementation", &self.implementation)?;
        validate_opaque("package", &self.package)?;
        validate_sha256("package digest", &self.package_digest)?;
        validate_opaque("resource", &self.resource)?;
        validate_sha256("resource digest", &self.resource_digest)
    }
}

/// Exact native execution profile selected by trusted proof-host code.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRuntimeLock {
    runtime: String,
    runtime_digest: String,
}

impl NativeRuntimeLock {
    /// Construct one exact native runtime/profile lock.
    ///
    /// # Errors
    ///
    /// Refuses an empty runtime coordinate or malformed digest.
    pub fn new(
        runtime: impl Into<String>,
        runtime_digest: impl Into<String>,
    ) -> Result<Self, JournalError> {
        let lock = Self {
            runtime: runtime.into(),
            runtime_digest: runtime_digest.into(),
        };
        lock.validate()?;
        Ok(lock)
    }

    /// Closed proof-host runtime/profile coordinate.
    #[must_use]
    pub fn runtime(&self) -> &str {
        &self.runtime
    }

    /// Digest of the complete proof-local runtime qualification.
    #[must_use]
    pub fn runtime_digest(&self) -> &str {
        &self.runtime_digest
    }

    fn validate(&self) -> Result<(), JournalError> {
        validate_opaque("native runtime", &self.runtime)?;
        validate_sha256("native runtime digest", &self.runtime_digest)
    }
}

/// Caller-supplied immutable inputs before aggregate identity is derived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnboundAttemptInputs {
    pub semantic_plan: ExactJson,
    pub invocation: ExactJson,
    pub baseline_snapshot: ExactJson,
    pub conformance_suite: String,
    pub provider: DeploymentLock,
    pub attester: DeploymentLock,
    pub native_runtime: NativeRuntimeLock,
    pub target: TargetBinding,
    pub provider_replay_law: String,
    pub attester_replay_law: String,
    pub execution_policy: ExactJson,
    pub admission_policy: ExactJson,
}

/// Immutable, content-identified inputs for one complete attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptInputs {
    attempt_id: String,
    semantic_plan: ExactJson,
    invocation: ExactJson,
    baseline_snapshot: ExactJson,
    conformance_suite: String,
    provider: DeploymentLock,
    attester: DeploymentLock,
    native_runtime: NativeRuntimeLock,
    target: TargetBinding,
    provider_replay_law: String,
    attester_replay_law: String,
    execution_policy: ExactJson,
    admission_policy: ExactJson,
}

impl AttemptInputs {
    /// Bind every semantic, deployment, target, runtime, replay, and policy input.
    ///
    /// # Errors
    ///
    /// Refuses invalid children, provider self-attestation, or identity drift.
    pub fn new(unbound: UnboundAttemptInputs) -> Result<Self, JournalError> {
        let mut inputs = Self {
            attempt_id: placeholder_identity(),
            semantic_plan: unbound.semantic_plan,
            invocation: unbound.invocation,
            baseline_snapshot: unbound.baseline_snapshot,
            conformance_suite: unbound.conformance_suite,
            provider: unbound.provider,
            attester: unbound.attester,
            native_runtime: unbound.native_runtime,
            target: unbound.target,
            provider_replay_law: unbound.provider_replay_law,
            attester_replay_law: unbound.attester_replay_law,
            execution_policy: unbound.execution_policy,
            admission_policy: unbound.admission_policy,
        };
        inputs.validate_structure()?;
        inputs.attempt_id = inputs.derived_id()?;
        Ok(inputs)
    }

    /// Aggregate attempt identity.
    #[must_use]
    pub fn attempt_id(&self) -> &str {
        &self.attempt_id
    }

    /// Exact semantic plan selected before execution.
    #[must_use]
    pub const fn semantic_plan(&self) -> &ExactJson {
        &self.semantic_plan
    }

    /// Exact linked invocation supplied to the provider.
    #[must_use]
    pub const fn invocation(&self) -> &ExactJson {
        &self.invocation
    }

    /// Exact target baseline captured before execution.
    #[must_use]
    pub const fn baseline_snapshot(&self) -> &ExactJson {
        &self.baseline_snapshot
    }

    /// Exact conformance suite selected for independent assessment.
    #[must_use]
    pub fn conformance_suite(&self) -> &str {
        &self.conformance_suite
    }

    /// Exact selected provider deployment.
    #[must_use]
    pub const fn provider(&self) -> &DeploymentLock {
        &self.provider
    }

    /// Exact independently selected attester deployment.
    #[must_use]
    pub const fn attester(&self) -> &DeploymentLock {
        &self.attester
    }

    /// Complete proof-local native runtime commitment.
    #[must_use]
    pub const fn native_runtime(&self) -> &NativeRuntimeLock {
        &self.native_runtime
    }

    /// Exact non-secret target binding.
    #[must_use]
    pub const fn target(&self) -> &TargetBinding {
        &self.target
    }

    /// Exact trusted provider replay law.
    #[must_use]
    pub fn provider_replay_law(&self) -> &str {
        &self.provider_replay_law
    }

    /// Exact trusted attester replay law.
    #[must_use]
    pub fn attester_replay_law(&self) -> &str {
        &self.attester_replay_law
    }

    /// Exact bounded native execution policy interpreted by the proof host.
    #[must_use]
    pub const fn execution_policy(&self) -> &ExactJson {
        &self.execution_policy
    }

    /// Exact contextual admission policy applied after assessment.
    #[must_use]
    pub const fn admission_policy(&self) -> &ExactJson {
        &self.admission_policy
    }

    /// Revalidate all children and aggregate identity.
    ///
    /// # Errors
    ///
    /// Refuses malformed children or any changed authority input.
    pub fn validate(&self) -> Result<(), JournalError> {
        self.validate_structure()?;
        validate_sha256("attempt identity", &self.attempt_id)?;
        let actual = self.derived_id()?;
        if actual != self.attempt_id {
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
        validate_opaque("conformance suite", &self.conformance_suite)?;
        self.provider.validate()?;
        self.attester.validate()?;
        if self.provider.implementation == self.attester.implementation
            || self.provider.resource_digest == self.attester.resource_digest
        {
            return Err(invalid(
                "provider and attester must identify distinct implementations and resources",
            ));
        }
        self.native_runtime.validate()?;
        self.target
            .validate()
            .map_err(|error| invalid(format!("target binding is invalid: {error}")))?;
        validate_opaque("provider replay law", &self.provider_replay_law)?;
        validate_opaque("attester replay law", &self.attester_replay_law)?;
        self.execution_policy.validate()?;
        self.admission_policy.validate()
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
            native_runtime: &'a NativeRuntimeLock,
            target: &'a TargetBinding,
            provider_replay_law: &'a str,
            attester_replay_law: &'a str,
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
            native_runtime: &self.native_runtime,
            target: &self.target,
            provider_replay_law: &self.provider_replay_law,
            attester_replay_law: &self.attester_replay_law,
            execution_policy: &self.execution_policy,
            admission_policy: &self.admission_policy,
        })
    }
}

/// One bounded process receipt retained without semantic interpretation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "retention", rename_all = "snake_case", deny_unknown_fields)]
pub enum RetainedReceipt {
    Exact {
        receipt: ExactJson,
    },
    Redacted {
        original_receipt_digest: String,
        redaction_rule: String,
    },
}

impl RetainedReceipt {
    /// Construct exact receipt evidence.
    ///
    /// # Errors
    ///
    /// Refuses an invalid exact document.
    pub fn exact(receipt: ExactJson) -> Result<Self, JournalError> {
        receipt.validate()?;
        Ok(Self::Exact { receipt })
    }

    /// Construct a non-decisive marker for deterministically redacted evidence.
    ///
    /// # Errors
    ///
    /// Refuses a malformed original digest or redaction-rule coordinate.
    pub fn redacted(
        original_receipt_digest: impl Into<String>,
        redaction_rule: impl Into<String>,
    ) -> Result<Self, JournalError> {
        let receipt = Self::Redacted {
            original_receipt_digest: original_receipt_digest.into(),
            redaction_rule: redaction_rule.into(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Exact retained receipt identity.
    #[must_use]
    pub fn digest(&self) -> &str {
        match self {
            Self::Exact { receipt } => receipt.digest(),
            Self::Redacted {
                original_receipt_digest,
                ..
            } => original_receipt_digest,
        }
    }

    /// Whether this evidence is permanently ineligible for capture.
    #[must_use]
    pub const fn is_redacted(&self) -> bool {
        matches!(self, Self::Redacted { .. })
    }

    fn validate(&self) -> Result<(), JournalError> {
        match self {
            Self::Exact { receipt } => receipt.validate(),
            Self::Redacted {
                original_receipt_digest,
                redaction_rule,
            } => {
                validate_sha256("original receipt digest", original_receipt_digest)?;
                validate_opaque("redaction rule", redaction_rule)
            }
        }
    }
}

/// Exact index and digest of a decisive receipt already retained in a prefix.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptRef {
    index: u8,
    receipt_digest: String,
}

impl ReceiptRef {
    /// Zero-based prefix index.
    #[must_use]
    pub const fn index(&self) -> u8 {
        self.index
    }

    /// Digest of the referenced exact receipt.
    #[must_use]
    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    fn for_prefix(prefix: &[RetainedReceipt], index: usize) -> Result<Self, JournalError> {
        let receipt = prefix
            .get(index)
            .ok_or_else(|| invalid("decisive receipt index is outside its prefix"))?;
        if receipt.is_redacted() {
            return Err(invalid("redacted receipt cannot become decisive"));
        }
        Ok(Self {
            index: u8::try_from(index).map_err(|_| invalid("receipt index exceeds u8"))?,
            receipt_digest: receipt.digest().to_owned(),
        })
    }

    fn validate_against(&self, prefix: &[RetainedReceipt]) -> Result<(), JournalError> {
        validate_sha256("receipt reference digest", &self.receipt_digest)?;
        let expected = Self::for_prefix(prefix, usize::from(self.index))?;
        if *self != expected {
            return Err(invalid(
                "receipt reference does not match retained evidence",
            ));
        }
        Ok(())
    }
}

/// Closed durable lifecycle of one apply/reobserve attempt.
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
    /// Whether no later effect or state transition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Admitted | Self::Withheld | Self::Unable)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptEvidence {
    provider_receipts: Vec<RetainedReceipt>,
    provider_decisive: Option<ReceiptRef>,
    candidate: Option<ExactJson>,
    assessment_request: Option<ExactJson>,
    attester_receipts: Vec<RetainedReceipt>,
    attester_decisive: Option<ReceiptRef>,
    assessment: Option<ExactJson>,
}

impl AttemptEvidence {
    fn validate(&self) -> Result<(), JournalError> {
        for prefix in [&self.provider_receipts, &self.attester_receipts] {
            if prefix.len() > RECEIPT_CAPACITY {
                return Err(invalid("receipt prefix exceeds the fixed proof capacity"));
            }
            for receipt in prefix {
                receipt.validate()?;
            }
        }
        if let Some(reference) = &self.provider_decisive {
            reference.validate_against(&self.provider_receipts)?;
        }
        if let Some(reference) = &self.attester_decisive {
            reference.validate_against(&self.attester_receipts)?;
        }
        for document in [
            self.candidate.as_ref(),
            self.assessment_request.as_ref(),
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

/// Terminal resolution retained with the complete evidence chain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttemptResolution {
    Admitted { admission_snapshot: ExactJson },
    Withheld { decision: ExactJson },
    Unable { result: ExactJson },
}

impl AttemptResolution {
    fn validate(&self) -> Result<(), JournalError> {
        match self {
            Self::Admitted { admission_snapshot } => admission_snapshot.validate(),
            Self::Withheld { decision } => decision.validate(),
            Self::Unable { result } => result.validate(),
        }
    }
}

/// Deterministic action exposed to the later proof driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    ArmProvider,
    InspectProviderPrefix { may_launch: bool },
    BuildCandidateOrUnable,
    ArmAttester,
    InspectAttesterPrefix { may_launch: bool },
    BuildAssessment,
    EvaluateAdmission,
    ReplayTerminal,
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

    /// Retained provider receipt prefix.
    #[must_use]
    pub fn provider_receipts(&self) -> &[RetainedReceipt] {
        &self.evidence.provider_receipts
    }

    /// Retained attester receipt prefix.
    #[must_use]
    pub fn attester_receipts(&self) -> &[RetainedReceipt] {
        &self.evidence.attester_receipts
    }

    /// Referenced decisive provider receipt, once captured.
    #[must_use]
    pub const fn provider_decisive(&self) -> Option<&ReceiptRef> {
        self.evidence.provider_decisive.as_ref()
    }

    /// Referenced decisive attester receipt, once captured.
    #[must_use]
    pub const fn attester_decisive(&self) -> Option<&ReceiptRef> {
        self.evidence.attester_decisive.as_ref()
    }

    /// Exact candidate retained after provider capture.
    #[must_use]
    pub const fn candidate(&self) -> Option<&ExactJson> {
        self.evidence.candidate.as_ref()
    }

    /// Exact request persisted before attester execution.
    #[must_use]
    pub const fn assessment_request(&self) -> Option<&ExactJson> {
        self.evidence.assessment_request.as_ref()
    }

    /// Exact independently derived assessment.
    #[must_use]
    pub const fn assessment(&self) -> Option<&ExactJson> {
        self.evidence.assessment.as_ref()
    }

    /// Terminal resolution, once published.
    #[must_use]
    pub const fn resolution(&self) -> Option<&AttemptResolution> {
        self.resolution.as_ref()
    }

    /// Advance from `Prepared` to the durable pre-effect provider arm.
    ///
    /// # Errors
    ///
    /// Refuses every phase other than `Prepared`.
    pub fn arm_provider(&self) -> Result<Self, JournalError> {
        self.advance(AttemptPhase::ProviderArmed, self.evidence.clone(), None)
    }

    /// Append one provider receipt while remaining durably armed.
    ///
    /// # Errors
    ///
    /// Refuses non-armed phases, invalid evidence, or exhausted capacity.
    pub fn append_provider_receipt(&self, receipt: RetainedReceipt) -> Result<Self, JournalError> {
        receipt.validate()?;
        if self.phase != AttemptPhase::ProviderArmed {
            return Err(JournalError::InvalidTransition {
                from: self.phase,
                to: AttemptPhase::ProviderArmed,
            });
        }
        if self.evidence.provider_receipts.len() == RECEIPT_CAPACITY {
            return Err(JournalError::ReceiptCapacityExhausted("provider"));
        }
        let mut evidence = self.evidence.clone();
        evidence.provider_receipts.push(receipt);
        self.advance(AttemptPhase::ProviderArmed, evidence, None)
    }

    /// Capture one exact provider receipt already retained in the prefix.
    ///
    /// # Errors
    ///
    /// Refuses an absent, redacted, or mismatched receipt.
    pub fn capture_provider(&self, index: usize) -> Result<Self, JournalError> {
        let reference = ReceiptRef::for_prefix(&self.evidence.provider_receipts, index)?;
        let mut evidence = self.evidence.clone();
        evidence.provider_decisive = Some(reference);
        self.advance(AttemptPhase::ProviderCaptured, evidence, None)
    }

    /// Retain the candidate derived from the captured provider result.
    ///
    /// # Errors
    ///
    /// Refuses every phase other than `ProviderCaptured` or invalid evidence.
    pub fn candidate_ready(&self, candidate: ExactJson) -> Result<Self, JournalError> {
        let mut evidence = self.evidence.clone();
        evidence.candidate = Some(candidate);
        self.advance(AttemptPhase::CandidateReady, evidence, None)
    }

    /// Resolve a captured exact typed inability without constructing a candidate.
    ///
    /// # Errors
    ///
    /// Refuses every phase other than `ProviderCaptured` or invalid evidence.
    pub fn unable(&self, result: ExactJson) -> Result<Self, JournalError> {
        self.advance(
            AttemptPhase::Unable,
            self.evidence.clone(),
            Some(AttemptResolution::Unable { result }),
        )
    }

    /// Persist the exact assessment request before reobservation.
    ///
    /// # Errors
    ///
    /// Refuses every phase other than `CandidateReady` or invalid evidence.
    pub fn arm_attester(&self, request: ExactJson) -> Result<Self, JournalError> {
        let mut evidence = self.evidence.clone();
        evidence.assessment_request = Some(request);
        self.advance(AttemptPhase::AttesterArmed, evidence, None)
    }

    /// Append one attester receipt while remaining durably armed.
    ///
    /// # Errors
    ///
    /// Refuses non-armed phases, invalid evidence, or exhausted capacity.
    pub fn append_attester_receipt(&self, receipt: RetainedReceipt) -> Result<Self, JournalError> {
        receipt.validate()?;
        if self.phase != AttemptPhase::AttesterArmed {
            return Err(JournalError::InvalidTransition {
                from: self.phase,
                to: AttemptPhase::AttesterArmed,
            });
        }
        if self.evidence.attester_receipts.len() == RECEIPT_CAPACITY {
            return Err(JournalError::ReceiptCapacityExhausted("attester"));
        }
        let mut evidence = self.evidence.clone();
        evidence.attester_receipts.push(receipt);
        self.advance(AttemptPhase::AttesterArmed, evidence, None)
    }

    /// Capture one exact attester receipt already retained in the prefix.
    ///
    /// # Errors
    ///
    /// Refuses an absent, redacted, or mismatched receipt.
    pub fn capture_attester(&self, index: usize) -> Result<Self, JournalError> {
        let reference = ReceiptRef::for_prefix(&self.evidence.attester_receipts, index)?;
        let mut evidence = self.evidence.clone();
        evidence.attester_decisive = Some(reference);
        self.advance(AttemptPhase::AttesterCaptured, evidence, None)
    }

    /// Retain the exact assessment derived from captured reobservation.
    ///
    /// # Errors
    ///
    /// Refuses every phase other than `AttesterCaptured` or invalid evidence.
    pub fn assessment_ready(&self, assessment: ExactJson) -> Result<Self, JournalError> {
        let mut evidence = self.evidence.clone();
        evidence.assessment = Some(assessment);
        self.advance(AttemptPhase::AssessmentReady, evidence, None)
    }

    /// Resolve an independently assessed candidate as admitted.
    ///
    /// # Errors
    ///
    /// Refuses every phase other than `AssessmentReady` or invalid evidence.
    pub fn admitted(&self, snapshot: ExactJson) -> Result<Self, JournalError> {
        self.advance(
            AttemptPhase::Admitted,
            self.evidence.clone(),
            Some(AttemptResolution::Admitted {
                admission_snapshot: snapshot,
            }),
        )
    }

    /// Resolve an independently assessed candidate as withheld.
    ///
    /// # Errors
    ///
    /// Refuses every phase other than `AssessmentReady` or invalid evidence.
    pub fn withheld(&self, decision: ExactJson) -> Result<Self, JournalError> {
        self.advance(
            AttemptPhase::Withheld,
            self.evidence.clone(),
            Some(AttemptResolution::Withheld { decision }),
        )
    }

    /// Deterministic restart action. Armed actions always require prefix
    /// interpretation before the `may_launch` permission may be consumed.
    #[must_use]
    pub fn recovery_action(&self) -> RecoveryAction {
        match self.phase {
            AttemptPhase::Prepared => RecoveryAction::ArmProvider,
            AttemptPhase::ProviderArmed => RecoveryAction::InspectProviderPrefix {
                may_launch: self.evidence.provider_receipts.len() < RECEIPT_CAPACITY,
            },
            AttemptPhase::ProviderCaptured => RecoveryAction::BuildCandidateOrUnable,
            AttemptPhase::CandidateReady => RecoveryAction::ArmAttester,
            AttemptPhase::AttesterArmed => RecoveryAction::InspectAttesterPrefix {
                may_launch: self.evidence.attester_receipts.len() < RECEIPT_CAPACITY,
            },
            AttemptPhase::AttesterCaptured => RecoveryAction::BuildAssessment,
            AttemptPhase::AssessmentReady => RecoveryAction::EvaluateAdmission,
            AttemptPhase::Admitted | AttemptPhase::Withheld | AttemptPhase::Unable => {
                RecoveryAction::ReplayTerminal
            }
        }
    }

    /// Revalidate protocol, identities, evidence shape, and checkpoint size.
    ///
    /// # Errors
    ///
    /// Refuses malformed, incompatible, or identity-drifting state.
    pub fn validate(&self) -> Result<(), JournalError> {
        if self.protocol != CHECKPOINT_PROTOCOL {
            return Err(invalid("checkpoint protocol changed"));
        }
        self.inputs.validate()?;
        self.evidence.validate()?;
        if let Some(resolution) = &self.resolution {
            resolution.validate()?;
        }
        validate_phase_shape(self.phase, &self.evidence, self.resolution.as_ref())?;
        validate_sha256("checkpoint identity", &self.checkpoint_id)?;
        let actual = self.derived_id()?;
        if actual != self.checkpoint_id {
            return Err(JournalError::ContentIdentityMismatch {
                document: "attempt checkpoint",
                expected: self.checkpoint_id.clone(),
                actual,
            });
        }
        if canonical_bytes(self)?.len() > MAX_CHECKPOINT_BYTES {
            return Err(invalid("checkpoint exceeds the proof bound"));
        }
        Ok(())
    }

    fn advance(
        &self,
        phase: AttemptPhase,
        evidence: AttemptEvidence,
        resolution: Option<AttemptResolution>,
    ) -> Result<Self, JournalError> {
        self.validate()?;
        validate_transition(self.phase, phase)?;
        validate_evidence_transition(self.phase, phase, &self.evidence, &evidence)?;
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
        checkpoint.validate()?;
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
            AttemptPhase::Prepared | AttemptPhase::ProviderArmed,
            AttemptPhase::ProviderArmed
        ) | (AttemptPhase::ProviderArmed, AttemptPhase::ProviderCaptured)
            | (
                AttemptPhase::ProviderCaptured,
                AttemptPhase::CandidateReady | AttemptPhase::Unable
            )
            | (
                AttemptPhase::CandidateReady | AttemptPhase::AttesterArmed,
                AttemptPhase::AttesterArmed
            )
            | (AttemptPhase::AttesterArmed, AttemptPhase::AttesterCaptured)
            | (
                AttemptPhase::AttesterCaptured,
                AttemptPhase::AssessmentReady
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

fn validate_evidence_transition(
    from: AttemptPhase,
    to: AttemptPhase,
    previous: &AttemptEvidence,
    next: &AttemptEvidence,
) -> Result<(), JournalError> {
    if !prefix_of(&previous.provider_receipts, &next.provider_receipts)
        || !prefix_of(&previous.attester_receipts, &next.attester_receipts)
        || !unchanged_or_added(
            previous.provider_decisive.as_ref(),
            next.provider_decisive.as_ref(),
        )
        || !unchanged_or_added(previous.candidate.as_ref(), next.candidate.as_ref())
        || !unchanged_or_added(
            previous.assessment_request.as_ref(),
            next.assessment_request.as_ref(),
        )
        || !unchanged_or_added(
            previous.attester_decisive.as_ref(),
            next.attester_decisive.as_ref(),
        )
        || !unchanged_or_added(previous.assessment.as_ref(), next.assessment.as_ref())
    {
        return Err(JournalError::EvidenceChanged);
    }

    match (from, to) {
        (AttemptPhase::ProviderArmed, AttemptPhase::ProviderArmed) => {
            if next.provider_receipts.len() != previous.provider_receipts.len() + 1
                || next.attester_receipts != previous.attester_receipts
                || next.provider_decisive != previous.provider_decisive
                || next.candidate != previous.candidate
                || next.assessment_request != previous.assessment_request
                || next.attester_decisive != previous.attester_decisive
                || next.assessment != previous.assessment
            {
                return Err(JournalError::EvidenceChanged);
            }
        }
        (AttemptPhase::AttesterArmed, AttemptPhase::AttesterArmed) => {
            if next.attester_receipts.len() != previous.attester_receipts.len() + 1
                || next.provider_receipts != previous.provider_receipts
                || next.provider_decisive != previous.provider_decisive
                || next.candidate != previous.candidate
                || next.assessment_request != previous.assessment_request
                || next.attester_decisive != previous.attester_decisive
                || next.assessment != previous.assessment
            {
                return Err(JournalError::EvidenceChanged);
            }
        }
        _ => {
            if next.provider_receipts != previous.provider_receipts
                || next.attester_receipts != previous.attester_receipts
            {
                return Err(JournalError::EvidenceChanged);
            }
        }
    }
    Ok(())
}

fn prefix_of<T: PartialEq>(previous: &[T], next: &[T]) -> bool {
    next.starts_with(previous)
}

fn unchanged_or_added<T: PartialEq>(previous: Option<&T>, next: Option<&T>) -> bool {
    previous.is_none_or(|previous| next == Some(previous))
}

fn validate_phase_shape(
    phase: AttemptPhase,
    evidence: &AttemptEvidence,
    resolution: Option<&AttemptResolution>,
) -> Result<(), JournalError> {
    evidence.validate()?;
    let provider_nonempty = !evidence.provider_receipts.is_empty();
    let attester_nonempty = !evidence.attester_receipts.is_empty();
    let fields = [
        evidence.provider_decisive.is_some(),
        evidence.candidate.is_some(),
        evidence.assessment_request.is_some(),
        evidence.attester_decisive.is_some(),
        evidence.assessment.is_some(),
    ];
    let shape_ok = match phase {
        AttemptPhase::Prepared => !provider_nonempty && !attester_nonempty && fields == [false; 5],
        AttemptPhase::ProviderArmed => !attester_nonempty && fields == [false; 5],
        AttemptPhase::ProviderCaptured | AttemptPhase::Unable => {
            provider_nonempty && !attester_nonempty && fields == [true, false, false, false, false]
        }
        AttemptPhase::CandidateReady => {
            provider_nonempty && !attester_nonempty && fields == [true, true, false, false, false]
        }
        AttemptPhase::AttesterArmed => {
            provider_nonempty && fields == [true, true, true, false, false]
        }
        AttemptPhase::AttesterCaptured => {
            provider_nonempty && attester_nonempty && fields == [true, true, true, true, false]
        }
        AttemptPhase::AssessmentReady | AttemptPhase::Admitted | AttemptPhase::Withheld => {
            provider_nonempty && attester_nonempty && fields == [true; 5]
        }
    };
    if !shape_ok {
        return Err(invalid(format!(
            "phase {phase:?} has an invalid monotonic evidence shape"
        )));
    }
    let resolution_ok = matches!(
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
    if !resolution_ok {
        return Err(invalid("phase and terminal resolution disagree"));
    }
    Ok(())
}

/// Owner-only durable journal for one attempt.
#[derive(Clone, Debug)]
pub struct AttemptJournal {
    directory_path: PathBuf,
    checkpoint_path: PathBuf,
    directory: Arc<File>,
    lock_device: u64,
    lock_inode: u64,
}

impl AttemptJournal {
    /// Open or create one private journal authority directory.
    ///
    /// # Errors
    ///
    /// Refuses unsafe paths, symlinks, wrong ownership, or permissive modes.
    pub fn new(directory_path: impl Into<PathBuf>) -> Result<Self, JournalError> {
        let directory_path = directory_path.into();
        let directory_name = directory_path
            .file_name()
            .ok_or_else(|| {
                invalid_filesystem(&directory_path, "journal path must name a directory")
            })?
            .to_os_string();
        let parent_path = directory_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = File::from(
            open(
                parent_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| filesystem("open journal parent", parent_path, error))?,
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
                    error,
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
                filesystem("open private journal directory", &directory_path, error)
            })?,
        );
        validate_authority_directory(&directory, &directory_path)?;
        if created {
            parent
                .sync_all()
                .map_err(|error| io_error("synchronize journal parent", &directory_path, error))?;
        }
        let checkpoint_path = directory_path.join(CHECKPOINT_NAME);
        let lock = open_lock_file(&directory, &checkpoint_path)?;
        let lock_metadata = lock
            .metadata()
            .map_err(|error| io_error("inspect stable journal lock", &checkpoint_path, error))?;
        Ok(Self {
            checkpoint_path,
            directory_path,
            directory: Arc::new(directory),
            lock_device: lock_metadata.dev(),
            lock_inode: lock_metadata.ino(),
        })
    }

    /// Private journal directory.
    #[must_use]
    pub fn directory_path(&self) -> &Path {
        &self.directory_path
    }

    /// Begin one continuously fenced recovery/execution session.
    ///
    /// The guard must remain alive through armed-prefix inspection, any later
    /// process execution, receipt publication, reload, and capture.
    ///
    /// # Errors
    ///
    /// Refuses unsafe lock authority or lock acquisition failure.
    pub fn begin_session(&self) -> Result<AttemptSession<'_>, JournalError> {
        self.session(FlockOperation::LockExclusive)
    }

    /// Attempt to begin a session without blocking.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Busy`] while another live session owns the fence.
    pub fn try_begin_session(&self) -> Result<AttemptSession<'_>, JournalError> {
        self.session(FlockOperation::NonBlockingLockExclusive)
    }

    fn session(&self, operation: FlockOperation) -> Result<AttemptSession<'_>, JournalError> {
        validate_authority_directory(&self.directory, &self.directory_path)?;
        let lock = self.open_lock()?;
        flock(&lock, operation).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK || error == rustix::io::Errno::AGAIN {
                JournalError::Busy
            } else {
                filesystem("lock journal authority", &self.checkpoint_path, error)
            }
        })?;
        validate_authority_directory(&self.directory, &self.directory_path)?;
        validate_authority_file(&lock, &self.checkpoint_path, "journal lock")?;
        Ok(AttemptSession {
            journal: self,
            _lock: lock,
        })
    }

    fn open_lock(&self) -> Result<File, JournalError> {
        let lock = open_lock_file(&self.directory, &self.checkpoint_path)?;
        let metadata = lock.metadata().map_err(|error| {
            io_error("inspect stable journal lock", &self.checkpoint_path, error)
        })?;
        if metadata.dev() != self.lock_device || metadata.ino() != self.lock_inode {
            return Err(invalid_filesystem(
                &self.checkpoint_path,
                "stable journal lock inode changed",
            ));
        }
        Ok(lock)
    }

    fn load_unlocked(&self) -> Result<AttemptCheckpoint, JournalError> {
        validate_authority_directory(&self.directory, &self.directory_path)?;
        let descriptor = openat(
            &*self.directory,
            CHECKPOINT_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| {
            if error == rustix::io::Errno::NOENT {
                JournalError::Missing(self.checkpoint_path.clone())
            } else {
                filesystem("open checkpoint", &self.checkpoint_path, error)
            }
        })?;
        let mut file = File::from(descriptor);
        validate_authority_file(&file, &self.checkpoint_path, "checkpoint")?;
        let metadata = file
            .metadata()
            .map_err(|error| io_error("inspect checkpoint", &self.checkpoint_path, error))?;
        if metadata.len() > MAX_CHECKPOINT_BYTES as u64 {
            return Err(invalid_filesystem(
                &self.checkpoint_path,
                "checkpoint exceeds the proof bound",
            ));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| {
            invalid_filesystem(
                &self.checkpoint_path,
                "checkpoint length cannot fit in memory",
            )
        })?);
        Read::by_ref(&mut file)
            .take(MAX_CHECKPOINT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("read checkpoint", &self.checkpoint_path, error))?;
        if bytes.len() as u64 != metadata.len() {
            return Err(invalid_filesystem(
                &self.checkpoint_path,
                "checkpoint changed length while being read",
            ));
        }
        let checkpoint: AttemptCheckpoint =
            serde_json::from_slice(&bytes).map_err(|error| JournalError::Decode {
                path: self.checkpoint_path.clone(),
                detail: error.to_string(),
            })?;
        if bytes != canonical_bytes(&checkpoint)? {
            return Err(JournalError::NonCanonical(self.checkpoint_path.clone()));
        }
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    fn persist_unlocked(
        &self,
        checkpoint: &AttemptCheckpoint,
        publication: Publication,
    ) -> Result<(), JournalError> {
        validate_authority_directory(&self.directory, &self.directory_path)?;
        checkpoint.validate()?;
        let bytes = canonical_bytes(checkpoint)?;
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(invalid("checkpoint exceeds the proof bound"));
        }
        match unlinkat(&*self.directory, TEMPORARY_NAME, AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => {
                return Err(filesystem(
                    "remove stale checkpoint sibling",
                    &self.checkpoint_path,
                    error,
                ));
            }
        }
        let mut temporary = TemporarySibling::create(
            Arc::clone(&self.directory),
            OsString::from(TEMPORARY_NAME),
            &self.checkpoint_path,
        )?;
        temporary
            .file
            .write_all(&bytes)
            .map_err(|error| io_error("write checkpoint sibling", &self.checkpoint_path, error))?;
        temporary
            .file
            .flush()
            .map_err(|error| io_error("flush checkpoint sibling", &self.checkpoint_path, error))?;
        temporary.file.sync_all().map_err(|error| {
            io_error(
                "synchronize checkpoint sibling",
                &self.checkpoint_path,
                error,
            )
        })?;
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
                JournalError::AlreadyExists(self.checkpoint_path.clone())
            } else {
                filesystem("publish checkpoint", &self.checkpoint_path, error)
            }
        })?;
        temporary.armed = false;
        self.directory.sync_all().map_err(|error| {
            io_error(
                "synchronize journal directory",
                &self.checkpoint_path,
                error,
            )
        })
    }

    fn verify_unlocked(&self, expected: &AttemptCheckpoint) -> Result<(), JournalError> {
        let actual = self.load_unlocked()?;
        if actual != *expected {
            return Err(JournalError::PublishedCheckpointMismatch {
                expected: expected.checkpoint_id.clone(),
                actual: actual.checkpoint_id,
            });
        }
        Ok(())
    }
}

fn open_lock_file(directory: &File, display_path: &Path) -> Result<File, JournalError> {
    let lock = File::from(
        openat(
            directory,
            LOCK_NAME,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| filesystem("open stable journal lock", display_path, error))?,
    );
    validate_authority_file(&lock, display_path, "journal lock")?;
    Ok(lock)
}

/// Continuously held exclusive ownership fence for one attempt.
#[derive(Debug)]
pub struct AttemptSession<'a> {
    journal: &'a AttemptJournal,
    _lock: File,
}

impl AttemptSession<'_> {
    /// Publish the sole legal initial `Prepared` checkpoint.
    ///
    /// # Errors
    ///
    /// Refuses existing state or invalid inputs.
    pub fn create(&self, inputs: AttemptInputs) -> Result<AttemptCheckpoint, JournalError> {
        let checkpoint = AttemptCheckpoint::prepared(inputs)?;
        match self.journal.load_unlocked() {
            Err(JournalError::Missing(_)) => {}
            Ok(_) => {
                return Err(JournalError::AlreadyExists(
                    self.journal.checkpoint_path.clone(),
                ));
            }
            Err(error) => return Err(error),
        }
        self.journal
            .persist_unlocked(&checkpoint, Publication::Create)?;
        self.journal.verify_unlocked(&checkpoint)?;
        Ok(checkpoint)
    }

    /// Load exact canonical state while retaining continuous ownership.
    ///
    /// # Errors
    ///
    /// Refuses missing, corrupt, noncanonical, or unsafe state.
    pub fn load(&self) -> Result<AttemptCheckpoint, JournalError> {
        self.journal.load_unlocked()
    }

    /// Compare-and-swap one exact checkpoint to one legal monotonic successor.
    ///
    /// # Errors
    ///
    /// Refuses stale writers, changed immutable inputs/evidence, or illegal state.
    pub fn replace(
        &self,
        expected_checkpoint_id: &str,
        next: &AttemptCheckpoint,
    ) -> Result<(), JournalError> {
        let current = self.journal.load_unlocked()?;
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
        validate_evidence_transition(current.phase, next.phase, &current.evidence, &next.evidence)?;
        self.journal.persist_unlocked(next, Publication::Replace)?;
        self.journal.verify_unlocked(next)
    }
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
            .map_err(|error| filesystem("create checkpoint sibling", display_path, error))?,
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

/// Closed journal failure.
#[derive(Debug)]
pub enum JournalError {
    Invalid(String),
    InvalidFilesystem {
        path: PathBuf,
        detail: String,
    },
    Missing(PathBuf),
    AlreadyExists(PathBuf),
    Decode {
        path: PathBuf,
        detail: String,
    },
    NonCanonical(PathBuf),
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
    ReceiptCapacityExhausted(&'static str),
    PublishedCheckpointMismatch {
        expected: String,
        actual: String,
    },
    Busy,
}

impl fmt::Display for JournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(detail) => write!(formatter, "invalid attempt journal: {detail}"),
            Self::InvalidFilesystem { path, detail } => {
                write!(
                    formatter,
                    "invalid journal authority `{}`: {detail}",
                    path.display()
                )
            }
            Self::Missing(path) => write!(formatter, "checkpoint `{}` is missing", path.display()),
            Self::AlreadyExists(path) => {
                write!(formatter, "checkpoint `{}` already exists", path.display())
            }
            Self::Decode { path, detail } => {
                write!(
                    formatter,
                    "cannot decode checkpoint `{}`: {detail}",
                    path.display()
                )
            }
            Self::NonCanonical(path) => {
                write!(
                    formatter,
                    "checkpoint `{}` is not canonical",
                    path.display()
                )
            }
            Self::ContentIdentityMismatch {
                document,
                expected,
                actual,
            } => write!(
                formatter,
                "{document} identity changed: expected `{expected}`, found `{actual}`"
            ),
            Self::InvalidTransition { from, to } => {
                write!(formatter, "invalid attempt transition {from:?} -> {to:?}")
            }
            Self::EvidenceChanged => {
                formatter.write_str("retained evidence was replaced or reordered")
            }
            Self::ImmutableInputsChanged => formatter.write_str("immutable attempt inputs changed"),
            Self::StaleCheckpoint { expected, actual } => write!(
                formatter,
                "stale checkpoint writer expected `{expected}`, found `{actual}`"
            ),
            Self::ReceiptCapacityExhausted(role) => {
                write!(
                    formatter,
                    "{role} receipt prefix exhausted its fixed capacity"
                )
            }
            Self::PublishedCheckpointMismatch { expected, actual } => write!(
                formatter,
                "published checkpoint differs: expected `{expected}`, found `{actual}`"
            ),
            Self::Busy => formatter.write_str("attempt is owned by another live session"),
        }
    }
}

impl Error for JournalError {}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, JournalError> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|error| invalid(format!("canonical JSON encoding failed: {error}")))
}

fn document_digest(value: &impl Serialize) -> Result<String, JournalError> {
    Ok(sha256_identity(&canonical_bytes(value)?))
}

fn sha256_identity(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn placeholder_identity() -> String {
    format!("sha256:{}", "0".repeat(64))
}

fn validate_sha256(label: &'static str, value: &str) -> Result<(), JournalError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(invalid(format!("{label} is not a SHA-256 identity")));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "{label} is not a lowercase SHA-256 identity"
        )));
    }
    Ok(())
}

fn validate_opaque(label: &'static str, value: &str) -> Result<(), JournalError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_OPAQUE_ID_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(invalid(format!(
            "{label} is empty, padded, oversized, or contains control characters"
        )));
    }
    Ok(())
}

fn validate_json_value(value: &Value) -> Result<(), JournalError> {
    if !value.is_object() {
        return Err(invalid("exact JSON must be an object"));
    }
    validate_json_number_domain(value)
}

fn validate_json_number_domain(value: &Value) -> Result<(), JournalError> {
    match value {
        Value::Number(number) => {
            if let Some(unsigned) = number.as_u64() {
                if unsigned > MAX_SAFE_JSON_INTEGER {
                    return Err(invalid("JSON integer exceeds the exact I-JSON domain"));
                }
            } else if let Some(signed) = number.as_i64() {
                if signed.unsigned_abs() > MAX_SAFE_JSON_INTEGER {
                    return Err(invalid("JSON integer exceeds the exact I-JSON domain"));
                }
            } else if number.as_f64().is_none_or(|number| !number.is_finite()) {
                return Err(invalid("JSON number is not finite"));
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

fn validate_authority_file(
    file: &File,
    display_path: &Path,
    label: &'static str,
) -> Result<(), JournalError> {
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect authority file", display_path, error))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(invalid_filesystem(
            display_path,
            format!("{label} must be an owner-owned 0600 regular file with one link"),
        ));
    }
    Ok(())
}

fn validate_authority_directory(file: &File, path: &Path) -> Result<(), JournalError> {
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect authority directory", path, error))?;
    if !metadata.is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(invalid_filesystem(
            path,
            "journal authority must be an owner-owned 0700 directory",
        ));
    }
    Ok(())
}

fn invalid(detail: impl Into<String>) -> JournalError {
    JournalError::Invalid(detail.into())
}

fn invalid_filesystem(path: &Path, detail: impl Into<String>) -> JournalError {
    JournalError::InvalidFilesystem {
        path: path.to_path_buf(),
        detail: detail.into(),
    }
}

fn filesystem(operation: &'static str, path: &Path, error: impl fmt::Display) -> JournalError {
    invalid_filesystem(path, format!("{operation}: {error}"))
}

fn io_error(operation: &'static str, path: &Path, error: impl fmt::Display) -> JournalError {
    invalid_filesystem(path, format!("{operation}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use serde_json::json;
    use tempfile::TempDir;

    use fleetd_direct_conversation_contract::FleetdTarget;

    use super::{
        AttemptInputs, AttemptJournal, AttemptPhase, DeploymentLock, ExactJson, JournalError,
        NativeRuntimeLock, RECEIPT_CAPACITY, RecoveryAction, RetainedReceipt, UnboundAttemptInputs,
    };
    use crate::target::{TargetDeployment, TargetLock};

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn exact(label: &str) -> ExactJson {
        ExactJson::new(json!({"value": label})).expect("exact JSON")
    }

    fn target_binding(temp: &TempDir) -> crate::target::TargetBinding {
        let target = TargetLock::new(temp.path().join("target")).expect("target");
        target
            .configure(
                TargetDeployment::new(
                    FleetdTarget::parse("fleetd:proof").expect("target coordinate"),
                    digest('a'),
                    "e6628b054b8559d6da4e5857c888676fe322b2f9",
                    digest('b'),
                    digest('c'),
                    digest('d'),
                    "credential/revision-1",
                )
                .expect("deployment"),
            )
            .expect("configure")
    }

    fn inputs_with_target(target: crate::target::TargetBinding) -> AttemptInputs {
        AttemptInputs::new(UnboundAttemptInputs {
            semantic_plan: exact("plan"),
            invocation: exact("invocation"),
            baseline_snapshot: exact("baseline"),
            conformance_suite: "dev.fleetd.conformance/direct_conversation_ref@0.1.0".to_owned(),
            provider: DeploymentLock::new(
                "dev.fleetd.implementation/direct_conversation_reqwest@0.1.0",
                "dev.fleetd.package/direct-conversation@0.1.0",
                digest('e'),
                "bin/reqwest-provider",
                digest('f'),
            )
            .expect("provider"),
            attester: DeploymentLock::new(
                "dev.fleetd.implementation/direct_conversation_attester@0.1.0",
                "dev.fleetd.package/direct-conversation@0.1.0",
                digest('e'),
                "bin/attester",
                digest('1'),
            )
            .expect("attester"),
            native_runtime: NativeRuntimeLock::new(
                "org.gooi.proof/native-command-fd3@0.1.0",
                digest('2'),
            )
            .expect("runtime"),
            target,
            provider_replay_law: "dev.fleetd.proof/direct-pair-open-or-resolve-replay@0.1.0"
                .to_owned(),
            attester_replay_law: "dev.fleetd.proof/direct-conversation-get-reobserve@0.1.0"
                .to_owned(),
            execution_policy: exact("execution-policy"),
            admission_policy: exact("admission-policy"),
        })
        .expect("inputs")
    }

    fn inputs(temp: &TempDir) -> AttemptInputs {
        inputs_with_target(target_binding(temp))
    }

    fn receipt(label: &str) -> RetainedReceipt {
        RetainedReceipt::exact(exact(label)).expect("receipt")
    }

    #[test]
    fn recovery_views_expose_every_immutable_input_without_schema_bypass() {
        let temp = TempDir::new().expect("temp");
        let inputs = inputs(&temp);
        inputs.validate().expect("valid inputs");

        assert_eq!(inputs.semantic_plan().value()["value"], "plan");
        assert_eq!(inputs.invocation().value()["value"], "invocation");
        assert_eq!(inputs.baseline_snapshot().value()["value"], "baseline");
        assert_eq!(
            inputs.conformance_suite(),
            "dev.fleetd.conformance/direct_conversation_ref@0.1.0"
        );
        assert_eq!(
            inputs.provider().implementation(),
            "dev.fleetd.implementation/direct_conversation_reqwest@0.1.0"
        );
        assert_eq!(
            inputs.provider().package(),
            "dev.fleetd.package/direct-conversation@0.1.0"
        );
        assert_eq!(inputs.provider().package_digest(), digest('e'));
        assert_eq!(inputs.provider().resource(), "bin/reqwest-provider");
        assert_eq!(inputs.provider().resource_digest(), digest('f'));
        assert_eq!(
            inputs.attester().implementation(),
            "dev.fleetd.implementation/direct_conversation_attester@0.1.0"
        );
        assert_eq!(
            inputs.native_runtime().runtime(),
            "org.gooi.proof/native-command-fd3@0.1.0"
        );
        assert_eq!(inputs.native_runtime().runtime_digest(), digest('2'));
        assert_eq!(
            inputs.provider_replay_law(),
            "dev.fleetd.proof/direct-pair-open-or-resolve-replay@0.1.0"
        );
        assert_eq!(
            inputs.attester_replay_law(),
            "dev.fleetd.proof/direct-conversation-get-reobserve@0.1.0"
        );
        assert_eq!(
            inputs.execution_policy().value()["value"],
            "execution-policy"
        );
        assert_eq!(
            inputs.admission_policy().value()["value"],
            "admission-policy"
        );

        let runtime = serde_json::to_value(inputs.native_runtime()).expect("runtime JSON");
        assert_eq!(
            runtime.as_object().expect("runtime object").keys().count(),
            2
        );
        assert!(runtime.get("runtime").is_some());
        assert!(runtime.get("runtime_digest").is_some());
    }

    #[test]
    fn provider_prefix_is_append_only_bounded_and_capture_references_exact_evidence() {
        let temp = TempDir::new().expect("temp");
        let prepared = super::AttemptCheckpoint::prepared(inputs(&temp)).expect("prepared");
        let armed = prepared.arm_provider().expect("arm");
        let first = armed
            .append_provider_receipt(receipt("operational"))
            .expect("first append");
        let second = first
            .append_provider_receipt(receipt("decisive"))
            .expect("second append");
        assert_eq!(second.provider_receipts().len(), RECEIPT_CAPACITY);
        assert_eq!(
            second.recovery_action(),
            RecoveryAction::InspectProviderPrefix { may_launch: false }
        );
        assert!(matches!(
            second.append_provider_receipt(receipt("third")),
            Err(JournalError::ReceiptCapacityExhausted("provider"))
        ));
        let captured = second.capture_provider(1).expect("capture");
        assert_eq!(captured.phase(), AttemptPhase::ProviderCaptured);
        assert_eq!(captured.provider_decisive().expect("reference").index(), 1);
        assert_eq!(
            captured
                .provider_decisive()
                .expect("reference")
                .receipt_digest(),
            second.provider_receipts()[1].digest()
        );
    }

    #[test]
    fn redacted_receipts_are_never_decisive() {
        let temp = TempDir::new().expect("temp");
        let armed = super::AttemptCheckpoint::prepared(inputs(&temp))
            .expect("prepared")
            .arm_provider()
            .expect("arm")
            .append_provider_receipt(
                RetainedReceipt::redacted(
                    digest('3'),
                    "org.gooi.proof/remove-authority-pipe-bytes@0.1.0",
                )
                .expect("redacted"),
            )
            .expect("append");
        assert!(armed.provider_receipts()[0].is_redacted());
        assert!(armed.capture_provider(0).is_err());
    }

    #[test]
    fn attester_prefix_and_terminal_replay_retain_the_complete_shape() {
        let temp = TempDir::new().expect("temp");
        let prepared = super::AttemptCheckpoint::prepared(inputs(&temp)).expect("prepared");
        let provider = prepared
            .arm_provider()
            .expect("arm provider")
            .append_provider_receipt(receipt("provider result"))
            .expect("append provider")
            .capture_provider(0)
            .expect("capture provider")
            .candidate_ready(exact("candidate"))
            .expect("candidate")
            .arm_attester(exact("assessment request"))
            .expect("arm attester");
        let attester = provider
            .append_attester_receipt(receipt("attester assessment"))
            .expect("append attester")
            .capture_attester(0)
            .expect("capture attester")
            .assessment_ready(exact("assessment"))
            .expect("assessment")
            .admitted(exact("snapshot"))
            .expect("admit");
        attester.validate().expect("terminal validates");
        assert_eq!(attester.recovery_action(), RecoveryAction::ReplayTerminal);
        assert_eq!(attester.provider_receipts().len(), 1);
        assert_eq!(attester.attester_receipts().len(), 1);
        assert!(attester.resolution().is_some());
    }

    #[test]
    fn typed_unable_can_only_follow_provider_capture() {
        let temp = TempDir::new().expect("temp");
        let prepared = super::AttemptCheckpoint::prepared(inputs(&temp)).expect("prepared");
        assert!(prepared.unable(exact("unable")).is_err());
        let unable = prepared
            .arm_provider()
            .expect("arm")
            .append_provider_receipt(receipt("typed unable"))
            .expect("append")
            .capture_provider(0)
            .expect("capture")
            .unable(exact("typed unable"))
            .expect("unable");
        assert_eq!(unable.phase(), AttemptPhase::Unable);
        assert_eq!(unable.recovery_action(), RecoveryAction::ReplayTerminal);
    }

    #[test]
    fn journal_cas_rejects_stale_and_changed_inputs_or_prefixes() {
        let temp = TempDir::new().expect("temp");
        let journal = AttemptJournal::new(temp.path().join("journal")).expect("journal");
        let session = journal.begin_session().expect("session");
        let prepared = session.create(inputs(&temp)).expect("create");
        let armed = prepared.arm_provider().expect("arm");
        session
            .replace(prepared.checkpoint_id(), &armed)
            .expect("publish arm");
        assert!(matches!(
            session.replace(prepared.checkpoint_id(), &armed),
            Err(JournalError::StaleCheckpoint { .. })
        ));

        let appended = armed
            .append_provider_receipt(receipt("first"))
            .expect("append");
        session
            .replace(armed.checkpoint_id(), &appended)
            .expect("publish receipt");
        let mut changed = appended
            .append_provider_receipt(receipt("second"))
            .expect("append second");
        changed.evidence.provider_receipts[0] = receipt("replacement");
        changed.checkpoint_id = changed.derived_id().expect("identity");
        assert!(matches!(
            session.replace(appended.checkpoint_id(), &changed),
            Err(JournalError::EvidenceChanged)
        ));

        let mut changed_inputs = appended.clone();
        changed_inputs
            .inputs
            .provider_replay_law
            .push_str("-changed");
        changed_inputs.inputs.attempt_id = changed_inputs.inputs.derived_id().expect("input id");
        changed_inputs.checkpoint_id = changed_inputs.derived_id().expect("checkpoint id");
        assert!(matches!(
            session.replace(appended.checkpoint_id(), &changed_inputs),
            Err(JournalError::ImmutableInputsChanged)
        ));
    }

    #[test]
    fn continuous_session_excludes_a_second_live_owner() {
        let temp = TempDir::new().expect("temp");
        let path = temp.path().join("journal");
        let first = AttemptJournal::new(&path).expect("first journal");
        let session = first.begin_session().expect("first session");
        let second = AttemptJournal::new(&path).expect("late journal opener");
        assert!(matches!(
            second.try_begin_session(),
            Err(JournalError::Busy)
        ));
        drop(session);
        let _second_session = second.try_begin_session().expect("second session");
    }

    #[test]
    fn permissions_and_corruption_fail_closed() {
        let temp = TempDir::new().expect("temp");
        let directory = temp.path().join("journal");
        fs::create_dir(&directory).expect("directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).expect("mode");
        assert!(matches!(
            AttemptJournal::new(&directory),
            Err(JournalError::InvalidFilesystem { .. })
        ));
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("mode");
        let journal = AttemptJournal::new(&directory).expect("journal");
        let session = journal.begin_session().expect("session");
        session.create(inputs(&temp)).expect("create");
        let path = directory.join("checkpoint.json");
        fs::write(&path, b"{\"unknown\":true}").expect("corrupt");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        assert!(matches!(session.load(), Err(JournalError::Decode { .. })));
    }

    #[test]
    fn retained_journal_authority_and_stable_lock_are_revalidated() {
        let temp = TempDir::new().expect("temp");
        let directory = temp.path().join("journal");
        let journal = AttemptJournal::new(&directory).expect("journal");

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).expect("widen mode");
        assert!(matches!(
            journal.try_begin_session(),
            Err(JournalError::InvalidFilesystem { .. })
        ));
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("restore mode");

        let lock_path = directory.join("lock");
        fs::rename(&lock_path, directory.join("old-lock")).expect("replace lock inode");
        fs::write(&lock_path, b"").expect("new lock file");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).expect("new lock mode");
        assert!(matches!(
            journal.try_begin_session(),
            Err(JournalError::InvalidFilesystem { .. })
        ));
    }

    #[test]
    fn persisted_target_lock_mismatch_changes_attempt_identity() {
        let temp = TempDir::new().expect("temp");
        let first = inputs(&temp);
        let target = TargetLock::new(temp.path().join("target")).expect("target");
        let changed = target
            .configure(
                TargetDeployment::new(
                    FleetdTarget::parse("fleetd:proof").expect("target coordinate"),
                    digest('a'),
                    "89720d73f9dd75af804c27d87a71bf33c65b58c2",
                    digest('b'),
                    digest('c'),
                    digest('d'),
                    "credential/revision-1",
                )
                .expect("deployment"),
            )
            .expect("reconfigure");
        let second = inputs_with_target(changed);
        assert_ne!(first.attempt_id(), second.attempt_id());
    }
}
