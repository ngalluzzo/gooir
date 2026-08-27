//! Trusted proof-local driver for one Fleetd direct-conversation attempt.
//!
//! This module composes the already public package, planning, protocol,
//! conformance, admission, target, native-runtime, supervisor, and journal
//! boundaries. It is deliberately not a generic execution host or plugin API.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use fleetd_direct_conversation_attester::{AssessmentRequest, AttesterError, implementation_id};
use fleetd_direct_conversation_command_abi::AuthorityDocument;
use fleetd_direct_conversation_contract::{
    ContractFactError, DirectConversationRef, DirectPairIntent, direct_conversation_ref_suite_id,
    direct_conversation_ref_value_kind, immutable_mode_conflict_failure_kind,
    open_or_resolve_capability_spec,
};
use gooir_capability::authority::{
    AdmissionDecision, AdmissionLedger, AdmissionOutcome, AdmissionPolicy, AdmissionSnapshot,
    AssessmentOutcome, AuthorityError, ConformanceAssessment, ConformanceAttester,
    ConformanceAuthority,
};
use gooir_capability::protocol::{
    ArtifactDigest, CapabilityCandidate, CapabilityInvocation, CapabilityOutcome, CapabilityResult,
    ProtocolError,
};
use gooir_fleetd_direct_conversation_package_proof::{ProviderPackageBinding, VerifiedPackageSet};
use gooir_planning::{InvocationLink, PlanLimits, PlanningError, SemanticPlan};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::journal::{
    AttemptCheckpoint, AttemptInputs, AttemptResolution, AttemptSession, DeploymentLock, ExactJson,
    JournalError, RECEIPT_CAPACITY, RecoveryAction, RetainedReceipt, UnboundAttemptInputs,
};
use crate::native::{
    NativeArtifactRole, NativeQualificationError, QualifiedNativeArtifact,
    QualifiedNativeArtifactLock,
};
use crate::runtime::{QualifiedNativeRuntime, RuntimeQualificationError};
use crate::supervisor::{
    NATIVE_SUPERVISOR_PROFILE_ID, ProcessLimits, ProcessReceipt, SupervisorError, launch,
};
use crate::target::{TargetError, TargetExecutionGuard};

/// Exact proof-local provider replay law bound into every attempt.
pub const PROVIDER_REPLAY_LAW: &str =
    "dev.fleetd.proof/direct-pair-open-or-resolve-immutable-modes-replay@0.1.0";

/// Exact proof-local independent observation replay law bound into every attempt.
pub const ATTESTER_REPLAY_LAW: &str =
    "dev.fleetd.proof/direct-conversation-bounded-get-reobserve@0.1.0";

const EXECUTION_POLICY_PROTOCOL: &str =
    "org.gooi.proof.fleetd-direct-conversation-execution-policy/v1";
const AUTHORITY_REDACTION_RULE: &str =
    "org.gooi.proof/fleetd-native-authority-stream-redaction@0.3.0";
const ATTESTER_CHECK_EXACT_CONTRACT: &str = "exact-contract";
const ATTESTER_CHECK_INTENT_OUTPUT_RELATION: &str = "intent-output-relation";
const ATTESTER_CHECK_FLEETD_OBSERVATION: &str = "fleetd-observation";

/// Exact process bounds selected independently for the provider and attester.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptProcessLimits {
    pub provider: ProcessLimits,
    pub attester: ProcessLimits,
}

/// Complete live authority needed to start or resume one exact attempt.
///
/// This type intentionally has no `Debug` implementation because it borrows a
/// credential-bearing [`AuthorityDocument`].
pub struct DriverRequest<'authority> {
    pub packages: &'authority VerifiedPackageSet,
    pub selected_provider: &'authority ProviderPackageBinding,
    pub invocation: &'authority CapabilityInvocation,
    pub baseline: &'authority AdmissionSnapshot,
    pub admission_policy: &'authority AdmissionPolicy,
    pub provider_artifact: &'authority QualifiedNativeArtifact,
    pub attester_artifact: &'authority QualifiedNativeArtifact,
    pub runtime: &'authority QualifiedNativeRuntime,
    pub target: &'authority TargetExecutionGuard,
    pub authority: &'authority AuthorityDocument,
    pub planning_limits: PlanLimits,
    pub process_limits: AttemptProcessLimits,
}

/// Why a valid, nonterminal attempt stopped without weakening its evidence.
#[derive(Debug)]
pub enum ParkReason {
    /// No receipt existed to append. Receipt capacity therefore does not bound
    /// repeated resumes; safety relies on [`PROVIDER_REPLAY_LAW`].
    ProviderLaunch(SupervisorError),
    /// No receipt existed to append. Receipt capacity therefore does not bound
    /// repeated resumes; safety relies on [`ATTESTER_REPLAY_LAW`].
    AttesterLaunch(SupervisorError),
    /// The retained provider prefix is full of non-decisive evidence.
    ProviderReceiptCapacity,
    /// The retained attester prefix is full of non-decisive evidence.
    AttesterReceiptCapacity,
}

/// Result of driving one bounded attempt.
#[derive(Debug)]
pub enum DriverProgress {
    Terminal(AttemptCheckpoint),
    Parked {
        checkpoint: AttemptCheckpoint,
        reason: ParkReason,
    },
}

/// One exact attempt whose complete live authority and durable checkpoint have
/// been validated without launching a provider or attester.
///
/// The fields are deliberately private and the type deliberately implements
/// neither `Debug` nor `Clone`: the value retains credential-bearing authority,
/// exact artifact/runtime materializations, the target execution fence, and
/// continuous journal ownership until it is consumed by [`Self::drive`].
#[must_use = "a validated attempt must be armed by its outer host before it is driven"]
pub struct ValidatedAttempt<'session, 'journal, 'authority>
where
    'journal: 'session,
{
    session: &'session AttemptSession<'journal>,
    context: Context<'authority>,
    checkpoint: AttemptCheckpoint,
}

impl ValidatedAttempt<'_, '_, '_> {
    /// Exact durable checkpoint identity validated into this one-shot value.
    #[must_use]
    pub fn checkpoint_id(&self) -> &str {
        self.checkpoint.checkpoint_id()
    }

    /// Closed durable phase validated into this one-shot value.
    #[must_use]
    pub const fn phase(&self) -> crate::journal::AttemptPhase {
        self.checkpoint.phase()
    }

    /// Reload the exact checkpoint and drive it until terminal or safely parked.
    ///
    /// This consumes the validation authority. A changed checkpoint is refused
    /// before the existing recovery loop can inspect an armed prefix or launch
    /// either child.
    ///
    /// # Errors
    ///
    /// Refuses stale, changed, malformed, noncanonical, or incompatible state,
    /// as well as every failure already reported by [`start`] and [`resume`].
    pub fn drive(self) -> Result<DriverProgress, DriverError> {
        let Self {
            session,
            context,
            checkpoint,
        } = self;
        let checkpoint = reload_exact_checkpoint(session, &checkpoint)?;
        context.validate_checkpoint(&checkpoint)?;
        drive_loop(session, &context, checkpoint)
    }
}

/// Prepare and durably bind a new exact attempt without launching a child.
///
/// The returned value retains all live execution authority so an outer durable
/// host can arm its own fence before consuming [`ValidatedAttempt::drive`].
///
/// # Errors
///
/// Refuses changed packages, planning, invocation authority, target/runtime
/// locks, existing journal state, or semantic correlation.
pub fn prepare<'session, 'journal, 'authority>(
    session: &'session AttemptSession<'journal>,
    request: &DriverRequest<'authority>,
) -> Result<ValidatedAttempt<'session, 'journal, 'authority>, DriverError>
where
    'journal: 'session,
{
    let context = Context::reconstruct(request)?;
    let checkpoint = publish_prepared(session, &context.inputs, &context.durable_guard)?;
    context.validate_checkpoint(&checkpoint)?;
    Ok(ValidatedAttempt {
        session,
        context,
        checkpoint,
    })
}

/// Reconstruct all live authority and validate one existing exact attempt
/// without advancing it or launching a child.
///
/// # Errors
///
/// Refuses missing, changed, malformed, noncanonical, or incompatible state.
pub fn validate_existing<'session, 'journal, 'authority>(
    session: &'session AttemptSession<'journal>,
    request: &DriverRequest<'authority>,
) -> Result<ValidatedAttempt<'session, 'journal, 'authority>, DriverError>
where
    'journal: 'session,
{
    let context = Context::reconstruct(request)?;
    let checkpoint = session.load()?;
    context.validate_checkpoint(&checkpoint)?;
    Ok(ValidatedAttempt {
        session,
        context,
        checkpoint,
    })
}

/// Start a new exact attempt and drive it until terminal or safely parked.
///
/// # Errors
///
/// Refuses changed packages, planning, invocation authority, target/runtime
/// locks, journal state, retained evidence, or semantic correlation.
pub fn start(
    session: &AttemptSession<'_>,
    request: &DriverRequest<'_>,
) -> Result<DriverProgress, DriverError> {
    prepare(session, request)?.drive()
}

/// Resume one exact attempt and drive it until terminal or safely parked.
///
/// # Errors
///
/// Refuses missing, changed, malformed, noncanonical, or incompatible state.
pub fn resume(
    session: &AttemptSession<'_>,
    request: &DriverRequest<'_>,
) -> Result<DriverProgress, DriverError> {
    validate_existing(session, request)?.drive()
}

fn publish_prepared(
    session: &AttemptSession<'_>,
    inputs: &AttemptInputs,
    durable_guard: &DurableAuthorityGuard,
) -> Result<AttemptCheckpoint, DriverError> {
    let prepared = AttemptCheckpoint::prepared(inputs.clone())?;
    let bytes = prepared.canonical_bytes()?;
    durable_guard.reject_canonical_bytes(&bytes)?;
    session
        .create_exact(&prepared, &bytes)
        .map_err(DriverError::Journal)
}

fn reload_exact_checkpoint(
    session: &AttemptSession<'_>,
    expected: &AttemptCheckpoint,
) -> Result<AttemptCheckpoint, DriverError> {
    let actual = session.load()?;
    if actual != *expected {
        return Err(DriverError::Journal(JournalError::StaleCheckpoint {
            expected: expected.checkpoint_id().to_owned(),
            actual: actual.checkpoint_id().to_owned(),
        }));
    }
    Ok(actual)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredProcessLimits {
    max_stdin_bytes: u64,
    max_stdout_bytes: u64,
    max_stderr_bytes: u64,
    wall_time_ms: u64,
}

impl StoredProcessLimits {
    fn from_limits(limits: ProcessLimits) -> Result<Self, DriverError> {
        Ok(Self {
            max_stdin_bytes: u64::try_from(limits.max_stdin_bytes())
                .map_err(|_| invariant("stdin limit does not fit u64"))?,
            max_stdout_bytes: u64::try_from(limits.max_stdout_bytes())
                .map_err(|_| invariant("stdout limit does not fit u64"))?,
            max_stderr_bytes: u64::try_from(limits.max_stderr_bytes())
                .map_err(|_| invariant("stderr limit does not fit u64"))?,
            wall_time_ms: u64::try_from(limits.wall_time().as_millis())
                .map_err(|_| invariant("wall-time limit does not fit u64"))?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptExecutionPolicy {
    protocol: String,
    supervisor_profile_id: String,
    provider: StoredProcessLimits,
    attester: StoredProcessLimits,
    authority_protocol: String,
    http_timeout_ms: u64,
    max_response_bytes: u64,
    receipt_capacity: u64,
    authority_redaction_rule: String,
}

impl AttemptExecutionPolicy {
    fn from_request(request: &DriverRequest<'_>) -> Result<Self, DriverError> {
        Ok(Self {
            protocol: EXECUTION_POLICY_PROTOCOL.to_owned(),
            supervisor_profile_id: NATIVE_SUPERVISOR_PROFILE_ID.to_owned(),
            provider: StoredProcessLimits::from_limits(request.process_limits.provider)?,
            attester: StoredProcessLimits::from_limits(request.process_limits.attester)?,
            authority_protocol: request.authority.protocol().to_owned(),
            http_timeout_ms: request.authority.http_timeout_ms(),
            max_response_bytes: request.authority.max_response_bytes(),
            receipt_capacity: u64::try_from(RECEIPT_CAPACITY)
                .map_err(|_| invariant("receipt capacity does not fit u64"))?,
            authority_redaction_rule: AUTHORITY_REDACTION_RULE.to_owned(),
        })
    }
}

/// Live, non-debuggable rejection patterns for every durable document.
///
/// The complete authority encoding is retained only in this reconstruction
/// scope. It is never returned, displayed, logged, or placed in the journal.
struct DurableAuthorityGuard {
    needles: Vec<Vec<u8>>,
}

impl DurableAuthorityGuard {
    fn preflight(
        authority: &AuthorityDocument,
        invocation: &CapabilityInvocation,
        baseline: &AdmissionSnapshot,
        policy: &AdmissionPolicy,
    ) -> Result<Self, DriverError> {
        let guard = Self::from_authority(authority)?;
        guard.reject_document(invocation)?;
        guard.reject_document(baseline)?;
        guard.reject_document(policy)?;
        Ok(guard)
    }

    fn from_authority(authority: &AuthorityDocument) -> Result<Self, DriverError> {
        let encoded_authority = authority
            .encode_for_pipe()
            .map_err(|_| DriverError::AuthorityEncoding)?;
        let mut needles = Vec::new();
        for raw in [
            authority.endpoint().as_bytes(),
            authority.bearer_token().expose_secret().as_bytes(),
            encoded_authority.as_slice(),
        ] {
            append_needle_spellings(&mut needles, raw)?;
        }
        Ok(Self { needles })
    }

    fn exact_document(&self, value: &impl Serialize) -> Result<ExactJson, DriverError> {
        self.reject_document(value)?;
        exact_document(value)
    }

    fn reject_document(&self, value: &impl Serialize) -> Result<(), DriverError> {
        let value = serde_json::to_value(value).map_err(|_| DriverError::Serialization)?;
        let canonical = canonical_bytes(&value)?;
        if json_value_contains(&value, &self.needles) || self.contains_authority(&canonical) {
            return Err(DriverError::SensitiveDurableDocument);
        }
        Ok(())
    }

    fn reject_canonical_bytes(&self, bytes: &[u8]) -> Result<(), DriverError> {
        if self.contains_authority(bytes) {
            return Err(DriverError::SensitiveDurableDocument);
        }
        Ok(())
    }

    fn contains_authority(&self, bytes: &[u8]) -> bool {
        self.needles
            .iter()
            .any(|needle| contains_bytes(bytes, needle))
    }

    fn retained_stream_may_contain_authority(&self, bytes: &[u8]) -> bool {
        self.needles.iter().any(|needle| {
            contains_bytes(bytes, needle) || longest_suffix_prefix(bytes, needle) != 0
        })
    }
}

struct Context<'authority> {
    invocation: &'authority CapabilityInvocation,
    baseline: &'authority AdmissionSnapshot,
    admission_policy: &'authority AdmissionPolicy,
    provider_artifact: &'authority QualifiedNativeArtifact,
    attester_artifact: &'authority QualifiedNativeArtifact,
    runtime: &'authority QualifiedNativeRuntime,
    target: &'authority TargetExecutionGuard,
    authority: &'authority AuthorityDocument,
    process_limits: AttemptProcessLimits,
    plan: SemanticPlan,
    expected_authority: ConformanceAuthority,
    attester_digest: ArtifactDigest,
    inputs: AttemptInputs,
    durable_guard: DurableAuthorityGuard,
}

impl<'authority> Context<'authority> {
    #[allow(clippy::too_many_lines)]
    fn reconstruct(request: &DriverRequest<'authority>) -> Result<Self, DriverError> {
        // This is deliberately first: both start and resume reject
        // caller-controlled durable secrets before package/runtime work and,
        // for start, before the journal can be created.
        let durable_guard = DurableAuthorityGuard::preflight(
            request.authority,
            request.invocation,
            request.baseline,
            request.admission_policy,
        )?;
        request.invocation.validate()?;
        if request.invocation.specification != open_or_resolve_capability_spec()
            || request.invocation.conformance_suite != direct_conversation_ref_suite_id()
        {
            return Err(invariant("invocation is outside the exact Fleetd contract"));
        }

        let offer = request
            .packages
            .provider_offer(request.selected_provider)
            .ok_or_else(|| invariant("selected provider is absent from verified packages"))?;
        if offer != &request.invocation.selection.offer {
            return Err(invariant(
                "selected invocation offer differs from package binding",
            ));
        }
        if request
            .packages
            .provider_artifact(request.selected_provider)
            .is_none()
        {
            return Err(invariant("selected provider artifact no longer resolves"));
        }
        let attester_binding = &request.packages.report().attester;
        if request
            .packages
            .attester_resource(attester_binding)
            .is_none()
        {
            return Err(invariant("attester artifact no longer resolves"));
        }

        validate_artifact_lock(
            request.provider_artifact.lock(),
            NativeArtifactRole::Provider,
            &request.selected_provider.implementation,
            request.selected_provider.package.as_str(),
            request.selected_provider.package_digest.as_str(),
            request.selected_provider.resource.as_str(),
            request.selected_provider.resource_digest.as_str(),
        )?;
        validate_artifact_lock(
            request.attester_artifact.lock(),
            NativeArtifactRole::Attester,
            &attester_binding.implementation,
            attester_binding.package.as_str(),
            attester_binding.package_digest.as_str(),
            attester_binding.resource.as_str(),
            attester_binding.resource_digest.as_str(),
        )?;
        request.provider_artifact.revalidate()?;
        request.attester_artifact.revalidate()?;
        request.runtime.qualification().validate()?;
        if request.runtime.qualification().provider_artifact_lock_id()
            != request.provider_artifact.lock().lock_id()
            || request.runtime.qualification().attester_artifact_lock_id()
                != request.attester_artifact.lock().lock_id()
            || request.runtime.lock().runtime_digest()
                != request.runtime.qualification().qualification_id()
        {
            return Err(invariant(
                "native runtime does not bind the selected artifacts",
            ));
        }

        request.target.binding().validate()?;
        validate_target_authority(request)?;
        let [input] = request.invocation.inputs.as_slice() else {
            return Err(invariant(
                "direct-conversation invocation must have one input",
            ));
        };
        let intent = DirectPairIntent::from_fact(&input.fact)?;
        if intent.fleetd_target() != request.target.binding().deployment().fleetd_target() {
            return Err(invariant("semantic target differs from locked deployment"));
        }

        request.baseline.validate()?;
        request.admission_policy.validate()?;
        let baseline = AdmissionLedger::rebuild(request.baseline)?;
        resolve_invocation_inputs(&baseline, request.invocation)?;

        let planner = request.packages.planner(request.planning_limits)?;
        let plan = planner.plan(
            request
                .invocation
                .inputs
                .iter()
                .map(|linked| linked.fact.value_kind.clone()),
            direct_conversation_ref_value_kind(),
        )?;
        let relinked = planner.link_invocation(
            &plan,
            InvocationLink {
                capability: &request.invocation.specification.id,
                offer: &request.invocation.selection.offer.offer_id,
                selection_extensions: request.invocation.selection.extensions.clone(),
                inputs: request.invocation.inputs.clone(),
                conformance_suite: request.invocation.conformance_suite.clone(),
                invocation_extensions: request.invocation.extensions.clone(),
            },
        )?;
        if relinked != *request.invocation {
            return Err(invariant("invocation differs from exact package relinking"));
        }

        let attester_digest = ArtifactDigest::parse(
            request
                .attester_artifact
                .lock()
                .resource_digest()
                .to_owned(),
        )
        .map_err(|_| invariant("attester resource digest is not an artifact digest"))?;
        let expected_authority = ConformanceAuthority::new(
            direct_conversation_ref_suite_id(),
            ConformanceAttester::new(
                implementation_id(),
                attester_digest.clone(),
                BTreeMap::new(),
            )?,
            BTreeMap::new(),
        )?;
        let execution_policy = AttemptExecutionPolicy::from_request(request)?;
        let provider_lock = deployment_lock(request.provider_artifact.lock())?;
        let attester_lock = deployment_lock(request.attester_artifact.lock())?;
        let inputs = AttemptInputs::new(UnboundAttemptInputs {
            semantic_plan: durable_guard.exact_document(&plan)?,
            invocation: durable_guard.exact_document(request.invocation)?,
            baseline_snapshot: durable_guard.exact_document(request.baseline)?,
            conformance_suite: request.invocation.conformance_suite.to_string(),
            provider: provider_lock,
            attester: attester_lock,
            native_runtime: request.runtime.lock().clone(),
            target: request.target.binding().clone(),
            provider_replay_law: PROVIDER_REPLAY_LAW.to_owned(),
            attester_replay_law: ATTESTER_REPLAY_LAW.to_owned(),
            execution_policy: durable_guard.exact_document(&execution_policy)?,
            admission_policy: durable_guard.exact_document(request.admission_policy)?,
        })?;
        durable_guard.reject_document(&inputs)?;

        Ok(Self {
            invocation: request.invocation,
            baseline: request.baseline,
            admission_policy: request.admission_policy,
            provider_artifact: request.provider_artifact,
            attester_artifact: request.attester_artifact,
            runtime: request.runtime,
            target: request.target,
            authority: request.authority,
            process_limits: request.process_limits,
            plan,
            expected_authority,
            attester_digest,
            inputs,
            durable_guard,
        })
    }

    fn validate_checkpoint(&self, checkpoint: &AttemptCheckpoint) -> Result<(), DriverError> {
        self.target.binding().validate()?;
        self.durable_guard
            .reject_canonical_bytes(&checkpoint.canonical_bytes()?)?;
        checkpoint.validate()?;
        if checkpoint.inputs() != &self.inputs {
            return Err(invariant("checkpoint immutable inputs changed"));
        }
        let plan: SemanticPlan = decode_exact(checkpoint.inputs().semantic_plan())?;
        if plan != self.plan {
            return Err(invariant("checkpoint semantic plan changed"));
        }
        let invocation: CapabilityInvocation = decode_exact(checkpoint.inputs().invocation())?;
        if invocation != *self.invocation {
            return Err(invariant("checkpoint invocation changed"));
        }
        let baseline: AdmissionSnapshot = decode_exact(checkpoint.inputs().baseline_snapshot())?;
        if baseline != *self.baseline {
            return Err(invariant("checkpoint baseline changed"));
        }
        let policy: AdmissionPolicy = decode_exact(checkpoint.inputs().admission_policy())?;
        if policy != *self.admission_policy {
            return Err(invariant("checkpoint admission policy changed"));
        }
        let execution_policy: AttemptExecutionPolicy =
            decode_exact(checkpoint.inputs().execution_policy())?;
        execution_policy_matches(&execution_policy, self)?;
        Ok(())
    }

    fn provider_stdin(&self) -> Result<Vec<u8>, DriverError> {
        canonical_bytes(self.invocation)
    }

    fn assessment_request(
        &self,
        result: &CapabilityResult,
        candidate: &CapabilityCandidate,
    ) -> Result<AssessmentRequest, DriverError> {
        AssessmentRequest::new(
            self.invocation.clone(),
            result.clone(),
            candidate.clone(),
            self.attester_digest.clone(),
        )
        .map_err(DriverError::Attester)
    }

    fn durable_document(&self, value: &impl Serialize) -> Result<ExactJson, DriverError> {
        self.durable_guard.exact_document(value)
    }

    fn receipt_expectation<'context>(
        &'context self,
        artifact: &'context QualifiedNativeArtifact,
        limits: ProcessLimits,
        stdin: &'context [u8],
    ) -> ReceiptExpectation<'context> {
        ReceiptExpectation {
            runtime_qualification_id: self.runtime.qualification().qualification_id(),
            artifact_lock_id: artifact.lock().lock_id(),
            limits,
            stdin,
            authority: self.authority,
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive journal recovery-action match is intentionally kept together"
)]
fn drive_loop(
    session: &AttemptSession<'_>,
    context: &Context<'_>,
    mut checkpoint: AttemptCheckpoint,
) -> Result<DriverProgress, DriverError> {
    loop {
        context.validate_checkpoint(&checkpoint)?;
        match checkpoint.recovery_action() {
            RecoveryAction::ArmProvider => {
                checkpoint = publish(session, context, &checkpoint, &checkpoint.arm_provider()?)?;
            }
            RecoveryAction::InspectProviderPrefix { may_launch } => {
                match scan_provider_prefix(context, &checkpoint)? {
                    Some((index, _)) => {
                        checkpoint = publish(
                            session,
                            context,
                            &checkpoint,
                            &checkpoint.capture_provider(index)?,
                        )?;
                    }
                    None if !may_launch => {
                        return Ok(DriverProgress::Parked {
                            checkpoint,
                            reason: ParkReason::ProviderReceiptCapacity,
                        });
                    }
                    None => {
                        let stdin = context.provider_stdin()?;
                        let redacted_fallback =
                            redacted_provider_successor(&context.durable_guard, &checkpoint)?;
                        let receipt = match launch(
                            context.runtime,
                            context.provider_artifact,
                            context.authority,
                            &stdin,
                            context.process_limits.provider,
                        ) {
                            Ok(receipt) => receipt,
                            Err(error) => {
                                return Ok(DriverProgress::Parked {
                                    checkpoint,
                                    reason: ParkReason::ProviderLaunch(error),
                                });
                            }
                        };
                        let next = receipt_successor_or_fallback(
                            &context.durable_guard,
                            retain_before_interpretation(&receipt, &context.durable_guard)
                                .and_then(|retained| {
                                    checkpoint
                                        .append_provider_receipt(retained)
                                        .map_err(DriverError::Journal)
                                }),
                            redacted_fallback,
                        );
                        checkpoint = publish(session, context, &checkpoint, &next)?;
                    }
                }
            }
            RecoveryAction::BuildCandidateOrUnable => {
                let result = decisive_provider_result(context, &checkpoint)?;
                let next = match &result.outcome {
                    CapabilityOutcome::Produced { .. } => {
                        checkpoint.candidate_ready(context.durable_document(
                            &CapabilityCandidate::new(context.invocation, result, BTreeMap::new())?,
                        )?)?
                    }
                    CapabilityOutcome::Unable { .. } => {
                        require_exact_typed_inability(&result)?;
                        checkpoint.unable(context.durable_document(&result)?)?
                    }
                };
                checkpoint = publish(session, context, &checkpoint, &next)?;
            }
            RecoveryAction::ArmAttester => {
                let (result, candidate) = reconstructed_candidate(context, &checkpoint)?;
                let request = context.assessment_request(&result, &candidate)?;
                checkpoint = publish(
                    session,
                    context,
                    &checkpoint,
                    &checkpoint.arm_attester(context.durable_document(&request)?)?,
                )?;
            }
            RecoveryAction::InspectAttesterPrefix { may_launch } => {
                match scan_attester_prefix(context, &checkpoint)? {
                    Some((index, _)) => {
                        checkpoint = publish(
                            session,
                            context,
                            &checkpoint,
                            &checkpoint.capture_attester(index)?,
                        )?;
                    }
                    None if !may_launch => {
                        return Ok(DriverProgress::Parked {
                            checkpoint,
                            reason: ParkReason::AttesterReceiptCapacity,
                        });
                    }
                    None => {
                        let request = reconstructed_assessment_request(context, &checkpoint)?;
                        let stdin = canonical_bytes(&request)?;
                        let redacted_fallback =
                            redacted_attester_successor(&context.durable_guard, &checkpoint)?;
                        let receipt = match launch(
                            context.runtime,
                            context.attester_artifact,
                            context.authority,
                            &stdin,
                            context.process_limits.attester,
                        ) {
                            Ok(receipt) => receipt,
                            Err(error) => {
                                return Ok(DriverProgress::Parked {
                                    checkpoint,
                                    reason: ParkReason::AttesterLaunch(error),
                                });
                            }
                        };
                        let next = receipt_successor_or_fallback(
                            &context.durable_guard,
                            retain_before_interpretation(&receipt, &context.durable_guard)
                                .and_then(|retained| {
                                    checkpoint
                                        .append_attester_receipt(retained)
                                        .map_err(DriverError::Journal)
                                }),
                            redacted_fallback,
                        );
                        checkpoint = publish(session, context, &checkpoint, &next)?;
                    }
                }
            }
            RecoveryAction::BuildAssessment => {
                let assessment = decisive_assessment(context, &checkpoint)?;
                checkpoint = publish(
                    session,
                    context,
                    &checkpoint,
                    &checkpoint.assessment_ready(context.durable_document(&assessment)?)?,
                )?;
            }
            RecoveryAction::EvaluateAdmission => {
                let next = match evaluate_admission(context, &checkpoint)? {
                    AdmissionEvaluation::Admitted(snapshot) => {
                        checkpoint.admitted(context.durable_document(&snapshot)?)?
                    }
                    AdmissionEvaluation::Withheld(decision) => {
                        checkpoint.withheld(context.durable_document(&decision)?)?
                    }
                };
                checkpoint = publish(session, context, &checkpoint, &next)?;
            }
            RecoveryAction::ReplayTerminal => {
                replay_terminal(context, &checkpoint)?;
                return Ok(DriverProgress::Terminal(checkpoint));
            }
        }
    }
}

fn publish(
    session: &AttemptSession<'_>,
    context: &Context<'_>,
    current: &AttemptCheckpoint,
    next: &AttemptCheckpoint,
) -> Result<AttemptCheckpoint, DriverError> {
    let bytes = next.canonical_bytes()?;
    context.durable_guard.reject_canonical_bytes(&bytes)?;
    session.replace_exact(current.checkpoint_id(), next, &bytes)?;
    let loaded = session.load()?;
    context.validate_checkpoint(&loaded)?;
    if loaded != *next {
        return Err(invariant("published checkpoint differs after reload"));
    }
    Ok(loaded)
}

fn redacted_provider_successor(
    guard: &DurableAuthorityGuard,
    checkpoint: &AttemptCheckpoint,
) -> Result<AttemptCheckpoint, DriverError> {
    let successor = checkpoint.append_provider_receipt(guarded_redacted_receipt(guard)?)?;
    guard.reject_canonical_bytes(&successor.canonical_bytes()?)?;
    Ok(successor)
}

fn redacted_attester_successor(
    guard: &DurableAuthorityGuard,
    checkpoint: &AttemptCheckpoint,
) -> Result<AttemptCheckpoint, DriverError> {
    let successor = checkpoint.append_attester_receipt(guarded_redacted_receipt(guard)?)?;
    guard.reject_canonical_bytes(&successor.canonical_bytes()?)?;
    Ok(successor)
}

fn receipt_successor_or_fallback(
    guard: &DurableAuthorityGuard,
    exact: Result<AttemptCheckpoint, DriverError>,
    redacted_fallback: AttemptCheckpoint,
) -> AttemptCheckpoint {
    // Both live call sites construct and validate `redacted_fallback` before
    // launch. That establishes current phase/capacity legality. `exact` then
    // contains only pure post-child receipt construction, append validation,
    // and complete-envelope guarding; every failure in that closed region
    // must select the already-proven successor instead of losing the effect.
    let exact = exact.and_then(|exact| {
        guard.reject_canonical_bytes(&exact.canonical_bytes()?)?;
        Ok(exact)
    });
    match exact {
        Ok(exact) => exact,
        Err(_) => redacted_fallback,
    }
}

/// Construct the only receipt evidence the driver may hand to the journal.
///
/// The guard covers the complete canonical `ProcessReceipt`, then the complete
/// `RetainedReceipt::Exact` wrapper. A rejected exact wrapper degrades to the
/// outer marker, whose complete canonical form is checked once and contains
/// only a rule-derived marker digest plus this driver's public redaction rule.
/// The complete redacted checkpoint successor is derived and checked before
/// launch, so post-effect exact-envelope collisions can always fall back to
/// already-proven persistable evidence. The full
/// `AttemptCheckpoint` which later contains this value is independently
/// checked immediately before exact-byte CAS and after every load. Filesystem
/// publication names and temporary siblings are journal mechanics rather than
/// retained documents and are not recursively scanned.
fn retain_before_interpretation(
    receipt: &ProcessReceipt,
    guard: &DurableAuthorityGuard,
) -> Result<RetainedReceipt, DriverError> {
    receipt.validate()?;
    let receipt_bytes = canonical_bytes(receipt)?;
    if receipt.stdout().redacted()
        || receipt.stderr().redacted()
        || guard.retained_stream_may_contain_authority(receipt.stdout().bytes())
        || guard.retained_stream_may_contain_authority(receipt.stderr().bytes())
        || guard.retained_stream_may_contain_authority(&receipt_bytes)
    {
        return guarded_redacted_receipt(guard);
    }
    let receipt_value: Value =
        serde_json::from_slice(&receipt_bytes).map_err(|_| DriverError::Serialization)?;
    let exact = ExactJson::new(receipt_value)?;
    let retained = RetainedReceipt::exact(exact)?;
    match guard.reject_document(&retained) {
        Ok(()) => Ok(retained),
        Err(DriverError::SensitiveDurableDocument) => guarded_redacted_receipt(guard),
        Err(error) => Err(error),
    }
}

fn guarded_redacted_receipt(guard: &DurableAuthorityGuard) -> Result<RetainedReceipt, DriverError> {
    let retained = RetainedReceipt::redacted(AUTHORITY_REDACTION_RULE)?;
    guard.reject_document(&retained)?;
    Ok(retained)
}

struct ReceiptExpectation<'authority> {
    runtime_qualification_id: &'authority str,
    artifact_lock_id: &'authority str,
    limits: ProcessLimits,
    stdin: &'authority [u8],
    authority: &'authority AuthorityDocument,
}

fn decode_correlated_receipt(
    retained: &RetainedReceipt,
    expected: &ReceiptExpectation<'_>,
) -> Result<Option<ProcessReceipt>, DriverError> {
    let receipt = match retained {
        RetainedReceipt::Exact { receipt } => receipt,
        RetainedReceipt::Redacted { redaction_rule, .. }
            if redaction_rule == AUTHORITY_REDACTION_RULE =>
        {
            return Ok(None);
        }
        RetainedReceipt::Redacted { .. } => {
            return Err(invariant("retained receipt uses a foreign redaction rule"));
        }
    };
    let decoded: ProcessReceipt = serde_json::from_value(receipt.value().clone())
        .map_err(|_| invariant("retained exact receipt is not a process receipt"))?;
    decoded.validate()?;
    let applied = decoded.limits();
    let expected_wall_time = u64::try_from(expected.limits.wall_time().as_millis())
        .map_err(|_| invariant("expected deadline does not fit u64"))?;
    let authority = decoded.input().authority();
    if decoded.runtime_qualification_id() != expected.runtime_qualification_id
        || decoded.artifact_lock_id() != expected.artifact_lock_id
        || applied.max_stdin_bytes()
            != u64::try_from(expected.limits.max_stdin_bytes())
                .map_err(|_| invariant("expected stdin limit does not fit u64"))?
        || applied.max_stdout_bytes()
            != u64::try_from(expected.limits.max_stdout_bytes())
                .map_err(|_| invariant("expected stdout limit does not fit u64"))?
        || applied.max_stderr_bytes()
            != u64::try_from(expected.limits.max_stderr_bytes())
                .map_err(|_| invariant("expected stderr limit does not fit u64"))?
        || applied.wall_time_ms() != expected_wall_time
        || decoded.input().stdin_bytes()
            != u64::try_from(expected.stdin.len())
                .map_err(|_| invariant("expected stdin length does not fit u64"))?
        || decoded.input().stdin_digest() != sha256_identity(expected.stdin)
        || authority.protocol() != expected.authority.protocol()
        || authority.target() != expected.authority.target()
        || authority.endpoint_mapping_digest() != expected.authority.endpoint_mapping_digest()
        || authority.credential_revision() != expected.authority.credential_revision()
        || authority.http_timeout_ms() != expected.authority.http_timeout_ms()
        || authority.max_response_bytes() != expected.authority.max_response_bytes()
    {
        return Err(invariant("process receipt correlation changed"));
    }
    Ok(Some(decoded))
}

fn scan_provider_prefix(
    context: &Context<'_>,
    checkpoint: &AttemptCheckpoint,
) -> Result<Option<(usize, CapabilityResult)>, DriverError> {
    let stdin = context.provider_stdin()?;
    let expected = context.receipt_expectation(
        context.provider_artifact,
        context.process_limits.provider,
        &stdin,
    );
    scan_provider_receipts(
        checkpoint.provider_receipts(),
        &expected,
        context.invocation,
    )
}

fn scan_provider_receipts(
    receipts: &[RetainedReceipt],
    expected: &ReceiptExpectation<'_>,
    invocation: &CapabilityInvocation,
) -> Result<Option<(usize, CapabilityResult)>, DriverError> {
    for (index, retained) in receipts.iter().enumerate() {
        let Some(receipt) = decode_correlated_receipt(retained, expected)? else {
            continue;
        };
        if !receipt.decisive_eligible() || !receipt.stderr().bytes().is_empty() {
            continue;
        }
        let Ok(result) = serde_json::from_slice::<CapabilityResult>(receipt.stdout().bytes())
        else {
            continue;
        };
        if result.validate_against(invocation).is_err()
            || validate_provider_result_shape(&result).is_err()
        {
            continue;
        }
        if index + 1 != receipts.len() {
            return Err(invariant("provider receipt follows decisive evidence"));
        }
        return Ok(Some((index, result)));
    }
    Ok(None)
}

fn scan_attester_prefix(
    context: &Context<'_>,
    checkpoint: &AttemptCheckpoint,
) -> Result<Option<(usize, ConformanceAssessment)>, DriverError> {
    let request = reconstructed_assessment_request(context, checkpoint)?;
    let stdin = canonical_bytes(&request)?;
    let expected = context.receipt_expectation(
        context.attester_artifact,
        context.process_limits.attester,
        &stdin,
    );
    scan_attester_receipts(
        checkpoint.attester_receipts(),
        &expected,
        &request,
        &context.expected_authority,
    )
}

fn scan_attester_receipts(
    receipts: &[RetainedReceipt],
    expected: &ReceiptExpectation<'_>,
    request: &AssessmentRequest,
    expected_authority: &ConformanceAuthority,
) -> Result<Option<(usize, ConformanceAssessment)>, DriverError> {
    for (index, retained) in receipts.iter().enumerate() {
        let Some(receipt) = decode_correlated_receipt(retained, expected)? else {
            continue;
        };
        if !receipt.decisive_eligible() || !receipt.stderr().bytes().is_empty() {
            continue;
        }
        let Ok(assessment) =
            serde_json::from_slice::<ConformanceAssessment>(receipt.stdout().bytes())
        else {
            continue;
        };
        if assessment
            .validate_against(request.invocation(), request.result(), request.candidate())
            .is_err()
            || assessment.authority != *expected_authority
            || validate_attester_assessment_shape(&assessment).is_err()
        {
            continue;
        }
        if index + 1 != receipts.len() {
            return Err(invariant("attester receipt follows decisive evidence"));
        }
        return Ok(Some((index, assessment)));
    }
    Ok(None)
}

fn decisive_provider_result(
    context: &Context<'_>,
    checkpoint: &AttemptCheckpoint,
) -> Result<CapabilityResult, DriverError> {
    let reference = checkpoint
        .provider_decisive()
        .ok_or_else(|| invariant("provider-captured checkpoint lacks receipt reference"))?;
    let (index, result) = scan_provider_prefix(context, checkpoint)?
        .ok_or_else(|| invariant("referenced provider receipt is not decisive"))?;
    if usize::from(reference.index()) != index
        || reference.receipt_digest() != checkpoint.provider_receipts()[index].digest()
    {
        return Err(invariant("provider decisive receipt reference changed"));
    }
    Ok(result)
}

fn reconstructed_candidate(
    context: &Context<'_>,
    checkpoint: &AttemptCheckpoint,
) -> Result<(CapabilityResult, CapabilityCandidate), DriverError> {
    let result = decisive_provider_result(context, checkpoint)?;
    if !result.is_produced() {
        return Err(invariant("candidate phase retains an unable result"));
    }
    let expected = CapabilityCandidate::new(context.invocation, result.clone(), BTreeMap::new())?;
    let candidate: CapabilityCandidate = decode_exact(
        checkpoint
            .candidate()
            .ok_or_else(|| invariant("candidate phase lacks candidate"))?,
    )?;
    candidate.validate_against(context.invocation)?;
    if candidate != expected {
        return Err(invariant(
            "journaled candidate differs from provider result",
        ));
    }
    Ok((result, candidate))
}

fn reconstructed_assessment_request(
    context: &Context<'_>,
    checkpoint: &AttemptCheckpoint,
) -> Result<AssessmentRequest, DriverError> {
    let (result, candidate) = reconstructed_candidate(context, checkpoint)?;
    let expected = context.assessment_request(&result, &candidate)?;
    let request: AssessmentRequest = decode_exact(
        checkpoint
            .assessment_request()
            .ok_or_else(|| invariant("attester phase lacks assessment request"))?,
    )?;
    request.validate()?;
    if request != expected {
        return Err(invariant("journaled assessment request changed"));
    }
    Ok(request)
}

fn decisive_assessment(
    context: &Context<'_>,
    checkpoint: &AttemptCheckpoint,
) -> Result<ConformanceAssessment, DriverError> {
    let reference = checkpoint
        .attester_decisive()
        .ok_or_else(|| invariant("attester-captured checkpoint lacks receipt reference"))?;
    let (index, assessment) = scan_attester_prefix(context, checkpoint)?
        .ok_or_else(|| invariant("referenced attester receipt is not decisive"))?;
    if usize::from(reference.index()) != index
        || reference.receipt_digest() != checkpoint.attester_receipts()[index].digest()
    {
        return Err(invariant("attester decisive receipt reference changed"));
    }
    Ok(assessment)
}

fn require_exact_typed_inability(result: &CapabilityResult) -> Result<(), DriverError> {
    let CapabilityOutcome::Unable {
        failure,
        extensions,
    } = &result.outcome
    else {
        return Err(invariant("produced result is not a typed inability"));
    };
    if failure.kind != immutable_mode_conflict_failure_kind()
        || failure.detail != Value::Null
        || !failure.extensions.is_empty()
        || !extensions.is_empty()
        || !result.evidence.is_empty()
        || !result.extensions.is_empty()
    {
        return Err(invariant(
            "provider inability is outside the exact contract",
        ));
    }
    Ok(())
}

fn validate_provider_result_shape(result: &CapabilityResult) -> Result<(), DriverError> {
    if !result.evidence.is_empty() || !result.extensions.is_empty() {
        return Err(invariant(
            "provider result carries unsupported ABI extensions",
        ));
    }
    match &result.outcome {
        CapabilityOutcome::Unable { .. } => require_exact_typed_inability(result),
        CapabilityOutcome::Produced {
            outputs,
            extensions,
        } => {
            let [output] = outputs.as_slice() else {
                return Err(invariant("provider result does not have one output"));
            };
            if !extensions.is_empty() || !output.extensions.is_empty() {
                return Err(invariant(
                    "provider output carries unsupported ABI extensions",
                ));
            }
            DirectConversationRef::from_fact(&output.fact)?;
            Ok(())
        }
    }
}

fn validate_attester_assessment_shape(
    assessment: &ConformanceAssessment,
) -> Result<(), DriverError> {
    if !assessment.extensions.is_empty()
        || !assessment.evidence.is_empty()
        || !assessment.authority.extensions.is_empty()
        || !assessment.authority.attester.extensions.is_empty()
        || assessment.checks.len() != 3
    {
        return Err(invariant(
            "attester assessment carries unsupported ABI shape",
        ));
    }
    let exact = assessment
        .checks
        .get(ATTESTER_CHECK_EXACT_CONTRACT)
        .ok_or_else(|| invariant("attester assessment lacks exact-contract check"))?;
    let relation = assessment
        .checks
        .get(ATTESTER_CHECK_INTENT_OUTPUT_RELATION)
        .ok_or_else(|| invariant("attester assessment lacks relation check"))?;
    let observation = assessment
        .checks
        .get(ATTESTER_CHECK_FLEETD_OBSERVATION)
        .ok_or_else(|| invariant("attester assessment lacks observation check"))?;
    if exact.outcome != AssessmentOutcome::Passed
        || relation.outcome != AssessmentOutcome::Passed
        || !matches!(
            observation.outcome,
            AssessmentOutcome::Passed | AssessmentOutcome::Failed
        )
        || assessment
            .checks
            .values()
            .any(|check| !check.evidence.is_empty() || !check.extensions.is_empty())
    {
        return Err(invariant(
            "attester assessment differs from exact command ABI",
        ));
    }
    Ok(())
}

enum AdmissionEvaluation {
    Admitted(AdmissionSnapshot),
    Withheld(AdmissionDecision),
}

fn evaluate_admission(
    context: &Context<'_>,
    checkpoint: &AttemptCheckpoint,
) -> Result<AdmissionEvaluation, DriverError> {
    let (result, candidate) = reconstructed_candidate(context, checkpoint)?;
    let assessment = decisive_assessment(context, checkpoint)?;
    let retained: ConformanceAssessment = decode_exact(
        checkpoint
            .assessment()
            .ok_or_else(|| invariant("assessment-ready checkpoint lacks assessment"))?,
    )?;
    if retained != assessment {
        return Err(invariant(
            "journaled assessment differs from decisive receipt",
        ));
    }
    evaluate_chain_admission(
        context.baseline,
        context.admission_policy,
        context.invocation,
        &result,
        &candidate,
        &assessment,
    )
}

fn evaluate_chain_admission(
    baseline: &AdmissionSnapshot,
    policy: &AdmissionPolicy,
    invocation: &CapabilityInvocation,
    result: &CapabilityResult,
    candidate: &CapabilityCandidate,
    assessment: &ConformanceAssessment,
) -> Result<AdmissionEvaluation, DriverError> {
    let mut ledger = AdmissionLedger::rebuild(baseline)?;
    let outcome = ledger.admit_candidate(policy, invocation, result, candidate, assessment)?;
    match outcome {
        AdmissionOutcome::Withheld { decision } => {
            decision.validate_candidate(policy, invocation, result, candidate, assessment)?;
            let unchanged = ledger.export_with_extensions(baseline.extensions.clone())?;
            if unchanged != *baseline {
                return Err(invariant("withheld admission mutated the baseline"));
            }
            Ok(AdmissionEvaluation::Withheld(decision))
        }
        AdmissionOutcome::Admitted { decision, links } => {
            decision.validate_candidate(policy, invocation, result, candidate, assessment)?;
            let CapabilityOutcome::Produced { outputs, .. } = &result.outcome else {
                return Err(invariant("admission accepted an unable result"));
            };
            if outputs.len() != links.len() {
                return Err(invariant("admission links do not cover every output"));
            }
            for (output, link) in outputs.iter().zip(&links) {
                if link.port.as_ref() != Some(&output.port)
                    || ledger.resolve(&link.reference)?.fact != &output.fact
                {
                    return Err(invariant("admission link changed its exact output"));
                }
            }
            let snapshot = ledger.export_with_extensions(baseline.extensions.clone())?;
            snapshot.validate()?;
            let rebuilt = AdmissionLedger::rebuild(&snapshot)?;
            for (output, link) in outputs.iter().zip(&links) {
                if rebuilt.resolve(&link.reference)?.fact != &output.fact {
                    return Err(invariant("rebuilt snapshot lost an admitted output"));
                }
            }
            Ok(AdmissionEvaluation::Admitted(snapshot))
        }
    }
}

fn replay_terminal(
    context: &Context<'_>,
    checkpoint: &AttemptCheckpoint,
) -> Result<(), DriverError> {
    match checkpoint
        .resolution()
        .ok_or_else(|| invariant("terminal checkpoint lacks resolution"))?
    {
        AttemptResolution::Unable { result } => {
            let expected = decisive_provider_result(context, checkpoint)?;
            require_exact_typed_inability(&expected)?;
            if decode_exact::<CapabilityResult>(result)? != expected {
                return Err(invariant("terminal inability changed"));
            }
        }
        AttemptResolution::Admitted { admission_snapshot } => {
            let AdmissionEvaluation::Admitted(expected) = evaluate_admission(context, checkpoint)?
            else {
                return Err(invariant("admitted resolution now evaluates withheld"));
            };
            if decode_exact::<AdmissionSnapshot>(admission_snapshot)? != expected {
                return Err(invariant("terminal admission snapshot changed"));
            }
        }
        AttemptResolution::Withheld { decision } => {
            let AdmissionEvaluation::Withheld(expected) = evaluate_admission(context, checkpoint)?
            else {
                return Err(invariant("withheld resolution now evaluates admitted"));
            };
            if decode_exact::<AdmissionDecision>(decision)? != expected {
                return Err(invariant("terminal withholding decision changed"));
            }
        }
    }
    Ok(())
}

fn validate_target_authority(request: &DriverRequest<'_>) -> Result<(), DriverError> {
    let deployment = request.target.binding().deployment();
    if request.authority.target() != deployment.fleetd_target().as_str()
        || request.authority.endpoint_mapping_digest() != deployment.endpoint_mapping_digest()
        || request.authority.credential_revision() != deployment.credential_revision()
    {
        return Err(invariant(
            "command authority differs from target deployment",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_artifact_lock(
    lock: &QualifiedNativeArtifactLock,
    role: NativeArtifactRole,
    implementation: &str,
    package: &str,
    package_digest: &str,
    resource: &str,
    resource_digest: &str,
) -> Result<(), DriverError> {
    lock.validate()?;
    if lock.role() != role
        || lock.implementation() != implementation
        || lock.package() != package
        || lock.package_digest() != package_digest
        || lock.resource() != resource
        || lock.resource_digest() != resource_digest
    {
        return Err(invariant(
            "qualified native artifact differs from package binding",
        ));
    }
    Ok(())
}

fn deployment_lock(lock: &QualifiedNativeArtifactLock) -> Result<DeploymentLock, DriverError> {
    DeploymentLock::new(
        lock.implementation(),
        lock.package(),
        lock.package_digest(),
        lock.resource(),
        lock.resource_digest(),
    )
    .map_err(DriverError::Journal)
}

fn execution_policy_matches(
    retained: &AttemptExecutionPolicy,
    context: &Context<'_>,
) -> Result<(), DriverError> {
    let expected = AttemptExecutionPolicy {
        protocol: EXECUTION_POLICY_PROTOCOL.to_owned(),
        supervisor_profile_id: NATIVE_SUPERVISOR_PROFILE_ID.to_owned(),
        provider: StoredProcessLimits::from_limits(context.process_limits.provider)?,
        attester: StoredProcessLimits::from_limits(context.process_limits.attester)?,
        authority_protocol: context.authority.protocol().to_owned(),
        http_timeout_ms: context.authority.http_timeout_ms(),
        max_response_bytes: context.authority.max_response_bytes(),
        receipt_capacity: u64::try_from(RECEIPT_CAPACITY)
            .map_err(|_| invariant("receipt capacity does not fit u64"))?,
        authority_redaction_rule: AUTHORITY_REDACTION_RULE.to_owned(),
    };
    if retained != &expected {
        return Err(invariant("checkpoint execution policy changed"));
    }
    Ok(())
}

fn resolve_invocation_inputs(
    ledger: &AdmissionLedger,
    invocation: &CapabilityInvocation,
) -> Result<(), DriverError> {
    for input in &invocation.inputs {
        if ledger.resolve(&input.admitted)?.fact != &input.fact {
            return Err(invariant("linked invocation input changed in baseline"));
        }
    }
    Ok(())
}

fn exact_document(value: &impl Serialize) -> Result<ExactJson, DriverError> {
    let value = serde_json::to_value(value).map_err(|_| DriverError::Serialization)?;
    ExactJson::new(value).map_err(DriverError::Journal)
}

fn decode_exact<T: serde::de::DeserializeOwned>(exact: &ExactJson) -> Result<T, DriverError> {
    serde_json::from_value(exact.value().clone()).map_err(|_| DriverError::Serialization)
}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, DriverError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| DriverError::Serialization)
}

fn sha256_identity(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn longest_suffix_prefix(haystack: &[u8], needle: &[u8]) -> usize {
    let maximum = haystack.len().min(needle.len().saturating_sub(1));
    (1..=maximum)
        .rev()
        .find(|length| haystack[haystack.len() - length..] == needle[..*length])
        .unwrap_or(0)
}

fn append_needle_spellings(needles: &mut Vec<Vec<u8>>, raw: &[u8]) -> Result<(), DriverError> {
    let text = std::str::from_utf8(raw).map_err(|_| DriverError::AuthorityEncoding)?;
    let ordinary_encoded = serde_json::to_vec(text).map_err(|_| DriverError::AuthorityEncoding)?;
    let ordinary = json_string_interior(&ordinary_encoded)?;
    let canonical_encoded =
        serde_json_canonicalizer::to_vec(&text).map_err(|_| DriverError::AuthorityEncoding)?;
    let canonical = json_string_interior(&canonical_encoded)?;
    for spelling in [raw.to_vec(), ordinary, canonical] {
        if !needles.contains(&spelling) {
            needles.push(spelling);
        }
    }
    Ok(())
}

fn json_string_interior(encoded: &[u8]) -> Result<Vec<u8>, DriverError> {
    let Some(interior) = encoded
        .strip_prefix(b"\"")
        .and_then(|encoded| encoded.strip_suffix(b"\""))
    else {
        return Err(DriverError::AuthorityEncoding);
    };
    Ok(interior.to_vec())
}

fn json_value_contains(value: &Value, patterns: &[Vec<u8>]) -> bool {
    let matches = |bytes: &[u8]| {
        patterns
            .iter()
            .any(|pattern| contains_bytes(bytes, pattern))
    };
    match value {
        Value::String(value) => matches(value.as_bytes()),
        Value::Array(values) => values
            .iter()
            .any(|value| json_value_contains(value, patterns)),
        Value::Object(entries) => entries
            .iter()
            .any(|(key, value)| matches(key.as_bytes()) || json_value_contains(value, patterns)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

const fn invariant(detail: &'static str) -> DriverError {
    DriverError::Invariant(detail)
}

/// Closed proof-driver failure. No variant carries endpoint or credential data.
#[derive(Debug)]
pub enum DriverError {
    Journal(JournalError),
    Planning(PlanningError),
    Protocol(ProtocolError),
    Authority(AuthorityError),
    Attester(AttesterError),
    Contract(ContractFactError),
    Native(NativeQualificationError),
    Runtime(RuntimeQualificationError),
    Target(TargetError),
    Supervisor(SupervisorError),
    AuthorityEncoding,
    SensitiveDurableDocument,
    Serialization,
    Invariant(&'static str),
}

impl fmt::Display for DriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Journal(_) => "attempt journal failed",
            Self::Planning(_) => "semantic planning or linking failed",
            Self::Protocol(_) => "capability protocol validation failed",
            Self::Authority(_) => "conformance or admission validation failed",
            Self::Attester(_) => "assessment request validation failed",
            Self::Contract(_) => "Fleetd contract payload validation failed",
            Self::Native(_) => "native artifact validation failed",
            Self::Runtime(_) => "native runtime validation failed",
            Self::Target(_) => "target deployment validation failed",
            Self::Supervisor(_) => "retained process receipt validation failed",
            Self::AuthorityEncoding => "live command authority could not be checked",
            Self::SensitiveDurableDocument => {
                "journal-bound document contains live command authority"
            }
            Self::Serialization => "exact proof document encoding failed",
            Self::Invariant(detail) => detail,
        })
    }
}

impl Error for DriverError {}

impl From<JournalError> for DriverError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}

impl From<PlanningError> for DriverError {
    fn from(value: PlanningError) -> Self {
        Self::Planning(value)
    }
}

impl From<ProtocolError> for DriverError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<AuthorityError> for DriverError {
    fn from(value: AuthorityError) -> Self {
        Self::Authority(value)
    }
}

impl From<AttesterError> for DriverError {
    fn from(value: AttesterError) -> Self {
        Self::Attester(value)
    }
}

impl From<ContractFactError> for DriverError {
    fn from(value: ContractFactError) -> Self {
        Self::Contract(value)
    }
}

impl From<NativeQualificationError> for DriverError {
    fn from(value: NativeQualificationError) -> Self {
        Self::Native(value)
    }
}

impl From<RuntimeQualificationError> for DriverError {
    fn from(value: RuntimeQualificationError) -> Self {
        Self::Runtime(value)
    }
}

impl From<TargetError> for DriverError {
    fn from(value: TargetError) -> Self {
        Self::Target(value)
    }
}

impl From<SupervisorError> for DriverError {
    fn from(value: SupervisorError) -> Self {
        Self::Supervisor(value)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use fleetd_direct_conversation_contract::{
        AgentId, ConversationId, DeliveryMode, DirectMember, FleetdTarget, conversation_port_name,
        intent_port_name,
    };
    use gooir_capability::authority::{
        AdmissionAuthorityId, ConformanceCheck, ObservationAuthority, ObservationSourceId,
        SourceObservation,
    };
    use gooir_capability::protocol::{
        AdmittedFactRef, ArtifactDigest, AuthorityRecordId, CapabilityFailure, CapabilityOffer,
        EvidenceDigest, EvidenceKindId, EvidenceRef, ImplementationId, ImplementationSelection,
        LinkedInput, NamedOutput,
    };
    use serde_json::{Map, json};

    use super::*;
    use crate::supervisor::{NATIVE_SUPERVISOR_PROFILE_ID, PROCESS_RECEIPT_PROTOCOL};

    struct SemanticFixture {
        invocation: CapabilityInvocation,
        result: CapabilityResult,
        candidate: CapabilityCandidate,
        request: AssessmentRequest,
        authority: AuthorityDocument,
        conformance_authority: ConformanceAuthority,
    }

    fn digest(byte: u8) -> String {
        sha256_identity(&[byte])
    }

    fn authority() -> AuthorityDocument {
        authority_with_token("test-secret-never-retained")
    }

    fn authority_with_token(token: &str) -> AuthorityDocument {
        AuthorityDocument::new(
            "fleetd:test",
            digest(b'a'),
            "credential-r1",
            "http://127.0.0.1:48123/",
            token,
            1_000,
            64 * 1024,
        )
        .unwrap()
    }

    fn limits() -> ProcessLimits {
        ProcessLimits::new(64 * 1024, 64 * 1024, 4 * 1024, Duration::from_secs(2)).unwrap()
    }

    fn members() -> [DirectMember; 2] {
        [
            DirectMember::new(AgentId::parse("agent-a").unwrap(), DeliveryMode::Inbox),
            DirectMember::new(AgentId::parse("agent-b").unwrap(), DeliveryMode::StreamOnly),
        ]
    }

    fn intent() -> DirectPairIntent {
        DirectPairIntent::new(FleetdTarget::parse("fleetd:test").unwrap(), members()).unwrap()
    }

    fn invocation_for_fact(
        admitted: AdmittedFactRef,
        fact: gooir_capability::Fact,
    ) -> CapabilityInvocation {
        let offer = CapabilityOffer::new(
            ImplementationId::new("dev.fleetd.implementation", "test_provider", "0.1.0"),
            ArtifactDigest::parse(digest(b'p')).unwrap(),
            open_or_resolve_capability_spec().id.clone(),
            BTreeMap::new(),
        )
        .unwrap();
        CapabilityInvocation::new(
            open_or_resolve_capability_spec(),
            ImplementationSelection::new(offer, BTreeMap::new()).unwrap(),
            vec![LinkedInput::new(intent_port_name(), admitted, fact, BTreeMap::new()).unwrap()],
            direct_conversation_ref_suite_id(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn invocation(admitted: AdmittedFactRef) -> CapabilityInvocation {
        invocation_for_fact(admitted, intent().to_fact().unwrap())
    }

    fn untrusted_invocation() -> CapabilityInvocation {
        let fact = intent().to_fact().unwrap();
        invocation(
            AdmittedFactRef::new(
                fact.id,
                AuthorityRecordId::parse(digest(b'r')).unwrap(),
                BTreeMap::new(),
            )
            .unwrap(),
        )
    }

    fn produced_result(invocation: &CapabilityInvocation) -> CapabilityResult {
        let reference = DirectConversationRef::for_intent(
            &intent(),
            ConversationId::parse("conversation-1").unwrap(),
            1_789_000_000_000,
        )
        .unwrap();
        CapabilityResult::produced(
            invocation,
            vec![
                NamedOutput::new(
                    conversation_port_name(),
                    reference.to_fact().unwrap(),
                    BTreeMap::new(),
                )
                .unwrap(),
            ],
            BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn typed_inability(invocation: &CapabilityInvocation) -> CapabilityResult {
        CapabilityResult::unable(
            invocation,
            CapabilityFailure::new(
                immutable_mode_conflict_failure_kind(),
                Value::Null,
                BTreeMap::new(),
            )
            .unwrap(),
            BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn semantic_fixture() -> SemanticFixture {
        let invocation = untrusted_invocation();
        let result = produced_result(&invocation);
        let candidate =
            CapabilityCandidate::new(&invocation, result.clone(), BTreeMap::new()).unwrap();
        let attester_digest = ArtifactDigest::parse(digest(b't')).unwrap();
        let request = AssessmentRequest::new(
            invocation.clone(),
            result.clone(),
            candidate.clone(),
            attester_digest.clone(),
        )
        .unwrap();
        let conformance_authority = ConformanceAuthority::new(
            direct_conversation_ref_suite_id(),
            ConformanceAttester::new(implementation_id(), attester_digest, BTreeMap::new())
                .unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        SemanticFixture {
            invocation,
            result,
            candidate,
            request,
            authority: authority(),
            conformance_authority,
        }
    }

    fn stream(bytes: &[u8]) -> Value {
        json!({
            "bytes": bytes,
            "observed_prefix_digest": sha256_identity(bytes),
            "retained_prefix_bytes": bytes.len() as u64,
            "observed_bytes": bytes.len().to_string(),
            "observed_byte_count": "exact",
            "overflowed": false,
            "read_failed": false,
            "redacted": false
        })
    }

    fn process_receipt(
        expectation: &ReceiptExpectation<'_>,
        stdout: &[u8],
        stderr: &[u8],
    ) -> ProcessReceipt {
        let mut body = json!({
            "protocol": PROCESS_RECEIPT_PROTOCOL,
            "supervisor_profile_id": NATIVE_SUPERVISOR_PROFILE_ID,
            "runtime_qualification_id": expectation.runtime_qualification_id,
            "artifact_lock_id": expectation.artifact_lock_id,
            "limits": {
                "max_stdin_bytes": expectation.limits.max_stdin_bytes() as u64,
                "max_stdout_bytes": expectation.limits.max_stdout_bytes() as u64,
                "max_stderr_bytes": expectation.limits.max_stderr_bytes() as u64,
                "wall_time_ms": u64::try_from(expectation.limits.wall_time().as_millis()).unwrap()
            },
            "input": {
                "stdin_bytes": expectation.stdin.len() as u64,
                "stdin_digest": sha256_identity(expectation.stdin),
                "authority": {
                    "protocol": expectation.authority.protocol(),
                    "target": expectation.authority.target(),
                    "endpoint_mapping_digest": expectation.authority.endpoint_mapping_digest(),
                    "credential_revision": expectation.authority.credential_revision(),
                    "http_timeout_ms": expectation.authority.http_timeout_ms(),
                    "max_response_bytes": expectation.authority.max_response_bytes()
                }
            },
            "termination": {"kind": "exited", "code": 0},
            "stdout": stream(stdout),
            "stderr": stream(stderr),
            "enforcement": {
                "timed_out": false,
                "stdin_write_failed": false,
                "authority_write_failed": false
            },
            "decisive_eligible": true
        });
        let receipt_id = sha256_identity(&serde_json_canonicalizer::to_vec(&body).unwrap());
        body.as_object_mut()
            .unwrap()
            .insert("receipt_id".to_owned(), Value::String(receipt_id));
        let receipt: ProcessReceipt = serde_json::from_value(body).unwrap();
        receipt.validate().unwrap();
        receipt
    }

    fn retained(receipt: &ProcessReceipt) -> RetainedReceipt {
        RetainedReceipt::exact(exact_document(receipt).unwrap()).unwrap()
    }

    fn expectation<'a>(
        stdin: &'a [u8],
        authority: &'a AuthorityDocument,
    ) -> ReceiptExpectation<'a> {
        ReceiptExpectation {
            runtime_qualification_id: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            artifact_lock_id: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            limits: limits(),
            stdin,
            authority,
        }
    }

    fn check(outcome: AssessmentOutcome) -> ConformanceCheck {
        ConformanceCheck::new(outcome, Vec::new(), BTreeMap::new()).unwrap()
    }

    fn assessment(
        fixture: &SemanticFixture,
        observation: AssessmentOutcome,
    ) -> ConformanceAssessment {
        ConformanceAssessment::new(
            &fixture.invocation,
            &fixture.result,
            &fixture.candidate,
            fixture.conformance_authority.clone(),
            BTreeMap::from([
                (
                    ATTESTER_CHECK_EXACT_CONTRACT.to_owned(),
                    check(AssessmentOutcome::Passed),
                ),
                (
                    ATTESTER_CHECK_INTENT_OUTPUT_RELATION.to_owned(),
                    check(AssessmentOutcome::Passed),
                ),
                (
                    ATTESTER_CHECK_FLEETD_OBSERVATION.to_owned(),
                    check(observation),
                ),
            ]),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    #[test]
    fn provider_prefix_replays_operational_evidence_before_decisive_result() {
        let invocation = untrusted_invocation();
        let result = produced_result(&invocation);
        let stdin = canonical_bytes(&invocation).unwrap();
        let authority = authority();
        let expectation = expectation(&stdin, &authority);
        let malformed = process_receipt(&expectation, b"not-json", b"");
        let decisive = process_receipt(
            &expectation,
            &serde_json_canonicalizer::to_vec(&result).unwrap(),
            b"",
        );
        let redacted = RetainedReceipt::redacted(AUTHORITY_REDACTION_RULE).unwrap();
        let prefix = vec![redacted, retained(&malformed), retained(&decisive)];

        let (index, decoded) = scan_provider_receipts(&prefix, &expectation, &invocation)
            .unwrap()
            .unwrap();
        assert_eq!(index, 2);
        assert_eq!(decoded, result);
    }

    #[test]
    fn exact_typed_inability_is_decisive_but_other_inability_is_not() {
        let invocation = untrusted_invocation();
        let stdin = canonical_bytes(&invocation).unwrap();
        let authority = authority();
        let expectation = expectation(&stdin, &authority);
        let unable = typed_inability(&invocation);
        let receipt = process_receipt(
            &expectation,
            &serde_json_canonicalizer::to_vec(&unable).unwrap(),
            b"",
        );
        assert_eq!(
            scan_provider_receipts(&[retained(&receipt)], &expectation, &invocation)
                .unwrap()
                .unwrap()
                .1,
            unable
        );

        let other = CapabilityResult::unable(
            &invocation,
            CapabilityFailure::new(
                gooir_capability::protocol::FailureKindId::new(
                    "test.failure",
                    "different",
                    "1.0.0",
                ),
                Value::Null,
                BTreeMap::new(),
            )
            .unwrap(),
            BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let receipt = process_receipt(
            &expectation,
            &serde_json_canonicalizer::to_vec(&other).unwrap(),
            b"",
        );
        assert!(
            scan_provider_receipts(&[retained(&receipt)], &expectation, &invocation)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn provider_extensions_and_nonempty_stderr_never_become_decisive() {
        let invocation = untrusted_invocation();
        let mut result = produced_result(&invocation);
        let CapabilityOutcome::Produced { extensions, .. } = &mut result.outcome else {
            unreachable!();
        };
        extensions.insert("test.extra".to_owned(), json!(true));
        let value = serde_json::to_value(&result).unwrap();
        let body = value.as_object().unwrap();
        let mut without_id = body
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Map<_, _>>();
        without_id.remove("result_id");
        result.result_id = gooir_capability::protocol::ResultId::parse(sha256_identity(
            &serde_json_canonicalizer::to_vec(&without_id).unwrap(),
        ))
        .unwrap();
        let stdin = canonical_bytes(&invocation).unwrap();
        let authority = authority();
        let expectation = expectation(&stdin, &authority);
        let extended = process_receipt(
            &expectation,
            &serde_json_canonicalizer::to_vec(&result).unwrap(),
            b"",
        );
        let stderr = process_receipt(
            &expectation,
            &serde_json_canonicalizer::to_vec(&produced_result(&invocation)).unwrap(),
            b"warning",
        );
        assert!(
            scan_provider_receipts(
                &[retained(&extended), retained(&stderr)],
                &expectation,
                &invocation,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn malformed_foreign_and_foreign_redaction_evidence_fail_closed() {
        let invocation = untrusted_invocation();
        let stdin = canonical_bytes(&invocation).unwrap();
        let authority = authority();
        let expectation = expectation(&stdin, &authority);
        let malformed =
            RetainedReceipt::exact(ExactJson::new(json!({"receipt": "foreign"})).unwrap()).unwrap();
        assert!(matches!(
            scan_provider_receipts(&[malformed], &expectation, &invocation),
            Err(DriverError::Invariant(_))
        ));

        let foreign_expectation = ReceiptExpectation {
            runtime_qualification_id: digest(b'f').leak(),
            artifact_lock_id: expectation.artifact_lock_id,
            limits: expectation.limits,
            stdin: expectation.stdin,
            authority: expectation.authority,
        };
        let receipt = process_receipt(&foreign_expectation, b"not-json", b"");
        assert!(matches!(
            scan_provider_receipts(&[retained(&receipt)], &expectation, &invocation),
            Err(DriverError::Invariant(_))
        ));

        let redacted = RetainedReceipt::redacted("foreign.redaction/rule@1").unwrap();
        assert!(matches!(
            scan_provider_receipts(&[redacted], &expectation, &invocation),
            Err(DriverError::Invariant(_))
        ));
    }

    #[test]
    fn decisive_receipt_must_be_the_last_retained_evidence() {
        let invocation = untrusted_invocation();
        let result = produced_result(&invocation);
        let stdin = canonical_bytes(&invocation).unwrap();
        let authority = authority();
        let expectation = expectation(&stdin, &authority);
        let decisive = process_receipt(
            &expectation,
            &serde_json_canonicalizer::to_vec(&result).unwrap(),
            b"",
        );
        let later = process_receipt(&expectation, b"not-json", b"");
        assert!(matches!(
            scan_provider_receipts(
                &[retained(&decisive), retained(&later)],
                &expectation,
                &invocation,
            ),
            Err(DriverError::Invariant(_))
        ));
    }

    #[test]
    fn operational_prefix_can_fill_exact_receipt_capacity() {
        let invocation = untrusted_invocation();
        let stdin = canonical_bytes(&invocation).unwrap();
        let authority = authority();
        let expectation = expectation(&stdin, &authority);
        let receipt = process_receipt(&expectation, b"not-json", b"");
        let prefix = (0..RECEIPT_CAPACITY)
            .map(|_| retained(&receipt))
            .collect::<Vec<_>>();
        assert_eq!(prefix.len(), RECEIPT_CAPACITY);
        assert!(
            scan_provider_receipts(&prefix, &expectation, &invocation)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn attester_prefix_requires_exact_command_shape() {
        let fixture = semantic_fixture();
        let stdin = canonical_bytes(&fixture.request).unwrap();
        let expectation = expectation(&stdin, &fixture.authority);
        let malformed = process_receipt(&expectation, b"not-json", b"");
        let valid = assessment(&fixture, AssessmentOutcome::Passed);
        let decisive = process_receipt(
            &expectation,
            &serde_json_canonicalizer::to_vec(&valid).unwrap(),
            b"",
        );
        let prefix = vec![retained(&malformed), retained(&decisive)];
        assert_eq!(
            scan_attester_receipts(
                &prefix,
                &expectation,
                &fixture.request,
                &fixture.conformance_authority,
            )
            .unwrap()
            .unwrap()
            .0,
            1
        );

        let mut checks = valid.checks.clone();
        checks.insert(
            "unexpected-check".to_owned(),
            check(AssessmentOutcome::Passed),
        );
        let extended = ConformanceAssessment::new(
            &fixture.invocation,
            &fixture.result,
            &fixture.candidate,
            fixture.conformance_authority.clone(),
            checks,
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let receipt = process_receipt(
            &expectation,
            &serde_json_canonicalizer::to_vec(&extended).unwrap(),
            b"",
        );
        assert!(
            scan_attester_receipts(
                &[retained(&receipt)],
                &expectation,
                &fixture.request,
                &fixture.conformance_authority,
            )
            .unwrap()
            .is_none()
        );
    }

    struct AdmissibleFixture {
        baseline: AdmissionSnapshot,
        invocation: CapabilityInvocation,
        result: CapabilityResult,
        candidate: CapabilityCandidate,
        authority: ConformanceAuthority,
    }

    fn admissible_fixture() -> AdmissibleFixture {
        let intent = intent();
        let fact = intent.to_fact().unwrap();
        let evidence_kind = EvidenceKindId::new("test.evidence", "source", "1.0.0");
        let observation_authority = ObservationAuthority::new(
            ObservationSourceId::new("test.source", "fleetd", "1.0.0"),
            ImplementationId::new("test.observer", "fleetd", "1.0.0"),
            ArtifactDigest::parse(digest(b'o')).unwrap(),
            fact.value_kind.clone(),
            evidence_kind.clone(),
            BTreeMap::new(),
        )
        .unwrap();
        let observation = SourceObservation::new(
            fact,
            observation_authority.clone(),
            EvidenceRef::new(
                evidence_kind,
                EvidenceDigest::parse(digest(b'e')).unwrap(),
                "opaque://fleetd/source",
                BTreeMap::new(),
            )
            .unwrap(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let source_policy = AdmissionPolicy::new(
            AdmissionAuthorityId::new("test.admission", "source", "1.0.0"),
            Vec::new(),
            vec![observation_authority],
            BTreeMap::new(),
        )
        .unwrap();
        let mut ledger = AdmissionLedger::new();
        let AdmissionOutcome::Admitted { links, .. } = ledger
            .admit_observation(&source_policy, &observation)
            .unwrap()
        else {
            panic!("accepted source observation was withheld");
        };
        let invocation = invocation(links[0].reference.clone());
        let result = produced_result(&invocation);
        let candidate =
            CapabilityCandidate::new(&invocation, result.clone(), BTreeMap::new()).unwrap();
        let authority = ConformanceAuthority::new(
            direct_conversation_ref_suite_id(),
            ConformanceAttester::new(
                implementation_id(),
                ArtifactDigest::parse(digest(b't')).unwrap(),
                BTreeMap::new(),
            )
            .unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        AdmissibleFixture {
            baseline: ledger.export().unwrap(),
            invocation,
            result,
            candidate,
            authority,
        }
    }

    fn admissible_assessment(
        fixture: &AdmissibleFixture,
        observation: AssessmentOutcome,
    ) -> ConformanceAssessment {
        ConformanceAssessment::new(
            &fixture.invocation,
            &fixture.result,
            &fixture.candidate,
            fixture.authority.clone(),
            BTreeMap::from([
                (
                    ATTESTER_CHECK_EXACT_CONTRACT.to_owned(),
                    check(AssessmentOutcome::Passed),
                ),
                (
                    ATTESTER_CHECK_INTENT_OUTPUT_RELATION.to_owned(),
                    check(AssessmentOutcome::Passed),
                ),
                (
                    ATTESTER_CHECK_FLEETD_OBSERVATION.to_owned(),
                    check(observation),
                ),
            ]),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn candidate_policy(fixture: &AdmissibleFixture) -> AdmissionPolicy {
        AdmissionPolicy::new(
            AdmissionAuthorityId::new("test.admission", "candidate", "1.0.0"),
            vec![fixture.authority.clone()],
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn test_attempt_inputs(temporary: &tempfile::TempDir) -> AttemptInputs {
        let target = crate::target::TargetLock::new(temporary.path().join("target")).unwrap();
        let target = target
            .configure(
                crate::target::TargetDeployment::new(
                    FleetdTarget::parse("fleetd:test").unwrap(),
                    digest(b'1'),
                    "e6628b054b8559d6da4e5857c888676fe322b2f9",
                    digest(b'2'),
                    digest(b'3'),
                    digest(b'4'),
                    "credential-r1",
                )
                .unwrap(),
            )
            .unwrap();
        AttemptInputs::new(UnboundAttemptInputs {
            semantic_plan: ExactJson::new(json!({"safe": "plan"})).unwrap(),
            invocation: ExactJson::new(json!({"safe": "invocation"})).unwrap(),
            baseline_snapshot: ExactJson::new(json!({"safe": "baseline"})).unwrap(),
            conformance_suite: direct_conversation_ref_suite_id().to_string(),
            provider: DeploymentLock::new(
                "dev.fleetd.implementation/test_provider@0.1.0",
                "dev.fleetd.package/test_provider@0.1.0",
                digest(b'5'),
                "bin/provider",
                digest(b'6'),
            )
            .unwrap(),
            attester: DeploymentLock::new(
                "dev.fleetd.implementation/test_attester@0.1.0",
                "dev.fleetd.package/test_attester@0.1.0",
                digest(b'7'),
                "bin/attester",
                digest(b'8'),
            )
            .unwrap(),
            native_runtime: crate::journal::NativeRuntimeLock::new(
                "org.gooi.proof/test-native-runtime@0.1.0",
                digest(b'9'),
            )
            .unwrap(),
            target,
            provider_replay_law: PROVIDER_REPLAY_LAW.to_owned(),
            attester_replay_law: ATTESTER_REPLAY_LAW.to_owned(),
            execution_policy: ExactJson::new(json!({"safe": "execution"})).unwrap(),
            admission_policy: ExactJson::new(json!({"safe": "admission"})).unwrap(),
        })
        .unwrap()
    }

    #[test]
    fn prepared_publication_seam_stops_before_every_launch_authority() {
        let temporary = tempfile::tempdir().unwrap();
        let journal =
            crate::journal::AttemptJournal::new(temporary.path().join("attempt")).unwrap();
        let session = journal.begin_session().unwrap();
        let inputs = test_attempt_inputs(&temporary);
        let guard = DurableAuthorityGuard::from_authority(&authority()).unwrap();

        // `publish_prepared` is the only state-changing helper used by
        // `prepare` after reconstruction. Its type has no artifact, runtime,
        // target authority, or launch function to consume.
        let prepared = publish_prepared(&session, &inputs, &guard).unwrap();

        assert_eq!(prepared.phase(), crate::journal::AttemptPhase::Prepared);
        assert!(prepared.provider_receipts().is_empty());
        assert!(prepared.attester_receipts().is_empty());
        assert!(prepared.provider_decisive().is_none());
        assert!(prepared.attester_decisive().is_none());
        assert!(prepared.resolution().is_none());
        assert_eq!(prepared.recovery_action(), RecoveryAction::ArmProvider);
        assert_eq!(session.load().unwrap(), prepared);
    }

    #[test]
    fn existing_checkpoint_load_is_exact_and_non_advancing() {
        let temporary = tempfile::tempdir().unwrap();
        let journal =
            crate::journal::AttemptJournal::new(temporary.path().join("attempt")).unwrap();
        let session = journal.begin_session().unwrap();
        let inputs = test_attempt_inputs(&temporary);
        let guard = DurableAuthorityGuard::from_authority(&authority()).unwrap();
        let prepared = publish_prepared(&session, &inputs, &guard).unwrap();
        let path = journal.directory_path().join("checkpoint.json");
        let before = std::fs::read(&path).unwrap();

        let loaded = session.load().unwrap();
        let after = std::fs::read(path).unwrap();

        assert_eq!(loaded, prepared);
        assert_eq!(loaded.phase(), crate::journal::AttemptPhase::Prepared);
        assert_eq!(loaded.recovery_action(), RecoveryAction::ArmProvider);
        assert_eq!(after, before);
    }

    #[test]
    fn drive_reload_rejects_a_checkpoint_changed_after_validation() {
        let temporary = tempfile::tempdir().unwrap();
        let journal =
            crate::journal::AttemptJournal::new(temporary.path().join("attempt")).unwrap();
        let session = journal.begin_session().unwrap();
        let inputs = test_attempt_inputs(&temporary);
        let guard = DurableAuthorityGuard::from_authority(&authority()).unwrap();
        let prepared = publish_prepared(&session, &inputs, &guard).unwrap();
        let armed = prepared.arm_provider().unwrap();
        session.replace(prepared.checkpoint_id(), &armed).unwrap();

        assert!(matches!(
            reload_exact_checkpoint(&session, &prepared),
            Err(DriverError::Journal(JournalError::StaleCheckpoint {
                expected,
                actual,
            })) if expected == prepared.checkpoint_id() && actual == armed.checkpoint_id()
        ));
        assert_eq!(
            session.load().unwrap().recovery_action(),
            RecoveryAction::InspectProviderPrefix { may_launch: true }
        );
    }

    #[test]
    fn exact_reload_preserves_the_validated_recovery_action() {
        let temporary = tempfile::tempdir().unwrap();
        let journal =
            crate::journal::AttemptJournal::new(temporary.path().join("attempt")).unwrap();
        let session = journal.begin_session().unwrap();
        let inputs = test_attempt_inputs(&temporary);
        let guard = DurableAuthorityGuard::from_authority(&authority()).unwrap();
        let prepared = publish_prepared(&session, &inputs, &guard).unwrap();

        let loaded = reload_exact_checkpoint(&session, &prepared).unwrap();

        assert_eq!(loaded, prepared);
        assert_eq!(loaded.recovery_action(), RecoveryAction::ArmProvider);
    }

    fn maximal_exact_json() -> ExactJson {
        let empty = json!({"padding": ""});
        let framing_bytes = canonical_bytes(&empty).unwrap().len();
        let value = json!({
            "padding": "x".repeat(crate::journal::MAX_EXACT_JSON_BYTES - framing_bytes)
        });
        assert_eq!(
            canonical_bytes(&value).unwrap().len(),
            crate::journal::MAX_EXACT_JSON_BYTES
        );
        ExactJson::new(value).unwrap()
    }

    fn maximum_provider_checkpoint_inputs(temporary: &tempfile::TempDir) -> AttemptInputs {
        let target = crate::target::TargetLock::new(temporary.path().join("maximum-target"))
            .unwrap()
            .configure(
                crate::target::TargetDeployment::new(
                    FleetdTarget::parse("fleetd:test").unwrap(),
                    digest(b'1'),
                    "e6628b054b8559d6da4e5857c888676fe322b2f9",
                    digest(b'2'),
                    digest(b'9'),
                    digest(b'3'),
                    "c".repeat(256),
                )
                .unwrap(),
            )
            .unwrap();
        let exact = maximal_exact_json();
        AttemptInputs::new(UnboundAttemptInputs {
            semantic_plan: exact.clone(),
            invocation: exact.clone(),
            baseline_snapshot: exact.clone(),
            conformance_suite: "s".repeat(4 * 1024),
            provider: DeploymentLock::new(
                "p".repeat(4 * 1024),
                "q".repeat(4 * 1024),
                digest(b'4'),
                "r".repeat(4 * 1024),
                digest(b'5'),
            )
            .unwrap(),
            attester: DeploymentLock::new(
                "a".repeat(4 * 1024),
                "b".repeat(4 * 1024),
                digest(b'6'),
                "c".repeat(4 * 1024),
                digest(b'7'),
            )
            .unwrap(),
            native_runtime: crate::journal::NativeRuntimeLock::new(
                "n".repeat(4 * 1024),
                digest(b'8'),
            )
            .unwrap(),
            target,
            provider_replay_law: "p".repeat(4 * 1024),
            attester_replay_law: "a".repeat(4 * 1024),
            execution_policy: exact.clone(),
            admission_policy: exact,
        })
        .unwrap()
    }

    fn sensitive_values(authority: &AuthorityDocument) -> [Value; 3] {
        [
            Value::String(authority.endpoint().to_owned()),
            Value::String(authority.bearer_token().expose_secret().to_owned()),
            serde_json::from_slice(&authority.encode_for_pipe().unwrap()).unwrap(),
        ]
    }

    #[test]
    fn reconstruction_preflight_rejects_each_authority_form_in_fact_before_journal_creation() {
        let fixture = admissible_fixture();
        let policy = candidate_policy(&fixture);
        let authority = authority();
        let temporary = tempfile::tempdir().unwrap();
        let journal =
            crate::journal::AttemptJournal::new(temporary.path().join("attempt")).unwrap();
        let _session = journal.begin_session().unwrap();

        for sensitive in sensitive_values(&authority) {
            let original = intent().to_fact().unwrap();
            let fact = gooir_capability::Fact::with_extensions(
                original.value_kind,
                original.payload,
                BTreeMap::from([("test.sensitive".to_owned(), sensitive)]),
            )
            .unwrap();
            let admitted = AdmittedFactRef::new(
                fact.id.clone(),
                AuthorityRecordId::parse(digest(b'r')).unwrap(),
                BTreeMap::new(),
            )
            .unwrap();
            let invocation = invocation_for_fact(admitted, fact);
            assert!(matches!(
                DurableAuthorityGuard::preflight(
                    &authority,
                    &invocation,
                    &fixture.baseline,
                    &policy,
                ),
                Err(DriverError::SensitiveDurableDocument)
            ));
            assert!(!journal.directory_path().join("checkpoint.json").exists());
        }
    }

    #[test]
    fn reconstruction_preflight_rejects_each_authority_form_in_baseline_and_policy() {
        let fixture = admissible_fixture();
        let authority = authority();
        let safe_policy = candidate_policy(&fixture);

        for sensitive in sensitive_values(&authority) {
            let ledger = AdmissionLedger::rebuild(&fixture.baseline).unwrap();
            let baseline = ledger
                .export_with_extensions(BTreeMap::from([("test.sensitive".to_owned(), sensitive)]))
                .unwrap();
            for _reconstruction_path in ["start", "resume"] {
                assert!(matches!(
                    DurableAuthorityGuard::preflight(
                        &authority,
                        &fixture.invocation,
                        &baseline,
                        &safe_policy,
                    ),
                    Err(DriverError::SensitiveDurableDocument)
                ));
            }
        }

        for sensitive in sensitive_values(&authority) {
            let policy = AdmissionPolicy::new(
                AdmissionAuthorityId::new("test.admission", "candidate", "1.0.0"),
                vec![fixture.authority.clone()],
                Vec::new(),
                BTreeMap::from([("test.sensitive".to_owned(), sensitive)]),
            )
            .unwrap();
            for _reconstruction_path in ["start", "resume"] {
                assert!(matches!(
                    DurableAuthorityGuard::preflight(
                        &authority,
                        &fixture.invocation,
                        &fixture.baseline,
                        &policy,
                    ),
                    Err(DriverError::SensitiveDurableDocument)
                ));
            }
        }
    }

    #[test]
    fn reconstruction_preflight_detects_json_escaped_bearer_in_raw_string_value() {
        let fixture = admissible_fixture();
        let policy = candidate_policy(&fixture);
        let authority = authority_with_token("quote\"and\\backslash");
        let ledger = AdmissionLedger::rebuild(&fixture.baseline).unwrap();
        let baseline = ledger
            .export_with_extensions(BTreeMap::from([(
                "test.sensitive".to_owned(),
                Value::String(authority.bearer_token().expose_secret().to_owned()),
            )]))
            .unwrap();

        assert!(matches!(
            DurableAuthorityGuard::preflight(&authority, &fixture.invocation, &baseline, &policy,),
            Err(DriverError::SensitiveDurableDocument)
        ));
    }

    #[test]
    fn reconstruction_preflight_detects_literal_escaped_bearer_spelling() {
        let fixture = admissible_fixture();
        let policy = candidate_policy(&fixture);
        let authority = authority_with_token("quote\"and\\backslash");
        let raw = authority.bearer_token().expose_secret().as_bytes();
        let encoded = serde_json::to_vec(authority.bearer_token().expose_secret()).unwrap();
        let escaped = json_string_interior(&encoded).unwrap();
        assert!(!contains_bytes(&escaped, raw));
        let ledger = AdmissionLedger::rebuild(&fixture.baseline).unwrap();
        let baseline = ledger
            .export_with_extensions(BTreeMap::from([(
                "test.sensitive".to_owned(),
                Value::String(String::from_utf8(escaped).unwrap()),
            )]))
            .unwrap();

        assert!(matches!(
            DurableAuthorityGuard::preflight(&authority, &fixture.invocation, &baseline, &policy,),
            Err(DriverError::SensitiveDurableDocument)
        ));
    }

    #[test]
    fn reconstruction_preflight_detects_bearer_spanning_canonical_json_boundaries() {
        let fixture = admissible_fixture();
        let policy = candidate_policy(&fixture);
        let authority = authority_with_token("a\":\"b");
        let ledger = AdmissionLedger::rebuild(&fixture.baseline).unwrap();
        let baseline = ledger
            .export_with_extensions(BTreeMap::from([(
                "test.sensitive".to_owned(),
                json!({"a": "b"}),
            )]))
            .unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let journal =
            crate::journal::AttemptJournal::new(temporary.path().join("attempt")).unwrap();
        let _session = journal.begin_session().unwrap();

        assert!(matches!(
            DurableAuthorityGuard::preflight(&authority, &fixture.invocation, &baseline, &policy,),
            Err(DriverError::SensitiveDurableDocument)
        ));
        assert!(!journal.directory_path().join("checkpoint.json").exists());
    }

    #[test]
    fn fixed_checkpoint_and_redacted_wrapper_collisions_fail_before_persistence() {
        let temporary = tempfile::tempdir().unwrap();
        let journal =
            crate::journal::AttemptJournal::new(temporary.path().join("attempt")).unwrap();
        let session = journal.begin_session().unwrap();

        let inputs = test_attempt_inputs(&temporary);
        let prepared = AttemptCheckpoint::prepared(inputs).unwrap();
        let prepared_bytes = prepared.canonical_bytes().unwrap();
        let prepared_guard =
            DurableAuthorityGuard::from_authority(&authority_with_token("phase\":\"prepared"))
                .unwrap();
        assert!(matches!(
            prepared_guard.reject_canonical_bytes(&prepared_bytes),
            Err(DriverError::SensitiveDurableDocument)
        ));
        assert!(session.create_exact(&prepared, b"{}").is_err());
        assert!(!journal.directory_path().join("checkpoint.json").exists());
        let armed = prepared.arm_provider().unwrap();
        let armed_guard = DurableAuthorityGuard::from_authority(&authority_with_token(
            "phase\":\"provider_armed",
        ))
        .unwrap();
        assert!(matches!(
            armed_guard.reject_canonical_bytes(&armed.canonical_bytes().unwrap()),
            Err(DriverError::SensitiveDurableDocument)
        ));
        let marker_guard =
            DurableAuthorityGuard::from_authority(&authority_with_token("retention\":\"redacted"))
                .unwrap();
        assert!(matches!(
            guarded_redacted_receipt(&marker_guard),
            Err(DriverError::SensitiveDurableDocument)
        ));

        let provider_successor_guard = DurableAuthorityGuard::from_authority(
            &authority_with_token("provider_receipts\":[{\"marker_digest"),
        )
        .unwrap();
        assert!(guarded_redacted_receipt(&provider_successor_guard).is_ok());
        assert!(matches!(
            redacted_provider_successor(&provider_successor_guard, &armed),
            Err(DriverError::SensitiveDurableDocument)
        ));

        let provider_receipt =
            RetainedReceipt::exact(ExactJson::new(json!({"safe": true})).unwrap()).unwrap();
        let attester_armed = armed
            .append_provider_receipt(provider_receipt)
            .unwrap()
            .capture_provider(0)
            .unwrap()
            .candidate_ready(ExactJson::new(json!({"candidate": "safe"})).unwrap())
            .unwrap()
            .arm_attester(ExactJson::new(json!({"request": "safe"})).unwrap())
            .unwrap();
        let attester_successor_guard = DurableAuthorityGuard::from_authority(
            &authority_with_token("attester_receipts\":[{\"marker_digest"),
        )
        .unwrap();
        assert!(guarded_redacted_receipt(&attester_successor_guard).is_ok());
        assert!(matches!(
            redacted_attester_successor(&attester_successor_guard, &attester_armed),
            Err(DriverError::SensitiveDurableDocument)
        ));

        let exact_guard =
            DurableAuthorityGuard::from_authority(&authority_with_token("retention\":\"exact"))
                .unwrap();
        let fallback = redacted_provider_successor(&exact_guard, &armed).unwrap();
        let exact = armed
            .append_provider_receipt(
                RetainedReceipt::exact(ExactJson::new(json!({"safe": true})).unwrap()).unwrap(),
            )
            .unwrap();
        let selected = receipt_successor_or_fallback(&exact_guard, Ok(exact), fallback.clone());
        assert_eq!(selected, fallback);
        assert!(selected.provider_receipts()[0].is_redacted());
        assert!(!journal.directory_path().join("checkpoint.json").exists());
    }

    #[test]
    fn provider_bound_and_post_child_failure_use_the_prevalidated_fallback() {
        let temporary = tempfile::tempdir().unwrap();
        let guard = DurableAuthorityGuard::from_authority(&authority()).unwrap();
        let inputs = test_attempt_inputs(&temporary);
        let provider_armed = AttemptCheckpoint::prepared(inputs)
            .unwrap()
            .arm_provider()
            .unwrap();
        let small_receipt = ExactJson::new(json!({"safe": true})).unwrap();
        let maximum_provider_shape = provider_armed
            .append_provider_receipt(RetainedReceipt::exact(small_receipt.clone()).unwrap())
            .unwrap()
            .append_provider_receipt(RetainedReceipt::exact(small_receipt).unwrap())
            .unwrap();

        // ProviderArmed can contain exactly five input ExactJson values and
        // two receipt ExactJson values. Replacing all seven values with their
        // independent maxima contributes 28 MiB. A conservative additional
        // 1 MiB covers every bounded opaque coordinate, the 64 KiB target
        // document, identities, and JSON framing, leaving strict headroom
        // beneath the 32 MiB aggregate bound. Provider aggregate overflow is
        // therefore unreachable under the current component bounds.
        let inputs = maximum_provider_shape.inputs();
        let small_value_bytes = [
            inputs.semantic_plan(),
            inputs.invocation(),
            inputs.baseline_snapshot(),
            inputs.execution_policy(),
            inputs.admission_policy(),
        ]
        .into_iter()
        .map(|exact| canonical_bytes(exact.value()).unwrap().len())
        .sum::<usize>()
            + maximum_provider_shape
                .provider_receipts()
                .iter()
                .map(|receipt| match receipt {
                    RetainedReceipt::Exact { receipt } => {
                        canonical_bytes(receipt.value()).unwrap().len()
                    }
                    RetainedReceipt::Redacted { .. } => unreachable!(),
                })
                .sum::<usize>();
        let structural_bytes =
            maximum_provider_shape.canonical_bytes().unwrap().len() - small_value_bytes;
        let provider_upper_bound =
            structural_bytes + 7 * crate::journal::MAX_EXACT_JSON_BYTES + 1024 * 1024;
        assert!(provider_upper_bound < crate::journal::MAX_CHECKPOINT_BYTES);

        // Any other pure exact-construction failure after a provider effect is
        // routed through the same selector used by both live role call sites.
        let provider_fallback = redacted_provider_successor(&guard, &provider_armed).unwrap();
        let selected = receipt_successor_or_fallback(
            &guard,
            Err(DriverError::Journal(JournalError::Invalid(
                "post-child exact construction failed".to_owned(),
            ))),
            provider_fallback.clone(),
        );
        assert_eq!(selected, provider_fallback);
    }

    /// Run with:
    /// `cargo test --release -p fleetd-direct-conversation-external-host-proof --lib -- --ignored --exact driver::tests::attester_aggregate_overflow_uses_prevalidated_fallback`
    #[test]
    #[ignore = "32 MiB aggregate-bound proof; run the documented optimized exact test"]
    fn attester_aggregate_overflow_uses_prevalidated_fallback() {
        let temporary = tempfile::tempdir().unwrap();
        let guard = DurableAuthorityGuard::from_authority(&authority()).unwrap();
        let maximum_exact = maximal_exact_json();
        let inputs = maximum_provider_checkpoint_inputs(&temporary);

        // AttesterArmed additionally retains a candidate and assessment
        // request. A redacted append still fits, but one maximally sized exact
        // receipt crosses the real global bound. The exact append error is
        // therefore replaced by the already validated, publishable fallback.
        let attester_armed = AttemptCheckpoint::prepared(inputs)
            .unwrap()
            .arm_provider()
            .unwrap()
            .append_provider_receipt(
                RetainedReceipt::exact(ExactJson::new(json!({"safe": true})).unwrap()).unwrap(),
            )
            .unwrap()
            .capture_provider(0)
            .unwrap()
            .candidate_ready(maximum_exact.clone())
            .unwrap()
            .arm_attester(maximum_exact.clone())
            .unwrap();
        let attester_fallback = redacted_attester_successor(&guard, &attester_armed).unwrap();
        assert!(
            attester_fallback.canonical_bytes().unwrap().len()
                <= crate::journal::MAX_CHECKPOINT_BYTES
        );
        let exact = attester_armed
            .append_attester_receipt(RetainedReceipt::exact(maximum_exact).unwrap())
            .map_err(DriverError::Journal);
        assert!(matches!(exact, Err(DriverError::Journal(_))));
        let selected = receipt_successor_or_fallback(&guard, exact, attester_fallback.clone());
        assert_eq!(selected, attester_fallback);
        selected.validate().unwrap();
    }

    #[test]
    fn loaded_checkpoint_is_rechecked_against_rotated_live_authority() {
        let fixture = admissible_fixture();
        let policy = candidate_policy(&fixture);
        let temporary = tempfile::tempdir().unwrap();
        let journal =
            crate::journal::AttemptJournal::new(temporary.path().join("attempt")).unwrap();
        let session = journal.begin_session().unwrap();
        let checkpoint = session.create(test_attempt_inputs(&temporary)).unwrap();
        let rotated = authority_with_token(checkpoint.checkpoint_id());
        let guard = DurableAuthorityGuard::preflight(
            &rotated,
            &fixture.invocation,
            &fixture.baseline,
            &policy,
        )
        .unwrap();
        let loaded = session.load().unwrap();

        assert!(matches!(
            guard.reject_canonical_bytes(&loaded.canonical_bytes().unwrap()),
            Err(DriverError::SensitiveDurableDocument)
        ));
    }

    #[test]
    fn serialized_escaped_bearer_receipt_is_redacted_before_retention() {
        let fixture = admissible_fixture();
        let policy = candidate_policy(&fixture);
        let authority = authority_with_token("quote\"and\\backslash");
        let guard = DurableAuthorityGuard::preflight(
            &authority,
            &fixture.invocation,
            &fixture.baseline,
            &policy,
        )
        .unwrap();
        let stdin = canonical_bytes(&fixture.invocation).unwrap();
        let expectation = expectation(&stdin, &authority);
        let stdout = serde_json::to_vec(&json!({
            "value": authority.bearer_token().expose_secret()
        }))
        .unwrap();
        assert!(!contains_bytes(
            &stdout,
            authority.bearer_token().expose_secret().as_bytes(),
        ));
        let receipt = process_receipt(&expectation, &stdout, b"");

        let retained = retain_before_interpretation(&receipt, &guard).unwrap();
        assert!(matches!(
            retained,
            RetainedReceipt::Redacted { redaction_rule, .. }
                if redaction_rule == AUTHORITY_REDACTION_RULE
        ));
    }

    #[test]
    fn complete_process_receipt_fixed_bytes_are_guarded_before_exact_json() {
        let fixture = admissible_fixture();
        let authority = authority_with_token("\"bytes\":[");
        let guard = DurableAuthorityGuard::from_authority(&authority).unwrap();
        let stdin = canonical_bytes(&fixture.invocation).unwrap();
        let expectation = expectation(&stdin, &authority);
        let receipt = process_receipt(&expectation, b"safe", b"");
        assert!(!guard.contains_authority(receipt.stdout().bytes()));
        assert!(!guard.contains_authority(receipt.stderr().bytes()));
        assert!(guard.contains_authority(&canonical_bytes(&receipt).unwrap()));

        assert!(matches!(
            retain_before_interpretation(&receipt, &guard).unwrap(),
            RetainedReceipt::Redacted { redaction_rule, .. }
                if redaction_rule == AUTHORITY_REDACTION_RULE
        ));
    }

    #[test]
    fn complete_exact_retained_receipt_wrapper_is_guarded() {
        let fixture = admissible_fixture();
        let authority = authority_with_token("retention\":\"exact");
        let guard = DurableAuthorityGuard::from_authority(&authority).unwrap();
        let stdin = canonical_bytes(&fixture.invocation).unwrap();
        let expectation = expectation(&stdin, &authority);
        let receipt = process_receipt(&expectation, b"safe", b"");
        assert!(!guard.contains_authority(&canonical_bytes(&receipt).unwrap()));

        assert!(matches!(
            retain_before_interpretation(&receipt, &guard).unwrap(),
            RetainedReceipt::Redacted { redaction_rule, .. }
                if redaction_rule == AUTHORITY_REDACTION_RULE
        ));
    }

    #[test]
    fn truncated_escaped_bearer_at_either_stream_boundary_is_redacted() {
        let fixture = admissible_fixture();
        let policy = candidate_policy(&fixture);
        let authority = authority_with_token("quote\"and\\backslash");
        let guard = DurableAuthorityGuard::preflight(
            &authority,
            &fixture.invocation,
            &fixture.baseline,
            &policy,
        )
        .unwrap();
        let encoded = serde_json::to_vec(authority.bearer_token().expose_secret()).unwrap();
        let escaped = json_string_interior(&encoded).unwrap();
        let truncated = &escaped[..escaped.len() - 1];
        assert!(!guard.contains_authority(truncated));
        assert!(guard.retained_stream_may_contain_authority(truncated));

        let stdin = canonical_bytes(&fixture.invocation).unwrap();
        let expectation = expectation(&stdin, &authority);
        for (stdout, stderr) in [(truncated, &b""[..]), (&b"safe"[..], truncated)] {
            let receipt = process_receipt(&expectation, stdout, stderr);
            assert!(matches!(
                retain_before_interpretation(&receipt, &guard).unwrap(),
                RetainedReceipt::Redacted { redaction_rule, .. }
                    if redaction_rule == AUTHORITY_REDACTION_RULE
            ));
        }
    }

    #[test]
    fn admission_pass_adds_output_and_failed_observation_withholds_without_mutation() {
        let fixture = admissible_fixture();
        let policy = candidate_policy(&fixture);
        let passed = admissible_assessment(&fixture, AssessmentOutcome::Passed);
        let AdmissionEvaluation::Admitted(snapshot) = evaluate_chain_admission(
            &fixture.baseline,
            &policy,
            &fixture.invocation,
            &fixture.result,
            &fixture.candidate,
            &passed,
        )
        .unwrap() else {
            panic!("passing accepted assessment was withheld");
        };
        assert_ne!(snapshot, fixture.baseline);
        AdmissionLedger::rebuild(&snapshot).unwrap();

        let failed = admissible_assessment(&fixture, AssessmentOutcome::Failed);
        let AdmissionEvaluation::Withheld(decision) = evaluate_chain_admission(
            &fixture.baseline,
            &policy,
            &fixture.invocation,
            &fixture.result,
            &fixture.candidate,
            &failed,
        )
        .unwrap() else {
            panic!("failed assessment was admitted");
        };
        decision
            .validate_candidate(
                &policy,
                &fixture.invocation,
                &fixture.result,
                &fixture.candidate,
                &failed,
            )
            .unwrap();
    }
}
