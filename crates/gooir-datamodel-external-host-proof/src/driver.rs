//! One proof-local composition of installed semantic packages and a durable host.
//!
//! This is intentionally not a generic GOOIR runtime. It proves that the
//! public package, planning, protocol, conformance, and admission boundaries
//! compose without adding execution lifecycle to the semantic substrate.
//!
//! The real-module and process-exit proof is deliberately excluded from the
//! ordinary fast suite because every recovery independently requalifies both
//! installed modules. Run it explicitly after building the final guests:
//!
//! ```text
//! cargo build --release --target wasm32-wasip1 \
//!   -p gooir-datamodel-pack -p gooir-datamodel-conformance --bins
//! cargo test -p gooir-datamodel-external-host-proof \
//!   driver::tests::real_modules_prove_outcomes_and_passing_path_crash_recovery \
//!   -- --ignored --exact --nocapture
//! ```

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use gooir_author_data_model_contract::{author_data_model_spec, author_data_model_suite_id};
use gooir_capability::authority::{
    AdmissionDecision, AdmissionLedger, AdmissionOutcome, AdmissionPolicy, AdmissionSnapshot,
    AuthorityError, ConformanceAssessment, ConformanceAttester, ConformanceAuthority,
};
use gooir_capability::protocol::{
    AdmittedFactRef, ArtifactDigest, CapabilityCandidate, CapabilityInvocation, CapabilityOutcome,
    CapabilityResult, LinkedInput, ProtocolError,
};
use gooir_datamodel_conformance::{AssessmentRequest, AttesterError};
use gooir_datamodel_package_proof::{
    ATTESTER_RESOURCE, PROVIDER_PACKAGE, PROVIDER_RESOURCE, ProofError, VerifiedPackageSet,
    verify_package_set,
};
use gooir_planning::{InvocationLink, PlanLimits, PlanningError, SemanticPlan};
use gooir_wasip1_command_runtime::{
    RUNTIME_ID, WasmError, WasmExecutionPolicy, WasmLimits, WasmReceipt, WasmRequest, prepare,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::journal::{
    AttemptCheckpoint, AttemptInputs, AttemptJournal, AttemptPhase, AttemptResolution,
    DeploymentLock, ExactJson, JournalError, UnboundAttemptInputs,
};

/// Exact proof-local wire identity for the two command-runtime policies.
const EXECUTION_POLICY_PROTOCOL: &str =
    "org.gooi.proof.data-model-external-host-execution-policy/v1";

/// Exact proof-local wire identity for a terminal inability.
const FAILURE_PROTOCOL: &str = "org.gooi.proof.data-model-external-host-failure/v1";

/// Caller-selected runtime limits for the producer and independent attester.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptExecutionLimits {
    pub provider: WasmLimits,
    pub attester: WasmLimits,
}

impl AttemptExecutionLimits {
    fn policy(self) -> Result<AttemptExecutionPolicy, WasmError> {
        let policy = AttemptExecutionPolicy {
            protocol: EXECUTION_POLICY_PROTOCOL.to_owned(),
            runtime: RUNTIME_ID.to_owned(),
            provider: self.provider.execution_policy()?,
            attester: self.attester.execution_policy()?,
        };
        policy.validate()?;
        Ok(policy)
    }
}

/// Platform-stable identity of all runtime authority granted to one attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptExecutionPolicy {
    protocol: String,
    runtime: String,
    provider: WasmExecutionPolicy,
    attester: WasmExecutionPolicy,
}

impl AttemptExecutionPolicy {
    fn validate(&self) -> Result<(), WasmError> {
        if self.protocol != EXECUTION_POLICY_PROTOCOL {
            return Err(WasmError::InvalidRequest(
                "external-host execution-policy protocol changed",
            ));
        }
        if self.runtime != RUNTIME_ID {
            return Err(WasmError::InvalidRequest(
                "external-host execution runtime changed",
            ));
        }
        Ok(())
    }
}

/// Trusted host inputs reconstructed independently for every start or resume.
///
/// The package root and journal directory are host locations, not semantic
/// facts. The snapshot, source authority reference, policy, and limits are
/// caller-selected authority inputs and are all revalidated before dispatch.
#[derive(Clone, Debug)]
pub struct HostRequest {
    pub package_root: PathBuf,
    pub journal_directory: PathBuf,
    pub baseline_snapshot: AdmissionSnapshot,
    pub source: AdmittedFactRef,
    pub planning_limits: PlanLimits,
    pub execution_limits: AttemptExecutionLimits,
    pub admission_policy: AdmissionPolicy,
}

/// Start one new attempt and drive it until a terminal or parked checkpoint.
///
/// This refuses an existing journal. Use [`resume`] to continue one exact
/// attempt; there is deliberately no create-or-resume ambiguity.
///
/// # Errors
///
/// Refuses invalid trusted inputs, packages, planning, deployment locks,
/// persistence, or a recovered contradiction. Guest failure after durable
/// capture becomes a terminal `Unable` checkpoint rather than an unrecorded
/// host error.
pub fn start(request: &HostRequest) -> Result<AttemptCheckpoint, HostError> {
    let context = Context::reconstruct(request)?;
    let journal = AttemptJournal::new(request.journal_directory.clone())?;
    let checkpoint = journal.create(context.inputs.clone())?;
    drive(&journal, &context, checkpoint, Interruption::None)
}

/// Resume one exact attempt from independently reconstructed trusted inputs.
///
/// A loaded armed checkpoint is always parked. Only the process that prepared
/// an exact invocation and successfully published the corresponding arm owns
/// the ephemeral right to execute it.
///
/// # Errors
///
/// Refuses missing, changed, malformed, or semantically inconsistent state.
pub fn resume(request: &HostRequest) -> Result<AttemptCheckpoint, HostError> {
    let context = Context::reconstruct(request)?;
    let journal = AttemptJournal::new(request.journal_directory.clone())?;
    let checkpoint = journal.load()?;
    drive(&journal, &context, checkpoint, Interruption::None)
}

#[cfg(test)]
fn start_exiting_after(
    request: &HostRequest,
    phase: AttemptPhase,
) -> Result<AttemptCheckpoint, HostError> {
    let context = Context::reconstruct(request)?;
    let journal = AttemptJournal::new(request.journal_directory.clone())?;
    let checkpoint = journal.create(context.inputs.clone())?;
    drive(
        &journal,
        &context,
        checkpoint,
        Interruption::ExitAfter(phase),
    )
}

#[derive(Debug)]
struct Context {
    packages: VerifiedPackageSet,
    plan: SemanticPlan,
    invocation: CapabilityInvocation,
    baseline: AdmissionSnapshot,
    policy: AdmissionPolicy,
    expected_authority: ConformanceAuthority,
    attester_digest: ArtifactDigest,
    planning_limits: PlanLimits,
    execution_limits: AttemptExecutionLimits,
    execution_policy: AttemptExecutionPolicy,
    provider_lock: DeploymentLock,
    attester_lock: DeploymentLock,
    inputs: AttemptInputs,
}

impl Context {
    #[allow(clippy::too_many_lines)]
    fn reconstruct(request: &HostRequest) -> Result<Self, HostError> {
        let packages = verify_package_set(&request.package_root)?;
        let report = packages.report();
        if report.runtime_profile != RUNTIME_ID {
            return Err(invariant(
                "package runtime profile differs from the host runtime",
            ));
        }

        let provider_offer = packages.provider_offer();
        provider_offer.validate()?;
        if report.provider_implementation != provider_offer.implementation.to_string()
            || report.provider_offer_id != provider_offer.offer_id.to_string()
        {
            return Err(invariant(
                "package report does not bind the verified provider offer",
            ));
        }
        let provider_artifact = packages.provider_artifact();
        if provider_offer.artifact_digest.as_str() != provider_artifact.digest().as_str()
            || provider_artifact.name().as_str() != PROVIDER_RESOURCE
        {
            return Err(invariant(
                "provider offer does not bind the verified provider resource",
            ));
        }
        let provider_package = report
            .packages
            .iter()
            .find(|coordinate| coordinate.package.to_string() == PROVIDER_PACKAGE)
            .ok_or_else(|| invariant("verified report lacks the provider package"))?;
        let provider_resource = provider_package
            .resources
            .iter()
            .find(|resource| resource.name.as_str() == PROVIDER_RESOURCE)
            .ok_or_else(|| invariant("verified report lacks the provider resource"))?;
        if provider_resource.digest != *provider_artifact.digest() {
            return Err(invariant(
                "provider report coordinate differs from retained resource bytes",
            ));
        }
        let provider_lock = DeploymentLock::new(
            provider_offer.implementation.to_string(),
            provider_package.package.to_string(),
            provider_package.digest.to_string(),
            provider_artifact.name().to_string(),
            provider_artifact.digest().to_string(),
        )?;

        let attester_report = &report.attester;
        if attester_report.suite != gooir_datamodel_conformance::suite_id().to_string()
            || attester_report.implementation
                != gooir_datamodel_conformance::implementation_id().to_string()
            || attester_report.resource.as_str() != ATTESTER_RESOURCE
        {
            return Err(invariant(
                "package report attester coordinates differ from the fixture authority",
            ));
        }
        let attester_artifact = packages
            .attester_resource(attester_report)
            .ok_or_else(|| invariant("verified attester deployment lock cannot be resolved"))?;
        let attester_digest = ArtifactDigest::parse(attester_artifact.digest().to_string())
            .map_err(|error| invariant(error.to_string()))?;
        let expected_authority = ConformanceAuthority::new(
            gooir_datamodel_conformance::suite_id(),
            ConformanceAttester::new(
                gooir_datamodel_conformance::implementation_id(),
                attester_digest.clone(),
                BTreeMap::new(),
            )?,
            BTreeMap::new(),
        )?;
        request.admission_policy.validate()?;
        if !request
            .admission_policy
            .accepted_conformance
            .contains(&expected_authority)
        {
            return Err(invariant(
                "admission policy does not accept the exact installed attester authority",
            ));
        }
        let attester_lock = DeploymentLock::new(
            attester_report.implementation.clone(),
            attester_report.package.to_string(),
            attester_report.package_digest.to_string(),
            attester_artifact.name().to_string(),
            attester_artifact.digest().to_string(),
        )?;

        request.baseline_snapshot.validate()?;
        let baseline_ledger = AdmissionLedger::rebuild(&request.baseline_snapshot)?;
        let resolved_source = baseline_ledger.resolve(&request.source)?;

        let planner = packages.planner(request.planning_limits)?;
        let contract = author_data_model_spec();
        let plan = planner.plan(
            [resolved_source.fact.value_kind.clone()],
            semantics_data_model_v1::model_contract(),
        )?;
        let [source_port] = contract.input_ports.as_slice() else {
            return Err(invariant(
                "author-data-model contract no longer has exactly one input",
            ));
        };
        let input = LinkedInput::new(
            source_port.name.clone(),
            request.source.clone(),
            resolved_source.fact.clone(),
            BTreeMap::new(),
        )?;
        let invocation = planner.link_invocation(
            &plan,
            InvocationLink {
                capability: &contract.id,
                offer: &provider_offer.offer_id,
                selection_extensions: BTreeMap::new(),
                inputs: vec![input],
                conformance_suite: author_data_model_suite_id(),
                invocation_extensions: BTreeMap::new(),
            },
        )?;
        invocation.validate()?;
        if invocation.selection.offer != *provider_offer
            || invocation.conformance_suite != expected_authority.suite
        {
            return Err(invariant(
                "linked invocation differs from the exact installed offer or suite",
            ));
        }
        resolve_invocation_inputs(&baseline_ledger, &invocation)?;

        let execution_policy = request.execution_limits.policy()?;
        let semantic_plan = exact_document(&plan)?;
        let exact_invocation = exact_document(&invocation)?;
        let baseline_snapshot = exact_document(&request.baseline_snapshot)?;
        let exact_execution_policy = exact_document(&execution_policy)?;
        let exact_admission_policy = exact_document(&request.admission_policy)?;
        let inputs = AttemptInputs::new(UnboundAttemptInputs {
            semantic_plan,
            invocation: exact_invocation,
            baseline_snapshot,
            conformance_suite: invocation.conformance_suite.to_string(),
            provider: provider_lock.clone(),
            attester: attester_lock.clone(),
            execution_policy: exact_execution_policy,
            admission_policy: exact_admission_policy,
        })?;

        Ok(Self {
            packages,
            plan,
            invocation,
            baseline: request.baseline_snapshot.clone(),
            policy: request.admission_policy.clone(),
            expected_authority,
            attester_digest,
            planning_limits: request.planning_limits,
            execution_limits: request.execution_limits,
            execution_policy,
            provider_lock,
            attester_lock,
            inputs,
        })
    }

    fn validate_checkpoint(&self, checkpoint: &AttemptCheckpoint) -> Result<(), HostError> {
        checkpoint.validate()?;
        if checkpoint.inputs() != &self.inputs {
            return Err(HostError::AttemptInputsMismatch {
                expected: self.inputs.attempt_id.clone(),
                actual: checkpoint.inputs().attempt_id.clone(),
            });
        }

        let plan: SemanticPlan = decode_exact(&checkpoint.inputs().semantic_plan)?;
        plan.validate(self.planning_limits)?;
        if plan != self.plan {
            return Err(invariant(
                "journaled plan differs from independently replanned graph",
            ));
        }
        let invocation: CapabilityInvocation = decode_exact(&checkpoint.inputs().invocation)?;
        invocation.validate()?;
        if invocation != self.invocation {
            return Err(invariant(
                "journaled invocation differs from independently relinked invocation",
            ));
        }
        let baseline: AdmissionSnapshot = decode_exact(&checkpoint.inputs().baseline_snapshot)?;
        baseline.validate()?;
        if baseline != self.baseline {
            return Err(invariant(
                "journaled baseline differs from trusted baseline",
            ));
        }
        let ledger = AdmissionLedger::rebuild(&baseline)?;
        resolve_invocation_inputs(&ledger, &invocation)?;
        let execution_policy: AttemptExecutionPolicy =
            decode_exact(&checkpoint.inputs().execution_policy)?;
        execution_policy.validate()?;
        if execution_policy != self.execution_policy {
            return Err(invariant(
                "journaled execution policy differs from host limits",
            ));
        }
        let policy: AdmissionPolicy = decode_exact(&checkpoint.inputs().admission_policy)?;
        policy.validate()?;
        if policy != self.policy {
            return Err(invariant(
                "journaled admission policy differs from host policy",
            ));
        }
        if checkpoint.inputs().provider != self.provider_lock
            || checkpoint.inputs().attester != self.attester_lock
            || checkpoint.inputs().conformance_suite != self.expected_authority.suite.to_string()
        {
            return Err(invariant("journaled deployment or suite lock changed"));
        }

        self.validate_retained_evidence(checkpoint)
    }

    fn provider_request(&self) -> Result<WasmRequest, HostError> {
        Ok(WasmRequest {
            module: self.packages.provider_artifact().bytes().to_vec(),
            stdin: canonical_bytes(&self.invocation)?,
            limits: self.execution_limits.provider,
        })
    }

    fn attester_request(&self, request: &AssessmentRequest) -> Result<WasmRequest, HostError> {
        let module = self
            .packages
            .attester_resource(&self.packages.report().attester)
            .ok_or_else(|| invariant("attester lock no longer resolves"))?
            .bytes()
            .to_vec();
        Ok(WasmRequest {
            module,
            stdin: canonical_bytes(request)?,
            limits: self.execution_limits.attester,
        })
    }

    fn validate_retained_evidence(&self, checkpoint: &AttemptCheckpoint) -> Result<(), HostError> {
        let provider = self.recover_provider_evidence(checkpoint)?;
        let assessment = self.recover_assessment_evidence(checkpoint, &provider)?;
        self.validate_resolution(checkpoint, &provider, assessment.as_ref())
    }

    fn recover_provider_evidence(
        &self,
        checkpoint: &AttemptCheckpoint,
    ) -> Result<RecoveredProviderEvidence, HostError> {
        let provider = if let Some(exact) = checkpoint.provider_receipt() {
            let receipt: WasmReceipt = decode_exact(exact)?;
            receipt.validate_against(&self.provider_request()?)?;
            Some(receipt)
        } else {
            None
        };

        let result = if checkpoint.candidate().is_some()
            || checkpoint.assessment_request().is_some()
            || checkpoint.attester_receipt().is_some()
            || checkpoint.assessment().is_some()
            || matches!(
                checkpoint.phase(),
                AttemptPhase::Admitted | AttemptPhase::Withheld
            ) {
            let receipt = provider
                .as_ref()
                .ok_or_else(|| invariant("semantic evidence lacks provider receipt"))?;
            Some(self.decode_provider_result(receipt)?)
        } else {
            None
        };

        let candidate = if let Some(exact) = checkpoint.candidate() {
            let decoded: CapabilityCandidate = decode_exact(exact)?;
            decoded.validate_against(&self.invocation)?;
            let expected = CapabilityCandidate::new(
                &self.invocation,
                result
                    .as_ref()
                    .ok_or_else(|| invariant("candidate lacks provider result"))?
                    .clone(),
                BTreeMap::new(),
            )?;
            if decoded != expected {
                return Err(invariant(
                    "journaled candidate differs from the captured provider result",
                ));
            }
            Some(decoded)
        } else {
            None
        };
        Ok(RecoveredProviderEvidence { result, candidate })
    }

    fn recover_assessment_evidence(
        &self,
        checkpoint: &AttemptCheckpoint,
        provider: &RecoveredProviderEvidence,
    ) -> Result<Option<ConformanceAssessment>, HostError> {
        let assessment_request = if let Some(exact) = checkpoint.assessment_request() {
            let decoded: AssessmentRequest = decode_exact(exact)?;
            decoded.validate()?;
            let expected = self.assessment_request(
                provider
                    .result
                    .as_ref()
                    .ok_or_else(|| invariant("assessment request lacks provider result"))?,
                provider
                    .candidate
                    .as_ref()
                    .ok_or_else(|| invariant("assessment request lacks candidate"))?,
            )?;
            if decoded != expected {
                return Err(invariant(
                    "journaled assessment request differs from the exact candidate chain",
                ));
            }
            Some(decoded)
        } else {
            None
        };

        let attester_receipt = if let Some(exact) = checkpoint.attester_receipt() {
            let request = assessment_request
                .as_ref()
                .ok_or_else(|| invariant("attester receipt lacks assessment request"))?;
            let decoded: WasmReceipt = decode_exact(exact)?;
            decoded.validate_against(&self.attester_request(request)?)?;
            Some(decoded)
        } else {
            None
        };

        let assessment = if let Some(exact) = checkpoint.assessment() {
            let receipt = attester_receipt
                .as_ref()
                .ok_or_else(|| invariant("assessment lacks attester receipt"))?;
            let decoded = self.decode_assessment(
                receipt,
                provider
                    .result
                    .as_ref()
                    .ok_or_else(|| invariant("assessment lacks provider result"))?,
                provider
                    .candidate
                    .as_ref()
                    .ok_or_else(|| invariant("assessment lacks candidate"))?,
            )?;
            if &exact_document(&decoded)? != exact {
                return Err(invariant(
                    "journaled assessment differs from the attester capture",
                ));
            }
            Some(decoded)
        } else {
            None
        };
        Ok(assessment)
    }

    fn validate_resolution(
        &self,
        checkpoint: &AttemptCheckpoint,
        provider: &RecoveredProviderEvidence,
        assessment: Option<&ConformanceAssessment>,
    ) -> Result<(), HostError> {
        match checkpoint.resolution() {
            Some(AttemptResolution::Unable { from, failure }) => {
                let failure: HostFailure = decode_exact(failure)?;
                failure.validate_for(*from)?;
                self.validate_unable_resolution(checkpoint, *from, &failure)?;
            }
            Some(AttemptResolution::Admitted { admission_snapshot }) => {
                let expected = self.evaluate_admission(
                    provider
                        .result
                        .as_ref()
                        .ok_or_else(|| invariant("admission lacks provider result"))?,
                    provider
                        .candidate
                        .as_ref()
                        .ok_or_else(|| invariant("admission lacks candidate"))?,
                    assessment.ok_or_else(|| invariant("admission lacks assessment"))?,
                )?;
                let AdmissionEvaluation::Admitted { snapshot, .. } = expected else {
                    return Err(invariant(
                        "journal says admitted but deterministic admission withheld",
                    ));
                };
                if &exact_document(&snapshot)? != admission_snapshot {
                    return Err(invariant(
                        "journaled admission snapshot differs from deterministic replay",
                    ));
                }
            }
            Some(AttemptResolution::Withheld { decision }) => {
                let expected = self.evaluate_admission(
                    provider
                        .result
                        .as_ref()
                        .ok_or_else(|| invariant("withholding lacks provider result"))?,
                    provider
                        .candidate
                        .as_ref()
                        .ok_or_else(|| invariant("withholding lacks candidate"))?,
                    assessment.ok_or_else(|| invariant("withholding lacks assessment"))?,
                )?;
                let AdmissionEvaluation::Withheld { decision: expected } = expected else {
                    return Err(invariant(
                        "journal says withheld but deterministic admission admitted",
                    ));
                };
                if &exact_document(&expected)? != decision {
                    return Err(invariant(
                        "journaled withholding differs from deterministic replay",
                    ));
                }
            }
            None => {}
        }
        Ok(())
    }

    fn validate_unable_resolution(
        &self,
        checkpoint: &AttemptCheckpoint,
        from: AttemptPhase,
        failure: &HostFailure,
    ) -> Result<(), HostError> {
        match from {
            AttemptPhase::Prepared => {
                if failure.evidence_digest.is_some() {
                    return Err(invariant(
                        "preparation failure unexpectedly names an execution receipt",
                    ));
                }
                validate_preparation_failure(&self.provider_request()?, failure)
            }
            AttemptPhase::CandidateReady => {
                if failure.evidence_digest.is_some() {
                    return Err(invariant(
                        "preparation failure unexpectedly names an execution receipt",
                    ));
                }
                let candidate: CapabilityCandidate =
                    decode_exact(checkpoint.candidate().ok_or_else(|| {
                        invariant("attester preparation failure lacks candidate")
                    })?)?;
                candidate.validate_against(&self.invocation)?;
                let request = self.assessment_request(&candidate.result, &candidate)?;
                validate_preparation_failure(&self.attester_request(&request)?, failure)
            }
            AttemptPhase::ProviderCaptured => self.validate_provider_unable(checkpoint, failure),
            AttemptPhase::AttesterCaptured => self.validate_attester_unable(checkpoint, failure),
            _ => Err(invariant(
                "unable resolution names an armed or terminal phase",
            )),
        }
    }

    fn validate_provider_unable(
        &self,
        checkpoint: &AttemptCheckpoint,
        failure: &HostFailure,
    ) -> Result<(), HostError> {
        let exact = checkpoint
            .provider_receipt()
            .ok_or_else(|| invariant("provider inability lacks its receipt"))?;
        if failure.evidence_digest.as_deref() != Some(exact.digest.as_str()) {
            return Err(invariant(
                "provider inability does not bind the retained receipt",
            ));
        }
        let receipt: WasmReceipt = decode_exact(exact)?;
        receipt.validate_against(&self.provider_request()?)?;
        let expected = if require_clean_success(&receipt).is_err() {
            (
                FailureStage::ProviderExecution,
                FailureReason::ExecutionDidNotSucceed,
            )
        } else {
            match serde_json::from_slice::<CapabilityResult>(&receipt.stdout) {
                Err(_) => (FailureStage::ProviderResult, FailureReason::InvalidOutput),
                Ok(result) if result.validate_against(&self.invocation).is_err() => {
                    (FailureStage::ProviderResult, FailureReason::InvalidOutput)
                }
                Ok(result) if !result.is_produced() => {
                    (FailureStage::ProviderResult, FailureReason::SemanticUnable)
                }
                Ok(_) => {
                    return Err(invariant(
                        "provider inability contradicts one valid produced result",
                    ));
                }
            }
        };
        if (failure.stage, failure.reason) != expected {
            return Err(invariant(
                "provider inability classification differs from its receipt",
            ));
        }
        Ok(())
    }

    fn validate_attester_unable(
        &self,
        checkpoint: &AttemptCheckpoint,
        failure: &HostFailure,
    ) -> Result<(), HostError> {
        let exact = checkpoint
            .attester_receipt()
            .ok_or_else(|| invariant("attester inability lacks its receipt"))?;
        if failure.evidence_digest.as_deref() != Some(exact.digest.as_str()) {
            return Err(invariant(
                "attester inability does not bind the retained receipt",
            ));
        }
        let request: AssessmentRequest = decode_exact(
            checkpoint
                .assessment_request()
                .ok_or_else(|| invariant("attester inability lacks its request"))?,
        )?;
        let receipt: WasmReceipt = decode_exact(exact)?;
        receipt.validate_against(&self.attester_request(&request)?)?;
        let expected = if require_clean_success(&receipt).is_err() {
            (
                FailureStage::AttesterExecution,
                FailureReason::ExecutionDidNotSucceed,
            )
        } else {
            match serde_json::from_slice::<ConformanceAssessment>(&receipt.stdout) {
                Err(_) => (
                    FailureStage::AttesterAssessment,
                    FailureReason::InvalidOutput,
                ),
                Ok(assessment)
                    if assessment
                        .validate_against(
                            request.invocation(),
                            request.result(),
                            request.candidate(),
                        )
                        .is_err() =>
                {
                    (
                        FailureStage::AttesterAssessment,
                        FailureReason::InvalidOutput,
                    )
                }
                Ok(assessment) if assessment.authority != self.expected_authority => (
                    FailureStage::AttesterAssessment,
                    FailureReason::AuthoritySubstituted,
                ),
                Ok(_) => {
                    return Err(invariant(
                        "attester inability contradicts one valid locked assessment",
                    ));
                }
            }
        };
        if (failure.stage, failure.reason) != expected {
            return Err(invariant(
                "attester inability classification differs from its receipt",
            ));
        }
        Ok(())
    }

    fn decode_provider_result(&self, receipt: &WasmReceipt) -> Result<CapabilityResult, HostError> {
        require_clean_success(receipt)?;
        let result: CapabilityResult = serde_json::from_slice(&receipt.stdout)?;
        result.validate_against(&self.invocation)?;
        Ok(result)
    }

    fn assessment_request(
        &self,
        result: &CapabilityResult,
        candidate: &CapabilityCandidate,
    ) -> Result<AssessmentRequest, HostError> {
        AssessmentRequest::new(
            self.invocation.clone(),
            result.clone(),
            candidate.clone(),
            self.attester_digest.clone(),
        )
        .map_err(HostError::Attester)
    }

    fn decode_assessment(
        &self,
        receipt: &WasmReceipt,
        result: &CapabilityResult,
        candidate: &CapabilityCandidate,
    ) -> Result<ConformanceAssessment, HostError> {
        require_clean_success(receipt)?;
        let assessment: ConformanceAssessment = serde_json::from_slice(&receipt.stdout)?;
        assessment.validate_against(&self.invocation, result, candidate)?;
        if assessment.authority != self.expected_authority {
            return Err(invariant(
                "attester response authority differs from the installed deployment lock",
            ));
        }
        Ok(assessment)
    }

    fn evaluate_admission(
        &self,
        result: &CapabilityResult,
        candidate: &CapabilityCandidate,
        assessment: &ConformanceAssessment,
    ) -> Result<AdmissionEvaluation, HostError> {
        let mut ledger = AdmissionLedger::rebuild(&self.baseline)?;
        let outcome = ledger.admit_candidate(
            &self.policy,
            &self.invocation,
            result,
            candidate,
            assessment,
        )?;
        match outcome {
            AdmissionOutcome::Withheld { decision } => {
                decision.validate_candidate(
                    &self.policy,
                    &self.invocation,
                    result,
                    candidate,
                    assessment,
                )?;
                let unchanged = ledger.export_with_extensions(self.baseline.extensions.clone())?;
                if unchanged != self.baseline {
                    return Err(invariant("withheld admission mutated the baseline ledger"));
                }
                Ok(AdmissionEvaluation::Withheld { decision })
            }
            AdmissionOutcome::Admitted { decision, links } => {
                decision.validate_candidate(
                    &self.policy,
                    &self.invocation,
                    result,
                    candidate,
                    assessment,
                )?;
                let CapabilityOutcome::Produced { outputs, .. } = &result.outcome else {
                    return Err(invariant("admission accepted an unable result"));
                };
                if outputs.len() != links.len() {
                    return Err(invariant("admission links do not cover every output"));
                }
                for (output, link) in outputs.iter().zip(&links) {
                    if link.port.as_ref() != Some(&output.port) {
                        return Err(invariant("admission link output port changed"));
                    }
                    let resolved = ledger.resolve(&link.reference)?;
                    if resolved.fact != &output.fact {
                        return Err(invariant("admission link resolves to a different fact"));
                    }
                }
                let snapshot = ledger.export_with_extensions(self.baseline.extensions.clone())?;
                snapshot.validate()?;
                let rebuilt = AdmissionLedger::rebuild(&snapshot)?;
                for (output, link) in outputs.iter().zip(&links) {
                    let resolved = rebuilt.resolve(&link.reference)?;
                    if resolved.fact != &output.fact {
                        return Err(invariant(
                            "rebuilt admission snapshot lost an admitted output",
                        ));
                    }
                }
                Ok(AdmissionEvaluation::Admitted { snapshot })
            }
        }
    }
}

#[derive(Debug)]
enum AdmissionEvaluation {
    Admitted { snapshot: AdmissionSnapshot },
    Withheld { decision: AdmissionDecision },
}

#[derive(Debug)]
struct RecoveredProviderEvidence {
    result: Option<CapabilityResult>,
    candidate: Option<CapabilityCandidate>,
}

#[derive(Clone, Copy, Debug)]
enum Interruption {
    None,
    #[cfg(test)]
    ExitAfter(AttemptPhase),
}

impl Interruption {
    fn after(self, phase: AttemptPhase) {
        match self {
            Self::None => {}
            #[cfg(test)]
            Self::ExitAfter(expected) if expected == phase => std::process::exit(86),
            #[cfg(test)]
            Self::ExitAfter(_) => {}
        }
        let _ = phase;
    }
}

fn drive(
    journal: &AttemptJournal,
    context: &Context,
    mut checkpoint: AttemptCheckpoint,
    interruption: Interruption,
) -> Result<AttemptCheckpoint, HostError> {
    loop {
        context.validate_checkpoint(&checkpoint)?;
        interruption.after(checkpoint.phase());
        let next = match checkpoint.phase() {
            AttemptPhase::Prepared => {
                execute_provider(journal, context, &checkpoint, interruption)?
            }
            AttemptPhase::ProviderArmed | AttemptPhase::AttesterArmed => return Ok(checkpoint),
            AttemptPhase::ProviderCaptured => build_candidate(journal, context, &checkpoint)?,
            AttemptPhase::CandidateReady => {
                execute_attester(journal, context, &checkpoint, interruption)?
            }
            AttemptPhase::AttesterCaptured => build_assessment(journal, context, &checkpoint)?,
            AttemptPhase::AssessmentReady => evaluate_admission(journal, context, &checkpoint)?,
            AttemptPhase::Admitted | AttemptPhase::Withheld | AttemptPhase::Unable => {
                return Ok(checkpoint);
            }
        };
        interruption.after(next.phase());
        checkpoint = next;
    }
}

fn execute_provider(
    journal: &AttemptJournal,
    context: &Context,
    checkpoint: &AttemptCheckpoint,
    interruption: Interruption,
) -> Result<AttemptCheckpoint, HostError> {
    let request = context.provider_request()?;
    let prepared = match prepare(&request) {
        Ok(prepared) => prepared,
        Err(error @ WasmError::SpawnWatchdog(_)) => return Err(error.into()),
        Err(error) => {
            return resolve_unable(
                journal,
                checkpoint,
                &HostFailure::new(
                    FailureStage::ProviderPreparation,
                    FailureReason::PreparationRefused,
                    None,
                    Some(error.to_string()),
                ),
            );
        }
    };
    let armed = checkpoint.arm_provider()?;
    journal.replace(checkpoint.checkpoint_id(), &armed)?;
    interruption.after(AttemptPhase::ProviderArmed);
    let receipt = prepared.execute();
    let captured = armed.capture_provider(exact_document(&receipt)?)?;
    journal.replace(armed.checkpoint_id(), &captured)?;
    Ok(captured)
}

fn build_candidate(
    journal: &AttemptJournal,
    context: &Context,
    checkpoint: &AttemptCheckpoint,
) -> Result<AttemptCheckpoint, HostError> {
    let exact_receipt = checkpoint
        .provider_receipt()
        .ok_or_else(|| invariant("provider-captured checkpoint lacks its receipt"))?;
    let receipt: WasmReceipt = decode_exact(exact_receipt)?;
    receipt.validate_against(&context.provider_request()?)?;
    if let Err(error) = require_clean_success(&receipt) {
        return resolve_unable(
            journal,
            checkpoint,
            &HostFailure::new(
                FailureStage::ProviderExecution,
                FailureReason::ExecutionDidNotSucceed,
                Some(exact_receipt.digest.clone()),
                Some(error.to_string()),
            ),
        );
    }
    let result: CapabilityResult = match serde_json::from_slice(&receipt.stdout) {
        Ok(result) => result,
        Err(error) => {
            return resolve_unable(
                journal,
                checkpoint,
                &HostFailure::new(
                    FailureStage::ProviderResult,
                    FailureReason::InvalidOutput,
                    Some(exact_receipt.digest.clone()),
                    Some(error.to_string()),
                ),
            );
        }
    };
    if let Err(error) = result.validate_against(&context.invocation) {
        return resolve_unable(
            journal,
            checkpoint,
            &HostFailure::new(
                FailureStage::ProviderResult,
                FailureReason::InvalidOutput,
                Some(exact_receipt.digest.clone()),
                Some(error.to_string()),
            ),
        );
    }
    if !result.is_produced() {
        return resolve_unable(
            journal,
            checkpoint,
            &HostFailure::new(
                FailureStage::ProviderResult,
                FailureReason::SemanticUnable,
                Some(exact_receipt.digest.clone()),
                Some(result.result_id.to_string()),
            ),
        );
    }
    let candidate = CapabilityCandidate::new(&context.invocation, result, BTreeMap::new())?;
    let next = checkpoint.candidate_ready(exact_document(&candidate)?)?;
    journal.replace(checkpoint.checkpoint_id(), &next)?;
    Ok(next)
}

fn execute_attester(
    journal: &AttemptJournal,
    context: &Context,
    checkpoint: &AttemptCheckpoint,
    interruption: Interruption,
) -> Result<AttemptCheckpoint, HostError> {
    let candidate: CapabilityCandidate = decode_exact(
        checkpoint
            .candidate()
            .ok_or_else(|| invariant("candidate-ready checkpoint lacks candidate"))?,
    )?;
    candidate.validate_against(&context.invocation)?;
    let result = &candidate.result;
    let assessment = context.assessment_request(result, &candidate)?;
    assessment.validate()?;
    let request = context.attester_request(&assessment)?;
    let prepared = match prepare(&request) {
        Ok(prepared) => prepared,
        Err(error @ WasmError::SpawnWatchdog(_)) => return Err(error.into()),
        Err(error) => {
            return resolve_unable(
                journal,
                checkpoint,
                &HostFailure::new(
                    FailureStage::AttesterPreparation,
                    FailureReason::PreparationRefused,
                    None,
                    Some(error.to_string()),
                ),
            );
        }
    };
    let armed = checkpoint.arm_attester(exact_document(&assessment)?)?;
    journal.replace(checkpoint.checkpoint_id(), &armed)?;
    interruption.after(AttemptPhase::AttesterArmed);
    let receipt = prepared.execute();
    let captured = armed.capture_attester(exact_document(&receipt)?)?;
    journal.replace(armed.checkpoint_id(), &captured)?;
    Ok(captured)
}

fn build_assessment(
    journal: &AttemptJournal,
    context: &Context,
    checkpoint: &AttemptCheckpoint,
) -> Result<AttemptCheckpoint, HostError> {
    let candidate: CapabilityCandidate = decode_exact(
        checkpoint
            .candidate()
            .ok_or_else(|| invariant("attester capture lacks candidate"))?,
    )?;
    let result = &candidate.result;
    let assessment_request: AssessmentRequest = decode_exact(
        checkpoint
            .assessment_request()
            .ok_or_else(|| invariant("attester capture lacks assessment request"))?,
    )?;
    let expected_request = context.assessment_request(result, &candidate)?;
    if assessment_request != expected_request {
        return Err(invariant("captured attester request changed"));
    }
    let exact_receipt = checkpoint
        .attester_receipt()
        .ok_or_else(|| invariant("attester-captured checkpoint lacks receipt"))?;
    let receipt: WasmReceipt = decode_exact(exact_receipt)?;
    receipt.validate_against(&context.attester_request(&assessment_request)?)?;
    if let Err(error) = require_clean_success(&receipt) {
        return resolve_unable(
            journal,
            checkpoint,
            &HostFailure::new(
                FailureStage::AttesterExecution,
                FailureReason::ExecutionDidNotSucceed,
                Some(exact_receipt.digest.clone()),
                Some(error.to_string()),
            ),
        );
    }
    let assessment: ConformanceAssessment = match serde_json::from_slice(&receipt.stdout) {
        Ok(assessment) => assessment,
        Err(error) => {
            return resolve_unable(
                journal,
                checkpoint,
                &HostFailure::new(
                    FailureStage::AttesterAssessment,
                    FailureReason::InvalidOutput,
                    Some(exact_receipt.digest.clone()),
                    Some(error.to_string()),
                ),
            );
        }
    };
    if let Err(error) = assessment.validate_against(&context.invocation, result, &candidate) {
        return resolve_unable(
            journal,
            checkpoint,
            &HostFailure::new(
                FailureStage::AttesterAssessment,
                FailureReason::InvalidOutput,
                Some(exact_receipt.digest.clone()),
                Some(error.to_string()),
            ),
        );
    }
    if assessment.authority != context.expected_authority {
        return resolve_unable(
            journal,
            checkpoint,
            &HostFailure::new(
                FailureStage::AttesterAssessment,
                FailureReason::AuthoritySubstituted,
                Some(exact_receipt.digest.clone()),
                Some(assessment.assessment_id.to_string()),
            ),
        );
    }
    let next = checkpoint.assessment_ready(exact_document(&assessment)?)?;
    journal.replace(checkpoint.checkpoint_id(), &next)?;
    Ok(next)
}

fn evaluate_admission(
    journal: &AttemptJournal,
    context: &Context,
    checkpoint: &AttemptCheckpoint,
) -> Result<AttemptCheckpoint, HostError> {
    let candidate: CapabilityCandidate = decode_exact(
        checkpoint
            .candidate()
            .ok_or_else(|| invariant("assessment-ready checkpoint lacks candidate"))?,
    )?;
    let assessment: ConformanceAssessment = decode_exact(
        checkpoint
            .assessment()
            .ok_or_else(|| invariant("assessment-ready checkpoint lacks assessment"))?,
    )?;
    let next = match context.evaluate_admission(&candidate.result, &candidate, &assessment)? {
        AdmissionEvaluation::Admitted { snapshot } => {
            checkpoint.admitted(exact_document(&snapshot)?)?
        }
        AdmissionEvaluation::Withheld { decision } => {
            checkpoint.withheld(exact_document(&decision)?)?
        }
    };
    journal.replace(checkpoint.checkpoint_id(), &next)?;
    Ok(next)
}

fn resolve_unable(
    journal: &AttemptJournal,
    checkpoint: &AttemptCheckpoint,
    failure: &HostFailure,
) -> Result<AttemptCheckpoint, HostError> {
    failure.validate_for(checkpoint.phase())?;
    let next = checkpoint.unable(exact_document(&failure)?)?;
    journal.replace(checkpoint.checkpoint_id(), &next)?;
    Ok(next)
}

fn resolve_invocation_inputs(
    ledger: &AdmissionLedger,
    invocation: &CapabilityInvocation,
) -> Result<(), HostError> {
    for input in &invocation.inputs {
        let resolved = ledger.resolve(&input.admitted)?;
        if resolved.fact != &input.fact {
            return Err(invariant(
                "linked invocation input differs from its admitted authority reference",
            ));
        }
    }
    Ok(())
}

fn require_clean_success(receipt: &WasmReceipt) -> Result<(), HostError> {
    if receipt.is_clean_success() {
        Ok(())
    } else {
        Err(invariant(
            "WASIp1 command did not complete successfully with empty stderr",
        ))
    }
}

fn validate_preparation_failure(
    request: &WasmRequest,
    failure: &HostFailure,
) -> Result<(), HostError> {
    match prepare(request) {
        Ok(prepared) => {
            drop(prepared);
            Err(invariant(
                "journaled preparation failure no longer reproduces for the exact request",
            ))
        }
        Err(WasmError::SpawnWatchdog(_)) => Err(invariant(
            "transient host inability cannot justify a terminal preparation failure",
        )),
        Err(error) => {
            let expected = error.to_string();
            if failure.detail.as_deref() != Some(expected.as_str()) {
                return Err(invariant(
                    "journaled preparation failure differs from exact-request replay",
                ));
            }
            Ok(())
        }
    }
}

fn exact_document<T: Serialize>(document: &T) -> Result<ExactJson, HostError> {
    let value = serde_json::to_value(document)?;
    ExactJson::new(value).map_err(HostError::Journal)
}

fn decode_exact<T>(exact: &ExactJson) -> Result<T, HostError>
where
    T: DeserializeOwned + Serialize,
{
    exact.validate()?;
    let decoded: T = serde_json::from_value(exact.value.clone())?;
    if exact_document(&decoded)? != *exact {
        return Err(invariant(
            "typed document does not reproduce its exact canonical JSON",
        ));
    }
    Ok(decoded)
}

fn canonical_bytes<T: Serialize>(document: &T) -> Result<Vec<u8>, HostError> {
    serde_json_canonicalizer::to_vec(document)
        .map_err(|error| HostError::Serialization(error.to_string()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FailureStage {
    ProviderPreparation,
    ProviderExecution,
    ProviderResult,
    AttesterPreparation,
    AttesterExecution,
    AttesterAssessment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FailureReason {
    PreparationRefused,
    ExecutionDidNotSucceed,
    InvalidOutput,
    SemanticUnable,
    AuthoritySubstituted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFailure {
    protocol: String,
    stage: FailureStage,
    reason: FailureReason,
    evidence_digest: Option<String>,
    detail: Option<String>,
}

impl HostFailure {
    fn new(
        stage: FailureStage,
        reason: FailureReason,
        evidence_digest: Option<String>,
        detail: Option<String>,
    ) -> Self {
        Self {
            protocol: FAILURE_PROTOCOL.to_owned(),
            stage,
            reason,
            evidence_digest,
            detail,
        }
    }

    fn validate_for(&self, phase: AttemptPhase) -> Result<(), HostError> {
        if self.protocol != FAILURE_PROTOCOL {
            return Err(invariant("unsupported external-host failure protocol"));
        }
        let stage_matches = matches!(
            (phase, self.stage),
            (AttemptPhase::Prepared, FailureStage::ProviderPreparation)
                | (
                    AttemptPhase::ProviderCaptured,
                    FailureStage::ProviderExecution | FailureStage::ProviderResult
                )
                | (
                    AttemptPhase::CandidateReady,
                    FailureStage::AttesterPreparation
                )
                | (
                    AttemptPhase::AttesterCaptured,
                    FailureStage::AttesterExecution | FailureStage::AttesterAssessment
                )
        );
        if !stage_matches {
            return Err(invariant("failure stage does not match its durable phase"));
        }
        let reason_matches = matches!(
            (self.stage, self.reason),
            (
                FailureStage::ProviderPreparation | FailureStage::AttesterPreparation,
                FailureReason::PreparationRefused
            ) | (
                FailureStage::ProviderExecution | FailureStage::AttesterExecution,
                FailureReason::ExecutionDidNotSucceed
            ) | (
                FailureStage::ProviderResult,
                FailureReason::InvalidOutput | FailureReason::SemanticUnable
            ) | (
                FailureStage::AttesterAssessment,
                FailureReason::InvalidOutput | FailureReason::AuthoritySubstituted
            )
        );
        if !reason_matches {
            return Err(invariant("failure reason does not match its stage"));
        }
        if let Some(digest) = &self.evidence_digest {
            ArtifactDigest::parse(digest.clone()).map_err(|error| invariant(error.to_string()))?;
        }
        if self.detail.as_deref().is_none_or(str::is_empty) {
            return Err(invariant(
                "external-host failure lacks bounded diagnostic detail",
            ));
        }
        Ok(())
    }
}

fn invariant(message: impl Into<String>) -> HostError {
    HostError::Invariant(message.into())
}

/// Failure to establish or advance one exact external-host attempt.
#[derive(Debug)]
pub enum HostError {
    Package(ProofError),
    Planning(PlanningError),
    Protocol(ProtocolError),
    Authority(AuthorityError),
    Attester(AttesterError),
    Runtime(WasmError),
    Journal(JournalError),
    Json(serde_json::Error),
    Serialization(String),
    AttemptInputsMismatch { expected: String, actual: String },
    Invariant(String),
}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Package(error) => write!(formatter, "package verification failed: {error}"),
            Self::Planning(error) => write!(formatter, "semantic planning failed: {error}"),
            Self::Protocol(error) => write!(formatter, "capability protocol failed: {error}"),
            Self::Authority(error) => write!(formatter, "authority validation failed: {error}"),
            Self::Attester(error) => write!(formatter, "conformance request failed: {error}"),
            Self::Runtime(error) => write!(formatter, "WASIp1 runtime failed: {error}"),
            Self::Journal(error) => write!(formatter, "attempt journal failed: {error}"),
            Self::Json(error) => write!(formatter, "JSON document failed: {error}"),
            Self::Serialization(error) => write!(formatter, "canonical JSON failed: {error}"),
            Self::AttemptInputsMismatch { expected, actual } => write!(
                formatter,
                "journal attempt {actual} differs from independently reconstructed attempt {expected}"
            ),
            Self::Invariant(message) => formatter.write_str(message),
        }
    }
}

impl Error for HostError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Package(error) => Some(error),
            Self::Planning(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Authority(error) => Some(error),
            Self::Attester(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::Journal(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Serialization(_) | Self::AttemptInputsMismatch { .. } | Self::Invariant(_) => {
                None
            }
        }
    }
}

impl From<ProofError> for HostError {
    fn from(error: ProofError) -> Self {
        Self::Package(error)
    }
}

impl From<PlanningError> for HostError {
    fn from(error: PlanningError) -> Self {
        Self::Planning(error)
    }
}

impl From<ProtocolError> for HostError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<AuthorityError> for HostError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}

impl From<AttesterError> for HostError {
    fn from(error: AttesterError) -> Self {
        Self::Attester(error)
    }
}

impl From<WasmError> for HostError {
    fn from(error: WasmError) -> Self {
        Self::Runtime(error)
    }
}

impl From<JournalError> for HostError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<serde_json::Error> for HostError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::num::NonZeroUsize;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Duration;

    use gooir_author_data_model_contract::{AuthoredSpec, authored_entity_spec_value_kind};
    use gooir_capability::Fact;
    use gooir_capability::authority::{
        AdmissionAuthorityId, ObservationAuthority, ObservationSourceId, SourceObservation,
    };
    use gooir_capability::protocol::{
        EvidenceDigest, EvidenceKindId, EvidenceRef, ImplementationId,
    };
    use gooir_datamodel_package_proof::{ProofReport, StageRequest, stage};
    use gooir_wasip1_command_runtime::WasmTermination;

    use super::*;
    use crate::journal::RecoveryAction;

    const CHILD_ENV: &str = "GOOIR_EXTERNAL_HOST_CRASH_CHILD";
    const PROVIDER_ENV: &str = "GOOIR_EXTERNAL_HOST_PROVIDER_WASM";
    const ATTESTER_ENV: &str = "GOOIR_EXTERNAL_HOST_ATTESTER_WASM";
    const PACKAGE_ENV: &str = "GOOIR_EXTERNAL_HOST_PACKAGE_ROOT";
    const JOURNAL_ENV: &str = "GOOIR_EXTERNAL_HOST_JOURNAL";
    const PHASE_ENV: &str = "GOOIR_EXTERNAL_HOST_EXIT_PHASE";

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn planning_limits() -> PlanLimits {
        PlanLimits {
            max_capabilities: NonZeroUsize::new(16).unwrap(),
            max_value_kinds: NonZeroUsize::new(32).unwrap(),
            max_ports_per_capability: NonZeroUsize::new(8).unwrap(),
            max_total_ports: NonZeroUsize::new(64).unwrap(),
            max_offers_per_capability: NonZeroUsize::new(8).unwrap(),
            max_total_offers: NonZeroUsize::new(32).unwrap(),
        }
    }

    fn wasm_limits() -> WasmLimits {
        WasmLimits {
            timeout: Duration::from_secs(30),
            fuel: 2_000_000_000,
            memory_bytes: 512 * 1024 * 1024,
            table_elements: 100_000,
            stdout_bytes: 256 * 1024,
            stderr_bytes: 256 * 1024,
        }
    }

    fn baseline_for(fact: Fact) -> (AdmissionSnapshot, AdmittedFactRef) {
        let evidence_kind =
            EvidenceKindId::new("org.gooi.evidence", "embedded_fixture_source", "1.0.0");
        let authority = ObservationAuthority::new(
            ObservationSourceId::new("org.gooi.source", "tasks_entities_fixture", "1.0.0"),
            ImplementationId::new("org.gooi.observer", "embedded_fixture", "1.0.0"),
            ArtifactDigest::parse(digest('1')).unwrap(),
            fact.value_kind.clone(),
            evidence_kind.clone(),
            BTreeMap::new(),
        )
        .unwrap();
        let observation = SourceObservation::new(
            fact,
            authority.clone(),
            EvidenceRef::new(
                evidence_kind,
                EvidenceDigest::parse(digest('2')).unwrap(),
                "crate:gooir-datamodel-conformance/tasks_entities_source_fact",
                BTreeMap::new(),
            )
            .unwrap(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let policy = AdmissionPolicy::new(
            AdmissionAuthorityId::new("org.gooi.admission", "fixture_source", "1.0.0"),
            Vec::new(),
            vec![authority],
            BTreeMap::new(),
        )
        .unwrap();
        let mut ledger = AdmissionLedger::new();
        let AdmissionOutcome::Admitted { links, .. } =
            ledger.admit_observation(&policy, &observation).unwrap()
        else {
            panic!("exact fixture observation must be admitted")
        };
        let source = links[0].reference.clone();
        (ledger.export().unwrap(), source)
    }

    fn fixture_baseline() -> (AdmissionSnapshot, AdmittedFactRef) {
        baseline_for(gooir_datamodel_conformance::tasks_entities_source_fact().unwrap())
    }

    fn expected_authority(report: &ProofReport) -> ConformanceAuthority {
        ConformanceAuthority::new(
            gooir_datamodel_conformance::suite_id(),
            ConformanceAttester::new(
                gooir_datamodel_conformance::implementation_id(),
                ArtifactDigest::parse(report.attester.resource_digest.to_string()).unwrap(),
                BTreeMap::new(),
            )
            .unwrap(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn request(package_root: &Path, journal_directory: PathBuf) -> HostRequest {
        let (baseline_snapshot, source) = fixture_baseline();
        request_with_baseline(package_root, journal_directory, baseline_snapshot, source)
    }

    fn request_for_fact(
        package_root: &Path,
        journal_directory: PathBuf,
        fact: Fact,
    ) -> HostRequest {
        let (baseline_snapshot, source) = baseline_for(fact);
        request_with_baseline(package_root, journal_directory, baseline_snapshot, source)
    }

    fn request_with_baseline(
        package_root: &Path,
        journal_directory: PathBuf,
        baseline_snapshot: AdmissionSnapshot,
        source: AdmittedFactRef,
    ) -> HostRequest {
        let report = gooir_datamodel_package_proof::verify(package_root).unwrap();
        let admission_policy = AdmissionPolicy::new(
            AdmissionAuthorityId::new("org.gooi.admission", "external_host_proof", "1.0.0"),
            vec![expected_authority(&report)],
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        HostRequest {
            package_root: package_root.to_path_buf(),
            journal_directory,
            baseline_snapshot,
            source,
            planning_limits: planning_limits(),
            execution_limits: AttemptExecutionLimits {
                provider: wasm_limits(),
                attester: wasm_limits(),
            },
            admission_policy,
        }
    }

    fn authored_fact(origin: &str, text: &str) -> Fact {
        Fact::new(
            authored_entity_spec_value_kind(),
            serde_json::to_value(AuthoredSpec {
                origin: origin.to_owned(),
                text: text.to_owned(),
            })
            .unwrap(),
        )
        .unwrap()
    }

    fn real_module_path(environment: &str, file: &str) -> PathBuf {
        std::env::var_os(environment).map_or_else(
            || {
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../target/wasm32-wasip1/release")
                    .join(file)
            },
            PathBuf::from,
        )
    }

    fn stage_modules(provider: &Path, attester: &Path, output: &Path) -> ProofReport {
        stage(StageRequest {
            provider_module: provider.to_path_buf(),
            attester_module: attester.to_path_buf(),
            output_root: output.to_path_buf(),
        })
        .unwrap()
    }

    fn write_module(path: &Path, wat: &str) {
        fs::write(path, wat::parse_str(wat).unwrap()).unwrap();
    }

    fn parse_phase(value: &str) -> AttemptPhase {
        match value {
            "prepared" => AttemptPhase::Prepared,
            "provider_armed" => AttemptPhase::ProviderArmed,
            "provider_captured" => AttemptPhase::ProviderCaptured,
            "candidate_ready" => AttemptPhase::CandidateReady,
            "attester_armed" => AttemptPhase::AttesterArmed,
            "attester_captured" => AttemptPhase::AttesterCaptured,
            "assessment_ready" => AttemptPhase::AssessmentReady,
            "admitted" => AttemptPhase::Admitted,
            other => panic!("unsupported test phase {other}"),
        }
    }

    fn phase_name(phase: AttemptPhase) -> &'static str {
        match phase {
            AttemptPhase::Prepared => "prepared",
            AttemptPhase::ProviderArmed => "provider_armed",
            AttemptPhase::ProviderCaptured => "provider_captured",
            AttemptPhase::CandidateReady => "candidate_ready",
            AttemptPhase::AttesterArmed => "attester_armed",
            AttemptPhase::AttesterCaptured => "attester_captured",
            AttemptPhase::AssessmentReady => "assessment_ready",
            AttemptPhase::Admitted => "admitted",
            AttemptPhase::Withheld | AttemptPhase::Unable => {
                panic!("phase is not part of the passing crash matrix")
            }
        }
    }

    #[test]
    fn invalid_provider_output_becomes_durable_unable_and_replays() {
        let temporary = tempfile::tempdir().unwrap();
        let provider = temporary.path().join("provider.wasm");
        let attester = temporary.path().join("attester.wasm");
        let packages = temporary.path().join("packages");
        write_module(&provider, "(module (func (export \"_start\")))");
        write_module(&attester, "(module (memory 1) (func (export \"_start\")))");
        stage_modules(&provider, &attester, &packages);
        let request = request(&packages, temporary.path().join("attempt"));

        let completed = start(&request).unwrap();
        assert_eq!(completed.phase(), AttemptPhase::Unable);
        assert!(matches!(
            completed.resolution(),
            Some(AttemptResolution::Unable {
                from: AttemptPhase::ProviderCaptured,
                ..
            })
        ));
        assert_eq!(resume(&request).unwrap(), completed);

        let mut changed = request.clone();
        changed.execution_limits.provider.fuel -= 1;
        assert!(matches!(
            resume(&changed),
            Err(HostError::AttemptInputsMismatch { .. })
        ));
    }

    #[test]
    fn successful_termination_with_stderr_is_not_clean_success() {
        let receipt = WasmReceipt {
            runtime: RUNTIME_ID.to_owned(),
            execution_policy: wasm_limits().execution_policy().unwrap(),
            module_digest: digest('3'),
            stdin_digest: digest('4'),
            termination: WasmTermination::Returned,
            stdin_bytes_provided: 0,
            stdout: b"{}".to_vec(),
            stderr: b"unexpected diagnostic".to_vec(),
        };
        assert!(require_clean_success(&receipt).is_err());
    }

    #[test]
    fn preparation_failure_must_reproduce_for_the_exact_request() {
        let request = WasmRequest {
            module: wat::parse_str("(module (func (export \"_start\")))").unwrap(),
            stdin: Vec::new(),
            limits: wasm_limits(),
        };
        let failure = HostFailure::new(
            FailureStage::ProviderPreparation,
            FailureReason::PreparationRefused,
            None,
            Some("forged preparation failure".to_owned()),
        );

        assert!(matches!(
            validate_preparation_failure(&request, &failure),
            Err(HostError::Invariant(message))
                if message.contains("no longer reproduces")
        ));
    }

    #[test]
    fn real_crash_child() {
        if std::env::var_os(CHILD_ENV).is_none() {
            return;
        }
        let package_root = PathBuf::from(std::env::var_os(PACKAGE_ENV).unwrap());
        let journal = PathBuf::from(std::env::var_os(JOURNAL_ENV).unwrap());
        let phase = parse_phase(&std::env::var(PHASE_ENV).unwrap());
        let request = request(&package_root, journal);
        start_exiting_after(&request, phase).unwrap();
        panic!("child did not exit at the requested durable phase");
    }

    #[test]
    #[ignore = "requires the documented release wasm32-wasip1 guest build"]
    fn real_modules_prove_outcomes_and_passing_path_crash_recovery() {
        let provider = real_module_path(PROVIDER_ENV, "author_data_model_provider.wasm");
        let attester = real_module_path(ATTESTER_ENV, "gooir-datamodel-conformance.wasm");
        let temporary = tempfile::tempdir().unwrap();
        let packages = temporary.path().join("packages");
        stage_modules(&provider, &attester, &packages);

        let direct_request = request(&packages, temporary.path().join("direct-attempt"));
        let completed = start(&direct_request).unwrap();
        assert_eq!(completed.phase(), AttemptPhase::Admitted);
        assert_eq!(resume(&direct_request).unwrap(), completed);

        let unable_request = request_for_fact(
            &packages,
            temporary.path().join("semantic-unable"),
            authored_fact("test:unparsable", "field_before_entity text"),
        );
        let unable = start(&unable_request).unwrap();
        assert_eq!(unable.phase(), AttemptPhase::Unable);
        assert!(matches!(
            unable.resolution(),
            Some(AttemptResolution::Unable {
                from: AttemptPhase::ProviderCaptured,
                ..
            })
        ));
        assert_eq!(resume(&unable_request).unwrap(), unable);

        let withheld_request = request_for_fact(
            &packages,
            temporary.path().join("conformance-withheld"),
            authored_fact(
                "test:different-valid-source",
                "entity Different\n  id uuid pk = uuid\n",
            ),
        );
        let withheld = start(&withheld_request).unwrap();
        assert_eq!(withheld.phase(), AttemptPhase::Withheld);
        assert!(matches!(
            withheld.resolution(),
            Some(AttemptResolution::Withheld { .. })
        ));
        assert_eq!(resume(&withheld_request).unwrap(), withheld);

        for phase in [
            AttemptPhase::Prepared,
            AttemptPhase::ProviderArmed,
            AttemptPhase::ProviderCaptured,
            AttemptPhase::CandidateReady,
            AttemptPhase::AttesterArmed,
            AttemptPhase::AttesterCaptured,
            AttemptPhase::AssessmentReady,
            AttemptPhase::Admitted,
        ] {
            let journal = temporary
                .path()
                .join(format!("crash-{}", phase_name(phase)));
            let status = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("driver::tests::real_crash_child")
                .arg("--nocapture")
                .env(CHILD_ENV, "1")
                .env(PACKAGE_ENV, &packages)
                .env(JOURNAL_ENV, &journal)
                .env(PHASE_ENV, phase_name(phase))
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(86), "child phase {phase:?}");

            let request = request(&packages, journal);
            let recovered = resume(&request).unwrap();
            if matches!(phase, AttemptPhase::ProviderArmed) {
                assert_eq!(recovered.phase(), AttemptPhase::ProviderArmed);
                assert_eq!(
                    recovered.recovery_action(),
                    RecoveryAction::ParkProviderUncertain
                );
            } else if matches!(phase, AttemptPhase::AttesterArmed) {
                assert_eq!(recovered.phase(), AttemptPhase::AttesterArmed);
                assert_eq!(
                    recovered.recovery_action(),
                    RecoveryAction::ParkAttesterUncertain
                );
            } else {
                assert_eq!(recovered.phase(), AttemptPhase::Admitted, "{phase:?}");
            }
        }
    }
}
