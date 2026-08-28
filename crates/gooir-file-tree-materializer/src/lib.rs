//! Host-side materialization boundary for an admitted virtual file tree.
//!
//! This crate is not a semantic capability and is not used by the compiler
//! kernel. It converts one exact ledger-resolved, admitted `FileTree` fact into
//! an authority-bound host value that a concrete materializer may consume.

#![forbid(unsafe_code)]

mod local;

use std::error::Error;
use std::fmt;
use std::path::Path;
use std::{collections::BTreeMap, collections::BTreeSet};

use gooir_capability::authority::{
    AdmissionDecision, AdmissionLedger, AdmissionPolicy, AdmissionSubject, AdmissionVerdict,
    AuthorityBasis, AuthorityRecord, ConformanceAssessment, ConformanceAuthority,
    ObservationAuthority, ResolvedFact, SourceObservation,
};
use gooir_capability::protocol::{
    AdmittedFactRef, AuthorityRecordId, CapabilityCandidate, CapabilityInvocation,
    CapabilityOutcome, CapabilityResult, EvidenceRef,
};
use gooir_capability::{CapabilitySpec, Fact, FactId};
use gooir_file_tree_v1::{FileTree, FileTreeError, file_tree_value_kind};
use serde::Deserialize as _;

pub use local::{
    ConflictPolicy, Durability, LocalFileTreeMaterializer, LocalMaterializationError,
    LocalMaterializationLimits, LocalMaterializationPolicy, LocalMaterializationReceipt,
    MaterializedFile,
};

/// Exact authority-document location of one preserved extension.
///
/// A host may understand the same extension key at one scope and reject it at
/// another. `FileTree` fact, tree, and file extensions are deliberately outside
/// this enum and remain unconditionally rejected by this materializer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthorityExtensionScope {
    AdmittedFactReference,
    AuthorityRecord,
    SourceAuthorityBasis,
    DerivedAuthorityBasis,
    SourceObservation,
    ObservationAuthority,
    EvidenceReference,
    AdmissionPolicy,
    ConformanceAuthority,
    ConformanceAttester,
    AdmissionDecision,
    ObservationAdmissionSubject,
    CandidateAdmissionSubject,
    AdmissionDecisionOutput,
    AdmitVerdict,
    WithholdVerdict,
    CapabilityInvocation,
    CapabilitySpecification,
    ImplementationSelection,
    CapabilityOffer,
    LinkedInput,
    LinkedInputAdmittedReference,
    CapabilityInputPort,
    CapabilityOutputPort,
    CapabilityCandidate,
    CapabilityResult,
    ProducedOutcome,
    UnableOutcome,
    CapabilityFailure,
    NamedOutput,
    ConformanceAssessment,
    ConformanceCheck,
}

impl AuthorityExtensionScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdmittedFactReference => "admitted fact reference",
            Self::AuthorityRecord => "authority record",
            Self::SourceAuthorityBasis => "source authority basis",
            Self::DerivedAuthorityBasis => "derived authority basis",
            Self::SourceObservation => "source observation",
            Self::ObservationAuthority => "observation authority",
            Self::EvidenceReference => "evidence reference",
            Self::AdmissionPolicy => "admission policy",
            Self::ConformanceAuthority => "conformance authority",
            Self::ConformanceAttester => "conformance attester",
            Self::AdmissionDecision => "admission decision",
            Self::ObservationAdmissionSubject => "observation admission subject",
            Self::CandidateAdmissionSubject => "candidate admission subject",
            Self::AdmissionDecisionOutput => "admission decision output",
            Self::AdmitVerdict => "admit verdict",
            Self::WithholdVerdict => "withhold verdict",
            Self::CapabilityInvocation => "capability invocation",
            Self::CapabilitySpecification => "capability specification",
            Self::ImplementationSelection => "implementation selection",
            Self::CapabilityOffer => "capability offer",
            Self::LinkedInput => "linked input",
            Self::LinkedInputAdmittedReference => "linked input admitted reference",
            Self::CapabilityInputPort => "capability input port",
            Self::CapabilityOutputPort => "capability output port",
            Self::CapabilityCandidate => "capability candidate",
            Self::CapabilityResult => "capability result",
            Self::ProducedOutcome => "produced outcome",
            Self::UnableOutcome => "unable outcome",
            Self::CapabilityFailure => "capability failure",
            Self::NamedOutput => "named output",
            Self::ConformanceAssessment => "conformance assessment",
            Self::ConformanceCheck => "conformance check",
        }
    }
}

impl fmt::Display for AuthorityExtensionScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One exact extension offered to a host-supplied semantic validator.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AuthorityExtension<'value> {
    pub scope: AuthorityExtensionScope,
    pub key: &'value str,
    pub value: &'value serde_json::Value,
}

/// Conservative outcome from a host's authority-extension validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityExtensionError {
    Unhandled,
    Invalid(String),
}

/// Explicit host understanding of authority-chain extension semantics.
///
/// Returning `Ok(())` asserts that the exact scope, key, and value were
/// understood and validated. The materializer still validates the enclosing
/// content identities and complete reachable authority chain. Implementations
/// must be deterministic and effect-free; they inspect already ledger-resolved
/// authority data and do not grant filesystem authority themselves.
pub trait AuthorityExtensionValidator {
    /// Validates one exact preserved authority extension.
    ///
    /// # Errors
    ///
    /// Returns `Unhandled` when the validator does not implement these
    /// semantics or `Invalid` when it understands but refuses the exact value.
    fn validate(
        &mut self,
        extension: AuthorityExtension<'_>,
    ) -> Result<(), AuthorityExtensionError>;
}

/// Default-deny validator used by [`AdmittedFileTree::resolve`].
#[derive(Clone, Copy, Debug, Default)]
pub struct RejectAllAuthorityExtensions;

impl AuthorityExtensionValidator for RejectAllAuthorityExtensions {
    fn validate(
        &mut self,
        _extension: AuthorityExtension<'_>,
    ) -> Result<(), AuthorityExtensionError> {
        Err(AuthorityExtensionError::Unhandled)
    }
}

/// A validated `FileTree` paired with the exact admitted authority selected by
/// an [`gooir_capability::authority::AdmissionLedger`].
///
/// Construction requires an [`AdmissionLedger`] and exact [`AdmittedFactRef`]
/// so ledger membership and selection are checked inside this crate. A bare
/// fact, provider candidate, authority record, or publicly assembled
/// [`ResolvedFact`] is not sufficient input.
#[derive(Clone, Debug, PartialEq)]
pub struct AdmittedFileTree {
    authority_record_id: AuthorityRecordId,
    fact_id: FactId,
    tree: FileTree,
}

impl AdmittedFileTree {
    /// Resolves one exact admitted reference through the supplied host ledger
    /// and revalidates every semantic value consumed by materialization.
    ///
    /// The caller owns the policy for selecting and authenticating the ledger.
    /// This function ensures the selected reference is actually present in that
    /// ledger and rejects all extension semantics this materializer does not
    /// implement.
    ///
    /// # Errors
    ///
    /// Returns an error when ledger resolution, authority validation, extension
    /// handling, value-kind matching, or `FileTree` validation fails.
    pub fn resolve(
        ledger: &AdmissionLedger,
        reference: &AdmittedFactRef,
    ) -> Result<Self, AdmittedFileTreeError> {
        Self::resolve_with_authority_extensions(
            ledger,
            reference,
            &mut RejectAllAuthorityExtensions,
        )
    }

    /// Resolves and validates a `FileTree` while delegating only preserved
    /// authority-extension meaning to an explicit host validator.
    ///
    /// `FileTree` fact, tree, and file extensions are never delegated and remain
    /// rejected. Returning `Ok(())` from the validator is an authority claim by
    /// the caller; the validator must check the exact scope, key, and value.
    ///
    /// # Errors
    ///
    /// Returns an error for ledger, authority, value, or extension failure.
    pub fn resolve_with_authority_extensions(
        ledger: &AdmissionLedger,
        reference: &AdmittedFactRef,
        validator: &mut dyn AuthorityExtensionValidator,
    ) -> Result<Self, AdmittedFileTreeError> {
        let resolved = ledger
            .resolve(reference)
            .map_err(|error| AdmittedFileTreeError::Resolution(error.to_string()))?;
        validate_authority_extensions(
            AuthorityExtensionScope::AdmittedFactReference,
            &reference.extensions,
            validator,
        )?;
        Self::from_resolved(ledger, resolved, validator)
    }

    /// Returns the exact authority selected for materialization.
    #[must_use]
    pub fn authority_record_id(&self) -> &AuthorityRecordId {
        &self.authority_record_id
    }

    /// Returns the exact admitted `FileTree` fact identity.
    #[must_use]
    pub fn fact_id(&self) -> &FactId {
        &self.fact_id
    }

    /// Returns the revalidated virtual file tree.
    #[must_use]
    pub fn tree(&self) -> &FileTree {
        &self.tree
    }

    fn from_resolved(
        ledger: &AdmissionLedger,
        resolved: ResolvedFact<'_>,
        validator: &mut dyn AuthorityExtensionValidator,
    ) -> Result<Self, AdmittedFileTreeError> {
        if &resolved.authority.fact != resolved.fact {
            return Err(AdmittedFileTreeError::FactAuthorityMismatch);
        }
        let expected = file_tree_value_kind();
        if resolved.fact.value_kind != expected {
            return Err(AdmittedFileTreeError::WrongValueKind {
                expected: expected.to_string(),
                actual: resolved.fact.value_kind.to_string(),
            });
        }
        if let Some(key) = resolved.fact.extensions.keys().next() {
            return Err(AdmittedFileTreeError::UnhandledFactExtension(key.clone()));
        }
        reject_authority_extensions(ledger, resolved.authority, &mut BTreeSet::new(), validator)?;

        reject_unhandled_raw_extensions(&resolved.fact.payload)?;
        let tree = FileTree::deserialize(&resolved.fact.payload)
            .map_err(|error| AdmittedFileTreeError::InvalidPayload(error.to_string()))?;
        tree.validate()
            .map_err(AdmittedFileTreeError::InvalidTree)?;
        if let Some(key) = tree.extensions.keys().next() {
            return Err(AdmittedFileTreeError::UnhandledTreeExtension(key.clone()));
        }
        for file in &tree.files {
            if let Some(key) = file.extensions.keys().next() {
                return Err(AdmittedFileTreeError::UnhandledFileExtension {
                    path: file.path.clone(),
                    key: key.clone(),
                });
            }
        }

        Ok(Self {
            authority_record_id: resolved.authority.authority_record_id.clone(),
            fact_id: resolved.fact.id.clone(),
            tree,
        })
    }
}

fn reject_authority_extensions(
    ledger: &AdmissionLedger,
    record: &AuthorityRecord,
    visited: &mut BTreeSet<AuthorityRecordId>,
    validator: &mut dyn AuthorityExtensionValidator,
) -> Result<(), AdmittedFileTreeError> {
    record
        .validate()
        .map_err(|error| AdmittedFileTreeError::InvalidAuthority(error.to_string()))?;
    if !visited.insert(record.authority_record_id.clone()) {
        return Ok(());
    }
    validate_authority_extensions(
        AuthorityExtensionScope::AuthorityRecord,
        &record.extensions,
        validator,
    )?;
    reject_fact_extensions("authority-record fact", &record.fact)?;
    match &record.basis {
        AuthorityBasis::Source {
            observation,
            policy,
            decision,
            extensions,
        } => {
            validate_authority_extensions(
                AuthorityExtensionScope::SourceAuthorityBasis,
                extensions,
                validator,
            )?;
            reject_observation_extensions(observation, validator)?;
            reject_policy_extensions(policy, validator)?;
            reject_decision_extensions(decision, validator)
        }
        AuthorityBasis::Derived {
            invocation,
            result,
            candidate,
            assessment,
            policy,
            decision,
            extensions,
            ..
        } => {
            validate_authority_extensions(
                AuthorityExtensionScope::DerivedAuthorityBasis,
                extensions,
                validator,
            )?;
            reject_invocation_extensions(invocation, validator)?;
            reject_result_extensions(result, validator)?;
            reject_candidate_extensions(candidate, validator)?;
            reject_assessment_extensions(assessment, validator)?;
            reject_policy_extensions(policy, validator)?;
            reject_decision_extensions(decision, validator)?;
            for input in &invocation.inputs {
                let resolved = ledger.resolve(&input.admitted).map_err(|error| {
                    AdmittedFileTreeError::Resolution(format!(
                        "linked input `{}`: {error}",
                        input.port
                    ))
                })?;
                if resolved.fact != &input.fact {
                    return Err(AdmittedFileTreeError::FactAuthorityMismatch);
                }
                reject_authority_extensions(ledger, resolved.authority, visited, validator)?;
            }
            Ok(())
        }
    }
}

fn reject_observation_extensions(
    observation: &SourceObservation,
    validator: &mut dyn AuthorityExtensionValidator,
) -> Result<(), AdmittedFileTreeError> {
    validate_authority_extensions(
        AuthorityExtensionScope::SourceObservation,
        &observation.extensions,
        validator,
    )?;
    reject_fact_extensions("source-observation fact", &observation.fact)?;
    reject_observation_authority_extensions(&observation.authority, validator)?;
    reject_evidence_extensions(&observation.primary_evidence, validator)?;
    for evidence in &observation.additional_evidence {
        reject_evidence_extensions(evidence, validator)?;
    }
    Ok(())
}

fn reject_policy_extensions(
    policy: &AdmissionPolicy,
    validator: &mut dyn AuthorityExtensionValidator,
) -> Result<(), AdmittedFileTreeError> {
    validate_authority_extensions(
        AuthorityExtensionScope::AdmissionPolicy,
        &policy.extensions,
        validator,
    )?;
    for authority in &policy.accepted_conformance {
        reject_conformance_authority_extensions(authority, validator)?;
    }
    for authority in &policy.accepted_observations {
        reject_observation_authority_extensions(authority, validator)?;
    }
    Ok(())
}

fn reject_decision_extensions(
    decision: &AdmissionDecision,
    validator: &mut dyn AuthorityExtensionValidator,
) -> Result<(), AdmittedFileTreeError> {
    validate_authority_extensions(
        AuthorityExtensionScope::AdmissionDecision,
        &decision.extensions,
        validator,
    )?;
    match &decision.subject {
        AdmissionSubject::Observation { extensions, .. } => {
            validate_authority_extensions(
                AuthorityExtensionScope::ObservationAdmissionSubject,
                extensions,
                validator,
            )?;
        }
        AdmissionSubject::Candidate {
            outputs,
            extensions,
            ..
        } => {
            validate_authority_extensions(
                AuthorityExtensionScope::CandidateAdmissionSubject,
                extensions,
                validator,
            )?;
            for output in outputs {
                validate_authority_extensions(
                    AuthorityExtensionScope::AdmissionDecisionOutput,
                    &output.extensions,
                    validator,
                )?;
            }
        }
    }
    match &decision.verdict {
        AdmissionVerdict::Admit { extensions } => validate_authority_extensions(
            AuthorityExtensionScope::AdmitVerdict,
            extensions,
            validator,
        ),
        AdmissionVerdict::Withhold { extensions, .. } => validate_authority_extensions(
            AuthorityExtensionScope::WithholdVerdict,
            extensions,
            validator,
        ),
    }
}

fn reject_invocation_extensions(
    invocation: &CapabilityInvocation,
    validator: &mut dyn AuthorityExtensionValidator,
) -> Result<(), AdmittedFileTreeError> {
    validate_authority_extensions(
        AuthorityExtensionScope::CapabilityInvocation,
        &invocation.extensions,
        validator,
    )?;
    reject_spec_extensions(&invocation.specification, validator)?;
    validate_authority_extensions(
        AuthorityExtensionScope::ImplementationSelection,
        &invocation.selection.extensions,
        validator,
    )?;
    validate_authority_extensions(
        AuthorityExtensionScope::CapabilityOffer,
        &invocation.selection.offer.extensions,
        validator,
    )?;
    for input in &invocation.inputs {
        validate_authority_extensions(
            AuthorityExtensionScope::LinkedInput,
            &input.extensions,
            validator,
        )?;
        validate_authority_extensions(
            AuthorityExtensionScope::LinkedInputAdmittedReference,
            &input.admitted.extensions,
            validator,
        )?;
        reject_fact_extensions("linked input fact", &input.fact)?;
    }
    Ok(())
}

fn reject_spec_extensions(
    specification: &CapabilitySpec,
    validator: &mut dyn AuthorityExtensionValidator,
) -> Result<(), AdmittedFileTreeError> {
    validate_authority_extensions(
        AuthorityExtensionScope::CapabilitySpecification,
        &specification.extensions,
        validator,
    )?;
    for input in &specification.input_ports {
        validate_authority_extensions(
            AuthorityExtensionScope::CapabilityInputPort,
            &input.extensions,
            validator,
        )?;
    }
    for output in &specification.output_ports {
        validate_authority_extensions(
            AuthorityExtensionScope::CapabilityOutputPort,
            &output.extensions,
            validator,
        )?;
    }
    Ok(())
}

fn reject_candidate_extensions(
    candidate: &CapabilityCandidate,
    validator: &mut dyn AuthorityExtensionValidator,
) -> Result<(), AdmittedFileTreeError> {
    validate_authority_extensions(
        AuthorityExtensionScope::CapabilityCandidate,
        &candidate.extensions,
        validator,
    )?;
    reject_result_extensions(&candidate.result, validator)
}

fn reject_result_extensions(
    result: &CapabilityResult,
    validator: &mut dyn AuthorityExtensionValidator,
) -> Result<(), AdmittedFileTreeError> {
    validate_authority_extensions(
        AuthorityExtensionScope::CapabilityResult,
        &result.extensions,
        validator,
    )?;
    for evidence in &result.evidence {
        reject_evidence_extensions(evidence, validator)?;
    }
    match &result.outcome {
        CapabilityOutcome::Produced {
            outputs,
            extensions,
        } => {
            validate_authority_extensions(
                AuthorityExtensionScope::ProducedOutcome,
                extensions,
                validator,
            )?;
            for output in outputs {
                validate_authority_extensions(
                    AuthorityExtensionScope::NamedOutput,
                    &output.extensions,
                    validator,
                )?;
                reject_fact_extensions("named output fact", &output.fact)?;
            }
            Ok(())
        }
        CapabilityOutcome::Unable {
            failure,
            extensions,
        } => {
            validate_authority_extensions(
                AuthorityExtensionScope::UnableOutcome,
                extensions,
                validator,
            )?;
            validate_authority_extensions(
                AuthorityExtensionScope::CapabilityFailure,
                &failure.extensions,
                validator,
            )
        }
    }
}

fn reject_assessment_extensions(
    assessment: &ConformanceAssessment,
    validator: &mut dyn AuthorityExtensionValidator,
) -> Result<(), AdmittedFileTreeError> {
    validate_authority_extensions(
        AuthorityExtensionScope::ConformanceAssessment,
        &assessment.extensions,
        validator,
    )?;
    reject_conformance_authority_extensions(&assessment.authority, validator)?;
    for check in assessment.checks.values() {
        validate_authority_extensions(
            AuthorityExtensionScope::ConformanceCheck,
            &check.extensions,
            validator,
        )?;
        for evidence in &check.evidence {
            reject_evidence_extensions(evidence, validator)?;
        }
    }
    for evidence in &assessment.evidence {
        reject_evidence_extensions(evidence, validator)?;
    }
    Ok(())
}

fn reject_conformance_authority_extensions(
    authority: &ConformanceAuthority,
    validator: &mut dyn AuthorityExtensionValidator,
) -> Result<(), AdmittedFileTreeError> {
    validate_authority_extensions(
        AuthorityExtensionScope::ConformanceAuthority,
        &authority.extensions,
        validator,
    )?;
    validate_authority_extensions(
        AuthorityExtensionScope::ConformanceAttester,
        &authority.attester.extensions,
        validator,
    )
}

fn reject_observation_authority_extensions(
    authority: &ObservationAuthority,
    validator: &mut dyn AuthorityExtensionValidator,
) -> Result<(), AdmittedFileTreeError> {
    validate_authority_extensions(
        AuthorityExtensionScope::ObservationAuthority,
        &authority.extensions,
        validator,
    )
}

fn reject_evidence_extensions(
    evidence: &EvidenceRef,
    validator: &mut dyn AuthorityExtensionValidator,
) -> Result<(), AdmittedFileTreeError> {
    validate_authority_extensions(
        AuthorityExtensionScope::EvidenceReference,
        &evidence.extensions,
        validator,
    )
}

fn reject_fact_extensions(scope: &'static str, fact: &Fact) -> Result<(), AdmittedFileTreeError> {
    if let Some(key) = fact.extensions.keys().next() {
        Err(AdmittedFileTreeError::UnhandledAuthorityExtension {
            scope,
            key: key.clone(),
        })
    } else {
        Ok(())
    }
}

fn validate_authority_extensions(
    scope: AuthorityExtensionScope,
    extensions: &BTreeMap<String, serde_json::Value>,
    validator: &mut dyn AuthorityExtensionValidator,
) -> Result<(), AdmittedFileTreeError> {
    for (key, value) in extensions {
        match validator.validate(AuthorityExtension { scope, key, value }) {
            Ok(()) => {}
            Err(AuthorityExtensionError::Unhandled) => {
                return Err(AdmittedFileTreeError::UnhandledAuthorityExtension {
                    scope: scope.as_str(),
                    key: key.clone(),
                });
            }
            Err(AuthorityExtensionError::Invalid(detail)) => {
                return Err(AdmittedFileTreeError::InvalidAuthorityExtension {
                    scope: scope.as_str(),
                    key: key.clone(),
                    detail,
                });
            }
        }
    }
    Ok(())
}

fn reject_unhandled_raw_extensions(
    payload: &serde_json::Value,
) -> Result<(), AdmittedFileTreeError> {
    let Some(root) = payload.as_object() else {
        return Ok(());
    };
    if let Some(key) = root.keys().find(|key| key.as_str() != "files") {
        return Err(AdmittedFileTreeError::UnhandledTreeExtension(key.clone()));
    }
    let Some(files) = root.get("files").and_then(serde_json::Value::as_array) else {
        return Ok(());
    };
    for file in files {
        let Some(file) = file.as_object() else {
            continue;
        };
        if let Some(key) = file.keys().find(|key| {
            !matches!(
                key.as_str(),
                "path" | "media_type" | "content_digest" | "content"
            )
        }) {
            let path = file
                .get("path")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<unknown>")
                .to_owned();
            return Err(AdmittedFileTreeError::UnhandledFileExtension {
                path,
                key: key.clone(),
            });
        }
    }
    Ok(())
}

/// Failure to turn an exact ledger resolution into a plain materializable
/// `FileTree`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmittedFileTreeError {
    Resolution(String),
    InvalidAuthority(String),
    FactAuthorityMismatch,
    WrongValueKind {
        expected: String,
        actual: String,
    },
    UnhandledFactExtension(String),
    InvalidPayload(String),
    InvalidTree(FileTreeError),
    UnhandledTreeExtension(String),
    UnhandledFileExtension {
        path: String,
        key: String,
    },
    UnhandledAuthorityExtension {
        scope: &'static str,
        key: String,
    },
    InvalidAuthorityExtension {
        scope: &'static str,
        key: String,
        detail: String,
    },
}

impl fmt::Display for AdmittedFileTreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolution(detail) => {
                write!(
                    formatter,
                    "file-tree admission reference did not resolve: {detail}"
                )
            }
            Self::InvalidAuthority(detail) => {
                write!(formatter, "file-tree authority is invalid: {detail}")
            }
            Self::FactAuthorityMismatch => formatter.write_str(
                "resolved file-tree fact does not equal the fact bound by its authority",
            ),
            Self::WrongValueKind { expected, actual } => write!(
                formatter,
                "materializer expected value kind `{expected}` but received `{actual}`"
            ),
            Self::UnhandledFactExtension(key) => write!(
                formatter,
                "file-tree fact has unhandled semantic extension `{}`",
                key.escape_debug()
            ),
            Self::InvalidPayload(detail) => {
                write!(formatter, "file-tree payload cannot be decoded: {detail}")
            }
            Self::InvalidTree(error) => write!(formatter, "file-tree payload is invalid: {error}"),
            Self::UnhandledTreeExtension(key) => write!(
                formatter,
                "file tree has unhandled semantic extension `{}`",
                key.escape_debug()
            ),
            Self::UnhandledFileExtension { path, key } => write!(
                formatter,
                "file `{}` has unhandled semantic extension `{}`",
                path.escape_debug(),
                key.escape_debug()
            ),
            Self::UnhandledAuthorityExtension { scope, key } => write!(
                formatter,
                "{scope} has unhandled semantic extension `{}`",
                key.escape_debug()
            ),
            Self::InvalidAuthorityExtension { scope, key, detail } => write!(
                formatter,
                "{scope} has invalid semantic extension `{}`: {detail}",
                key.escape_debug()
            ),
        }
    }
}

impl Error for AdmittedFileTreeError {}

/// Host protocol for publishing an exact admitted virtual file tree.
///
/// Implementations own destination interpretation, conflict policy, effects,
/// and receipts. This trait is an orchestration seam, not a capability edge.
pub trait FileTreeMaterializer {
    type Destination: ?Sized;
    type Policy;
    type Receipt;
    type Error: Error;

    /// Attempts one host materialization under an explicit policy.
    ///
    /// # Errors
    ///
    /// Returns the implementation's host-side refusal or effect failure.
    fn materialize(
        &mut self,
        artifact: &AdmittedFileTree,
        destination: &Self::Destination,
        policy: &Self::Policy,
    ) -> Result<Self::Receipt, Self::Error>;
}

impl FileTreeMaterializer for LocalFileTreeMaterializer {
    type Destination = Path;
    type Policy = LocalMaterializationPolicy;
    type Receipt = LocalMaterializationReceipt;
    type Error = LocalMaterializationError;

    fn materialize(
        &mut self,
        artifact: &AdmittedFileTree,
        destination: &Path,
        policy: &Self::Policy,
    ) -> Result<Self::Receipt, Self::Error> {
        self.materialize_local(artifact, destination, policy)
    }
}
