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
        reject_extensions("admitted fact reference", &reference.extensions)?;
        let resolved = ledger
            .resolve(reference)
            .map_err(|error| AdmittedFileTreeError::Resolution(error.to_string()))?;
        Self::from_resolved(ledger, resolved)
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
        reject_authority_extensions(ledger, resolved.authority, &mut BTreeSet::new())?;

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
) -> Result<(), AdmittedFileTreeError> {
    record
        .validate()
        .map_err(|error| AdmittedFileTreeError::InvalidAuthority(error.to_string()))?;
    if !visited.insert(record.authority_record_id.clone()) {
        return Ok(());
    }
    reject_extensions("authority record", &record.extensions)?;
    reject_fact_extensions("authority-record fact", &record.fact)?;
    match &record.basis {
        AuthorityBasis::Source {
            observation,
            policy,
            decision,
            extensions,
        } => {
            reject_extensions("source authority basis", extensions)?;
            reject_observation_extensions(observation)?;
            reject_policy_extensions(policy)?;
            reject_decision_extensions(decision)
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
            reject_extensions("derived authority basis", extensions)?;
            reject_invocation_extensions(invocation)?;
            reject_result_extensions(result)?;
            reject_candidate_extensions(candidate)?;
            reject_assessment_extensions(assessment)?;
            reject_policy_extensions(policy)?;
            reject_decision_extensions(decision)?;
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
                reject_authority_extensions(ledger, resolved.authority, visited)?;
            }
            Ok(())
        }
    }
}

fn reject_observation_extensions(
    observation: &SourceObservation,
) -> Result<(), AdmittedFileTreeError> {
    reject_extensions("source observation", &observation.extensions)?;
    reject_fact_extensions("source-observation fact", &observation.fact)?;
    reject_observation_authority_extensions(&observation.authority)?;
    reject_evidence_extensions(&observation.primary_evidence)?;
    for evidence in &observation.additional_evidence {
        reject_evidence_extensions(evidence)?;
    }
    Ok(())
}

fn reject_policy_extensions(policy: &AdmissionPolicy) -> Result<(), AdmittedFileTreeError> {
    reject_extensions("admission policy", &policy.extensions)?;
    for authority in &policy.accepted_conformance {
        reject_conformance_authority_extensions(authority)?;
    }
    for authority in &policy.accepted_observations {
        reject_observation_authority_extensions(authority)?;
    }
    Ok(())
}

fn reject_decision_extensions(decision: &AdmissionDecision) -> Result<(), AdmittedFileTreeError> {
    reject_extensions("admission decision", &decision.extensions)?;
    match &decision.subject {
        AdmissionSubject::Observation { extensions, .. } => {
            reject_extensions("observation admission subject", extensions)?;
        }
        AdmissionSubject::Candidate {
            outputs,
            extensions,
            ..
        } => {
            reject_extensions("candidate admission subject", extensions)?;
            for output in outputs {
                reject_extensions("admission decision output", &output.extensions)?;
            }
        }
    }
    match &decision.verdict {
        AdmissionVerdict::Admit { extensions } => reject_extensions("admit verdict", extensions),
        AdmissionVerdict::Withhold { extensions, .. } => {
            reject_extensions("withhold verdict", extensions)
        }
    }
}

fn reject_invocation_extensions(
    invocation: &CapabilityInvocation,
) -> Result<(), AdmittedFileTreeError> {
    reject_extensions("capability invocation", &invocation.extensions)?;
    reject_spec_extensions(&invocation.specification)?;
    reject_extensions("implementation selection", &invocation.selection.extensions)?;
    reject_extensions("capability offer", &invocation.selection.offer.extensions)?;
    for input in &invocation.inputs {
        reject_extensions("linked input", &input.extensions)?;
        reject_extensions(
            "linked input admitted reference",
            &input.admitted.extensions,
        )?;
        reject_fact_extensions("linked input fact", &input.fact)?;
    }
    Ok(())
}

fn reject_spec_extensions(specification: &CapabilitySpec) -> Result<(), AdmittedFileTreeError> {
    reject_extensions("capability specification", &specification.extensions)?;
    for input in &specification.input_ports {
        reject_extensions("capability input port", &input.extensions)?;
    }
    for output in &specification.output_ports {
        reject_extensions("capability output port", &output.extensions)?;
    }
    Ok(())
}

fn reject_candidate_extensions(
    candidate: &CapabilityCandidate,
) -> Result<(), AdmittedFileTreeError> {
    reject_extensions("capability candidate", &candidate.extensions)?;
    reject_result_extensions(&candidate.result)
}

fn reject_result_extensions(result: &CapabilityResult) -> Result<(), AdmittedFileTreeError> {
    reject_extensions("capability result", &result.extensions)?;
    for evidence in &result.evidence {
        reject_evidence_extensions(evidence)?;
    }
    match &result.outcome {
        CapabilityOutcome::Produced {
            outputs,
            extensions,
        } => {
            reject_extensions("produced outcome", extensions)?;
            for output in outputs {
                reject_extensions("named output", &output.extensions)?;
                reject_fact_extensions("named output fact", &output.fact)?;
            }
            Ok(())
        }
        CapabilityOutcome::Unable {
            failure,
            extensions,
        } => {
            reject_extensions("unable outcome", extensions)?;
            reject_extensions("capability failure", &failure.extensions)
        }
    }
}

fn reject_assessment_extensions(
    assessment: &ConformanceAssessment,
) -> Result<(), AdmittedFileTreeError> {
    reject_extensions("conformance assessment", &assessment.extensions)?;
    reject_conformance_authority_extensions(&assessment.authority)?;
    for check in assessment.checks.values() {
        reject_extensions("conformance check", &check.extensions)?;
        for evidence in &check.evidence {
            reject_evidence_extensions(evidence)?;
        }
    }
    for evidence in &assessment.evidence {
        reject_evidence_extensions(evidence)?;
    }
    Ok(())
}

fn reject_conformance_authority_extensions(
    authority: &ConformanceAuthority,
) -> Result<(), AdmittedFileTreeError> {
    reject_extensions("conformance authority", &authority.extensions)?;
    reject_extensions("conformance attester", &authority.attester.extensions)
}

fn reject_observation_authority_extensions(
    authority: &ObservationAuthority,
) -> Result<(), AdmittedFileTreeError> {
    reject_extensions("observation authority", &authority.extensions)
}

fn reject_evidence_extensions(evidence: &EvidenceRef) -> Result<(), AdmittedFileTreeError> {
    reject_extensions("evidence reference", &evidence.extensions)
}

fn reject_fact_extensions(scope: &'static str, fact: &Fact) -> Result<(), AdmittedFileTreeError> {
    reject_extensions(scope, &fact.extensions)
}

fn reject_extensions(
    scope: &'static str,
    extensions: &BTreeMap<String, serde_json::Value>,
) -> Result<(), AdmittedFileTreeError> {
    if let Some(key) = extensions.keys().next() {
        Err(AdmittedFileTreeError::UnhandledAuthorityExtension {
            scope,
            key: key.clone(),
        })
    } else {
        Ok(())
    }
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
    WrongValueKind { expected: String, actual: String },
    UnhandledFactExtension(String),
    InvalidPayload(String),
    InvalidTree(FileTreeError),
    UnhandledTreeExtension(String),
    UnhandledFileExtension { path: String, key: String },
    UnhandledAuthorityExtension { scope: &'static str, key: String },
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
