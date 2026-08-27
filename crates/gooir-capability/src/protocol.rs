//! Neutral capability offer, invocation, result, and candidate documents.
//!
//! These documents describe semantic work and its proposed result. They do not
//! launch implementations, grant credentials, schedule attempts, or admit
//! facts. Every deserialized document is untrusted until its `validate` method
//! succeeds. Even a structurally valid invocation has only *references* to
//! authority records; resolving those references against a contextual
//! admission ledger is the next and only trust-producing step.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::{
    CapabilityId, CapabilitySpec, Fact, FactId, InputPort, OutputPort, PortName, ValueKindId,
    canonical_digest, validate_spec,
};

pub const OFFER_PROTOCOL: &str = "org.gooi.capability.offer/v1";
pub const INVOCATION_PROTOCOL: &str = "org.gooi.capability.invocation/v1";
pub const RESULT_PROTOCOL: &str = "org.gooi.capability.result/v1";
pub const CANDIDATE_PROTOCOL: &str = "org.gooi.capability.candidate/v1";

/// Why a value could not be read as an exact lowercase SHA-256 identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestParseError(pub String);

impl fmt::Display for DigestParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "`{}` is not an exact SHA-256 identity", self.0)
    }
}

impl std::error::Error for DigestParseError {}

macro_rules! sha256_wrapper {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, DigestParseError> {
                let value = value.into();
                if is_sha256(&value) {
                    Ok(Self(value))
                } else {
                    Err(DigestParseError(value))
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
    /// Digest of the exact implementation artifact offered to an execution host.
    ArtifactDigest
}
sha256_wrapper! {
    /// Content identity of one implementation offer.
    OfferId
}
sha256_wrapper! {
    /// Content identity of one linked semantic invocation.
    InvocationId
}
sha256_wrapper! {
    /// Content identity of one neutral implementation result.
    ResultId
}
sha256_wrapper! {
    /// Content identity of one untrusted candidate.
    CandidateId
}
sha256_wrapper! {
    /// Identity of an authority record resolved only by contextual admission.
    AuthorityRecordId
}
sha256_wrapper! {
    /// Digest of exact evidence bytes held outside the semantic document.
    EvidenceDigest
}

gooir_identity::exact_identity! {
    /// Exact semantic identity of an implementation, independent of its artifact bytes.
    ImplementationId
}

gooir_identity::exact_identity! {
    /// Exact semantic identity of a conformance suite.
    ConformanceSuiteId
}

gooir_identity::exact_identity! {
    /// Exact semantic identity of an opaque evidence kind.
    EvidenceKindId
}

gooir_identity::exact_identity! {
    /// Exact semantic identity of an opaque inability/failure kind.
    FailureKindId
}

/// A structural protocol validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    ProtocolMismatch {
        expected: &'static str,
        actual: String,
    },
    InvalidIdentity {
        field: &'static str,
        value: String,
    },
    InvalidCapability(String),
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
    OfferCapabilityMismatch {
        offered: Box<CapabilityId>,
        invoked: Box<CapabilityId>,
    },
    DuplicatePort {
        direction: &'static str,
        port: PortName,
    },
    PortSetMismatch {
        direction: &'static str,
        expected: Vec<PortName>,
        actual: Vec<PortName>,
    },
    PortOrderMismatch {
        direction: &'static str,
        expected: Vec<PortName>,
        actual: Vec<PortName>,
    },
    FactInvalid {
        port: PortName,
        detail: String,
    },
    FactReferenceMismatch {
        port: PortName,
        expected: FactId,
        actual: FactId,
    },
    ValueKindMismatch {
        port: PortName,
        expected: Box<ValueKindId>,
        actual: Box<ValueKindId>,
    },
    EmptyEvidenceLocator,
    InvocationCorrelationMismatch {
        expected: InvocationId,
        actual: InvocationId,
    },
    UnableResultCannotBecomeCandidate,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ProtocolError {}

/// One content-identified implementation offer.
///
/// An offer establishes availability coordinates only. It is not selection,
/// invocation, conformance, or admission.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityOffer {
    pub offer_id: OfferId,
    pub protocol: String,
    pub implementation: ImplementationId,
    pub artifact_digest: ArtifactDigest,
    pub capability: CapabilityId,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl CapabilityOffer {
    pub fn new(
        implementation: ImplementationId,
        artifact_digest: ArtifactDigest,
        capability: CapabilityId,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ProtocolError> {
        let mut offer = Self {
            offer_id: placeholder_sha256::<OfferId>(),
            protocol: OFFER_PROTOCOL.to_owned(),
            implementation,
            artifact_digest,
            capability,
            extensions,
        };
        offer.validate_structure()?;
        offer.offer_id = OfferId::parse(document_digest(&offer, "offer_id")?)
            .expect("a canonical SHA-256 digest is valid");
        Ok(offer)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.validate_structure()?;
        validate_content_id(
            "offer",
            self.offer_id.as_str(),
            &document_digest(self, "offer_id")?,
        )
    }

    fn validate_structure(&self) -> Result<(), ProtocolError> {
        validate_protocol(OFFER_PROTOCOL, &self.protocol)?;
        validate_exact_id("implementation", &self.implementation)?;
        validate_exact_id("capability", &self.capability)?;
        validate_extensions(
            "capability offer",
            &self.extensions,
            &[
                "offer_id",
                "protocol",
                "implementation",
                "artifact_digest",
                "capability",
            ],
        )
    }
}

/// The caller's explicit implementation choice.
///
/// The complete chosen offer is carried forward. There is no priority,
/// default, provider alias, or iteration-order fallback.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImplementationSelection {
    pub offer: CapabilityOffer,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl ImplementationSelection {
    pub fn new(
        offer: CapabilityOffer,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ProtocolError> {
        let selection = Self { offer, extensions };
        selection.validate()?;
        Ok(selection)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.offer.validate()?;
        validate_extensions("implementation selection", &self.extensions, &["offer"])
    }
}

/// Exact fact and authority-record identities accepted by the invoking caller.
///
/// Structural validation proves only that the IDs are exact and that the fact
/// accompanies its own ID. It does not prove the authority record exists or is
/// accepted. Contextual ledger resolution is deliberately deferred.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AdmittedFactRef {
    pub fact_id: FactId,
    pub authority_record_id: AuthorityRecordId,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl AdmittedFactRef {
    pub fn new(
        fact_id: FactId,
        authority_record_id: AuthorityRecordId,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ProtocolError> {
        let reference = Self {
            fact_id,
            authority_record_id,
            extensions,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        FactId::parse(self.fact_id.to_string()).map_err(|_| ProtocolError::InvalidIdentity {
            field: "fact_id",
            value: self.fact_id.to_string(),
        })?;
        validate_extensions(
            "admitted fact reference",
            &self.extensions,
            &["fact_id", "authority_record_id"],
        )
    }
}

/// One exact named invocation input.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LinkedInput {
    pub port: PortName,
    pub admitted: AdmittedFactRef,
    pub fact: Fact,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl LinkedInput {
    /// A linked input cannot be constructed from a bare [`Fact`]. The caller
    /// must provide the exact accepted authority-record reference as well.
    pub fn new(
        port: PortName,
        admitted: AdmittedFactRef,
        fact: Fact,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ProtocolError> {
        let input = Self {
            port,
            admitted,
            fact,
            extensions,
        };
        input.validate_envelope()?;
        Ok(input)
    }

    fn validate_envelope(&self) -> Result<(), ProtocolError> {
        self.admitted.validate()?;
        self.fact
            .validate()
            .map_err(|error| ProtocolError::FactInvalid {
                port: self.port.clone(),
                detail: error.to_string(),
            })?;
        if self.admitted.fact_id != self.fact.id {
            return Err(ProtocolError::FactReferenceMismatch {
                port: self.port.clone(),
                expected: self.fact.id.clone(),
                actual: self.admitted.fact_id.clone(),
            });
        }
        validate_extensions(
            &format!("linked input `{}`", self.port),
            &self.extensions,
            &["port", "admitted", "fact"],
        )
    }
}

/// One content-identified, explicitly selected semantic invocation.
///
/// This is untrusted structural data until [`CapabilityInvocation::validate`]
/// succeeds. Validation does not resolve authority records.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityInvocation {
    pub invocation_id: InvocationId,
    pub protocol: String,
    pub specification: CapabilitySpec,
    pub selection: ImplementationSelection,
    pub inputs: Vec<LinkedInput>,
    pub conformance_suite: ConformanceSuiteId,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl CapabilityInvocation {
    pub fn new(
        specification: CapabilitySpec,
        selection: ImplementationSelection,
        inputs: Vec<LinkedInput>,
        conformance_suite: ConformanceSuiteId,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ProtocolError> {
        let mut invocation = Self {
            invocation_id: placeholder_sha256::<InvocationId>(),
            protocol: INVOCATION_PROTOCOL.to_owned(),
            specification,
            selection,
            inputs,
            conformance_suite,
            extensions,
        };
        invocation.validate_structure()?;
        invocation.invocation_id =
            InvocationId::parse(document_digest(&invocation, "invocation_id")?)
                .expect("a canonical SHA-256 digest is valid");
        Ok(invocation)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.validate_structure()?;
        validate_content_id(
            "invocation",
            self.invocation_id.as_str(),
            &document_digest(self, "invocation_id")?,
        )
    }

    fn validate_structure(&self) -> Result<(), ProtocolError> {
        validate_protocol(INVOCATION_PROTOCOL, &self.protocol)?;
        validate_spec(&self.specification)
            .map_err(|error| ProtocolError::InvalidCapability(error.to_string()))?;
        self.selection.validate()?;
        validate_exact_id("conformance_suite", &self.conformance_suite)?;
        if self.selection.offer.capability != self.specification.id {
            return Err(ProtocolError::OfferCapabilityMismatch {
                offered: Box::new(self.selection.offer.capability.clone()),
                invoked: Box::new(self.specification.id.clone()),
            });
        }
        validate_extensions(
            "capability invocation",
            &self.extensions,
            &[
                "invocation_id",
                "protocol",
                "specification",
                "selection",
                "inputs",
                "conformance_suite",
            ],
        )?;
        validate_inputs(&self.specification.input_ports, &self.inputs)
    }
}

/// Opaque evidence held by an execution host or another external authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub kind: EvidenceKindId,
    pub digest: EvidenceDigest,
    pub locator: String,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl EvidenceRef {
    pub fn new(
        kind: EvidenceKindId,
        digest: EvidenceDigest,
        locator: impl Into<String>,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ProtocolError> {
        let evidence = Self {
            kind,
            digest,
            locator: locator.into(),
            extensions,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_exact_id("evidence kind", &self.kind)?;
        if self.locator.is_empty() {
            return Err(ProtocolError::EmptyEvidenceLocator);
        }
        validate_extensions(
            "evidence reference",
            &self.extensions,
            &["kind", "digest", "locator"],
        )
    }
}

/// Opaque typed explanation that an implementation could not produce outputs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityFailure {
    pub kind: FailureKindId,
    pub detail: Value,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl CapabilityFailure {
    pub fn new(
        kind: FailureKindId,
        detail: Value,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ProtocolError> {
        let failure = Self {
            kind,
            detail,
            extensions,
        };
        failure.validate()?;
        Ok(failure)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_exact_id("failure kind", &self.kind)?;
        validate_extensions("capability failure", &self.extensions, &["kind", "detail"])
    }
}

/// One exact named produced fact.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NamedOutput {
    pub port: PortName,
    pub fact: Fact,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl NamedOutput {
    pub fn new(
        port: PortName,
        fact: Fact,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ProtocolError> {
        let output = Self {
            port,
            fact,
            extensions,
        };
        output.validate_envelope()?;
        Ok(output)
    }

    fn validate_envelope(&self) -> Result<(), ProtocolError> {
        self.fact
            .validate()
            .map_err(|error| ProtocolError::FactInvalid {
                port: self.port.clone(),
                detail: error.to_string(),
            })?;
        validate_extensions(
            &format!("named output `{}`", self.port),
            &self.extensions,
            &["port", "fact"],
        )
    }
}

/// Produced outputs and inability are disjoint by construction.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CapabilityOutcome {
    Produced {
        outputs: Vec<NamedOutput>,
        #[serde(default, flatten)]
        extensions: BTreeMap<String, Value>,
    },
    Unable {
        failure: CapabilityFailure,
        #[serde(default, flatten)]
        extensions: BTreeMap<String, Value>,
    },
}

/// One content-identified neutral result returned by an execution host.
///
/// A valid result is still not trusted. It becomes candidate material only for
/// the exact invocation it names, and admission remains separate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityResult {
    pub result_id: ResultId,
    pub protocol: String,
    pub invocation_id: InvocationId,
    pub outcome: CapabilityOutcome,
    pub evidence: Vec<EvidenceRef>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl CapabilityResult {
    pub fn produced(
        invocation: &CapabilityInvocation,
        outputs: Vec<NamedOutput>,
        outcome_extensions: BTreeMap<String, Value>,
        evidence: Vec<EvidenceRef>,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ProtocolError> {
        let mut result = Self {
            result_id: placeholder_sha256::<ResultId>(),
            protocol: RESULT_PROTOCOL.to_owned(),
            invocation_id: invocation.invocation_id.clone(),
            outcome: CapabilityOutcome::Produced {
                outputs,
                extensions: outcome_extensions,
            },
            evidence,
            extensions,
        };
        result.validate_structure_against(invocation)?;
        result.result_id = ResultId::parse(document_digest(&result, "result_id")?)
            .expect("a canonical SHA-256 digest is valid");
        Ok(result)
    }

    pub fn unable(
        invocation: &CapabilityInvocation,
        failure: CapabilityFailure,
        outcome_extensions: BTreeMap<String, Value>,
        evidence: Vec<EvidenceRef>,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ProtocolError> {
        let mut result = Self {
            result_id: placeholder_sha256::<ResultId>(),
            protocol: RESULT_PROTOCOL.to_owned(),
            invocation_id: invocation.invocation_id.clone(),
            outcome: CapabilityOutcome::Unable {
                failure,
                extensions: outcome_extensions,
            },
            evidence,
            extensions,
        };
        result.validate_structure_against(invocation)?;
        result.result_id = ResultId::parse(document_digest(&result, "result_id")?)
            .expect("a canonical SHA-256 digest is valid");
        Ok(result)
    }

    pub fn validate_against(&self, invocation: &CapabilityInvocation) -> Result<(), ProtocolError> {
        self.validate_structure_against(invocation)?;
        validate_content_id(
            "result",
            self.result_id.as_str(),
            &document_digest(self, "result_id")?,
        )
    }

    pub fn is_produced(&self) -> bool {
        matches!(self.outcome, CapabilityOutcome::Produced { .. })
    }

    fn validate_structure_against(
        &self,
        invocation: &CapabilityInvocation,
    ) -> Result<(), ProtocolError> {
        invocation.validate()?;
        validate_protocol(RESULT_PROTOCOL, &self.protocol)?;
        if self.invocation_id != invocation.invocation_id {
            return Err(ProtocolError::InvocationCorrelationMismatch {
                expected: invocation.invocation_id.clone(),
                actual: self.invocation_id.clone(),
            });
        }
        validate_extensions(
            "capability result",
            &self.extensions,
            &[
                "result_id",
                "protocol",
                "invocation_id",
                "outcome",
                "evidence",
            ],
        )?;
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        match &self.outcome {
            CapabilityOutcome::Produced {
                outputs,
                extensions,
            } => {
                validate_extensions(
                    "produced outcome",
                    extensions,
                    &["status", "outputs", "failure"],
                )?;
                validate_outputs(&invocation.specification.output_ports, outputs)
            }
            CapabilityOutcome::Unable {
                failure,
                extensions,
            } => {
                validate_extensions(
                    "unable outcome",
                    extensions,
                    &["status", "failure", "outputs"],
                )?;
                failure.validate()
            }
        }
    }
}

/// One content-identified untrusted candidate containing the exact produced
/// result. There is no second output list that could disagree with it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityCandidate {
    pub candidate_id: CandidateId,
    pub protocol: String,
    pub invocation_id: InvocationId,
    pub result: CapabilityResult,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl CapabilityCandidate {
    pub fn new(
        invocation: &CapabilityInvocation,
        result: CapabilityResult,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ProtocolError> {
        result.validate_against(invocation)?;
        if !result.is_produced() {
            return Err(ProtocolError::UnableResultCannotBecomeCandidate);
        }
        let mut candidate = Self {
            candidate_id: placeholder_sha256::<CandidateId>(),
            protocol: CANDIDATE_PROTOCOL.to_owned(),
            invocation_id: invocation.invocation_id.clone(),
            result,
            extensions,
        };
        candidate.validate_structure_against(invocation)?;
        candidate.candidate_id = CandidateId::parse(document_digest(&candidate, "candidate_id")?)
            .expect("a canonical SHA-256 digest is valid");
        Ok(candidate)
    }

    pub fn validate_against(&self, invocation: &CapabilityInvocation) -> Result<(), ProtocolError> {
        self.validate_structure_against(invocation)?;
        validate_content_id(
            "candidate",
            self.candidate_id.as_str(),
            &document_digest(self, "candidate_id")?,
        )
    }

    fn validate_structure_against(
        &self,
        invocation: &CapabilityInvocation,
    ) -> Result<(), ProtocolError> {
        validate_protocol(CANDIDATE_PROTOCOL, &self.protocol)?;
        if self.invocation_id != invocation.invocation_id {
            return Err(ProtocolError::InvocationCorrelationMismatch {
                expected: invocation.invocation_id.clone(),
                actual: self.invocation_id.clone(),
            });
        }
        self.result.validate_against(invocation)?;
        if !self.result.is_produced() {
            return Err(ProtocolError::UnableResultCannotBecomeCandidate);
        }
        validate_extensions(
            "capability candidate",
            &self.extensions,
            &[
                "candidate_id",
                "protocol",
                "invocation_id",
                "result",
                // A candidate has no copied output list. Treating one as an
                // extension would create the same ambiguity under another name.
                "outputs",
            ],
        )
    }
}

fn validate_inputs(expected: &[InputPort], actual: &[LinkedInput]) -> Result<(), ProtocolError> {
    let expected_names = expected
        .iter()
        .map(|port| port.name.clone())
        .collect::<Vec<_>>();
    let actual_names = actual
        .iter()
        .map(|input| input.port.clone())
        .collect::<Vec<_>>();
    validate_named_port_sequence("input", &expected_names, &actual_names)?;
    for (port, input) in expected.iter().zip(actual) {
        input.validate_envelope()?;
        if input.fact.value_kind != port.value_kind {
            return Err(ProtocolError::ValueKindMismatch {
                port: port.name.clone(),
                expected: Box::new(port.value_kind.clone()),
                actual: Box::new(input.fact.value_kind.clone()),
            });
        }
    }
    Ok(())
}

fn validate_outputs(expected: &[OutputPort], actual: &[NamedOutput]) -> Result<(), ProtocolError> {
    let expected_names = expected
        .iter()
        .map(|port| port.name.clone())
        .collect::<Vec<_>>();
    let actual_names = actual
        .iter()
        .map(|output| output.port.clone())
        .collect::<Vec<_>>();
    validate_named_port_sequence("output", &expected_names, &actual_names)?;
    for (port, output) in expected.iter().zip(actual) {
        output.validate_envelope()?;
        if output.fact.value_kind != port.value_kind {
            return Err(ProtocolError::ValueKindMismatch {
                port: port.name.clone(),
                expected: Box::new(port.value_kind.clone()),
                actual: Box::new(output.fact.value_kind.clone()),
            });
        }
    }
    Ok(())
}

fn validate_named_port_sequence(
    direction: &'static str,
    expected: &[PortName],
    actual: &[PortName],
) -> Result<(), ProtocolError> {
    let mut seen = BTreeSet::new();
    for port in actual {
        if !seen.insert(port) {
            return Err(ProtocolError::DuplicatePort {
                direction,
                port: port.clone(),
            });
        }
    }
    let expected_set = expected.iter().collect::<BTreeSet<_>>();
    let actual_set = actual.iter().collect::<BTreeSet<_>>();
    if expected_set != actual_set {
        return Err(ProtocolError::PortSetMismatch {
            direction,
            expected: expected.to_vec(),
            actual: actual.to_vec(),
        });
    }
    if expected != actual {
        return Err(ProtocolError::PortOrderMismatch {
            direction,
            expected: expected.to_vec(),
            actual: actual.to_vec(),
        });
    }
    Ok(())
}

fn validate_protocol(expected: &'static str, actual: &str) -> Result<(), ProtocolError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ProtocolError::ProtocolMismatch {
            expected,
            actual: actual.to_owned(),
        })
    }
}

fn validate_exact_id<T: ExactSemanticId>(
    field: &'static str,
    value: &T,
) -> Result<(), ProtocolError> {
    if value.is_well_formed() {
        Ok(())
    } else {
        Err(ProtocolError::InvalidIdentity {
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
    CapabilityId,
    ImplementationId,
    ConformanceSuiteId,
    EvidenceKindId,
    FailureKindId,
);

fn validate_extensions(
    scope: &str,
    extensions: &BTreeMap<String, Value>,
    reserved: &[&str],
) -> Result<(), ProtocolError> {
    if let Some(key) = reserved.iter().find(|key| extensions.contains_key(**key)) {
        Err(ProtocolError::ReservedExtension {
            scope: scope.to_owned(),
            key: (*key).to_owned(),
        })
    } else {
        Ok(())
    }
}

fn document_digest(
    document: &impl Serialize,
    identity_field: &str,
) -> Result<String, ProtocolError> {
    let mut value = serde_json::to_value(document)
        .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        ProtocolError::Serialization("protocol document did not serialize as an object".to_owned())
    })?;
    if object.remove(identity_field).is_none() {
        return Err(ProtocolError::Serialization(format!(
            "protocol document omitted `{identity_field}`"
        )));
    }
    canonical_digest(&value).map_err(ProtocolError::Serialization)
}

fn validate_content_id(
    document: &'static str,
    actual: &str,
    expected: &str,
) -> Result<(), ProtocolError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ProtocolError::ContentIdentityMismatch {
            document,
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        })
    }
}

trait PlaceholderSha256: Sized {
    fn placeholder() -> Self;
}

macro_rules! placeholder_sha256_impl {
    ($($type:ty),+ $(,)?) => {
        $(
            impl PlaceholderSha256 for $type {
                fn placeholder() -> Self {
                    <$type>::parse(format!("sha256:{}", "0".repeat(64)))
                        .expect("the placeholder is a valid SHA-256 identity")
                }
            }
        )+
    };
}

placeholder_sha256_impl!(OfferId, InvocationId, ResultId, CandidateId);

fn placeholder_sha256<T: PlaceholderSha256>() -> T {
    T::placeholder()
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FactAcceptance, InputPort, OutputPort};
    use serde_json::json;

    fn sha(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn port(name: &str) -> PortName {
        PortName::parse(name).unwrap()
    }

    fn input_kind() -> ValueKindId {
        ValueKindId::new("test.values", "source", "1.0.0")
    }

    fn output_kind() -> ValueKindId {
        ValueKindId::new("test.values", "result", "1.0.0")
    }

    fn capability_id() -> CapabilityId {
        CapabilityId::new("test.capability", "compare", "1.0.0")
    }

    fn suite_id() -> ConformanceSuiteId {
        ConformanceSuiteId::new("test.conformance", "compare", "1.0.0")
    }

    fn specification() -> CapabilitySpec {
        CapabilitySpec {
            id: capability_id(),
            input_ports: vec![
                InputPort {
                    name: port("left"),
                    value_kind: input_kind(),
                    acceptance: FactAcceptance::CompleteOnly,
                    extensions: BTreeMap::new(),
                },
                InputPort {
                    name: port("right"),
                    value_kind: input_kind(),
                    acceptance: FactAcceptance::CompleteOnly,
                    extensions: BTreeMap::new(),
                },
            ],
            output_ports: vec![
                OutputPort::new(port("primary"), output_kind()),
                OutputPort::new(port("secondary"), output_kind()),
            ],
            default_conformance_suite: suite_id().to_string(),
            extensions: BTreeMap::new(),
        }
    }

    fn offer(name: &str, digest_byte: char) -> CapabilityOffer {
        CapabilityOffer::new(
            ImplementationId::new("test.implementation", name, "1.0.0"),
            ArtifactDigest::parse(sha(digest_byte)).unwrap(),
            capability_id(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn fact(value: i64) -> Fact {
        Fact::new(input_kind(), json!({"value": value})).unwrap()
    }

    fn output_fact(value: i64) -> Fact {
        Fact::new(output_kind(), json!({"value": value})).unwrap()
    }

    fn authority(byte: char) -> AuthorityRecordId {
        AuthorityRecordId::parse(sha(byte)).unwrap()
    }

    fn linked(name: &str, fact: Fact, authority_byte: char) -> LinkedInput {
        LinkedInput::new(
            port(name),
            AdmittedFactRef::new(fact.id.clone(), authority(authority_byte), BTreeMap::new())
                .unwrap(),
            fact,
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn invocation_with(selected: CapabilityOffer) -> CapabilityInvocation {
        CapabilityInvocation::new(
            specification(),
            ImplementationSelection::new(selected, BTreeMap::new()).unwrap(),
            vec![linked("left", fact(1), '1'), linked("right", fact(2), '2')],
            suite_id(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn invocation() -> CapabilityInvocation {
        invocation_with(offer("second", 'b'))
    }

    fn evidence(name: &str, byte: char) -> EvidenceRef {
        EvidenceRef::new(
            EvidenceKindId::new("test.evidence", name, "1.0.0"),
            EvidenceDigest::parse(sha(byte)).unwrap(),
            format!("opaque://evidence/{name}"),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn outputs() -> Vec<NamedOutput> {
        vec![
            NamedOutput::new(port("primary"), output_fact(10), BTreeMap::new()).unwrap(),
            NamedOutput::new(port("secondary"), output_fact(20), BTreeMap::new()).unwrap(),
        ]
    }

    fn result(invocation: &CapabilityInvocation) -> CapabilityResult {
        CapabilityResult::produced(
            invocation,
            outputs(),
            BTreeMap::new(),
            vec![evidence("log", 'c')],
            BTreeMap::new(),
        )
        .unwrap()
    }

    #[test]
    fn two_offers_remain_visible_and_only_the_caller_choice_enters_the_invocation() {
        let first = offer("first", 'a');
        let second = offer("second", 'b');
        let eligible = [first.clone(), second.clone()];
        assert_eq!(eligible.len(), 2);
        assert_ne!(first.offer_id, second.offer_id);

        let selected_second = invocation_with(second.clone());
        assert_eq!(selected_second.selection.offer, second);
        assert_ne!(selected_second.selection.offer, first);

        let selected_first = invocation_with(first);
        assert_ne!(selected_first.invocation_id, selected_second.invocation_id);
    }

    #[test]
    fn repeated_same_kind_ports_bind_distinct_facts_and_outputs() {
        let invocation = invocation();
        invocation.validate().unwrap();
        assert_eq!(invocation.inputs[0].fact.value_kind, input_kind());
        assert_eq!(invocation.inputs[1].fact.value_kind, input_kind());
        assert_ne!(invocation.inputs[0].fact.id, invocation.inputs[1].fact.id);

        let result = result(&invocation);
        result.validate_against(&invocation).unwrap();
        let CapabilityOutcome::Produced { outputs, .. } = &result.outcome else {
            panic!("fixture is produced")
        };
        assert_eq!(outputs[0].fact.value_kind, output_kind());
        assert_eq!(outputs[1].fact.value_kind, output_kind());
        assert_ne!(outputs[0].port, outputs[1].port);
    }

    #[test]
    fn input_reference_kind_port_order_offer_and_result_correlation_fail_closed() {
        let valid = invocation();

        let mut substituted = valid.clone();
        substituted.inputs[0].admitted.fact_id = substituted.inputs[1].fact.id.clone();
        assert!(matches!(
            substituted.validate(),
            Err(ProtocolError::FactReferenceMismatch { .. })
        ));

        let mut wrong_kind = valid.clone();
        let alien = Fact::new(
            ValueKindId::new("test.values", "alien", "1.0.0"),
            json!({"value": 1}),
        )
        .unwrap();
        wrong_kind.inputs[0].admitted.fact_id = alien.id.clone();
        wrong_kind.inputs[0].fact = alien;
        assert!(matches!(
            wrong_kind.validate(),
            Err(ProtocolError::ValueKindMismatch { .. })
        ));

        let mut wrong_port = valid.clone();
        wrong_port.inputs[0].port = port("unknown");
        assert!(matches!(
            wrong_port.validate(),
            Err(ProtocolError::PortSetMismatch { .. })
        ));

        let mut reordered = valid.clone();
        reordered.inputs.swap(0, 1);
        assert!(matches!(
            reordered.validate(),
            Err(ProtocolError::PortOrderMismatch { .. })
        ));

        let other_offer = CapabilityOffer::new(
            ImplementationId::new("test.implementation", "other", "1.0.0"),
            ArtifactDigest::parse(sha('d')).unwrap(),
            CapabilityId::new("test.capability", "other", "1.0.0"),
            BTreeMap::new(),
        )
        .unwrap();
        assert!(matches!(
            CapabilityInvocation::new(
                specification(),
                ImplementationSelection::new(other_offer, BTreeMap::new()).unwrap(),
                valid.inputs.clone(),
                suite_id(),
                BTreeMap::new(),
            ),
            Err(ProtocolError::OfferCapabilityMismatch { .. })
        ));

        let mut wrong_correlation = result(&valid);
        wrong_correlation.invocation_id = InvocationId::parse(sha('e')).unwrap();
        assert!(matches!(
            wrong_correlation.validate_against(&valid),
            Err(ProtocolError::InvocationCorrelationMismatch { .. })
        ));
    }

    #[test]
    fn produced_outputs_require_exact_ports_kinds_facts_and_order() {
        let invocation = invocation();
        let valid = result(&invocation);

        let mut wrong_port = valid.clone();
        let CapabilityOutcome::Produced { outputs, .. } = &mut wrong_port.outcome else {
            unreachable!()
        };
        outputs[0].port = port("other");
        assert!(matches!(
            wrong_port.validate_against(&invocation),
            Err(ProtocolError::PortSetMismatch { .. })
        ));

        let mut wrong_kind = valid.clone();
        let CapabilityOutcome::Produced { outputs, .. } = &mut wrong_kind.outcome else {
            unreachable!()
        };
        outputs[0].fact = Fact::new(input_kind(), json!({"wrong": true})).unwrap();
        assert!(matches!(
            wrong_kind.validate_against(&invocation),
            Err(ProtocolError::ValueKindMismatch { .. })
        ));

        let mut repeated_port = valid.clone();
        let CapabilityOutcome::Produced { outputs, .. } = &mut repeated_port.outcome else {
            unreachable!()
        };
        outputs[1].port = port("primary");
        assert!(matches!(
            repeated_port.validate_against(&invocation),
            Err(ProtocolError::DuplicatePort { .. })
        ));

        let mut reordered = valid;
        let CapabilityOutcome::Produced { outputs, .. } = &mut reordered.outcome else {
            unreachable!()
        };
        outputs.swap(0, 1);
        assert!(matches!(
            reordered.validate_against(&invocation),
            Err(ProtocolError::PortOrderMismatch { .. })
        ));
    }

    #[test]
    fn unable_results_cannot_become_candidates_or_smuggle_outputs() {
        let invocation = invocation();
        let unable = CapabilityResult::unable(
            &invocation,
            CapabilityFailure::new(
                FailureKindId::new("test.failure", "unavailable", "1.0.0"),
                json!({"bounded": true}),
                BTreeMap::new(),
            )
            .unwrap(),
            BTreeMap::new(),
            vec![evidence("failure", 'f')],
            BTreeMap::new(),
        )
        .unwrap();
        assert!(matches!(
            CapabilityCandidate::new(&invocation, unable.clone(), BTreeMap::new()),
            Err(ProtocolError::UnableResultCannotBecomeCandidate)
        ));

        let mut wire = serde_json::to_value(unable).unwrap();
        wire["outcome"]["outputs"] = json!([]);
        let smuggled: CapabilityResult = serde_json::from_value(wire).unwrap();
        assert!(matches!(
            smuggled.validate_against(&invocation),
            Err(ProtocolError::ReservedExtension { key, .. }) if key == "outputs"
        ));
    }

    #[test]
    fn candidate_embeds_the_exact_result_and_has_no_replaceable_output_list() {
        let invocation = invocation();
        let result = result(&invocation);
        let candidate =
            CapabilityCandidate::new(&invocation, result.clone(), BTreeMap::new()).unwrap();
        assert_eq!(candidate.result, result);
        candidate.validate_against(&invocation).unwrap();

        let mut copied_outputs = serde_json::to_value(&candidate).unwrap();
        copied_outputs["outputs"] = json!([]);
        let copied: CapabilityCandidate = serde_json::from_value(copied_outputs).unwrap();
        assert!(matches!(
            copied.validate_against(&invocation),
            Err(ProtocolError::ReservedExtension { key, .. }) if key == "outputs"
        ));

        let mut replaced = candidate;
        let CapabilityOutcome::Produced { outputs, .. } = &mut replaced.result.outcome else {
            unreachable!()
        };
        outputs[0].fact = output_fact(999);
        assert!(matches!(
            replaced.validate_against(&invocation),
            Err(ProtocolError::ContentIdentityMismatch {
                document: "result",
                ..
            })
        ));
    }

    #[test]
    fn opaque_extensions_survive_every_level_and_change_enclosing_identities() {
        let mut offer_extensions = BTreeMap::new();
        offer_extensions.insert("x.offer".to_owned(), json!({"v": [2, 1]}));
        let extended_offer = CapabilityOffer::new(
            ImplementationId::new("test.implementation", "extended", "1.0.0"),
            ArtifactDigest::parse(sha('7')).unwrap(),
            capability_id(),
            offer_extensions,
        )
        .unwrap();
        let plain_offer = CapabilityOffer::new(
            extended_offer.implementation.clone(),
            extended_offer.artifact_digest.clone(),
            capability_id(),
            BTreeMap::new(),
        )
        .unwrap();
        assert_ne!(extended_offer.offer_id, plain_offer.offer_id);

        let mut spec = specification();
        spec.extensions.insert("x.spec".to_owned(), json!(true));
        spec.input_ports[0]
            .extensions
            .insert("x.input_port".to_owned(), json!({"role": "opaque"}));
        spec.output_ports[0]
            .extensions
            .insert("x.output_port".to_owned(), json!(["future"]));

        let left = fact(1);
        let mut admitted_extensions = BTreeMap::new();
        admitted_extensions.insert("x.authority_ref".to_owned(), json!(1));
        let admitted =
            AdmittedFactRef::new(left.id.clone(), authority('8'), admitted_extensions).unwrap();
        let mut linked_extensions = BTreeMap::new();
        linked_extensions.insert("x.link".to_owned(), json!({"exact": true}));
        let linked_left =
            LinkedInput::new(port("left"), admitted, left, linked_extensions).unwrap();

        let mut selection_extensions = BTreeMap::new();
        selection_extensions.insert("x.selection".to_owned(), json!("caller"));
        let selection = ImplementationSelection::new(extended_offer, selection_extensions).unwrap();
        let mut invocation_extensions = BTreeMap::new();
        invocation_extensions.insert("x.invocation".to_owned(), json!([3, 2, 1]));
        let extended_invocation = CapabilityInvocation::new(
            spec,
            selection,
            vec![linked_left, linked("right", fact(2), '9')],
            suite_id(),
            invocation_extensions,
        )
        .unwrap();
        let round_trip: CapabilityInvocation =
            serde_json::from_str(&serde_json::to_string(&extended_invocation).unwrap()).unwrap();
        assert_eq!(round_trip, extended_invocation);
        round_trip.validate().unwrap();
        assert_eq!(round_trip.extensions["x.invocation"], json!([3, 2, 1]));
        let same_contents_without_invocation_extension = CapabilityInvocation::new(
            extended_invocation.specification.clone(),
            extended_invocation.selection.clone(),
            extended_invocation.inputs.clone(),
            extended_invocation.conformance_suite.clone(),
            BTreeMap::new(),
        )
        .unwrap();
        assert_ne!(
            extended_invocation.invocation_id,
            same_contents_without_invocation_extension.invocation_id
        );
        let mut selection_without_offer_extension = extended_invocation.selection.clone();
        selection_without_offer_extension.offer = plain_offer;
        let same_contents_without_offer_extension = CapabilityInvocation::new(
            extended_invocation.specification.clone(),
            selection_without_offer_extension,
            extended_invocation.inputs.clone(),
            extended_invocation.conformance_suite.clone(),
            extended_invocation.extensions.clone(),
        )
        .unwrap();
        assert_ne!(
            extended_invocation.invocation_id,
            same_contents_without_offer_extension.invocation_id
        );

        let mut invocation_extension_tampers = Vec::new();
        let mut tampered = extended_invocation.clone();
        tampered.specification.extensions.remove("x.spec");
        invocation_extension_tampers.push(tampered);
        let mut tampered = extended_invocation.clone();
        tampered.specification.input_ports[0]
            .extensions
            .remove("x.input_port");
        invocation_extension_tampers.push(tampered);
        let mut tampered = extended_invocation.clone();
        tampered.specification.output_ports[0]
            .extensions
            .remove("x.output_port");
        invocation_extension_tampers.push(tampered);
        let mut tampered = extended_invocation.clone();
        tampered.inputs[0]
            .admitted
            .extensions
            .remove("x.authority_ref");
        invocation_extension_tampers.push(tampered);
        let mut tampered = extended_invocation.clone();
        tampered.inputs[0].extensions.remove("x.link");
        invocation_extension_tampers.push(tampered);
        let mut tampered = extended_invocation.clone();
        tampered.selection.extensions.remove("x.selection");
        invocation_extension_tampers.push(tampered);
        for tampered in invocation_extension_tampers {
            assert!(matches!(
                tampered.validate(),
                Err(ProtocolError::ContentIdentityMismatch {
                    document: "invocation",
                    ..
                })
            ));
        }

        let mut outcome_extensions = BTreeMap::new();
        outcome_extensions.insert("x.outcome".to_owned(), json!(false));
        let mut output_extensions = BTreeMap::new();
        output_extensions.insert("x.output".to_owned(), json!({"n": 1}));
        let mut evidence_extensions = BTreeMap::new();
        evidence_extensions.insert("x.evidence".to_owned(), json!(["opaque"]));
        let extended_evidence = EvidenceRef::new(
            EvidenceKindId::new("test.evidence", "trace", "1.0.0"),
            EvidenceDigest::parse(sha('a')).unwrap(),
            "opaque://trace/exact",
            evidence_extensions,
        )
        .unwrap();
        let mut result_extensions = BTreeMap::new();
        result_extensions.insert("x.result".to_owned(), json!(7));
        let extended_result = CapabilityResult::produced(
            &extended_invocation,
            vec![
                NamedOutput::new(port("primary"), output_fact(10), output_extensions).unwrap(),
                NamedOutput::new(port("secondary"), output_fact(20), BTreeMap::new()).unwrap(),
            ],
            outcome_extensions,
            vec![extended_evidence],
            result_extensions,
        )
        .unwrap();
        let plain_result = CapabilityResult::produced(
            &extended_invocation,
            outputs(),
            BTreeMap::new(),
            vec![evidence("trace", 'a')],
            BTreeMap::new(),
        )
        .unwrap();
        assert_ne!(extended_result.result_id, plain_result.result_id);
        let result_round_trip: CapabilityResult =
            serde_json::from_str(&serde_json::to_string(&extended_result).unwrap()).unwrap();
        assert_eq!(result_round_trip, extended_result);
        result_round_trip
            .validate_against(&extended_invocation)
            .unwrap();
        let mut result_extension_tampers = Vec::new();
        let mut tampered = extended_result.clone();
        tampered.extensions.remove("x.result");
        result_extension_tampers.push(tampered);
        let mut tampered = extended_result.clone();
        let CapabilityOutcome::Produced { extensions, .. } = &mut tampered.outcome else {
            unreachable!()
        };
        extensions.remove("x.outcome");
        result_extension_tampers.push(tampered);
        let mut tampered = extended_result.clone();
        let CapabilityOutcome::Produced { outputs, .. } = &mut tampered.outcome else {
            unreachable!()
        };
        outputs[0].extensions.remove("x.output");
        result_extension_tampers.push(tampered);
        let mut tampered = extended_result.clone();
        tampered.evidence[0].extensions.remove("x.evidence");
        result_extension_tampers.push(tampered);
        for tampered in result_extension_tampers {
            assert!(matches!(
                tampered.validate_against(&extended_invocation),
                Err(ProtocolError::ContentIdentityMismatch {
                    document: "result",
                    ..
                })
            ));
        }

        let mut candidate_extensions = BTreeMap::new();
        candidate_extensions.insert("x.candidate".to_owned(), json!({"u": null}));
        let extended_candidate =
            CapabilityCandidate::new(&extended_invocation, extended_result, candidate_extensions)
                .unwrap();
        let candidate_round_trip: CapabilityCandidate =
            serde_json::from_str(&serde_json::to_string(&extended_candidate).unwrap()).unwrap();
        assert_eq!(candidate_round_trip, extended_candidate);
        candidate_round_trip
            .validate_against(&extended_invocation)
            .unwrap();
        let same_result_without_candidate_extension = CapabilityCandidate::new(
            &extended_invocation,
            extended_candidate.result.clone(),
            BTreeMap::new(),
        )
        .unwrap();
        assert_ne!(
            extended_candidate.candidate_id,
            same_result_without_candidate_extension.candidate_id
        );

        let plain_candidate =
            CapabilityCandidate::new(&extended_invocation, plain_result, BTreeMap::new()).unwrap();
        assert_ne!(
            extended_candidate.candidate_id,
            plain_candidate.candidate_id
        );
    }

    #[test]
    fn inability_failure_extensions_round_trip_and_change_result_identity() {
        let invocation = invocation();
        let plain_failure = CapabilityFailure::new(
            FailureKindId::new("test.failure", "blocked", "1.0.0"),
            json!({"reason": "opaque"}),
            BTreeMap::new(),
        )
        .unwrap();
        let plain = CapabilityResult::unable(
            &invocation,
            plain_failure.clone(),
            BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let mut unable_extensions = BTreeMap::new();
        unable_extensions.insert("x.unable".to_owned(), json!({"opaque": true}));
        let extended_outcome = CapabilityResult::unable(
            &invocation,
            plain_failure.clone(),
            unable_extensions,
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        assert_ne!(plain.result_id, extended_outcome.result_id);
        let decoded_outcome: CapabilityResult =
            serde_json::from_str(&serde_json::to_string(&extended_outcome).unwrap()).unwrap();
        assert_eq!(decoded_outcome, extended_outcome);
        decoded_outcome.validate_against(&invocation).unwrap();

        let mut failure_extensions = BTreeMap::new();
        failure_extensions.insert("x.failure".to_owned(), json!([1, 2]));
        let extended = CapabilityResult::unable(
            &invocation,
            CapabilityFailure::new(plain_failure.kind, plain_failure.detail, failure_extensions)
                .unwrap(),
            BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        assert_ne!(plain.result_id, extended.result_id);
        let decoded: CapabilityResult =
            serde_json::from_str(&serde_json::to_string(&extended).unwrap()).unwrap();
        assert_eq!(decoded, extended);
        decoded.validate_against(&invocation).unwrap();
    }

    #[test]
    fn hostile_deserialization_and_tampering_require_revalidation() {
        let invocation = invocation();
        let candidate =
            CapabilityCandidate::new(&invocation, result(&invocation), BTreeMap::new()).unwrap();

        let mut malformed_digest = serde_json::to_value(&candidate).unwrap();
        malformed_digest["candidate_id"] = json!("sha256:NOT-A-DIGEST");
        assert!(serde_json::from_value::<CapabilityCandidate>(malformed_digest).is_err());

        let mut wrong_protocol = candidate.clone();
        wrong_protocol.protocol = "org.gooi.capability.candidate/v99".to_owned();
        assert!(matches!(
            wrong_protocol.validate_against(&invocation),
            Err(ProtocolError::ProtocolMismatch { .. })
        ));

        let mut valid_but_wrong_id = candidate.clone();
        valid_but_wrong_id.candidate_id = CandidateId::parse(sha('9')).unwrap();
        assert!(matches!(
            valid_but_wrong_id.validate_against(&invocation),
            Err(ProtocolError::ContentIdentityMismatch {
                document: "candidate",
                ..
            })
        ));

        let mut shadowed = candidate;
        shadowed.extensions.insert("result".to_owned(), Value::Null);
        assert!(matches!(
            shadowed.validate_against(&invocation),
            Err(ProtocolError::ReservedExtension { key, .. }) if key == "result"
        ));

        let mut bare_fact = serde_json::to_value(&invocation).unwrap();
        bare_fact["inputs"] = json!([invocation.inputs[0].fact]);
        assert!(serde_json::from_value::<CapabilityInvocation>(bare_fact).is_err());

        let mut malformed_reference = serde_json::to_value(&invocation.inputs[0].admitted).unwrap();
        malformed_reference["fact_id"] = json!("sha256:NOT-A-DIGEST");
        let malformed_reference: AdmittedFactRef =
            serde_json::from_value(malformed_reference).unwrap();
        assert!(matches!(
            malformed_reference.validate(),
            Err(ProtocolError::InvalidIdentity {
                field: "fact_id",
                ..
            })
        ));
    }

    #[test]
    fn every_protocol_extension_scope_rejects_known_field_shadows() {
        let valid_invocation = invocation();

        let mut offer = valid_invocation.selection.offer.clone();
        offer.extensions.insert("offer_id".to_owned(), Value::Null);
        assert!(matches!(
            offer.validate(),
            Err(ProtocolError::ReservedExtension { key, .. }) if key == "offer_id"
        ));

        let mut selection = valid_invocation.selection.clone();
        selection.extensions.insert("offer".to_owned(), Value::Null);
        assert!(matches!(
            selection.validate(),
            Err(ProtocolError::ReservedExtension { key, .. }) if key == "offer"
        ));

        let mut admitted = valid_invocation.inputs[0].admitted.clone();
        admitted
            .extensions
            .insert("authority_record_id".to_owned(), Value::Null);
        assert!(matches!(
            admitted.validate(),
            Err(ProtocolError::ReservedExtension { key, .. }) if key == "authority_record_id"
        ));

        let mut linked = valid_invocation.inputs[0].clone();
        linked.extensions.insert("fact".to_owned(), Value::Null);
        assert!(matches!(
            linked.validate_envelope(),
            Err(ProtocolError::ReservedExtension { key, .. }) if key == "fact"
        ));

        let mut invocation = valid_invocation.clone();
        invocation
            .extensions
            .insert("inputs".to_owned(), Value::Null);
        assert!(matches!(
            invocation.validate(),
            Err(ProtocolError::ReservedExtension { key, .. }) if key == "inputs"
        ));

        for (mut specification, field) in [
            (valid_invocation.specification.clone(), "id"),
            (valid_invocation.specification.clone(), "input_ports"),
            (valid_invocation.specification.clone(), "output_ports"),
        ] {
            match field {
                "id" => {
                    specification
                        .extensions
                        .insert(field.to_owned(), Value::Null);
                }
                "input_ports" => {
                    specification.input_ports[0]
                        .extensions
                        .insert("name".to_owned(), Value::Null);
                }
                "output_ports" => {
                    specification.output_ports[0]
                        .extensions
                        .insert("value_kind".to_owned(), Value::Null);
                }
                _ => unreachable!(),
            }
            assert!(matches!(
                CapabilityInvocation::new(
                    specification,
                    valid_invocation.selection.clone(),
                    valid_invocation.inputs.clone(),
                    suite_id(),
                    BTreeMap::new(),
                ),
                Err(ProtocolError::InvalidCapability(_))
            ));
        }

        let mut evidence = evidence("shadow", '3');
        evidence.extensions.insert("digest".to_owned(), Value::Null);
        assert!(matches!(
            evidence.validate(),
            Err(ProtocolError::ReservedExtension { key, .. }) if key == "digest"
        ));

        let mut failure = CapabilityFailure::new(
            FailureKindId::new("test.failure", "shadow", "1.0.0"),
            json!({}),
            BTreeMap::new(),
        )
        .unwrap();
        failure.extensions.insert("kind".to_owned(), Value::Null);
        assert!(matches!(
            failure.validate(),
            Err(ProtocolError::ReservedExtension { key, .. }) if key == "kind"
        ));

        let mut output = outputs().remove(0);
        output.extensions.insert("port".to_owned(), Value::Null);
        assert!(matches!(
            output.validate_envelope(),
            Err(ProtocolError::ReservedExtension { key, .. }) if key == "port"
        ));

        let mut shadowed_result = result(&valid_invocation);
        shadowed_result
            .extensions
            .insert("evidence".to_owned(), Value::Null);
        assert!(matches!(
            shadowed_result.validate_against(&valid_invocation),
            Err(ProtocolError::ReservedExtension { key, .. }) if key == "evidence"
        ));

        let mut outcome = result(&valid_invocation);
        let CapabilityOutcome::Produced { extensions, .. } = &mut outcome.outcome else {
            unreachable!()
        };
        extensions.insert("outputs".to_owned(), Value::Null);
        assert!(matches!(
            outcome.validate_against(&valid_invocation),
            Err(ProtocolError::ReservedExtension { key, .. }) if key == "outputs"
        ));

        let mut candidate = CapabilityCandidate::new(
            &valid_invocation,
            result(&valid_invocation),
            BTreeMap::new(),
        )
        .unwrap();
        candidate
            .extensions
            .insert("result".to_owned(), Value::Null);
        assert!(matches!(
            candidate.validate_against(&valid_invocation),
            Err(ProtocolError::ReservedExtension { key, .. }) if key == "result"
        ));
    }

    #[test]
    fn exact_array_order_is_not_normalized_into_one_identity() {
        let invocation = invocation();
        let forward = CapabilityResult::produced(
            &invocation,
            outputs(),
            BTreeMap::new(),
            vec![evidence("first", '1'), evidence("second", '2')],
            BTreeMap::new(),
        )
        .unwrap();
        let reverse = CapabilityResult::produced(
            &invocation,
            outputs(),
            BTreeMap::new(),
            vec![evidence("second", '2'), evidence("first", '1')],
            BTreeMap::new(),
        )
        .unwrap();
        assert_ne!(forward.result_id, reverse.result_id);
    }

    #[test]
    fn protocol_documents_contain_no_execution_host_state() {
        const FORBIDDEN: [&str; 14] = [
            "host",
            "process",
            "command",
            "transport",
            "lease",
            "session",
            "retry",
            "credential",
            "attempt",
            "scheduler",
            "priority",
            "provider",
            "deadline",
            "owner",
        ];

        let invocation = invocation();
        let result = result(&invocation);
        let candidate =
            CapabilityCandidate::new(&invocation, result.clone(), BTreeMap::new()).unwrap();
        for document in [
            serde_json::to_value(&invocation.selection.offer).unwrap(),
            serde_json::to_value(&invocation).unwrap(),
            serde_json::to_value(&result).unwrap(),
            serde_json::to_value(&candidate).unwrap(),
        ] {
            assert_no_forbidden_keys(&document, &FORBIDDEN);
        }
    }

    fn assert_no_forbidden_keys(value: &Value, forbidden: &[&str]) {
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    assert!(
                        !forbidden.contains(&key.as_str()),
                        "protocol leaked execution-host field `{key}`"
                    );
                    assert_no_forbidden_keys(child, forbidden);
                }
            }
            Value::Array(values) => {
                for child in values {
                    assert_no_forbidden_keys(child, forbidden);
                }
            }
            _ => {}
        }
    }
}
