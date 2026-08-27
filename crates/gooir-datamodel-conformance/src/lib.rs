//! Fixture-scoped independent conformance for `examples/tasks.entities`.
//!
//! This crate does not parse the authoring language or reconstruct the expected
//! data model. It compares a complete neutral capability chain with one
//! checked-in, human-reviewed pair of generic GOOIR facts. Passing is evidence
//! about only that exact fixture, capability, source fact, and named output.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fmt::Write as _;

use gooir_author_data_model_contract::{
    author_data_model_spec, author_data_model_suite_id, authored_entity_spec_value_kind,
};
use gooir_capability::Fact;
use gooir_capability::authority::{
    AssessmentOutcome, AuthorityError, ConformanceAssessment, ConformanceAttester,
    ConformanceAuthority, ConformanceCheck,
};
use gooir_capability::protocol::{
    ArtifactDigest, CapabilityCandidate, CapabilityInvocation, CapabilityOutcome, CapabilityResult,
    ConformanceSuiteId, EvidenceDigest, EvidenceKindId, EvidenceRef, ImplementationId, NamedOutput,
    ProtocolError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ORACLE_BYTES: &[u8] = include_bytes!("../oracles/tasks_entities.json");
const SOURCE_COORDINATE: &str =
    "git:blob:0ff6995a757b8d773e1f3e092650791b29b7beb4#examples/tasks.entities";
const ORACLE_LOCATOR: &str = "crate:gooir-datamodel-conformance/oracles/tasks_entities.json";

const CHECK_CAPABILITY: &str = "exact-capability-coordinate";
const CHECK_SOURCE: &str = "exact-source-fact";
const CHECK_OUTPUT: &str = "exact-named-output";

/// Versioned wire protocol for this fixture-scoped attester's request.
///
/// This is deliberately owned by the product-specific conformance crate, not
/// by `gooir-capability`: different attesters may expose different transports
/// while consuming the same neutral capability documents.
pub const ASSESSMENT_REQUEST_PROTOCOL: &str =
    "org.gooi.conformance.author-data-model-tasks-entities/request/v1";

/// One strict request to the independently deployed fixture attester.
///
/// The request embeds the complete invocation, the exact result including any
/// evidence it carries, and the candidate that embeds that same result. The
/// measured attester artifact is supplied by the execution host and remains
/// distinct from the selected producer artifact.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentRequest {
    protocol: String,
    invocation: CapabilityInvocation,
    result: CapabilityResult,
    candidate: CapabilityCandidate,
    attester_artifact_digest: ArtifactDigest,
}

impl AssessmentRequest {
    /// Constructs one request only from a complete, exactly correlated chain.
    ///
    /// # Errors
    ///
    /// Returns an error when any content identity or correlation is invalid,
    /// the suite is unsupported, or the measured attester is not independent
    /// from the selected producer.
    pub fn new(
        invocation: CapabilityInvocation,
        result: CapabilityResult,
        candidate: CapabilityCandidate,
        attester_artifact_digest: ArtifactDigest,
    ) -> Result<Self, AttesterError> {
        let request = Self {
            protocol: ASSESSMENT_REQUEST_PROTOCOL.to_owned(),
            invocation,
            result,
            candidate,
            attester_artifact_digest,
        };
        request.validate()?;
        Ok(request)
    }

    /// Revalidates the exact request protocol, documents, and correlations.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`Self::new`].
    pub fn validate(&self) -> Result<(), AttesterError> {
        if self.protocol != ASSESSMENT_REQUEST_PROTOCOL {
            return Err(AttesterError::RequestProtocolMismatch {
                actual: self.protocol.clone(),
            });
        }
        self.invocation
            .validate()
            .map_err(AttesterError::Protocol)?;
        self.result
            .validate_against(&self.invocation)
            .map_err(AttesterError::Protocol)?;
        self.candidate
            .validate_against(&self.invocation)
            .map_err(AttesterError::Protocol)?;
        if self.candidate.result != self.result {
            return Err(AttesterError::ResultCandidateMismatch);
        }
        if self.invocation.conformance_suite != suite_id() {
            return Err(AttesterError::UnsupportedSuite(
                self.invocation.conformance_suite.clone(),
            ));
        }
        let selected = &self.invocation.selection.offer;
        if selected.implementation == implementation_id()
            || selected.artifact_digest == self.attester_artifact_digest
        {
            return Err(AttesterError::Authority(
                AuthorityError::AttesterNotIndependent,
            ));
        }
        Ok(())
    }

    /// Returns the exact complete invocation embedded by this request.
    #[must_use]
    pub const fn invocation(&self) -> &CapabilityInvocation {
        &self.invocation
    }

    /// Returns the exact result embedded by this request.
    #[must_use]
    pub const fn result(&self) -> &CapabilityResult {
        &self.result
    }

    /// Returns the candidate that embeds the exact request result.
    #[must_use]
    pub const fn candidate(&self) -> &CapabilityCandidate {
        &self.candidate
    }

    /// Returns the host-measured attester artifact digest.
    #[must_use]
    pub const fn attester_artifact_digest(&self) -> &ArtifactDigest {
        &self.attester_artifact_digest
    }

    /// Produces an assessment through the same validated path used by the
    /// attester executable.
    ///
    /// # Errors
    ///
    /// Returns an error when request validation or fixture conformance fails.
    pub fn assess(&self) -> Result<ConformanceAssessment, AttesterError> {
        self.validate()?;
        assess(
            &self.invocation,
            &self.result,
            &self.candidate,
            self.attester_artifact_digest.clone(),
        )
    }
}

/// Returns the exact validated authored-source fact governed by this
/// fixture-scoped conformance suite.
///
/// This exposes only the suite's public input fixture. The checked oracle
/// bytes, expected output, and private oracle document shape remain internal
/// to the independent attester.
///
/// # Errors
///
/// Refuses the embedded fixture if its fact identity, source coordinate, or
/// other checked oracle invariants are inconsistent.
pub fn tasks_entities_source_fact() -> Result<Fact, AttesterError> {
    Ok(load_oracle(ORACLE_BYTES)?.source)
}

/// The one suite implemented by this fixture-scoped attester.
pub fn suite_id() -> ConformanceSuiteId {
    author_data_model_suite_id()
}

/// Exact identity of this oracle attester, distinct from the data-model producer.
pub fn implementation_id() -> ImplementationId {
    ImplementationId::new(
        "org.gooi.attester",
        "author_data_model_tasks_entities_oracle",
        "1.1.0",
    )
}

/// Independently assess one complete neutral provider chain against the pinned
/// `tasks.entities` oracle.
///
/// `attester_artifact` must be measured and supplied by the caller. This crate
/// neither measures nor trusts its own executable. Structurally invalid or
/// incorrectly correlated documents are errors. A structurally valid chain
/// outside the exact fixture coordinates produces a failed assessment.
pub fn assess(
    invocation: &CapabilityInvocation,
    result: &CapabilityResult,
    candidate: &CapabilityCandidate,
    attester_artifact: ArtifactDigest,
) -> Result<ConformanceAssessment, AttesterError> {
    invocation.validate().map_err(AttesterError::Protocol)?;
    result
        .validate_against(invocation)
        .map_err(AttesterError::Protocol)?;
    candidate
        .validate_against(invocation)
        .map_err(AttesterError::Protocol)?;
    if candidate.result != *result {
        return Err(AttesterError::ResultCandidateMismatch);
    }
    if invocation.conformance_suite != suite_id() {
        return Err(AttesterError::UnsupportedSuite(
            invocation.conformance_suite.clone(),
        ));
    }

    let oracle = load_oracle(ORACLE_BYTES)?;
    let evidence = oracle_evidence()?;
    let checks = BTreeMap::from([
        (
            CHECK_CAPABILITY.to_owned(),
            check(
                invocation.specification == author_data_model_spec(),
                &evidence,
            )?,
        ),
        (
            CHECK_SOURCE.to_owned(),
            check(source_matches(invocation, &oracle.source), &evidence)?,
        ),
        (
            CHECK_OUTPUT.to_owned(),
            check(output_matches(result, &oracle.output), &evidence)?,
        ),
    ]);
    let authority = ConformanceAuthority::new(
        suite_id(),
        ConformanceAttester::new(implementation_id(), attester_artifact, BTreeMap::new())
            .map_err(AttesterError::Authority)?,
        BTreeMap::new(),
    )
    .map_err(AttesterError::Authority)?;
    ConformanceAssessment::new(
        invocation,
        result,
        candidate,
        authority,
        checks,
        vec![evidence],
        BTreeMap::new(),
    )
    .map_err(AttesterError::Authority)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Oracle {
    source_coordinate: String,
    source: Fact,
    output: NamedOutput,
}

fn load_oracle(bytes: &[u8]) -> Result<Oracle, AttesterError> {
    let oracle: Oracle =
        serde_json::from_slice(bytes).map_err(|error| AttesterError::Oracle(error.to_string()))?;
    oracle
        .source
        .validate()
        .map_err(|error| AttesterError::Oracle(error.to_string()))?;
    let validated_output = NamedOutput::new(
        oracle.output.port.clone(),
        oracle.output.fact.clone(),
        oracle.output.extensions.clone(),
    )
    .map_err(AttesterError::Protocol)?;
    let contract = author_data_model_spec();
    let [source_port] = contract.input_ports.as_slice() else {
        return Err(AttesterError::ContractShape);
    };
    let [model_port] = contract.output_ports.as_slice() else {
        return Err(AttesterError::ContractShape);
    };
    if validated_output != oracle.output
        || oracle.source_coordinate != SOURCE_COORDINATE
        || source_port.value_kind != authored_entity_spec_value_kind()
        || oracle.source.value_kind != source_port.value_kind
        || oracle
            .source
            .payload
            .get("origin")
            .and_then(serde_json::Value::as_str)
            != Some(SOURCE_COORDINATE)
        || oracle.output.port != model_port.name
        || oracle.output.fact.value_kind != model_port.value_kind
    {
        return Err(AttesterError::OracleCoordinate);
    }
    Ok(oracle)
}

fn check(passed: bool, evidence: &EvidenceRef) -> Result<ConformanceCheck, AttesterError> {
    ConformanceCheck::new(
        if passed {
            AssessmentOutcome::Passed
        } else {
            AssessmentOutcome::Failed
        },
        vec![evidence.clone()],
        BTreeMap::new(),
    )
    .map_err(AttesterError::Authority)
}

fn source_matches(invocation: &CapabilityInvocation, expected: &Fact) -> bool {
    let [input] = invocation.inputs.as_slice() else {
        return false;
    };
    let contract = author_data_model_spec();
    let [source_port] = contract.input_ports.as_slice() else {
        return false;
    };
    input.port == source_port.name && input.fact == *expected
}

fn output_matches(result: &CapabilityResult, expected: &NamedOutput) -> bool {
    let CapabilityOutcome::Produced { outputs, .. } = &result.outcome else {
        return false;
    };
    outputs.as_slice() == std::slice::from_ref(expected)
}

fn oracle_evidence() -> Result<EvidenceRef, AttesterError> {
    EvidenceRef::new(
        EvidenceKindId::new("org.gooi.evidence", "conformance_oracle", "1.0.0"),
        EvidenceDigest::parse(sha256_identity(ORACLE_BYTES))
            .map_err(|error| AttesterError::Oracle(error.to_string()))?,
        ORACLE_LOCATOR,
        BTreeMap::new(),
    )
    .map_err(AttesterError::Protocol)
}

fn sha256_identity(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(7 + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// A refusal to produce an assessment from malformed or unsupported input.
#[derive(Debug)]
pub enum AttesterError {
    RequestProtocolMismatch { actual: String },
    Protocol(ProtocolError),
    Authority(AuthorityError),
    Oracle(String),
    OracleCoordinate,
    ContractShape,
    ResultCandidateMismatch,
    UnsupportedSuite(ConformanceSuiteId),
}

impl fmt::Display for AttesterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestProtocolMismatch { actual } => write!(
                formatter,
                "unsupported assessment request protocol {actual}; expected {ASSESSMENT_REQUEST_PROTOCOL}"
            ),
            Self::Protocol(error) => write!(formatter, "invalid capability chain: {error}"),
            Self::Authority(error) => write!(formatter, "assessment construction failed: {error}"),
            Self::Oracle(error) => write!(formatter, "checked-in oracle is invalid: {error}"),
            Self::OracleCoordinate => {
                formatter.write_str("checked-in oracle has unexpected fixture coordinates")
            }
            Self::ContractShape => formatter.write_str(
                "author-data-model contract is not the expected one-input, one-output promise",
            ),
            Self::ResultCandidateMismatch => {
                formatter.write_str("candidate does not contain the supplied result")
            }
            Self::UnsupportedSuite(suite) => {
                write!(formatter, "invocation requests unsupported suite {suite}")
            }
        }
    }
}

impl Error for AttesterError {}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;
    use std::process::Command;

    use gooir_capability::authority::{AssessmentOutcome, AuthorityError};
    use gooir_capability::protocol::{
        AdmittedFactRef, AuthorityRecordId, CapabilityOffer, ImplementationSelection, LinkedInput,
    };
    use gooir_capability::{CapabilitySpec, OutputPort, PortName};
    use serde_json::{Value, json};

    use super::*;

    fn digest(byte: char) -> ArtifactDigest {
        ArtifactDigest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn request_evidence(byte: char) -> EvidenceRef {
        EvidenceRef::new(
            EvidenceKindId::new("test.evidence", "host-result", "1.0.0"),
            EvidenceDigest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap(),
            format!("test:host-result:{byte}"),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn producer() -> ImplementationId {
        ImplementationId::new("org.gooi.implementation", "entity_spec_rust", "1.1.0")
    }

    fn admitted(fact: Fact) -> LinkedInput {
        let authority = AuthorityRecordId::parse(format!("sha256:{}", "1".repeat(64))).unwrap();
        let reference = AdmittedFactRef::new(fact.id.clone(), authority, BTreeMap::new()).unwrap();
        let source_port = author_data_model_spec().input_ports.remove(0).name;
        LinkedInput::new(source_port, reference, fact, BTreeMap::new()).unwrap()
    }

    fn invocation_with(
        specification: CapabilitySpec,
        source: Fact,
        producer: ImplementationId,
        producer_artifact: ArtifactDigest,
    ) -> CapabilityInvocation {
        let offer = CapabilityOffer::new(
            producer,
            producer_artifact,
            specification.id.clone(),
            BTreeMap::new(),
        )
        .unwrap();
        CapabilityInvocation::new(
            specification,
            ImplementationSelection::new(offer, BTreeMap::new()).unwrap(),
            vec![admitted(source)],
            suite_id(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn chain_with(
        specification: CapabilitySpec,
        source: Fact,
        output: NamedOutput,
        producer: ImplementationId,
        producer_artifact: ArtifactDigest,
    ) -> (CapabilityInvocation, CapabilityResult, CapabilityCandidate) {
        let invocation = invocation_with(specification, source, producer, producer_artifact);
        let result = CapabilityResult::produced(
            &invocation,
            vec![output],
            BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let candidate =
            CapabilityCandidate::new(&invocation, result.clone(), BTreeMap::new()).unwrap();
        (invocation, result, candidate)
    }

    fn valid_chain() -> (CapabilityInvocation, CapabilityResult, CapabilityCandidate) {
        let oracle = load_oracle(ORACLE_BYTES).unwrap();
        chain_with(
            author_data_model_spec(),
            oracle.source,
            oracle.output,
            producer(),
            digest('a'),
        )
    }

    fn evidenced_chain() -> (CapabilityInvocation, CapabilityResult, CapabilityCandidate) {
        let (invocation, result, _) = valid_chain();
        let CapabilityOutcome::Produced {
            outputs,
            extensions,
        } = result.outcome
        else {
            unreachable!()
        };
        let result = CapabilityResult::produced(
            &invocation,
            outputs,
            extensions,
            vec![request_evidence('e')],
            result.extensions,
        )
        .unwrap();
        let candidate =
            CapabilityCandidate::new(&invocation, result.clone(), BTreeMap::new()).unwrap();
        (invocation, result, candidate)
    }

    fn assert_failed(assessment: &ConformanceAssessment, check_name: &str) {
        assert_eq!(assessment.outcome, AssessmentOutcome::Failed);
        assert_eq!(
            assessment.checks[check_name].outcome,
            AssessmentOutcome::Failed
        );
    }

    #[test]
    fn exact_oracle_chain_passes_with_nonempty_deterministic_checks() {
        let (invocation, result, candidate) = valid_chain();
        let assessment = assess(&invocation, &result, &candidate, digest('b')).unwrap();
        assert_eq!(assessment.outcome, AssessmentOutcome::Passed);
        assert_eq!(assessment.authority.suite, suite_id());
        assert_eq!(
            assessment.authority.attester.implementation,
            implementation_id()
        );
        assert_eq!(assessment.authority.attester.artifact_digest, digest('b'));
        assert_eq!(assessment.checks.len(), 3);
        assert!(
            assessment
                .checks
                .values()
                .all(|check| check.outcome == AssessmentOutcome::Passed
                    && !check.evidence.is_empty())
        );
        assert!(!assessment.evidence.is_empty());
    }

    #[test]
    fn public_assessment_request_round_trips_and_drives_the_exact_attester() {
        let (invocation, result, candidate) = evidenced_chain();
        let request = AssessmentRequest::new(
            invocation.clone(),
            result.clone(),
            candidate.clone(),
            digest('b'),
        )
        .unwrap();

        assert_eq!(request.invocation(), &invocation);
        assert_eq!(request.result(), &result);
        assert_eq!(request.candidate(), &candidate);
        assert_eq!(request.attester_artifact_digest(), &digest('b'));
        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded: AssessmentRequest = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, request);
        decoded.validate().unwrap();

        let assessment = decoded.assess().unwrap();
        assert_eq!(assessment.outcome, AssessmentOutcome::Passed);
        assert_eq!(assessment.result_id, result.result_id);
        assert_eq!(assessment.candidate_id, candidate.candidate_id);
        assert_eq!(assessment.authority.attester.artifact_digest, digest('b'));
    }

    #[test]
    fn assessment_request_rejects_unknown_fields_and_wrong_protocol_version() {
        let (invocation, result, candidate) = evidenced_chain();
        let request = AssessmentRequest::new(invocation, result, candidate, digest('b')).unwrap();
        let mut unknown = serde_json::to_value(&request).unwrap();
        unknown["lease_token"] = json!("must-not-enter-attester-wire");
        assert!(serde_json::from_value::<AssessmentRequest>(unknown).is_err());

        let mut wrong_protocol = serde_json::to_value(request).unwrap();
        wrong_protocol["protocol"] =
            json!("org.gooi.conformance.author-data-model-tasks-entities/request/v2");
        let wrong_protocol: AssessmentRequest = serde_json::from_value(wrong_protocol).unwrap();
        assert!(matches!(
            wrong_protocol.validate(),
            Err(AttesterError::RequestProtocolMismatch { .. })
        ));
    }

    #[test]
    fn assessment_request_rejects_chain_and_attester_substitution() {
        let (invocation, result, candidate) = evidenced_chain();
        let CapabilityOutcome::Produced {
            outputs,
            extensions,
        } = &result.outcome
        else {
            unreachable!()
        };
        let substituted_result = CapabilityResult::produced(
            &invocation,
            outputs.clone(),
            extensions.clone(),
            vec![request_evidence('f')],
            result.extensions.clone(),
        )
        .unwrap();
        let substituted_candidate =
            CapabilityCandidate::new(&invocation, substituted_result, BTreeMap::new()).unwrap();
        assert!(matches!(
            AssessmentRequest::new(
                invocation.clone(),
                result,
                substituted_candidate,
                digest('b')
            ),
            Err(AttesterError::ResultCandidateMismatch)
        ));

        assert!(matches!(
            AssessmentRequest::new(invocation, candidate.result.clone(), candidate, digest('a')),
            Err(AttesterError::Authority(
                AuthorityError::AttesterNotIndependent
            ))
        ));
    }

    #[test]
    fn assessment_request_does_not_invent_a_host_evidence_requirement() {
        let (invocation, result, candidate) = valid_chain();
        assert!(result.evidence.is_empty());
        let request = AssessmentRequest::new(invocation, result, candidate, digest('b')).unwrap();
        assert_eq!(request.assess().unwrap().outcome, AssessmentOutcome::Passed);
    }

    #[test]
    fn structurally_valid_wrong_source_output_and_port_are_failed_assessments() {
        let oracle = load_oracle(ORACLE_BYTES).unwrap();
        let wrong_source = Fact::new(
            authored_entity_spec_value_kind(),
            json!({"origin": SOURCE_COORDINATE, "text": "entity Other\n  id uuid pk"}),
        )
        .unwrap();
        let (invocation, result, candidate) = chain_with(
            author_data_model_spec(),
            wrong_source,
            oracle.output.clone(),
            producer(),
            digest('a'),
        );
        assert_failed(
            &assess(&invocation, &result, &candidate, digest('b')).unwrap(),
            CHECK_SOURCE,
        );

        let model_port = author_data_model_spec().output_ports.remove(0);
        let wrong_fact = Fact::new(model_port.value_kind, json!({"not": "the oracle"})).unwrap();
        let wrong_output = NamedOutput::new(model_port.name, wrong_fact, BTreeMap::new()).unwrap();
        let (invocation, result, candidate) = chain_with(
            author_data_model_spec(),
            oracle.source.clone(),
            wrong_output,
            producer(),
            digest('a'),
        );
        assert_failed(
            &assess(&invocation, &result, &candidate, digest('b')).unwrap(),
            CHECK_OUTPUT,
        );

        let mut wrong_specification = author_data_model_spec();
        let model_kind = wrong_specification.output_ports[0].value_kind.clone();
        let different = PortName::parse("different").unwrap();
        wrong_specification.output_ports[0] = OutputPort::new(different.clone(), model_kind);
        let wrong_port = NamedOutput::new(different, oracle.output.fact, BTreeMap::new()).unwrap();
        let (invocation, result, candidate) = chain_with(
            wrong_specification,
            oracle.source,
            wrong_port,
            producer(),
            digest('a'),
        );
        let assessment = assess(&invocation, &result, &candidate, digest('b')).unwrap();
        assert_failed(&assessment, CHECK_CAPABILITY);
        assert_failed(&assessment, CHECK_OUTPUT);
    }

    #[test]
    fn malformed_or_correlation_invalid_chains_are_errors() {
        let (invocation, result, candidate) = valid_chain();
        let mut invalid_result = result.clone();
        let CapabilityOutcome::Produced { outputs, .. } = &mut invalid_result.outcome else {
            unreachable!()
        };
        outputs[0].fact.payload = json!({"tampered": true});
        assert!(matches!(
            assess(&invocation, &invalid_result, &candidate, digest('b')),
            Err(AttesterError::Protocol(_))
        ));

        let oracle = load_oracle(ORACLE_BYTES).unwrap();
        let (other_invocation, _, other_candidate) = chain_with(
            author_data_model_spec(),
            oracle.source,
            oracle.output,
            producer(),
            digest('c'),
        );
        assert_ne!(invocation, other_invocation);
        assert!(matches!(
            assess(&invocation, &result, &other_candidate, digest('b')),
            Err(AttesterError::Protocol(_))
        ));
    }

    #[test]
    fn attester_must_be_independent_by_implementation_and_artifact() {
        let oracle = load_oracle(ORACLE_BYTES).unwrap();
        let (invocation, result, candidate) = chain_with(
            author_data_model_spec(),
            oracle.source.clone(),
            oracle.output.clone(),
            implementation_id(),
            digest('a'),
        );
        assert!(matches!(
            assess(&invocation, &result, &candidate, digest('b')),
            Err(AttesterError::Authority(
                AuthorityError::AttesterNotIndependent
            ))
        ));

        let (invocation, result, candidate) = chain_with(
            author_data_model_spec(),
            oracle.source,
            oracle.output,
            producer(),
            digest('b'),
        );
        assert!(matches!(
            assess(&invocation, &result, &candidate, digest('b')),
            Err(AttesterError::Authority(
                AuthorityError::AttesterNotIndependent
            ))
        ));
    }

    #[test]
    fn checked_in_oracle_is_exactly_pinned_and_tampering_breaks_fact_identity() {
        let oracle = load_oracle(ORACLE_BYTES).unwrap();
        assert_eq!(oracle.source_coordinate, SOURCE_COORDINATE);
        assert_eq!(
            oracle.source.payload["text"].as_str().unwrap(),
            include_str!("../../../examples/tasks.entities")
        );
        oracle.source.validate().unwrap();
        oracle.output.fact.validate().unwrap();

        let mut tampered: Value = serde_json::from_slice(ORACLE_BYTES).unwrap();
        tampered["source"]["payload"]["text"] = json!("changed without a new fact identity");
        let tampered = serde_json::to_vec(&tampered).unwrap();
        assert!(matches!(
            load_oracle(&tampered),
            Err(AttesterError::Oracle(_))
        ));

        let evidence = oracle_evidence().unwrap();
        assert_eq!(evidence.digest.as_str(), sha256_identity(ORACLE_BYTES));
        assert_eq!(evidence.locator, ORACLE_LOCATOR);
    }

    #[test]
    fn public_fixture_source_is_the_exact_validated_oracle_input() {
        let expected = load_oracle(ORACLE_BYTES).unwrap().source;
        let exposed = tasks_entities_source_fact().unwrap();

        assert_eq!(exposed, expected);
        exposed.validate().unwrap();

        let mut changed = exposed;
        changed.payload["text"] = json!("changed without a new fact identity");
        assert!(changed.validate().is_err());
    }

    #[test]
    fn assessment_replays_exactly_and_measured_artifact_changes_authority() {
        let (invocation, result, candidate) = valid_chain();
        let first = assess(&invocation, &result, &candidate, digest('b')).unwrap();
        let replay = assess(&invocation, &result, &candidate, digest('b')).unwrap();
        assert_eq!(first, replay);

        let different = assess(&invocation, &result, &candidate, digest('c')).unwrap();
        assert_eq!(different.outcome, AssessmentOutcome::Passed);
        assert_ne!(first.authority, different.authority);
        assert_ne!(first.assessment_id, different.assessment_id);
    }

    #[test]
    fn dependency_closure_excludes_the_producer_and_its_pack() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        let output = Command::new(env!("CARGO"))
            .args(["metadata", "--format-version", "1", "--locked", "--offline"])
            .current_dir(workspace)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
        let packages = metadata["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|package| {
                (
                    package["id"].as_str().unwrap().to_owned(),
                    package["name"].as_str().unwrap().to_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let nodes = metadata["resolve"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|node| {
                (
                    node["id"].as_str().unwrap().to_owned(),
                    node["deps"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|dependency| dependency["pkg"].as_str().unwrap().to_owned())
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let root = packages
            .iter()
            .find_map(|(id, name)| (name == env!("CARGO_PKG_NAME")).then_some(id.clone()))
            .unwrap();
        let mut pending = vec![root];
        let mut seen = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if seen.insert(id.clone())
                && let Some(dependencies) = nodes.get(&id)
            {
                pending.extend(dependencies.iter().cloned());
            }
        }
        let names = seen
            .iter()
            .filter_map(|id| packages.get(id))
            .collect::<BTreeSet<_>>();
        assert!(!names.contains(&"entity-spec".to_owned()));
        assert!(!names.contains(&"gooir-datamodel-pack".to_owned()));
        assert!(!names.contains(&"gooir-provider".to_owned()));
    }

    #[test]
    fn assessment_documents_contain_no_host_or_admission_fields() {
        let (invocation, result, candidate) = valid_chain();
        let assessment = assess(&invocation, &result, &candidate, digest('b')).unwrap();
        let value = serde_json::to_value(assessment).unwrap();
        assert_no_forbidden_keys(
            &value,
            &[
                "policy",
                "admission",
                "coverage",
                "fleetd",
                "host",
                "process",
                "transport",
                "lease",
                "session",
                "retry",
                "credential",
                "deadline",
                "owner",
                "persistence",
            ],
        );
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
