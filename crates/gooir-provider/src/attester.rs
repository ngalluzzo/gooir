//! Neutral v1 authoring and stdio framing for independent attesters.
//!
//! The execution host selects and measures an attester artifact. This module
//! only validates the complete candidate chain, binds the selected authority
//! to the attester's exact suite and implementation identity, and constructs
//! one neutral [`ConformanceAssessment`]. Process lifecycle and artifact
//! measurement remain host responsibilities.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io::{Read, Write};

pub use gooir_capability::assessment::{ASSESSMENT_REQUEST_PROTOCOL, AssessmentRequest};
use gooir_capability::authority::{ConformanceAssessment, ConformanceCheck};
use gooir_capability::protocol::{ConformanceSuiteId, EvidenceRef, ImplementationId};
use gooir_capability::strict_json;
use serde_json::Value;

/// One exact neutral conformance implementation.
#[derive(Clone, Debug)]
pub struct Attester {
    suite: ConformanceSuiteId,
    implementation: ImplementationId,
}

impl Attester {
    /// Binds authoring code to one suite and implementation identity.
    pub fn new(
        suite: ConformanceSuiteId,
        implementation: ImplementationId,
    ) -> Result<Self, AttesterError> {
        if !suite.is_well_formed() {
            return Err(AttesterError::InvalidSuite(suite));
        }
        if !implementation.is_well_formed() {
            return Err(AttesterError::InvalidImplementation(implementation));
        }
        Ok(Self {
            suite,
            implementation,
        })
    }

    /// Validates and independently assesses one complete request.
    pub fn assess<F>(
        &self,
        request: &AssessmentRequest,
        handler: F,
    ) -> Result<ConformanceAssessment, AttesterError>
    where
        F: FnOnce(&AssessmentRequest) -> Result<Assessment, AttesterError>,
    {
        request
            .validate()
            .map_err(|error| AttesterError::Request(error.to_string()))?;
        if request.authority().suite != self.suite {
            return Err(AttesterError::SuiteMismatch {
                expected: Box::new(self.suite.clone()),
                actual: Box::new(request.authority().suite.clone()),
            });
        }
        if request.authority().attester.implementation != self.implementation {
            return Err(AttesterError::ImplementationMismatch {
                expected: Box::new(self.implementation.clone()),
                actual: Box::new(request.authority().attester.implementation.clone()),
            });
        }
        let authored = handler(request)?;
        ConformanceAssessment::new(
            request.invocation(),
            request.result(),
            request.candidate(),
            request.authority().clone(),
            authored.checks,
            authored.evidence,
            authored.extensions,
        )
        .map_err(|error| AttesterError::Authority(error.to_string()))
    }

    /// Parses one request document and returns one assessment document.
    pub fn assess_json<F>(&self, input: &str, handler: F) -> Result<String, AttesterError>
    where
        F: FnOnce(&AssessmentRequest) -> Result<Assessment, AttesterError>,
    {
        let request = strict_json::from_str(input)
            .map_err(|error| AttesterError::RequestJson(error.to_string()))?;
        let assessment = self.assess(&request, handler)?;
        serde_json::to_string(&assessment)
            .map_err(|error| AttesterError::AssessmentJson(error.to_string()))
    }

    /// Serves one complete assessment over caller-supplied streams.
    pub fn serve_once<R, W, F>(
        &self,
        mut input: R,
        mut output: W,
        handler: F,
    ) -> Result<(), AttesterError>
    where
        R: Read,
        W: Write,
        F: FnOnce(&AssessmentRequest) -> Result<Assessment, AttesterError>,
    {
        let mut document = String::new();
        input
            .read_to_string(&mut document)
            .map_err(|error| AttesterError::Io(error.to_string()))?;
        let assessment = self.assess_json(&document, handler)?;
        output
            .write_all(assessment.as_bytes())
            .and_then(|()| output.flush())
            .map_err(|error| AttesterError::Io(error.to_string()))
    }

    /// Serves one complete assessment over stdin/stdout.
    ///
    /// Process lifecycle, byte limits, deadlines, and artifact measurement
    /// remain external-host concerns.
    pub fn serve_stdio<F>(&self, handler: F) -> Result<(), AttesterError>
    where
        F: FnOnce(&AssessmentRequest) -> Result<Assessment, AttesterError>,
    {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        self.serve_once(stdin.lock(), stdout.lock(), handler)
    }
}

/// Authored checks and evidence before exact assessment framing.
#[derive(Clone, Debug)]
pub struct Assessment {
    checks: BTreeMap<String, ConformanceCheck>,
    evidence: Vec<EvidenceRef>,
    extensions: BTreeMap<String, Value>,
}

impl Assessment {
    /// Creates one assessment body. Exact check validation and aggregate
    /// outcome derivation happen when [`Attester::assess`] frames it.
    #[must_use]
    pub fn new(checks: BTreeMap<String, ConformanceCheck>) -> Self {
        Self {
            checks,
            evidence: Vec::new(),
            extensions: BTreeMap::new(),
        }
    }

    /// Adds exact evidence references to the complete assessment.
    #[must_use]
    pub fn with_evidence(mut self, evidence: impl IntoIterator<Item = EvidenceRef>) -> Self {
        self.evidence.extend(evidence);
        self
    }

    /// Adds explicitly handled assessment extensions.
    #[must_use]
    pub fn with_extensions(mut self, extensions: BTreeMap<String, Value>) -> Self {
        self.extensions = extensions;
        self
    }
}

/// Attester authoring or framing failure.
#[derive(Debug)]
pub enum AttesterError {
    InvalidSuite(ConformanceSuiteId),
    InvalidImplementation(ImplementationId),
    Request(String),
    Authority(String),
    SuiteMismatch {
        expected: Box<ConformanceSuiteId>,
        actual: Box<ConformanceSuiteId>,
    },
    ImplementationMismatch {
        expected: Box<ImplementationId>,
        actual: Box<ImplementationId>,
    },
    Implementation(String),
    RequestJson(String),
    AssessmentJson(String),
    Io(String),
}

impl AttesterError {
    /// Converts an attester implementation failure into a framing error.
    pub fn implementation(error: impl fmt::Display) -> Self {
        Self::Implementation(error.to_string())
    }
}

impl fmt::Display for AttesterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSuite(suite) => write!(formatter, "invalid conformance suite `{suite}`"),
            Self::InvalidImplementation(implementation) => {
                write!(
                    formatter,
                    "invalid attester implementation `{implementation}`"
                )
            }
            Self::Request(detail) => write!(formatter, "invalid assessment request: {detail}"),
            Self::Authority(detail) => write!(formatter, "invalid conformance authority: {detail}"),
            Self::SuiteMismatch { expected, actual } => write!(
                formatter,
                "assessment suite `{actual}` does not match attester suite `{expected}`"
            ),
            Self::ImplementationMismatch { expected, actual } => write!(
                formatter,
                "assessment implementation `{actual}` does not match attester `{expected}`"
            ),
            Self::Implementation(detail) => {
                write!(formatter, "attester implementation failed: {detail}")
            }
            Self::RequestJson(detail) => {
                write!(
                    formatter,
                    "assessment request JSON cannot be decoded: {detail}"
                )
            }
            Self::AssessmentJson(detail) => {
                write!(formatter, "assessment JSON cannot be encoded: {detail}")
            }
            Self::Io(detail) => write!(formatter, "attester stdio failed: {detail}"),
        }
    }
}

impl Error for AttesterError {}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use gooir_capability::Fact;
    use gooir_capability::authority::{
        AssessmentOutcome, ConformanceAttester, ConformanceAuthority, ConformanceCheck,
    };
    use gooir_capability::protocol::{
        AdmittedFactRef, ArtifactDigest, AuthorityRecordId, CapabilityCandidate,
        CapabilityInvocation, CapabilityOffer, CapabilityResult, ImplementationSelection,
        LinkedInput, NamedOutput,
    };
    use gooir_capability::{
        CapabilityId, CapabilitySpec, InputPort, OutputPort, PortName, ValueKindId,
    };
    use serde_json::json;

    use super::*;

    struct Fixture {
        request: AssessmentRequest,
        attester: Attester,
    }

    fn fixture() -> Fixture {
        let source_kind = ValueKindId::new("test.value", "source", "1.0.0");
        let target_kind = ValueKindId::new("test.value", "target", "1.0.0");
        let specification = CapabilitySpec {
            id: CapabilityId::new("test.capability", "copy", "1.0.0"),
            input_ports: vec![InputPort::complete(port("source"), source_kind.clone())],
            output_ports: vec![OutputPort::new(port("target"), target_kind.clone())],
            default_conformance_suite: suite().to_string(),
            extensions: BTreeMap::new(),
        };
        let offer = CapabilityOffer::new(
            ImplementationId::new("test.provider", "copy", "1.0.0"),
            artifact('a'),
            specification.id.clone(),
            BTreeMap::new(),
        )
        .unwrap();
        let source = Fact::new(source_kind, json!({"value": 1})).unwrap();
        let invocation = CapabilityInvocation::new(
            specification,
            ImplementationSelection::new(offer, BTreeMap::new()).unwrap(),
            vec![
                LinkedInput::new(
                    port("source"),
                    AdmittedFactRef::new(
                        source.id.clone(),
                        AuthorityRecordId::parse(sha('c')).unwrap(),
                        BTreeMap::new(),
                    )
                    .unwrap(),
                    source,
                    BTreeMap::new(),
                )
                .unwrap(),
            ],
            suite(),
            BTreeMap::new(),
        )
        .unwrap();
        let result = CapabilityResult::produced(
            &invocation,
            vec![
                NamedOutput::new(
                    port("target"),
                    Fact::new(target_kind, json!({"value": 1})).unwrap(),
                    BTreeMap::new(),
                )
                .unwrap(),
            ],
            BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let candidate =
            CapabilityCandidate::new(&invocation, result.clone(), BTreeMap::new()).unwrap();
        let implementation = ImplementationId::new("test.attester", "exact", "1.0.0");
        let authority = ConformanceAuthority::new(
            suite(),
            ConformanceAttester::new(implementation.clone(), artifact('b'), BTreeMap::new())
                .unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        Fixture {
            request: AssessmentRequest::new(invocation, result, candidate, authority).unwrap(),
            attester: Attester::new(suite(), implementation).unwrap(),
        }
    }

    #[test]
    fn serve_once_frames_one_exact_independent_assessment() {
        let fixture = fixture();
        let input = serde_json::to_vec(&fixture.request).unwrap();
        let mut output = Vec::new();

        fixture
            .attester
            .serve_once(input.as_slice(), &mut output, |_| {
                Ok(Assessment::new(BTreeMap::from([(
                    "semantic".to_owned(),
                    ConformanceCheck::new(AssessmentOutcome::Passed, Vec::new(), BTreeMap::new())
                        .unwrap(),
                )])))
            })
            .unwrap();

        let assessment: ConformanceAssessment = serde_json::from_slice(&output).unwrap();
        assessment
            .validate_against(
                fixture.request.invocation(),
                fixture.request.result(),
                fixture.request.candidate(),
            )
            .unwrap();
        assert_eq!(assessment.authority, *fixture.request.authority());
        assert_eq!(assessment.outcome, AssessmentOutcome::Passed);
    }

    #[test]
    fn request_is_closed_and_handler_never_runs_for_identity_substitution() {
        let fixture = fixture();
        let mut encoded = serde_json::to_value(&fixture.request).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), json!(true));
        assert!(serde_json::from_value::<AssessmentRequest>(encoded).is_err());

        let wrong = Attester::new(
            suite(),
            ImplementationId::new("test.attester", "other", "1.0.0"),
        )
        .unwrap();
        let called = Cell::new(false);
        let error = wrong
            .assess(&fixture.request, |_| {
                called.set(true);
                unreachable!("identity mismatch must stop before semantic checks")
            })
            .unwrap_err();
        assert!(matches!(
            error,
            AttesterError::ImplementationMismatch { .. }
        ));
        assert!(!called.get());
    }

    #[test]
    fn assessment_request_rejects_nested_duplicate_payload_keys() {
        let fixture = fixture();
        let encoded = serde_json::to_string(&fixture.request).unwrap();
        let duplicate = encoded.replacen(
            r#""payload":{"value":1}"#,
            r#""payload":{"value":1,"value":2}"#,
            1,
        );
        assert_ne!(
            duplicate, encoded,
            "fixture must contain the nested payload"
        );

        let error = fixture
            .attester
            .assess_json(&duplicate, |_| {
                unreachable!("duplicate keys must fail before semantic assessment")
            })
            .unwrap_err();

        assert!(matches!(
            error,
            AttesterError::RequestJson(detail)
                if detail.contains("duplicate JSON object key `value`")
        ));
    }

    fn suite() -> ConformanceSuiteId {
        ConformanceSuiteId::new("test.conformance", "exact", "1.0.0")
    }

    fn artifact(byte: char) -> ArtifactDigest {
        ArtifactDigest::parse(sha(byte)).unwrap()
    }

    fn sha(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn port(name: &str) -> PortName {
        PortName::parse(name).unwrap()
    }
}
