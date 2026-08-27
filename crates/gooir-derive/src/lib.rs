//! Synchronous host and admission membrane for one linked capability invocation.
//!
//! This crate neither selects graph routes nor defines an execution transport.
//! It accepts an already-linked invocation, resolves every exact input against
//! contextual admission state, and turns host output into linkable authority
//! records only after independent conformance and local admission.

use std::error::Error;
use std::fmt;

use gooir_capability::PortName;
use gooir_capability::authority::{
    AdmissionDecision, AdmissionDenial, AdmissionLedger, AdmissionOutcome, AdmissionPolicy,
    AdmissionVerdict, AuthorityError, AuthorityRecord, ConformanceAssessment, ConformanceAuthority,
};
use gooir_capability::protocol::{
    CapabilityCandidate, CapabilityFailure, CapabilityInvocation, CapabilityOutcome,
    CapabilityResult, ProtocolError,
};
use serde::{Deserialize, Serialize};

mod driver;
mod facade;
mod local_stdio;

pub use driver::*;
pub use facade::*;
pub use local_stdio::*;

/// Effectful operations supplied by an execution host for one linked invocation.
///
/// Invocation and assessment remain separate calls. The returned assessment is
/// still untrusted: the membrane validates that it is content-bound to the
/// candidate and was produced by an implementation independent of the selected
/// provider.
pub trait DerivationHost {
    /// Host-local failure type. It is deliberately not part of serialized
    /// derivation data.
    type Error;

    /// Invoke the exact implementation already selected by `invocation`.
    ///
    /// # Errors
    ///
    /// Returns a host-local error when the host cannot perform the invocation.
    fn invoke(
        &mut self,
        invocation: &CapabilityInvocation,
    ) -> Result<CapabilityResult, Self::Error>;

    /// Independently assess the exact candidate produced by `invoke`.
    ///
    /// # Errors
    ///
    /// Returns a host-local error when the host cannot perform the assessment.
    fn assess(
        &mut self,
        invocation: &CapabilityInvocation,
        result: &CapabilityResult,
        candidate: &CapabilityCandidate,
        authority: &ConformanceAuthority,
    ) -> Result<ConformanceAssessment, Self::Error>;
}

/// One output that became linkable through its complete authority record.
///
/// The fact is intentionally not duplicated as a bare field. It is available
/// as `authority.fact` together with the exact derivation and admission chain.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AdmittedOutput {
    pub port: PortName,
    pub authority: AuthorityRecord,
}

/// Neutral documents available from one exact host attempt.
///
/// A result or assessment may be retained here even when its validation
/// failed; presence records what crossed the host membrane, not endorsement.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttemptDocuments {
    pub invocation: CapabilityInvocation,
    pub result: Option<CapabilityResult>,
    pub candidate: Option<CapabilityCandidate>,
    pub assessment: Option<ConformanceAssessment>,
}

/// Successful admission of every output from one candidate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AdmittedDerivation {
    pub documents: AttemptDocuments,
    pub decision: AdmissionDecision,
    pub outputs: Vec<AdmittedOutput>,
}

/// A validated assessment and the exact decision that withheld its candidate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WithheldDerivation {
    pub documents: AttemptDocuments,
    pub decision: AdmissionDecision,
}

/// A complete validated provider inability, retained with its envelope.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProviderUnableDerivation {
    pub documents: AttemptDocuments,
    pub failure: CapabilityFailure,
}

/// Stable data outcomes from executing one already-linked invocation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", content = "detail", rename_all = "snake_case")]
pub enum LinkedInvocationOutcome {
    Admitted(Box<AdmittedDerivation>),
    ProviderUnable(Box<ProviderUnableDerivation>),
    AuthorityNotAccepted(Box<WithheldDerivation>),
    ConformanceFailed(Box<WithheldDerivation>),
    ConformanceIndeterminate(Box<WithheldDerivation>),
}

/// Failure of the host/admission membrane itself.
///
/// Host-local errors remain generic and are never serialized. Protocol and
/// authority errors remain typed so callers can distinguish substitution from
/// transport or provider failure.
#[derive(Debug)]
pub enum LinkedInvocationError<E> {
    InvalidInvocation(ProtocolError),
    InvalidPolicy(AuthorityError),
    InvalidAttester(AuthorityError),
    UnresolvedInput {
        port: PortName,
        error: AuthorityError,
    },
    SubstitutedInput {
        port: PortName,
        error: AuthorityError,
    },
    InvalidInputAuthority {
        port: PortName,
        error: AuthorityError,
    },
    HostInvocation(E),
    InvalidHostResult {
        documents: Box<AttemptDocuments>,
        error: ProtocolError,
    },
    HostAssessment {
        documents: Box<AttemptDocuments>,
        error: E,
    },
    InvalidHostAssessment {
        documents: Box<AttemptDocuments>,
        error: AuthorityError,
    },
    SubstitutedAttester {
        documents: Box<AttemptDocuments>,
        expected: Box<ConformanceAuthority>,
        actual: Box<ConformanceAuthority>,
    },
    Admission {
        documents: Box<AttemptDocuments>,
        error: AuthorityError,
    },
    AdmissionReturnedSourceLink {
        documents: Box<AttemptDocuments>,
    },
    AdmittedOutputUnresolvable {
        documents: Box<AttemptDocuments>,
        port: PortName,
        error: AuthorityError,
    },
    UnexpectedAdmissionDecision {
        documents: Box<AttemptDocuments>,
        decision: Box<AdmissionDecision>,
    },
}

impl<E: fmt::Display> fmt::Display for LinkedInvocationError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInvocation(error) => {
                write!(formatter, "invalid linked invocation: {error}")
            }
            Self::InvalidPolicy(error) => write!(formatter, "invalid admission policy: {error}"),
            Self::InvalidAttester(error) => {
                write!(formatter, "invalid selected conformance authority: {error}")
            }
            Self::UnresolvedInput { port, error } => {
                write!(formatter, "input `{port}` is not admitted: {error}")
            }
            Self::SubstitutedInput { port, error } => {
                write!(formatter, "input `{port}` was substituted: {error}")
            }
            Self::InvalidInputAuthority { port, error } => {
                write!(formatter, "input `{port}` has invalid authority: {error}")
            }
            Self::HostInvocation(error) => write!(formatter, "host invocation failed: {error}"),
            Self::InvalidHostResult { error, .. } => {
                write!(formatter, "host result is invalid: {error}")
            }
            Self::HostAssessment { error, .. } => {
                write!(formatter, "host assessment failed: {error}")
            }
            Self::InvalidHostAssessment { error, .. } => {
                write!(formatter, "host assessment is invalid: {error}")
            }
            Self::SubstitutedAttester { .. } => formatter
                .write_str("host assessment substituted the selected conformance authority"),
            Self::Admission { error, .. } => {
                write!(formatter, "candidate admission failed: {error}")
            }
            Self::AdmissionReturnedSourceLink { .. } => {
                formatter.write_str("candidate admission returned a source link")
            }
            Self::AdmittedOutputUnresolvable { port, error, .. } => {
                write!(
                    formatter,
                    "admitted output `{port}` cannot be resolved: {error}"
                )
            }
            Self::UnexpectedAdmissionDecision { decision, .. } => write!(
                formatter,
                "admission returned an outcome inconsistent with decision {}",
                decision.decision_id
            ),
        }
    }
}

impl<E> Error for LinkedInvocationError<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidInvocation(error) | Self::InvalidHostResult { error, .. } => Some(error),
            Self::InvalidPolicy(error)
            | Self::InvalidAttester(error)
            | Self::UnresolvedInput { error, .. }
            | Self::SubstitutedInput { error, .. }
            | Self::InvalidInputAuthority { error, .. }
            | Self::InvalidHostAssessment { error, .. }
            | Self::Admission { error, .. }
            | Self::AdmittedOutputUnresolvable { error, .. } => Some(error),
            Self::HostInvocation(error) | Self::HostAssessment { error, .. } => Some(error),
            Self::SubstitutedAttester { .. }
            | Self::AdmissionReturnedSourceLink { .. }
            | Self::UnexpectedAdmissionDecision { .. } => None,
        }
    }
}

/// Execute, independently assess, and contextually admit one linked invocation.
///
/// Every input is resolved against `ledger` before either host method is
/// called. An `Unable` result is returned directly and never becomes a
/// candidate. Produced facts are returned only inside authority records after
/// atomic admission succeeds.
///
/// # Errors
///
/// Returns a typed membrane error for an invalid invocation or policy,
/// unresolved or substituted input, host invocation or assessment failure,
/// malformed or substituted host document, or admission invariant failure.
pub fn run_linked_invocation<H: DerivationHost>(
    ledger: &mut AdmissionLedger,
    policy: &AdmissionPolicy,
    invocation: &CapabilityInvocation,
    attester: &ConformanceAuthority,
    host: &mut H,
) -> Result<LinkedInvocationOutcome, LinkedInvocationError<H::Error>> {
    preflight_linked_invocation(ledger, policy, invocation, attester)?;
    let mut documents = AttemptDocuments {
        invocation: invocation.clone(),
        result: None,
        candidate: None,
        assessment: None,
    };
    let result = host
        .invoke(invocation)
        .map_err(LinkedInvocationError::HostInvocation)?;
    documents.result = Some(result.clone());
    if let Err(error) = result.validate_against(invocation) {
        return Err(LinkedInvocationError::InvalidHostResult {
            documents: Box::new(documents),
            error,
        });
    }

    if let CapabilityOutcome::Unable { failure, .. } = &result.outcome {
        return Ok(LinkedInvocationOutcome::ProviderUnable(Box::new(
            ProviderUnableDerivation {
                documents,
                failure: failure.clone(),
            },
        )));
    }

    let candidate = match CapabilityCandidate::new(
        invocation,
        result.clone(),
        std::collections::BTreeMap::new(),
    ) {
        Ok(candidate) => candidate,
        Err(error) => {
            return Err(LinkedInvocationError::InvalidHostResult {
                documents: Box::new(documents),
                error,
            });
        }
    };
    documents.candidate = Some(candidate.clone());
    let assessment = match host.assess(invocation, &result, &candidate, attester) {
        Ok(assessment) => assessment,
        Err(error) => {
            return Err(LinkedInvocationError::HostAssessment {
                documents: Box::new(documents),
                error,
            });
        }
    };
    documents.assessment = Some(assessment.clone());
    if let Err(error) = assessment.validate_against(invocation, &result, &candidate) {
        return Err(LinkedInvocationError::InvalidHostAssessment {
            documents: Box::new(documents),
            error,
        });
    }
    if assessment.authority != *attester {
        return Err(LinkedInvocationError::SubstitutedAttester {
            documents: Box::new(documents),
            expected: Box::new(attester.clone()),
            actual: Box::new(assessment.authority.clone()),
        });
    }

    admit_linked_candidate(ledger, policy, invocation, &result, &candidate, documents)
}

fn preflight_linked_invocation<E>(
    ledger: &AdmissionLedger,
    policy: &AdmissionPolicy,
    invocation: &CapabilityInvocation,
    attester: &ConformanceAuthority,
) -> Result<(), LinkedInvocationError<E>> {
    invocation
        .validate()
        .map_err(LinkedInvocationError::InvalidInvocation)?;
    policy
        .validate()
        .map_err(LinkedInvocationError::InvalidPolicy)?;
    attester
        .validate()
        .map_err(LinkedInvocationError::InvalidAttester)?;
    if attester.suite != invocation.conformance_suite {
        return Err(LinkedInvocationError::InvalidAttester(
            AuthorityError::ConformanceSuiteMismatch,
        ));
    }
    if attester.attester.implementation == invocation.selection.offer.implementation
        || attester.attester.artifact_digest == invocation.selection.offer.artifact_digest
    {
        return Err(LinkedInvocationError::InvalidAttester(
            AuthorityError::AttesterNotIndependent,
        ));
    }

    for input in &invocation.inputs {
        let resolved = ledger
            .resolve(&input.admitted)
            .map_err(|error| classify_input_error(input.port.clone(), error))?;
        if resolved.fact != &input.fact {
            return Err(LinkedInvocationError::SubstitutedInput {
                port: input.port.clone(),
                error: AuthorityError::LinkedInputMismatch(input.port.clone()),
            });
        }
    }
    Ok(())
}

fn admit_linked_candidate<E>(
    ledger: &mut AdmissionLedger,
    policy: &AdmissionPolicy,
    invocation: &CapabilityInvocation,
    result: &CapabilityResult,
    candidate: &CapabilityCandidate,
    documents: AttemptDocuments,
) -> Result<LinkedInvocationOutcome, LinkedInvocationError<E>> {
    let assessment = documents
        .assessment
        .as_ref()
        .expect("admission receives an assessed attempt");
    match ledger
        .admit_candidate(policy, invocation, result, candidate, assessment)
        .map_err(|error| LinkedInvocationError::Admission {
            documents: Box::new(documents.clone()),
            error,
        })? {
        AdmissionOutcome::Admitted { decision, links } => {
            let mut outputs = Vec::with_capacity(links.len());
            for link in links {
                let Some(port) = link.port else {
                    return Err(LinkedInvocationError::AdmissionReturnedSourceLink {
                        documents: Box::new(documents),
                    });
                };
                let resolved = ledger.resolve(&link.reference).map_err(|error| {
                    LinkedInvocationError::AdmittedOutputUnresolvable {
                        documents: Box::new(documents.clone()),
                        port: port.clone(),
                        error,
                    }
                })?;
                outputs.push(AdmittedOutput {
                    port,
                    authority: resolved.authority.clone(),
                });
            }
            Ok(LinkedInvocationOutcome::Admitted(Box::new(
                AdmittedDerivation {
                    documents,
                    decision,
                    outputs,
                },
            )))
        }
        AdmissionOutcome::Withheld { decision } => {
            let reason = match &decision.verdict {
                AdmissionVerdict::Withhold { reason, .. } => *reason,
                AdmissionVerdict::Admit { .. } => {
                    return Err(LinkedInvocationError::UnexpectedAdmissionDecision {
                        documents: Box::new(documents),
                        decision: Box::new(decision),
                    });
                }
            };
            let withheld = Box::new(WithheldDerivation {
                documents,
                decision,
            });
            Ok(match reason {
                AdmissionDenial::AuthorityNotAccepted => {
                    LinkedInvocationOutcome::AuthorityNotAccepted(withheld)
                }
                AdmissionDenial::AssessmentFailed => {
                    LinkedInvocationOutcome::ConformanceFailed(withheld)
                }
                AdmissionDenial::AssessmentIndeterminate => {
                    LinkedInvocationOutcome::ConformanceIndeterminate(withheld)
                }
            })
        }
    }
}

fn classify_input_error<E>(port: PortName, error: AuthorityError) -> LinkedInvocationError<E> {
    if matches!(
        &error,
        AuthorityError::UnknownAuthority(_)
            | AuthorityError::MissingFact(_)
            | AuthorityError::MissingDecision(_)
    ) {
        LinkedInvocationError::UnresolvedInput { port, error }
    } else if matches!(
        &error,
        AuthorityError::FactReferenceMismatch
            | AuthorityError::StoredFactMismatch(_)
            | AuthorityError::LinkedInputMismatch(_)
    ) {
        LinkedInvocationError::SubstitutedInput { port, error }
    } else {
        LinkedInvocationError::InvalidInputAuthority { port, error }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::num::NonZeroUsize;

    use gooir_capability::authority::{
        AdmissionAuthorityId, AssessmentOutcome, AuthorityBasis, ConformanceAttester,
        ConformanceAuthority, ConformanceCheck, ObservationAuthority, ObservationSourceId,
        SourceObservation,
    };
    use gooir_capability::protocol::{
        AdmittedFactRef, ArtifactDigest, AuthorityRecordId, CapabilityOffer, ConformanceSuiteId,
        EvidenceDigest, EvidenceKindId, EvidenceRef, FailureKindId, ImplementationId,
        ImplementationSelection, LinkedInput, NamedOutput,
    };
    use gooir_capability::{
        CapabilityId, CapabilitySpec, Fact, FactAcceptance, InputPort, OutputPort, ValueKindId,
        canonical_digest,
    };
    use gooir_package::{
        ConformanceSuiteDeclaration, DialectDeclaration, ImplementationOfferDeclaration,
        LoadLimits, PackageId, PackageManifest, PackageRegistry, PackageResource, ResourceDigest,
        ResourceName, ValueKindDeclaration, load_local_package, write_manifest,
    };
    use gooir_planning::{PlanLimits, RouteId, RouteSelection, SemanticPlanner};
    use serde_json::json;

    use super::*;

    const VERSION: &str = "1.0.0";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ProviderBehavior {
        Produced,
        Unable,
        HostFailure,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum AssessmentBehavior {
        Outcome(AssessmentOutcome),
        ProviderSelfAssessment,
        HostFailure,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestHostError(&'static str);

    impl fmt::Display for TestHostError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl Error for TestHostError {}

    struct TestHost {
        output: Fact,
        provider: ProviderBehavior,
        assessment: AssessmentBehavior,
        invocations: usize,
        assessments: usize,
        seen_invocations: Vec<CapabilityInvocation>,
    }

    impl TestHost {
        fn new(output: Fact) -> Self {
            Self {
                output,
                provider: ProviderBehavior::Produced,
                assessment: AssessmentBehavior::Outcome(AssessmentOutcome::Passed),
                invocations: 0,
                assessments: 0,
                seen_invocations: Vec::new(),
            }
        }
    }

    impl DerivationHost for TestHost {
        type Error = TestHostError;

        fn invoke(
            &mut self,
            invocation: &CapabilityInvocation,
        ) -> Result<CapabilityResult, Self::Error> {
            self.invocations += 1;
            self.seen_invocations.push(invocation.clone());
            match self.provider {
                ProviderBehavior::Produced => CapabilityResult::produced(
                    invocation,
                    vec![
                        NamedOutput::new(port("result"), self.output.clone(), BTreeMap::new())
                            .expect("test output is exact"),
                    ],
                    BTreeMap::new(),
                    Vec::new(),
                    BTreeMap::new(),
                )
                .map_err(|_| TestHostError("could not form result")),
                ProviderBehavior::Unable => CapabilityResult::unable(
                    invocation,
                    CapabilityFailure::new(
                        FailureKindId::new("test.failure", "unable", VERSION),
                        json!({"reason": "fixture"}),
                        BTreeMap::from([("org.test.failure".to_owned(), json!({"kept": true}))]),
                    )
                    .expect("test failure is exact"),
                    BTreeMap::from([("org.test.outcome".to_owned(), json!({"kept": true}))]),
                    Vec::new(),
                    BTreeMap::from([("org.test.result".to_owned(), json!({"kept": true}))]),
                )
                .map_err(|_| TestHostError("could not form inability")),
                ProviderBehavior::HostFailure => Err(TestHostError("secret://provider-token")),
            }
        }

        fn assess(
            &mut self,
            invocation: &CapabilityInvocation,
            result: &CapabilityResult,
            candidate: &CapabilityCandidate,
            authority: &ConformanceAuthority,
        ) -> Result<ConformanceAssessment, Self::Error> {
            self.assessments += 1;
            let outcome = match self.assessment {
                AssessmentBehavior::Outcome(outcome) => outcome,
                AssessmentBehavior::ProviderSelfAssessment => AssessmentOutcome::Passed,
                AssessmentBehavior::HostFailure => {
                    return Err(TestHostError("secret://attester-token"));
                }
            };
            let checks = BTreeMap::from([(
                "semantic".to_owned(),
                ConformanceCheck::new(outcome, Vec::new(), BTreeMap::new())
                    .expect("test check is exact"),
            )]);
            let mut assessment = ConformanceAssessment::new(
                invocation,
                result,
                candidate,
                authority.clone(),
                checks,
                Vec::new(),
                BTreeMap::new(),
            )
            .map_err(|_| TestHostError("could not form assessment"))?;
            if self.assessment == AssessmentBehavior::ProviderSelfAssessment {
                assessment.authority = ConformanceAuthority::new(
                    invocation.conformance_suite.clone(),
                    ConformanceAttester::new(
                        invocation.selection.offer.implementation.clone(),
                        invocation.selection.offer.artifact_digest.clone(),
                        BTreeMap::new(),
                    )
                    .expect("provider coordinates are exact"),
                    BTreeMap::new(),
                )
                .expect("provider self-authority is structurally exact");
            }
            Ok(assessment)
        }
    }

    struct Fixture {
        ledger: AdmissionLedger,
        policy: AdmissionPolicy,
        invocation: CapabilityInvocation,
        output: Fact,
        conformance: ConformanceAuthority,
    }

    fn fixture(accept_conformance: bool) -> Fixture {
        let source_kind = value_kind("source");
        let result_kind = value_kind("result");
        let source = Fact::new(source_kind.clone(), json!({"value": 1})).unwrap();
        let observation_authority = ObservationAuthority::new(
            ObservationSourceId::new("test.source", "fixture", VERSION),
            ImplementationId::new("test.observer", "fixture", VERSION),
            artifact('1'),
            source_kind.clone(),
            EvidenceKindId::new("test.evidence", "source", VERSION),
            BTreeMap::new(),
        )
        .unwrap();
        let conformance = ConformanceAuthority::new(
            suite(),
            ConformanceAttester::new(
                ImplementationId::new("test.attester", "exact", VERSION),
                artifact('b'),
                BTreeMap::new(),
            )
            .unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        let policy = AdmissionPolicy::new(
            AdmissionAuthorityId::new("test.admission", "local", VERSION),
            if accept_conformance {
                vec![conformance.clone()]
            } else {
                Vec::new()
            },
            vec![observation_authority.clone()],
            BTreeMap::new(),
        )
        .unwrap();
        let observation = SourceObservation::new(
            source.clone(),
            observation_authority,
            EvidenceRef::new(
                EvidenceKindId::new("test.evidence", "source", VERSION),
                EvidenceDigest::parse(sha('c')).unwrap(),
                "memory://source",
                BTreeMap::new(),
            )
            .unwrap(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let mut ledger = AdmissionLedger::new();
        let AdmissionOutcome::Admitted { links, .. } =
            ledger.admit_observation(&policy, &observation).unwrap()
        else {
            panic!("source must be admitted");
        };
        let specification = CapabilitySpec {
            id: CapabilityId::new("test.capability", "transform", VERSION),
            input_ports: vec![InputPort {
                name: port("source"),
                value_kind: source_kind,
                acceptance: FactAcceptance::CompleteOnly,
                extensions: BTreeMap::new(),
            }],
            output_ports: vec![OutputPort::new(port("result"), result_kind.clone())],
            default_conformance_suite: suite().to_string(),
            extensions: BTreeMap::new(),
        };
        let offer = CapabilityOffer::new(
            ImplementationId::new("test.provider", "transform", VERSION),
            artifact('a'),
            specification.id.clone(),
            BTreeMap::new(),
        )
        .unwrap();
        let invocation = CapabilityInvocation::new(
            specification,
            ImplementationSelection::new(offer, BTreeMap::new()).unwrap(),
            vec![
                LinkedInput::new(
                    port("source"),
                    links[0].reference.clone(),
                    source,
                    BTreeMap::new(),
                )
                .unwrap(),
            ],
            suite(),
            BTreeMap::new(),
        )
        .unwrap();

        Fixture {
            ledger,
            policy,
            invocation,
            output: Fact::new(result_kind, json!({"value": 2})).unwrap(),
            conformance,
        }
    }

    fn value_kind(name: &str) -> ValueKindId {
        ValueKindId::new("test.value", name, VERSION)
    }

    fn suite() -> ConformanceSuiteId {
        ConformanceSuiteId::new("test.conformance", "exact", VERSION)
    }

    fn port(name: &str) -> PortName {
        PortName::parse(name).unwrap()
    }

    fn artifact(byte: char) -> ArtifactDigest {
        ArtifactDigest::parse(sha(byte)).unwrap()
    }

    fn sha(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn limits() -> DerivationLimits {
        let bounded = NonZeroUsize::new(32).unwrap();
        DerivationLimits {
            planning: PlanLimits {
                max_capabilities: bounded,
                max_value_kinds: bounded,
                max_ports_per_capability: bounded,
                max_total_ports: bounded,
                max_offers_per_capability: bounded,
                max_total_offers: bounded,
            },
            max_inputs: bounded,
            max_attesters: bounded,
        }
    }

    fn package_registry(
        specification: CapabilitySpec,
        implementation: ImplementationId,
        with_offer: bool,
    ) -> PackageRegistry {
        const EMPTY_SHA256: &str =
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let implementation_resource = ResourceName::parse("provider").unwrap();
        let mut value_kinds = specification
            .input_ports
            .iter()
            .map(|input| input.value_kind.clone())
            .chain(
                specification
                    .output_ports
                    .iter()
                    .map(|output| output.value_kind.clone()),
            )
            .collect::<Vec<_>>();
        value_kinds.sort();
        value_kinds.dedup();
        let dialect = value_kinds[0].dialect();
        assert!(value_kinds.iter().all(|kind| kind.dialect() == dialect));
        let resources = with_offer.then(|| PackageResource {
            name: implementation_resource.clone(),
            path: "provider.bin".to_owned(),
            media_type: "application/octet-stream".to_owned(),
            size: 0,
            digest: ResourceDigest::parse(EMPTY_SHA256).unwrap(),
            extensions: BTreeMap::new(),
        });
        let offers = with_offer.then(|| ImplementationOfferDeclaration {
            implementation,
            capability: specification.id.clone(),
            artifact: implementation_resource,
            extensions: BTreeMap::new(),
        });
        let manifest = PackageManifest::new(
            PackageId::parse("test.package@1.0.0").unwrap(),
            Vec::new(),
            resources.into_iter().collect(),
            vec![DialectDeclaration {
                id: dialect,
                value_kinds: value_kinds
                    .into_iter()
                    .map(|id| ValueKindDeclaration {
                        id,
                        schema: None,
                        extensions: BTreeMap::new(),
                    })
                    .collect(),
                extensions: BTreeMap::new(),
            }],
            vec![ConformanceSuiteDeclaration {
                id: suite(),
                extensions: BTreeMap::new(),
            }],
            vec![specification],
            offers.into_iter().collect(),
            BTreeMap::new(),
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join(gooir_package::PACKAGE_MANIFEST_FILE),
            write_manifest(&manifest).unwrap(),
        )
        .unwrap();
        if with_offer {
            fs::write(directory.path().join("provider.bin"), []).unwrap();
        }
        let package = load_local_package(
            directory.path(),
            &PackageRegistry::default(),
            LoadLimits::default(),
        )
        .unwrap();
        let mut registry = PackageRegistry::default();
        registry.install(package).unwrap();
        registry
    }

    struct FacadeFixture {
        ledger: AdmissionLedger,
        policy: AdmissionPolicy,
        facade: DerivationFacade,
        request: DerivationRequest,
        attesters: AttesterInventory,
        host: TestHost,
    }

    fn facade_fixture(accept_conformance: bool, with_offer: bool) -> FacadeFixture {
        let fixture = fixture(accept_conformance);
        let registry = package_registry(
            fixture.invocation.specification.clone(),
            fixture.invocation.selection.offer.implementation.clone(),
            with_offer,
        );
        let request = DerivationRequest {
            target: fixture.output.value_kind.clone(),
            inputs: vec![fixture.invocation.inputs[0].admitted.clone()],
            selection: DerivationSelection::UniqueOnly {
                extensions: BTreeMap::new(),
            },
            extensions: BTreeMap::new(),
        };
        FacadeFixture {
            ledger: fixture.ledger,
            policy: fixture.policy,
            facade: DerivationFacade::new(&registry, limits()).unwrap(),
            request,
            attesters: AttesterInventory::new([fixture.conformance], limits().max_attesters)
                .unwrap(),
            host: TestHost::new(fixture.output),
        }
    }

    #[test]
    fn unresolved_input_stops_before_any_host_effect() {
        let mut fixture = fixture(true);
        let unknown = AdmittedFactRef::new(
            fixture.invocation.inputs[0].fact.id.clone(),
            AuthorityRecordId::parse(sha('f')).unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        let invocation = CapabilityInvocation::new(
            fixture.invocation.specification.clone(),
            fixture.invocation.selection.clone(),
            vec![
                LinkedInput::new(
                    port("source"),
                    unknown,
                    fixture.invocation.inputs[0].fact.clone(),
                    BTreeMap::new(),
                )
                .unwrap(),
            ],
            fixture.invocation.conformance_suite.clone(),
            BTreeMap::new(),
        )
        .unwrap();
        let mut host = TestHost::new(fixture.output);

        let error = run_linked_invocation(
            &mut fixture.ledger,
            &fixture.policy,
            &invocation,
            &fixture.conformance,
            &mut host,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            LinkedInvocationError::UnresolvedInput { .. }
        ));
        assert_eq!(host.invocations, 0);
        assert_eq!(host.assessments, 0);
    }

    #[test]
    fn provider_inability_never_becomes_a_candidate() {
        let mut fixture = fixture(true);
        let baseline = fixture.ledger.export().unwrap();
        let mut host = TestHost::new(fixture.output);
        host.provider = ProviderBehavior::Unable;
        let outcome = run_linked_invocation(
            &mut fixture.ledger,
            &fixture.policy,
            &fixture.invocation,
            &fixture.conformance,
            &mut host,
        )
        .unwrap();

        assert!(matches!(
            outcome,
            LinkedInvocationOutcome::ProviderUnable(_)
        ));
        assert_eq!(host.invocations, 1);
        assert_eq!(host.assessments, 0);
        assert_eq!(fixture.ledger.export().unwrap(), baseline);
    }

    #[test]
    fn substituted_self_assessment_fails_without_admission() {
        let mut fixture = fixture(true);
        let baseline = fixture.ledger.export().unwrap();
        let mut host = TestHost::new(fixture.output);
        host.assessment = AssessmentBehavior::ProviderSelfAssessment;
        let error = run_linked_invocation(
            &mut fixture.ledger,
            &fixture.policy,
            &fixture.invocation,
            &fixture.conformance,
            &mut host,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            LinkedInvocationError::InvalidHostAssessment {
                error: AuthorityError::AttesterNotIndependent,
                ..
            }
        ));
        assert_eq!(fixture.ledger.export().unwrap(), baseline);
    }

    #[test]
    fn unaccepted_attester_is_a_policy_refusal_and_mutates_nothing() {
        let mut fixture = fixture(false);
        let baseline = fixture.ledger.export().unwrap();
        let mut host = TestHost::new(fixture.output);
        let outcome = run_linked_invocation(
            &mut fixture.ledger,
            &fixture.policy,
            &fixture.invocation,
            &fixture.conformance,
            &mut host,
        )
        .unwrap();

        let LinkedInvocationOutcome::AuthorityNotAccepted(withheld) = outcome else {
            panic!("expected exact admission-policy refusal");
        };
        assert!(matches!(
            withheld.decision.verdict,
            AdmissionVerdict::Withhold {
                reason: AdmissionDenial::AuthorityNotAccepted,
                ..
            }
        ));
        assert_eq!(fixture.ledger.export().unwrap(), baseline);
    }

    #[test]
    fn admitted_output_contains_and_resolves_its_complete_authority() {
        let mut fixture = fixture(true);
        let expected = fixture.output.clone();
        let mut host = TestHost::new(fixture.output);
        let outcome = run_linked_invocation(
            &mut fixture.ledger,
            &fixture.policy,
            &fixture.invocation,
            &fixture.conformance,
            &mut host,
        )
        .unwrap();

        let LinkedInvocationOutcome::Admitted(admitted) = outcome else {
            panic!("expected admitted output");
        };
        assert_eq!(admitted.outputs.len(), 1);
        assert_eq!(admitted.outputs[0].port, port("result"));
        assert_eq!(admitted.outputs[0].authority.fact, expected);
        assert!(matches!(
            admitted.outputs[0].authority.basis,
            AuthorityBasis::Derived { .. }
        ));
        let reference = AdmittedFactRef::new(
            admitted.outputs[0].authority.fact.id.clone(),
            admitted.outputs[0].authority.authority_record_id.clone(),
            BTreeMap::new(),
        )
        .unwrap();
        let resolved = fixture.ledger.resolve(&reference).unwrap();
        assert_eq!(resolved.fact, &expected);
        assert_eq!(resolved.authority, &admitted.outputs[0].authority);
    }

    #[test]
    fn failed_and_indeterminate_assessments_are_distinct_outcomes() {
        for (assessment, expected_failed) in [
            (AssessmentOutcome::Failed, true),
            (AssessmentOutcome::Indeterminate, false),
        ] {
            let mut fixture = fixture(true);
            let baseline = fixture.ledger.export().unwrap();
            let mut host = TestHost::new(fixture.output);
            host.assessment = AssessmentBehavior::Outcome(assessment);
            let outcome = run_linked_invocation(
                &mut fixture.ledger,
                &fixture.policy,
                &fixture.invocation,
                &fixture.conformance,
                &mut host,
            )
            .unwrap();
            if expected_failed {
                assert!(matches!(
                    outcome,
                    LinkedInvocationOutcome::ConformanceFailed(_)
                ));
            } else {
                assert!(matches!(
                    outcome,
                    LinkedInvocationOutcome::ConformanceIndeterminate(_)
                ));
            }
            assert_eq!(fixture.ledger.export().unwrap(), baseline);
        }
    }

    #[test]
    fn host_failures_remain_outside_serialized_outcomes() {
        let mut provider_fixture = fixture(true);
        let mut host = TestHost::new(provider_fixture.output);
        host.provider = ProviderBehavior::HostFailure;
        assert!(matches!(
            run_linked_invocation(
                &mut provider_fixture.ledger,
                &provider_fixture.policy,
                &provider_fixture.invocation,
                &provider_fixture.conformance,
                &mut host,
            ),
            Err(LinkedInvocationError::HostInvocation(TestHostError(
                "secret://provider-token"
            )))
        ));

        let mut assessment_fixture = fixture(true);
        let mut host = TestHost::new(assessment_fixture.output);
        host.assessment = AssessmentBehavior::HostFailure;
        assert!(matches!(
            run_linked_invocation(
                &mut assessment_fixture.ledger,
                &assessment_fixture.policy,
                &assessment_fixture.invocation,
                &assessment_fixture.conformance,
                &mut host,
            ),
            Err(LinkedInvocationError::HostAssessment {
                error: TestHostError("secret://attester-token"),
                ..
            })
        ));
    }

    #[test]
    fn facade_produces_only_an_admitted_target_with_complete_authority() {
        let mut fixture = facade_fixture(true, true);

        let answer = fixture.facade.answer(
            &mut fixture.ledger,
            &fixture.policy,
            &fixture.attesters,
            &mut fixture.host,
            &fixture.request,
        );

        let Answer::Produced(produced) = answer else {
            panic!("expected the product-facing admitted result");
        };
        assert_eq!(fixture.host.invocations, 1);
        assert_eq!(fixture.host.assessments, 1);
        assert_eq!(
            fixture.host.seen_invocations[0]
                .selection
                .extensions
                .get(COMPLETE_SELECTION_EXTENSION),
            Some(&json!(produced.selection_id.as_str()))
        );
        assert!(!produced.admitted.is_empty());
        let resolved = fixture.ledger.resolve(&produced.target).unwrap();
        assert_eq!(resolved.fact.value_kind, fixture.request.target);
        assert!(
            produced
                .admitted
                .iter()
                .any(|record| record.authority_record_id == produced.target.authority_record_id)
        );
    }

    #[test]
    fn facade_returns_an_already_admitted_target_without_host_effects() {
        let mut fixture = facade_fixture(true, true);
        fixture.request.target = fixture
            .ledger
            .resolve(&fixture.request.inputs[0])
            .unwrap()
            .fact
            .value_kind
            .clone();

        let answer = fixture.facade.answer(
            &mut fixture.ledger,
            &fixture.policy,
            &fixture.attesters,
            &mut fixture.host,
            &fixture.request,
        );

        let Answer::Produced(produced) = answer else {
            panic!("expected the existing admitted input");
        };
        assert_eq!(produced.target, fixture.request.inputs[0]);
        assert_eq!(produced.admitted.len(), 1);
        assert_eq!(fixture.host.invocations, 0);
        assert_eq!(fixture.host.assessments, 0);
    }

    #[test]
    fn facade_distinguishes_missing_implementations_and_attesters_as_blockage() {
        let mut no_offer = facade_fixture(true, false);
        let answer = no_offer.facade.answer(
            &mut no_offer.ledger,
            &no_offer.policy,
            &no_offer.attesters,
            &mut no_offer.host,
            &no_offer.request,
        );
        let Answer::Blocked(blocked) = answer else {
            panic!("expected implementation blockage");
        };
        assert!(!blocked.blockage.missing_needs.is_empty());
        assert!(
            blocked
                .blockage
                .nodes
                .iter()
                .all(|node| node.missing_attesters.is_empty())
        );
        assert_eq!(no_offer.host.invocations, 0);
        assert_eq!(no_offer.host.assessments, 0);

        let mut no_attester = facade_fixture(true, true);
        no_attester.attesters = AttesterInventory::new([], limits().max_attesters).unwrap();
        let answer = no_attester.facade.answer(
            &mut no_attester.ledger,
            &no_attester.policy,
            &no_attester.attesters,
            &mut no_attester.host,
            &no_attester.request,
        );
        let Answer::Blocked(blocked) = answer else {
            panic!("expected attester blockage");
        };
        assert_eq!(blocked.blockage.nodes[0].missing_attesters.len(), 1);
        assert!(
            !blocked.blockage.nodes[0].missing_attesters[0]
                .offers
                .is_empty()
        );
        assert_eq!(no_attester.host.invocations, 0);
        assert_eq!(no_attester.host.assessments, 0);
    }

    #[test]
    fn facade_reports_semantic_unreachability_without_host_effects() {
        let mut fixture = facade_fixture(true, true);
        fixture.request.target = value_kind("unreachable");

        let answer = fixture.facade.answer(
            &mut fixture.ledger,
            &fixture.policy,
            &fixture.attesters,
            &mut fixture.host,
            &fixture.request,
        );

        assert!(matches!(answer, Answer::Unreachable(_)));
        assert_eq!(fixture.host.invocations, 0);
        assert_eq!(fixture.host.assessments, 0);
    }

    #[test]
    fn facade_treats_pre_execution_policy_ineligibility_as_refusal() {
        let mut fixture = facade_fixture(false, true);

        let answer = fixture.facade.answer(
            &mut fixture.ledger,
            &fixture.policy,
            &fixture.attesters,
            &mut fixture.host,
            &fixture.request,
        );

        assert!(matches!(
            answer,
            Answer::Refused(refusal)
                if matches!(*refusal, Refusal::AdmissionPolicy { decision: None, .. })
        ));
        assert_eq!(fixture.host.invocations, 0);
        assert_eq!(fixture.host.assessments, 0);
    }

    #[test]
    fn facade_ambiguity_retains_two_complete_selection_identities() {
        let mut fixture = facade_fixture(true, true);
        let first = fixture.attesters.authorities()[0].clone();
        let second = ConformanceAuthority::new(
            suite(),
            ConformanceAttester::new(
                ImplementationId::new("test.attester", "other", VERSION),
                artifact('e'),
                BTreeMap::new(),
            )
            .unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        assert!(matches!(
            AttesterInventory::new([first.clone(), first.clone()], limits().max_attesters,),
            Err(FacadeError::DuplicateAttester)
        ));
        fixture.policy = AdmissionPolicy::new(
            fixture.policy.decision_authority.clone(),
            vec![first.clone(), second.clone()],
            fixture.policy.accepted_observations.clone(),
            BTreeMap::new(),
        )
        .unwrap();
        fixture.attesters =
            AttesterInventory::new([second, first], limits().max_attesters).unwrap();

        let answer = fixture.facade.answer(
            &mut fixture.ledger,
            &fixture.policy,
            &fixture.attesters,
            &mut fixture.host,
            &fixture.request,
        );

        let Answer::Refused(refusal) = answer else {
            panic!("expected complete-selection ambiguity");
        };
        let Refusal::AmbiguousSelection { alternatives, .. } = *refusal else {
            panic!("expected exact ambiguity alternatives");
        };
        assert_eq!(alternatives.len(), 2);
        assert_ne!(alternatives[0].selection_id, alternatives[1].selection_id);
        assert_ne!(
            alternatives[0].selection.attesters,
            alternatives[1].selection.attesters
        );
        assert_eq!(fixture.host.invocations, 0);
        assert_eq!(fixture.host.assessments, 0);
    }

    #[test]
    fn facade_retains_one_fixed_provider_inability_as_failure() {
        let mut fixture = facade_fixture(true, true);
        fixture.host.provider = ProviderBehavior::Unable;

        let answer = fixture.facade.answer(
            &mut fixture.ledger,
            &fixture.policy,
            &fixture.attesters,
            &mut fixture.host,
            &fixture.request,
        );

        let Answer::Failed(failed) = answer else {
            panic!("expected one fixed attempt to fail");
        };
        assert_eq!(failed.stage, FailureStage::ProviderUnable);
        assert!(failed.provider_failure.is_some());
        let attempt = failed
            .attempt
            .expect("failed attempt retains neutral documents");
        let result = attempt
            .result
            .expect("provider inability retains its envelope");
        assert!(result.extensions.contains_key("org.test.result"));
        assert!(matches!(
            result.outcome,
            CapabilityOutcome::Unable { extensions, .. }
                if extensions.contains_key("org.test.outcome")
        ));
        assert!(
            failed
                .provider_failure
                .unwrap()
                .extensions
                .contains_key("org.test.failure")
        );
        assert_eq!(fixture.host.invocations, 1);
        assert_eq!(fixture.host.assessments, 0);
    }

    #[test]
    fn facade_never_serializes_host_local_error_text() {
        let mut fixture = facade_fixture(true, true);
        fixture.host.provider = ProviderBehavior::HostFailure;

        let answer = fixture.facade.answer(
            &mut fixture.ledger,
            &fixture.policy,
            &fixture.attesters,
            &mut fixture.host,
            &fixture.request,
        );

        let Answer::Failed(failed) = answer else {
            panic!("expected provider-host failure");
        };
        assert_eq!(failed.stage, FailureStage::ProviderHost);
        assert_eq!(failed.detail, "external provider host failed");
        assert!(
            !serde_json::to_string(&failed)
                .unwrap()
                .contains("provider-token")
        );
        assert!(failed.attempt.is_some());
    }

    #[test]
    fn explicit_selection_can_fix_a_nondefault_exact_suite() {
        let fixture = fixture(true);
        let registry = package_registry(
            fixture.invocation.specification.clone(),
            fixture.invocation.selection.offer.implementation.clone(),
            true,
        );
        let planner = SemanticPlanner::from_registry(&registry, limits().planning).unwrap();
        let plan = planner
            .plan(
                [fixture.invocation.inputs[0].fact.value_kind.clone()],
                fixture.output.value_kind.clone(),
            )
            .unwrap();
        let route = planner
            .select_route(&plan, RouteSelection::UniqueOnly)
            .unwrap();
        let override_authority = ConformanceAuthority::new(
            ConformanceSuiteId::new("test.conformance", "explicit", VERSION),
            ConformanceAttester::new(
                ImplementationId::new("test.attester", "explicit", VERSION),
                artifact('d'),
                BTreeMap::new(),
            )
            .unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        let policy = AdmissionPolicy::new(
            fixture.policy.decision_authority.clone(),
            vec![override_authority.clone()],
            fixture.policy.accepted_observations.clone(),
            BTreeMap::new(),
        )
        .unwrap();
        let binding = InitialBinding {
            capability: route.steps[0].capability.clone(),
            input_port: route.steps[0].inputs[0].input_port.clone(),
            admitted: fixture.invocation.inputs[0].admitted.clone(),
            extensions: BTreeMap::new(),
        };
        let request = DerivationRequest {
            target: fixture.output.value_kind.clone(),
            inputs: vec![fixture.invocation.inputs[0].admitted.clone()],
            selection: DerivationSelection::Explicit {
                selection: Box::new(ExplicitSelection {
                    route: route.clone(),
                    initial_bindings: vec![binding],
                    target_input: None,
                    attesters: vec![SelectedAttester {
                        capability: route.steps[0].capability.clone(),
                        authority: override_authority.clone(),
                        extensions: BTreeMap::new(),
                    }],
                    extensions: BTreeMap::new(),
                }),
                extensions: BTreeMap::new(),
            },
            extensions: BTreeMap::new(),
        };
        let facade = DerivationFacade::new(&registry, limits()).unwrap();
        let attesters =
            AttesterInventory::new([override_authority], limits().max_attesters).unwrap();
        let mut ledger = fixture.ledger;
        let mut host = TestHost::new(fixture.output);

        let mut extended_request = request.clone();
        let DerivationSelection::Explicit { selection, .. } = &mut extended_request.selection
        else {
            unreachable!();
        };
        selection.route.steps[0].inputs[0]
            .extensions
            .insert("org.test.unknown-route".to_owned(), json!({"kept": true}));
        let mut identity_value = serde_json::to_value(&selection.route).unwrap();
        identity_value.as_object_mut().unwrap().remove("route_id");
        selection.route.route_id =
            RouteId::parse(canonical_digest(&identity_value).unwrap()).unwrap();
        let refusal = facade.answer(
            &mut ledger,
            &policy,
            &attesters,
            &mut host,
            &extended_request,
        );
        assert!(matches!(
            refusal,
            Answer::Refused(reason) if matches!(*reason, Refusal::InvalidSelection { .. })
        ));
        assert_eq!(host.invocations, 0);
        assert_eq!(host.assessments, 0);

        let answer = facade.answer(&mut ledger, &policy, &attesters, &mut host, &request);

        assert!(matches!(answer, Answer::Produced(_)));
        assert_eq!(host.invocations, 1);
        assert_eq!(host.assessments, 1);
    }
}
