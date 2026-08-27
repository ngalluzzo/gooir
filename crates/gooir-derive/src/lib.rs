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
    AdmissionVerdict, AuthorityError, AuthorityRecord, ConformanceAssessment,
};
use gooir_capability::protocol::{
    CapabilityCandidate, CapabilityFailure, CapabilityInvocation, CapabilityOutcome,
    CapabilityResult, ProtocolError,
};
use serde::{Deserialize, Serialize};

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

/// Successful admission of every output from one candidate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AdmittedDerivation {
    pub decision: AdmissionDecision,
    pub outputs: Vec<AdmittedOutput>,
}

/// A validated assessment and the exact decision that withheld its candidate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WithheldDerivation {
    pub assessment: ConformanceAssessment,
    pub decision: AdmissionDecision,
}

/// Stable data outcomes from executing one already-linked invocation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", content = "detail", rename_all = "snake_case")]
pub enum LinkedInvocationOutcome {
    Admitted(Box<AdmittedDerivation>),
    ProviderUnable(Box<CapabilityFailure>),
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
    InvalidHostResult(ProtocolError),
    HostAssessment(E),
    InvalidHostAssessment(AuthorityError),
    Admission(AuthorityError),
    AdmissionReturnedSourceLink,
    AdmittedOutputUnresolvable {
        port: PortName,
        error: AuthorityError,
    },
    UnexpectedAdmissionDecision(Box<AdmissionDecision>),
}

impl<E: fmt::Display> fmt::Display for LinkedInvocationError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInvocation(error) => {
                write!(formatter, "invalid linked invocation: {error}")
            }
            Self::InvalidPolicy(error) => write!(formatter, "invalid admission policy: {error}"),
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
            Self::InvalidHostResult(error) => write!(formatter, "host result is invalid: {error}"),
            Self::HostAssessment(error) => write!(formatter, "host assessment failed: {error}"),
            Self::InvalidHostAssessment(error) => {
                write!(formatter, "host assessment is invalid: {error}")
            }
            Self::Admission(error) => write!(formatter, "candidate admission failed: {error}"),
            Self::AdmissionReturnedSourceLink => {
                formatter.write_str("candidate admission returned a source link")
            }
            Self::AdmittedOutputUnresolvable { port, error } => {
                write!(
                    formatter,
                    "admitted output `{port}` cannot be resolved: {error}"
                )
            }
            Self::UnexpectedAdmissionDecision(decision) => write!(
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
            Self::InvalidInvocation(error) | Self::InvalidHostResult(error) => Some(error),
            Self::InvalidPolicy(error)
            | Self::UnresolvedInput { error, .. }
            | Self::SubstitutedInput { error, .. }
            | Self::InvalidInputAuthority { error, .. }
            | Self::InvalidHostAssessment(error)
            | Self::Admission(error)
            | Self::AdmittedOutputUnresolvable { error, .. } => Some(error),
            Self::HostInvocation(error) | Self::HostAssessment(error) => Some(error),
            Self::AdmissionReturnedSourceLink | Self::UnexpectedAdmissionDecision(_) => None,
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
    host: &mut H,
) -> Result<LinkedInvocationOutcome, LinkedInvocationError<H::Error>> {
    invocation
        .validate()
        .map_err(LinkedInvocationError::InvalidInvocation)?;
    policy
        .validate()
        .map_err(LinkedInvocationError::InvalidPolicy)?;

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

    let result = host
        .invoke(invocation)
        .map_err(LinkedInvocationError::HostInvocation)?;
    result
        .validate_against(invocation)
        .map_err(LinkedInvocationError::InvalidHostResult)?;

    if let CapabilityOutcome::Unable { failure, .. } = &result.outcome {
        return Ok(LinkedInvocationOutcome::ProviderUnable(Box::new(
            failure.clone(),
        )));
    }

    let candidate = CapabilityCandidate::new(
        invocation,
        result.clone(),
        std::collections::BTreeMap::new(),
    )
    .map_err(LinkedInvocationError::InvalidHostResult)?;
    let assessment = host
        .assess(invocation, &result, &candidate)
        .map_err(LinkedInvocationError::HostAssessment)?;
    assessment
        .validate_against(invocation, &result, &candidate)
        .map_err(LinkedInvocationError::InvalidHostAssessment)?;

    match ledger
        .admit_candidate(policy, invocation, &result, &candidate, &assessment)
        .map_err(LinkedInvocationError::Admission)?
    {
        AdmissionOutcome::Admitted { decision, links } => {
            let mut outputs = Vec::with_capacity(links.len());
            for link in links {
                let Some(port) = link.port else {
                    return Err(LinkedInvocationError::AdmissionReturnedSourceLink);
                };
                let resolved = ledger.resolve(&link.reference).map_err(|error| {
                    LinkedInvocationError::AdmittedOutputUnresolvable {
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
                AdmittedDerivation { decision, outputs },
            )))
        }
        AdmissionOutcome::Withheld { decision } => {
            let reason = match &decision.verdict {
                AdmissionVerdict::Withhold { reason, .. } => *reason,
                AdmissionVerdict::Admit { .. } => {
                    return Err(LinkedInvocationError::UnexpectedAdmissionDecision(
                        Box::new(decision),
                    ));
                }
            };
            let withheld = Box::new(WithheldDerivation {
                assessment,
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
    };
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
        authority: ConformanceAuthority,
        provider: ProviderBehavior,
        assessment: AssessmentBehavior,
        invocations: usize,
        assessments: usize,
    }

    impl TestHost {
        fn new(output: Fact, authority: ConformanceAuthority) -> Self {
            Self {
                output,
                authority,
                provider: ProviderBehavior::Produced,
                assessment: AssessmentBehavior::Outcome(AssessmentOutcome::Passed),
                invocations: 0,
                assessments: 0,
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
                        BTreeMap::new(),
                    )
                    .expect("test failure is exact"),
                    BTreeMap::new(),
                    Vec::new(),
                    BTreeMap::new(),
                )
                .map_err(|_| TestHostError("could not form inability")),
                ProviderBehavior::HostFailure => Err(TestHostError("provider host failed")),
            }
        }

        fn assess(
            &mut self,
            invocation: &CapabilityInvocation,
            result: &CapabilityResult,
            candidate: &CapabilityCandidate,
        ) -> Result<ConformanceAssessment, Self::Error> {
            self.assessments += 1;
            let outcome = match self.assessment {
                AssessmentBehavior::Outcome(outcome) => outcome,
                AssessmentBehavior::ProviderSelfAssessment => AssessmentOutcome::Passed,
                AssessmentBehavior::HostFailure => {
                    return Err(TestHostError("attester host failed"));
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
                self.authority.clone(),
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
        let mut host = TestHost::new(fixture.output, fixture.conformance);

        let error =
            run_linked_invocation(&mut fixture.ledger, &fixture.policy, &invocation, &mut host)
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
        let mut host = TestHost::new(fixture.output, fixture.conformance);
        host.provider = ProviderBehavior::Unable;
        let outcome = run_linked_invocation(
            &mut fixture.ledger,
            &fixture.policy,
            &fixture.invocation,
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
        let mut host = TestHost::new(fixture.output, fixture.conformance);
        host.assessment = AssessmentBehavior::ProviderSelfAssessment;
        let error = run_linked_invocation(
            &mut fixture.ledger,
            &fixture.policy,
            &fixture.invocation,
            &mut host,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            LinkedInvocationError::InvalidHostAssessment(AuthorityError::AttesterNotIndependent)
        ));
        assert_eq!(fixture.ledger.export().unwrap(), baseline);
    }

    #[test]
    fn unaccepted_attester_is_a_policy_refusal_and_mutates_nothing() {
        let mut fixture = fixture(false);
        let baseline = fixture.ledger.export().unwrap();
        let mut host = TestHost::new(fixture.output, fixture.conformance);
        let outcome = run_linked_invocation(
            &mut fixture.ledger,
            &fixture.policy,
            &fixture.invocation,
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
        let mut host = TestHost::new(fixture.output, fixture.conformance);
        let outcome = run_linked_invocation(
            &mut fixture.ledger,
            &fixture.policy,
            &fixture.invocation,
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
            let mut host = TestHost::new(fixture.output, fixture.conformance);
            host.assessment = AssessmentBehavior::Outcome(assessment);
            let outcome = run_linked_invocation(
                &mut fixture.ledger,
                &fixture.policy,
                &fixture.invocation,
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
        let mut host = TestHost::new(provider_fixture.output, provider_fixture.conformance);
        host.provider = ProviderBehavior::HostFailure;
        assert!(matches!(
            run_linked_invocation(
                &mut provider_fixture.ledger,
                &provider_fixture.policy,
                &provider_fixture.invocation,
                &mut host,
            ),
            Err(LinkedInvocationError::HostInvocation(TestHostError(
                "provider host failed"
            )))
        ));

        let mut assessment_fixture = fixture(true);
        let mut host = TestHost::new(assessment_fixture.output, assessment_fixture.conformance);
        host.assessment = AssessmentBehavior::HostFailure;
        assert!(matches!(
            run_linked_invocation(
                &mut assessment_fixture.ledger,
                &assessment_fixture.policy,
                &assessment_fixture.invocation,
                &mut host,
            ),
            Err(LinkedInvocationError::HostAssessment(TestHostError(
                "attester host failed"
            )))
        ));
    }
}
