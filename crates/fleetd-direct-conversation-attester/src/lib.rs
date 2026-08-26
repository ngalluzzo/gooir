//! Independent Fleetd observation for one direct-conversation candidate.
//!
//! This crate owns one exact assessment request and one exact Fleetd GET
//! observer. It is not a planner offer, does not trust a provider response,
//! and shares no Fleetd response projection with either provider client.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::io::Read as _;
use std::time::Duration;

use fleetd_direct_conversation_command_abi::AuthorityDocument;
use fleetd_direct_conversation_contract::{
    AgentId, DeliveryMode, DirectConversationRef, DirectMember, DirectPairIntent,
    direct_conversation_ref_suite_id, open_or_resolve_capability_spec,
};
use gooir_capability::authority::{
    AssessmentOutcome, AuthorityError, ConformanceAssessment, ConformanceAttester,
    ConformanceAuthority, ConformanceCheck,
};
use gooir_capability::protocol::{
    ArtifactDigest, CapabilityCandidate, CapabilityInvocation, CapabilityOutcome, CapabilityResult,
    ConformanceSuiteId, ImplementationId, ProtocolError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Exact versioned stdin document accepted by this attester artifact.
pub const ASSESSMENT_REQUEST_PROTOCOL: &str =
    "dev.fleetd.conformance.direct-conversation-ref/assessment-request/v1";

/// Conservative artifact-local ceiling for the assessment request on stdin.
pub const MAX_ASSESSMENT_REQUEST_BYTES: u64 = 4 * 1024 * 1024;

const CHECK_EXACT_CONTRACT: &str = "exact-contract";
const CHECK_INTENT_OUTPUT_RELATION: &str = "intent-output-relation";
const CHECK_FLEETD_OBSERVATION: &str = "fleetd-observation";
const CONVERSATIONS_PATH: &str = "v1/conversations?include_archived=true";

/// Exact identity of this independently packaged observation artifact.
#[must_use]
pub fn implementation_id() -> ImplementationId {
    ImplementationId::new("dev.fleetd.attester", "direct_conversation_ref", "0.1.0")
}

/// One closed request containing the complete neutral candidate chain.
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
    /// Constructs a request only from a valid, exactly correlated chain.
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

    /// Revalidates identities, correlation, contract, suite, and independence.
    pub fn validate(&self) -> Result<(), AttesterError> {
        if self.protocol != ASSESSMENT_REQUEST_PROTOCOL {
            return Err(AttesterError::RequestProtocolMismatch);
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
        if self.invocation.specification != open_or_resolve_capability_spec() {
            return Err(AttesterError::UnsupportedSpecification);
        }
        if self.invocation.conformance_suite != direct_conversation_ref_suite_id() {
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
        decode_chain(self)?;
        Ok(())
    }

    /// Exact invocation embedded in this request.
    #[must_use]
    pub const fn invocation(&self) -> &CapabilityInvocation {
        &self.invocation
    }

    /// Exact provider result embedded in this request.
    #[must_use]
    pub const fn result(&self) -> &CapabilityResult {
        &self.result
    }

    /// Exact candidate embedding the provider result.
    #[must_use]
    pub const fn candidate(&self) -> &CapabilityCandidate {
        &self.candidate
    }

    /// Host-measured digest of the attester artifact selected for execution.
    #[must_use]
    pub const fn attester_artifact_digest(&self) -> &ArtifactDigest {
        &self.attester_artifact_digest
    }
}

/// Executes the exact bounded Fleetd observation and constructs an assessment.
///
/// Structural request errors, authority-target disagreement, transport errors,
/// non-200 status, duplicate IDs, malformed JSON, and body overflow are
/// operational errors. A complete well-formed list with an absent or
/// mismatching candidate produces an ordinary failed assessment.
pub fn assess(
    request: &AssessmentRequest,
    authority: &AuthorityDocument,
) -> Result<ConformanceAssessment, AttesterError> {
    request.validate()?;
    let chain = decode_chain(request)?;
    if authority.target() != chain.intent.fleetd_target().as_str() {
        return Err(AttesterError::AuthorityTargetMismatch);
    }

    let conversations = fetch_conversations(authority)?;
    validate_list_integrity(&conversations)?;
    let matching = conversations
        .iter()
        .filter(|conversation| conversation.id == chain.reference.conversation_id().as_str())
        .collect::<Vec<_>>();
    let observation_matches = match matching.as_slice() {
        [] => false,
        [conversation] => observation_matches(
            conversation,
            &chain.intent,
            &chain.reference,
            authority.target(),
        ),
        _ => return Err(AttesterError::DuplicateConversationId),
    };

    let reconstructed = DirectConversationRef::for_intent(
        &chain.intent,
        chain.reference.conversation_id().clone(),
        chain.reference.created_at_ms(),
    )
    .map_err(|_| AttesterError::InvalidContractPayload)?;
    let relation_matches = reconstructed == chain.reference;
    let checks = BTreeMap::from([
        (
            CHECK_EXACT_CONTRACT.to_owned(),
            check(AssessmentOutcome::Passed)?,
        ),
        (
            CHECK_INTENT_OUTPUT_RELATION.to_owned(),
            check(if relation_matches {
                AssessmentOutcome::Passed
            } else {
                AssessmentOutcome::Failed
            })?,
        ),
        (
            CHECK_FLEETD_OBSERVATION.to_owned(),
            check(if observation_matches {
                AssessmentOutcome::Passed
            } else {
                AssessmentOutcome::Failed
            })?,
        ),
    ]);
    let conformance_authority = ConformanceAuthority::new(
        direct_conversation_ref_suite_id(),
        ConformanceAttester::new(
            implementation_id(),
            request.attester_artifact_digest.clone(),
            BTreeMap::new(),
        )
        .map_err(AttesterError::Authority)?,
        BTreeMap::new(),
    )
    .map_err(AttesterError::Authority)?;
    let assessment = ConformanceAssessment::new(
        &request.invocation,
        &request.result,
        &request.candidate,
        conformance_authority,
        checks,
        Vec::new(),
        BTreeMap::new(),
    )
    .map_err(AttesterError::Authority)?;
    assessment
        .validate_against(&request.invocation, &request.result, &request.candidate)
        .map_err(AttesterError::Authority)?;
    Ok(assessment)
}

struct ValidatedChain {
    intent: DirectPairIntent,
    reference: DirectConversationRef,
}

fn decode_chain(request: &AssessmentRequest) -> Result<ValidatedChain, AttesterError> {
    let [input] = request.invocation.inputs.as_slice() else {
        return Err(AttesterError::UnsupportedSpecification);
    };
    let intent = DirectPairIntent::from_fact(&input.fact)
        .map_err(|_| AttesterError::InvalidContractPayload)?;
    let CapabilityOutcome::Produced { outputs, .. } = &request.result.outcome else {
        return Err(AttesterError::ResultNotProduced);
    };
    let [output] = outputs.as_slice() else {
        return Err(AttesterError::UnsupportedSpecification);
    };
    let reference = DirectConversationRef::from_fact(&output.fact)
        .map_err(|_| AttesterError::InvalidContractPayload)?;
    Ok(ValidatedChain { intent, reference })
}

fn fetch_conversations(
    authority: &AuthorityDocument,
) -> Result<Vec<FleetdConversationSummary>, AttesterError> {
    let url = format!("{}{CONVERSATIONS_PATH}", authority.endpoint());
    let timeout = Duration::from_millis(authority.http_timeout_ms());
    let authorization = format!("Bearer {}", authority.bearer_token().expose_secret());
    let request = attohttpc::RequestBuilder::try_new(attohttpc::Method::GET, url)
        .map_err(|_| AttesterError::HttpTransport)?
        .try_header(attohttpc::header::AUTHORIZATION, authorization)
        .map_err(|_| AttesterError::HttpTransport)?
        .try_header(attohttpc::header::ACCEPT, "application/json")
        .map_err(|_| AttesterError::HttpTransport)?
        .follow_redirects(false)
        .max_redirections(0)
        .connect_timeout(timeout)
        .read_timeout(timeout)
        .timeout(timeout)
        .proxy_settings(attohttpc::ProxySettings::builder().build());
    let response = request.send().map_err(|_| AttesterError::HttpTransport)?;
    if response.status() != attohttpc::StatusCode::OK {
        return Err(AttesterError::HttpStatus(response.status().as_u16()));
    }
    if !has_json_content_type(&response) {
        return Err(AttesterError::UnexpectedContentType);
    }
    let (_, _, reader) = response.split();
    let maximum = authority
        .max_response_bytes()
        .checked_add(1)
        .ok_or(AttesterError::InvalidResponseLimit)?;
    let mut bytes = Vec::new();
    reader
        .take(maximum)
        .read_to_end(&mut bytes)
        .map_err(|_| AttesterError::HttpTransport)?;
    if bytes.len() as u64 > authority.max_response_bytes() {
        return Err(AttesterError::ResponseTooLarge);
    }
    serde_json::from_slice(&bytes).map_err(|_| AttesterError::MalformedObservation)
}

fn has_json_content_type(response: &attohttpc::Response) -> bool {
    response
        .headers()
        .get(attohttpc::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

fn validate_list_integrity(
    conversations: &[FleetdConversationSummary],
) -> Result<(), AttesterError> {
    let mut ids = BTreeSet::new();
    let mut previous: Option<(i64, &str)> = None;
    for conversation in conversations {
        if !ids.insert(conversation.id.as_str()) {
            return Err(AttesterError::DuplicateConversationId);
        }
        let coordinate = (conversation.created_at_ms, conversation.id.as_str());
        if previous.is_some_and(|prior| prior > coordinate) {
            return Err(AttesterError::MalformedObservation);
        }
        previous = Some(coordinate);
    }
    Ok(())
}

fn observation_matches(
    conversation: &FleetdConversationSummary,
    intent: &DirectPairIntent,
    reference: &DirectConversationRef,
    authority_target: &str,
) -> bool {
    if authority_target != reference.fleetd_target().as_str()
        || conversation.kind != FleetdConversationKind::Direct
        || conversation.archived_at_ms.is_some()
        || conversation.id != reference.conversation_id().as_str()
        || conversation.created_at_ms != reference.created_at_ms()
    {
        return false;
    }
    let [first, second] = conversation.members.as_slice() else {
        return false;
    };
    if first.channel_id != conversation.id || second.channel_id != conversation.id {
        return false;
    }
    let Ok(first) = fleetd_member(first) else {
        return false;
    };
    let Ok(second) = fleetd_member(second) else {
        return false;
    };
    let response_order = [first, second];
    let Ok(observed_intent) =
        DirectPairIntent::new(intent.fleetd_target().clone(), response_order.clone())
    else {
        return false;
    };
    observed_intent.members() == &response_order && observed_intent == *intent
}

fn fleetd_member(member: &FleetdChannelMember) -> Result<DirectMember, ()> {
    let agent_id = AgentId::parse(member.agent_id.clone()).map_err(|_| ())?;
    let mode = match member.delivery_mode {
        FleetdDeliveryMode::Inbox => DeliveryMode::Inbox,
        FleetdDeliveryMode::StreamOnly => DeliveryMode::StreamOnly,
    };
    Ok(DirectMember::new(agent_id, mode))
}

fn check(outcome: AssessmentOutcome) -> Result<ConformanceCheck, AttesterError> {
    ConformanceCheck::new(outcome, Vec::new(), BTreeMap::new()).map_err(AttesterError::Authority)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum FleetdConversationKind {
    Shared,
    Direct,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum FleetdDeliveryMode {
    Inbox,
    StreamOnly,
}

#[derive(Debug, Deserialize)]
struct FleetdChannelMember {
    channel_id: String,
    agent_id: String,
    #[serde(rename = "agent_name")]
    _agent_name: String,
    #[serde(rename = "joined_at_ms")]
    _joined_at_ms: i64,
    delivery_mode: FleetdDeliveryMode,
}

#[derive(Debug, Deserialize)]
struct FleetdConversationSummary {
    id: String,
    #[serde(rename = "name")]
    _name: String,
    kind: FleetdConversationKind,
    #[serde(rename = "metadata")]
    _metadata: Value,
    created_at_ms: i64,
    archived_at_ms: Option<i64>,
    members: Vec<FleetdChannelMember>,
    #[serde(rename = "latest_message_seq")]
    _latest_message_seq: Option<i64>,
    #[serde(rename = "latest_message_at_ms")]
    _latest_message_at_ms: Option<i64>,
}

/// Refusal to emit an assessment or operational observation failure.
#[derive(Debug)]
pub enum AttesterError {
    RequestProtocolMismatch,
    Protocol(ProtocolError),
    Authority(AuthorityError),
    ResultCandidateMismatch,
    UnsupportedSpecification,
    UnsupportedSuite(ConformanceSuiteId),
    ResultNotProduced,
    InvalidContractPayload,
    AuthorityTargetMismatch,
    InvalidResponseLimit,
    HttpTransport,
    HttpStatus(u16),
    UnexpectedContentType,
    ResponseTooLarge,
    MalformedObservation,
    DuplicateConversationId,
}

impl fmt::Display for AttesterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestProtocolMismatch => {
                formatter.write_str("unsupported assessment request protocol")
            }
            Self::Protocol(_) => formatter.write_str("invalid capability chain"),
            Self::Authority(_) => formatter.write_str("assessment construction failed"),
            Self::ResultCandidateMismatch => formatter.write_str("candidate/result mismatch"),
            Self::UnsupportedSpecification => {
                formatter.write_str("unsupported capability specification")
            }
            Self::UnsupportedSuite(_) => formatter.write_str("unsupported conformance suite"),
            Self::ResultNotProduced => formatter.write_str("candidate result is not produced"),
            Self::InvalidContractPayload => formatter.write_str("invalid Fleetd contract payload"),
            Self::AuthorityTargetMismatch => formatter.write_str("authority target mismatch"),
            Self::InvalidResponseLimit => formatter.write_str("invalid response limit"),
            Self::HttpTransport => formatter.write_str("Fleetd observation transport failed"),
            Self::HttpStatus(status) => {
                write!(formatter, "Fleetd observation returned status {status}")
            }
            Self::UnexpectedContentType => {
                formatter.write_str("Fleetd observation media type was invalid")
            }
            Self::ResponseTooLarge => {
                formatter.write_str("Fleetd observation exceeded its byte bound")
            }
            Self::MalformedObservation => formatter.write_str("Fleetd observation was malformed"),
            Self::DuplicateConversationId => {
                formatter.write_str("Fleetd observation contained duplicate IDs")
            }
        }
    }
}

impl Error for AttesterError {}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};

    use fleetd_direct_conversation_contract::{
        ConversationId, FleetdTarget, conversation_port_name, intent_port_name,
    };
    use gooir_capability::authority::AssessmentOutcome;
    use gooir_capability::protocol::{
        AdmittedFactRef, AuthorityRecordId, CapabilityOffer, ImplementationSelection, LinkedInput,
        NamedOutput,
    };
    use serde_json::{Value, json};

    use super::*;

    const TARGET: &str = "fleetd:target-a";
    const TOKEN: &str = "fleetd-test-token.secret";

    fn digest(byte: char) -> ArtifactDigest {
        ArtifactDigest::parse(format!("sha256:{}", byte.to_string().repeat(64)))
            .expect("artifact digest")
    }

    fn member(id: &str, mode: DeliveryMode) -> DirectMember {
        DirectMember::new(AgentId::parse(id).expect("agent ID"), mode)
    }

    fn intent() -> DirectPairIntent {
        DirectPairIntent::new(
            FleetdTarget::parse(TARGET).expect("target"),
            [
                member("agent-a", DeliveryMode::StreamOnly),
                member("agent-b", DeliveryMode::Inbox),
            ],
        )
        .expect("intent")
    }

    fn linked_input(intent: &DirectPairIntent) -> LinkedInput {
        let fact = intent.to_fact().expect("intent fact");
        let authority = AuthorityRecordId::parse(format!("sha256:{}", "1".repeat(64)))
            .expect("authority record");
        let admitted = AdmittedFactRef::new(fact.id.clone(), authority, BTreeMap::new())
            .expect("admitted reference");
        LinkedInput::new(intent_port_name(), admitted, fact, BTreeMap::new()).expect("linked input")
    }

    fn request_with_reference(reference: DirectConversationRef) -> AssessmentRequest {
        let intent = intent();
        let offer = CapabilityOffer::new(
            ImplementationId::new(
                "dev.fleetd.implementation",
                "direct_conversation_test_provider",
                "0.1.0",
            ),
            digest('a'),
            open_or_resolve_capability_spec().id,
            BTreeMap::new(),
        )
        .expect("offer");
        let invocation = CapabilityInvocation::new(
            open_or_resolve_capability_spec(),
            ImplementationSelection::new(offer, BTreeMap::new()).expect("selection"),
            vec![linked_input(&intent)],
            direct_conversation_ref_suite_id(),
            BTreeMap::new(),
        )
        .expect("invocation");
        let output = NamedOutput::new(
            conversation_port_name(),
            reference.to_fact().expect("reference fact"),
            BTreeMap::new(),
        )
        .expect("output");
        let result = CapabilityResult::produced(
            &invocation,
            vec![output],
            BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
        )
        .expect("result");
        let candidate = CapabilityCandidate::new(&invocation, result.clone(), BTreeMap::new())
            .expect("candidate");
        AssessmentRequest::new(invocation, result, candidate, digest('b')).expect("request")
    }

    fn request() -> AssessmentRequest {
        request_with_reference(
            DirectConversationRef::for_intent(
                &intent(),
                ConversationId::parse("conversation-1").expect("conversation ID"),
                1_787_700_000_000,
            )
            .expect("reference"),
        )
    }

    fn summary() -> Value {
        json!({
            "id": "conversation-1",
            "name": "presentation may change",
            "kind": "direct",
            "metadata": {"ignored": true},
            "created_at_ms": 1_787_700_000_000i64,
            "archived_at_ms": null,
            "members": [
                {
                    "channel_id": "conversation-1",
                    "agent_id": "agent-a",
                    "agent_name": "Agent A",
                    "joined_at_ms": 1_787_700_000_000i64,
                    "delivery_mode": "stream_only"
                },
                {
                    "channel_id": "conversation-1",
                    "agent_id": "agent-b",
                    "agent_name": "Agent B",
                    "joined_at_ms": 1_787_700_000_000i64,
                    "delivery_mode": "inbox"
                }
            ],
            "latest_message_seq": 999,
            "latest_message_at_ms": 1_787_700_123_456i64
        })
    }

    struct Stub {
        endpoint: String,
        request: JoinHandle<String>,
    }

    impl Stub {
        fn spawn(status: u16, body: Vec<u8>) -> Self {
            Self::spawn_with_content_type(status, Some("application/json"), body)
        }

        fn spawn_with_content_type(status: u16, content_type: Option<&str>, body: Vec<u8>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("stub listener");
            let address = listener.local_addr().expect("stub address");
            let content_type = content_type.map(str::to_owned);
            let request = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("stub accept");
                let request = read_request(&mut stream);
                let reason = if status == 200 { "OK" } else { "ERROR" };
                let content_type = content_type
                    .as_deref()
                    .map(|value| format!("Content-Type: {value}\r\n"))
                    .unwrap_or_default();
                write!(
                    stream,
                    "HTTP/1.1 {status} {reason}\r\n{content_type}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .expect("stub headers");
                stream.write_all(&body).expect("stub body");
                request
            });
            Self {
                endpoint: format!("http://{address}/"),
                request,
            }
        }

        fn authority(&self, target: &str, max_response_bytes: u64) -> AuthorityDocument {
            AuthorityDocument::new(
                target,
                format!("sha256:{}", "c".repeat(64)),
                "test-credential/revision-1",
                &self.endpoint,
                TOKEN,
                2_000,
                max_response_bytes,
            )
            .expect("authority")
        }

        fn finish(self) -> String {
            self.request.join().expect("stub request thread")
        }
    }

    fn read_request(stream: &mut TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("stub read timeout");
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).expect("stub request read");
            assert!(read > 0, "request ended before headers");
            bytes.extend_from_slice(&buffer[..read]);
            assert!(
                bytes.len() <= 64 * 1024,
                "request headers exceeded test bound"
            );
        }
        String::from_utf8(bytes).expect("ASCII request")
    }

    fn body(value: Value) -> Vec<u8> {
        serde_json::to_vec(&value).expect("stub JSON")
    }

    #[test]
    fn exact_get_observation_passes_and_presentation_fields_are_not_projected() {
        let request = request();
        let proposed_fact = match &request.result.outcome {
            CapabilityOutcome::Produced { outputs, .. } => outputs[0].fact.clone(),
            CapabilityOutcome::Unable { .. } => unreachable!(),
        };
        let stub = Stub::spawn(200, body(json!([summary()])));
        let authority = stub.authority(TARGET, 64 * 1024);
        let assessment = assess(&request, &authority).expect("assessment");
        assert_eq!(assessment.outcome, AssessmentOutcome::Passed);
        assert_eq!(
            assessment.authority.attester.implementation,
            implementation_id()
        );
        assert_eq!(assessment.authority.attester.artifact_digest, digest('b'));
        assert_eq!(assessment.checks.len(), 3);
        assert!(assessment.evidence.is_empty());
        assert_eq!(
            match &request.candidate.result.outcome {
                CapabilityOutcome::Produced { outputs, .. } => &outputs[0].fact,
                CapabilityOutcome::Unable { .. } => unreachable!(),
            },
            &proposed_fact
        );

        let wire = stub.finish();
        assert!(wire.starts_with("GET /v1/conversations?include_archived=true HTTP/1.1\r\n"));
        assert!(wire.to_ascii_lowercase().contains(&format!(
            "authorization: bearer {}",
            TOKEN.to_ascii_lowercase()
        )));
    }

    #[test]
    fn complete_absence_and_semantic_mismatch_are_failed_assessments() {
        let absent = Stub::spawn(200, body(json!([])));
        let absent_assessment =
            assess(&request(), &absent.authority(TARGET, 64 * 1024)).expect("absence assessment");
        assert_eq!(absent_assessment.outcome, AssessmentOutcome::Failed);
        assert_eq!(
            absent_assessment.checks[CHECK_FLEETD_OBSERVATION].outcome,
            AssessmentOutcome::Failed
        );
        absent.finish();

        let mut reversed = summary();
        reversed["members"]
            .as_array_mut()
            .expect("members")
            .reverse();
        let mismatch = Stub::spawn(200, body(json!([reversed])));
        let mismatch_assessment = assess(&request(), &mismatch.authority(TARGET, 64 * 1024))
            .expect("mismatch assessment");
        assert_eq!(mismatch_assessment.outcome, AssessmentOutcome::Failed);
        assert_eq!(
            mismatch_assessment.checks[CHECK_FLEETD_OBSERVATION].outcome,
            AssessmentOutcome::Failed
        );
        mismatch.finish();
    }

    #[test]
    fn output_relation_and_authority_target_are_checked_separately() {
        let mismatching_reference = DirectConversationRef::new(
            FleetdTarget::parse("fleetd:target-b").expect("other target"),
            ConversationId::parse("conversation-1").expect("conversation ID"),
            1_787_700_000_000,
            intent().members().clone(),
        )
        .expect("mismatching reference");
        let stub = Stub::spawn(200, body(json!([summary()])));
        let assessment = assess(
            &request_with_reference(mismatching_reference),
            &stub.authority(TARGET, 64 * 1024),
        )
        .expect("relation assessment");
        assert_eq!(assessment.outcome, AssessmentOutcome::Failed);
        assert_eq!(
            assessment.checks[CHECK_INTENT_OUTPUT_RELATION].outcome,
            AssessmentOutcome::Failed
        );
        stub.finish();

        let unused_listener = TcpListener::bind("127.0.0.1:0").expect("unused listener");
        let endpoint = format!("http://{}/", unused_listener.local_addr().expect("address"));
        let wrong_authority = AuthorityDocument::new(
            "fleetd:target-b",
            format!("sha256:{}", "c".repeat(64)),
            "test-credential/revision-1",
            endpoint,
            TOKEN,
            100,
            1024,
        )
        .expect("wrong authority");
        assert!(matches!(
            assess(&request(), &wrong_authority),
            Err(AttesterError::AuthorityTargetMismatch)
        ));
    }

    #[test]
    fn duplicate_malformed_oversized_and_http_failure_are_operational() {
        let duplicate = Stub::spawn(200, body(json!([summary(), summary()])));
        assert!(matches!(
            assess(&request(), &duplicate.authority(TARGET, 64 * 1024)),
            Err(AttesterError::DuplicateConversationId)
        ));
        duplicate.finish();

        let malformed = Stub::spawn(200, b"not-json".to_vec());
        assert!(matches!(
            assess(&request(), &malformed.authority(TARGET, 64 * 1024)),
            Err(AttesterError::MalformedObservation)
        ));
        malformed.finish();

        let oversized = Stub::spawn(200, body(json!([summary()])));
        assert!(matches!(
            assess(&request(), &oversized.authority(TARGET, 32)),
            Err(AttesterError::ResponseTooLarge)
        ));
        oversized.finish();

        let unauthorized = Stub::spawn(401, body(json!({"error": "unauthorized"})));
        assert!(matches!(
            assess(&request(), &unauthorized.authority(TARGET, 64 * 1024)),
            Err(AttesterError::HttpStatus(401))
        ));
        unauthorized.finish();
    }

    #[test]
    fn public_response_extensions_are_ignored_but_malformed_order_is_operational() {
        let mut unknown = summary();
        unknown["transport_status"] = json!(200);
        unknown["members"][0]["future_member_field"] = json!({"ignored": true});
        let unknown = Stub::spawn(200, body(json!([unknown])));
        let assessment =
            assess(&request(), &unknown.authority(TARGET, 64 * 1024)).expect("assessment");
        assert_eq!(assessment.outcome, AssessmentOutcome::Passed);
        unknown.finish();

        let mut later = summary();
        later["id"] = json!("unrelated-later");
        later["created_at_ms"] = json!(2_000);
        let mut earlier = summary();
        earlier["id"] = json!("unrelated-earlier");
        earlier["created_at_ms"] = json!(1_000);
        let unordered = Stub::spawn(200, body(json!([later, earlier])));
        assert!(matches!(
            assess(&request(), &unordered.authority(TARGET, 64 * 1024)),
            Err(AttesterError::MalformedObservation)
        ));
        unordered.finish();
    }

    #[test]
    fn missing_and_wrong_success_content_types_are_operational() {
        for content_type in [None, Some("text/plain")] {
            let stub = Stub::spawn_with_content_type(200, content_type, body(json!([summary()])));
            assert!(matches!(
                assess(&request(), &stub.authority(TARGET, 64 * 1024)),
                Err(AttesterError::UnexpectedContentType)
            ));
            stub.finish();
        }
    }

    #[test]
    fn assessment_request_is_closed_and_rejects_attester_substitution() {
        let request = request();
        let encoded = serde_json::to_vec(&request).expect("request JSON");
        let decoded: AssessmentRequest = serde_json::from_slice(&encoded).expect("request decode");
        assert_eq!(decoded, request);
        decoded.validate().expect("request validation");

        let mut unknown = serde_json::to_value(&request).expect("request value");
        unknown["endpoint"] = json!("must-not-enter-semantic-request");
        assert!(serde_json::from_value::<AssessmentRequest>(unknown).is_err());

        let selected_artifact = request.invocation.selection.offer.artifact_digest.clone();
        assert!(matches!(
            AssessmentRequest::new(
                request.invocation.clone(),
                request.result.clone(),
                request.candidate.clone(),
                selected_artifact,
            ),
            Err(AttesterError::Authority(
                AuthorityError::AttesterNotIndependent
            ))
        ));
    }

    #[test]
    fn operational_errors_and_debug_surfaces_never_echo_authority_secrets() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral listener");
        let endpoint = format!("http://{}/", listener.local_addr().expect("address"));
        drop(listener);
        let authority = AuthorityDocument::new(
            TARGET,
            format!("sha256:{}", "c".repeat(64)),
            "test-credential/revision-1",
            endpoint,
            TOKEN,
            100,
            1024,
        )
        .expect("authority");
        let error = assess(&request(), &authority).expect_err("network failure");
        let surface = format!("{error} {error:?} {authority:?}");
        assert!(!surface.contains(TOKEN));
    }
}
