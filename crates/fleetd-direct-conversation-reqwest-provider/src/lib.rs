//! Exact Reqwest client for Fleetd's direct-conversation capability.
//!
//! This crate is one concrete client artifact. It owns neither a generic HTTP
//! provider interface nor Fleetd's state law. It accepts the exact semantic
//! invocation and separately supplied command authority, performs one public
//! Fleetd operation, and constructs one ordinary neutral capability result.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::time::Duration;

use fleetd_direct_conversation_command_abi::AuthorityDocument;
use fleetd_direct_conversation_contract::{
    AgentId, ConversationId, DeliveryMode, DirectConversationRef, DirectMember, DirectPairIntent,
    conversation_port_name, direct_conversation_ref_suite_id, immutable_mode_conflict_failure_kind,
    intent_port_name, open_or_resolve_capability_spec,
};
use gooir_capability::protocol::{
    CapabilityFailure, CapabilityInvocation, CapabilityResult, ImplementationId, NamedOutput,
};
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Exact implementation identity of this Reqwest client artifact.
pub const IMPLEMENTATION_ID: &str = "dev.fleetd.implementation/direct_conversation_reqwest@0.1.0";

const DIRECT_CONVERSATIONS_PATH: &str = "v1/direct-conversations";
const JSON_MEDIA_TYPE: &str = "application/json";
const IMMUTABLE_MODE_CONFLICT: &str =
    "conflict: direct conversation participant delivery modes are immutable";

/// Returns this client's fixed semantic implementation identity.
#[must_use]
pub fn implementation_id() -> ImplementationId {
    ImplementationId::new(
        "dev.fleetd.implementation",
        "direct_conversation_reqwest",
        "0.1.0",
    )
}

/// Executes one exact invocation using authority received outside its semantic
/// document.
///
/// # Errors
///
/// Fails closed before HTTP when invocation or authority correlation is wrong.
/// Transport failures, unexpected statuses, oversized responses, and malformed
/// or semantically inconsistent Fleetd responses are operational errors rather
/// than fabricated capability results.
pub fn execute(
    invocation: &CapabilityInvocation,
    authority: &AuthorityDocument,
) -> Result<CapabilityResult, ProviderError> {
    execute_with_authority(
        invocation,
        ResolvedAuthority {
            target: authority.target(),
            endpoint: authority.endpoint(),
            bearer_token: authority.bearer_token().expose_secret(),
            http_timeout_ms: authority.http_timeout_ms(),
            max_response_bytes: authority.max_response_bytes(),
        },
    )
}

#[derive(Clone, Copy)]
struct ResolvedAuthority<'a> {
    target: &'a str,
    endpoint: &'a str,
    bearer_token: &'a str,
    http_timeout_ms: u64,
    max_response_bytes: u64,
}

fn execute_with_authority(
    invocation: &CapabilityInvocation,
    authority: ResolvedAuthority<'_>,
) -> Result<CapabilityResult, ProviderError> {
    let intent = validate_invocation(invocation)?;
    if authority.target != intent.fleetd_target().as_str() {
        return Err(ProviderError::AuthorityTargetMismatch);
    }
    if authority.http_timeout_ms == 0 || authority.max_response_bytes == 0 {
        return Err(ProviderError::InvalidAuthorityLimits);
    }

    let request = OpenDirectConversationRequest::from_intent(&intent);
    let request_bytes =
        serde_json::to_vec(&request).map_err(|_| ProviderError::RequestSerializationFailed)?;
    let client = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .timeout(Duration::from_millis(authority.http_timeout_ms))
        .build()
        .map_err(|_| ProviderError::ClientConstructionFailed)?;
    let response = client
        .post(format!("{}{DIRECT_CONVERSATIONS_PATH}", authority.endpoint))
        .header(ACCEPT, JSON_MEDIA_TYPE)
        .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
        .header(AUTHORIZATION, format!("Bearer {}", authority.bearer_token))
        .body(request_bytes)
        .send()
        .map_err(|_| ProviderError::TransportFailed)?;

    match response.status().as_u16() {
        200 | 201 => produced_result(invocation, &intent, response, authority.max_response_bytes),
        409 => unable_result(invocation, response, authority.max_response_bytes),
        _ => Err(ProviderError::UnexpectedStatus),
    }
}

fn validate_invocation(
    invocation: &CapabilityInvocation,
) -> Result<DirectPairIntent, ProviderError> {
    invocation
        .validate()
        .map_err(|_| ProviderError::InvalidInvocation)?;
    if invocation.specification != open_or_resolve_capability_spec() {
        return Err(ProviderError::UnexpectedCapabilitySpecification);
    }
    if invocation.selection.offer.implementation != implementation_id() {
        return Err(ProviderError::UnexpectedImplementation);
    }
    if invocation.conformance_suite != direct_conversation_ref_suite_id() {
        return Err(ProviderError::UnexpectedConformanceSuite);
    }
    let [input] = invocation.inputs.as_slice() else {
        return Err(ProviderError::UnexpectedInput);
    };
    if input.port != intent_port_name() {
        return Err(ProviderError::UnexpectedInput);
    }
    DirectPairIntent::from_fact(&input.fact).map_err(|_| ProviderError::UnexpectedInput)
}

fn produced_result(
    invocation: &CapabilityInvocation,
    intent: &DirectPairIntent,
    response: Response,
    max_response_bytes: u64,
) -> Result<CapabilityResult, ProviderError> {
    let body = read_json_body(response, max_response_bytes)?;
    let summary: ConversationSummary =
        serde_json::from_slice(&body).map_err(|_| ProviderError::MalformedSuccessResponse)?;
    let fact = summary.project(intent)?;
    let output = NamedOutput::new(conversation_port_name(), fact, BTreeMap::new())
        .map_err(|_| ProviderError::ResultConstructionFailed)?;
    CapabilityResult::produced(
        invocation,
        vec![output],
        BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
    )
    .map_err(|_| ProviderError::ResultConstructionFailed)
}

fn unable_result(
    invocation: &CapabilityInvocation,
    response: Response,
    max_response_bytes: u64,
) -> Result<CapabilityResult, ProviderError> {
    let body = read_json_body(response, max_response_bytes)?;
    let error: ErrorResponse =
        serde_json::from_slice(&body).map_err(|_| ProviderError::UnexpectedConflictResponse)?;
    if error.error != IMMUTABLE_MODE_CONFLICT {
        return Err(ProviderError::UnexpectedConflictResponse);
    }
    let failure = CapabilityFailure::new(
        immutable_mode_conflict_failure_kind(),
        Value::Null,
        BTreeMap::new(),
    )
    .map_err(|_| ProviderError::ResultConstructionFailed)?;
    CapabilityResult::unable(
        invocation,
        failure,
        BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
    )
    .map_err(|_| ProviderError::ResultConstructionFailed)
}

fn read_json_body(
    mut response: Response,
    max_response_bytes: u64,
) -> Result<Vec<u8>, ProviderError> {
    if !has_json_content_type(&response) {
        return Err(ProviderError::UnexpectedContentType);
    }
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > max_response_bytes)
    {
        return Err(ProviderError::ResponseTooLarge);
    }
    let read_limit = max_response_bytes
        .checked_add(1)
        .ok_or(ProviderError::InvalidAuthorityLimits)?;
    let mut body = Vec::new();
    response
        .by_ref()
        .take(read_limit)
        .read_to_end(&mut body)
        .map_err(|_| ProviderError::ResponseReadFailed)?;
    if u64::try_from(body.len()).map_or(true, |length| length > max_response_bytes) {
        return Err(ProviderError::ResponseTooLarge);
    }
    Ok(body)
}

fn has_json_content_type(response: &Response) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(JSON_MEDIA_TYPE))
}

#[derive(Serialize)]
struct OpenDirectConversationRequest<'a> {
    members: [CreateChannelMember<'a>; 2],
}

impl<'a> OpenDirectConversationRequest<'a> {
    fn from_intent(intent: &'a DirectPairIntent) -> Self {
        let members = intent.members();
        Self {
            members: [
                CreateChannelMember::from_member(&members[0]),
                CreateChannelMember::from_member(&members[1]),
            ],
        }
    }
}

#[derive(Serialize)]
struct CreateChannelMember<'a> {
    agent_id: &'a str,
    delivery_mode: DeliveryMode,
}

impl<'a> CreateChannelMember<'a> {
    fn from_member(member: &'a DirectMember) -> Self {
        Self {
            agent_id: member.agent_id().as_str(),
            delivery_mode: member.delivery_mode(),
        }
    }
}

#[derive(Deserialize)]
struct ConversationSummary {
    id: String,
    name: String,
    kind: ConversationKind,
    metadata: Value,
    created_at_ms: i64,
    #[serde(default)]
    archived_at_ms: Option<i64>,
    #[serde(default)]
    latest_message_seq: Option<i64>,
    #[serde(default)]
    latest_message_at_ms: Option<i64>,
    members: Vec<ChannelMember>,
}

impl ConversationSummary {
    fn project(self, intent: &DirectPairIntent) -> Result<gooir_capability::Fact, ProviderError> {
        let _validated_nonsemantic_fields = (
            self.name,
            self.metadata,
            self.latest_message_seq,
            self.latest_message_at_ms,
        );
        if self.kind != ConversationKind::Direct || self.archived_at_ms.is_some() {
            return Err(ProviderError::InconsistentSuccessResponse);
        }
        let [first, second] = self.members.as_slice() else {
            return Err(ProviderError::InconsistentSuccessResponse);
        };
        let response_members = [
            first.to_direct_member(&self.id)?,
            second.to_direct_member(&self.id)?,
        ];
        let response_intent =
            DirectPairIntent::new(intent.fleetd_target().clone(), response_members)
                .map_err(|_| ProviderError::InconsistentSuccessResponse)?;
        if &response_intent != intent {
            return Err(ProviderError::InconsistentSuccessResponse);
        }
        let conversation_id = ConversationId::parse(self.id)
            .map_err(|_| ProviderError::InconsistentSuccessResponse)?;
        DirectConversationRef::for_intent(intent, conversation_id, self.created_at_ms)
            .map_err(|_| ProviderError::InconsistentSuccessResponse)?
            .to_fact()
            .map_err(|_| ProviderError::ResultConstructionFailed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ConversationKind {
    Direct,
    Shared,
}

#[derive(Deserialize)]
struct ChannelMember {
    channel_id: String,
    agent_id: String,
    agent_name: String,
    joined_at_ms: i64,
    delivery_mode: DeliveryMode,
}

impl ChannelMember {
    fn to_direct_member(&self, conversation_id: &str) -> Result<DirectMember, ProviderError> {
        let _validated_nonsemantic_fields = (&self.agent_name, self.joined_at_ms);
        if self.channel_id != conversation_id {
            return Err(ProviderError::InconsistentSuccessResponse);
        }
        let agent_id = AgentId::parse(self.agent_id.clone())
            .map_err(|_| ProviderError::InconsistentSuccessResponse)?;
        Ok(DirectMember::new(agent_id, self.delivery_mode))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorResponse {
    error: String,
}

/// Operational failure that must not be serialized as a semantic result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderError {
    InvalidInvocation,
    UnexpectedCapabilitySpecification,
    UnexpectedImplementation,
    UnexpectedConformanceSuite,
    UnexpectedInput,
    AuthorityTargetMismatch,
    InvalidEndpoint,
    InvalidAuthorityLimits,
    RequestSerializationFailed,
    ClientConstructionFailed,
    TransportFailed,
    UnexpectedStatus,
    UnexpectedContentType,
    ResponseTooLarge,
    ResponseReadFailed,
    MalformedSuccessResponse,
    InconsistentSuccessResponse,
    UnexpectedConflictResponse,
    ResultConstructionFailed,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInvocation => "the capability invocation is invalid",
            Self::UnexpectedCapabilitySpecification => {
                "the capability specification is not the exact Fleetd direct-conversation contract"
            }
            Self::UnexpectedImplementation => "the invocation selected a different implementation",
            Self::UnexpectedConformanceSuite => {
                "the invocation selected a different conformance suite"
            }
            Self::UnexpectedInput => "the invocation input is not the exact direct-pair intent",
            Self::AuthorityTargetMismatch => {
                "the deployment authority does not match the semantic target"
            }
            Self::InvalidEndpoint => "the deployment authority endpoint is invalid",
            Self::InvalidAuthorityLimits => "the deployment authority limits are invalid",
            Self::RequestSerializationFailed => "the Fleetd request could not be serialized",
            Self::ClientConstructionFailed => "the HTTP client could not be constructed",
            Self::TransportFailed => "the Fleetd request failed operationally",
            Self::UnexpectedStatus => "Fleetd returned an unexpected status",
            Self::UnexpectedContentType => "Fleetd returned an unexpected content type",
            Self::ResponseTooLarge => "the Fleetd response exceeded its byte limit",
            Self::ResponseReadFailed => "the Fleetd response could not be read",
            Self::MalformedSuccessResponse => "Fleetd returned a malformed success response",
            Self::InconsistentSuccessResponse => {
                "Fleetd returned a success response inconsistent with the exact intent"
            }
            Self::UnexpectedConflictResponse => "Fleetd returned an unrecognized conflict response",
            Self::ResultConstructionFailed => "the capability result could not be constructed",
        })
    }
}

impl Error for ProviderError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc::{self, Receiver};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use fleetd_direct_conversation_command_abi::AuthorityDocument;
    use fleetd_direct_conversation_contract::{
        AgentId, DeliveryMode, DirectConversationRef, DirectMember, DirectPairIntent, FleetdTarget,
        direct_conversation_ref_suite_id, immutable_mode_conflict_failure_kind, intent_port_name,
        open_or_resolve_capability_spec,
    };
    use gooir_capability::protocol::{
        AdmittedFactRef, ArtifactDigest, AuthorityRecordId, CapabilityInvocation, CapabilityOffer,
        CapabilityOutcome, ImplementationSelection, LinkedInput,
    };
    use serde_json::{Value, json};

    use super::*;

    const TARGET: &str = "fleetd:target-a";
    const TOKEN: &str = "operator-token.secret";
    const MAX_RESPONSE: u64 = 64 * 1024;

    fn sha(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn intent() -> DirectPairIntent {
        DirectPairIntent::new(
            FleetdTarget::parse(TARGET).expect("target"),
            [
                DirectMember::new(
                    AgentId::parse("agent-b").expect("agent"),
                    DeliveryMode::StreamOnly,
                ),
                DirectMember::new(
                    AgentId::parse("agent-a").expect("agent"),
                    DeliveryMode::Inbox,
                ),
            ],
        )
        .expect("intent")
    }

    fn invocation() -> CapabilityInvocation {
        let intent_fact = intent().to_fact().expect("intent fact");
        let specification = open_or_resolve_capability_spec();
        let offer = CapabilityOffer::new(
            implementation_id(),
            ArtifactDigest::parse(sha('a')).expect("artifact digest"),
            specification.id.clone(),
            BTreeMap::new(),
        )
        .expect("offer");
        let admitted = AdmittedFactRef::new(
            intent_fact.id.clone(),
            AuthorityRecordId::parse(sha('b')).expect("authority record"),
            BTreeMap::new(),
        )
        .expect("admitted fact");
        let input = LinkedInput::new(intent_port_name(), admitted, intent_fact, BTreeMap::new())
            .expect("linked input");
        CapabilityInvocation::new(
            specification,
            ImplementationSelection::new(offer, BTreeMap::new()).expect("selection"),
            vec![input],
            direct_conversation_ref_suite_id(),
            BTreeMap::new(),
        )
        .expect("invocation")
    }

    fn authority(endpoint: &str, target: &str, max_response_bytes: u64) -> AuthorityDocument {
        AuthorityDocument::new(
            target,
            sha('c'),
            "operator-credential/revision-1",
            endpoint,
            TOKEN,
            5_000,
            max_response_bytes,
        )
        .expect("authority")
    }

    fn success_body() -> Value {
        json!({
            "id": "conversation-1",
            "name": "Direct agent-a and agent-b",
            "kind": "direct",
            "metadata": {},
            "created_at_ms": 42,
            "archived_at_ms": null,
            "latest_message_seq": null,
            "latest_message_at_ms": null,
            "members": [
                {
                    "channel_id": "conversation-1",
                    "agent_id": "agent-b",
                    "agent_name": "Agent B",
                    "joined_at_ms": 42,
                    "delivery_mode": "stream_only"
                },
                {
                    "channel_id": "conversation-1",
                    "agent_id": "agent-a",
                    "agent_name": "Agent A",
                    "joined_at_ms": 42,
                    "delivery_mode": "inbox"
                }
            ]
        })
    }

    struct CapturedRequest {
        method: String,
        path: String,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    }

    struct StubServer {
        endpoint: String,
        request: Receiver<CapturedRequest>,
        thread: JoinHandle<()>,
    }

    fn serve_once(status: u16, content_type: Option<&str>, body: Vec<u8>) -> StubServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub server");
        let address = listener.local_addr().expect("stub address");
        let endpoint = format!("http://{address}/");
        let (sender, request) = mpsc::channel();
        let content_type = content_type.map(str::to_owned);
        let thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout");
            let captured = read_request(&mut stream);
            sender.send(captured).expect("capture request");
            let phrase = match status {
                200 => "OK",
                201 => "Created",
                400 => "Bad Request",
                401 => "Unauthorized",
                403 => "Forbidden",
                404 => "Not Found",
                409 => "Conflict",
                _ => "Internal Server Error",
            };
            let mut headers = format!(
                "HTTP/1.1 {status} {phrase}\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            if let Some(content_type) = content_type {
                headers.push_str(&format!("Content-Type: {content_type}\r\n"));
            }
            headers.push_str("\r\n");
            let _ = stream.write_all(headers.as_bytes());
            let _ = stream.write_all(&body);
        });
        StubServer {
            endpoint,
            request,
            thread,
        }
    }

    fn read_request(stream: &mut TcpStream) -> CapturedRequest {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        let header_end = loop {
            let read = stream.read(&mut buffer).expect("read request");
            assert!(read != 0, "request ended before headers");
            bytes.extend_from_slice(&buffer[..read]);
            if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let header_text = std::str::from_utf8(&bytes[..header_end]).expect("request headers");
        let mut lines = header_text.split("\r\n");
        let mut request_line = lines.next().expect("request line").split_whitespace();
        let method = request_line.next().expect("method").to_owned();
        let path = request_line.next().expect("path").to_owned();
        let mut headers = BTreeMap::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').expect("header");
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
        let body_length = headers
            .get("content-length")
            .expect("content length")
            .parse::<usize>()
            .expect("content length number");
        while bytes.len() - header_end < body_length {
            let read = stream.read(&mut buffer).expect("read request body");
            assert!(read != 0, "request body ended early");
            bytes.extend_from_slice(&buffer[..read]);
        }
        CapturedRequest {
            method,
            path,
            headers,
            body: bytes[header_end..header_end + body_length].to_vec(),
        }
    }

    fn finish(server: StubServer) -> CapturedRequest {
        let request = server
            .request
            .recv_timeout(Duration::from_secs(5))
            .expect("captured request");
        server.thread.join().expect("stub server");
        request
    }

    #[test]
    fn created_response_projects_the_exact_fact_and_request() {
        let invocation = invocation();
        let server = serve_once(
            201,
            Some("application/json; charset=utf-8"),
            serde_json::to_vec(&success_body()).expect("success JSON"),
        );
        let authority = authority(&server.endpoint, TARGET, MAX_RESPONSE);
        let result = execute(&invocation, &authority).expect("produced result");
        result.validate_against(&invocation).expect("valid result");
        assert!(result.evidence.is_empty());
        let CapabilityOutcome::Produced {
            outputs,
            extensions,
        } = result.outcome
        else {
            panic!("expected produced result")
        };
        assert!(extensions.is_empty());
        let [output] = outputs.as_slice() else {
            panic!("expected one output")
        };
        assert!(output.extensions.is_empty());
        let reference =
            DirectConversationRef::from_fact(&output.fact).expect("conversation reference");
        assert_eq!(reference.conversation_id().as_str(), "conversation-1");
        assert_eq!(reference.created_at_ms(), 42);
        assert_eq!(reference.members(), intent().members());

        let request = finish(server);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/v1/direct-conversations");
        assert!(
            request
                .headers
                .get("authorization")
                .is_some_and(|value| value == "Bearer operator-token.secret"),
            "authorization header mismatch"
        );
        assert_eq!(
            request.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body).expect("request JSON"),
            json!({
                "members": [
                    {"agent_id": "agent-a", "delivery_mode": "inbox"},
                    {"agent_id": "agent-b", "delivery_mode": "stream_only"}
                ]
            })
        );
    }

    #[test]
    fn existing_response_and_unknown_public_response_fields_are_accepted() {
        let invocation = invocation();
        let mut body = success_body();
        body["metadata"] = json!(["public", "unconstrained", 7]);
        body["future_summary_field"] = json!({"preserved_by_fleetd": true});
        body["members"][0]["future_member_field"] = json!(7);
        let server = serve_once(
            200,
            Some(JSON_MEDIA_TYPE),
            serde_json::to_vec(&body).expect("success JSON"),
        );
        let authority = authority(&server.endpoint, TARGET, MAX_RESPONSE);
        let result = execute(&invocation, &authority).expect("resolved result");
        assert!(result.is_produced());
        finish(server);
    }

    #[test]
    fn only_the_exact_closed_conflict_is_a_typed_inability() {
        let invocation = invocation();
        let server = serve_once(
            409,
            Some(JSON_MEDIA_TYPE),
            serde_json::to_vec(&json!({"error": IMMUTABLE_MODE_CONFLICT})).expect("conflict JSON"),
        );
        let authority = authority(&server.endpoint, TARGET, MAX_RESPONSE);
        let result = execute(&invocation, &authority).expect("typed inability");
        result.validate_against(&invocation).expect("valid result");
        assert!(result.evidence.is_empty());
        let CapabilityOutcome::Unable {
            failure,
            extensions,
        } = result.outcome
        else {
            panic!("expected inability")
        };
        assert_eq!(failure.kind, immutable_mode_conflict_failure_kind());
        assert_eq!(failure.detail, Value::Null);
        assert!(failure.extensions.is_empty());
        assert!(extensions.is_empty());
        finish(server);
    }

    #[test]
    fn arbitrary_malformed_and_extended_conflicts_are_operational() {
        for body in [
            br#"{"error":"some other conflict"}"#.to_vec(),
            br#"{"error":"conflict: direct conversation participant delivery modes are immutable","extra":true}"#.to_vec(),
            b"not-json".to_vec(),
        ] {
            let invocation = invocation();
            let server = serve_once(409, Some(JSON_MEDIA_TYPE), body);
            let authority = authority(&server.endpoint, TARGET, MAX_RESPONSE);
            assert_eq!(
                execute(&invocation, &authority),
                Err(ProviderError::UnexpectedConflictResponse)
            );
            finish(server);
        }
    }

    #[test]
    fn every_other_status_is_operational() {
        for status in [400, 401, 403, 404, 500] {
            let invocation = invocation();
            let server = serve_once(
                status,
                Some(JSON_MEDIA_TYPE),
                br#"{"error":"operational"}"#.to_vec(),
            );
            let authority = authority(&server.endpoint, TARGET, MAX_RESPONSE);
            assert_eq!(
                execute(&invocation, &authority),
                Err(ProviderError::UnexpectedStatus)
            );
            finish(server);
        }
    }

    #[test]
    fn malformed_mismatched_and_non_json_successes_are_operational() {
        let mut cases = Vec::new();
        cases.push((Some(JSON_MEDIA_TYPE), b"not-json".to_vec()));

        let mut wrong_kind = success_body();
        wrong_kind["kind"] = json!("shared");
        cases.push((
            Some(JSON_MEDIA_TYPE),
            serde_json::to_vec(&wrong_kind).expect("wrong kind"),
        ));

        let mut wrong_member = success_body();
        wrong_member["members"][0]["agent_id"] = json!("agent-c");
        cases.push((
            Some(JSON_MEDIA_TYPE),
            serde_json::to_vec(&wrong_member).expect("wrong member"),
        ));

        let mut wrong_channel = success_body();
        wrong_channel["members"][1]["channel_id"] = json!("other-conversation");
        cases.push((
            Some(JSON_MEDIA_TYPE),
            serde_json::to_vec(&wrong_channel).expect("wrong channel"),
        ));

        let mut archived = success_body();
        archived["archived_at_ms"] = json!(43);
        cases.push((
            Some(JSON_MEDIA_TYPE),
            serde_json::to_vec(&archived).expect("archived"),
        ));

        cases.push((
            Some("text/plain"),
            serde_json::to_vec(&success_body()).expect("success JSON"),
        ));

        for (content_type, body) in cases {
            let invocation = invocation();
            let server = serve_once(200, content_type, body);
            let authority = authority(&server.endpoint, TARGET, MAX_RESPONSE);
            assert!(execute(&invocation, &authority).is_err());
            finish(server);
        }
    }

    #[test]
    fn response_byte_bound_is_enforced_before_interpretation() {
        let invocation = invocation();
        let body = serde_json::to_vec(&success_body()).expect("success JSON");
        let limit = u64::try_from(body.len() - 1).expect("limit");
        let server = serve_once(200, Some(JSON_MEDIA_TYPE), body);
        let authority = authority(&server.endpoint, TARGET, limit);
        assert_eq!(
            execute(&invocation, &authority),
            Err(ProviderError::ResponseTooLarge)
        );
        finish(server);
    }

    #[test]
    fn authority_target_is_correlated_before_http() {
        let invocation = invocation();
        let authority = AuthorityDocument::new(
            "fleetd:other-target",
            sha('c'),
            "operator-credential/revision-1",
            "http://127.0.0.1:9/",
            TOKEN,
            100,
            MAX_RESPONSE,
        )
        .expect("authority");
        assert_eq!(
            execute(&invocation, &authority),
            Err(ProviderError::AuthorityTargetMismatch)
        );
    }

    #[test]
    fn network_failure_is_operational_and_secret_free() {
        let invocation = invocation();
        let listener = TcpListener::bind("127.0.0.1:0").expect("reserve endpoint");
        let endpoint = format!("http://{}/", listener.local_addr().expect("address"));
        drop(listener);
        let authority = AuthorityDocument::new(
            TARGET,
            sha('c'),
            "operator-credential/revision-1",
            endpoint,
            TOKEN,
            100,
            MAX_RESPONSE,
        )
        .expect("authority");
        let error = execute(&invocation, &authority).expect_err("network failure");
        assert_eq!(error, ProviderError::TransportFailed);
        let surface = format!("{error} {error:?}");
        assert!(!surface.contains(TOKEN));
    }
}
