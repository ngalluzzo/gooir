//! One exact Fleetd direct-conversation provider implemented with Ureq.
//!
//! Fleetd owns the durable operation. This crate independently maps the
//! governed semantic contract to Fleetd's pinned public HTTP representation;
//! it is not a reusable Fleetd client or an execution-host abstraction.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io::Read as _;
use std::time::Duration;

use fleetd_direct_conversation_command_abi::AuthorityDocument;
use fleetd_direct_conversation_contract::{
    ConversationId, DeliveryMode, DirectConversationRef, DirectPairIntent, conversation_port_name,
    direct_conversation_ref_suite_id, immutable_mode_conflict_failure_kind,
    open_or_resolve_capability_spec,
};
use gooir_capability::CapabilitySpec;
use gooir_capability::protocol::{
    ArtifactDigest, CapabilityFailure, CapabilityInvocation, CapabilityOffer, CapabilityResult,
    ImplementationId, NamedOutput, ProtocolError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const IMPLEMENTATION_NAMESPACE: &str = "dev.fleetd.implementation";
const IMPLEMENTATION_NAME: &str = "direct_conversation_ureq";
const IMPLEMENTATION_VERSION: &str = "0.1.0";
const OPEN_PATH: &str = "v1/direct-conversations";
const JSON_MEDIA_TYPE: &str = "application/json";
const IMMUTABLE_MODE_CONFLICT: &str =
    "conflict: direct conversation participant delivery modes are immutable";

/// Exact semantic implementation identity of this Ureq client artifact.
#[must_use]
pub fn implementation_id() -> ImplementationId {
    ImplementationId::new(
        IMPLEMENTATION_NAMESPACE,
        IMPLEMENTATION_NAME,
        IMPLEMENTATION_VERSION,
    )
}

/// The complete implementation-independent promise this client implements.
#[must_use]
pub fn capability_spec() -> CapabilitySpec {
    open_or_resolve_capability_spec()
}

/// Constructs this client's offer from a host-measured artifact digest.
///
/// This declaration does not qualify a native runtime, select the offer, or
/// bind a target deployment. Those remain execution-host responsibilities.
pub fn capability_offer(
    artifact_digest: ArtifactDigest,
) -> Result<CapabilityOffer, UreqProviderError> {
    CapabilityOffer::new(
        implementation_id(),
        artifact_digest,
        capability_spec().id,
        BTreeMap::new(),
    )
    .map_err(UreqProviderError::Protocol)
}

/// Executes one exact invocation against the authority-bound Fleetd target.
///
/// The caller must supply an authority document obtained from the dedicated
/// inherited pipe. Only an exact immutable-mode conflict is a semantic
/// inability. Every transport, authentication, shape, or status failure is an
/// operational error and therefore produces no [`CapabilityResult`].
pub fn invoke(
    invocation: &CapabilityInvocation,
    authority: &AuthorityDocument,
) -> Result<CapabilityResult, UreqProviderError> {
    invocation.validate().map_err(UreqProviderError::Protocol)?;
    if invocation.specification != capability_spec() {
        return Err(UreqProviderError::SpecificationMismatch);
    }
    if invocation.selection.offer.implementation != implementation_id() {
        return Err(UreqProviderError::ImplementationMismatch);
    }
    if invocation.conformance_suite != direct_conversation_ref_suite_id() {
        return Err(UreqProviderError::ConformanceSuiteMismatch);
    }
    let [linked] = invocation.inputs.as_slice() else {
        return Err(UreqProviderError::DeclarationShapeMismatch);
    };
    let intent = DirectPairIntent::from_fact(&linked.fact)
        .map_err(|_| UreqProviderError::IntentFactInvalid)?;
    if authority.target() != intent.fleetd_target().as_str() {
        return Err(UreqProviderError::AuthorityTargetMismatch);
    }

    let request = OpenDirectConversation {
        members: intent
            .members()
            .iter()
            .map(|member| CreateChannelMember {
                agent_id: member.agent_id().as_str(),
                delivery_mode: member.delivery_mode(),
            })
            .collect(),
    };
    let configuration = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_millis(authority.http_timeout_ms())))
        .max_redirects(0)
        .proxy(None)
        .http_status_as_error(false)
        .build();
    let agent: ureq::Agent = configuration.into();
    let authorization = format!("Bearer {}", authority.bearer_token().expose_secret());
    let endpoint = format!("{}{OPEN_PATH}", authority.endpoint());
    let mut response = agent
        .post(&endpoint)
        .header("accept", JSON_MEDIA_TYPE)
        .header("authorization", &authorization)
        .send_json(&request)
        .map_err(|_| UreqProviderError::Transport)?;
    drop(authorization);

    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(authority.max_response_bytes() + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| UreqProviderError::Transport)?;
    if bytes.len() as u64 > authority.max_response_bytes() {
        return Err(UreqProviderError::ResponseTooLarge);
    }

    match status {
        200 | 201 => {
            require_json_content_type(content_type.as_deref())?;
            produced_result(invocation, &intent, &bytes)
        }
        409 => {
            require_json_content_type(content_type.as_deref())?;
            unable_result(invocation, &bytes)
        }
        other => Err(UreqProviderError::UnexpectedStatus(other)),
    }
}

fn produced_result(
    invocation: &CapabilityInvocation,
    intent: &DirectPairIntent,
    bytes: &[u8],
) -> Result<CapabilityResult, UreqProviderError> {
    let response: ConversationSummary =
        serde_json::from_slice(bytes).map_err(|_| UreqProviderError::ResponseJsonInvalid)?;
    let ConversationSummary {
        id,
        _name: _,
        kind,
        _metadata: _,
        created_at_ms,
        archived_at_ms,
        members,
        _latest_message_seq: _,
        _latest_message_at_ms: _,
    } = response;
    if kind != ConversationKind::Direct {
        return Err(UreqProviderError::ResponseMismatch("conversation kind"));
    }
    if archived_at_ms.is_some() {
        return Err(UreqProviderError::ResponseMismatch("archived conversation"));
    }
    if members.len() != 2 {
        return Err(UreqProviderError::ResponseMismatch(
            "membership cardinality",
        ));
    }
    let conversation_id =
        ConversationId::parse(id).map_err(|_| UreqProviderError::ResponseMismatch("id"))?;
    let expected_id = conversation_id.as_str();
    let mut observed = members
        .into_iter()
        .map(|member| {
            let ChannelMember {
                channel_id,
                agent_id,
                _agent_name: _,
                _joined_at_ms: _,
                delivery_mode,
            } = member;
            if channel_id != expected_id {
                return Err(UreqProviderError::ResponseMismatch("member channel"));
            }
            Ok((agent_id, delivery_mode))
        })
        .collect::<Result<Vec<_>, _>>()?;
    observed.sort_by(|left, right| left.0.cmp(&right.0));
    for (actual, expected) in observed.iter().zip(intent.members()) {
        if actual.0 != expected.agent_id().as_str() || actual.1 != expected.delivery_mode() {
            return Err(UreqProviderError::ResponseMismatch("members"));
        }
    }

    let reference = DirectConversationRef::for_intent(intent, conversation_id, created_at_ms)
        .map_err(|_| UreqProviderError::ResponseMismatch("creation time"))?;
    let output = NamedOutput::new(
        conversation_port_name(),
        reference
            .to_fact()
            .map_err(|_| UreqProviderError::OutputFactInvalid)?,
        BTreeMap::new(),
    )
    .map_err(UreqProviderError::Protocol)?;
    CapabilityResult::produced(
        invocation,
        vec![output],
        BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
    )
    .map_err(UreqProviderError::Protocol)
}

fn unable_result(
    invocation: &CapabilityInvocation,
    bytes: &[u8],
) -> Result<CapabilityResult, UreqProviderError> {
    let response: ErrorResponse =
        serde_json::from_slice(bytes).map_err(|_| UreqProviderError::ConflictBodyMismatch)?;
    if response.error != IMMUTABLE_MODE_CONFLICT {
        return Err(UreqProviderError::ConflictBodyMismatch);
    }
    let failure = CapabilityFailure::new(
        immutable_mode_conflict_failure_kind(),
        Value::Null,
        BTreeMap::new(),
    )
    .map_err(UreqProviderError::Protocol)?;
    CapabilityResult::unable(
        invocation,
        failure,
        BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
    )
    .map_err(UreqProviderError::Protocol)
}

fn require_json_content_type(content_type: Option<&str>) -> Result<(), UreqProviderError> {
    let Some(media_type) = content_type.and_then(|value| value.split(';').next()) else {
        return Err(UreqProviderError::ResponseContentTypeInvalid);
    };
    if media_type.trim().eq_ignore_ascii_case(JSON_MEDIA_TYPE) {
        Ok(())
    } else {
        Err(UreqProviderError::ResponseContentTypeInvalid)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct OpenDirectConversation<'a> {
    members: Vec<CreateChannelMember<'a>>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CreateChannelMember<'a> {
    agent_id: &'a str,
    delivery_mode: DeliveryMode,
}

#[derive(Deserialize)]
struct ConversationSummary {
    id: String,
    #[serde(rename = "name")]
    _name: String,
    kind: ConversationKind,
    #[serde(rename = "metadata")]
    _metadata: Value,
    created_at_ms: i64,
    archived_at_ms: Option<i64>,
    members: Vec<ChannelMember>,
    #[serde(rename = "latest_message_seq")]
    _latest_message_seq: Option<i64>,
    #[serde(rename = "latest_message_at_ms")]
    _latest_message_at_ms: Option<i64>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ConversationKind {
    Direct,
}

#[derive(Deserialize)]
struct ChannelMember {
    channel_id: String,
    agent_id: String,
    #[serde(rename = "agent_name")]
    _agent_name: String,
    #[serde(rename = "joined_at_ms")]
    _joined_at_ms: i64,
    delivery_mode: DeliveryMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorResponse {
    error: String,
}

/// A secret-free failure at this exact client boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UreqProviderError {
    Protocol(ProtocolError),
    SpecificationMismatch,
    ImplementationMismatch,
    ConformanceSuiteMismatch,
    DeclarationShapeMismatch,
    IntentFactInvalid,
    AuthorityTargetMismatch,
    Transport,
    ResponseTooLarge,
    ResponseContentTypeInvalid,
    UnexpectedStatus(u16),
    ResponseJsonInvalid,
    ResponseMismatch(&'static str),
    ConflictBodyMismatch,
    OutputFactInvalid,
}

impl fmt::Display for UreqProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "neutral protocol is invalid: {error}"),
            Self::SpecificationMismatch => formatter.write_str("capability specification mismatch"),
            Self::ImplementationMismatch => formatter.write_str("selected implementation mismatch"),
            Self::ConformanceSuiteMismatch => formatter.write_str("conformance suite mismatch"),
            Self::DeclarationShapeMismatch => {
                formatter.write_str("invocation declaration shape mismatch")
            }
            Self::IntentFactInvalid => formatter.write_str("direct-pair intent fact is invalid"),
            Self::AuthorityTargetMismatch => {
                formatter.write_str("authority target does not match the semantic target")
            }
            Self::Transport => formatter.write_str("Fleetd request failed operationally"),
            Self::ResponseTooLarge => {
                formatter.write_str("Fleetd response exceeded the authority limit")
            }
            Self::ResponseContentTypeInvalid => {
                formatter.write_str("Fleetd response media type is invalid")
            }
            Self::UnexpectedStatus(status) => {
                write!(formatter, "Fleetd returned operational status {status}")
            }
            Self::ResponseJsonInvalid => formatter.write_str("Fleetd success response is invalid"),
            Self::ResponseMismatch(field) => {
                write!(formatter, "Fleetd success response mismatched {field}")
            }
            Self::ConflictBodyMismatch => {
                formatter.write_str("Fleetd conflict response did not identify immutable modes")
            }
            Self::OutputFactInvalid => {
                formatter.write_str("Fleetd result fact could not be constructed")
            }
        }
    }
}

impl Error for UreqProviderError {}
