//! Fleetd-native meaning for opening or resolving one direct conversation.
//!
//! This contract owns only Fleetd's exact durable pair intent and resulting
//! conversation reference. It contains no HTTP, credential, process,
//! execution-host, presentation, messaging, or generic conversation model.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use gooir_capability::protocol::{ConformanceSuiteId, FailureKindId};
use gooir_capability::{
    CapabilityId, CapabilitySpec, DialectId, Fact, FactIdentityError, InputPort, OutputPort,
    PortName, ValueKindId,
};
use gooir_package::{
    ConformanceSuiteDeclaration, DialectDeclaration, PackageId, PackageManifest,
    PackageManifestError, PackageResource, ResourceDigest, ResourceName, ValueKindDeclaration,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

/// Exact package coordinate for this Fleetd-native contract.
pub const CONTRACT_PACKAGE: &str = "dev.fleetd.contract.direct_conversation@0.1.0";

/// Exact governed Fleetd conversation dialect package.
pub const DIALECT_PACKAGE: &str = "dev.fleetd.conversation";

/// Exact version shared by the dialect, value kinds, capability, and suite.
pub const CONTRACT_VERSION: &str = "0.1.0";

/// Package-local path of the direct-pair intent JSON Schema.
pub const DIRECT_PAIR_INTENT_SCHEMA_PATH: &str = "resources/direct-pair-intent.schema.json";

/// Package-local path of the direct-conversation reference JSON Schema.
pub const DIRECT_CONVERSATION_REF_SCHEMA_PATH: &str =
    "resources/direct-conversation-ref.schema.json";

/// Exact direct-pair intent JSON Schema bytes measured by the package.
pub const DIRECT_PAIR_INTENT_SCHEMA_BYTES: &[u8] =
    include_bytes!("../resources/direct-pair-intent.schema.json");

/// Exact direct-conversation reference JSON Schema bytes measured by the package.
pub const DIRECT_CONVERSATION_REF_SCHEMA_BYTES: &[u8] =
    include_bytes!("../resources/direct-conversation-ref.schema.json");

const MAX_OPAQUE_COORDINATE_CHARS: usize = 256;

/// Largest nonnegative integer retained exactly by JCS/I-JSON canonicalization.
pub const MAX_SAFE_JSON_INTEGER: i64 = 9_007_199_254_740_991;

/// Exact Fleetd delivery mode made immutable by a direct conversation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    Inbox,
    StreamOnly,
}

macro_rules! opaque_coordinate {
    ($(#[$meta:meta])* $name:ident, $invalid:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Parses one exact opaque coordinate without assigning structure to it.
            ///
            /// # Errors
            ///
            /// Refuses empty, padded, control-bearing, or oversized values.
            pub fn parse(value: impl Into<String>) -> Result<Self, PayloadError> {
                let value = value.into();
                if valid_opaque_coordinate(&value) {
                    Ok(Self(value))
                } else {
                    Err(PayloadError::$invalid)
                }
            }

            /// Exact preserved spelling of this opaque coordinate.
            #[must_use]
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

opaque_coordinate! {
    /// Opaque globally scoped coordinate for one operator-governed Fleetd target.
    ///
    /// It is deliberately not a URL, credential, tenant selector, or process
    /// handle. A separate host-qualified deployment lock gives it authority.
    FleetdTarget, InvalidFleetdTarget
}

opaque_coordinate! {
    /// Exact Fleetd-owned agent identity within one [`FleetdTarget`].
    AgentId, InvalidAgentId
}

opaque_coordinate! {
    /// Exact Fleetd-owned direct-conversation identity within one target.
    ConversationId, InvalidConversationId
}

/// One exact participant and the delivery mode fixed by the direct pair.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectMember {
    agent_id: AgentId,
    delivery_mode: DeliveryMode,
}

impl DirectMember {
    /// Constructs one exact member.
    #[must_use]
    pub const fn new(agent_id: AgentId, delivery_mode: DeliveryMode) -> Self {
        Self {
            agent_id,
            delivery_mode,
        }
    }

    /// Exact Fleetd-owned participant identity.
    #[must_use]
    pub const fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// Exact immutable delivery mode for this participant.
    #[must_use]
    pub const fn delivery_mode(&self) -> DeliveryMode {
        self.delivery_mode
    }
}

/// Intent to open or resolve Fleetd's one durable direct conversation for a pair.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DirectPairIntent {
    fleetd_target: FleetdTarget,
    members: [DirectMember; 2],
}

impl DirectPairIntent {
    /// Constructs one intent and canonicalizes its unordered pair by agent ID.
    ///
    /// # Errors
    ///
    /// Refuses two entries for the same agent.
    pub fn new(
        fleetd_target: FleetdTarget,
        mut members: [DirectMember; 2],
    ) -> Result<Self, PayloadError> {
        canonicalize_members(&mut members)?;
        Ok(Self {
            fleetd_target,
            members,
        })
    }

    /// Validates target structure and canonical, distinct pair ordering.
    ///
    /// # Errors
    ///
    /// Refuses invalid target coordinates, duplicate agents, or non-canonical
    /// member order.
    pub fn validate(&self) -> Result<(), PayloadError> {
        if !valid_opaque_coordinate(self.fleetd_target.as_str()) {
            return Err(PayloadError::InvalidFleetdTarget);
        }
        validate_canonical_members(&self.members)
    }

    /// Exact target coordinate governed outside this semantic document.
    #[must_use]
    pub const fn fleetd_target(&self) -> &FleetdTarget {
        &self.fleetd_target
    }

    /// Canonical distinct pair, sorted by exact agent ID.
    #[must_use]
    pub const fn members(&self) -> &[DirectMember; 2] {
        &self.members
    }

    /// Encodes this exact intent as its contract-owned semantic fact.
    ///
    /// # Errors
    ///
    /// Refuses a payload that cannot be validated, serialized, or assigned a
    /// canonical fact identity.
    pub fn to_fact(&self) -> Result<Fact, ContractFactError> {
        self.validate()
            .map_err(|error| ContractFactError::Payload(error.to_string()))?;
        encode_fact(self, direct_pair_intent_value_kind())
    }

    /// Decodes one exact, identity-valid intent fact.
    ///
    /// # Errors
    ///
    /// Refuses stale identities, the wrong value kind, semantic extensions,
    /// or a payload outside this contract's closed canonical shape.
    pub fn from_fact(fact: &Fact) -> Result<Self, ContractFactError> {
        decode_fact(fact, direct_pair_intent_value_kind())
    }
}

impl<'de> Deserialize<'de> for DirectPairIntent {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireIntent {
            fleetd_target: FleetdTarget,
            members: [DirectMember; 2],
        }

        let wire = WireIntent::deserialize(deserializer)?;
        let intent = Self {
            fleetd_target: wire.fleetd_target,
            members: wire.members,
        };
        intent.validate().map_err(serde::de::Error::custom)?;
        Ok(intent)
    }
}

/// Target-scoped reference to Fleetd's durable direct conversation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DirectConversationRef {
    fleetd_target: FleetdTarget,
    conversation_id: ConversationId,
    created_at_ms: i64,
    members: [DirectMember; 2],
}

impl DirectConversationRef {
    /// Constructs one target-scoped reference and canonicalizes its member pair.
    ///
    /// # Errors
    ///
    /// Refuses a Fleetd creation time outside the nonnegative JCS/I-JSON
    /// safe-integer domain or duplicate members.
    pub fn new(
        fleetd_target: FleetdTarget,
        conversation_id: ConversationId,
        created_at_ms: i64,
        mut members: [DirectMember; 2],
    ) -> Result<Self, PayloadError> {
        if !(0..=MAX_SAFE_JSON_INTEGER).contains(&created_at_ms) {
            return Err(PayloadError::CreatedAtMsOutsideSafeIntegerRange);
        }
        canonicalize_members(&mut members)?;
        Ok(Self {
            fleetd_target,
            conversation_id,
            created_at_ms,
            members,
        })
    }

    /// Validates target-scoped identity, time, and canonical distinct members.
    ///
    /// # Errors
    ///
    /// Refuses invalid coordinates, creation time outside the nonnegative
    /// JCS/I-JSON safe-integer domain, duplicate agents, or non-canonical
    /// member order.
    pub fn validate(&self) -> Result<(), PayloadError> {
        if !valid_opaque_coordinate(self.fleetd_target.as_str()) {
            return Err(PayloadError::InvalidFleetdTarget);
        }
        if !valid_opaque_coordinate(self.conversation_id.as_str()) {
            return Err(PayloadError::InvalidConversationId);
        }
        if !(0..=MAX_SAFE_JSON_INTEGER).contains(&self.created_at_ms) {
            return Err(PayloadError::CreatedAtMsOutsideSafeIntegerRange);
        }
        validate_canonical_members(&self.members)
    }

    /// Exact target coordinate that scopes the conversation identity.
    #[must_use]
    pub const fn fleetd_target(&self) -> &FleetdTarget {
        &self.fleetd_target
    }

    /// Opaque Fleetd-owned durable conversation identity.
    #[must_use]
    pub const fn conversation_id(&self) -> &ConversationId {
        &self.conversation_id
    }

    /// Fleetd-owned creation time in Unix epoch milliseconds.
    #[must_use]
    pub const fn created_at_ms(&self) -> i64 {
        self.created_at_ms
    }

    /// Canonical distinct pair, sorted by exact agent ID.
    #[must_use]
    pub const fn members(&self) -> &[DirectMember; 2] {
        &self.members
    }

    /// Constructs a result that retains the intent's target and canonical pair
    /// exactly, adding only Fleetd's durable identity and creation time.
    ///
    /// # Errors
    ///
    /// Refuses creation times outside the nonnegative JCS/I-JSON safe-integer
    /// domain.
    pub fn for_intent(
        intent: &DirectPairIntent,
        conversation_id: ConversationId,
        created_at_ms: i64,
    ) -> Result<Self, PayloadError> {
        Self::new(
            intent.fleetd_target.clone(),
            conversation_id,
            created_at_ms,
            intent.members.clone(),
        )
    }

    /// Encodes this exact reference as its contract-owned semantic fact.
    ///
    /// # Errors
    ///
    /// Refuses a payload that cannot be validated, serialized, or assigned a
    /// canonical fact identity.
    pub fn to_fact(&self) -> Result<Fact, ContractFactError> {
        self.validate()
            .map_err(|error| ContractFactError::Payload(error.to_string()))?;
        encode_fact(self, direct_conversation_ref_value_kind())
    }

    /// Decodes one exact, identity-valid conversation-reference fact.
    ///
    /// # Errors
    ///
    /// Refuses stale identities, the wrong value kind, semantic extensions,
    /// or a payload outside this contract's closed canonical shape.
    pub fn from_fact(fact: &Fact) -> Result<Self, ContractFactError> {
        decode_fact(fact, direct_conversation_ref_value_kind())
    }
}

impl<'de> Deserialize<'de> for DirectConversationRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireReference {
            fleetd_target: FleetdTarget,
            conversation_id: ConversationId,
            created_at_ms: i64,
            members: [DirectMember; 2],
        }

        let wire = WireReference::deserialize(deserializer)?;
        let reference = Self {
            fleetd_target: wire.fleetd_target,
            conversation_id: wire.conversation_id,
            created_at_ms: wire.created_at_ms,
            members: wire.members,
        };
        reference.validate().map_err(serde::de::Error::custom)?;
        Ok(reference)
    }
}

/// Structural failure in one Fleetd-native semantic payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadError {
    InvalidFleetdTarget,
    InvalidAgentId,
    InvalidConversationId,
    DuplicateMembers,
    NonCanonicalMembers,
    CreatedAtMsOutsideSafeIntegerRange,
}

impl fmt::Display for PayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFleetdTarget => "Fleetd target coordinate is invalid",
            Self::InvalidAgentId => "Fleetd agent ID is invalid",
            Self::InvalidConversationId => "Fleetd conversation ID is invalid",
            Self::DuplicateMembers => "direct pair members must be distinct",
            Self::NonCanonicalMembers => "direct pair members must be sorted by exact agent ID",
            Self::CreatedAtMsOutsideSafeIntegerRange => {
                "Fleetd creation time must be a nonnegative JCS/I-JSON safe integer"
            }
        })
    }
}

impl Error for PayloadError {}

/// Exact package identity for this contract.
#[must_use]
pub fn contract_package_id() -> PackageId {
    PackageId::parse(CONTRACT_PACKAGE).expect("the fixed contract package coordinate is valid")
}

/// Exact identity of Fleetd's governed conversation dialect.
#[must_use]
pub fn dialect_id() -> DialectId {
    DialectId::new(DIALECT_PACKAGE, CONTRACT_VERSION)
}

/// Exact value kind of one Fleetd direct-pair intent.
#[must_use]
pub fn direct_pair_intent_value_kind() -> ValueKindId {
    ValueKindId::in_dialect(dialect_id(), "direct_pair_intent")
}

/// Exact value kind of one target-scoped Fleetd direct-conversation reference.
#[must_use]
pub fn direct_conversation_ref_value_kind() -> ValueKindId {
    ValueKindId::in_dialect(dialect_id(), "direct_conversation_ref")
}

/// Exact Fleetd-native capability identity.
#[must_use]
pub fn open_or_resolve_capability_id() -> CapabilityId {
    CapabilityId::new(
        "dev.fleetd.capability",
        "open_or_resolve_direct_conversation",
        CONTRACT_VERSION,
    )
}

/// Exact conformance obligation for a Fleetd direct-conversation reference.
#[must_use]
pub fn direct_conversation_ref_suite_id() -> ConformanceSuiteId {
    ConformanceSuiteId::new(
        "dev.fleetd.conformance",
        "direct_conversation_ref",
        CONTRACT_VERSION,
    )
}

/// Exact typed inability for Fleetd's immutable delivery-mode conflict.
///
/// This names only the semantic inability owned by the contract. A later
/// provider may emit it for Fleetd's exact conflict response; transport and
/// status-code interpretation do not belong in this crate.
#[must_use]
pub fn immutable_mode_conflict_failure_kind() -> FailureKindId {
    FailureKindId::new(
        "dev.fleetd.failure",
        "direct_conversation_immutable_mode_conflict",
        CONTRACT_VERSION,
    )
}

/// Complete provider-independent Fleetd direct-conversation promise.
#[must_use]
pub fn open_or_resolve_capability_spec() -> CapabilitySpec {
    CapabilitySpec {
        id: open_or_resolve_capability_id(),
        input_ports: vec![InputPort::complete(
            intent_port_name(),
            direct_pair_intent_value_kind(),
        )],
        output_ports: vec![OutputPort::new(
            conversation_port_name(),
            direct_conversation_ref_value_kind(),
        )],
        default_conformance_suite: direct_conversation_ref_suite_id().to_string(),
        extensions: BTreeMap::new(),
    }
}

/// Exact public input-port identity of the direct-conversation capability.
#[must_use]
pub fn intent_port_name() -> PortName {
    port("intent")
}

/// Exact public output-port identity of the direct-conversation capability.
#[must_use]
pub fn conversation_port_name() -> PortName {
    port("conversation")
}

/// Constructs the exact implementation-independent contract package.
///
/// The package owns only its two schema resources, dialect and value kinds,
/// one conformance-suite declaration, and one capability. Provider and
/// attester artifacts belong to later, separately measured packages.
///
/// # Errors
///
/// Refuses an invalid fixed resource digest or manifest invariant.
pub fn package_manifest() -> Result<PackageManifest, ContractPackageError> {
    PackageManifest::new(
        contract_package_id(),
        Vec::new(),
        vec![
            schema_resource(
                direct_conversation_ref_schema_resource_name(),
                DIRECT_CONVERSATION_REF_SCHEMA_PATH,
                DIRECT_CONVERSATION_REF_SCHEMA_BYTES,
            )?,
            schema_resource(
                direct_pair_intent_schema_resource_name(),
                DIRECT_PAIR_INTENT_SCHEMA_PATH,
                DIRECT_PAIR_INTENT_SCHEMA_BYTES,
            )?,
        ],
        vec![DialectDeclaration {
            id: dialect_id(),
            value_kinds: vec![
                ValueKindDeclaration {
                    id: direct_conversation_ref_value_kind(),
                    schema: Some(direct_conversation_ref_schema_resource_name()),
                    extensions: BTreeMap::new(),
                },
                ValueKindDeclaration {
                    id: direct_pair_intent_value_kind(),
                    schema: Some(direct_pair_intent_schema_resource_name()),
                    extensions: BTreeMap::new(),
                },
            ],
            extensions: BTreeMap::new(),
        }],
        vec![ConformanceSuiteDeclaration {
            id: direct_conversation_ref_suite_id(),
            extensions: BTreeMap::new(),
        }],
        vec![open_or_resolve_capability_spec()],
        Vec::new(),
        BTreeMap::new(),
    )
    .map_err(ContractPackageError::Manifest)
}

fn valid_opaque_coordinate(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.chars().count() <= MAX_OPAQUE_COORDINATE_CHARS
        && !value.chars().any(char::is_control)
}

fn canonicalize_members(members: &mut [DirectMember; 2]) -> Result<(), PayloadError> {
    members.sort_by(|left, right| left.agent_id.cmp(&right.agent_id));
    validate_canonical_members(members)
}

fn validate_canonical_members(members: &[DirectMember; 2]) -> Result<(), PayloadError> {
    match members[0].agent_id.cmp(&members[1].agent_id) {
        Ordering::Less => Ok(()),
        Ordering::Equal => Err(PayloadError::DuplicateMembers),
        Ordering::Greater => Err(PayloadError::NonCanonicalMembers),
    }
}

fn direct_conversation_ref_schema_resource_name() -> ResourceName {
    ResourceName::parse("direct-conversation-ref-schema")
        .expect("the fixed direct-conversation schema resource name is valid")
}

fn direct_pair_intent_schema_resource_name() -> ResourceName {
    ResourceName::parse("direct-pair-intent-schema")
        .expect("the fixed direct-pair schema resource name is valid")
}

fn schema_resource(
    name: ResourceName,
    path: &str,
    bytes: &[u8],
) -> Result<PackageResource, ContractPackageError> {
    Ok(PackageResource {
        name,
        path: path.to_owned(),
        media_type: "application/schema+json".to_owned(),
        size: bytes.len() as u64,
        digest: ResourceDigest::parse(sha256_identity(bytes))
            .map_err(|error| ContractPackageError::SchemaDigest(error.to_string()))?,
        extensions: BTreeMap::new(),
    })
}

fn port(name: &str) -> PortName {
    PortName::parse(name).expect("the fixed Fleetd contract port name is valid")
}

fn sha256_identity(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut identity = String::with_capacity(71);
    identity.push_str("sha256:");
    for byte in digest {
        use fmt::Write as _;
        write!(identity, "{byte:02x}").expect("writing to a string cannot fail");
    }
    identity
}

fn encode_fact<T: Serialize>(
    payload: &T,
    value_kind: ValueKindId,
) -> Result<Fact, ContractFactError> {
    let payload = serde_json::to_value(payload)
        .map_err(|error| ContractFactError::Payload(error.to_string()))?;
    Fact::new(value_kind, payload).map_err(ContractFactError::Identity)
}

fn decode_fact<T: DeserializeOwned>(
    fact: &Fact,
    expected_kind: ValueKindId,
) -> Result<T, ContractFactError> {
    fact.validate().map_err(ContractFactError::Identity)?;
    if fact.value_kind != expected_kind {
        return Err(ContractFactError::UnexpectedValueKind {
            expected: Box::new(expected_kind),
            actual: Box::new(fact.value_kind.clone()),
        });
    }
    if !fact.extensions.is_empty() {
        return Err(ContractFactError::SemanticExtensions(
            fact.extensions.keys().cloned().collect(),
        ));
    }
    serde_json::from_value(fact.payload.clone())
        .map_err(|error| ContractFactError::Payload(error.to_string()))
}

/// Failure to cross between a closed Fleetd payload and a semantic [`Fact`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractFactError {
    Identity(FactIdentityError),
    UnexpectedValueKind {
        expected: Box<ValueKindId>,
        actual: Box<ValueKindId>,
    },
    SemanticExtensions(Vec<String>),
    Payload(String),
}

impl fmt::Display for ContractFactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(error) => write!(formatter, "fact identity is invalid: {error}"),
            Self::UnexpectedValueKind { expected, actual } => {
                write!(formatter, "expected fact kind {expected}, got {actual}")
            }
            Self::SemanticExtensions(keys) => {
                write!(
                    formatter,
                    "semantic fact extensions are not supported: {keys:?}"
                )
            }
            Self::Payload(error) => write!(formatter, "contract payload is invalid: {error}"),
        }
    }
}

impl Error for ContractFactError {}

/// Failure to construct the exact contract package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractPackageError {
    SchemaDigest(String),
    Manifest(PackageManifestError),
}

impl fmt::Display for ContractPackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaDigest(error) => write!(formatter, "schema digest failed: {error}"),
            Self::Manifest(error) => write!(formatter, "contract package is invalid: {error}"),
        }
    }
}

impl Error for ContractPackageError {}
