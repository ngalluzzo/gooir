use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::num::NonZeroUsize;

use fleetd_direct_conversation_contract::{
    AgentId, CONTRACT_PACKAGE, CONTRACT_VERSION, ContractFactError, ConversationId,
    DIRECT_CONVERSATION_REF_SCHEMA_BYTES, DIRECT_CONVERSATION_REF_SCHEMA_PATH,
    DIRECT_PAIR_INTENT_SCHEMA_BYTES, DIRECT_PAIR_INTENT_SCHEMA_PATH, DeliveryMode,
    DirectConversationRef, DirectMember, DirectPairIntent, FleetdTarget, MAX_SAFE_JSON_INTEGER,
    PayloadError, conversation_port_name, dialect_id, direct_conversation_ref_suite_id,
    direct_conversation_ref_value_kind, direct_pair_intent_value_kind,
    immutable_mode_conflict_failure_kind, intent_port_name, open_or_resolve_capability_id,
    open_or_resolve_capability_spec, package_manifest,
};
use gooir_capability::Fact;
use gooir_package::{LoadLimits, PackageRegistry, load_local_package, write_manifest};
use gooir_planning::{PlanLimits, SemanticPlanner};
use serde_json::{Value, json};

fn member(id: &str, mode: DeliveryMode) -> DirectMember {
    DirectMember::new(AgentId::parse(id).expect("agent ID"), mode)
}

fn members() -> [DirectMember; 2] {
    [
        member("agent-a", DeliveryMode::StreamOnly),
        member("agent-b", DeliveryMode::Inbox),
    ]
}

fn intent() -> DirectPairIntent {
    DirectPairIntent::new(
        FleetdTarget::parse("fleetd:local-proof").expect("target"),
        members(),
    )
    .expect("intent")
}

fn conversation(target: &str) -> DirectConversationRef {
    DirectConversationRef::new(
        FleetdTarget::parse(target).expect("target"),
        ConversationId::parse("conversation-1").expect("conversation ID"),
        1_787_700_000_000,
        members(),
    )
    .expect("conversation")
}

fn intent_fact(intent: &DirectPairIntent) -> Fact {
    intent.to_fact().expect("intent fact")
}

#[test]
fn constructors_canonicalize_but_wire_requires_canonical_distinct_members() {
    let forward = DirectPairIntent::new(
        FleetdTarget::parse("fleetd:local-proof").expect("target"),
        [
            member("agent-a", DeliveryMode::StreamOnly),
            member("agent-z", DeliveryMode::Inbox),
        ],
    )
    .expect("forward intent");
    let reversed = DirectPairIntent::new(
        forward.fleetd_target().clone(),
        [
            member("agent-z", DeliveryMode::Inbox),
            member("agent-a", DeliveryMode::StreamOnly),
        ],
    )
    .expect("reversed intent");
    assert_eq!(forward, reversed);
    assert_eq!(
        serde_json::to_value(&forward).expect("forward payload"),
        serde_json::to_value(&reversed).expect("reversed payload")
    );
    assert_eq!(intent_fact(&forward).id, intent_fact(&reversed).id);
    assert_eq!(reversed.members()[0].agent_id().as_str(), "agent-a");
    assert_eq!(reversed.members()[1].agent_id().as_str(), "agent-z");

    let noncanonical = json!({
        "fleetd_target": "fleetd:local-proof",
        "members": [
            {"agent_id": "agent-z", "delivery_mode": "inbox"},
            {"agent_id": "agent-a", "delivery_mode": "stream_only"}
        ]
    });
    assert!(serde_json::from_value::<DirectPairIntent>(noncanonical).is_err());

    let noncanonical_reference = json!({
        "fleetd_target": "fleetd:local-proof",
        "conversation_id": "conversation-1",
        "created_at_ms": 1,
        "members": [
            {"agent_id": "agent-z", "delivery_mode": "inbox"},
            {"agent_id": "agent-a", "delivery_mode": "stream_only"}
        ]
    });
    assert!(serde_json::from_value::<DirectConversationRef>(noncanonical_reference).is_err());

    let duplicate = DirectPairIntent::new(
        FleetdTarget::parse("fleetd:local-proof").expect("target"),
        [
            member("agent-a", DeliveryMode::Inbox),
            member("agent-a", DeliveryMode::StreamOnly),
        ],
    );
    assert_eq!(duplicate, Err(PayloadError::DuplicateMembers));
}

#[test]
fn delivery_modes_are_member_meaning_and_change_fact_identity() {
    let original = intent();
    let swapped = DirectPairIntent::new(
        original.fleetd_target().clone(),
        [
            member("agent-a", DeliveryMode::Inbox),
            member("agent-b", DeliveryMode::StreamOnly),
        ],
    )
    .expect("mode-swapped intent");
    assert_ne!(original, swapped);
    assert_ne!(intent_fact(&original).id, intent_fact(&swapped).id);
}

#[test]
fn schemas_and_rust_payloads_agree_on_closed_structural_shapes() {
    let intent_schema: Value =
        serde_json::from_slice(DIRECT_PAIR_INTENT_SCHEMA_BYTES).expect("intent schema JSON");
    let reference_schema: Value = serde_json::from_slice(DIRECT_CONVERSATION_REF_SCHEMA_BYTES)
        .expect("reference schema JSON");
    let intent_validator = jsonschema::validator_for(&intent_schema).expect("intent schema");
    let reference_validator =
        jsonschema::validator_for(&reference_schema).expect("reference schema");

    let intent_document = serde_json::to_value(intent()).expect("intent JSON");
    assert!(intent_validator.is_valid(&intent_document));
    assert!(serde_json::from_value::<DirectPairIntent>(intent_document).is_ok());

    let reference_document =
        serde_json::to_value(conversation("fleetd:local-proof")).expect("reference JSON");
    assert!(reference_validator.is_valid(&reference_document));
    assert!(serde_json::from_value::<DirectConversationRef>(reference_document).is_ok());
    let maximum_reference = DirectConversationRef::for_intent(
        &intent(),
        ConversationId::parse("conversation-at-safe-maximum").expect("conversation ID"),
        MAX_SAFE_JSON_INTEGER,
    )
    .expect("maximum reference");
    assert!(
        reference_validator
            .is_valid(&serde_json::to_value(maximum_reference).expect("maximum reference JSON"))
    );

    for invalid in [
        json!({"fleetd_target": "fleetd:local-proof", "members": []}),
        json!({
            "fleetd_target": "fleetd:\u{80}target",
            "members": [
                {"agent_id": "agent-a", "delivery_mode": "stream_only"},
                {"agent_id": "agent-b", "delivery_mode": "inbox"}
            ]
        }),
        json!({
            "fleetd_target": "fleetd:local-proof",
            "members": [
                {"agent_id": "agent-\u{9f}", "delivery_mode": "stream_only"},
                {"agent_id": "agent-b", "delivery_mode": "inbox"}
            ]
        }),
        json!({
            "fleetd_target": "fleetd:local-proof",
            "members": [
                {"agent_id": "agent-a", "delivery_mode": "broadcast"},
                {"agent_id": "agent-b", "delivery_mode": "inbox"}
            ]
        }),
        json!({
            "fleetd_target": "fleetd:local-proof",
            "members": [
                {"agent_id": "agent-a", "delivery_mode": "stream_only"},
                {"agent_id": "agent-b", "delivery_mode": "inbox"}
            ],
            "http_status": 201
        }),
    ] {
        assert!(
            !intent_validator.is_valid(&invalid),
            "schema accepted {invalid}"
        );
        assert!(
            serde_json::from_value::<DirectPairIntent>(invalid.clone()).is_err(),
            "Rust accepted {invalid}"
        );
    }

    for invalid in [
        json!({
            "fleetd_target": "fleetd:local-proof",
            "conversation_id": "conversation-\u{85}",
            "created_at_ms": 1,
            "members": [
                {"agent_id": "agent-a", "delivery_mode": "stream_only"},
                {"agent_id": "agent-b", "delivery_mode": "inbox"}
            ]
        }),
        json!({
            "fleetd_target": "fleetd:local-proof",
            "conversation_id": "conversation-1",
            "created_at_ms": -1,
            "members": [
                {"agent_id": "agent-a", "delivery_mode": "stream_only"},
                {"agent_id": "agent-b", "delivery_mode": "inbox"}
            ]
        }),
        json!({
            "fleetd_target": "fleetd:local-proof",
            "created_at_ms": 1,
            "members": [
                {"agent_id": "agent-a", "delivery_mode": "stream_only"},
                {"agent_id": "agent-b", "delivery_mode": "inbox"}
            ]
        }),
        json!({
            "fleetd_target": "fleetd:local-proof",
            "conversation_id": "conversation-1",
            "created_at_ms": MAX_SAFE_JSON_INTEGER + 1,
            "members": [
                {"agent_id": "agent-a", "delivery_mode": "stream_only"},
                {"agent_id": "agent-b", "delivery_mode": "inbox"}
            ]
        }),
    ] {
        assert!(
            !reference_validator.is_valid(&invalid),
            "schema accepted {invalid}"
        );
        assert!(
            serde_json::from_value::<DirectConversationRef>(invalid.clone()).is_err(),
            "Rust accepted {invalid}"
        );
    }
}

#[test]
fn coordinate_schemas_match_rust_at_unicode_whitespace_boundaries() {
    let intent_schema: Value =
        serde_json::from_slice(DIRECT_PAIR_INTENT_SCHEMA_BYTES).expect("intent schema JSON");
    let reference_schema: Value = serde_json::from_slice(DIRECT_CONVERSATION_REF_SCHEMA_BYTES)
        .expect("reference schema JSON");
    let intent_validator = jsonschema::validator_for(&intent_schema).expect("intent schema");
    let reference_validator =
        jsonschema::validator_for(&reference_schema).expect("reference schema");

    let whitespace = [
        '\u{0009}', '\u{000a}', '\u{000b}', '\u{000c}', '\u{000d}', '\u{0020}', '\u{0085}',
        '\u{00a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}',
        '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{2028}',
        '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}',
    ];
    for boundary in whitespace {
        for target in [
            format!("{boundary}fleetd:target"),
            format!("fleetd:target{boundary}"),
        ] {
            assert!(
                FleetdTarget::parse(&target).is_err(),
                "Rust accepted {target:?}"
            );
            let document = json!({
                "fleetd_target": target,
                "members": [
                    {"agent_id": "agent-a", "delivery_mode": "stream_only"},
                    {"agent_id": "agent-b", "delivery_mode": "inbox"}
                ]
            });
            assert!(
                !intent_validator.is_valid(&document),
                "schema accepted boundary whitespace U+{:04X}",
                boundary as u32
            );
        }
    }

    let padded_agent = "\u{2002}agent-a".to_owned();
    assert!(AgentId::parse(&padded_agent).is_err());
    assert!(!intent_validator.is_valid(&json!({
        "fleetd_target": "fleetd:target",
        "members": [
            {"agent_id": padded_agent, "delivery_mode": "stream_only"},
            {"agent_id": "agent-b", "delivery_mode": "inbox"}
        ]
    })));

    let padded_conversation = "conversation-a\u{202f}".to_owned();
    assert!(ConversationId::parse(&padded_conversation).is_err());
    assert!(!reference_validator.is_valid(&json!({
        "fleetd_target": "fleetd:target",
        "conversation_id": padded_conversation,
        "created_at_ms": 1,
        "members": [
            {"agent_id": "agent-a", "delivery_mode": "stream_only"},
            {"agent_id": "agent-b", "delivery_mode": "inbox"}
        ]
    })));

    for exact in ["\u{feff}fleetd:target", "fleetd:\u{2002}target"] {
        assert!(
            FleetdTarget::parse(exact).is_ok(),
            "Rust rejected {exact:?}"
        );
        assert!(
            intent_validator.is_valid(&json!({
                "fleetd_target": exact,
                "members": [
                    {"agent_id": "agent-a", "delivery_mode": "stream_only"},
                    {"agent_id": "agent-b", "delivery_mode": "inbox"}
                ]
            })),
            "schema rejected exact coordinate {exact:?}"
        );
    }
}

#[test]
fn payloads_exclude_presentation_transport_authority_and_unknown_fields() {
    let intent_document = serde_json::to_value(intent()).expect("intent JSON");
    let reference_document =
        serde_json::to_value(conversation("fleetd:local-proof")).expect("reference JSON");
    let intent_keys = intent_document
        .as_object()
        .expect("intent object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let reference_keys = reference_document
        .as_object()
        .expect("reference object")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(intent_keys, BTreeSet::from(["fleetd_target", "members"]));
    assert_eq!(
        reference_keys,
        BTreeSet::from([
            "conversation_id",
            "created_at_ms",
            "fleetd_target",
            "members"
        ])
    );

    for forbidden in [
        "name",
        "agent_name",
        "latest_message_seq",
        "metadata",
        "http_status",
        "base_url",
        "bearer_token",
        "credential_revision",
    ] {
        assert!(!intent_document.to_string().contains(forbidden));
        assert!(!reference_document.to_string().contains(forbidden));
    }

    let mut unknown_reference = reference_document;
    unknown_reference
        .as_object_mut()
        .expect("reference object")
        .insert("name".to_owned(), json!("presentation-only"));
    assert!(serde_json::from_value::<DirectConversationRef>(unknown_reference).is_err());

    let unknown_member = json!({
        "fleetd_target": "fleetd:local-proof",
        "members": [
            {"agent_id": "agent-a", "delivery_mode": "stream_only", "role": "author"},
            {"agent_id": "agent-b", "delivery_mode": "inbox"}
        ]
    });
    assert!(serde_json::from_value::<DirectPairIntent>(unknown_member).is_err());
}

#[test]
fn target_coordinate_scopes_reference_and_semantic_fact_identity() {
    let first = conversation("fleetd:target-a");
    let second = conversation("fleetd:target-b");
    assert_ne!(first, second);

    let first_fact = first.to_fact().expect("first fact");
    let second_fact = second.to_fact().expect("second fact");
    assert_ne!(first_fact.id, second_fact.id);
}

#[test]
fn typed_fact_boundary_round_trips_and_rejects_untrusted_envelopes() {
    let intent = intent();
    let intent_fact = intent.to_fact().expect("intent fact");
    assert_eq!(
        DirectPairIntent::from_fact(&intent_fact).expect("decoded intent"),
        intent
    );

    let reference = conversation("fleetd:local-proof");
    let reference_fact = reference.to_fact().expect("reference fact");
    assert_eq!(
        DirectConversationRef::from_fact(&reference_fact).expect("decoded reference"),
        reference
    );

    let wrong_kind = Fact::new(
        direct_conversation_ref_value_kind(),
        serde_json::to_value(&intent).expect("intent payload"),
    )
    .expect("wrong-kind fact with valid identity");
    assert!(matches!(
        DirectPairIntent::from_fact(&wrong_kind),
        Err(ContractFactError::UnexpectedValueKind { .. })
    ));

    let extended = Fact::with_extensions(
        direct_pair_intent_value_kind(),
        serde_json::to_value(&intent).expect("intent payload"),
        BTreeMap::from([("dev.example.note".to_owned(), json!("not contract meaning"))]),
    )
    .expect("identity-valid extended fact");
    assert_eq!(
        DirectPairIntent::from_fact(&extended),
        Err(ContractFactError::SemanticExtensions(vec![
            "dev.example.note".to_owned()
        ]))
    );

    let noncanonical_payload = json!({
        "fleetd_target": "fleetd:local-proof",
        "members": [
            {"agent_id": "agent-z", "delivery_mode": "inbox"},
            {"agent_id": "agent-a", "delivery_mode": "stream_only"}
        ]
    });
    let noncanonical = Fact::new(direct_pair_intent_value_kind(), noncanonical_payload)
        .expect("identity-valid noncanonical fact");
    assert!(matches!(
        DirectPairIntent::from_fact(&noncanonical),
        Err(ContractFactError::Payload(_))
    ));

    let unknown_payload = json!({
        "fleetd_target": "fleetd:local-proof",
        "members": [
            {"agent_id": "agent-a", "delivery_mode": "stream_only"},
            {"agent_id": "agent-b", "delivery_mode": "inbox"}
        ],
        "transport_status": 201
    });
    let unknown = Fact::new(direct_pair_intent_value_kind(), unknown_payload)
        .expect("identity-valid unknown-field fact");
    assert!(matches!(
        DirectPairIntent::from_fact(&unknown),
        Err(ContractFactError::Payload(_))
    ));

    let mut stale = intent_fact;
    stale.payload["fleetd_target"] = json!("fleetd:different-target");
    assert!(matches!(
        DirectPairIntent::from_fact(&stale),
        Err(ContractFactError::Identity(_))
    ));
}

#[test]
fn output_identity_covers_every_fleetd_owned_semantic_field() {
    let baseline_intent = intent();
    let baseline = DirectConversationRef::for_intent(
        &baseline_intent,
        ConversationId::parse("conversation-1").expect("conversation ID"),
        1_000,
    )
    .expect("baseline reference");
    let baseline_id = baseline.to_fact().expect("baseline fact").id;

    let changed_id = DirectConversationRef::for_intent(
        &baseline_intent,
        ConversationId::parse("conversation-2").expect("conversation ID"),
        1_000,
    )
    .expect("changed ID");
    let changed_time = DirectConversationRef::for_intent(
        &baseline_intent,
        ConversationId::parse("conversation-1").expect("conversation ID"),
        1_001,
    )
    .expect("changed time");
    let changed_agent_intent = DirectPairIntent::new(
        baseline_intent.fleetd_target().clone(),
        [
            member("agent-a", DeliveryMode::StreamOnly),
            member("agent-c", DeliveryMode::Inbox),
        ],
    )
    .expect("changed agent intent");
    let changed_agent = DirectConversationRef::for_intent(
        &changed_agent_intent,
        ConversationId::parse("conversation-1").expect("conversation ID"),
        1_000,
    )
    .expect("changed agent");
    let changed_mode_intent = DirectPairIntent::new(
        baseline_intent.fleetd_target().clone(),
        [
            member("agent-a", DeliveryMode::Inbox),
            member("agent-b", DeliveryMode::StreamOnly),
        ],
    )
    .expect("changed mode intent");
    let changed_mode = DirectConversationRef::for_intent(
        &changed_mode_intent,
        ConversationId::parse("conversation-1").expect("conversation ID"),
        1_000,
    )
    .expect("changed mode");

    for changed in [changed_id, changed_time, changed_agent, changed_mode] {
        assert_ne!(baseline_id, changed.to_fact().expect("changed fact").id);
    }
}

#[test]
fn output_constructor_copies_the_exact_intent_scope_and_pair() {
    let intent = DirectPairIntent::new(
        FleetdTarget::parse("Fleetd/Target-A").expect("target"),
        [
            member("agent-z", DeliveryMode::Inbox),
            member("agent-a", DeliveryMode::StreamOnly),
        ],
    )
    .expect("canonical intent");
    let reference = DirectConversationRef::for_intent(
        &intent,
        ConversationId::parse("conversation-1").expect("conversation ID"),
        42,
    )
    .expect("reference");
    assert_eq!(reference.fleetd_target(), intent.fleetd_target());
    assert_eq!(reference.members(), intent.members());
    assert_eq!(reference.conversation_id().as_str(), "conversation-1");
    assert_eq!(reference.created_at_ms(), 42);
}

#[test]
fn opaque_coordinates_and_creation_time_fail_closed() {
    for invalid in ["", " padded", "padded ", "contains\ncontrol"] {
        assert!(FleetdTarget::parse(invalid).is_err());
        assert!(AgentId::parse(invalid).is_err());
        assert!(ConversationId::parse(invalid).is_err());
    }
    let oversized = "x".repeat(257);
    assert!(FleetdTarget::parse(oversized).is_err());

    let exact_target = FleetdTarget::parse("Operator/Fleetd#A").expect("opaque target");
    let exact_agent = AgentId::parse("Agent-A:not-a-uuid").expect("opaque agent ID");
    let exact_conversation =
        ConversationId::parse("Conversation/A:not-a-uuid").expect("opaque conversation ID");
    assert_eq!(exact_target.as_str(), "Operator/Fleetd#A");
    assert_eq!(exact_agent.as_str(), "Agent-A:not-a-uuid");
    assert_eq!(exact_conversation.as_str(), "Conversation/A:not-a-uuid");

    for valid in [0, MAX_SAFE_JSON_INTEGER] {
        let reference = DirectConversationRef::new(
            FleetdTarget::parse("fleetd:local-proof").expect("target"),
            ConversationId::parse("conversation-1").expect("conversation ID"),
            valid,
            members(),
        )
        .expect("safe timestamp");
        reference.to_fact().expect("safe timestamp fact");
    }
    for invalid in [-1, MAX_SAFE_JSON_INTEGER + 1] {
        assert_eq!(
            DirectConversationRef::new(
                FleetdTarget::parse("fleetd:local-proof").expect("target"),
                ConversationId::parse("conversation-1").expect("conversation ID"),
                invalid,
                members(),
            ),
            Err(PayloadError::CreatedAtMsOutsideSafeIntegerRange)
        );
    }

    let unsafe_wire = json!({
        "fleetd_target": "fleetd:local-proof",
        "conversation_id": "conversation-1",
        "created_at_ms": MAX_SAFE_JSON_INTEGER + 1,
        "members": [
            {"agent_id": "agent-a", "delivery_mode": "stream_only"},
            {"agent_id": "agent-b", "delivery_mode": "inbox"}
        ]
    });
    assert!(serde_json::from_value::<DirectConversationRef>(unsafe_wire).is_err());
}

#[test]
fn package_installs_exact_contract_and_plans_one_unimplemented_need() {
    let manifest = package_manifest().expect("contract manifest");
    assert_eq!(manifest.package.to_string(), CONTRACT_PACKAGE);
    assert!(manifest.dependencies.is_empty());
    assert_eq!(manifest.resources.len(), 2);
    assert_eq!(manifest.dialects.len(), 1);
    assert_eq!(manifest.conformance_suites.len(), 1);
    assert_eq!(manifest.dialects[0].id, dialect_id());
    assert_eq!(
        manifest.dialects[0]
            .value_kinds
            .iter()
            .map(|kind| kind.id.clone())
            .collect::<Vec<_>>(),
        vec![
            direct_conversation_ref_value_kind(),
            direct_pair_intent_value_kind()
        ]
    );
    assert_eq!(
        manifest.conformance_suites[0].id,
        direct_conversation_ref_suite_id()
    );
    assert_eq!(
        manifest.capabilities,
        vec![open_or_resolve_capability_spec()]
    );
    assert!(manifest.implementation_offers.is_empty());
    assert_eq!(dialect_id().version, CONTRACT_VERSION);
    assert_eq!(intent_port_name().as_str(), "intent");
    assert_eq!(conversation_port_name().as_str(), "conversation");
    assert_eq!(
        immutable_mode_conflict_failure_kind().to_string(),
        "dev.fleetd.failure/direct_conversation_immutable_mode_conflict@0.1.0"
    );

    let directory = tempfile::tempdir().expect("package directory");
    for (path, bytes) in [
        (
            DIRECT_CONVERSATION_REF_SCHEMA_PATH,
            DIRECT_CONVERSATION_REF_SCHEMA_BYTES,
        ),
        (
            DIRECT_PAIR_INTENT_SCHEMA_PATH,
            DIRECT_PAIR_INTENT_SCHEMA_BYTES,
        ),
    ] {
        let destination = directory.path().join(path);
        fs::create_dir_all(destination.parent().expect("schema parent")).expect("schema directory");
        fs::write(destination, bytes).expect("schema resource");
    }
    fs::write(
        directory.path().join(gooir_package::PACKAGE_MANIFEST_FILE),
        write_manifest(&manifest).expect("manifest JSON"),
    )
    .expect("package manifest");

    let mut registry = PackageRegistry::default();
    let loaded = load_local_package(directory.path(), &registry, LoadLimits::default())
        .expect("load contract package");
    registry.install(loaded).expect("install contract package");

    let planner = SemanticPlanner::from_registry(&registry, planning_limits()).expect("planner");
    let plan = planner
        .plan(
            [direct_pair_intent_value_kind()],
            direct_conversation_ref_value_kind(),
        )
        .expect("declared route");
    assert_eq!(plan.capabilities.len(), 1);
    assert_eq!(
        plan.capabilities[0].specification.id,
        open_or_resolve_capability_id()
    );
    assert!(plan.capabilities[0].offers.is_empty());
    assert_eq!(
        plan.needs().map(|need| need.id.clone()).collect::<Vec<_>>(),
        vec![open_or_resolve_capability_id()]
    );
}

fn planning_limits() -> PlanLimits {
    let bound = NonZeroUsize::new(16).expect("non-zero");
    PlanLimits {
        max_capabilities: bound,
        max_value_kinds: bound,
        max_ports_per_capability: bound,
        max_total_ports: bound,
        max_offers_per_capability: bound,
        max_total_offers: bound,
    }
}
