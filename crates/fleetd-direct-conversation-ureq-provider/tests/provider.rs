use std::collections::BTreeMap;
use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use fleetd_direct_conversation_command_abi::AuthorityDocument;
use fleetd_direct_conversation_contract::{
    AgentId, DeliveryMode, DirectConversationRef, DirectMember, DirectPairIntent, FleetdTarget,
    direct_conversation_ref_suite_id, immutable_mode_conflict_failure_kind, intent_port_name,
};
use fleetd_direct_conversation_ureq_provider::{
    UreqProviderError, capability_offer, capability_spec, invoke,
};
use gooir_capability::protocol::{
    AdmittedFactRef, ArtifactDigest, AuthorityRecordId, CapabilityInvocation, CapabilityOutcome,
    ImplementationSelection, LinkedInput,
};
use serde_json::{Value, json};

const TARGET: &str = "fleetd:target-a";
const SECRET: &str = "provider-test-token";

struct CapturedRequest {
    request_line: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct StubResponse {
    status: u16,
    reason: &'static str,
    content_type: Option<&'static str>,
    body: Vec<u8>,
}

fn member(agent: &str, mode: DeliveryMode) -> DirectMember {
    DirectMember::new(AgentId::parse(agent).expect("agent"), mode)
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

fn digest(byte: char) -> ArtifactDigest {
    ArtifactDigest::parse(format!("sha256:{}", byte.to_string().repeat(64))).expect("digest")
}

fn authority_record(byte: char) -> AuthorityRecordId {
    AuthorityRecordId::parse(format!("sha256:{}", byte.to_string().repeat(64))).expect("authority")
}

fn invocation() -> CapabilityInvocation {
    let fact = intent().to_fact().expect("intent fact");
    let admitted = AdmittedFactRef::new(fact.id.clone(), authority_record('a'), BTreeMap::new())
        .expect("admitted fact");
    let linked = LinkedInput::new(intent_port_name(), admitted, fact, BTreeMap::new())
        .expect("linked input");
    let selection = ImplementationSelection::new(
        capability_offer(digest('1')).expect("offer"),
        BTreeMap::new(),
    )
    .expect("selection");
    CapabilityInvocation::new(
        capability_spec(),
        selection,
        vec![linked],
        direct_conversation_ref_suite_id(),
        BTreeMap::new(),
    )
    .expect("invocation")
}

fn authority(endpoint: &str, maximum: u64) -> AuthorityDocument {
    AuthorityDocument::new(
        TARGET,
        format!("sha256:{}", "b".repeat(64)),
        "credential/revision-1",
        endpoint,
        SECRET,
        5_000,
        maximum,
    )
    .expect("authority")
}

fn summary(status: u16) -> StubResponse {
    StubResponse {
        status,
        reason: if status == 200 { "OK" } else { "Created" },
        content_type: Some("application/json"),
        body: serde_json::to_vec(&json!({
            "id": "conversation-1",
            "name": "generated-name",
            "kind": "direct",
            "metadata": {},
            "future_summary_field": {"retained_by_fleetd": true},
            "created_at_ms": 1_787_700_000_000_i64,
            "archived_at_ms": null,
            "members": [
                {
                    "channel_id": "conversation-1",
                    "agent_id": "agent-b",
                    "agent_name": "Beta",
                    "joined_at_ms": 1_787_700_000_000_i64,
                    "delivery_mode": "inbox",
                    "future_member_field": 1
                },
                {
                    "channel_id": "conversation-1",
                    "agent_id": "agent-a",
                    "agent_name": "Alpha",
                    "joined_at_ms": 1_787_700_000_000_i64,
                    "delivery_mode": "stream_only"
                }
            ],
            "latest_message_seq": null,
            "latest_message_at_ms": null
        }))
        .expect("summary JSON"),
    }
}

fn stub(response: StubResponse) -> (String, Receiver<CapturedRequest>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let address = listener.local_addr().expect("stub address");
    let (sender, receiver) = mpsc::sync_channel(1);
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let request = read_request(&mut stream);
        sender.send(request).expect("capture request");
        let content_type = response
            .content_type
            .map(|value| format!("Content-Type: {value}\r\n"))
            .unwrap_or_default();
        let head = format!(
            "HTTP/1.1 {} {}\r\n{content_type}Content-Length: {}\r\nConnection: close\r\n\r\n",
            response.status,
            response.reason,
            response.body.len()
        );
        stream.write_all(head.as_bytes()).expect("write head");
        stream.write_all(&response.body).expect("write body");
    });
    (format!("http://{address}/"), receiver, handle)
}

fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut buffer = [0_u8; 1024];
        let read = stream.read(&mut buffer).expect("read request");
        assert_ne!(read, 0, "request ended before headers");
        bytes.extend_from_slice(&buffer[..read]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        assert!(
            bytes.len() < 64 * 1024,
            "request headers exceeded test bound"
        );
    };
    let head = std::str::from_utf8(&bytes[..header_end]).expect("request head UTF-8");
    let mut lines = head.split("\r\n");
    let request_line = lines.next().expect("request line").to_owned();
    let mut headers = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').expect("header");
        headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
    }
    let content_length = headers
        .get("content-length")
        .expect("content length")
        .parse::<usize>()
        .expect("numeric content length");
    while bytes.len() - header_end < content_length {
        let mut buffer = [0_u8; 1024];
        let read = stream.read(&mut buffer).expect("read request body");
        assert_ne!(read, 0, "request body ended early");
        bytes.extend_from_slice(&buffer[..read]);
    }
    CapturedRequest {
        request_line,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    }
}

fn reference(result: &gooir_capability::protocol::CapabilityResult) -> DirectConversationRef {
    let CapabilityOutcome::Produced { outputs, .. } = &result.outcome else {
        panic!("expected produced result");
    };
    let [output] = outputs.as_slice() else {
        panic!("expected one output");
    };
    DirectConversationRef::from_fact(&output.fact).expect("conversation reference")
}

fn run_command(invocation: &CapabilityInvocation, authority: &AuthorityDocument) -> Output {
    let directory = tempfile::tempdir().expect("command directory");
    let invocation_path = directory.path().join("invocation.json");
    fs::write(
        &invocation_path,
        serde_json::to_vec(invocation).expect("invocation JSON"),
    )
    .expect("write invocation");
    let executable = env!("CARGO_BIN_EXE_fleetd-direct-conversation-ureq-provider");
    let mut child = Command::new("/bin/sh")
        .args([
            "-c",
            "exec 3<&0; exec \"$1\" < \"$2\"",
            "ureq-provider-boundary",
        ])
        .arg(executable)
        .arg(invocation_path)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn provider");
    child
        .stdin
        .take()
        .expect("authority pipe")
        .write_all(&authority.encode_for_pipe().expect("authority JSON"))
        .expect("write authority");
    child.wait_with_output().expect("provider output")
}

#[test]
fn success_is_exact_and_200_and_201_produce_the_same_fact() {
    let exact_invocation = invocation();
    let mut results = Vec::new();
    for status in [201, 200] {
        let (endpoint, captured, handle) = stub(summary(status));
        let result = invoke(&exact_invocation, &authority(&endpoint, 256 * 1024)).expect("result");
        result
            .validate_against(&exact_invocation)
            .expect("valid result");
        let request = captured.recv().expect("captured request");
        handle.join().expect("stub thread");

        assert_eq!(
            request.request_line,
            "POST /v1/direct-conversations HTTP/1.1"
        );
        assert!(
            request
                .headers
                .get("authorization")
                .is_some_and(|value| value.starts_with("Bearer "))
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body).expect("request JSON"),
            json!({
                "members": [
                    {"agent_id": "agent-a", "delivery_mode": "stream_only"},
                    {"agent_id": "agent-b", "delivery_mode": "inbox"}
                ]
            })
        );
        let reference = reference(&result);
        assert_eq!(reference.fleetd_target().as_str(), TARGET);
        assert_eq!(reference.conversation_id().as_str(), "conversation-1");
        assert_eq!(reference.created_at_ms(), 1_787_700_000_000);
        results.push(result);
    }
    assert_eq!(results[0], results[1]);
}

#[test]
fn only_the_exact_immutable_mode_conflict_is_semantic_inability() {
    let exact = StubResponse {
        status: 409,
        reason: "Conflict",
        content_type: Some("application/json"),
        body: serde_json::to_vec(&json!({
            "error": "conflict: direct conversation participant delivery modes are immutable"
        }))
        .expect("conflict JSON"),
    };
    let (endpoint, _captured, handle) = stub(exact);
    let exact_invocation = invocation();
    let result = invoke(&exact_invocation, &authority(&endpoint, 64 * 1024)).expect("inability");
    handle.join().expect("stub thread");
    let CapabilityOutcome::Unable { failure, .. } = result.outcome else {
        panic!("expected inability");
    };
    assert_eq!(failure.kind, immutable_mode_conflict_failure_kind());
    assert_eq!(failure.detail, Value::Null);

    let arbitrary = StubResponse {
        status: 409,
        reason: "Conflict",
        content_type: Some("application/json"),
        body: br#"{"error":"conflict: something else"}"#.to_vec(),
    };
    let (endpoint, _captured, handle) = stub(arbitrary);
    assert_eq!(
        invoke(&exact_invocation, &authority(&endpoint, 64 * 1024)),
        Err(UreqProviderError::ConflictBodyMismatch)
    );
    handle.join().expect("stub thread");

    let extended = StubResponse {
        status: 409,
        reason: "Conflict",
        content_type: Some("application/json"),
        body: serde_json::to_vec(&json!({
            "error": "conflict: direct conversation participant delivery modes are immutable",
            "future_field": true
        }))
        .expect("extended conflict JSON"),
    };
    let (endpoint, _captured, handle) = stub(extended);
    assert_eq!(
        invoke(&exact_invocation, &authority(&endpoint, 64 * 1024)),
        Err(UreqProviderError::ConflictBodyMismatch)
    );
    handle.join().expect("stub thread");
}

#[test]
fn target_response_and_operational_failures_produce_no_neutral_result() {
    let wrong_target = AuthorityDocument::new(
        "fleetd:target-b",
        format!("sha256:{}", "b".repeat(64)),
        "credential/revision-1",
        "http://127.0.0.1:9/",
        SECRET,
        100,
        1024,
    )
    .expect("wrong-target authority");
    assert_eq!(
        invoke(&invocation(), &wrong_target),
        Err(UreqProviderError::AuthorityTargetMismatch)
    );

    let (endpoint, _captured, handle) = stub(StubResponse {
        status: 201,
        reason: "Created",
        content_type: Some("application/json"),
        body: br#"{"id":"wrong-shape"}"#.to_vec(),
    });
    assert_eq!(
        invoke(&invocation(), &authority(&endpoint, 64 * 1024)),
        Err(UreqProviderError::ResponseJsonInvalid)
    );
    handle.join().expect("stub thread");

    let (endpoint, _captured, handle) = stub(StubResponse {
        status: 503,
        reason: "Unavailable",
        content_type: Some("application/json"),
        body: br#"{"error":"later"}"#.to_vec(),
    });
    assert_eq!(
        invoke(&invocation(), &authority(&endpoint, 64 * 1024)),
        Err(UreqProviderError::UnexpectedStatus(503))
    );
    handle.join().expect("stub thread");

    let (endpoint, _captured, handle) = stub(StubResponse {
        status: 201,
        reason: "Created",
        content_type: Some("application/json"),
        body: vec![b'x'; 129],
    });
    assert_eq!(
        invoke(&invocation(), &authority(&endpoint, 128)),
        Err(UreqProviderError::ResponseTooLarge)
    );
    handle.join().expect("stub thread");
}

#[test]
fn command_boundary_emits_one_result_or_no_stdout_and_never_echoes_authority() {
    let exact_invocation = invocation();
    let (endpoint, _captured, handle) = stub(summary(201));
    let output = run_command(&exact_invocation, &authority(&endpoint, 256 * 1024));
    handle.join().expect("stub thread");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let result: gooir_capability::protocol::CapabilityResult =
        serde_json::from_slice(&output.stdout).expect("single result JSON");
    result
        .validate_against(&exact_invocation)
        .expect("valid command result");

    let private_endpoint = "http://127.0.0.1:9/";
    let wrong_target = AuthorityDocument::new(
        "fleetd:target-b",
        format!("sha256:{}", "b".repeat(64)),
        "credential/revision-1",
        private_endpoint,
        SECRET,
        100,
        1024,
    )
    .expect("wrong-target authority");
    let output = run_command(&exact_invocation, &wrong_target);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr UTF-8");
    assert!(!stderr.contains(SECRET));
    assert!(!stderr.contains(private_endpoint));
}
