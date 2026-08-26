#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fleetd_direct_conversation_attester::{AssessmentRequest, implementation_id};
use fleetd_direct_conversation_command_abi::AuthorityDocument;
use fleetd_direct_conversation_contract::{
    AgentId, ConversationId, DeliveryMode, DirectConversationRef, DirectMember, DirectPairIntent,
    FleetdTarget, conversation_port_name, direct_conversation_ref_suite_id, intent_port_name,
    open_or_resolve_capability_spec,
};
use gooir_capability::authority::{AssessmentOutcome, ConformanceAssessment};
use gooir_capability::protocol::{
    AdmittedFactRef, ArtifactDigest, AuthorityRecordId, CapabilityCandidate, CapabilityInvocation,
    CapabilityOffer, CapabilityResult, ImplementationId, ImplementationSelection, LinkedInput,
    NamedOutput,
};
use serde_json::json;

const TARGET: &str = "fleetd:target-a";
const SECRET: &str = "attester-command-test-token.secret";
const FAILURE_STDERR: &[u8] = b"fleetd direct-conversation attester failed\n";

fn digest(byte: char) -> ArtifactDigest {
    ArtifactDigest::parse(format!("sha256:{}", byte.to_string().repeat(64))).expect("digest")
}

fn member(agent_id: &str, delivery_mode: DeliveryMode) -> DirectMember {
    DirectMember::new(AgentId::parse(agent_id).expect("agent ID"), delivery_mode)
}

fn intent() -> DirectPairIntent {
    DirectPairIntent::new(
        FleetdTarget::parse(TARGET).expect("Fleetd target"),
        [
            member("agent-a", DeliveryMode::StreamOnly),
            member("agent-b", DeliveryMode::Inbox),
        ],
    )
    .expect("direct-pair intent")
}

fn assessment_request() -> AssessmentRequest {
    let intent = intent();
    let fact = intent.to_fact().expect("intent fact");
    let admitted = AdmittedFactRef::new(
        fact.id.clone(),
        AuthorityRecordId::parse(format!("sha256:{}", "1".repeat(64))).expect("authority record"),
        BTreeMap::new(),
    )
    .expect("admitted fact");
    let linked = LinkedInput::new(intent_port_name(), admitted, fact, BTreeMap::new())
        .expect("linked input");
    let offer = CapabilityOffer::new(
        ImplementationId::new(
            "dev.fleetd.implementation",
            "direct_conversation_command_test",
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
        vec![linked],
        direct_conversation_ref_suite_id(),
        BTreeMap::new(),
    )
    .expect("invocation");
    let reference = DirectConversationRef::for_intent(
        &intent,
        ConversationId::parse("conversation-1").expect("conversation ID"),
        1_787_700_000_000,
    )
    .expect("conversation reference");
    let output = NamedOutput::new(
        conversation_port_name(),
        reference.to_fact().expect("reference fact"),
        BTreeMap::new(),
    )
    .expect("named output");
    let result = CapabilityResult::produced(
        &invocation,
        vec![output],
        BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
    )
    .expect("result");
    let candidate =
        CapabilityCandidate::new(&invocation, result.clone(), BTreeMap::new()).expect("candidate");
    AssessmentRequest::new(invocation, result, candidate, digest('b')).expect("assessment request")
}

fn authority(endpoint: &str, target: &str) -> AuthorityDocument {
    AuthorityDocument::new(
        target,
        format!("sha256:{}", "c".repeat(64)),
        "credential/revision-command-test",
        endpoint,
        SECRET,
        2_000,
        64 * 1024,
    )
    .expect("authority")
}

fn run_command(request: &AssessmentRequest, authority: &AuthorityDocument) -> Output {
    let directory = tempfile::tempdir().expect("command directory");
    let request_path = directory.path().join("assessment-request.json");
    fs::write(
        &request_path,
        serde_json::to_vec(request).expect("request JSON"),
    )
    .expect("write request");
    let mut child = Command::new("/bin/sh")
        .args([
            "-c",
            "exec 3<&0; exec \"$1\" < \"$2\"",
            "attester-command-test",
        ])
        .arg(env!("CARGO_BIN_EXE_fleetd-direct-conversation-attester"))
        .arg(request_path)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn attester command");
    child
        .stdin
        .take()
        .expect("authority pipe")
        .write_all(&authority.encode_for_pipe().expect("authority encoding"))
        .expect("write and close authority pipe");
    child.wait_with_output().expect("attester command output")
}

struct Stub {
    endpoint: String,
    request: JoinHandle<String>,
}

impl Stub {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        listener.set_nonblocking(true).expect("nonblocking stub");
        let address = listener.local_addr().expect("stub address");
        let request = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "attester did not call Fleetd");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("stub accept failed: {error}"),
                }
            };
            let request = read_request(&mut stream);
            let body = serde_json::to_vec(&json!([{
                "id": "conversation-1",
                "name": "presentation-only",
                "kind": "direct",
                "metadata": {"ignored": true},
                "created_at_ms": 1_787_700_000_000_i64,
                "archived_at_ms": null,
                "members": [
                    {
                        "channel_id": "conversation-1",
                        "agent_id": "agent-a",
                        "agent_name": "Agent A",
                        "joined_at_ms": 1_787_700_000_000_i64,
                        "delivery_mode": "stream_only"
                    },
                    {
                        "channel_id": "conversation-1",
                        "agent_id": "agent-b",
                        "agent_name": "Agent B",
                        "joined_at_ms": 1_787_700_000_000_i64,
                        "delivery_mode": "inbox"
                    }
                ],
                "latest_message_seq": null,
                "latest_message_at_ms": null
            }]))
            .expect("response JSON");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .expect("response headers");
            stream.write_all(&body).expect("response body");
            request
        });
        Self {
            endpoint: format!("http://{address}/"),
            request,
        }
    }

    fn finish(self) -> String {
        self.request.join().expect("stub thread")
    }
}

fn read_request(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("stub read timeout");
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).expect("read request");
        assert_ne!(read, 0, "request ended before headers");
        bytes.extend_from_slice(&buffer[..read]);
        assert!(bytes.len() <= 64 * 1024, "request headers too large");
    }
    String::from_utf8(bytes).expect("request is ASCII")
}

#[test]
fn binary_fd3_success_emits_one_valid_assessment_and_no_stderr() {
    let request = assessment_request();
    let stub = Stub::spawn();
    let output = run_command(&request, &authority(&stub.endpoint, TARGET));
    assert!(output.status.success(), "attester command failed");
    assert!(output.stderr.is_empty(), "success wrote stderr");
    let assessment: ConformanceAssessment =
        serde_json::from_slice(&output.stdout).expect("one assessment JSON document");
    assessment
        .validate_against(request.invocation(), request.result(), request.candidate())
        .expect("assessment chain");
    assert_eq!(assessment.outcome, AssessmentOutcome::Passed);
    assert_eq!(
        assessment.authority.attester.implementation,
        implementation_id()
    );

    let wire = stub.finish();
    assert!(wire.starts_with("GET /v1/conversations?include_archived=true HTTP/1.1\r\n"));
    let lower = wire.to_ascii_lowercase();
    assert!(lower.contains("accept: application/json\r\n"));
    let authorization = wire
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.trim())
        .expect("authorization header");
    if authorization != format!("Bearer {SECRET}") {
        panic!("authorization header did not carry the granted credential");
    }
}

#[test]
fn binary_operational_failure_emits_no_assessment_and_fixed_secret_free_stderr() {
    let request = assessment_request();
    let wrong_target = authority("http://127.0.0.1:9/", "fleetd:other-target");
    let output = run_command(&request, &wrong_target);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, FAILURE_STDERR);
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
}
