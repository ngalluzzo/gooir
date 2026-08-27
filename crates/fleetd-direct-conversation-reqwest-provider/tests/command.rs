#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::thread;

use fleetd_direct_conversation_command_abi::AuthorityDocument;
use fleetd_direct_conversation_contract::{
    AgentId, DeliveryMode, DirectMember, DirectPairIntent, FleetdTarget,
    direct_conversation_ref_suite_id, intent_port_name, open_or_resolve_capability_spec,
};
use fleetd_direct_conversation_reqwest_provider::implementation_id;
use gooir_capability::protocol::{
    AdmittedFactRef, ArtifactDigest, AuthorityRecordId, CapabilityInvocation, CapabilityOffer,
    CapabilityResult, ImplementationSelection, LinkedInput,
};
use nix::spawn::{PosixSpawnAttr, PosixSpawnFileActions, posix_spawn};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::pipe;
use serde_json::json;
use tempfile::TempDir;

const TARGET: &str = "fleetd:target-a";
const SECRET: &str = "command-test-secret.token";

struct CommandOutput {
    exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn sha(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn invocation(target: &str) -> CapabilityInvocation {
    let intent = DirectPairIntent::new(
        FleetdTarget::parse(target).expect("target"),
        [
            DirectMember::new(
                AgentId::parse("agent-a").expect("agent"),
                DeliveryMode::Inbox,
            ),
            DirectMember::new(
                AgentId::parse("agent-b").expect("agent"),
                DeliveryMode::StreamOnly,
            ),
        ],
    )
    .expect("intent");
    let fact = intent.to_fact().expect("intent fact");
    let specification = open_or_resolve_capability_spec();
    let offer = CapabilityOffer::new(
        implementation_id(),
        ArtifactDigest::parse(sha('a')).expect("artifact digest"),
        specification.id.clone(),
        BTreeMap::new(),
    )
    .expect("offer");
    let admitted = AdmittedFactRef::new(
        fact.id.clone(),
        AuthorityRecordId::parse(sha('b')).expect("authority record"),
        BTreeMap::new(),
    )
    .expect("admitted fact");
    let input = LinkedInput::new(intent_port_name(), admitted, fact, BTreeMap::new())
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

fn authority(endpoint: &str) -> AuthorityDocument {
    AuthorityDocument::new(
        TARGET,
        sha('c'),
        "operator-credential/revision-1",
        endpoint,
        SECRET,
        5_000,
        64 * 1024,
    )
    .expect("authority")
}

fn serve_success() -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let address = listener.local_addr().expect("stub address");
    let thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        read_request(&mut stream);
        let body = serde_json::to_vec(&json!({
            "id": "conversation-1",
            "name": "Direct agent-a and agent-b",
            "kind": "direct",
            "metadata": null,
            "created_at_ms": 42,
            "archived_at_ms": null,
            "latest_message_seq": null,
            "latest_message_at_ms": null,
            "members": [
                {
                    "channel_id": "conversation-1",
                    "agent_id": "agent-a",
                    "agent_name": "Agent A",
                    "joined_at_ms": 42,
                    "delivery_mode": "inbox"
                },
                {
                    "channel_id": "conversation-1",
                    "agent_id": "agent-b",
                    "agent_name": "Agent B",
                    "joined_at_ms": 42,
                    "delivery_mode": "stream_only"
                }
            ]
        }))
        .expect("response JSON");
        let head = format!(
            "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).expect("response head");
        stream.write_all(&body).expect("response body");
    });
    (format!("http://{address}/"), thread)
}

fn read_request(stream: &mut TcpStream) {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    let header_end = loop {
        let count = stream.read(&mut buffer).expect("request read");
        assert_ne!(count, 0, "request ended before headers");
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&bytes[..header_end]).expect("headers");
    let content_length = headers
        .split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("content length"))
        })
        .expect("content-length header");
    while bytes.len() - header_end < content_length {
        let count = stream.read(&mut buffer).expect("request body read");
        assert_ne!(count, 0, "request body ended early");
        bytes.extend_from_slice(&buffer[..count]);
    }
}

fn run_command(
    directory: &TempDir,
    name: &str,
    invocation: &CapabilityInvocation,
    authority: &AuthorityDocument,
) -> CommandOutput {
    let stdin_path = directory.path().join(format!("{name}.stdin"));
    let stdout_path = directory.path().join(format!("{name}.stdout"));
    let stderr_path = directory.path().join(format!("{name}.stderr"));
    std::fs::write(
        &stdin_path,
        serde_json::to_vec(invocation).expect("invocation JSON"),
    )
    .expect("write stdin");
    let stdin_file = File::open(&stdin_path).expect("open stdin");
    let stdout_file = output_file(&stdout_path);
    let stderr_file = output_file(&stderr_path);
    let (authority_read, authority_write) = pipe().expect("authority pipe");
    let mut actions = PosixSpawnFileActions::init().expect("spawn actions");
    actions
        .add_dup2(stdin_file.as_raw_fd(), 0)
        .expect("map stdin");
    actions
        .add_dup2(stdout_file.as_raw_fd(), 1)
        .expect("map stdout");
    actions
        .add_dup2(stderr_file.as_raw_fd(), 2)
        .expect("map stderr");
    actions
        .add_dup2(authority_read.as_raw_fd(), 3)
        .expect("map authority");
    if authority_read.as_raw_fd() != 3 {
        actions
            .add_close(authority_read.as_raw_fd())
            .expect("close child authority reader source");
    }
    if authority_write.as_raw_fd() != 3 {
        actions
            .add_close(authority_write.as_raw_fd())
            .expect("close child authority writer");
    }

    let executable = Path::new(env!(
        "CARGO_BIN_EXE_fleetd-direct-conversation-reqwest-provider"
    ));
    let executable_c = CString::new(executable.as_os_str().as_bytes()).expect("executable path");
    let arguments = [executable_c.clone()];
    let environment: [CString; 0] = [];
    let attributes = PosixSpawnAttr::init().expect("spawn attributes");
    let pid = posix_spawn(
        executable_c.as_c_str(),
        &actions,
        &attributes,
        &arguments,
        &environment,
    )
    .expect("spawn provider");
    drop(authority_read);
    let mut authority_writer = File::from(authority_write);
    authority_writer
        .write_all(&authority.encode_for_pipe().expect("authority bytes"))
        .expect("write authority pipe");
    drop(authority_writer);
    let exit_code = match waitpid(pid, None).expect("wait provider") {
        WaitStatus::Exited(_, code) => code,
        status => panic!("provider terminated unexpectedly: {status:?}"),
    };
    drop((stdin_file, stdout_file, stderr_file));
    CommandOutput {
        exit_code,
        stdout: std::fs::read(stdout_path).expect("read stdout"),
        stderr: std::fs::read(stderr_path).expect("read stderr"),
    }
}

fn output_file(path: &Path) -> File {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path)
        .expect("open output")
}

#[test]
fn real_command_emits_one_exact_result_or_no_result() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let exact_invocation = invocation(TARGET);
    let (endpoint, server) = serve_success();
    let success = run_command(
        &directory,
        "success",
        &exact_invocation,
        &authority(&endpoint),
    );
    server.join().expect("stub server");
    assert_eq!(success.exit_code, 0);
    assert!(success.stderr.is_empty());
    let result: CapabilityResult = serde_json::from_slice(&success.stdout).expect("one result");
    result
        .validate_against(&exact_invocation)
        .expect("valid result");
    assert_eq!(
        success.stdout,
        serde_json::to_vec(&result).expect("exact result encoding")
    );

    let mismatch = run_command(
        &directory,
        "mismatch",
        &invocation("fleetd:target-b"),
        &authority("http://127.0.0.1:9/"),
    );
    assert_ne!(mismatch.exit_code, 0);
    assert!(mismatch.stdout.is_empty());
    let stderr = String::from_utf8(mismatch.stderr).expect("stderr text");
    assert!(!stderr.is_empty());
    assert!(!stderr.contains(SECRET));
    assert!(!stderr.contains("http://127.0.0.1:9/"));
}
