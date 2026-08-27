//! Distinct Host-Fleetd to Target-Fleetd dogfood proof support.

#[allow(
    clippy::wildcard_imports,
    reason = "this proof is a private child of the accepted real-Fleetd fixture"
)]
use super::*;

use super::http::{accept_request, forward_request};
use fleetd_direct_conversation_command_abi::{
    MAX_AUTHORITY_DOCUMENT_BYTES, parse_authority_document,
};
use fleetd_direct_conversation_external_host_proof::driver::{
    DriverError, prepare, validate_existing,
};
use fleetd_direct_conversation_external_host_proof::journal::JournalError;
use fleetd_direct_conversation_external_host_proof::target::TargetBinding;
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, pipe};
use std::net::TcpListener;

const CONFIG_PROTOCOL: &str = "org.gooi.proof/fleetd-host-runner-config@0.1.0";
const HOST_AUTHORITY_PROTOCOL: &str = "org.gooi.proof/fleetd-host-agent-authority@0.1.0";
const WORK_PROTOCOL: &str = "org.gooi.proof/fleetd-host-opaque-work@0.1.0";
const RESULT_PROTOCOL: &str = "org.gooi.proof/fleetd-host-opaque-result@0.1.0";
const RUNNER_MARKER_PROTOCOL: &str = "org.gooi.proof/fleetd-host-runner-marker@0.1.0";
const PROXY_CONTROL_PROTOCOL: &str = "org.gooi.proof/fleetd-host-proxy-control@0.1.0";
const PROXY_READY_PROTOCOL: &str = "org.gooi.proof/fleetd-host-proxy-ready@0.1.0";
const TARGET_PROXY_TERMINAL_PROTOCOL: &str =
    "org.gooi.proof/fleetd-host-target-proxy-terminal@0.1.0";
const HOST_PROXY_TERMINAL_PROTOCOL: &str =
    "org.gooi.proof/fleetd-host-completion-proxy-terminal@0.1.0";
const WORK_KIND: &str = "org.gooi.proof/fleetd-host-attempt@0.1.0";
const RESULT_KIND: &str = "org.gooi.proof/fleetd-host-attempt-result@0.1.0";
const MAX_PIPE_BYTES: usize = 256 * 1024;
const MAX_CONFIG_BYTES: usize = 512 * 1024;
const LEASE_DURATION_MS: u64 = 180_000;
const CHILD_DEADLINE: Duration = Duration::from_mins(2);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpaqueWork {
    protocol: String,
    request_id: String,
    invocation: gooir_capability::protocol::CapabilityInvocation,
    baseline: AdmissionSnapshot,
    admission_policy: AdmissionPolicy,
}

impl OpaqueWork {
    fn validate(&self) {
        assert_eq!(self.protocol, WORK_PROTOCOL);
        self.invocation
            .validate()
            .unwrap_or_else(|_| panic!("host work invocation was invalid"));
        self.baseline
            .validate()
            .unwrap_or_else(|_| panic!("host work baseline was invalid"));
        self.admission_policy
            .validate()
            .unwrap_or_else(|_| panic!("host work admission policy was invalid"));
        let expected = digest_document(&json!({
            "protocol": WORK_PROTOCOL,
            "invocation_id": self.invocation.invocation_id.as_str(),
            "baseline_id": self.baseline.snapshot_id.as_str(),
            "policy_id": self.admission_policy.policy_id.as_str(),
        }));
        assert_eq!(self.request_id, expected, "host work identity changed");
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpaqueResult {
    protocol: String,
    request_id: String,
    gooir_invocation_id: String,
    checkpoint_id: String,
    resolution: AttemptResolution,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerConfig {
    protocol: String,
    package_root: PathBuf,
    native_parent: PathBuf,
    journal_parent: PathBuf,
    target_lock: PathBuf,
    target_binding: TargetBinding,
    host_deployment_id: String,
}

impl RunnerConfig {
    fn validate(&self) {
        assert_eq!(self.protocol, CONFIG_PROTOCOL);
        for path in [
            &self.package_root,
            &self.native_parent,
            &self.journal_parent,
            &self.target_lock,
        ] {
            assert!(path.is_absolute(), "runner path must be absolute");
        }
        self.target_binding
            .validate()
            .unwrap_or_else(|_| panic!("runner target binding was invalid"));
        assert_sha256(&self.host_deployment_id, "host deployment identity");
    }
}

struct HostAuthority {
    endpoint: String,
    agent_id: AgentId,
    bearer: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostAuthorityWire {
    protocol: String,
    endpoint: String,
    agent_id: String,
    bearer_token: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct HostAuthorityOut<'a> {
    protocol: &'static str,
    endpoint: &'a str,
    agent_id: &'a str,
    bearer_token: &'a str,
}

#[derive(Clone, Copy)]
enum RunnerMode {
    ArmThenExit,
    DriveThenExit,
    TerminalComplete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerMarker {
    protocol: String,
    mode: String,
    host_invocation_id: String,
    source_message_id: String,
    gooir_invocation_id: String,
    checkpoint_id: String,
    phase: AttemptPhase,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyControl {
    protocol: String,
    backend: SocketAddr,
    allow_marker: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyReady {
    protocol: String,
    address: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetProxyTerminal {
    protocol: String,
    requests: u8,
    provider_status: u16,
    attester_status: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostProxyTerminal {
    protocol: String,
    forwarded_requests: u8,
    first_completion_status: u16,
    replay_completion_status: u16,
    first_completion_body_digest: String,
    replay_completion_body_digest: String,
}

struct HostReservation {
    id: String,
    message_id: String,
    lease_token: String,
    fence_token: String,
    lease_expires_at_ms: i64,
    payload: Value,
}

/// Dispatch the single-thread coordinator and proof-local process modes.
pub(crate) fn dispatch() {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    match arguments.next().as_deref() {
        None => run_coordinator(),
        Some(mode) if mode == std::ffi::OsStr::new("--log-pump") => run_log_pump(arguments),
        Some(mode) if mode == std::ffi::OsStr::new("--target-proxy") => {
            run_target_proxy(arguments);
        }
        Some(mode) if mode == std::ffi::OsStr::new("--host-proxy") => {
            run_host_proxy(arguments);
        }
        Some(mode) if mode == std::ffi::OsStr::new("--runner-arm-exit") => {
            run_runner(arguments, RunnerMode::ArmThenExit);
        }
        Some(mode) if mode == std::ffi::OsStr::new("--runner-drive-exit") => {
            run_runner(arguments, RunnerMode::DriveThenExit);
        }
        Some(mode) if mode == std::ffi::OsStr::new("--runner-terminal-complete") => {
            run_runner(arguments, RunnerMode::TerminalComplete);
        }
        Some(_) => panic!("unknown host-proof process mode"),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the process-separated acceptance sequence is intentionally linear and auditable"
)]
fn run_coordinator() {
    let external = ExternalInputs::load();
    let revision = clean_revision(&external.fleetd_repo);
    let fleetd = StagedFleetdExecutable::stage(&external.fleetd_binary);
    let openapi_digest = sha256_file(&external.fleetd_repo.join("openapi/fleetd-v1.json"));
    let root = private_tempdir("gooir-host-fleetd-proof-");
    let package_root = private_directory(root.path(), "packages-parent").join("packages");
    stage(StageRequest {
        reqwest_command: external.reqwest_binary,
        ureq_command: external.ureq_binary,
        attester_command: external.attester_binary,
        output_root: package_root.clone(),
    })
    .unwrap_or_else(|_| panic!("host proof could not stage release packages"));
    let packages = verify_package_set(&package_root)
        .unwrap_or_else(|_| panic!("host proof could not verify release packages"));
    let (provider_binding, _) = provider_bindings(&packages);
    assert_eq!(provider_binding.package.as_str(), REQWEST_PACKAGE);

    let policy = {
        let policy_native = private_directory(root.path(), "policy-native");
        let attester = qualify_attester(&packages, &packages.report().attester, &policy_native)
            .unwrap_or_else(|_| panic!("host proof policy attester qualification failed"));
        candidate_policy(&attester)
    };

    let host_root = private_directory(root.path(), "host-fleetd");
    let target_root = private_directory(root.path(), "target-fleetd");
    let host_database = host_root.join("fleetd.db");
    let target_database = target_root.join("fleetd.db");
    let host_token_file = host_root.join("operator.token");
    let target_token_file = target_root.join("operator.token");
    let mut host = FleetdDaemon::spawn(&fleetd, &host_root, &host_database, &host_token_file, None);
    let mut target = FleetdDaemon::spawn(
        &fleetd,
        &target_root,
        &target_database,
        &target_token_file,
        None,
    );
    assert_ne!(host.child.id(), target.child.id());
    assert_ne!(host.address(), target.address());
    let host_endpoint = host.endpoint();
    let target_endpoint = target.endpoint();
    let host_operator = SecretCanary(read_operator_token(&host_token_file));
    let target_operator = SecretCanary(read_operator_token(&target_token_file));
    assert_ne!(host_operator.as_str(), target_operator.as_str());

    let client = public_client();
    let AgentRegistration {
        id: source_agent,
        bearer: source_bearer,
    } = create_agent(
        &client,
        &host_endpoint,
        host_operator.as_str(),
        "gooir-proof-source",
    );
    let AgentRegistration {
        id: runner_agent,
        bearer: runner_bearer,
    } = create_agent(
        &client,
        &host_endpoint,
        host_operator.as_str(),
        "gooir-proof-runner",
    );
    let AgentRegistration {
        id: target_agent_a,
        bearer: target_bearer_a,
    } = create_agent(
        &client,
        &target_endpoint,
        target_operator.as_str(),
        "target-agent-a",
    );
    let AgentRegistration {
        id: target_agent_b,
        bearer: target_bearer_b,
    } = create_agent(
        &client,
        &target_endpoint,
        target_operator.as_str(),
        "target-agent-b",
    );
    assert_no_public_conversations(&client, &target_endpoint, target_operator.as_str());

    let host_channel = create_host_channel(
        &client,
        &host_endpoint,
        host_operator.as_str(),
        &source_agent,
        &runner_agent,
    );

    let target_proxy_root = private_directory(root.path(), "target-proxy");
    let target_allow = target_proxy_root.join("allow");
    let (mut target_proxy, mut target_control) =
        spawn_controlled_mode("--target-proxy", &target_proxy_root);
    write_canonical_pipe(
        &mut target_control,
        &ProxyControl {
            protocol: PROXY_CONTROL_PROTOCOL.to_owned(),
            backend: target.address(),
            allow_marker: Some(target_allow.clone()),
        },
    );
    drop(target_control);
    let target_ready: ProxyReady = wait_for_canonical(&target_proxy_root.join("ready.json"));
    assert_eq!(target_ready.protocol, PROXY_READY_PROTOCOL);

    let host_proxy_root = private_directory(root.path(), "host-proxy");
    let (mut host_proxy, mut host_control) =
        spawn_controlled_mode("--host-proxy", &host_proxy_root);
    write_canonical_pipe(
        &mut host_control,
        &ProxyControl {
            protocol: PROXY_CONTROL_PROTOCOL.to_owned(),
            backend: host.address(),
            allow_marker: None,
        },
    );
    drop(host_control);
    let host_ready: ProxyReady = wait_for_canonical(&host_proxy_root.join("ready.json"));
    assert_eq!(host_ready.protocol, PROXY_READY_PROTOCOL);

    let target_endpoint_through_proxy = format!("http://{}/", target_ready.address);
    let target_coordinate = FleetdTarget::parse(format!(
        "fleetd:proof:{:x}",
        Sha256::digest(format!("{}:target", root.path().display()).as_bytes())
    ))
    .unwrap_or_else(|_| panic!("host proof target coordinate was invalid"));
    let data_identity = persist_marker(
        &target_root,
        "data-directory.identity.json",
        &json!({
            "protocol": "org.gooi.proof/fleetd-data-directory-identity@0.1.0",
            "fleetd_target": target_coordinate.as_str(),
            "marker": fresh_marker(&target_root, "data")
        }),
    );
    let credential_revision = persist_marker(
        &target_root,
        "credential-generation.identity.json",
        &json!({
            "protocol": "org.gooi.proof/fleetd-credential-generation@0.1.0",
            "fleetd_target": target_coordinate.as_str(),
            "marker": fresh_marker(&target_root, "credential")
        }),
    );
    let mapping_digest = digest_document(&json!({
        "protocol": "org.gooi.proof/fleetd-endpoint-mapping@0.1.0",
        "fleetd_target": target_coordinate.as_str(),
        "endpoint": target_endpoint_through_proxy,
    }));
    let target_lock_path = private_directory(root.path(), "target-authority").join("lock");
    let target_lock = TargetLock::new(&target_lock_path)
        .unwrap_or_else(|_| panic!("host proof target lock creation failed"));
    let target_binding = target_lock
        .configure(
            TargetDeployment::new(
                target_coordinate.clone(),
                fleetd.digest(),
                &revision,
                &openapi_digest,
                data_identity,
                mapping_digest.clone(),
                credential_revision.clone(),
            )
            .unwrap_or_else(|_| panic!("host proof target deployment was invalid")),
        )
        .unwrap_or_else(|_| panic!("host proof target binding publication failed"));
    drop(target_lock);
    let target_authority = AuthorityDocument::new(
        target_coordinate.as_str(),
        mapping_digest,
        credential_revision,
        &target_endpoint_through_proxy,
        target_operator.as_str(),
        5_000,
        u64::try_from(MAX_RESPONSE_BYTES).expect("response bound fits u64"),
    )
    .unwrap_or_else(|_| panic!("host proof target authority was invalid"));
    let target_authority_bytes = target_authority
        .encode_for_pipe()
        .unwrap_or_else(|_| panic!("host proof target authority encoding failed"));

    let intent = DirectPairIntent::new(
        target_coordinate,
        [
            DirectMember::new(target_agent_a, DeliveryMode::Inbox),
            DirectMember::new(target_agent_b, DeliveryMode::StreamOnly),
        ],
    )
    .unwrap_or_else(|_| panic!("host proof direct-pair intent was invalid"));
    let (baseline, admitted_intent) = observed_intent_baseline(&intent);
    let invocation = link_invocation(
        &packages,
        provider_binding,
        &intent,
        admitted_intent,
        planning_limits(),
    );
    let request_id = digest_document(&json!({
        "protocol": WORK_PROTOCOL,
        "invocation_id": invocation.invocation_id.as_str(),
        "baseline_id": baseline.snapshot_id.as_str(),
        "policy_id": policy.policy_id.as_str(),
    }));
    let work = OpaqueWork {
        protocol: WORK_PROTOCOL.to_owned(),
        request_id: request_id.clone(),
        invocation,
        baseline,
        admission_policy: policy,
    };
    work.validate();
    let source_message = send_host_work(
        &client,
        &host_endpoint,
        source_bearer.as_str(),
        &host_channel,
        &runner_agent,
        &work,
    );

    let host_deployment_id = digest_document(&json!({
        "protocol": "org.gooi.proof/fleetd-host-deployment@0.1.0",
        "fleetd_binary_digest": fleetd.digest(),
        "fleetd_revision": revision,
        "openapi_digest": openapi_digest,
        "data_identity": fresh_marker(&host_root, "host-deployment"),
    }));
    let native_parent = private_directory(root.path(), "runner-native");
    let journal_parent = private_directory(root.path(), "runner-journals");
    let config_path = root.path().join("runner-config.json");
    persist_canonical(
        &config_path,
        &RunnerConfig {
            protocol: CONFIG_PROTOCOL.to_owned(),
            package_root: package_root.clone(),
            native_parent,
            journal_parent: journal_parent.clone(),
            target_lock: target_lock_path,
            target_binding,
            host_deployment_id,
        },
    );
    let host_authority_bytes = encode_host_authority(
        &format!("http://{}/", host_ready.address),
        &runner_agent,
        runner_bearer.as_str(),
    );

    let first_marker_path = root.path().join("runner-first.json");
    run_runner_child(
        "--runner-arm-exit",
        &config_path,
        &first_marker_path,
        &host_authority_bytes,
        &target_authority_bytes,
    );
    let first: RunnerMarker = load_canonical(&first_marker_path);
    assert_eq!(first.mode, "arm_then_exit");
    assert_eq!(first.phase, AttemptPhase::Prepared);
    assert_eq!(first.source_message_id, source_message);
    assert_eq!(
        first.gooir_invocation_id,
        work.invocation.invocation_id.as_str()
    );
    assert!(!target_allow.exists());
    let journal_path = journal_parent.join(stable_journal_name(
        &load_config(&config_path).host_deployment_id,
        &source_message,
        work.invocation.invocation_id.as_str(),
    ));
    let prepared_bytes = canonical_checkpoint(&load_checkpoint(&journal_path));
    block_and_requeue(
        &client,
        &host_endpoint,
        host_operator.as_str(),
        runner_bearer.as_str(),
        &runner_agent,
        &first.host_invocation_id,
        &source_message,
    );
    create_marker(&target_allow);

    let second_marker_path = root.path().join("runner-second.json");
    run_runner_child(
        "--runner-drive-exit",
        &config_path,
        &second_marker_path,
        &host_authority_bytes,
        &target_authority_bytes,
    );
    let second: RunnerMarker = load_canonical(&second_marker_path);
    assert_eq!(second.mode, "drive_then_exit");
    assert_eq!(second.phase, AttemptPhase::Admitted);
    assert_eq!(second.source_message_id, source_message);
    assert_ne!(second.checkpoint_id, first.checkpoint_id);
    let terminal_checkpoint = load_checkpoint(&journal_path);
    assert_admitted_receipts(&terminal_checkpoint);
    let terminal_bytes = canonical_checkpoint(&terminal_checkpoint);
    assert_ne!(terminal_bytes, prepared_bytes);
    let reference = DirectConversationRef::from_fact(&conversation_fact(&admitted_snapshot(
        &terminal_checkpoint,
    )))
    .unwrap_or_else(|_| panic!("host proof output was not a conversation reference"));
    assert_public_conversation(
        &client,
        &target_endpoint,
        target_operator.as_str(),
        &reference,
    );
    block_and_requeue(
        &client,
        &host_endpoint,
        host_operator.as_str(),
        runner_bearer.as_str(),
        &runner_agent,
        &second.host_invocation_id,
        &source_message,
    );

    assert!(wait_managed(&mut target_proxy, CHILD_DEADLINE, "target proxy").success());
    let target_observation: TargetProxyTerminal =
        load_canonical(&target_proxy_root.join("terminal.json"));
    assert_eq!(target_observation.protocol, TARGET_PROXY_TERMINAL_PROTOCOL);
    assert_eq!(target_observation.requests, 2);
    assert_eq!(target_observation.provider_status, 201);
    assert_eq!(target_observation.attester_status, 200);
    let target_logs = target.stop();

    let third_marker_path = root.path().join("runner-third.json");
    run_runner_child(
        "--runner-terminal-complete",
        &config_path,
        &third_marker_path,
        &host_authority_bytes,
        &target_authority_bytes,
    );
    let third: RunnerMarker = load_canonical(&third_marker_path);
    assert_eq!(third.mode, "terminal_complete");
    assert_eq!(third.phase, AttemptPhase::Admitted);
    assert_eq!(third.checkpoint_id, second.checkpoint_id);
    assert_eq!(
        canonical_checkpoint(&load_checkpoint(&journal_path)),
        terminal_bytes
    );
    assert!(wait_managed(&mut host_proxy, CHILD_DEADLINE, "host proxy").success());
    let host_observation: HostProxyTerminal =
        load_canonical(&host_proxy_root.join("terminal.json"));
    assert_eq!(host_observation.protocol, HOST_PROXY_TERMINAL_PROTOCOL);
    assert_eq!(host_observation.forwarded_requests, 8);
    assert_eq!(host_observation.first_completion_status, 201);
    assert_eq!(host_observation.replay_completion_status, 200);
    assert_eq!(
        host_observation.first_completion_body_digest,
        host_observation.replay_completion_body_digest
    );

    assert_host_result(
        &client,
        &host_endpoint,
        host_operator.as_str(),
        &runner_agent,
        &third.host_invocation_id,
        &work,
        &terminal_checkpoint,
    );
    assert_host_has_no_target_conversation(
        &client,
        &host_endpoint,
        host_operator.as_str(),
        reference.conversation_id().as_str(),
    );

    let host_logs = host.stop();
    let host_durable = read_tree(&host_root);
    let journal_durable = read_tree(&journal_parent);
    let host_message_bytes = serde_json_canonicalizer::to_vec(&work)
        .unwrap_or_else(|_| panic!("host work audit encoding failed"));
    for surface in [
        &host_durable,
        &host_logs,
        &host_message_bytes,
        &journal_durable,
    ] {
        assert_absent(surface, target_endpoint.as_bytes(), "target endpoint");
        assert_absent(
            surface,
            target_endpoint_through_proxy.as_bytes(),
            "target proxy endpoint",
        );
        assert_absent(
            surface,
            target_operator.as_bytes(),
            "target operator credential",
        );
        assert_absent(
            surface,
            &target_authority_bytes,
            "target authority document",
        );
    }
    for bearer in [&target_bearer_a, &target_bearer_b] {
        for surface in [
            &host_durable,
            &host_logs,
            &host_message_bytes,
            &journal_durable,
        ] {
            assert_absent(surface, bearer.as_bytes(), "target agent credential");
        }
    }
    assert_log_canaries_absent(
        &target_logs,
        &target_endpoint,
        target_operator.as_str(),
        &target_authority_bytes,
        &[&target_bearer_a, &target_bearer_b],
    );
    assert_eq!(clean_revision(&external.fleetd_repo), revision);
}

fn run_target_proxy(mut arguments: impl Iterator<Item = OsString>) {
    let root = one_absolute_argument(&mut arguments, "target proxy root");
    validate_private_directory(&root, "target proxy root");
    let control: ProxyControl = read_canonical_stdin(MAX_PIPE_BYTES, "target proxy control");
    control.validate(true);
    let allow = control
        .allow_marker
        .as_ref()
        .unwrap_or_else(|| panic!("target proxy allow marker was absent"));
    let listener =
        TcpListener::bind("127.0.0.1:0").unwrap_or_else(|_| panic!("target proxy bind failed"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|_| panic!("target proxy address failed"));
    persist_canonical(
        &root.join("ready.json"),
        &ProxyReady {
            protocol: PROXY_READY_PROTOCOL.to_owned(),
            address,
        },
    );

    listener
        .set_nonblocking(true)
        .unwrap_or_else(|_| panic!("target proxy nonblocking transition failed"));
    let deadline = Instant::now() + CHILD_DEADLINE;
    while !allow.exists() {
        match listener.accept() {
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Ok((_stream, _peer)) => panic!("target effect occurred before host recovery arm"),
            Err(error) => panic!("target proxy pre-arm observation failed: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "target proxy allow deadline expired"
        );
        thread::sleep(Duration::from_millis(5));
    }
    listener
        .set_nonblocking(false)
        .unwrap_or_else(|_| panic!("target proxy blocking transition failed"));

    let mut provider = accept_request(&listener, 4);
    assert_eq!(provider.method(), "POST");
    assert_eq!(provider.target(), "/v1/direct-conversations");
    let provider_response = forward_request(&provider, control.backend);
    assert_eq!(provider_response.status(), 201);
    provider.write_response(&provider_response);
    provider.shutdown_write();
    let mut attester = accept_request(&listener, 4);
    assert_eq!(attester.method(), "GET");
    assert_eq!(attester.target(), "/v1/conversations?include_archived=true");
    assert_eq!(attester.body_bytes(), 0);
    let attester_response = forward_request(&attester, control.backend);
    assert_eq!(attester_response.status(), 200);
    attester.write_response(&attester_response);
    attester.shutdown_write();
    listener
        .set_nonblocking(true)
        .unwrap_or_else(|_| panic!("target proxy final nonblocking transition failed"));
    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        Ok((_stream, _peer)) => panic!("target proxy observed an unexpected third request"),
        Err(error) => panic!("target proxy final observation failed: {error}"),
    }
    persist_canonical(
        &root.join("terminal.json"),
        &TargetProxyTerminal {
            protocol: TARGET_PROXY_TERMINAL_PROTOCOL.to_owned(),
            requests: 2,
            provider_status: provider_response.status(),
            attester_status: attester_response.status(),
        },
    );
}

fn run_host_proxy(mut arguments: impl Iterator<Item = OsString>) {
    let root = one_absolute_argument(&mut arguments, "host proxy root");
    validate_private_directory(&root, "host proxy root");
    let control: ProxyControl = read_canonical_stdin(MAX_PIPE_BYTES, "host proxy control");
    control.validate(false);
    let listener =
        TcpListener::bind("127.0.0.1:0").unwrap_or_else(|_| panic!("host proxy bind failed"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|_| panic!("host proxy address failed"));
    persist_canonical(
        &root.join("ready.json"),
        &ProxyReady {
            protocol: PROXY_READY_PROTOCOL.to_owned(),
            address,
        },
    );
    let mut forwarded = 0_u8;
    let mut first_completion = None;
    let replay_completion = loop {
        let mut request = accept_request(&listener, 8);
        let is_completion = request.method() == "POST" && request.target().ends_with("/complete");
        let response = forward_request(&request, control.backend);
        forwarded = forwarded
            .checked_add(1)
            .unwrap_or_else(|| panic!("host proxy request count overflowed"));
        if is_completion && first_completion.is_none() {
            assert_eq!(response.status(), 201);
            first_completion = Some((response.status(), response.body_digest()));
            request.shutdown_both();
            continue;
        }
        request.write_response(&response);
        request.shutdown_write();
        if is_completion {
            assert_eq!(response.status(), 200);
            break (response.status(), response.body_digest());
        }
    };
    let (first_status, first_digest) =
        first_completion.unwrap_or_else(|| panic!("host proxy did not lose a completion"));
    let (replay_status, replay_digest) = replay_completion;
    persist_canonical(
        &root.join("terminal.json"),
        &HostProxyTerminal {
            protocol: HOST_PROXY_TERMINAL_PROTOCOL.to_owned(),
            forwarded_requests: forwarded,
            first_completion_status: first_status,
            replay_completion_status: replay_status,
            first_completion_body_digest: first_digest,
            replay_completion_body_digest: replay_digest,
        },
    );
}

#[allow(
    clippy::too_many_lines,
    reason = "qualification, outer-host validation, and the exact driver call remain one auditable process"
)]
fn run_runner(mut arguments: impl Iterator<Item = OsString>, mode: RunnerMode) {
    let config_path = PathBuf::from(
        arguments
            .next()
            .unwrap_or_else(|| panic!("runner config argument was missing")),
    );
    let marker_path = PathBuf::from(
        arguments
            .next()
            .unwrap_or_else(|| panic!("runner marker argument was missing")),
    );
    assert!(
        arguments.next().is_none(),
        "runner received extra arguments"
    );
    assert!(config_path.is_absolute() && marker_path.is_absolute());

    // Consume and close both credential pipes before opening durable state.
    let host_authority = read_host_authority();
    let target_authority = read_target_authority_from_fd2();
    let config = load_config(&config_path);
    assert_eq!(
        target_authority.target(),
        config.target_binding.deployment().fleetd_target().as_str()
    );
    assert_eq!(
        target_authority.endpoint_mapping_digest(),
        config.target_binding.deployment().endpoint_mapping_digest()
    );
    assert_eq!(
        target_authority.credential_revision(),
        config.target_binding.deployment().credential_revision()
    );

    let reservation = reserve(&host_authority);
    let work = serde_json::from_value::<OpaqueWork>(reservation.payload.clone())
        .unwrap_or_else(|_| panic!("host work payload was not the closed proof protocol"));
    work.validate();
    let journal_name = stable_journal_name(
        &config.host_deployment_id,
        &reservation.message_id,
        work.invocation.invocation_id.as_str(),
    );
    let journal_path = config.journal_parent.join(journal_name);
    let packages = verify_package_set(&config.package_root)
        .unwrap_or_else(|_| panic!("runner package verification failed"));
    let selected = packages
        .report()
        .providers
        .iter()
        .find(|binding| binding.offer_id == work.invocation.selection.offer.offer_id.as_str())
        .unwrap_or_else(|| panic!("runner selected offer was not in the verified package set"));
    let provider = qualify_provider(&packages, selected, &config.native_parent)
        .unwrap_or_else(|_| panic!("runner provider qualification failed"));
    let attester = qualify_attester(
        &packages,
        &packages.report().attester,
        &config.native_parent,
    )
    .unwrap_or_else(|_| panic!("runner attester qualification failed"));
    let runtime = qualify_native_runtime(provider.lock(), attester.lock())
        .unwrap_or_else(|_| panic!("runner runtime qualification failed"));
    let target_lock = TargetLock::new(&config.target_lock)
        .unwrap_or_else(|_| panic!("runner target lock reopen failed"));
    let target_guard = target_lock
        .acquire_execution(&config.target_binding)
        .unwrap_or_else(|_| panic!("runner target execution fence failed"));
    let journal =
        AttemptJournal::new(&journal_path).unwrap_or_else(|_| panic!("runner journal open failed"));
    let session = journal
        .begin_session()
        .unwrap_or_else(|_| panic!("runner journal session failed"));
    let request = DriverRequest {
        packages: &packages,
        selected_provider: selected,
        invocation: &work.invocation,
        baseline: &work.baseline,
        admission_policy: &work.admission_policy,
        provider_artifact: &provider,
        attester_artifact: &attester,
        runtime: &runtime,
        target: &target_guard,
        authority: &target_authority,
        planning_limits: planning_limits(),
        process_limits: process_limits(),
    };
    let validated = match validate_existing(&session, &request) {
        Ok(validated) => validated,
        Err(DriverError::Journal(JournalError::Missing(_))) => prepare(&session, &request)
            .unwrap_or_else(|_| panic!("runner attempt preparation failed")),
        Err(error) => panic!("runner existing-attempt validation failed: {error}"),
    };
    let before_phase = validated.phase();
    match mode {
        RunnerMode::ArmThenExit | RunnerMode::DriveThenExit => {
            assert_eq!(before_phase, AttemptPhase::Prepared);
        }
        RunnerMode::TerminalComplete => assert!(before_phase.is_terminal()),
    }
    assert_lease_budget(&reservation);
    arm(&host_authority, &reservation);

    if matches!(mode, RunnerMode::ArmThenExit) {
        persist_canonical(
            &marker_path,
            &runner_marker(
                mode,
                &reservation,
                &work,
                validated.checkpoint_id(),
                before_phase,
            ),
        );
        return;
    }

    let progress = validated
        .drive()
        .unwrap_or_else(|_| panic!("runner driver failed"));
    let checkpoint = match progress {
        DriverProgress::Terminal(checkpoint) => checkpoint,
        DriverProgress::Parked { .. } => panic!("runner parked during the admitted proof path"),
    };
    assert!(checkpoint.phase().is_terminal());
    if matches!(mode, RunnerMode::DriveThenExit) {
        persist_canonical(
            &marker_path,
            &runner_marker(
                mode,
                &reservation,
                &work,
                checkpoint.checkpoint_id(),
                checkpoint.phase(),
            ),
        );
        return;
    }

    let result = result_for(&work, &checkpoint);
    complete_with_lost_response_replay(&host_authority, &reservation, &result);
    persist_canonical(
        &marker_path,
        &runner_marker(
            mode,
            &reservation,
            &work,
            checkpoint.checkpoint_id(),
            checkpoint.phase(),
        ),
    );
}

impl ProxyControl {
    fn validate(&self, target: bool) {
        assert_eq!(self.protocol, PROXY_CONTROL_PROTOCOL);
        assert!(self.backend.ip().is_loopback());
        match (&self.allow_marker, target) {
            (Some(path), true) => assert!(path.is_absolute()),
            (None, false) => {}
            _ => panic!("proxy control kind and allow marker disagreed"),
        }
    }
}

fn runner_marker(
    mode: RunnerMode,
    reservation: &HostReservation,
    work: &OpaqueWork,
    checkpoint_id: &str,
    phase: AttemptPhase,
) -> RunnerMarker {
    RunnerMarker {
        protocol: RUNNER_MARKER_PROTOCOL.to_owned(),
        mode: match mode {
            RunnerMode::ArmThenExit => "arm_then_exit",
            RunnerMode::DriveThenExit => "drive_then_exit",
            RunnerMode::TerminalComplete => "terminal_complete",
        }
        .to_owned(),
        host_invocation_id: reservation.id.clone(),
        source_message_id: reservation.message_id.clone(),
        gooir_invocation_id: work.invocation.invocation_id.as_str().to_owned(),
        checkpoint_id: checkpoint_id.to_owned(),
        phase,
    }
}

fn result_for(work: &OpaqueWork, checkpoint: &AttemptCheckpoint) -> OpaqueResult {
    OpaqueResult {
        protocol: RESULT_PROTOCOL.to_owned(),
        request_id: work.request_id.clone(),
        gooir_invocation_id: work.invocation.invocation_id.as_str().to_owned(),
        checkpoint_id: checkpoint.checkpoint_id().to_owned(),
        resolution: checkpoint
            .resolution()
            .cloned()
            .unwrap_or_else(|| panic!("terminal checkpoint lacked a resolution")),
    }
}

fn reserve(authority: &HostAuthority) -> HostReservation {
    let response = public_client()
        .post(format!(
            "{}v1/agents/{}/invocations/reserve",
            authority.endpoint,
            authority.agent_id.as_str()
        ))
        .bearer_auth(&authority.bearer)
        .header(CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_vec(&json!({
                "limit": 1,
                "lease_duration_ms": LEASE_DURATION_MS,
            }))
            .unwrap_or_else(|_| panic!("host reserve request encoding failed")),
        )
        .send()
        .unwrap_or_else(|_| panic!("host reserve request failed"));
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = read_json(response);
    let invocations = body
        .get("invocations")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("host reserve response lacked invocations"));
    let [invocation] = invocations.as_slice() else {
        panic!("host reserve did not return exactly one invocation");
    };
    assert_eq!(
        string_at(invocation, "/agent_id"),
        authority.agent_id.as_str()
    );
    assert_eq!(string_at(invocation, "/state"), "reserved");
    assert!(
        invocation
            .pointer("/dispatch_armed_at_ms")
            .is_some_and(Value::is_null)
    );
    let message_id = string_at(invocation, "/message/id").to_owned();
    let payload = invocation
        .pointer("/message/payload")
        .cloned()
        .unwrap_or_else(|| panic!("host reserve response lacked message payload"));
    HostReservation {
        id: string_at(invocation, "/id").to_owned(),
        message_id,
        lease_token: string_at(invocation, "/lease_token").to_owned(),
        fence_token: string_at(invocation, "/fence_token").to_owned(),
        lease_expires_at_ms: integer_at(invocation, "/lease_expires_at_ms"),
        payload,
    }
}

fn arm(authority: &HostAuthority, reservation: &HostReservation) {
    let response = public_client()
        .post(format!(
            "{}v1/agents/{}/invocations/{}/arm",
            authority.endpoint,
            authority.agent_id.as_str(),
            reservation.id
        ))
        .bearer_auth(&authority.bearer)
        .header(CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_vec(&json!({
                "lease_token": reservation.lease_token,
                "fence_token": reservation.fence_token,
            }))
            .unwrap_or_else(|_| panic!("host arm request encoding failed")),
        )
        .send()
        .unwrap_or_else(|_| panic!("host arm request failed"));
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let invocation = read_json(response);
    assert_eq!(string_at(&invocation, "/id"), reservation.id);
    assert_eq!(string_at(&invocation, "/state"), "dispatch_armed");
    assert_eq!(
        string_at(&invocation, "/message/id"),
        reservation.message_id
    );
    assert_eq!(
        string_at(&invocation, "/lease_token"),
        reservation.lease_token
    );
    assert_eq!(
        string_at(&invocation, "/fence_token"),
        reservation.fence_token
    );
    assert!(
        invocation
            .pointer("/dispatch_armed_at_ms")
            .and_then(Value::as_i64)
            .is_some()
    );
}

fn complete_with_lost_response_replay(
    authority: &HostAuthority,
    reservation: &HostReservation,
    result: &OpaqueResult,
) {
    let body = serde_json::to_vec(&json!({
        "lease_token": reservation.lease_token,
        "fence_token": reservation.fence_token,
        "kind": RESULT_KIND,
        "payload": result,
    }))
    .unwrap_or_else(|_| panic!("host completion request encoding failed"));
    let url = format!(
        "{}v1/agents/{}/invocations/{}/complete",
        authority.endpoint,
        authority.agent_id.as_str(),
        reservation.id
    );
    let first = public_client()
        .post(&url)
        .bearer_auth(&authority.bearer)
        .header(CONTENT_TYPE, "application/json")
        .body(body.clone())
        .send();
    assert!(first.is_err(), "host completion response was not lost");
    let replay = public_client()
        .post(url)
        .bearer_auth(&authority.bearer)
        .header(CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .unwrap_or_else(|_| panic!("host completion replay failed"));
    assert_eq!(replay.status(), reqwest::StatusCode::OK);
    let completion = read_json(replay);
    assert_eq!(string_at(&completion, "/invocation/id"), reservation.id);
    assert_eq!(string_at(&completion, "/invocation/state"), "terminal");
    assert_eq!(string_at(&completion, "/result/kind"), RESULT_KIND);
    assert_eq!(
        completion
            .pointer("/result/payload")
            .cloned()
            .unwrap_or_else(|| panic!("host completion replay lacked result payload")),
        serde_json::to_value(result)
            .unwrap_or_else(|_| panic!("host result comparison encoding failed"))
    );
}

fn assert_lease_budget(reservation: &HostReservation) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| panic!("system clock is before Unix epoch"));
    let now_ms = i64::try_from(now.as_millis())
        .unwrap_or_else(|_| panic!("current epoch time did not fit i64"));
    let required = i64::try_from(
        process_limits()
            .provider
            .wall_time()
            .saturating_add(process_limits().attester.wall_time())
            .saturating_add(Duration::from_secs(30))
            .as_millis(),
    )
    .unwrap_or_else(|_| panic!("required lease budget did not fit i64"));
    assert!(
        reservation.lease_expires_at_ms.saturating_sub(now_ms) >= required,
        "host lease was too short for one bounded GOOIR attempt"
    );
}

fn create_host_channel(
    client: &Client,
    endpoint: &str,
    token: &str,
    source: &AgentId,
    runner: &AgentId,
) -> String {
    let response = client
        .post(format!("{endpoint}v1/channels"))
        .bearer_auth(token)
        .header(CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_vec(&json!({
                "name": "gooir opaque work",
                "metadata": {"proof": "host-fleetd"},
                "member_ids": [],
                "members": [
                    {"agent_id": source.as_str(), "delivery_mode": "stream_only"},
                    {"agent_id": runner.as_str(), "delivery_mode": "inbox"}
                ]
            }))
            .unwrap_or_else(|_| panic!("host channel request encoding failed")),
        )
        .send()
        .unwrap_or_else(|_| panic!("host channel creation failed"));
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    string_at(&read_json(response), "/id").to_owned()
}

fn send_host_work(
    client: &Client,
    endpoint: &str,
    source_bearer: &str,
    channel: &str,
    runner: &AgentId,
    work: &OpaqueWork,
) -> String {
    let response = client
        .post(format!("{endpoint}v1/channels/{channel}/messages"))
        .bearer_auth(source_bearer)
        .header(CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_vec(&json!({
                "idempotency_key": work.request_id,
                "recipient_id": runner.as_str(),
                "kind": WORK_KIND,
                "payload": work,
                "correlation_id": work.request_id,
                "causation_id": null,
            }))
            .unwrap_or_else(|_| panic!("host work message encoding failed")),
        )
        .send()
        .unwrap_or_else(|_| panic!("host work message publication failed"));
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    let message = read_json(response);
    assert_eq!(string_at(&message, "/kind"), WORK_KIND);
    assert_eq!(string_at(&message, "/recipient_id"), runner.as_str());
    string_at(&message, "/id").to_owned()
}

fn block_and_requeue(
    client: &Client,
    endpoint: &str,
    operator: &str,
    runner_bearer: &str,
    runner: &AgentId,
    invocation_id: &str,
    source_message_id: &str,
) {
    let response = client
        .get(format!(
            "{endpoint}v1/invocations?agent={}",
            runner.as_str()
        ))
        .bearer_auth(operator)
        .send()
        .unwrap_or_else(|_| panic!("host invocation observation failed"));
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let invocations = read_json(response);
    let invocation = invocations
        .as_array()
        .unwrap_or_else(|| panic!("host invocation list was not an array"))
        .iter()
        .find(|entry| string_at(entry, "/id") == invocation_id)
        .unwrap_or_else(|| panic!("armed host invocation was absent"));
    assert_eq!(string_at(invocation, "/state"), "dispatch_armed");
    assert_eq!(string_at(invocation, "/message/id"), source_message_id);
    let lease = string_at(invocation, "/lease_token");
    let response = client
        .post(format!(
            "{endpoint}v1/agents/{}/deliveries/{source_message_id}/block",
            runner.as_str()
        ))
        .bearer_auth(runner_bearer)
        .header(CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_vec(&json!({
                "lease_token": lease,
                "reason": "proof supervisor observed runner exit after durable host arm",
            }))
            .unwrap_or_else(|_| panic!("host block request encoding failed")),
        )
        .send()
        .unwrap_or_else(|_| panic!("host delivery block failed"));
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    let blocked = read_json(response);
    let block_id = integer_at(&blocked, "/block_id");
    assert_eq!(string_at(&blocked, "/message/id"), source_message_id);
    let response = client
        .post(format!("{endpoint}v1/delivery-blocks/{block_id}/resolve"))
        .bearer_auth(operator)
        .header(CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_vec(&json!({
                "resolution": "requeue",
                "retry_after_ms": 0,
                "note": "resume exact GOOIR checkpoint",
            }))
            .unwrap_or_else(|_| panic!("host requeue request encoding failed")),
        )
        .send()
        .unwrap_or_else(|_| panic!("host blocked-delivery requeue failed"));
    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
}

fn assert_host_result(
    client: &Client,
    endpoint: &str,
    operator: &str,
    runner: &AgentId,
    invocation_id: &str,
    work: &OpaqueWork,
    checkpoint: &AttemptCheckpoint,
) {
    let response = client
        .get(format!(
            "{endpoint}v1/invocations?agent={}",
            runner.as_str()
        ))
        .bearer_auth(operator)
        .send()
        .unwrap_or_else(|_| panic!("host terminal invocation observation failed"));
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = read_json(response);
    let invocation = body
        .as_array()
        .unwrap_or_else(|| panic!("host terminal invocation list was not an array"))
        .iter()
        .find(|entry| string_at(entry, "/id") == invocation_id)
        .unwrap_or_else(|| panic!("host terminal invocation was absent"));
    assert_eq!(string_at(invocation, "/state"), "terminal");
    assert_eq!(
        string_at(invocation, "/execution_certainty"),
        "outcome_known"
    );
    let trace = client
        .get(format!("{endpoint}v1/invocations/{invocation_id}/trace"))
        .bearer_auth(operator)
        .send()
        .unwrap_or_else(|_| panic!("host invocation trace observation failed"));
    assert_eq!(trace.status(), reqwest::StatusCode::OK);
    let trace = read_json(trace);
    let result = trace
        .pointer("/result")
        .unwrap_or_else(|| panic!("host trace lacked a result message"));
    assert_eq!(string_at(result, "/kind"), RESULT_KIND);
    assert_eq!(
        result
            .pointer("/payload")
            .cloned()
            .unwrap_or_else(|| panic!("host result lacked payload")),
        serde_json::to_value(result_for(work, checkpoint))
            .unwrap_or_else(|_| panic!("host expected result encoding failed"))
    );
}

fn assert_host_has_no_target_conversation(
    client: &Client,
    endpoint: &str,
    token: &str,
    target_conversation_id: &str,
) {
    let response = client
        .get(format!("{endpoint}v1/conversations?include_archived=true"))
        .bearer_auth(token)
        .send()
        .unwrap_or_else(|_| panic!("host conversation observation failed"));
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let conversations = read_json(response);
    let entries = conversations
        .as_array()
        .unwrap_or_else(|| panic!("host conversation list was not an array"));
    assert_eq!(
        entries.len(),
        1,
        "host contained an unexpected conversation"
    );
    assert_eq!(string_at(&entries[0], "/kind"), "shared");
    assert_ne!(string_at(&entries[0], "/id"), target_conversation_id);
}

fn encode_host_authority(endpoint: &str, agent_id: &AgentId, bearer: &str) -> Vec<u8> {
    let value = HostAuthorityOut {
        protocol: HOST_AUTHORITY_PROTOCOL,
        endpoint,
        agent_id: agent_id.as_str(),
        bearer_token: bearer,
    };
    let bytes = serde_json_canonicalizer::to_vec(&value)
        .unwrap_or_else(|_| panic!("host authority encoding failed"));
    assert!(bytes.len() <= MAX_PIPE_BYTES);
    bytes
}

fn read_host_authority() -> HostAuthority {
    let wire: HostAuthorityWire = read_canonical_stdin(MAX_PIPE_BYTES, "host authority");
    assert_eq!(wire.protocol, HOST_AUTHORITY_PROTOCOL);
    assert_canonical_loopback_endpoint(&wire.endpoint);
    assert!(!wire.bearer_token.is_empty() && wire.bearer_token.len() <= 4096);
    HostAuthority {
        endpoint: wire.endpoint,
        agent_id: AgentId::parse(wire.agent_id)
            .unwrap_or_else(|_| panic!("host authority agent ID was invalid")),
        bearer: wire.bearer_token,
    }
}

fn read_target_authority_from_fd2() -> AuthorityDocument {
    let mut descriptor =
        File::open("/dev/fd/2").unwrap_or_else(|_| panic!("target authority pipe was unavailable"));
    let bytes = read_bounded(
        &mut descriptor,
        MAX_AUTHORITY_DOCUMENT_BYTES,
        "target authority",
    );
    drop(descriptor);
    parse_authority_document(&bytes)
        .unwrap_or_else(|_| panic!("target authority document was invalid"))
}

fn assert_canonical_loopback_endpoint(endpoint: &str) {
    assert!(endpoint.starts_with("http://") && endpoint.ends_with('/'));
    assert!(!endpoint.contains('?') && !endpoint.contains('#'));
    let authority = endpoint
        .strip_prefix("http://")
        .and_then(|value| value.strip_suffix('/'))
        .unwrap_or_else(|| panic!("host endpoint shape changed"));
    let address = authority
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| panic!("host endpoint was not an IP socket address"));
    assert!(address.ip().is_loopback());
}

fn run_runner_child(
    mode: &str,
    config: &Path,
    marker: &Path,
    host_authority: &[u8],
    target_authority: &[u8],
) {
    let executable =
        env::current_exe().unwrap_or_else(|_| panic!("host-proof executable could not be located"));
    let (target_read, mut target_writer) =
        pipe().unwrap_or_else(|_| panic!("target authority pipe creation failed"));
    let raw_child = Command::new(executable)
        .env_clear()
        .arg(mode)
        .arg(config)
        .arg(marker)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::from(target_read))
        .spawn()
        .unwrap_or_else(|_| panic!("host-proof runner child failed to execute"));
    let mut child = ManagedChild::new(raw_child);
    let mut host_writer = child
        .child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("host authority pipe was unavailable"));
    write_bounded_pipe(
        &mut host_writer,
        host_authority,
        MAX_PIPE_BYTES,
        "host authority",
    );
    drop(host_writer);
    write_bounded_pipe(
        &mut target_writer,
        target_authority,
        MAX_AUTHORITY_DOCUMENT_BYTES,
        "target authority",
    );
    drop(target_writer);
    assert!(
        wait_managed(&mut child, CHILD_DEADLINE, "host-proof runner").success(),
        "host-proof runner exited unsuccessfully"
    );
}

fn spawn_controlled_mode(mode: &str, root: &Path) -> (ManagedChild, ChildStdin) {
    let executable =
        env::current_exe().unwrap_or_else(|_| panic!("host-proof executable could not be located"));
    let raw_child = Command::new(executable)
        .env_clear()
        .arg(mode)
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|_| panic!("host-proof controlled child failed to execute"));
    let mut child = ManagedChild::new(raw_child);
    let input = child
        .child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("host-proof control pipe was unavailable"));
    (child, input)
}

fn wait_managed(child: &mut ManagedChild, duration: Duration, surface: &str) -> ExitStatus {
    let deadline = Instant::now() + duration;
    loop {
        if let Some(status) = child
            .try_wait()
            .unwrap_or_else(|_| panic!("{surface} observation failed"))
        {
            return status;
        }
        if Instant::now() >= deadline {
            child
                .kill()
                .unwrap_or_else(|_| panic!("{surface} deadline kill failed"));
            let _status = child
                .wait()
                .unwrap_or_else(|_| panic!("{surface} deadline reap failed"));
            panic!("{surface} deadline expired");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn one_absolute_argument(arguments: &mut impl Iterator<Item = OsString>, surface: &str) -> PathBuf {
    let path = PathBuf::from(
        arguments
            .next()
            .unwrap_or_else(|| panic!("{surface} argument was missing")),
    );
    assert!(
        arguments.next().is_none(),
        "{surface} received extra arguments"
    );
    assert!(path.is_absolute(), "{surface} argument was not absolute");
    path
}

fn stable_journal_name(host_deployment: &str, message: &str, invocation: &str) -> String {
    assert_sha256(host_deployment, "host deployment identity");
    assert_sha256(invocation, "GOOIR invocation identity");
    assert!(!message.is_empty() && message.len() <= 256);
    let digest = digest_document(&json!({
        "protocol": "org.gooi.proof/fleetd-host-journal-key@0.1.0",
        "host_deployment_id": host_deployment,
        "source_message_id": message,
        "gooir_invocation_id": invocation,
    }));
    format!(
        "attempt-{}",
        digest.strip_prefix("sha256:").unwrap_or(&digest)
    )
}

fn load_checkpoint(path: &Path) -> AttemptCheckpoint {
    let journal = AttemptJournal::new(path)
        .unwrap_or_else(|_| panic!("host-proof checkpoint journal open failed"));
    let session = journal
        .begin_session()
        .unwrap_or_else(|_| panic!("host-proof checkpoint session failed"));
    let checkpoint = session
        .load()
        .unwrap_or_else(|_| panic!("host-proof checkpoint load failed"));
    checkpoint
        .validate()
        .unwrap_or_else(|_| panic!("host-proof checkpoint validation failed"));
    checkpoint
}

fn private_directory(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    fs::create_dir(&path).unwrap_or_else(|_| panic!("private directory creation failed"));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|_| panic!("private directory permission failed"));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .unwrap_or_else(|_| panic!("private directory parent sync failed"));
    let canonical = path
        .canonicalize()
        .unwrap_or_else(|_| panic!("private directory canonicalization failed"));
    validate_private_directory(&canonical, "private directory");
    canonical
}

fn validate_private_directory(path: &Path, surface: &str) {
    assert!(path.is_absolute(), "{surface} must be absolute");
    let metadata =
        fs::symlink_metadata(path).unwrap_or_else(|_| panic!("{surface} inspection failed"));
    assert!(
        metadata.file_type().is_dir()
            && metadata.uid() == geteuid().as_raw()
            && metadata.mode() & 0o777 == 0o700,
        "{surface} metadata was invalid"
    );
}

fn persist_canonical(path: &Path, value: &impl Serialize) {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .unwrap_or_else(|_| panic!("canonical proof document encoding failed"));
    assert!(bytes.len() <= MAX_CONFIG_BYTES);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|_| panic!("canonical proof document creation failed"));
    file.write_all(&bytes)
        .unwrap_or_else(|_| panic!("canonical proof document write failed"));
    file.sync_all()
        .unwrap_or_else(|_| panic!("canonical proof document sync failed"));
    File::open(
        path.parent()
            .unwrap_or_else(|| panic!("canonical proof document lacked parent")),
    )
    .and_then(|parent| parent.sync_all())
    .unwrap_or_else(|_| panic!("canonical proof document parent sync failed"));
}

fn load_canonical<T>(path: &Path) -> T
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let bytes = fs::read(path).unwrap_or_else(|_| panic!("canonical proof document read failed"));
    assert!(bytes.len() <= MAX_CONFIG_BYTES);
    let value = serde_json::from_slice::<T>(&bytes)
        .unwrap_or_else(|_| panic!("canonical proof document decode failed"));
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .unwrap_or_else(|_| panic!("canonical proof document re-encoding failed"));
    assert_eq!(bytes, canonical, "proof document was not canonical");
    value
}

fn load_config(path: &Path) -> RunnerConfig {
    let config: RunnerConfig = load_canonical(path);
    config.validate();
    config
}

fn wait_for_canonical<T>(path: &Path) -> T
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let deadline = Instant::now() + CHILD_DEADLINE;
    loop {
        if path.exists() {
            return load_canonical(path);
        }
        assert!(Instant::now() < deadline, "proof document deadline expired");
        thread::sleep(Duration::from_millis(5));
    }
}

fn write_canonical_pipe(writer: &mut ChildStdin, value: &impl Serialize) {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .unwrap_or_else(|_| panic!("canonical control encoding failed"));
    write_bounded_pipe(writer, &bytes, MAX_PIPE_BYTES, "control");
}

fn write_bounded_pipe(writer: &mut impl Write, bytes: &[u8], bound: usize, surface: &str) {
    assert!(
        !bytes.is_empty() && bytes.len() <= bound,
        "{surface} exceeded its bound"
    );
    writer
        .write_all(bytes)
        .unwrap_or_else(|_| panic!("{surface} pipe write failed"));
    writer
        .flush()
        .unwrap_or_else(|_| panic!("{surface} pipe flush failed"));
}

fn read_canonical_stdin<T>(bound: usize, surface: &str) -> T
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let bytes = read_bounded(&mut std::io::stdin().lock(), bound, surface);
    let value = serde_json::from_slice::<T>(&bytes)
        .unwrap_or_else(|_| panic!("{surface} JSON was invalid"));
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .unwrap_or_else(|_| panic!("{surface} canonicalization failed"));
    assert_eq!(bytes, canonical, "{surface} was not canonical");
    value
}

fn read_bounded(reader: &mut impl Read, bound: usize, surface: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    reader
        .take(u64::try_from(bound + 1).expect("pipe bound fits u64"))
        .read_to_end(&mut bytes)
        .unwrap_or_else(|_| panic!("{surface} read failed"));
    assert!(
        !bytes.is_empty() && bytes.len() <= bound,
        "{surface} exceeded its bound"
    );
    bytes
}

fn create_marker(path: &Path) {
    persist_canonical(
        path,
        &json!({
            "protocol": "org.gooi.proof/fleetd-host-effect-release@0.1.0",
            "released": true,
        }),
    );
}

fn string_at<'a>(value: &'a Value, pointer: &str) -> &'a str {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("Fleetd response lacked string at {pointer}"))
}

fn integer_at(value: &Value, pointer: &str) -> i64 {
    value
        .pointer(pointer)
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("Fleetd response lacked integer at {pointer}"))
}

fn assert_sha256(value: &str, surface: &str) {
    assert_eq!(value.len(), 71, "{surface} had the wrong length");
    assert!(
        value.starts_with("sha256:"),
        "{surface} lacked its algorithm"
    );
    assert!(
        value[7..].bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{surface} was not hexadecimal"
    );
}

fn assert_absent(haystack: &[u8], needle: &[u8], surface: &str) {
    assert!(
        needle.is_empty()
            || !haystack
                .windows(needle.len())
                .any(|window| window == needle),
        "{surface} appeared in a forbidden durable surface"
    );
}
