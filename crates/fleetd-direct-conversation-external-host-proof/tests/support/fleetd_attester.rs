//! Process-separated real Fleetd attester recovery and capacity proof support.

#[allow(
    clippy::wildcard_imports,
    reason = "this proof is a private child of the accepted real-proof fixture and reuses its exact boundary"
)]
use super::*;

use super::http::{HttpRequest, HttpResponse, accept_request, forward_request};
use fleetd_direct_conversation_command_abi::{
    MAX_AUTHORITY_DOCUMENT_BYTES, parse_authority_document,
};
use fleetd_direct_conversation_external_host_proof::native::NativeQualificationError;
use fleetd_direct_conversation_external_host_proof::supervisor::{
    ProcessReceipt, ProcessTermination, SupervisorError,
};
use fleetd_direct_conversation_external_host_proof::target::TargetBinding;
use serde::{Deserialize, Serialize};
use std::io::ErrorKind;

const CONFIG_PROTOCOL: &str = "org.gooi.proof/fleetd-attester-config@0.1.0";
const PROXY_CONTROL_PROTOCOL: &str = "org.gooi.proof/fleetd-attester-proxy-control@0.1.0";
const PROXY_READY_PROTOCOL: &str = "org.gooi.proof/fleetd-attester-proxy-ready@0.1.0";
const PROXY_TERMINAL_PROTOCOL: &str = "org.gooi.proof/fleetd-attester-proxy-terminal@0.1.0";
const MAX_CONTROL_BYTES: usize = 8 * 1024;
const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_NATIVE_ARTIFACT_BYTES: usize = 128 * 1024 * 1024;
const PROCESS_DEADLINE: Duration = Duration::from_secs(90);
const ATTESTER_FAILURE: &[u8] = b"fleetd direct-conversation attester failed\n";
const EMPTY_BODY_DIGEST: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const FAILURE_RESPONSE: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttesterConfig {
    protocol: String,
    package_root: PathBuf,
    native_parent: PathBuf,
    journal: PathBuf,
    target_lock: PathBuf,
    target_binding: TargetBinding,
    intent: DirectPairIntent,
}

impl AttesterConfig {
    fn validate(&self) {
        assert_eq!(self.protocol, CONFIG_PROTOCOL);
        for path in [
            &self.package_root,
            &self.native_parent,
            &self.journal,
            &self.target_lock,
        ] {
            assert!(path.is_absolute(), "attester-proof paths must be absolute");
        }
        self.target_binding
            .validate()
            .unwrap_or_else(|_| panic!("attester-proof target binding was invalid"));
        assert_eq!(
            self.intent.fleetd_target(),
            self.target_binding.deployment().fleetd_target(),
            "attester-proof intent and deployment targets differed"
        );
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyControl {
    protocol: String,
    backend: SocketAddr,
    native_parent: PathBuf,
    attester_resource_digest: String,
    completion_marker: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyReady {
    protocol: String,
    address: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyObservation {
    bytes: u64,
    digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyTerminal {
    protocol: String,
    provider_posts: u8,
    attester_gets: u8,
    provider_request: BodyObservation,
    provider_response: BodyObservation,
    successful_attester_response: Option<BodyObservation>,
    third_request_absent_after_reexec: bool,
}

struct PreparedScenario {
    config: PathBuf,
    journal: PathBuf,
    authority: Vec<u8>,
    endpoint: String,
}

/// Dispatch the credential-owning coordinator and proof-local child modes.
pub(crate) fn dispatch() {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    match arguments.next().as_deref() {
        None => run_coordinator(),
        Some(mode) if mode == std::ffi::OsStr::new("--log-pump") => run_log_pump(arguments),
        Some(mode) if mode == std::ffi::OsStr::new("--recovery-proxy") => {
            run_proxy(arguments, true);
        }
        Some(mode) if mode == std::ffi::OsStr::new("--capacity-proxy") => {
            run_proxy(arguments, false);
        }
        Some(mode) if mode == std::ffi::OsStr::new("--host-start-recovery") => {
            run_host(arguments, HostExpectation::RecoveryPark);
        }
        Some(mode) if mode == std::ffi::OsStr::new("--host-resume-admitted") => {
            run_host(arguments, HostExpectation::Admitted);
        }
        Some(mode) if mode == std::ffi::OsStr::new("--host-start-capacity") => {
            run_host(arguments, HostExpectation::CapacityStart);
        }
        Some(mode) if mode == std::ffi::OsStr::new("--host-resume-capacity") => {
            run_host(arguments, HostExpectation::CapacityReplay);
        }
        Some(mode) if mode == std::ffi::OsStr::new("--host-terminal") => {
            run_host(arguments, HostExpectation::TerminalReplay);
        }
        Some(_) => panic!("unknown attester-proof process mode"),
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
    let root = private_tempdir("gooir-attester-proof-");
    let package_root = root.path().join("packages");
    stage(StageRequest {
        reqwest_command: external.reqwest_binary,
        ureq_command: external.ureq_binary,
        attester_command: external.attester_binary,
        output_root: package_root.clone(),
    })
    .unwrap_or_else(|_| panic!("attester coordinator could not stage release packages"));
    let packages = verify_package_set(&package_root)
        .unwrap_or_else(|_| panic!("attester coordinator could not verify release packages"));
    let (provider_binding, _) = provider_bindings(&packages);
    assert_eq!(provider_binding.package.as_str(), REQWEST_PACKAGE);
    let attester_binding = &packages.report().attester;
    assert_ne!(
        provider_binding.resource_digest.as_str(),
        attester_binding.resource_digest.as_str(),
        "provider and attester resources must be distinct"
    );

    let database = root.path().join("fleetd.db");
    let token_file = root.path().join("operator.token");
    let mut daemon = FleetdDaemon::spawn(&fleetd, root.path(), &database, &token_file, None);
    let backend = daemon.address();
    let backend_endpoint = daemon.endpoint();
    let operator_bearer = SecretCanary(read_operator_token(&token_file));
    let client = public_client();
    let AgentRegistration {
        id: recovery_agent_a,
        bearer: recovery_bearer_a,
    } = create_agent(
        &client,
        &backend_endpoint,
        operator_bearer.as_str(),
        "attester-recovery-agent-a",
    );
    let AgentRegistration {
        id: recovery_agent_b,
        bearer: recovery_bearer_b,
    } = create_agent(
        &client,
        &backend_endpoint,
        operator_bearer.as_str(),
        "attester-recovery-agent-b",
    );
    let AgentRegistration {
        id: capacity_agent_a,
        bearer: capacity_bearer_a,
    } = create_agent(
        &client,
        &backend_endpoint,
        operator_bearer.as_str(),
        "attester-capacity-agent-a",
    );
    let AgentRegistration {
        id: capacity_agent_b,
        bearer: capacity_bearer_b,
    } = create_agent(
        &client,
        &backend_endpoint,
        operator_bearer.as_str(),
        "attester-capacity-agent-b",
    );
    assert_no_public_conversations(&client, &backend_endpoint, operator_bearer.as_str());
    drop(client);
    let agent_bearers = [
        &recovery_bearer_a,
        &recovery_bearer_b,
        &capacity_bearer_a,
        &capacity_bearer_b,
    ];

    let recovery_native = attester_private_directory(root.path(), "recovery-native");
    let recovery_proxy_root = attester_private_directory(root.path(), "recovery-proxy");
    let (mut recovery_proxy, mut recovery_control) =
        attester_spawn_mode("--recovery-proxy", &recovery_proxy_root);
    attester_write_canonical_pipe(
        &mut recovery_control,
        &ProxyControl {
            protocol: PROXY_CONTROL_PROTOCOL.to_owned(),
            backend,
            native_parent: recovery_native.clone(),
            attester_resource_digest: attester_binding.resource_digest.as_str().to_owned(),
            completion_marker: None,
        },
    );
    drop(recovery_control);
    let recovery_ready: ProxyReady =
        attester_wait_for_canonical(&recovery_proxy_root.join("ready.json"));
    assert_eq!(recovery_ready.protocol, PROXY_READY_PROTOCOL);
    assert!(recovery_ready.address.ip().is_loopback());
    let recovery = prepare_scenario(
        root.path(),
        "recovery",
        &package_root,
        recovery_native,
        &fleetd,
        &revision,
        &openapi_digest,
        recovery_ready.address,
        operator_bearer.as_str(),
        recovery_agent_a,
        recovery_agent_b,
    );
    let (mut first_host, mut first_authority) =
        attester_spawn_mode("--host-start-recovery", &recovery.config);
    attester_write_pipe(
        &mut first_authority,
        &recovery.authority,
        "first recovery authority",
    );
    drop(first_authority);
    assert!(
        attester_wait_managed(&mut first_host, PROCESS_DEADLINE, "first recovery host").success()
    );
    let armed = attester_load_checkpoint(&recovery.journal);
    assert_one_receipt_armed(&armed);

    let (mut recovery_host, mut recovery_authority) =
        attester_spawn_mode("--host-resume-admitted", &recovery.config);
    attester_write_pipe(
        &mut recovery_authority,
        &recovery.authority,
        "recovery authority",
    );
    drop(recovery_authority);
    assert!(attester_wait_managed(&mut recovery_host, PROCESS_DEADLINE, "recovery host").success());
    assert!(
        attester_wait_managed(&mut recovery_proxy, PROCESS_DEADLINE, "recovery proxy").success()
    );
    let recovery_observation: ProxyTerminal =
        attester_wait_for_canonical(&recovery_proxy_root.join("terminal.json"));
    assert_eq!(recovery_observation.protocol, PROXY_TERMINAL_PROTOCOL);
    assert_eq!(recovery_observation.provider_posts, 1);
    assert_eq!(recovery_observation.attester_gets, 2);
    assert!(!recovery_observation.third_request_absent_after_reexec);
    assert!(recovery_observation.provider_request.bytes > 0);
    assert!(recovery_observation.successful_attester_response.is_some());

    let admitted = attester_load_checkpoint(&recovery.journal);
    assert_recovered_admitted(&admitted);
    let admitted_bytes = canonical_checkpoint(&admitted);
    let snapshot = admitted_snapshot(&admitted);
    let fact = conversation_fact(&snapshot);
    let reference = DirectConversationRef::from_fact(&fact)
        .unwrap_or_else(|_| panic!("attester recovery output was not a conversation reference"));
    assert_public_conversation(
        &public_client(),
        &backend_endpoint,
        operator_bearer.as_str(),
        &reference,
    );

    let capacity_native = attester_private_directory(root.path(), "capacity-native");
    let capacity_proxy_root = attester_private_directory(root.path(), "capacity-proxy");
    let completion_marker = capacity_proxy_root.join("resume-complete");
    let (mut capacity_proxy, mut capacity_control) =
        attester_spawn_mode("--capacity-proxy", &capacity_proxy_root);
    attester_write_canonical_pipe(
        &mut capacity_control,
        &ProxyControl {
            protocol: PROXY_CONTROL_PROTOCOL.to_owned(),
            backend,
            native_parent: capacity_native.clone(),
            attester_resource_digest: attester_binding.resource_digest.as_str().to_owned(),
            completion_marker: Some(completion_marker.clone()),
        },
    );
    drop(capacity_control);
    let capacity_ready: ProxyReady =
        attester_wait_for_canonical(&capacity_proxy_root.join("ready.json"));
    assert_eq!(capacity_ready.protocol, PROXY_READY_PROTOCOL);
    assert!(capacity_ready.address.ip().is_loopback());
    let capacity = prepare_scenario(
        root.path(),
        "capacity",
        &package_root,
        capacity_native,
        &fleetd,
        &revision,
        &openapi_digest,
        capacity_ready.address,
        operator_bearer.as_str(),
        capacity_agent_a,
        capacity_agent_b,
    );
    let (mut capacity_host, mut capacity_authority) =
        attester_spawn_mode("--host-start-capacity", &capacity.config);
    attester_write_pipe(
        &mut capacity_authority,
        &capacity.authority,
        "capacity authority",
    );
    drop(capacity_authority);
    assert!(attester_wait_managed(&mut capacity_host, PROCESS_DEADLINE, "capacity host").success());
    let capacity_armed = attester_load_checkpoint(&capacity.journal);
    assert_capacity_armed(&capacity_armed);
    let capacity_bytes = canonical_checkpoint(&capacity_armed);
    let (mut capacity_resume, mut capacity_resume_authority) =
        attester_spawn_mode("--host-resume-capacity", &capacity.config);
    attester_write_pipe(
        &mut capacity_resume_authority,
        &capacity.authority,
        "capacity resume authority",
    );
    drop(capacity_resume_authority);
    assert!(
        attester_wait_managed(
            &mut capacity_resume,
            PROCESS_DEADLINE,
            "capacity resume host"
        )
        .success()
    );
    let capacity_replayed = attester_load_checkpoint(&capacity.journal);
    assert_eq!(canonical_checkpoint(&capacity_replayed), capacity_bytes);
    attester_create_marker(&completion_marker);
    assert!(
        attester_wait_managed(&mut capacity_proxy, PROCESS_DEADLINE, "capacity proxy").success()
    );
    let capacity_observation: ProxyTerminal =
        attester_wait_for_canonical(&capacity_proxy_root.join("terminal.json"));
    assert_eq!(capacity_observation.protocol, PROXY_TERMINAL_PROTOCOL);
    assert_eq!(capacity_observation.provider_posts, 1);
    assert_eq!(capacity_observation.attester_gets, 2);
    assert!(capacity_observation.successful_attester_response.is_none());
    assert!(capacity_observation.third_request_absent_after_reexec);

    let logs = daemon.stop();
    let (mut terminal_host, mut terminal_authority) =
        attester_spawn_mode("--host-terminal", &recovery.config);
    attester_write_pipe(
        &mut terminal_authority,
        &recovery.authority,
        "terminal replay authority",
    );
    drop(terminal_authority);
    assert!(
        attester_wait_managed(&mut terminal_host, PROCESS_DEADLINE, "terminal replay host")
            .success()
    );
    assert_eq!(
        canonical_checkpoint(&attester_load_checkpoint(&recovery.journal)),
        admitted_bytes,
        "offline terminal replay changed the exact checkpoint"
    );

    let recovery_journal = AttemptJournal::new(&recovery.journal)
        .unwrap_or_else(|_| panic!("recovery journal audit open failed"));
    let capacity_journal = AttemptJournal::new(&capacity.journal)
        .unwrap_or_else(|_| panic!("capacity journal audit open failed"));
    let recovery_journal_bytes = read_tree(recovery_journal.directory_path());
    let capacity_journal_bytes = read_tree(capacity_journal.directory_path());
    let recovery_config_bytes =
        fs::read(&recovery.config).unwrap_or_else(|_| panic!("recovery config audit failed"));
    let capacity_config_bytes =
        fs::read(&capacity.config).unwrap_or_else(|_| panic!("capacity config audit failed"));
    let recovery_proxy_bytes = read_tree(&recovery_proxy_root);
    let capacity_proxy_bytes = read_tree(&capacity_proxy_root);
    for surface in [
        &recovery_journal_bytes,
        &capacity_journal_bytes,
        &recovery_config_bytes,
        &capacity_config_bytes,
        &recovery_proxy_bytes,
        &capacity_proxy_bytes,
    ] {
        for (endpoint, authority) in [
            (&recovery.endpoint, recovery.authority.as_slice()),
            (&capacity.endpoint, capacity.authority.as_slice()),
            (&backend_endpoint, recovery.authority.as_slice()),
            (&backend_endpoint, capacity.authority.as_slice()),
        ] {
            assert_journal_canaries_absent(
                surface,
                endpoint,
                operator_bearer.as_str(),
                authority,
                &agent_bearers,
            );
        }
    }
    for (endpoint, authority) in [
        (&backend_endpoint, recovery.authority.as_slice()),
        (&recovery.endpoint, recovery.authority.as_slice()),
        (&capacity.endpoint, capacity.authority.as_slice()),
    ] {
        assert_log_canaries_absent(
            &logs,
            endpoint,
            operator_bearer.as_str(),
            authority,
            &agent_bearers,
        );
    }
    assert_eq!(clean_revision(&external.fleetd_repo), revision);
}

#[allow(clippy::too_many_arguments)]
fn prepare_scenario(
    root: &Path,
    label: &str,
    package_root: &Path,
    native_parent: PathBuf,
    fleetd: &StagedFleetdExecutable,
    revision: &str,
    openapi_digest: &str,
    proxy: SocketAddr,
    operator_bearer: &str,
    agent_a: AgentId,
    agent_b: AgentId,
) -> PreparedScenario {
    let endpoint = format!("http://{proxy}/");
    let target = FleetdTarget::parse(format!(
        "fleetd:proof:{:x}",
        Sha256::digest(format!("{}:{label}:attester", root.display()).as_bytes())
    ))
    .unwrap_or_else(|_| panic!("attester scenario target construction failed"));
    let data_identity = persist_marker(
        root,
        &format!("{label}-data.identity.json"),
        &json!({
            "protocol": "org.gooi.proof/fleetd-data-directory-identity@0.1.0",
            "fleetd_target": target.as_str(),
            "marker": fresh_marker(root, &format!("{label}-data"))
        }),
    );
    let credential_revision = persist_marker(
        root,
        &format!("{label}-credential.identity.json"),
        &json!({
            "protocol": "org.gooi.proof/fleetd-credential-generation@0.1.0",
            "fleetd_target": target.as_str(),
            "marker": fresh_marker(root, &format!("{label}-credential"))
        }),
    );
    let mapping_digest = digest_document(&json!({
        "protocol": "org.gooi.proof/fleetd-endpoint-mapping@0.1.0",
        "fleetd_target": target.as_str(),
        "endpoint": endpoint
    }));
    let target_lock_path = root.join(format!("{label}-target-lock"));
    let target_lock = TargetLock::new(&target_lock_path)
        .unwrap_or_else(|_| panic!("attester scenario target-lock creation failed"));
    let target_binding = target_lock
        .configure(
            TargetDeployment::new(
                target.clone(),
                fleetd.digest(),
                revision,
                openapi_digest,
                data_identity,
                mapping_digest.clone(),
                credential_revision.clone(),
            )
            .unwrap_or_else(|_| panic!("attester scenario target deployment was invalid")),
        )
        .unwrap_or_else(|_| panic!("attester scenario target deployment publish failed"));
    let authority = AuthorityDocument::new(
        target.as_str(),
        mapping_digest,
        credential_revision,
        &endpoint,
        operator_bearer,
        5_000,
        u64::try_from(MAX_RESPONSE_BYTES).expect("response bound fits u64"),
    )
    .unwrap_or_else(|_| panic!("attester scenario authority was invalid"))
    .encode_for_pipe()
    .unwrap_or_else(|_| panic!("attester scenario authority encoding failed"));
    let intent = DirectPairIntent::new(
        target,
        [
            DirectMember::new(agent_a, DeliveryMode::Inbox),
            DirectMember::new(agent_b, DeliveryMode::StreamOnly),
        ],
    )
    .unwrap_or_else(|_| panic!("attester scenario intent was invalid"));
    let journal = root.join(format!("{label}-attempt"));
    let config = root.join(format!("{label}-config.json"));
    attester_persist_canonical(
        &config,
        &AttesterConfig {
            protocol: CONFIG_PROTOCOL.to_owned(),
            package_root: package_root.to_path_buf(),
            native_parent,
            journal: journal.clone(),
            target_lock: target_lock_path,
            target_binding,
            intent,
        },
    );
    PreparedScenario {
        config,
        journal,
        authority,
        endpoint,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the proxy's fixed two-request attester sequence is intentionally linear and auditable"
)]
fn run_proxy(mut arguments: impl Iterator<Item = OsString>, poison_first_cwd: bool) {
    let root = PathBuf::from(
        arguments
            .next()
            .unwrap_or_else(|| panic!("attester proxy root argument was missing")),
    );
    assert!(
        arguments.next().is_none(),
        "attester proxy received extra arguments"
    );
    attester_validate_private_directory(&root, "attester proxy root");
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|_| panic!("attester proxy loopback bind failed"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|_| panic!("attester proxy address inspection failed"));
    assert!(address.ip().is_loopback());
    attester_persist_canonical(
        &root.join("ready.json"),
        &ProxyReady {
            protocol: PROXY_READY_PROTOCOL.to_owned(),
            address,
        },
    );
    let control: ProxyControl = attester_read_canonical_stdin(MAX_CONTROL_BYTES, "proxy control");
    assert_eq!(control.protocol, PROXY_CONTROL_PROTOCOL);
    assert!(control.backend.ip().is_loopback());
    attester_validate_private_directory(&control.native_parent, "native parent");
    assert!(
        control.attester_resource_digest.starts_with("sha256:")
            && control.attester_resource_digest.len() == 71
    );
    if poison_first_cwd {
        assert!(control.completion_marker.is_none());
    } else {
        let marker = control
            .completion_marker
            .as_ref()
            .unwrap_or_else(|| panic!("capacity proxy completion marker was absent"));
        assert!(marker.is_absolute());
        assert_eq!(marker.parent(), Some(root.as_path()));
    }

    let mut provider_request = accept_request(&listener, 4);
    assert_provider_request(&provider_request);
    let provider_observation = BodyObservation {
        bytes: provider_request.body_bytes(),
        digest: provider_request.body_digest(),
    };
    assert!(provider_observation.bytes > 0);
    let provider_response = forward_request(&provider_request, control.backend);
    assert_eq!(provider_response.status(), 201);
    let provider_response_observation = BodyObservation {
        bytes: provider_response.body_bytes(),
        digest: provider_response.body_digest(),
    };
    provider_request.write_response(&provider_response);
    provider_request.shutdown_write();

    let mut first_attester = accept_request(&listener, 4);
    assert_attester_request(&first_attester);
    if poison_first_cwd {
        poison_attester_cwd(&control.native_parent, &control.attester_resource_digest);
    }
    write_failure(&mut first_attester);
    let mut second_attester = accept_request(&listener, 4);
    assert_attester_request(&second_attester);
    let successful_attester_response = if poison_first_cwd {
        let response = forward_request(&second_attester, control.backend);
        assert_eq!(response.status(), 200);
        let observation = BodyObservation {
            bytes: response.body_bytes(),
            digest: response.body_digest(),
        };
        second_attester.write_response(&response);
        second_attester.shutdown_write();
        Some(observation)
    } else {
        write_failure(&mut second_attester);
        None
    };

    let third_request_absent_after_reexec = if let Some(marker) = &control.completion_marker {
        attester_wait_for_marker(marker);
        listener
            .set_nonblocking(true)
            .unwrap_or_else(|_| panic!("capacity proxy nonblocking transition failed"));
        match listener.accept() {
            Err(error) if error.kind() == ErrorKind::WouldBlock => true,
            Ok((_stream, _peer)) => panic!("capacity resume attempted a third HTTP request"),
            Err(error) => panic!(
                "capacity proxy final connection inspection failed: {:?}",
                error.kind()
            ),
        }
    } else {
        false
    };
    attester_persist_canonical(
        &root.join("terminal.json"),
        &ProxyTerminal {
            protocol: PROXY_TERMINAL_PROTOCOL.to_owned(),
            provider_posts: 1,
            attester_gets: 2,
            provider_request: provider_observation,
            provider_response: provider_response_observation,
            successful_attester_response,
            third_request_absent_after_reexec,
        },
    );
}

fn assert_provider_request(request: &HttpRequest) {
    assert_eq!(request.method(), "POST");
    assert_eq!(request.target(), "/v1/direct-conversations");
}

fn assert_attester_request(request: &HttpRequest) {
    assert_eq!(request.method(), "GET");
    assert_eq!(request.target(), "/v1/conversations?include_archived=true");
    assert_eq!(request.body_bytes(), 0);
    assert_eq!(request.body_digest(), EMPTY_BODY_DIGEST);
}

fn write_failure(request: &mut HttpRequest) {
    let response = HttpResponse::from_bytes(FAILURE_RESPONSE.to_vec());
    assert_eq!(response.status(), 503);
    assert_eq!(response.body_bytes(), 0);
    assert_eq!(response.body_digest(), EMPTY_BODY_DIGEST);
    request.write_response(&response);
    request.shutdown_write();
}

#[derive(Clone, Copy)]
enum HostExpectation {
    RecoveryPark,
    Admitted,
    CapacityStart,
    CapacityReplay,
    TerminalReplay,
}

#[allow(
    clippy::too_many_lines,
    reason = "the exact qualification and driver reconstruction is kept together for auditability"
)]
fn run_host(mut arguments: impl Iterator<Item = OsString>, expectation: HostExpectation) {
    let config_path = PathBuf::from(
        arguments
            .next()
            .unwrap_or_else(|| panic!("attester host config argument was missing")),
    );
    assert!(
        arguments.next().is_none(),
        "attester host received extra arguments"
    );
    let config = attester_load_config(&config_path);
    let authority = attester_read_authority();
    let packages = verify_package_set(&config.package_root)
        .unwrap_or_else(|_| panic!("attester host package verification failed"));
    let (provider_binding, _) = provider_bindings(&packages);
    let provider = qualify_provider(&packages, provider_binding, &config.native_parent)
        .unwrap_or_else(|_| panic!("attester host provider qualification failed"));
    let attester = qualify_attester(
        &packages,
        &packages.report().attester,
        &config.native_parent,
    )
    .unwrap_or_else(|_| panic!("attester host attester qualification failed"));
    let runtime = qualify_native_runtime(provider.lock(), attester.lock())
        .unwrap_or_else(|_| panic!("attester host runtime qualification failed"));
    let (baseline, admitted_intent) = observed_intent_baseline(&config.intent);
    let policy = candidate_policy(&attester);
    let plan_limits = planning_limits();
    let process_limits = process_limits();
    let invocation = link_invocation(
        &packages,
        provider_binding,
        &config.intent,
        admitted_intent,
        plan_limits,
    );
    let target_lock = TargetLock::new(&config.target_lock)
        .unwrap_or_else(|_| panic!("attester host target-lock reopen failed"));
    let target_guard = target_lock
        .acquire_execution(&config.target_binding)
        .unwrap_or_else(|_| panic!("attester host target execution fence failed"));
    let journal = AttemptJournal::new(&config.journal)
        .unwrap_or_else(|_| panic!("attester host journal open failed"));
    let session = journal
        .begin_session()
        .unwrap_or_else(|_| panic!("attester host attempt session failed"));
    let request = DriverRequest {
        packages: &packages,
        selected_provider: provider_binding,
        invocation: &invocation,
        baseline: &baseline,
        admission_policy: &policy,
        provider_artifact: &provider,
        attester_artifact: &attester,
        runtime: &runtime,
        target: &target_guard,
        authority: &authority,
        planning_limits: plan_limits,
        process_limits,
    };
    let progress = match expectation {
        HostExpectation::RecoveryPark | HostExpectation::CapacityStart => start(&session, &request),
        HostExpectation::CapacityReplay
        | HostExpectation::Admitted
        | HostExpectation::TerminalReplay => resume(&session, &request),
    }
    .unwrap_or_else(|_| panic!("attester host driver failed"));
    let checkpoint = match (expectation, progress) {
        (
            HostExpectation::RecoveryPark,
            DriverProgress::Parked {
                checkpoint,
                reason:
                    ParkReason::AttesterLaunch(SupervisorError::Qualification(
                        NativeQualificationError::PrivateCwdNotEmpty,
                    )),
            },
        ) => {
            assert_one_receipt_armed(&checkpoint);
            checkpoint
        }
        (
            HostExpectation::CapacityStart | HostExpectation::CapacityReplay,
            DriverProgress::Parked {
                checkpoint,
                reason: ParkReason::AttesterReceiptCapacity,
            },
        ) => {
            assert_capacity_armed(&checkpoint);
            checkpoint
        }
        (
            HostExpectation::Admitted | HostExpectation::TerminalReplay,
            DriverProgress::Terminal(checkpoint),
        ) => {
            assert_recovered_admitted(&checkpoint);
            checkpoint
        }
        _ => panic!("attester host returned an unexpected progress class"),
    };
    assert_receipt_correlations(
        &checkpoint,
        &attester,
        &runtime,
        process_limits.attester,
        &config.target_binding,
    );
}

fn assert_one_receipt_armed(checkpoint: &AttemptCheckpoint) {
    assert_common_armed(checkpoint);
    assert_eq!(checkpoint.attester_receipts().len(), 1);
    assert_eq!(
        checkpoint.recovery_action(),
        fleetd_direct_conversation_external_host_proof::journal::RecoveryAction::InspectAttesterPrefix {
            may_launch: true
        }
    );
    assert_operational_receipt(&decode_receipt(&checkpoint.attester_receipts()[0]));
}

fn assert_capacity_armed(checkpoint: &AttemptCheckpoint) {
    assert_common_armed(checkpoint);
    assert_eq!(checkpoint.attester_receipts().len(), 2);
    assert_eq!(
        checkpoint.attester_receipts()[0],
        checkpoint.attester_receipts()[1]
    );
    assert_eq!(
        checkpoint.recovery_action(),
        fleetd_direct_conversation_external_host_proof::journal::RecoveryAction::InspectAttesterPrefix {
            may_launch: false
        }
    );
    for retained in checkpoint.attester_receipts() {
        assert_operational_receipt(&decode_receipt(retained));
    }
}

fn assert_common_armed(checkpoint: &AttemptCheckpoint) {
    checkpoint
        .validate()
        .unwrap_or_else(|_| panic!("armed attester checkpoint was invalid"));
    assert_eq!(checkpoint.phase(), AttemptPhase::AttesterArmed);
    assert_eq!(checkpoint.provider_receipts().len(), 1);
    assert_eq!(
        checkpoint
            .provider_decisive()
            .unwrap_or_else(|| panic!("provider decisive reference was absent"))
            .index(),
        0
    );
    assert!(checkpoint.candidate().is_some());
    assert!(checkpoint.assessment_request().is_some());
    assert!(checkpoint.attester_decisive().is_none());
    assert!(checkpoint.assessment().is_none());
    assert!(checkpoint.resolution().is_none());
    assert!(
        checkpoint
            .provider_receipts()
            .iter()
            .all(|receipt| matches!(receipt, RetainedReceipt::Exact { .. }))
    );
    assert!(
        checkpoint
            .attester_receipts()
            .iter()
            .all(|receipt| matches!(receipt, RetainedReceipt::Exact { .. }))
    );
}

fn assert_recovered_admitted(checkpoint: &AttemptCheckpoint) {
    assert_admitted_receipts(checkpoint);
    assert_eq!(checkpoint.provider_receipts().len(), 1);
    assert_eq!(checkpoint.attester_receipts().len(), 2);
    let decisive = checkpoint
        .attester_decisive()
        .unwrap_or_else(|| panic!("recovered attester decisive reference was absent"));
    assert_eq!(decisive.index(), 1);
    assert_eq!(
        decisive.receipt_digest(),
        checkpoint.attester_receipts()[1].digest()
    );
    assert_operational_receipt(&decode_receipt(&checkpoint.attester_receipts()[0]));
    let decisive_receipt = decode_receipt(&checkpoint.attester_receipts()[1]);
    assert!(decisive_receipt.decisive_eligible());
    assert!(matches!(
        decisive_receipt.termination(),
        ProcessTermination::Exited { code: 0 }
    ));
    assert!(!decisive_receipt.stdout().bytes().is_empty());
    assert!(decisive_receipt.stderr().bytes().is_empty());
    assert_eq!(
        checkpoint.recovery_action(),
        fleetd_direct_conversation_external_host_proof::journal::RecoveryAction::ReplayTerminal
    );
}

fn assert_operational_receipt(receipt: &ProcessReceipt) {
    assert!(!receipt.decisive_eligible());
    assert!(matches!(
        receipt.termination(),
        ProcessTermination::Exited { code: 1 }
    ));
    assert!(receipt.stdout().bytes().is_empty());
    assert_eq!(receipt.stderr().bytes(), ATTESTER_FAILURE);
    for stream in [receipt.stdout(), receipt.stderr()] {
        assert!(!stream.overflowed());
        assert!(!stream.read_failed());
        assert!(!stream.redacted());
    }
    let enforcement = receipt.enforcement();
    assert!(!enforcement.timed_out());
    assert!(!enforcement.stdin_write_failed());
    assert!(!enforcement.authority_write_failed());
}

fn decode_receipt(retained: &RetainedReceipt) -> ProcessReceipt {
    let RetainedReceipt::Exact { receipt } = retained else {
        panic!("attester proof retained a redacted receipt");
    };
    let decoded = serde_json::from_value::<ProcessReceipt>(receipt.value().clone())
        .unwrap_or_else(|_| panic!("attester proof receipt decoding failed"));
    decoded
        .validate()
        .unwrap_or_else(|_| panic!("attester proof receipt validation failed"));
    decoded
}

fn assert_receipt_correlations(
    checkpoint: &AttemptCheckpoint,
    attester: &QualifiedNativeArtifact,
    runtime: &QualifiedNativeRuntime,
    limits: ProcessLimits,
    binding: &TargetBinding,
) {
    let request = checkpoint
        .assessment_request()
        .unwrap_or_else(|| panic!("attester assessment request was absent"));
    let stdin = serde_json_canonicalizer::to_vec(request.value())
        .unwrap_or_else(|_| panic!("attester assessment request canonicalization failed"));
    for retained in checkpoint.attester_receipts() {
        let receipt = decode_receipt(retained);
        assert_eq!(receipt.artifact_lock_id(), attester.lock().lock_id());
        assert_eq!(
            receipt.runtime_qualification_id(),
            runtime.qualification().qualification_id()
        );
        assert_eq!(
            receipt.input().stdin_bytes(),
            u64::try_from(stdin.len()).expect("assessment request size fits u64")
        );
        assert_eq!(receipt.input().stdin_digest(), sha256_identity(&stdin));
        assert_eq!(
            receipt.input().authority().target(),
            binding.deployment().fleetd_target().as_str()
        );
        assert_eq!(
            receipt.input().authority().endpoint_mapping_digest(),
            binding.deployment().endpoint_mapping_digest()
        );
        assert_eq!(
            receipt.input().authority().credential_revision(),
            binding.deployment().credential_revision()
        );
        let applied = receipt.limits();
        assert_eq!(
            applied.max_stdin_bytes(),
            u64::try_from(limits.max_stdin_bytes()).expect("stdin limit fits u64")
        );
        assert_eq!(
            applied.max_stdout_bytes(),
            u64::try_from(limits.max_stdout_bytes()).expect("stdout limit fits u64")
        );
        assert_eq!(
            applied.max_stderr_bytes(),
            u64::try_from(limits.max_stderr_bytes()).expect("stderr limit fits u64")
        );
        assert_eq!(
            applied.wall_time_ms(),
            u64::try_from(limits.wall_time().as_millis()).expect("wall-time limit fits u64")
        );
    }
}

fn attester_load_checkpoint(path: &Path) -> AttemptCheckpoint {
    let journal = AttemptJournal::new(path)
        .unwrap_or_else(|_| panic!("attester checkpoint journal open failed"));
    let session = journal
        .begin_session()
        .unwrap_or_else(|_| panic!("attester checkpoint session failed"));
    let checkpoint = session
        .load()
        .unwrap_or_else(|_| panic!("attester checkpoint load failed"));
    checkpoint
        .validate()
        .unwrap_or_else(|_| panic!("attester checkpoint validation failed"));
    checkpoint
}

fn poison_attester_cwd(native_parent: &Path, expected_digest: &str) {
    let parent = File::from(
        open(
            native_parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap_or_else(|_| panic!("attester fault parent open failed")),
    );
    let mut entries = Dir::read_from(&parent)
        .unwrap_or_else(|_| panic!("attester fault parent enumeration failed"));
    let mut materializations = 0_u8;
    let mut poisoned = 0_u8;
    for entry in &mut entries {
        let entry = entry.unwrap_or_else(|_| panic!("attester fault parent entry failed"));
        if matches!(entry.file_name().to_bytes(), b"." | b"..") {
            continue;
        }
        assert!(
            entry
                .file_name()
                .to_bytes()
                .starts_with(b".fleetd-direct-conversation-native-"),
            "native parent contained an unexpected entry"
        );
        materializations = materializations
            .checked_add(1)
            .unwrap_or_else(|| panic!("native materialization count overflowed"));
        let root = File::from(
            openat(
                &parent,
                entry.file_name(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap_or_else(|_| panic!("native materialization root open failed")),
        );
        attester_validate_descriptor_directory(&root, "native materialization root");
        let artifact = File::from(
            openat(
                &root,
                "artifact",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .unwrap_or_else(|_| panic!("native materialized artifact open failed")),
        );
        let metadata = artifact
            .metadata()
            .unwrap_or_else(|_| panic!("native materialized artifact inspection failed"));
        assert!(
            metadata.is_file()
                && metadata.uid() == geteuid().as_raw()
                && metadata.nlink() == 1
                && metadata.mode() & 0o777 == 0o500
                && metadata.len() > 0
                && metadata.len()
                    <= u64::try_from(MAX_NATIVE_ARTIFACT_BYTES)
                        .expect("native artifact bound fits u64"),
            "native materialized artifact metadata was invalid"
        );
        if descriptor_digest(&artifact, metadata.len(), MAX_NATIVE_ARTIFACT_BYTES)
            != expected_digest
        {
            continue;
        }
        poisoned = poisoned
            .checked_add(1)
            .unwrap_or_else(|| panic!("attester fault count overflowed"));
        let cwd = File::from(
            openat(
                &root,
                "cwd",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap_or_else(|_| panic!("attester private cwd open failed")),
        );
        attester_validate_descriptor_directory(&cwd, "attester private cwd");
        let mut marker = File::from(
            openat(
                &cwd,
                "recovery-fault",
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap_or_else(|_| panic!("attester private cwd fault creation failed")),
        );
        marker
            .write_all(b"fixed-attester-recovery-fault\n")
            .unwrap_or_else(|_| panic!("attester private cwd fault write failed"));
        marker
            .sync_all()
            .unwrap_or_else(|_| panic!("attester private cwd fault sync failed"));
        cwd.sync_all()
            .unwrap_or_else(|_| panic!("attester private cwd sync failed"));
        root.sync_all()
            .unwrap_or_else(|_| panic!("attester private root sync failed"));
    }
    assert_eq!(materializations, 2, "expected provider and attester roots");
    assert_eq!(poisoned, 1, "exactly one attester cwd must be faulted");
}

fn attester_private_directory(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    fs::create_dir(&path).unwrap_or_else(|_| panic!("attester private directory creation failed"));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|_| panic!("attester private directory permission failed"));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .unwrap_or_else(|_| panic!("attester private parent sync failed"));
    let canonical = path
        .canonicalize()
        .unwrap_or_else(|_| panic!("attester private directory canonicalization failed"));
    attester_validate_private_directory(&canonical, "attester private directory");
    canonical
}

fn attester_validate_private_directory(path: &Path, surface: &str) {
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

fn attester_validate_descriptor_directory(directory: &File, surface: &str) {
    let metadata = directory
        .metadata()
        .unwrap_or_else(|_| panic!("{surface} descriptor inspection failed"));
    assert!(
        metadata.is_dir()
            && metadata.uid() == geteuid().as_raw()
            && metadata.mode() & 0o777 == 0o700,
        "{surface} descriptor metadata was invalid"
    );
}

fn attester_spawn_mode(mode: &str, argument: &Path) -> (ManagedChild, ChildStdin) {
    assert!(argument.is_absolute());
    let executable = env::current_exe()
        .unwrap_or_else(|_| panic!("attester-proof process executable could not be located"));
    let raw_child = Command::new(executable)
        .env_clear()
        .arg(mode)
        .arg(argument)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|_| panic!("attester-proof child process failed to execute"));
    let mut child = ManagedChild::new(raw_child);
    let input = child
        .child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("attester-proof child input pipe was unavailable"));
    (child, input)
}

fn attester_wait_managed(
    child: &mut ManagedChild,
    duration: Duration,
    surface: &str,
) -> ExitStatus {
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
        thread::sleep(Duration::from_millis(10));
    }
}

fn attester_write_canonical_pipe(writer: &mut ChildStdin, value: &impl Serialize) {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .unwrap_or_else(|_| panic!("attester-proof control canonicalization failed"));
    assert!(bytes.len() <= MAX_CONTROL_BYTES);
    attester_write_pipe(writer, &bytes, "attester-proof control");
}

fn attester_write_pipe(writer: &mut ChildStdin, bytes: &[u8], surface: &str) {
    writer
        .write_all(bytes)
        .unwrap_or_else(|_| panic!("{surface} pipe write failed"));
    writer
        .flush()
        .unwrap_or_else(|_| panic!("{surface} pipe flush failed"));
}

fn attester_read_canonical_stdin<T>(bound: usize, surface: &str) -> T
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let mut input = std::io::stdin().lock();
    let bytes = attester_read_bounded(&mut input, bound, surface);
    drop(input);
    let value: T =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("{surface} decoding failed"));
    assert_eq!(
        serde_json_canonicalizer::to_vec(&value)
            .unwrap_or_else(|_| panic!("{surface} canonicalization failed")),
        bytes,
        "{surface} was not canonical"
    );
    value
}

fn attester_read_authority() -> AuthorityDocument {
    let mut input = std::io::stdin().lock();
    let bytes = attester_read_bounded(
        &mut input,
        MAX_AUTHORITY_DOCUMENT_BYTES,
        "attester host authority",
    );
    drop(input);
    parse_authority_document(&bytes)
        .unwrap_or_else(|_| panic!("attester host authority decoding failed"))
}

fn attester_read_bounded(reader: &mut impl Read, bound: usize, surface: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    reader
        .take(u64::try_from(bound + 1).expect("proof byte bound fits u64"))
        .read_to_end(&mut bytes)
        .unwrap_or_else(|_| panic!("{surface} read failed"));
    assert!(bytes.len() <= bound, "{surface} exceeded its byte bound");
    bytes
}

fn attester_persist_canonical(path: &Path, value: &impl Serialize) {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .unwrap_or_else(|_| panic!("attester-proof document canonicalization failed"));
    assert!(bytes.len() <= MAX_CONFIG_BYTES);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|_| panic!("attester-proof document creation failed"));
    file.write_all(&bytes)
        .unwrap_or_else(|_| panic!("attester-proof document write failed"));
    file.sync_all()
        .unwrap_or_else(|_| panic!("attester-proof document sync failed"));
    File::open(
        path.parent()
            .unwrap_or_else(|| panic!("attester-proof document lacked a parent")),
    )
    .and_then(|directory| directory.sync_all())
    .unwrap_or_else(|_| panic!("attester-proof directory sync failed"));
}

fn attester_wait_for_canonical<T>(path: &Path) -> T
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let deadline = Instant::now() + PROCESS_DEADLINE;
    loop {
        match fs::read(path) {
            Ok(bytes) => {
                assert!(bytes.len() <= MAX_CONFIG_BYTES);
                let value: T = serde_json::from_slice(&bytes)
                    .unwrap_or_else(|_| panic!("attester status decoding failed"));
                assert_eq!(
                    serde_json_canonicalizer::to_vec(&value)
                        .unwrap_or_else(|_| panic!("attester status canonicalization failed")),
                    bytes,
                    "attester status was not canonical"
                );
                return value;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                assert!(
                    Instant::now() < deadline,
                    "attester status deadline expired"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("attester status read failed: {:?}", error.kind()),
        }
    }
}

fn attester_load_config(path: &Path) -> AttesterConfig {
    assert!(path.is_absolute(), "attester config path must be absolute");
    let metadata =
        fs::symlink_metadata(path).unwrap_or_else(|_| panic!("attester config inspection failed"));
    assert!(
        metadata.file_type().is_file()
            && metadata.uid() == geteuid().as_raw()
            && metadata.mode() & 0o777 == 0o600,
        "attester config metadata was invalid"
    );
    let mut file = File::open(path).unwrap_or_else(|_| panic!("attester config open failed"));
    let bytes = attester_read_bounded(&mut file, MAX_CONFIG_BYTES, "attester config");
    let config: AttesterConfig = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("attester config decoding failed"));
    assert_eq!(
        serde_json_canonicalizer::to_vec(&config)
            .unwrap_or_else(|_| panic!("attester config canonicalization failed")),
        bytes,
        "attester config was not canonical"
    );
    config.validate();
    config
}

fn attester_create_marker(path: &Path) {
    assert!(path.is_absolute());
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|_| panic!("capacity completion marker creation failed"));
    marker
        .write_all(b"complete\n")
        .unwrap_or_else(|_| panic!("capacity completion marker write failed"));
    marker
        .sync_all()
        .unwrap_or_else(|_| panic!("capacity completion marker sync failed"));
    File::open(
        path.parent()
            .unwrap_or_else(|| panic!("capacity completion marker lacked a parent")),
    )
    .and_then(|directory| directory.sync_all())
    .unwrap_or_else(|_| panic!("capacity completion parent sync failed"));
}

fn attester_wait_for_marker(path: &Path) {
    let deadline = Instant::now() + PROCESS_DEADLINE;
    loop {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                assert!(
                    metadata.file_type().is_file()
                        && metadata.uid() == geteuid().as_raw()
                        && metadata.mode() & 0o777 == 0o600,
                    "capacity completion marker metadata was invalid"
                );
                return;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                assert!(
                    Instant::now() < deadline,
                    "capacity completion marker deadline expired"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("capacity completion marker failed: {:?}", error.kind()),
        }
    }
}
