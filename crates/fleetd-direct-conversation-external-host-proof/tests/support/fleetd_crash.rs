//! Process-separated bounded crash/reexec proof support.

#[allow(
    clippy::wildcard_imports,
    reason = "the proof is a private child of the accepted real-proof fixture and reuses its exact boundary"
)]
use super::*;

use super::http::{HTTP_IO_DEADLINE, HttpRequest, HttpResponse, accept_request, forward_request};

use fleetd_direct_conversation_command_abi::{
    MAX_AUTHORITY_DOCUMENT_BYTES, parse_authority_document,
};
use fleetd_direct_conversation_external_host_proof::driver::DriverError;
use fleetd_direct_conversation_external_host_proof::target::TargetBinding;
use serde::{Deserialize, Serialize};
use std::os::unix::process::ExitStatusExt;

const CRASH_CONFIG_PROTOCOL: &str = "org.gooi.proof/fleetd-crash-config@0.2.0";
const PROXY_CONTROL_PROTOCOL: &str = "org.gooi.proof/fleetd-crash-proxy-control@0.2.0";
const PROXY_READY_PROTOCOL: &str = "org.gooi.proof/fleetd-crash-proxy-ready@0.1.0";
const PROXY_OBSERVATION_PROTOCOL: &str = "org.gooi.proof/fleetd-crash-proxy-observation@0.2.0";
const MAX_PROXY_CONTROL_BYTES: usize = 4 * 1024;
const PROXY_IO_DEADLINE: Duration = HTTP_IO_DEADLINE;
const MAX_CRASH_CONFIG_BYTES: usize = 256 * 1024;
const MISMATCH_DEADLINE: Duration = Duration::from_secs(45);
const MATRIX_BARRIER_DEADLINE: Duration = Duration::from_mins(6);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyControl {
    protocol: String,
    backend: SocketAddr,
    first_host_pid: u32,
    mismatch_completion_marker: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyReady {
    protocol: String,
    address: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyObservation {
    status: u16,
    body_bytes: u64,
    body_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyBodyDigest {
    body_bytes: u64,
    body_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyCommitObservation {
    request: ProxyBodyDigest,
    response: ProxyObservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyMismatchObservation {
    protocol: String,
    requests_before_legitimate_resume: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyTerminal {
    protocol: String,
    first_request: ProxyBodyDigest,
    replay_request: ProxyBodyDigest,
    first: ProxyObservation,
    replay: ProxyObservation,
    attestation: ProxyObservation,
    first_provider_disappeared: bool,
    requests_before_legitimate_resume: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CrashConfig {
    protocol: String,
    package_root: PathBuf,
    native_parent: PathBuf,
    journal: PathBuf,
    target_lock: PathBuf,
    target_binding: TargetBinding,
    alternate_target_lock: PathBuf,
    alternate_target_binding: TargetBinding,
    alternate_credential_lock: PathBuf,
    alternate_credential_binding: TargetBinding,
    intent: DirectPairIntent,
    alternate_intent: DirectPairIntent,
}

impl CrashConfig {
    fn validate(&self) {
        assert_eq!(self.protocol, CRASH_CONFIG_PROTOCOL);
        for path in [
            &self.package_root,
            &self.native_parent,
            &self.journal,
            &self.target_lock,
            &self.alternate_target_lock,
            &self.alternate_credential_lock,
        ] {
            assert!(path.is_absolute(), "crash config paths must be absolute");
        }
        self.target_binding
            .validate()
            .unwrap_or_else(|_| panic!("crash config target binding was invalid"));
        self.alternate_target_binding
            .validate()
            .unwrap_or_else(|_| panic!("crash config alternate target binding was invalid"));
        self.alternate_credential_binding
            .validate()
            .unwrap_or_else(|_| panic!("crash config alternate credential binding was invalid"));
        assert_eq!(
            self.intent.fleetd_target(),
            self.target_binding.deployment().fleetd_target(),
            "crash config intent and deployment targets differed"
        );
        assert_eq!(
            self.alternate_intent.fleetd_target(),
            self.target_binding.deployment().fleetd_target(),
            "crash config alternate intent target differed"
        );
        assert_ne!(self.alternate_intent, self.intent);
        let primary = self.target_binding.deployment();
        let alternate_target = self.alternate_target_binding.deployment();
        let alternate_credential = self.alternate_credential_binding.deployment();
        assert_eq!(alternate_target.fleetd_target(), primary.fleetd_target());
        assert_ne!(
            alternate_target.endpoint_mapping_digest(),
            primary.endpoint_mapping_digest()
        );
        assert_eq!(
            alternate_target.credential_revision(),
            primary.credential_revision()
        );
        assert_eq!(
            alternate_credential.fleetd_target(),
            primary.fleetd_target()
        );
        assert_eq!(
            alternate_credential.endpoint_mapping_digest(),
            primary.endpoint_mapping_digest()
        );
        assert_ne!(
            alternate_credential.credential_revision(),
            primary.credential_revision()
        );
    }
}

#[derive(Clone, Copy)]
enum HostMode {
    Start,
    Resume,
    Terminal,
    Mismatch(MismatchKind),
}

#[derive(Clone, Copy)]
enum MismatchKind {
    SelectedProvider,
    ProviderArtifact,
    RuntimeQualification,
    TargetDeployment,
    CredentialRevision,
    InvocationIntent,
    ExecutionPolicy,
}

/// Dispatch one credential-owning coordinator, proof host, proxy, or log pump.
pub(crate) fn dispatch() {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    match arguments.next().as_deref() {
        None => run_coordinator(),
        Some(mode) if mode == std::ffi::OsStr::new("--log-pump") => run_log_pump(arguments),
        Some(mode) if mode == std::ffi::OsStr::new("--proxy") => run_proxy(arguments),
        Some(mode) if mode == std::ffi::OsStr::new("--host-start") => {
            run_host(arguments, HostMode::Start);
        }
        Some(mode) if mode == std::ffi::OsStr::new("--host-resume") => {
            run_host(arguments, HostMode::Resume);
        }
        Some(mode) if mode == std::ffi::OsStr::new("--host-terminal") => {
            run_host(arguments, HostMode::Terminal);
        }
        Some(mode) if mode == std::ffi::OsStr::new("--host-mismatch-selected-provider") => {
            run_host(
                arguments,
                HostMode::Mismatch(MismatchKind::SelectedProvider),
            );
        }
        Some(mode) if mode == std::ffi::OsStr::new("--host-mismatch-provider-artifact") => {
            run_host(
                arguments,
                HostMode::Mismatch(MismatchKind::ProviderArtifact),
            );
        }
        Some(mode) if mode == std::ffi::OsStr::new("--host-mismatch-runtime") => {
            run_host(
                arguments,
                HostMode::Mismatch(MismatchKind::RuntimeQualification),
            );
        }
        Some(mode) if mode == std::ffi::OsStr::new("--host-mismatch-target") => {
            run_host(
                arguments,
                HostMode::Mismatch(MismatchKind::TargetDeployment),
            );
        }
        Some(mode) if mode == std::ffi::OsStr::new("--host-mismatch-credential") => {
            run_host(
                arguments,
                HostMode::Mismatch(MismatchKind::CredentialRevision),
            );
        }
        Some(mode) if mode == std::ffi::OsStr::new("--host-mismatch-intent") => {
            run_host(
                arguments,
                HostMode::Mismatch(MismatchKind::InvocationIntent),
            );
        }
        Some(mode) if mode == std::ffi::OsStr::new("--host-mismatch-execution-policy") => {
            run_host(arguments, HostMode::Mismatch(MismatchKind::ExecutionPolicy));
        }
        Some(_) => panic!("unknown crash-proof process mode"),
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
    let root = private_tempdir("gooir-crash-proof-");
    let package_root = root.path().join("packages");
    stage(StageRequest {
        reqwest_command: external.reqwest_binary,
        ureq_command: external.ureq_binary,
        attester_command: external.attester_binary,
        output_root: package_root.clone(),
    })
    .unwrap_or_else(|_| panic!("crash coordinator could not stage exact release packages"));
    let packages = verify_package_set(&package_root)
        .unwrap_or_else(|_| panic!("crash coordinator could not verify exact release packages"));
    let (reqwest_binding, _ureq_binding) = provider_bindings(&packages);
    assert_eq!(reqwest_binding.package.as_str(), REQWEST_PACKAGE);

    let database = root.path().join("fleetd.db");
    let token_file = root.path().join("operator.token");
    let mut daemon = FleetdDaemon::spawn(&fleetd, root.path(), &database, &token_file, None);
    let backend = daemon.address();
    let backend_endpoint = daemon.endpoint();
    let operator_bearer = SecretCanary(read_operator_token(&token_file));
    let client = public_client();
    let AgentRegistration {
        id: agent_a,
        bearer: inbox_bearer,
    } = create_agent(
        &client,
        &backend_endpoint,
        operator_bearer.as_str(),
        "crash-proof-agent-a",
    );
    let AgentRegistration {
        id: agent_b,
        bearer: stream_bearer,
    } = create_agent(
        &client,
        &backend_endpoint,
        operator_bearer.as_str(),
        "crash-proof-agent-b",
    );
    assert_no_public_conversations(&client, &backend_endpoint, operator_bearer.as_str());
    drop(client);

    let proxy_root = create_private_directory(root.path(), "proxy");
    let (mut proxy, mut proxy_control) = spawn_mode("--proxy", &proxy_root);
    let ready: ProxyReady = wait_for_canonical(&proxy_root.join("ready.json"));
    assert_eq!(ready.protocol, PROXY_READY_PROTOCOL);
    assert!(ready.address.ip().is_loopback());
    let proxy_endpoint = format!("http://{}/", ready.address);

    let target = FleetdTarget::parse(format!(
        "fleetd:proof:{:x}",
        Sha256::digest(format!("{}:commit-before-response", root.path().display()).as_bytes())
    ))
    .unwrap_or_else(|_| panic!("crash coordinator target construction failed"));
    let data_identity = persist_marker(
        root.path(),
        "data-directory.identity.json",
        &json!({
            "protocol": "org.gooi.proof/fleetd-data-directory-identity@0.1.0",
            "fleetd_target": target.as_str(),
            "marker": fresh_marker(root.path(), "crash-data")
        }),
    );
    let credential_revision = persist_marker(
        root.path(),
        "credential-generation.identity.json",
        &json!({
            "protocol": "org.gooi.proof/fleetd-credential-generation@0.1.0",
            "fleetd_target": target.as_str(),
            "marker": fresh_marker(root.path(), "crash-credential")
        }),
    );
    let mapping_digest = digest_document(&json!({
        "protocol": "org.gooi.proof/fleetd-endpoint-mapping@0.1.0",
        "fleetd_target": target.as_str(),
        "endpoint": proxy_endpoint
    }));
    let alternate_mapping_digest = digest_document(&json!({
        "protocol": "org.gooi.proof/fleetd-endpoint-mapping@0.1.0",
        "fleetd_target": target.as_str(),
        "endpoint": proxy_endpoint,
        "proof_variant": "mismatched-target-deployment"
    }));
    assert_ne!(alternate_mapping_digest, mapping_digest);
    let alternate_credential_revision = persist_marker(
        root.path(),
        "alternate-credential-generation.identity.json",
        &json!({
            "protocol": "org.gooi.proof/fleetd-credential-generation@0.1.0",
            "fleetd_target": target.as_str(),
            "marker": fresh_marker(root.path(), "crash-alternate-credential")
        }),
    );
    assert_ne!(alternate_credential_revision, credential_revision);
    let target_lock_path = root.path().join("target-lock");
    let target_lock = TargetLock::new(&target_lock_path)
        .unwrap_or_else(|_| panic!("crash coordinator could not create target lock"));
    let target_binding = target_lock
        .configure(
            TargetDeployment::new(
                target.clone(),
                fleetd.digest(),
                &revision,
                &openapi_digest,
                data_identity.clone(),
                mapping_digest.clone(),
                credential_revision.clone(),
            )
            .unwrap_or_else(|_| panic!("crash coordinator target deployment was invalid")),
        )
        .unwrap_or_else(|_| panic!("crash coordinator could not publish target deployment"));
    let alternate_target_lock_path = root.path().join("alternate-target-lock");
    let alternate_target_lock = TargetLock::new(&alternate_target_lock_path)
        .unwrap_or_else(|_| panic!("crash coordinator could not create alternate target lock"));
    let alternate_target_binding = alternate_target_lock
        .configure(
            TargetDeployment::new(
                target.clone(),
                fleetd.digest(),
                &revision,
                &openapi_digest,
                data_identity.clone(),
                alternate_mapping_digest.clone(),
                credential_revision.clone(),
            )
            .unwrap_or_else(|_| panic!("crash coordinator alternate target was invalid")),
        )
        .unwrap_or_else(|_| panic!("crash coordinator alternate target publish failed"));
    let alternate_credential_lock_path = root.path().join("alternate-credential-lock");
    let alternate_credential_lock = TargetLock::new(&alternate_credential_lock_path)
        .unwrap_or_else(|_| panic!("crash coordinator could not create credential target lock"));
    let alternate_credential_binding = alternate_credential_lock
        .configure(
            TargetDeployment::new(
                target.clone(),
                fleetd.digest(),
                &revision,
                &openapi_digest,
                data_identity,
                mapping_digest.clone(),
                alternate_credential_revision.clone(),
            )
            .unwrap_or_else(|_| panic!("crash coordinator alternate credential was invalid")),
        )
        .unwrap_or_else(|_| panic!("crash coordinator alternate credential publish failed"));
    let authority = AuthorityDocument::new(
        target.as_str(),
        mapping_digest.clone(),
        credential_revision.clone(),
        &proxy_endpoint,
        operator_bearer.as_str(),
        5_000,
        u64::try_from(MAX_RESPONSE_BYTES).expect("response bound fits u64"),
    )
    .unwrap_or_else(|_| panic!("crash coordinator live authority was invalid"));
    let authority_bytes = authority
        .encode_for_pipe()
        .unwrap_or_else(|_| panic!("crash coordinator authority encoding failed"));
    let alternate_target_authority_bytes = AuthorityDocument::new(
        target.as_str(),
        alternate_mapping_digest,
        credential_revision,
        &proxy_endpoint,
        operator_bearer.as_str(),
        5_000,
        u64::try_from(MAX_RESPONSE_BYTES).expect("response bound fits u64"),
    )
    .unwrap_or_else(|_| panic!("crash coordinator alternate target authority was invalid"))
    .encode_for_pipe()
    .unwrap_or_else(|_| panic!("crash coordinator alternate target authority encoding failed"));
    let alternate_credential_authority_bytes = AuthorityDocument::new(
        target.as_str(),
        mapping_digest,
        alternate_credential_revision,
        &proxy_endpoint,
        operator_bearer.as_str(),
        5_000,
        u64::try_from(MAX_RESPONSE_BYTES).expect("response bound fits u64"),
    )
    .unwrap_or_else(|_| panic!("crash coordinator alternate credential authority was invalid"))
    .encode_for_pipe()
    .unwrap_or_else(|_| panic!("crash coordinator alternate credential authority encoding failed"));
    let intent = DirectPairIntent::new(
        target.clone(),
        [
            DirectMember::new(agent_a.clone(), DeliveryMode::Inbox),
            DirectMember::new(agent_b.clone(), DeliveryMode::StreamOnly),
        ],
    )
    .unwrap_or_else(|_| panic!("crash coordinator direct-pair intent was invalid"));
    let alternate_intent = DirectPairIntent::new(
        target,
        [
            DirectMember::new(agent_a, DeliveryMode::StreamOnly),
            DirectMember::new(agent_b, DeliveryMode::Inbox),
        ],
    )
    .unwrap_or_else(|_| panic!("crash coordinator alternate intent was invalid"));
    assert_ne!(alternate_intent, intent);
    let native_parent = create_private_directory(root.path(), "native");
    let journal_path = root.path().join("attempt");
    let config_path = root.path().join("crash-config.json");
    let mismatch_completion_marker = proxy_root.join("mismatch-complete");
    persist_canonical(
        &config_path,
        &CrashConfig {
            protocol: CRASH_CONFIG_PROTOCOL.to_owned(),
            package_root,
            native_parent,
            journal: journal_path.clone(),
            target_lock: target_lock_path,
            target_binding,
            alternate_target_lock: alternate_target_lock_path,
            alternate_target_binding,
            alternate_credential_lock: alternate_credential_lock_path,
            alternate_credential_binding,
            intent,
            alternate_intent,
        },
    );

    let (mut first_host, mut first_authority) = spawn_mode("--host-start", &config_path);
    write_canonical_pipe(
        &mut proxy_control,
        &ProxyControl {
            protocol: PROXY_CONTROL_PROTOCOL.to_owned(),
            backend,
            first_host_pid: first_host.id(),
            mismatch_completion_marker: mismatch_completion_marker.clone(),
        },
    );
    drop(proxy_control);
    write_pipe_bytes(
        &mut first_authority,
        &authority_bytes,
        "first host authority",
    );
    drop(first_authority);
    let first_status = wait_managed(&mut first_host, Duration::from_secs(30), "first proof host");
    assert_eq!(first_status.signal(), Some(libc::SIGKILL));
    let first_observation: ProxyCommitObservation =
        wait_for_canonical(&proxy_root.join("first-response.json"));
    assert_eq!(first_observation.response.status, 201);

    let journal = AttemptJournal::new(&journal_path)
        .unwrap_or_else(|_| panic!("crash coordinator could not reopen armed journal"));
    let armed = {
        let session = journal
            .begin_session()
            .unwrap_or_else(|_| panic!("crash coordinator could not inspect armed journal"));
        session
            .load()
            .unwrap_or_else(|_| panic!("crash coordinator could not load armed journal"))
    };
    armed
        .validate()
        .unwrap_or_else(|_| panic!("crash coordinator armed checkpoint was invalid"));
    assert_eq!(armed.phase(), AttemptPhase::ProviderArmed);
    assert!(armed.provider_receipts().is_empty());
    assert!(armed.provider_decisive().is_none());
    assert!(armed.resolution().is_none());
    let armed_bytes = canonical_checkpoint(&armed);

    // Public package/native types expose only exact verified bindings. The
    // provider-artifact case therefore substitutes the complete Ureq artifact
    // for the selected Reqwest binding, jointly proving implementation,
    // package, package-digest, resource, and resource-digest lock refusal.
    // No public request field can vary either replay law: they are trusted
    // driver constants and private, content-identified AttemptInputs fields.
    // Existing journal corruption/content-identity/CAS tests cover durable
    // replay-law tampering, so this real proof does not add a bypass hook.
    for (mode, authority) in [
        (
            "--host-mismatch-selected-provider",
            authority_bytes.as_slice(),
        ),
        (
            "--host-mismatch-provider-artifact",
            authority_bytes.as_slice(),
        ),
        ("--host-mismatch-runtime", authority_bytes.as_slice()),
        (
            "--host-mismatch-target",
            alternate_target_authority_bytes.as_slice(),
        ),
        (
            "--host-mismatch-credential",
            alternate_credential_authority_bytes.as_slice(),
        ),
        ("--host-mismatch-intent", authority_bytes.as_slice()),
        (
            "--host-mismatch-execution-policy",
            authority_bytes.as_slice(),
        ),
    ] {
        run_mismatch_host(mode, &config_path, authority);
        let unchanged = {
            let session = journal.begin_session().unwrap_or_else(|_| {
                panic!("crash coordinator could not inspect mismatch checkpoint")
            });
            session
                .load()
                .unwrap_or_else(|_| panic!("crash coordinator mismatch checkpoint load failed"))
        };
        assert_eq!(canonical_checkpoint(&unchanged), armed_bytes);
        assert_eq!(unchanged.phase(), AttemptPhase::ProviderArmed);
        assert!(unchanged.provider_receipts().is_empty());
    }
    create_completion_marker(&mismatch_completion_marker);
    let mismatch_observation: ProxyMismatchObservation =
        wait_for_canonical(&proxy_root.join("mismatch-verified.json"));
    assert_eq!(mismatch_observation.protocol, PROXY_OBSERVATION_PROTOCOL);
    assert_eq!(mismatch_observation.requests_before_legitimate_resume, 0);

    let (mut resume_host, mut resume_authority) = spawn_mode("--host-resume", &config_path);
    write_pipe_bytes(
        &mut resume_authority,
        &authority_bytes,
        "resume host authority",
    );
    drop(resume_authority);
    let resume_status = wait_managed(
        &mut resume_host,
        Duration::from_secs(45),
        "resume proof host",
    );
    assert!(resume_status.success());
    let proxy_status = wait_managed(&mut proxy, Duration::from_secs(15), "crash proxy");
    assert!(proxy_status.success());
    let proxy_terminal: ProxyTerminal = wait_for_canonical(&proxy_root.join("terminal.json"));
    assert_eq!(proxy_terminal.protocol, PROXY_OBSERVATION_PROTOCOL);
    assert_eq!(proxy_terminal.first, first_observation.response);
    assert_eq!(proxy_terminal.first_request, first_observation.request);
    assert_eq!(proxy_terminal.first_request, proxy_terminal.replay_request);
    assert_eq!(proxy_terminal.first.status, 201);
    assert_eq!(proxy_terminal.replay.status, 200);
    assert_eq!(proxy_terminal.attestation.status, 200);
    assert_eq!(proxy_terminal.requests_before_legitimate_resume, 0);
    assert_eq!(
        proxy_terminal.first.body_digest,
        proxy_terminal.replay.body_digest
    );
    assert!(proxy_terminal.first_provider_disappeared);

    let terminal_checkpoint = {
        let session = journal
            .begin_session()
            .unwrap_or_else(|_| panic!("crash coordinator could not inspect terminal journal"));
        session
            .load()
            .unwrap_or_else(|_| panic!("crash coordinator could not load terminal journal"))
    };
    assert_admitted_receipts(&terminal_checkpoint);
    assert_eq!(terminal_checkpoint.provider_receipts().len(), 1);
    let snapshot = admitted_snapshot(&terminal_checkpoint);
    let fact = conversation_fact(&snapshot);
    let reference = DirectConversationRef::from_fact(&fact)
        .unwrap_or_else(|_| panic!("crash proof output was not a conversation reference"));
    assert_public_conversation(
        &public_client(),
        &backend_endpoint,
        operator_bearer.as_str(),
        &reference,
    );

    let terminal_bytes = canonical_checkpoint(&terminal_checkpoint);
    let logs = daemon.stop();
    let (mut terminal_host, mut terminal_authority) = spawn_mode("--host-terminal", &config_path);
    write_pipe_bytes(
        &mut terminal_authority,
        &authority_bytes,
        "terminal host authority",
    );
    drop(terminal_authority);
    let terminal_status = wait_managed(
        &mut terminal_host,
        Duration::from_secs(30),
        "terminal replay host",
    );
    assert!(terminal_status.success());
    let terminal_replay = {
        let session = journal
            .begin_session()
            .unwrap_or_else(|_| panic!("crash coordinator could not inspect terminal replay"));
        session
            .load()
            .unwrap_or_else(|_| panic!("crash coordinator could not load terminal replay"))
    };
    assert_eq!(canonical_checkpoint(&terminal_replay), terminal_bytes);

    let journal_bytes = read_tree(journal.directory_path());
    let config_bytes = fs::read(&config_path)
        .unwrap_or_else(|_| panic!("crash coordinator config audit read failed"));
    let proxy_diagnostics = read_tree(&proxy_root);
    for surface in [&journal_bytes, &config_bytes, &proxy_diagnostics] {
        for endpoint in [&backend_endpoint, &proxy_endpoint] {
            for authority in [
                authority_bytes.as_slice(),
                alternate_target_authority_bytes.as_slice(),
                alternate_credential_authority_bytes.as_slice(),
            ] {
                assert_journal_canaries_absent(
                    surface,
                    endpoint,
                    operator_bearer.as_str(),
                    authority,
                    &[&inbox_bearer, &stream_bearer],
                );
            }
        }
    }
    for authority in [
        authority_bytes.as_slice(),
        alternate_target_authority_bytes.as_slice(),
        alternate_credential_authority_bytes.as_slice(),
    ] {
        assert_log_canaries_absent(
            &logs,
            &backend_endpoint,
            operator_bearer.as_str(),
            authority,
            &[&inbox_bearer, &stream_bearer],
        );
    }
    for spelling in endpoint_spellings(&proxy_endpoint) {
        assert!(!contains_bytes(&logs, &spelling));
    }
    assert_eq!(clean_revision(&external.fleetd_repo), revision);
}

#[allow(
    clippy::too_many_lines,
    reason = "the crash-proxy commit, barrier, replay, and attestation sequence is intentionally linear"
)]
fn run_proxy(mut arguments: impl Iterator<Item = OsString>) {
    let root = PathBuf::from(
        arguments
            .next()
            .unwrap_or_else(|| panic!("proxy root argument was missing")),
    );
    assert!(arguments.next().is_none(), "proxy received extra arguments");
    validate_private_directory(&root, "proxy root");
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|_| panic!("crash proxy loopback bind failed"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|_| panic!("crash proxy address inspection failed"));
    assert!(address.ip().is_loopback());
    persist_canonical(
        &root.join("ready.json"),
        &ProxyReady {
            protocol: PROXY_READY_PROTOCOL.to_owned(),
            address,
        },
    );

    let control: ProxyControl = read_canonical_stdin(MAX_PROXY_CONTROL_BYTES, "proxy control");
    assert_eq!(control.protocol, PROXY_CONTROL_PROTOCOL);
    assert!(control.backend.ip().is_loopback());
    assert_ne!(control.first_host_pid, 0);
    assert!(control.mismatch_completion_marker.is_absolute());
    assert_eq!(
        control.mismatch_completion_marker.parent(),
        Some(root.as_path())
    );

    let (first_request, first_response) = proxy_exchange(&listener, control.backend);
    assert_eq!(first_request.http.method(), "POST");
    assert_eq!(first_request.http.target(), "/v1/direct-conversations");
    assert_eq!(first_response.http.status(), 201);
    let first_request_digest = first_request.body_digest();
    let first = first_response.observation();
    persist_canonical(
        &root.join("first-response.json"),
        &ProxyCommitObservation {
            request: first_request_digest.clone(),
            response: first.clone(),
        },
    );

    let provider_pid = direct_child_pid(control.first_host_pid);
    let host_pid = i32::try_from(control.first_host_pid)
        .ok()
        .and_then(Pid::from_raw)
        .unwrap_or_else(|| panic!("first proof-host PID was invalid"));
    kill_process(host_pid, Signal::KILL)
        .unwrap_or_else(|_| panic!("crash proxy could not terminate first proof host"));
    first_request.http.shutdown_both();
    wait_for_pid_disappearance(provider_pid);

    wait_for_completion_marker(&control.mismatch_completion_marker);
    listener
        .set_nonblocking(true)
        .unwrap_or_else(|_| panic!("crash proxy nonblocking mismatch check failed"));
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((_stream, _peer)) => panic!("one mismatch resume reached the proof proxy"),
        Err(error) => panic!("crash proxy mismatch check failed: {:?}", error.kind()),
    }
    persist_canonical(
        &root.join("mismatch-verified.json"),
        &ProxyMismatchObservation {
            protocol: PROXY_OBSERVATION_PROTOCOL.to_owned(),
            requests_before_legitimate_resume: 0,
        },
    );
    listener
        .set_nonblocking(false)
        .unwrap_or_else(|_| panic!("crash proxy blocking replay transition failed"));

    let (mut replay_request, replay_response) = proxy_exchange(&listener, control.backend);
    assert_eq!(replay_request.http.method(), "POST");
    assert_eq!(replay_request.http.target(), "/v1/direct-conversations");
    assert_eq!(replay_response.http.status(), 200);
    replay_request.http.write_response(&replay_response.http);
    replay_request.http.shutdown_write();
    let replay_request_digest = replay_request.body_digest();
    let replay = replay_response.observation();

    let (mut attester_request, attester_response) = proxy_exchange(&listener, control.backend);
    assert_eq!(attester_request.http.method(), "GET");
    assert_eq!(
        attester_request.http.target(),
        "/v1/conversations?include_archived=true"
    );
    assert_eq!(attester_response.http.status(), 200);
    attester_request
        .http
        .write_response(&attester_response.http);
    attester_request.http.shutdown_write();
    let attestation = attester_response.observation();

    assert_eq!(first.body_bytes, replay.body_bytes);
    assert_eq!(first.body_digest, replay.body_digest);
    assert_eq!(first_request_digest, replay_request_digest);
    persist_canonical(
        &root.join("terminal.json"),
        &ProxyTerminal {
            protocol: PROXY_OBSERVATION_PROTOCOL.to_owned(),
            first_request: first_request_digest,
            replay_request: replay_request_digest,
            first,
            replay,
            attestation,
            first_provider_disappeared: true,
            requests_before_legitimate_resume: 0,
        },
    );
}

struct ProxyRequest {
    http: HttpRequest,
}

impl ProxyRequest {
    fn body_digest(&self) -> ProxyBodyDigest {
        ProxyBodyDigest {
            body_bytes: self.http.body_bytes(),
            body_digest: self.http.body_digest(),
        }
    }
}

struct ProxyResponse {
    http: HttpResponse,
}

impl ProxyResponse {
    fn observation(&self) -> ProxyObservation {
        ProxyObservation {
            status: self.http.status(),
            body_bytes: self.http.body_bytes(),
            body_digest: self.http.body_digest(),
        }
    }
}

fn proxy_exchange(
    listener: &std::net::TcpListener,
    backend: SocketAddr,
) -> (ProxyRequest, ProxyResponse) {
    let request = accept_request(listener, 4);
    let response = forward_request(&request, backend);
    (
        ProxyRequest { http: request },
        ProxyResponse { http: response },
    )
}

fn run_mismatch_host(mode: &str, config_path: &Path, authority: &[u8]) {
    let (mut host, mut authority_pipe) = spawn_mode(mode, config_path);
    let host_pid = host.id();
    write_pipe_bytes(&mut authority_pipe, authority, "mismatch host authority");
    drop(authority_pipe);
    let deadline = Instant::now() + MISMATCH_DEADLINE;
    let mut process_observations = 0_u64;
    let status = loop {
        let children = direct_child_pids(host_pid);
        assert!(
            children.is_empty(),
            "mismatch proof host launched a native child"
        );
        process_observations += 1;
        if let Some(status) = host
            .try_wait()
            .unwrap_or_else(|_| panic!("mismatch proof host observation failed"))
        {
            assert!(direct_child_pids(host_pid).is_empty());
            break status;
        }
        if Instant::now() >= deadline {
            host.kill()
                .unwrap_or_else(|_| panic!("mismatch proof host deadline kill failed"));
            let _status = host
                .wait()
                .unwrap_or_else(|_| panic!("mismatch proof host deadline reap failed"));
            panic!("mismatch proof host deadline expired");
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert_ne!(process_observations, 0);
    assert!(
        status.success(),
        "mismatch proof host did not refuse cleanly"
    );
}

fn create_completion_marker(path: &Path) {
    fs::create_dir(path).unwrap_or_else(|_| panic!("mismatch completion marker creation failed"));
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|_| panic!("mismatch completion marker permission failed"));
    File::open(
        path.parent()
            .unwrap_or_else(|| panic!("mismatch completion marker lacked a parent")),
    )
    .and_then(|directory| directory.sync_all())
    .unwrap_or_else(|_| panic!("mismatch completion marker parent sync failed"));
}

fn wait_for_completion_marker(path: &Path) {
    let deadline = Instant::now() + MATRIX_BARRIER_DEADLINE;
    loop {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                assert!(
                    metadata.file_type().is_dir()
                        && metadata.uid() == rustix::process::geteuid().as_raw()
                        && metadata.mode() & 0o777 == 0o700,
                    "mismatch completion marker metadata was invalid"
                );
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                assert!(
                    Instant::now() < deadline,
                    "mismatch completion marker deadline expired"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!(
                "mismatch completion marker inspection failed: {:?}",
                error.kind()
            ),
        }
    }
}

fn direct_child_pid(parent: u32) -> u32 {
    let children = direct_child_pids(parent);
    let [provider] = children.as_slice() else {
        panic!("crash proxy did not observe exactly one live provider child");
    };
    *provider
}

fn direct_child_pids(parent: u32) -> Vec<u32> {
    let output = Command::new("/bin/ps")
        .env_clear()
        .args(["-axo", "pid=,ppid="])
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|_| panic!("crash proxy process observation failed"));
    assert!(output.status.success());
    assert!(output.stdout.len() <= 1024 * 1024);
    let process_table = std::str::from_utf8(&output.stdout)
        .unwrap_or_else(|_| panic!("crash proxy process observation was not UTF-8"));
    process_table
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let process_id = fields.next()?.parse::<u32>().ok()?;
            let parent_process_id = fields.next()?.parse::<u32>().ok()?;
            (fields.next().is_none() && parent_process_id == parent).then_some(process_id)
        })
        .collect::<Vec<_>>()
}

fn wait_for_pid_disappearance(pid: u32) {
    let deadline = Instant::now() + PROXY_IO_DEADLINE;
    loop {
        let output = Command::new("/bin/ps")
            .env_clear()
            .args(["-p", &pid.to_string(), "-o", "pid="])
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|_| panic!("crash proxy provider-exit observation failed"));
        assert!(output.stdout.len() <= 128);
        if output.stdout.iter().all(u8::is_ascii_whitespace) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "first provider remained after host termination"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn validate_private_directory(path: &Path, surface: &str) {
    assert!(path.is_absolute(), "{surface} must be absolute");
    let metadata =
        fs::symlink_metadata(path).unwrap_or_else(|_| panic!("{surface} inspection failed"));
    assert!(
        metadata.file_type().is_dir()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o777 == 0o700,
        "{surface} metadata was invalid"
    );
}

fn persist_canonical(path: &Path, value: &impl Serialize) {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .unwrap_or_else(|_| panic!("bounded proof document canonicalization failed"));
    assert!(bytes.len() <= MAX_CRASH_CONFIG_BYTES);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|_| panic!("bounded proof document creation failed"));
    file.write_all(&bytes)
        .unwrap_or_else(|_| panic!("bounded proof document write failed"));
    file.sync_all()
        .unwrap_or_else(|_| panic!("bounded proof document sync failed"));
    File::open(
        path.parent()
            .unwrap_or_else(|| panic!("bounded proof document lacked a parent")),
    )
    .and_then(|directory| directory.sync_all())
    .unwrap_or_else(|_| panic!("bounded proof directory sync failed"));
}

fn read_canonical_stdin<T>(bound: usize, surface: &str) -> T
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let mut input = std::io::stdin().lock();
    let bytes = read_bounded(&mut input, bound, surface);
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

fn create_private_directory(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    fs::create_dir(&path).unwrap_or_else(|_| panic!("private proof directory creation failed"));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|_| panic!("private proof directory permission failed"));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .unwrap_or_else(|_| panic!("private proof parent sync failed"));
    let canonical = path
        .canonicalize()
        .unwrap_or_else(|_| panic!("private proof directory canonicalization failed"));
    validate_private_directory(&canonical, "private proof directory");
    canonical
}

fn spawn_mode(mode: &str, argument: &Path) -> (ManagedChild, ChildStdin) {
    assert!(argument.is_absolute());
    let executable = env::current_exe()
        .unwrap_or_else(|_| panic!("crash-proof process executable could not be located"));
    let raw_child = Command::new(executable)
        .env_clear()
        .arg(mode)
        .arg(argument)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|_| panic!("crash-proof child process failed to execute"));
    let mut child = ManagedChild::new(raw_child);
    let input = child
        .child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("crash-proof child input pipe was unavailable"));
    (child, input)
}

fn write_canonical_pipe(writer: &mut ChildStdin, value: &impl Serialize) {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .unwrap_or_else(|_| panic!("crash-proof control canonicalization failed"));
    assert!(bytes.len() <= MAX_PROXY_CONTROL_BYTES);
    write_pipe_bytes(writer, &bytes, "crash-proof control");
}

fn write_pipe_bytes(writer: &mut ChildStdin, bytes: &[u8], surface: &str) {
    writer
        .write_all(bytes)
        .unwrap_or_else(|_| panic!("{surface} pipe write failed"));
    writer
        .flush()
        .unwrap_or_else(|_| panic!("{surface} pipe flush failed"));
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
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_canonical<T>(path: &Path) -> T
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let deadline = Instant::now() + PROXY_IO_DEADLINE;
    loop {
        match fs::read(path) {
            Ok(bytes) => {
                assert!(bytes.len() <= MAX_CRASH_CONFIG_BYTES);
                let value: T = serde_json::from_slice(&bytes)
                    .unwrap_or_else(|_| panic!("crash-proof status decoding failed"));
                assert_eq!(
                    serde_json_canonicalizer::to_vec(&value)
                        .unwrap_or_else(|_| panic!("crash-proof status canonicalization failed")),
                    bytes,
                    "crash-proof status was not canonical"
                );
                return value;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                assert!(
                    Instant::now() < deadline,
                    "crash-proof status deadline expired"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("crash-proof status read failed: {:?}", error.kind()),
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the isolated host explicitly constructs each hostile public resume input"
)]
fn run_host(mut arguments: impl Iterator<Item = OsString>, mode: HostMode) {
    let config_path = PathBuf::from(
        arguments
            .next()
            .unwrap_or_else(|| panic!("proof-host config argument was missing")),
    );
    assert!(
        arguments.next().is_none(),
        "proof host received extra arguments"
    );
    let config = load_crash_config(&config_path);
    let authority = read_host_authority();

    let packages = verify_package_set(&config.package_root)
        .unwrap_or_else(|_| panic!("proof host could not verify exact release packages"));
    let (reqwest_binding, ureq_binding) = provider_bindings(&packages);
    let reqwest_provider = qualify_provider(&packages, reqwest_binding, &config.native_parent)
        .unwrap_or_else(|_| panic!("proof host provider qualification failed"));
    let needs_ureq = matches!(
        mode,
        HostMode::Mismatch(
            MismatchKind::SelectedProvider
                | MismatchKind::ProviderArtifact
                | MismatchKind::RuntimeQualification
        )
    );
    let ureq_provider = needs_ureq.then(|| {
        qualify_provider(&packages, ureq_binding, &config.native_parent)
            .unwrap_or_else(|_| panic!("proof host alternate provider qualification failed"))
    });
    let attester = qualify_attester(
        &packages,
        &packages.report().attester,
        &config.native_parent,
    )
    .unwrap_or_else(|_| panic!("proof host attester qualification failed"));

    let mismatch = match mode {
        HostMode::Mismatch(kind) => Some(kind),
        HostMode::Start | HostMode::Resume | HostMode::Terminal => None,
    };
    let selected_provider = if matches!(mismatch, Some(MismatchKind::SelectedProvider)) {
        ureq_binding
    } else {
        reqwest_binding
    };
    let provider_artifact = if matches!(
        mismatch,
        Some(MismatchKind::SelectedProvider | MismatchKind::ProviderArtifact)
    ) {
        ureq_provider
            .as_ref()
            .unwrap_or_else(|| panic!("proof host alternate artifact was unavailable"))
    } else {
        &reqwest_provider
    };
    let runtime_provider = if matches!(
        mismatch,
        Some(
            MismatchKind::SelectedProvider
                | MismatchKind::ProviderArtifact
                | MismatchKind::RuntimeQualification
        )
    ) {
        ureq_provider
            .as_ref()
            .unwrap_or_else(|| panic!("proof host alternate runtime artifact was unavailable"))
    } else {
        &reqwest_provider
    };
    let runtime = qualify_native_runtime(runtime_provider.lock(), attester.lock())
        .unwrap_or_else(|_| panic!("proof host runtime qualification failed"));

    let intent = if matches!(mismatch, Some(MismatchKind::InvocationIntent)) {
        &config.alternate_intent
    } else {
        &config.intent
    };
    let (baseline, admitted_intent) = observed_intent_baseline(intent);
    let policy = candidate_policy(&attester);
    let plan_limits = planning_limits();
    let mut selected_process_limits = process_limits();
    if matches!(mismatch, Some(MismatchKind::ExecutionPolicy)) {
        selected_process_limits.provider =
            ProcessLimits::new(64 * 1024, 128 * 1024, 8 * 1024, Duration::from_secs(14))
                .unwrap_or_else(|_| panic!("proof host alternate execution policy was invalid"));
    }
    let invocation = link_invocation(
        &packages,
        selected_provider,
        intent,
        admitted_intent,
        plan_limits,
    );
    let (target_lock_path, target_binding) = match mismatch {
        Some(MismatchKind::TargetDeployment) => (
            &config.alternate_target_lock,
            &config.alternate_target_binding,
        ),
        Some(MismatchKind::CredentialRevision) => (
            &config.alternate_credential_lock,
            &config.alternate_credential_binding,
        ),
        _ => (&config.target_lock, &config.target_binding),
    };
    let target_lock = TargetLock::new(target_lock_path)
        .unwrap_or_else(|_| panic!("proof host could not reopen target lock"));
    let target_guard = target_lock
        .acquire_execution(target_binding)
        .unwrap_or_else(|_| panic!("proof host could not acquire target execution fence"));
    let journal = AttemptJournal::new(&config.journal)
        .unwrap_or_else(|_| panic!("proof host could not open attempt journal"));
    let session = journal
        .begin_session()
        .unwrap_or_else(|_| panic!("proof host could not acquire attempt session"));
    let request = DriverRequest {
        packages: &packages,
        selected_provider,
        invocation: &invocation,
        baseline: &baseline,
        admission_policy: &policy,
        provider_artifact,
        attester_artifact: &attester,
        runtime: &runtime,
        target: &target_guard,
        authority: &authority,
        planning_limits: plan_limits,
        process_limits: selected_process_limits,
    };
    match mode {
        HostMode::Start => {
            let progress = start(&session, &request)
                .unwrap_or_else(|_| panic!("proof host driver start failed"));
            assert_admitted_receipts(&terminal(Ok(progress)));
        }
        HostMode::Resume | HostMode::Terminal => {
            let progress = resume(&session, &request)
                .unwrap_or_else(|_| panic!("proof host driver resume failed"));
            assert_admitted_receipts(&terminal(Ok(progress)));
        }
        HostMode::Mismatch(kind) => {
            let expected = match kind {
                MismatchKind::ProviderArtifact => {
                    "qualified native artifact differs from package binding"
                }
                MismatchKind::RuntimeQualification => {
                    "native runtime does not bind the selected artifacts"
                }
                MismatchKind::SelectedProvider
                | MismatchKind::TargetDeployment
                | MismatchKind::CredentialRevision
                | MismatchKind::InvocationIntent
                | MismatchKind::ExecutionPolicy => "checkpoint immutable inputs changed",
            };
            let refusal = resume(&session, &request);
            assert!(
                matches!(
                    refusal,
                    Err(DriverError::Invariant(detail)) if detail == expected
                ),
                "proof host did not return the exact closed mismatch error"
            );
            let unchanged = session
                .load()
                .unwrap_or_else(|_| panic!("proof host could not reload refused attempt"));
            assert_eq!(unchanged.phase(), AttemptPhase::ProviderArmed);
            assert!(unchanged.provider_receipts().is_empty());
            assert!(unchanged.provider_decisive().is_none());
            assert!(unchanged.resolution().is_none());
        }
    }
}

fn load_crash_config(path: &Path) -> CrashConfig {
    assert!(
        path.is_absolute(),
        "proof-host config path must be absolute"
    );
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|_| panic!("proof-host config inspection failed"));
    assert!(
        metadata.file_type().is_file()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o777 == 0o600,
        "proof-host config metadata was invalid"
    );
    let mut file = File::open(path).unwrap_or_else(|_| panic!("proof-host config open failed"));
    let bytes = read_bounded(&mut file, MAX_CRASH_CONFIG_BYTES, "proof-host config");
    let config: CrashConfig = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("proof-host config decoding failed"));
    assert_eq!(
        serde_json_canonicalizer::to_vec(&config)
            .unwrap_or_else(|_| panic!("proof-host config canonicalization failed")),
        bytes,
        "proof-host config was not canonical"
    );
    config.validate();
    config
}

/// Read the coordinator-owned live authority channel from standard input.
///
/// Standard input is dedicated to this one bounded document in host modes. It
/// is consumed to EOF and dropped before package, artifact, runtime, target,
/// journal, or child-process work begins. The authority is never retained.
fn read_host_authority() -> AuthorityDocument {
    let mut input = std::io::stdin().lock();
    let bytes = read_bounded(
        &mut input,
        MAX_AUTHORITY_DOCUMENT_BYTES,
        "proof-host authority",
    );
    drop(input);
    parse_authority_document(&bytes)
        .unwrap_or_else(|_| panic!("proof-host authority decoding failed"))
}

fn read_bounded(reader: &mut impl Read, bound: usize, surface: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    reader
        .take(u64::try_from(bound + 1).expect("proof byte bound fits u64"))
        .read_to_end(&mut bytes)
        .unwrap_or_else(|_| panic!("{surface} read failed"));
    assert!(bytes.len() <= bound, "{surface} exceeded its byte bound");
    bytes
}
