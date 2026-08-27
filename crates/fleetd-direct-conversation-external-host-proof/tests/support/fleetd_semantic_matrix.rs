//! Process-separated real Fleetd semantic and convergence proof support.

#[allow(
    clippy::wildcard_imports,
    reason = "this proof is a private child of the accepted real-proof fixture and reuses its exact boundary"
)]
use super::*;

use super::http::{HTTP_IO_DEADLINE, HttpRequest, HttpResponse, forward_request, read_request};
use fleetd_direct_conversation_command_abi::{
    MAX_AUTHORITY_DOCUMENT_BYTES, parse_authority_document,
};
use fleetd_direct_conversation_contract::immutable_mode_conflict_failure_kind;
use fleetd_direct_conversation_external_host_proof::target::TargetBinding;
use gooir_capability::authority::{
    AdmissionDecision, AdmissionDenial, AdmissionVerdict, AssessmentOutcome, ConformanceAssessment,
};
use gooir_capability::protocol::{CapabilityCandidate, CapabilityOutcome, CapabilityResult};
use rustix::process::{kill_process_group, test_kill_process};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};

const MATRIX_CONFIG_PROTOCOL: &str = "org.gooi.proof/fleetd-semantic-matrix-config@0.1.0";
const MATRIX_PROXY_CONTROL_PROTOCOL: &str =
    "org.gooi.proof/fleetd-semantic-matrix-proxy-control@0.1.0";
const MATRIX_PROXY_READY_PROTOCOL: &str = "org.gooi.proof/fleetd-semantic-matrix-proxy-ready@0.1.0";
const MATRIX_PROXY_OBSERVATION_PROTOCOL: &str =
    "org.gooi.proof/fleetd-semantic-matrix-proxy-observation@0.1.0";
const MAX_MATRIX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_PROXY_CONTROL_BYTES: usize = 4 * 1024;
const MAX_PROXY_CONNECTIONS: usize = 16;
const MAX_EMPTY_CONNECTIONS: usize = 8;
const PROXY_TOTAL_DEADLINE: Duration = Duration::from_mins(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MatrixProvider {
    Reqwest,
    Ureq,
}

impl MatrixProvider {
    fn parse(value: &std::ffi::OsStr) -> Self {
        if value == std::ffi::OsStr::new("reqwest") {
            Self::Reqwest
        } else if value == std::ffi::OsStr::new("ureq") {
            Self::Ureq
        } else {
            panic!("semantic-matrix provider argument was invalid");
        }
    }

    const fn argument(self) -> &'static str {
        match self {
            Self::Reqwest => "reqwest",
            Self::Ureq => "ureq",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostPurpose {
    Exact,
    Conflict,
    Altered,
}

impl HostPurpose {
    fn parse(value: &std::ffi::OsStr) -> Self {
        if value == std::ffi::OsStr::new("exact") {
            Self::Exact
        } else if value == std::ffi::OsStr::new("conflict") {
            Self::Conflict
        } else if value == std::ffi::OsStr::new("altered") {
            Self::Altered
        } else {
            panic!("semantic-matrix host purpose was invalid");
        }
    }

    const fn argument(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Conflict => "conflict",
            Self::Altered => "altered",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MatrixConfig {
    protocol: String,
    package_root: PathBuf,
    reqwest_native_parent: PathBuf,
    ureq_native_parent: PathBuf,
    target_lock: PathBuf,
    target_binding: TargetBinding,
    exact_intent: DirectPairIntent,
    conflict_intent: DirectPairIntent,
}

impl MatrixConfig {
    fn validate(&self) {
        assert_eq!(self.protocol, MATRIX_CONFIG_PROTOCOL);
        for path in [
            &self.package_root,
            &self.reqwest_native_parent,
            &self.ureq_native_parent,
            &self.target_lock,
        ] {
            assert!(path.is_absolute(), "semantic-matrix paths must be absolute");
        }
        self.target_binding
            .validate()
            .unwrap_or_else(|_| panic!("semantic-matrix target binding was invalid"));
        assert_eq!(
            self.exact_intent.fleetd_target(),
            self.target_binding.deployment().fleetd_target()
        );
        assert_eq!(
            self.conflict_intent.fleetd_target(),
            self.exact_intent.fleetd_target()
        );
        let exact_agents = self
            .exact_intent
            .members()
            .iter()
            .map(DirectMember::agent_id)
            .collect::<Vec<_>>();
        let conflict_agents = self
            .conflict_intent
            .members()
            .iter()
            .map(DirectMember::agent_id)
            .collect::<Vec<_>>();
        assert_eq!(exact_agents, conflict_agents);
        assert_ne!(self.exact_intent, self.conflict_intent);
    }

    fn intent(&self, purpose: HostPurpose) -> &DirectPairIntent {
        match purpose {
            HostPurpose::Exact | HostPurpose::Altered => &self.exact_intent,
            HostPurpose::Conflict => &self.conflict_intent,
        }
    }

    fn native_parent(&self, provider: MatrixProvider) -> &Path {
        match provider {
            MatrixProvider::Reqwest => &self.reqwest_native_parent,
            MatrixProvider::Ureq => &self.ureq_native_parent,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyControl {
    protocol: String,
    backend: SocketAddr,
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
struct ResponseObservation {
    status: u16,
    body: BodyObservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PostObservation {
    ordinal: u8,
    request: BodyObservation,
    backend: ResponseObservation,
    delivered: ResponseObservation,
    barrier_arrivals: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetObservation {
    ordinal: u8,
    response: ResponseObservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyTerminal {
    protocol: String,
    posts: Vec<PostObservation>,
    gets: Vec<GetObservation>,
    empty_connections: u8,
}

#[derive(Default)]
struct ProxyState {
    posts_arrived: u8,
    posts: Vec<PostObservation>,
    gets_arrived: u8,
    gets: Vec<GetObservation>,
    empty_connections: u8,
}

struct ProxyShared {
    state: Mutex<ProxyState>,
    barrier: Condvar,
}

/// Dispatch one credential-owning coordinator, host, proxy, or log pump.
pub(crate) fn dispatch() {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    match arguments.next().as_deref() {
        None => run_coordinator(),
        Some(mode) if mode == std::ffi::OsStr::new("--log-pump") => run_log_pump(arguments),
        Some(mode) if mode == std::ffi::OsStr::new("--proxy") => run_proxy(arguments),
        Some(mode) if mode == std::ffi::OsStr::new("--host") => run_host(arguments),
        Some(_) => panic!("unknown semantic-matrix process mode"),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the process-separated semantic matrix is intentionally linear and auditable"
)]
fn run_coordinator() {
    let external = ExternalInputs::load();
    let revision = clean_revision(&external.fleetd_repo);
    let fleetd = StagedFleetdExecutable::stage(&external.fleetd_binary);
    let openapi_digest = sha256_file(&external.fleetd_repo.join("openapi/fleetd-v1.json"));
    let root = private_tempdir("gooir-semantic-matrix-");
    let package_root = root.path().join("packages");
    stage(StageRequest {
        reqwest_command: external.reqwest_binary,
        ureq_command: external.ureq_binary,
        attester_command: external.attester_binary,
        output_root: package_root.clone(),
    })
    .unwrap_or_else(|_| panic!("semantic-matrix coordinator could not stage release packages"));
    let packages = verify_package_set(&package_root)
        .unwrap_or_else(|_| panic!("semantic-matrix coordinator could not verify packages"));
    let (reqwest_binding, ureq_binding) = provider_bindings(&packages);
    assert_ne!(reqwest_binding.implementation, ureq_binding.implementation);

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
        "semantic-matrix-agent-a",
    );
    let AgentRegistration {
        id: agent_b,
        bearer: stream_bearer,
    } = create_agent(
        &client,
        &backend_endpoint,
        operator_bearer.as_str(),
        "semantic-matrix-agent-b",
    );
    assert_no_public_conversations(&client, &backend_endpoint, operator_bearer.as_str());
    drop(client);

    let proxy_root = create_matrix_private_directory(root.path(), "proxy");
    let (mut proxy, mut proxy_control) = spawn_matrix_proxy(&proxy_root);
    write_matrix_canonical_pipe(
        &mut proxy_control,
        &ProxyControl {
            protocol: MATRIX_PROXY_CONTROL_PROTOCOL.to_owned(),
            backend,
        },
    );
    drop(proxy_control);
    let ready: ProxyReady = wait_for_matrix_canonical(&proxy_root.join("ready.json"));
    assert_eq!(ready.protocol, MATRIX_PROXY_READY_PROTOCOL);
    assert!(ready.address.ip().is_loopback());
    let proxy_endpoint = format!("http://{}/", ready.address);

    let target = FleetdTarget::parse(format!(
        "fleetd:proof:{:x}",
        Sha256::digest(format!("{}:semantic-matrix", root.path().display()).as_bytes())
    ))
    .unwrap_or_else(|_| panic!("semantic-matrix target construction failed"));
    let data_identity = persist_marker(
        root.path(),
        "data-directory.identity.json",
        &json!({
            "protocol": "org.gooi.proof/fleetd-data-directory-identity@0.1.0",
            "fleetd_target": target.as_str(),
            "marker": fresh_marker(root.path(), "semantic-matrix-data")
        }),
    );
    let credential_revision = persist_marker(
        root.path(),
        "credential-generation.identity.json",
        &json!({
            "protocol": "org.gooi.proof/fleetd-credential-generation@0.1.0",
            "fleetd_target": target.as_str(),
            "marker": fresh_marker(root.path(), "semantic-matrix-credential")
        }),
    );
    let mapping_digest = digest_document(&json!({
        "protocol": "org.gooi.proof/fleetd-endpoint-mapping@0.1.0",
        "fleetd_target": target.as_str(),
        "endpoint": proxy_endpoint
    }));
    let target_lock_path = root.path().join("target-lock");
    let target_lock = TargetLock::new(&target_lock_path)
        .unwrap_or_else(|_| panic!("semantic-matrix could not create target lock"));
    let target_binding = target_lock
        .configure(
            TargetDeployment::new(
                target.clone(),
                fleetd.digest(),
                &revision,
                &openapi_digest,
                data_identity,
                mapping_digest.clone(),
                credential_revision.clone(),
            )
            .unwrap_or_else(|_| panic!("semantic-matrix target deployment was invalid")),
        )
        .unwrap_or_else(|_| panic!("semantic-matrix could not publish target deployment"));
    let authority = AuthorityDocument::new(
        target.as_str(),
        mapping_digest,
        credential_revision,
        &proxy_endpoint,
        operator_bearer.as_str(),
        5_000,
        u64::try_from(MAX_RESPONSE_BYTES).expect("response bound fits u64"),
    )
    .unwrap_or_else(|_| panic!("semantic-matrix live authority was invalid"));
    let authority_bytes = authority
        .encode_for_pipe()
        .unwrap_or_else(|_| panic!("semantic-matrix authority encoding failed"));
    let exact_intent = DirectPairIntent::new(
        target.clone(),
        [
            DirectMember::new(agent_a.clone(), DeliveryMode::Inbox),
            DirectMember::new(agent_b.clone(), DeliveryMode::StreamOnly),
        ],
    )
    .unwrap_or_else(|_| panic!("semantic-matrix exact intent was invalid"));
    let conflict_intent = DirectPairIntent::new(
        target,
        [
            DirectMember::new(agent_a, DeliveryMode::StreamOnly),
            DirectMember::new(agent_b, DeliveryMode::StreamOnly),
        ],
    )
    .unwrap_or_else(|_| panic!("semantic-matrix conflict intent was invalid"));
    let reqwest_native_parent = create_matrix_private_directory(root.path(), "native-reqwest");
    let ureq_native_parent = create_matrix_private_directory(root.path(), "native-ureq");
    let config_path = root.path().join("semantic-matrix-config.json");
    let config = MatrixConfig {
        protocol: MATRIX_CONFIG_PROTOCOL.to_owned(),
        package_root,
        reqwest_native_parent,
        ureq_native_parent,
        target_lock: target_lock_path,
        target_binding,
        exact_intent: exact_intent.clone(),
        conflict_intent,
    };
    config.validate();
    persist_matrix_canonical(&config_path, &config);

    let reqwest_exact_journal = root.path().join("attempt-exact-reqwest");
    let ureq_exact_journal = root.path().join("attempt-exact-ureq");
    let (mut reqwest_host, mut reqwest_authority) = spawn_matrix_host(
        &config_path,
        MatrixProvider::Reqwest,
        HostPurpose::Exact,
        &reqwest_exact_journal,
    );
    let (mut ureq_host, mut ureq_authority) = spawn_matrix_host(
        &config_path,
        MatrixProvider::Ureq,
        HostPurpose::Exact,
        &ureq_exact_journal,
    );
    write_matrix_pipe(
        &mut reqwest_authority,
        &authority_bytes,
        "concurrent Reqwest authority",
    );
    drop(reqwest_authority);
    write_matrix_pipe(
        &mut ureq_authority,
        &authority_bytes,
        "concurrent Ureq authority",
    );
    drop(ureq_authority);
    assert!(
        wait_matrix_host(
            &mut reqwest_host,
            Duration::from_secs(45),
            "concurrent Reqwest host"
        )
        .success()
    );
    assert!(
        wait_matrix_host(
            &mut ureq_host,
            Duration::from_secs(45),
            "concurrent Ureq host"
        )
        .success()
    );
    let reqwest_exact = load_matrix_checkpoint(&reqwest_exact_journal);
    let ureq_exact = load_matrix_checkpoint(&ureq_exact_journal);
    assert_admitted_receipts(&reqwest_exact);
    assert_admitted_receipts(&ureq_exact);
    let reqwest_snapshot = admitted_snapshot(&reqwest_exact);
    let ureq_snapshot = admitted_snapshot(&ureq_exact);
    let reqwest_fact = conversation_fact(&reqwest_snapshot);
    let ureq_fact = conversation_fact(&ureq_snapshot);
    assert_eq!(reqwest_fact, ureq_fact);
    let reference = DirectConversationRef::from_fact(&reqwest_fact)
        .unwrap_or_else(|_| panic!("semantic-matrix result was not a conversation reference"));
    let (baseline, _) = observed_intent_baseline(&exact_intent);
    assert_concurrent_authorities(&baseline, &reqwest_snapshot, &ureq_snapshot, &reqwest_fact);
    assert_public_conversation(
        &public_client(),
        &backend_endpoint,
        operator_bearer.as_str(),
        &reference,
    );

    let reqwest_conflict_journal = root.path().join("attempt-conflict-reqwest");
    run_matrix_host_to_completion(
        &config_path,
        MatrixProvider::Reqwest,
        HostPurpose::Conflict,
        &reqwest_conflict_journal,
        &authority_bytes,
    );
    assert_terminal_unable(&load_matrix_checkpoint(&reqwest_conflict_journal));
    let ureq_conflict_journal = root.path().join("attempt-conflict-ureq");
    run_matrix_host_to_completion(
        &config_path,
        MatrixProvider::Ureq,
        HostPurpose::Conflict,
        &ureq_conflict_journal,
        &authority_bytes,
    );
    assert_terminal_unable(&load_matrix_checkpoint(&ureq_conflict_journal));
    assert_public_conversation(
        &public_client(),
        &backend_endpoint,
        operator_bearer.as_str(),
        &reference,
    );

    let altered_journal = root.path().join("attempt-altered-reqwest");
    run_matrix_host_to_completion(
        &config_path,
        MatrixProvider::Reqwest,
        HostPurpose::Altered,
        &altered_journal,
        &authority_bytes,
    );
    let altered_checkpoint = load_matrix_checkpoint(&altered_journal);
    assert_terminal_withheld(&altered_checkpoint);
    assert_altered_candidate(&altered_checkpoint, &reference);
    assert_public_conversation(
        &public_client(),
        &backend_endpoint,
        operator_bearer.as_str(),
        &reference,
    );

    let proxy_status =
        wait_matrix_child(&mut proxy, Duration::from_secs(30), "semantic-matrix proxy");
    assert!(proxy_status.success());
    let proxy_terminal: ProxyTerminal =
        wait_for_matrix_canonical(&proxy_root.join("terminal.json"));
    assert_proxy_terminal(&proxy_terminal);
    let logs = daemon.stop();

    let journal_paths = [
        &reqwest_exact_journal,
        &ureq_exact_journal,
        &reqwest_conflict_journal,
        &ureq_conflict_journal,
        &altered_journal,
    ];
    let mut journal_bytes = Vec::new();
    for journal in journal_paths {
        journal_bytes.extend(read_tree(journal));
    }
    let config_bytes = fs::read(&config_path)
        .unwrap_or_else(|_| panic!("semantic-matrix config audit read failed"));
    let proxy_diagnostics = read_tree(&proxy_root);
    for surface in [&journal_bytes, &config_bytes, &proxy_diagnostics] {
        for endpoint in [&backend_endpoint, &proxy_endpoint] {
            assert_journal_canaries_absent(
                surface,
                endpoint,
                operator_bearer.as_str(),
                &authority_bytes,
                &[&inbox_bearer, &stream_bearer],
            );
        }
    }
    assert_log_canaries_absent(
        &logs,
        &backend_endpoint,
        operator_bearer.as_str(),
        &authority_bytes,
        &[&inbox_bearer, &stream_bearer],
    );
    for spelling in endpoint_spellings(&proxy_endpoint) {
        assert!(!contains_bytes(&logs, &spelling));
    }
    assert_eq!(clean_revision(&external.fleetd_repo), revision);
}

fn assert_concurrent_authorities(
    baseline: &AdmissionSnapshot,
    reqwest: &AdmissionSnapshot,
    ureq: &AdmissionSnapshot,
    fact: &gooir_capability::Fact,
) {
    let mut ledger = AdmissionLedger::rebuild(baseline)
        .unwrap_or_else(|_| panic!("semantic-matrix baseline rebuild failed"));
    let mut implementations = Vec::new();
    let mut authority_ids = Vec::new();
    for snapshot in [reqwest, ureq] {
        let records = snapshot
            .authority_records
            .iter()
            .filter(|record| record.fact == *fact)
            .filter(|record| matches!(record.basis, AuthorityBasis::Derived { .. }))
            .collect::<Vec<_>>();
        let [record] = records.as_slice() else {
            panic!("concurrent snapshot lacked one exact derived authority");
        };
        let AuthorityBasis::Derived {
            invocation,
            result,
            candidate,
            assessment,
            policy,
            ..
        } = &record.basis
        else {
            unreachable!("derived filter already established basis");
        };
        let outcome = ledger
            .admit_candidate(policy, invocation, result, candidate, assessment)
            .unwrap_or_else(|_| panic!("semantic-matrix concurrent admission replay failed"));
        let AdmissionOutcome::Admitted { links, .. } = outcome else {
            panic!("semantic-matrix concurrent chain was unexpectedly withheld");
        };
        let [link] = links.as_slice() else {
            panic!("semantic-matrix concurrent chain did not admit one output");
        };
        assert_eq!(
            link.reference.authority_record_id,
            record.authority_record_id
        );
        let resolved = ledger
            .resolve(&link.reference)
            .unwrap_or_else(|_| panic!("semantic-matrix concurrent fact resolution failed"));
        assert_eq!(resolved.fact, fact);
        implementations.push(invocation.selection.offer.implementation.to_string());
        authority_ids.push(record.authority_record_id.to_string());
    }
    implementations.sort();
    implementations.dedup();
    authority_ids.sort();
    authority_ids.dedup();
    assert_eq!(implementations.len(), 2);
    assert_eq!(authority_ids.len(), 2);
    let combined = ledger
        .export()
        .unwrap_or_else(|_| panic!("semantic-matrix combined ledger export failed"));
    combined
        .validate()
        .unwrap_or_else(|_| panic!("semantic-matrix combined ledger was invalid"));
    assert_eq!(conversation_fact(&combined), *fact);
    assert_two_derived_authorities(&combined, fact);
}

fn assert_altered_candidate(checkpoint: &AttemptCheckpoint, durable: &DirectConversationRef) {
    let candidate: CapabilityCandidate = serde_json::from_value(
        checkpoint
            .candidate()
            .unwrap_or_else(|| panic!("altered checkpoint lacked candidate"))
            .value()
            .clone(),
    )
    .unwrap_or_else(|_| panic!("altered candidate decoding failed"));
    let CapabilityOutcome::Produced {
        outputs,
        extensions,
    } = &candidate.result.outcome
    else {
        panic!("altered candidate result was not produced");
    };
    assert!(extensions.is_empty());
    let [output] = outputs.as_slice() else {
        panic!("altered candidate did not contain one output");
    };
    let altered = DirectConversationRef::from_fact(&output.fact)
        .unwrap_or_else(|_| panic!("altered candidate was not valid-shaped"));
    assert_eq!(altered.conversation_id(), durable.conversation_id());
    assert_eq!(altered.members(), durable.members());
    assert_eq!(altered.fleetd_target(), durable.fleetd_target());
    assert_eq!(
        altered.created_at_ms(),
        durable
            .created_at_ms()
            .checked_add(1)
            .expect("durable creation time can be incremented")
    );
    assert_ne!(
        output.fact,
        durable.to_fact().expect("durable fact is valid")
    );
}

fn assert_proxy_terminal(terminal: &ProxyTerminal) {
    assert_eq!(terminal.protocol, MATRIX_PROXY_OBSERVATION_PROTOCOL);
    let [first, second, reqwest_conflict, ureq_conflict, altered] = terminal.posts.as_slice()
    else {
        panic!("semantic-matrix proxy did not retain five POST observations");
    };
    assert_eq!(
        terminal
            .posts
            .iter()
            .map(|observation| observation.ordinal)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5]
    );
    assert_eq!(first.barrier_arrivals, 2);
    assert_eq!(second.barrier_arrivals, 2);
    assert!(
        terminal.posts[2..]
            .iter()
            .all(|observation| observation.barrier_arrivals == 0)
    );
    let mut concurrent_statuses = [first.backend.status, second.backend.status];
    concurrent_statuses.sort_unstable();
    assert_eq!(concurrent_statuses, [200, 201]);
    assert_ne!(first.request, second.request);
    assert_eq!(first.backend.body, second.backend.body);
    assert_eq!(first.backend, first.delivered);
    assert_eq!(second.backend, second.delivered);
    assert_eq!(reqwest_conflict.backend.status, 409);
    assert_eq!(ureq_conflict.backend.status, 409);
    assert_eq!(reqwest_conflict.backend, reqwest_conflict.delivered);
    assert_eq!(ureq_conflict.backend, ureq_conflict.delivered);
    assert_ne!(reqwest_conflict.request, ureq_conflict.request);
    assert_ne!(first.request, reqwest_conflict.request);
    assert!(altered.request == first.request || altered.request == second.request);
    assert_eq!(altered.backend.status, 200);
    assert_eq!(altered.delivered.status, 200);
    assert_ne!(altered.backend.body, altered.delivered.body);
    assert_eq!(terminal.gets.len(), 3);
    assert_eq!(
        terminal
            .gets
            .iter()
            .map(|observation| observation.ordinal)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(
        terminal
            .gets
            .iter()
            .all(|observation| observation.response.status == 200)
    );
    assert!(
        terminal
            .gets
            .windows(2)
            .all(|pair| pair[0].response == pair[1].response)
    );
    assert!(usize::from(terminal.empty_connections) <= MAX_EMPTY_CONNECTIONS);
}

fn run_matrix_host_to_completion(
    config: &Path,
    provider: MatrixProvider,
    purpose: HostPurpose,
    journal: &Path,
    authority: &[u8],
) {
    let (mut child, mut input) = spawn_matrix_host(config, provider, purpose, journal);
    write_matrix_pipe(&mut input, authority, "semantic-matrix host authority");
    drop(input);
    let status = wait_matrix_host(&mut child, Duration::from_secs(45), "semantic-matrix host");
    assert!(status.success());
}

fn spawn_matrix_proxy(root: &Path) -> (ManagedChild, ChildStdin) {
    assert!(root.is_absolute());
    let executable = env::current_exe()
        .unwrap_or_else(|_| panic!("semantic-matrix executable could not be located"));
    let raw_child = Command::new(executable)
        .env_clear()
        .arg("--proxy")
        .arg(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|_| panic!("semantic-matrix proxy failed to execute"));
    let mut child = ManagedChild::new(raw_child);
    let input = child
        .child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("semantic-matrix proxy control pipe was unavailable"));
    (child, input)
}

fn spawn_matrix_host(
    config: &Path,
    provider: MatrixProvider,
    purpose: HostPurpose,
    journal: &Path,
) -> (ManagedMatrixHost, ChildStdin) {
    assert!(config.is_absolute());
    assert!(journal.is_absolute());
    let executable = env::current_exe()
        .unwrap_or_else(|_| panic!("semantic-matrix executable could not be located"));
    let raw_child = Command::new(executable)
        .env_clear()
        .arg("--host")
        .arg(config)
        .arg(provider.argument())
        .arg(purpose.argument())
        .arg(journal)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|_| panic!("semantic-matrix host failed to execute"));
    let mut child = ManagedMatrixHost::new(raw_child);
    let input = child
        .child
        .child
        .stdin
        .take()
        .unwrap_or_else(|| panic!("semantic-matrix authority pipe was unavailable"));
    (child, input)
}

struct ManagedMatrixHost {
    child: ManagedChild,
}

impl ManagedMatrixHost {
    const fn new(child: Child) -> Self {
        Self {
            child: ManagedChild::new(child),
        }
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    fn terminate(&mut self) {
        if self.child.reaped {
            return;
        }
        let host = pid_from_u32(self.child.id(), "semantic-matrix host");
        match kill_process(host, Signal::STOP) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(error) => panic!("semantic-matrix host freeze failed: {error:?}"),
        }
        let providers = direct_child_pids(self.child.id());
        assert!(
            providers.len() <= 1,
            "semantic-matrix host had more than one direct child"
        );
        for provider in &providers {
            match kill_process_group(
                pid_from_u32(*provider, "semantic-matrix provider"),
                Signal::KILL,
            ) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(error) => {
                    panic!("semantic-matrix provider-group termination failed: {error:?}")
                }
            }
        }
        match kill_process(host, Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(error) => panic!("semantic-matrix host termination failed: {error:?}"),
        }
        self.child
            .wait()
            .unwrap_or_else(|_| panic!("semantic-matrix host reap failed"));
        for provider in providers {
            wait_for_process_disappearance(provider);
        }
    }
}

impl Drop for ManagedMatrixHost {
    fn drop(&mut self) {
        if self.child.reaped {
            return;
        }
        let host = Pid::from_raw(i32::try_from(self.child.id()).unwrap_or_default());
        if let Some(host) = host {
            let _ignored = kill_process(host, Signal::STOP);
        }
        let providers = try_direct_child_pids(self.child.id()).unwrap_or_default();
        for provider in providers {
            if let Some(provider) = Pid::from_raw(i32::try_from(provider).unwrap_or_default()) {
                let _ignored = kill_process_group(provider, Signal::KILL);
            }
        }
        if let Some(host) = host {
            let _ignored = kill_process(host, Signal::KILL);
        }
        let _ignored = self.child.wait();
    }
}

fn pid_from_u32(raw: u32, surface: &str) -> Pid {
    i32::try_from(raw)
        .ok()
        .and_then(Pid::from_raw)
        .unwrap_or_else(|| panic!("{surface} PID was invalid"))
}

fn direct_child_pids(parent: u32) -> Vec<u32> {
    try_direct_child_pids(parent)
        .unwrap_or_else(|()| panic!("semantic-matrix process observation failed"))
}

fn try_direct_child_pids(parent: u32) -> Result<Vec<u32>, ()> {
    let output = Command::new("/bin/ps")
        .env_clear()
        .args(["-axo", "pid=,ppid="])
        .stdin(Stdio::null())
        .output()
        .map_err(|_| ())?;
    if !output.status.success() || output.stdout.len() > 1024 * 1024 {
        return Err(());
    }
    let process_table = std::str::from_utf8(&output.stdout).map_err(|_| ())?;
    Ok(process_table
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let process_id = fields.next()?.parse::<u32>().ok()?;
            let parent_process_id = fields.next()?.parse::<u32>().ok()?;
            (fields.next().is_none() && parent_process_id == parent).then_some(process_id)
        })
        .collect())
}

fn wait_for_process_disappearance(raw: u32) {
    let process = pid_from_u32(raw, "semantic-matrix provider");
    let deadline = Instant::now() + HTTP_IO_DEADLINE;
    loop {
        match test_kill_process(process) {
            Err(rustix::io::Errno::SRCH) => return,
            Ok(()) | Err(rustix::io::Errno::PERM) => {}
            Err(error) => {
                panic!("semantic-matrix provider-exit observation failed: {error:?}")
            }
        }
        assert!(
            Instant::now() < deadline,
            "semantic-matrix provider remained after host termination"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn write_matrix_canonical_pipe(writer: &mut ChildStdin, value: &impl Serialize) {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .unwrap_or_else(|_| panic!("semantic-matrix control canonicalization failed"));
    assert!(bytes.len() <= MAX_PROXY_CONTROL_BYTES);
    write_matrix_pipe(writer, &bytes, "semantic-matrix control");
}

fn write_matrix_pipe(writer: &mut ChildStdin, bytes: &[u8], surface: &str) {
    writer
        .write_all(bytes)
        .unwrap_or_else(|_| panic!("{surface} write failed"));
    writer
        .flush()
        .unwrap_or_else(|_| panic!("{surface} flush failed"));
}

fn wait_matrix_child(child: &mut ManagedChild, duration: Duration, surface: &str) -> ExitStatus {
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

fn wait_matrix_host(
    child: &mut ManagedMatrixHost,
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
            child.terminate();
            panic!("{surface} deadline expired");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn load_matrix_checkpoint(path: &Path) -> AttemptCheckpoint {
    let journal = AttemptJournal::new(path)
        .unwrap_or_else(|_| panic!("semantic-matrix coordinator could not open journal"));
    let session = journal
        .begin_session()
        .unwrap_or_else(|_| panic!("semantic-matrix coordinator could not inspect journal"));
    let checkpoint = session
        .load()
        .unwrap_or_else(|_| panic!("semantic-matrix coordinator could not load journal"));
    checkpoint
        .validate()
        .unwrap_or_else(|_| panic!("semantic-matrix checkpoint was invalid"));
    checkpoint
}

fn create_matrix_private_directory(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    fs::create_dir(&path)
        .unwrap_or_else(|_| panic!("semantic-matrix private directory creation failed"));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|_| panic!("semantic-matrix private directory permission failed"));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .unwrap_or_else(|_| panic!("semantic-matrix private directory parent sync failed"));
    let canonical = path
        .canonicalize()
        .unwrap_or_else(|_| panic!("semantic-matrix private directory canonicalization failed"));
    validate_matrix_private_directory(&canonical, "semantic-matrix private directory");
    canonical
}

fn wait_for_matrix_canonical<T>(path: &Path) -> T
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let deadline = Instant::now() + HTTP_IO_DEADLINE;
    loop {
        match fs::read(path) {
            Ok(bytes) => {
                assert!(bytes.len() <= MAX_MATRIX_CONFIG_BYTES);
                let value: T = serde_json::from_slice(&bytes)
                    .unwrap_or_else(|_| panic!("semantic-matrix status decoding failed"));
                assert_eq!(
                    serde_json_canonicalizer::to_vec(&value).unwrap_or_else(|_| panic!(
                        "semantic-matrix status canonicalization failed"
                    )),
                    bytes,
                    "semantic-matrix status was not canonical"
                );
                return value;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                assert!(
                    Instant::now() < deadline,
                    "semantic-matrix status deadline expired"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("semantic-matrix status read failed: {:?}", error.kind()),
        }
    }
}

fn run_proxy(mut arguments: impl Iterator<Item = OsString>) {
    let root = PathBuf::from(
        arguments
            .next()
            .unwrap_or_else(|| panic!("semantic-matrix proxy root was missing")),
    );
    assert!(arguments.next().is_none(), "proxy received extra arguments");
    validate_matrix_private_directory(&root, "semantic-matrix proxy root");
    let listener = TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|_| panic!("semantic-matrix proxy loopback bind failed"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|_| panic!("semantic-matrix proxy address inspection failed"));
    assert!(address.ip().is_loopback());
    persist_matrix_canonical(
        &root.join("ready.json"),
        &ProxyReady {
            protocol: MATRIX_PROXY_READY_PROTOCOL.to_owned(),
            address,
        },
    );
    let control: ProxyControl =
        read_matrix_canonical_stdin(MAX_PROXY_CONTROL_BYTES, "proxy control");
    assert_eq!(control.protocol, MATRIX_PROXY_CONTROL_PROTOCOL);
    assert!(control.backend.ip().is_loopback());

    listener
        .set_nonblocking(true)
        .unwrap_or_else(|_| panic!("semantic-matrix proxy nonblocking setup failed"));
    let shared = Arc::new(ProxyShared {
        state: Mutex::new(ProxyState::default()),
        barrier: Condvar::new(),
    });
    let deadline = Instant::now() + PROXY_TOTAL_DEADLINE;
    let mut handlers = Vec::new();
    loop {
        let done = {
            let state = shared
                .state
                .lock()
                .unwrap_or_else(|_| panic!("semantic-matrix proxy state was poisoned"));
            state.posts.len() == 5 && state.gets.len() == 3
        };
        if done {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "semantic-matrix proxy total deadline expired"
        );
        match listener.accept() {
            Ok((stream, peer)) => {
                assert!(peer.ip().is_loopback());
                assert!(
                    handlers.len() < MAX_PROXY_CONNECTIONS,
                    "semantic-matrix proxy connection capacity was exhausted"
                );
                let shared = Arc::clone(&shared);
                let backend = control.backend;
                handlers.push(thread::spawn(move || {
                    handle_proxy_connection(stream, backend, &shared);
                }));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("semantic-matrix proxy accept failed: {:?}", error.kind()),
        }
    }
    for handler in handlers {
        handler
            .join()
            .unwrap_or_else(|_| panic!("semantic-matrix proxy handler failed"));
    }
    let mut state = Arc::try_unwrap(shared)
        .unwrap_or_else(|_| panic!("semantic-matrix proxy state remained shared"))
        .state
        .into_inner()
        .unwrap_or_else(|_| panic!("semantic-matrix proxy state was poisoned"));
    state.posts.sort_by_key(|observation| observation.ordinal);
    state.gets.sort_by_key(|observation| observation.ordinal);
    assert_eq!(state.posts.len(), 5);
    assert_eq!(state.gets.len(), 3);
    persist_matrix_canonical(
        &root.join("terminal.json"),
        &ProxyTerminal {
            protocol: MATRIX_PROXY_OBSERVATION_PROTOCOL.to_owned(),
            posts: state.posts,
            gets: state.gets,
            empty_connections: state.empty_connections,
        },
    );
}

fn run_host(mut arguments: impl Iterator<Item = OsString>) {
    let config_path = PathBuf::from(
        arguments
            .next()
            .unwrap_or_else(|| panic!("semantic-matrix host config was missing")),
    );
    let provider = MatrixProvider::parse(
        &arguments
            .next()
            .unwrap_or_else(|| panic!("semantic-matrix host provider was missing")),
    );
    let purpose = HostPurpose::parse(
        &arguments
            .next()
            .unwrap_or_else(|| panic!("semantic-matrix host purpose was missing")),
    );
    let journal_path = PathBuf::from(
        arguments
            .next()
            .unwrap_or_else(|| panic!("semantic-matrix host journal was missing")),
    );
    assert!(arguments.next().is_none(), "host received extra arguments");
    let config = load_matrix_config(&config_path);
    assert!(journal_path.is_absolute());
    assert_eq!(journal_path.parent(), config_path.parent());
    let authority = read_matrix_authority();

    let packages = verify_package_set(&config.package_root)
        .unwrap_or_else(|_| panic!("semantic-matrix host could not verify release packages"));
    let (reqwest_binding, ureq_binding) = provider_bindings(&packages);
    let selected = match provider {
        MatrixProvider::Reqwest => reqwest_binding,
        MatrixProvider::Ureq => ureq_binding,
    };
    let provider_artifact = qualify_provider(&packages, selected, config.native_parent(provider))
        .unwrap_or_else(|_| panic!("semantic-matrix provider qualification failed"));
    let attester_artifact = qualify_attester(
        &packages,
        &packages.report().attester,
        config.native_parent(provider),
    )
    .unwrap_or_else(|_| panic!("semantic-matrix attester qualification failed"));
    let runtime = qualify_native_runtime(provider_artifact.lock(), attester_artifact.lock())
        .unwrap_or_else(|_| panic!("semantic-matrix native runtime qualification failed"));
    let intent = config.intent(purpose);
    let (baseline, admitted_intent) = observed_intent_baseline(intent);
    let policy = candidate_policy(&attester_artifact);
    let plan_limits = planning_limits();
    let invocation = link_invocation(&packages, selected, intent, admitted_intent, plan_limits);
    let target_lock = TargetLock::new(&config.target_lock)
        .unwrap_or_else(|_| panic!("semantic-matrix host could not reopen target lock"));
    let target_guard = target_lock
        .acquire_execution(&config.target_binding)
        .unwrap_or_else(|_| panic!("semantic-matrix host could not acquire target fence"));
    let journal = AttemptJournal::new(&journal_path)
        .unwrap_or_else(|_| panic!("semantic-matrix host could not open journal"));
    let session = journal
        .begin_session()
        .unwrap_or_else(|_| panic!("semantic-matrix host could not acquire journal session"));
    let request = DriverRequest {
        packages: &packages,
        selected_provider: selected,
        invocation: &invocation,
        baseline: &baseline,
        admission_policy: &policy,
        provider_artifact: &provider_artifact,
        attester_artifact: &attester_artifact,
        runtime: &runtime,
        target: &target_guard,
        authority: &authority,
        planning_limits: plan_limits,
        process_limits: process_limits(),
    };
    let checkpoint = terminal(start(&session, &request));
    match purpose {
        HostPurpose::Exact => assert_admitted_receipts(&checkpoint),
        HostPurpose::Conflict => assert_terminal_unable(&checkpoint),
        HostPurpose::Altered => assert_terminal_withheld(&checkpoint),
    }
}

fn assert_terminal_unable(checkpoint: &AttemptCheckpoint) {
    checkpoint
        .validate()
        .unwrap_or_else(|_| panic!("semantic-matrix Unable checkpoint was invalid"));
    assert_eq!(checkpoint.phase(), AttemptPhase::Unable);
    assert!(checkpoint.provider_decisive().is_some());
    assert_eq!(checkpoint.provider_receipts().len(), 1);
    assert!(matches!(
        checkpoint.provider_receipts(),
        [RetainedReceipt::Exact { .. }]
    ));
    assert!(checkpoint.candidate().is_none());
    assert!(checkpoint.assessment_request().is_none());
    assert!(checkpoint.attester_receipts().is_empty());
    assert!(checkpoint.attester_decisive().is_none());
    assert!(checkpoint.assessment().is_none());
    let Some(AttemptResolution::Unable { result }) = checkpoint.resolution() else {
        panic!("semantic-matrix conflict did not retain Unable resolution");
    };
    let result: CapabilityResult = serde_json::from_value(result.value().clone())
        .unwrap_or_else(|_| panic!("semantic-matrix Unable result decoding failed"));
    let CapabilityOutcome::Unable {
        failure,
        extensions,
    } = result.outcome
    else {
        panic!("semantic-matrix conflict result was not Unable");
    };
    assert_eq!(failure.kind, immutable_mode_conflict_failure_kind());
    assert_eq!(failure.detail, Value::Null);
    assert!(failure.extensions.is_empty());
    assert!(extensions.is_empty());
    assert!(result.evidence.is_empty());
    assert!(result.extensions.is_empty());
}

fn assert_terminal_withheld(checkpoint: &AttemptCheckpoint) {
    checkpoint
        .validate()
        .unwrap_or_else(|_| panic!("semantic-matrix Withheld checkpoint was invalid"));
    assert_eq!(checkpoint.phase(), AttemptPhase::Withheld);
    assert!(checkpoint.provider_decisive().is_some());
    assert!(checkpoint.candidate().is_some());
    assert!(checkpoint.assessment_request().is_some());
    assert!(checkpoint.attester_decisive().is_some());
    assert!(checkpoint.assessment().is_some());
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
    let assessment: ConformanceAssessment = serde_json::from_value(
        checkpoint
            .assessment()
            .expect("Withheld assessment exists")
            .value()
            .clone(),
    )
    .unwrap_or_else(|_| panic!("semantic-matrix assessment decoding failed"));
    assert_eq!(assessment.outcome, AssessmentOutcome::Failed);
    assert_eq!(
        assessment
            .checks
            .get("exact-contract")
            .map(|check| check.outcome),
        Some(AssessmentOutcome::Passed)
    );
    assert_eq!(
        assessment
            .checks
            .get("intent-output-relation")
            .map(|check| check.outcome),
        Some(AssessmentOutcome::Passed)
    );
    assert_eq!(
        assessment
            .checks
            .get("fleetd-observation")
            .map(|check| check.outcome),
        Some(AssessmentOutcome::Failed)
    );
    let Some(AttemptResolution::Withheld { decision }) = checkpoint.resolution() else {
        panic!("semantic-matrix altered result did not retain Withheld resolution");
    };
    let decision: AdmissionDecision = serde_json::from_value(decision.value().clone())
        .unwrap_or_else(|_| panic!("semantic-matrix Withheld decision decoding failed"));
    assert!(matches!(
        decision.verdict,
        AdmissionVerdict::Withhold {
            reason: AdmissionDenial::AssessmentFailed,
            ..
        }
    ));
}

fn load_matrix_config(path: &Path) -> MatrixConfig {
    assert!(
        path.is_absolute(),
        "semantic-matrix config must be absolute"
    );
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|_| panic!("semantic-matrix config inspection failed"));
    assert!(
        metadata.file_type().is_file()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o777 == 0o600,
        "semantic-matrix config metadata was invalid"
    );
    let mut file =
        File::open(path).unwrap_or_else(|_| panic!("semantic-matrix config open failed"));
    let bytes = read_matrix_bounded(&mut file, MAX_MATRIX_CONFIG_BYTES, "semantic-matrix config");
    let config: MatrixConfig = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("semantic-matrix config decoding failed"));
    assert_eq!(
        serde_json_canonicalizer::to_vec(&config)
            .unwrap_or_else(|_| panic!("semantic-matrix config canonicalization failed")),
        bytes,
        "semantic-matrix config was not canonical"
    );
    config.validate();
    config
}

/// Read the one live authority document from host-only standard input.
fn read_matrix_authority() -> AuthorityDocument {
    let mut input = std::io::stdin().lock();
    let bytes = read_matrix_bounded(
        &mut input,
        MAX_AUTHORITY_DOCUMENT_BYTES,
        "semantic-matrix host authority",
    );
    drop(input);
    parse_authority_document(&bytes)
        .unwrap_or_else(|_| panic!("semantic-matrix host authority decoding failed"))
}

fn handle_proxy_connection(stream: TcpStream, backend: SocketAddr, shared: &ProxyShared) {
    let Some(mut request) = read_request(stream) else {
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(|_| panic!("semantic-matrix proxy state was poisoned"));
        state.empty_connections = state
            .empty_connections
            .checked_add(1)
            .unwrap_or_else(|| panic!("semantic-matrix empty connection count overflowed"));
        assert!(usize::from(state.empty_connections) <= MAX_EMPTY_CONNECTIONS);
        return;
    };
    match (request.method(), request.target()) {
        ("POST", "/v1/direct-conversations") => {
            handle_post(&mut request, backend, shared);
        }
        ("GET", "/v1/conversations?include_archived=true") => {
            handle_get(&mut request, backend, shared);
        }
        _ => panic!("semantic-matrix proxy received an unexpected request"),
    }
}

fn handle_post(request: &mut HttpRequest, backend: SocketAddr, shared: &ProxyShared) {
    let (ordinal, barrier_arrivals) = {
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(|_| panic!("semantic-matrix proxy state was poisoned"));
        state.posts_arrived = state
            .posts_arrived
            .checked_add(1)
            .unwrap_or_else(|| panic!("semantic-matrix POST count overflowed"));
        let ordinal = state.posts_arrived;
        assert!(ordinal <= 5, "semantic-matrix received excess POSTs");
        if state.posts_arrived == 2 {
            shared.barrier.notify_all();
        }
        if ordinal <= 2 {
            let deadline = Instant::now() + HTTP_IO_DEADLINE;
            while state.posts_arrived < 2 {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .unwrap_or(Duration::ZERO);
                assert!(!remaining.is_zero(), "semantic-matrix POST barrier expired");
                let (next, result) = shared
                    .barrier
                    .wait_timeout(state, remaining)
                    .unwrap_or_else(|_| panic!("semantic-matrix POST barrier was poisoned"));
                state = next;
                assert!(
                    !(result.timed_out() && state.posts_arrived < 2),
                    "semantic-matrix POST barrier expired"
                );
            }
            (ordinal, state.posts_arrived)
        } else {
            (ordinal, 0)
        }
    };

    let request_observation = BodyObservation {
        bytes: request.body_bytes(),
        digest: request.body_digest(),
    };
    let backend_response = forward_request(request, backend);
    let backend_observation = response_observation(&backend_response);
    let delivered_response = if ordinal == 5 {
        altered_success_response(&backend_response)
    } else {
        HttpResponse::from_bytes(backend_response.bytes().to_vec())
    };
    let delivered_observation = response_observation(&delivered_response);
    request.write_response(&delivered_response);
    request.shutdown_write();
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(|_| panic!("semantic-matrix proxy state was poisoned"));
    state.posts.push(PostObservation {
        ordinal,
        request: request_observation,
        backend: backend_observation,
        delivered: delivered_observation,
        barrier_arrivals,
    });
}

fn handle_get(request: &mut HttpRequest, backend: SocketAddr, shared: &ProxyShared) {
    assert_eq!(request.body_bytes(), 0);
    let ordinal = {
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(|_| panic!("semantic-matrix proxy state was poisoned"));
        state.gets_arrived = state
            .gets_arrived
            .checked_add(1)
            .unwrap_or_else(|| panic!("semantic-matrix GET count overflowed"));
        assert!(
            state.gets_arrived <= 3,
            "semantic-matrix received excess GETs"
        );
        state.gets_arrived
    };
    let response = forward_request(request, backend);
    assert_eq!(response.status(), 200);
    let observation = response_observation(&response);
    request.write_response(&response);
    request.shutdown_write();
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(|_| panic!("semantic-matrix proxy state was poisoned"));
    state.gets.push(GetObservation {
        ordinal,
        response: observation,
    });
}

fn altered_success_response(response: &HttpResponse) -> HttpResponse {
    assert_eq!(response.status(), 200);
    let mut value: Value = serde_json::from_slice(response.body())
        .unwrap_or_else(|_| panic!("semantic-matrix altered response was not JSON"));
    let created_at = value
        .get_mut("created_at_ms")
        .and_then(|value| value.as_i64())
        .unwrap_or_else(|| panic!("semantic-matrix response lacked creation time"));
    let altered = created_at
        .checked_add(1)
        .filter(|value| *value <= ((1_i64 << 53) - 1))
        .unwrap_or_else(|| panic!("semantic-matrix creation time could not be altered safely"));
    value["created_at_ms"] = json!(altered);
    let body = serde_json::to_vec(&value)
        .unwrap_or_else(|_| panic!("semantic-matrix altered response encoding failed"));
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(&body);
    let altered = HttpResponse::from_bytes(bytes);
    assert_ne!(altered.body_digest(), response.body_digest());
    altered
}

fn response_observation(response: &HttpResponse) -> ResponseObservation {
    ResponseObservation {
        status: response.status(),
        body: BodyObservation {
            bytes: response.body_bytes(),
            digest: response.body_digest(),
        },
    }
}

fn validate_matrix_private_directory(path: &Path, surface: &str) {
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

fn persist_matrix_canonical(path: &Path, value: &impl Serialize) {
    assert!(path.is_absolute(), "canonical output path must be absolute");
    let bytes = serde_json_canonicalizer::to_vec(value)
        .unwrap_or_else(|_| panic!("semantic-matrix canonicalization failed"));
    assert!(bytes.len() <= MAX_MATRIX_CONFIG_BYTES);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|_| panic!("semantic-matrix canonical output creation failed"));
    file.write_all(&bytes)
        .unwrap_or_else(|_| panic!("semantic-matrix canonical output write failed"));
    file.sync_all()
        .unwrap_or_else(|_| panic!("semantic-matrix canonical output sync failed"));
    File::open(
        path.parent()
            .unwrap_or_else(|| panic!("canonical output parent was absent")),
    )
    .and_then(|directory| directory.sync_all())
    .unwrap_or_else(|_| panic!("semantic-matrix canonical output parent sync failed"));
}

fn read_matrix_canonical_stdin<T>(bound: usize, surface: &str) -> T
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let mut input = std::io::stdin().lock();
    let bytes = read_matrix_bounded(&mut input, bound, surface);
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

fn read_matrix_bounded(reader: &mut impl Read, bound: usize, surface: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    reader
        .take(u64::try_from(bound + 1).expect("semantic-matrix byte bound fits u64"))
        .read_to_end(&mut bytes)
        .unwrap_or_else(|_| panic!("{surface} read failed"));
    assert!(bytes.len() <= bound, "{surface} exceeded its byte bound");
    bytes
}
