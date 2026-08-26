#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

use fleetd_direct_conversation_command_abi::AuthorityDocument;
use fleetd_direct_conversation_external_host_proof::native::{
    QualifiedNativeArtifact, qualify_provider,
};
use fleetd_direct_conversation_external_host_proof::supervisor::{
    NATIVE_SUPERVISOR_PROFILE_ID, PROCESS_RECEIPT_PROTOCOL, ProcessLimits, ProcessTermination,
    SupervisorError, launch,
};
use gooir_fleetd_direct_conversation_package_proof::{
    StageRequest, VerifiedPackageSet, stage, verify_package_set,
};
use rustix::io::fcntl_dupfd_cloexec;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const TARGET: &str = "fleetd:supervisor-proof-target";
const ENDPOINT: &str = "http://127.0.0.1:43123/";
const TOKEN: &str = "supervisor-proof-bearer-secret-never-retained";

fn executable_bytes(marker: u8) -> Vec<u8> {
    let mut bytes = fs::read(env!("CARGO_BIN_EXE_native-supervisor-fixture"))
        .expect("fixture executable bytes");
    bytes.extend_from_slice(b"\nproof-inert-trailing-marker:");
    bytes.push(marker);
    bytes
}

fn packages() -> &'static VerifiedPackageSet {
    static PACKAGES: OnceLock<VerifiedPackageSet> = OnceLock::new();
    PACKAGES.get_or_init(|| {
        let source = TempDir::new().expect("source root");
        fs::set_permissions(source.path(), fs::Permissions::from_mode(0o700))
            .expect("source root mode");
        let reqwest = source.path().join("reqwest");
        let ureq = source.path().join("ureq");
        let attester = source.path().join("attester");
        for (path, marker) in [(&reqwest, 1), (&ureq, 2), (&attester, 3)] {
            fs::write(path, executable_bytes(marker)).expect("write exact fixture artifact");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("fixture artifact mode");
        }
        let package_root = source.path().join("packages");
        stage(StageRequest {
            reqwest_command: reqwest,
            ureq_command: ureq,
            attester_command: attester,
            output_root: package_root.clone(),
        })
        .expect("stage fixture package set exactly once");
        let retained = verify_package_set(&package_root).expect("verify fixture package set");
        let deleted = source.path().to_path_buf();
        drop(source);
        assert!(
            !deleted.exists(),
            "qualification must use retained package bytes"
        );
        retained
    })
}

fn qualified_fixture() -> (TempDir, QualifiedNativeArtifact) {
    let parent = TempDir::new().expect("private parent");
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700))
        .expect("private parent mode");
    let packages = packages();
    let artifact = qualify_provider(packages, &packages.report().providers[0], parent.path())
        .expect("qualify fixture through package proof");
    (parent, artifact)
}

fn authority() -> AuthorityDocument {
    AuthorityDocument::new(
        TARGET,
        format!("sha256:{}", "a".repeat(64)),
        "operator-credential/revision-supervisor-proof",
        ENDPOINT,
        TOKEN,
        2_000,
        64 * 1024,
    )
    .expect("test authority")
}

fn limits(stdout: usize, stderr: usize, wall_time: Duration) -> ProcessLimits {
    ProcessLimits::new(64 * 1024, stdout, stderr, wall_time).expect("process limits")
}

#[test]
fn qualified_process_gets_only_fixed_argv_empty_env_private_cwd_and_fds_zero_through_three() {
    let (_parent, artifact) = qualified_fixture();
    let probe_source = File::open("/dev/null").expect("probe source");
    let probe = fcntl_dupfd_cloexec(&probe_source, 200).expect("high probe fd");
    let input = serde_json::to_vec(&json!({
        "mode": "basic",
        "probe_fd": probe.as_raw_fd(),
    }))
    .expect("fixture input");
    let process_limits = limits(64 * 1024, 64 * 1024, Duration::from_secs(3));
    let receipt =
        launch(&artifact, &authority(), &input, process_limits).expect("supervised fixture");

    receipt.validate().expect("bound process receipt");
    assert_eq!(receipt.protocol(), PROCESS_RECEIPT_PROTOCOL);
    assert_eq!(
        receipt.supervisor_profile_id(),
        NATIVE_SUPERVISOR_PROFILE_ID
    );
    assert_eq!(receipt.artifact_lock_id(), artifact.lock().lock_id());
    assert_eq!(receipt.limits().max_stdin_bytes(), 64 * 1024);
    assert_eq!(receipt.limits().max_stdout_bytes(), 64 * 1024);
    assert_eq!(receipt.limits().max_stderr_bytes(), 64 * 1024);
    assert_eq!(receipt.limits().wall_time_ms(), 3_000);
    assert_eq!(receipt.input().stdin_bytes(), input.len() as u64);
    assert_eq!(
        receipt.input().stdin_digest(),
        format!("sha256:{:x}", Sha256::digest(&input))
    );
    assert_eq!(receipt.input().authority().target(), TARGET);
    assert_eq!(
        receipt.input().authority().protocol(),
        fleetd_direct_conversation_command_abi::AUTHORITY_PROTOCOL
    );
    assert_eq!(
        receipt.input().authority().endpoint_mapping_digest(),
        format!("sha256:{}", "a".repeat(64))
    );
    assert_eq!(
        receipt.input().authority().credential_revision(),
        "operator-credential/revision-supervisor-proof"
    );
    assert_eq!(receipt.input().authority().http_timeout_ms(), 2_000);
    assert_eq!(receipt.input().authority().max_response_bytes(), 64 * 1024);
    assert_eq!(
        receipt.termination(),
        ProcessTermination::Exited { code: 0 }
    );
    assert!(receipt.decisive_eligible());
    assert!(receipt.stderr().bytes().is_empty());
    let output: Value = serde_json::from_slice(receipt.stdout().bytes()).expect("fixture JSON");
    assert_eq!(output["argv"], json!(["fleetd-native-command"]));
    assert_eq!(output["environment_count"], 0);
    assert_eq!(output["extra_open_fds"], json!([]));
    assert_eq!(output["cwd_empty"], true);
    assert_eq!(output["probe_open"], false);
    assert_eq!(output["stdin_len"], input.len());
    assert_eq!(
        output["stdin_digest"],
        format!("sha256:{:x}", Sha256::digest(&input))
    );
    assert_eq!(output["target"], TARGET);
}

#[test]
fn stdout_and_stderr_overflow_are_bounded_active_enforcement() {
    for (mode, stdout_bound, stderr_bound) in [
        ("stdout_overflow", 257, 4 * 1024),
        ("stderr_overflow", 4 * 1024, 263),
    ] {
        let (_parent, artifact) = qualified_fixture();
        let input = serde_json::to_vec(&json!({"mode": mode, "bytes": 1024 * 1024}))
            .expect("overflow input");
        let receipt = launch(
            &artifact,
            &authority(),
            &input,
            limits(stdout_bound, stderr_bound, Duration::from_secs(3)),
        )
        .expect("bounded overflow receipt");
        assert!(!receipt.decisive_eligible());
        if mode == "stdout_overflow" {
            assert!(receipt.stdout().overflowed());
            assert_eq!(receipt.stdout().bytes().len(), stdout_bound);
            assert!(!receipt.stderr().overflowed());
        } else {
            assert!(receipt.stderr().overflowed());
            assert_eq!(receipt.stderr().bytes().len(), stderr_bound);
            assert!(!receipt.stdout().overflowed());
        }
    }
}

#[test]
fn nonzero_exit_is_exact_operational_evidence_but_never_decisive() {
    let (_parent, artifact) = qualified_fixture();
    let input = serde_json::to_vec(&json!({"mode": "nonzero"})).expect("nonzero input");
    let receipt = launch(
        &artifact,
        &authority(),
        &input,
        limits(1024, 1024, Duration::from_secs(3)),
    )
    .expect("nonzero receipt");
    assert_eq!(
        receipt.termination(),
        ProcessTermination::Exited { code: 23 }
    );
    assert!(!receipt.decisive_eligible());
    receipt.validate().expect("valid bound receipt");
}

#[test]
fn timeout_kills_descendant_process_group_before_it_can_mutate_state() {
    let (_parent, artifact) = qualified_fixture();
    let marker_root = TempDir::new().expect("marker root");
    let marker = marker_root.path().join("descendant-marker");
    let input = serde_json::to_vec(&json!({
        "mode": "timeout_group",
        "marker_path": marker,
    }))
    .expect("timeout input");
    let receipt = launch(
        &artifact,
        &authority(),
        &input,
        limits(16 * 1024, 16 * 1024, Duration::from_millis(100)),
    )
    .expect("timeout receipt");
    assert!(receipt.enforcement().timed_out());
    assert!(!receipt.decisive_eligible());
    assert_eq!(
        receipt.termination(),
        ProcessTermination::Signaled { signal: 9 }
    );
    thread::sleep(Duration::from_millis(850));
    assert!(!marker.exists(), "descendant escaped timeout cleanup");
}

#[test]
fn natural_child_exit_still_kills_lingering_descendants_before_pipe_joins() {
    let (_parent, artifact) = qualified_fixture();
    let marker_root = TempDir::new().expect("marker root");
    let marker = marker_root.path().join("descendant-marker");
    let input = serde_json::to_vec(&json!({
        "mode": "exit_with_descendant",
        "marker_path": marker,
    }))
    .expect("descendant input");
    let receipt = launch(
        &artifact,
        &authority(),
        &input,
        limits(16 * 1024, 16 * 1024, Duration::from_secs(3)),
    )
    .expect("natural-exit receipt");
    assert_eq!(
        receipt.termination(),
        ProcessTermination::Exited { code: 0 }
    );
    assert!(receipt.decisive_eligible());
    thread::sleep(Duration::from_millis(850));
    assert!(!marker.exists(), "descendant escaped terminal cleanup");
}

#[test]
fn sensitive_output_is_redacted_and_never_decisive_or_debuggable() {
    let (_parent, artifact) = qualified_fixture();
    let authority = authority();
    let encoded_authority = authority.encode_for_pipe().expect("encoded authority");
    let input = serde_json::to_vec(&json!({"mode": "secret"})).expect("secret input");
    let receipt = launch(
        &artifact,
        &authority,
        &input,
        limits(64 * 1024, 64 * 1024, Duration::from_secs(3)),
    )
    .expect("redacted receipt");

    assert!(!receipt.decisive_eligible());
    assert!(receipt.stdout().redacted());
    assert!(receipt.stderr().redacted());
    for retained in [receipt.stdout().bytes(), receipt.stderr().bytes()] {
        assert!(!contains(retained, ENDPOINT.as_bytes()));
        assert!(!contains(retained, TOKEN.as_bytes()));
        assert!(!contains(retained, &encoded_authority));
    }
    for rendered in [
        format!("{receipt:?}").into_bytes(),
        serde_json::to_vec(&receipt).expect("receipt JSON"),
    ] {
        assert!(!contains(&rendered, ENDPOINT.as_bytes()));
        assert!(!contains(&rendered, TOKEN.as_bytes()));
        assert!(!contains(&rendered, &encoded_authority));
    }
}

#[test]
fn authority_is_refused_from_stdin_without_entering_errors() {
    let (_parent, artifact) = qualified_fixture();
    let authority = authority();
    for sensitive in [
        ENDPOINT.as_bytes().to_vec(),
        TOKEN.as_bytes().to_vec(),
        authority.encode_for_pipe().expect("encoded authority"),
    ] {
        let error = launch(
            &artifact,
            &authority,
            &sensitive,
            limits(1024, 1024, Duration::from_secs(1)),
        )
        .expect_err("sensitive stdin must fail closed");
        assert!(matches!(error, SupervisorError::SensitiveStdin));
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(ENDPOINT));
        assert!(!rendered.contains(TOKEN));
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
