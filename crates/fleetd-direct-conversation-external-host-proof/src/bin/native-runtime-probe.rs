#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::thread;
use std::time::Duration;

use fleetd_direct_conversation_command_abi::AuthorityDocument;
use fleetd_direct_conversation_external_host_proof::journal::NativeRuntimeLock;
use fleetd_direct_conversation_external_host_proof::native::{
    QualifiedNativeArtifact, qualify_attester, qualify_provider,
};
use fleetd_direct_conversation_external_host_proof::runtime::{
    NativeRuntimeQualification, QualifiedNativeRuntime, qualify_native_runtime,
    recover_native_runtime,
};
use fleetd_direct_conversation_external_host_proof::supervisor::{
    NATIVE_SUPERVISOR_PROFILE_ID, PROCESS_RECEIPT_PROTOCOL, ProcessLimits, ProcessTermination,
    SupervisorError, launch,
};
use gooir_fleetd_direct_conversation_package_proof::{StageRequest, stage, verify_package_set};
use rustix::io::fcntl_dupfd_cloexec;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const TARGET: &str = "fleetd:native-runtime-probe";
const ENDPOINT: &str = "http://127.0.0.1:43123/";
const TOKEN: &str = "native-runtime-probe-secret-never-retained";
const CREDENTIAL_REVISION: &str = "operator-credential/revision-native-runtime-probe";

fn main() {
    if let Err(error) = run() {
        eprintln!("native runtime probe failed closed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), &'static str> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let mode = arguments.next().ok_or("missing mode")?;
    let mode = mode.to_str().ok_or("invalid mode")?;
    let fixture = arguments.next().ok_or("missing fixture")?;
    if arguments.next().is_some() {
        return Err("unexpected argument");
    }
    let (private_parent, packages) = stage_packages(Path::new(&fixture))?;
    let provider = qualify_provider(
        &packages,
        &packages.report().providers[0],
        private_parent.path(),
    )
    .map_err(|_| "provider qualification")?;
    let attester = qualify_attester(
        &packages,
        &packages.report().attester,
        private_parent.path(),
    )
    .map_err(|_| "attester qualification")?;

    if mode == "recover" {
        return run_recovery(&provider, &attester);
    }

    let runtime = qualify_native_runtime(provider.lock(), attester.lock())
        .map_err(|_| "runtime qualification")?;
    match mode {
        "qualify" => run_composition(&runtime, &provider, &attester),
        "isolation" => run_isolation(&runtime, &provider),
        "overflow" => run_overflow(&runtime, &provider),
        "nonzero" => run_nonzero(&runtime, &provider),
        "timeout-group" => run_timeout_group(&runtime, &provider),
        "descendant-cleanup" => run_descendant_cleanup(&runtime, &provider),
        "secret-output" => run_secret_output(&runtime, &provider),
        "sensitive-stdin" => run_sensitive_stdin(&runtime, &provider),
        _ => Err("unknown mode"),
    }
}

fn run_composition(
    runtime: &QualifiedNativeRuntime,
    provider: &QualifiedNativeArtifact,
    attester: &QualifiedNativeArtifact,
) -> Result<(), &'static str> {
    let authority = authority()?;
    let process_limits = limits(64 * 1024, 64 * 1024, Duration::from_secs(30))?;
    let input =
        serde_json::to_vec(&json!({"mode": "basic", "probe_fd": -1})).map_err(|_| "input")?;
    let provider_receipt = launch(runtime, provider, &authority, &input, process_limits)
        .map_err(|_| "provider launch")?;
    let attester_receipt = launch(runtime, attester, &authority, &input, process_limits)
        .map_err(|_| "attester launch")?;
    for receipt in [&provider_receipt, &attester_receipt] {
        receipt.validate().map_err(|_| "receipt")?;
        ensure(
            receipt.runtime_qualification_id() == runtime.qualification().qualification_id(),
            "runtime receipt mismatch",
        )?;
    }
    ensure(
        provider_receipt.artifact_lock_id() == provider.lock().lock_id()
            && attester_receipt.artifact_lock_id() == attester.lock().lock_id()
            && provider_receipt.runtime_qualification_id()
                == attester_receipt.runtime_qualification_id(),
        "receipt composition mismatch",
    )?;
    write_json(&ProbeQualification {
        runtime_lock: runtime.lock(),
        runtime_qualification: runtime.qualification(),
        runtime_qualification_id: runtime.qualification().qualification_id(),
        provider_artifact_lock_id: provider.lock().lock_id(),
        attester_artifact_lock_id: attester.lock().lock_id(),
        provider_receipt_id: provider_receipt.receipt_id(),
        attester_receipt_id: attester_receipt.receipt_id(),
    })
}

fn run_recovery(
    provider: &QualifiedNativeArtifact,
    attester: &QualifiedNativeArtifact,
) -> Result<(), &'static str> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(16 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|_| "read lock")?;
    let expected: NativeRuntimeLock = serde_json::from_slice(&bytes).map_err(|_| "decode lock")?;
    let runtime = recover_native_runtime(&expected, provider.lock(), attester.lock())
        .map_err(|_| "runtime recovery")?;
    ensure(runtime.lock() == &expected, "recovered lock mismatch")?;

    let authority = authority()?;
    let input =
        serde_json::to_vec(&json!({"mode": "basic", "probe_fd": -1})).map_err(|_| "input")?;
    let receipt = launch(
        &runtime,
        provider,
        &authority,
        &input,
        limits(64 * 1024, 64 * 1024, Duration::from_secs(30))?,
    )
    .map_err(|_| "recovered runtime launch")?;
    receipt.validate().map_err(|_| "recovered receipt")?;
    ensure(
        receipt.runtime_qualification_id() == runtime.qualification().qualification_id()
            && receipt.runtime_qualification_id() == expected.runtime_digest()
            && receipt.artifact_lock_id() == provider.lock().lock_id()
            && receipt.decisive_eligible(),
        "recovered launch binding mismatch",
    )?;
    write_json(&RecoveredProbe {
        runtime_lock: runtime.lock(),
        runtime_qualification_id: runtime.qualification().qualification_id(),
        artifact_lock_id: provider.lock().lock_id(),
        receipt_runtime_qualification_id: receipt.runtime_qualification_id(),
        receipt_artifact_lock_id: receipt.artifact_lock_id(),
        receipt_id: receipt.receipt_id(),
    })
}

fn run_isolation(
    runtime: &QualifiedNativeRuntime,
    provider: &QualifiedNativeArtifact,
) -> Result<(), &'static str> {
    let probe_source = File::open("/dev/null").map_err(|_| "probe source")?;
    let probe = fcntl_dupfd_cloexec(&probe_source, 200).map_err(|_| "probe fd")?;
    let input = serde_json::to_vec(&json!({
        "mode": "basic",
        "probe_fd": probe.as_raw_fd(),
    }))
    .map_err(|_| "fixture input")?;
    let authority = authority()?;
    let receipt = launch(
        runtime,
        provider,
        &authority,
        &input,
        limits(64 * 1024, 64 * 1024, Duration::from_secs(3))?,
    )
    .map_err(|_| "isolation launch")?;
    receipt.validate().map_err(|_| "isolation receipt")?;
    ensure(
        receipt.protocol() == PROCESS_RECEIPT_PROTOCOL,
        "receipt protocol",
    )?;
    ensure(
        receipt.supervisor_profile_id() == NATIVE_SUPERVISOR_PROFILE_ID,
        "supervisor profile",
    )?;
    ensure(
        receipt.runtime_qualification_id() == runtime.qualification().qualification_id()
            && receipt.artifact_lock_id() == provider.lock().lock_id(),
        "isolation receipt binding",
    )?;
    ensure(
        receipt.limits().max_stdin_bytes() == 64 * 1024
            && receipt.limits().max_stdout_bytes() == 64 * 1024
            && receipt.limits().max_stderr_bytes() == 64 * 1024
            && receipt.limits().wall_time_ms() == 3_000,
        "applied limits",
    )?;
    ensure(
        receipt.input().stdin_bytes() == input.len() as u64
            && receipt.input().stdin_digest() == format!("sha256:{:x}", Sha256::digest(&input)),
        "stdin binding",
    )?;
    let correlation = receipt.input().authority();
    ensure(
        correlation.target() == TARGET
            && correlation.protocol() == fleetd_direct_conversation_command_abi::AUTHORITY_PROTOCOL
            && correlation.endpoint_mapping_digest() == format!("sha256:{}", "a".repeat(64))
            && correlation.credential_revision() == CREDENTIAL_REVISION
            && correlation.http_timeout_ms() == 2_000
            && correlation.max_response_bytes() == 64 * 1024,
        "authority correlation",
    )?;
    ensure(
        receipt.termination() == ProcessTermination::Exited { code: 0 }
            && receipt.decisive_eligible()
            && receipt.stderr().bytes().is_empty(),
        "isolation termination",
    )?;
    let output: Value =
        serde_json::from_slice(receipt.stdout().bytes()).map_err(|_| "fixture output")?;
    ensure(
        output["argv"] == json!(["fleetd-native-command"])
            && output["environment_count"] == 0
            && output["extra_open_fds"] == json!([])
            && output["cwd_empty"] == true
            && output["probe_open"] == false
            && output["stdin_len"] == input.len()
            && output["stdin_digest"] == format!("sha256:{:x}", Sha256::digest(&input))
            && output["target"] == TARGET,
        "argv environment cwd or fd isolation",
    )?;
    write_success("isolation", runtime)
}

fn run_overflow(
    runtime: &QualifiedNativeRuntime,
    provider: &QualifiedNativeArtifact,
) -> Result<(), &'static str> {
    for (mode, stdout_bound, stderr_bound) in [
        ("stdout_overflow", 257, 4 * 1024),
        ("stderr_overflow", 4 * 1024, 263),
    ] {
        let input = serde_json::to_vec(&json!({"mode": mode, "bytes": 1024 * 1024}))
            .map_err(|_| "overflow input")?;
        let receipt = launch(
            runtime,
            provider,
            &authority()?,
            &input,
            limits(stdout_bound, stderr_bound, Duration::from_secs(3))?,
        )
        .map_err(|_| "overflow launch")?;
        receipt.validate().map_err(|_| "overflow receipt")?;
        ensure(!receipt.decisive_eligible(), "overflow was decisive")?;
        if mode == "stdout_overflow" {
            ensure(
                receipt.stdout().overflowed()
                    && receipt.stdout().bytes().len() == stdout_bound
                    && !receipt.stderr().overflowed(),
                "stdout overflow enforcement",
            )?;
        } else {
            ensure(
                receipt.stderr().overflowed()
                    && receipt.stderr().bytes().len() == stderr_bound
                    && !receipt.stdout().overflowed(),
                "stderr overflow enforcement",
            )?;
        }
    }
    write_success("overflow", runtime)
}

fn run_nonzero(
    runtime: &QualifiedNativeRuntime,
    provider: &QualifiedNativeArtifact,
) -> Result<(), &'static str> {
    let input = serde_json::to_vec(&json!({"mode": "nonzero"})).map_err(|_| "nonzero input")?;
    let receipt = launch(
        runtime,
        provider,
        &authority()?,
        &input,
        limits(1024, 1024, Duration::from_secs(3))?,
    )
    .map_err(|_| "nonzero launch")?;
    receipt.validate().map_err(|_| "nonzero receipt")?;
    ensure(
        receipt.termination() == ProcessTermination::Exited { code: 23 }
            && !receipt.decisive_eligible(),
        "nonzero eligibility",
    )?;
    write_success("nonzero", runtime)
}

fn run_timeout_group(
    runtime: &QualifiedNativeRuntime,
    provider: &QualifiedNativeArtifact,
) -> Result<(), &'static str> {
    let marker_root = TempDir::new().map_err(|_| "marker root")?;
    let marker = marker_root.path().join("descendant-marker");
    let input = serde_json::to_vec(&json!({
        "mode": "timeout_group",
        "marker_path": marker,
    }))
    .map_err(|_| "timeout input")?;
    let receipt = launch(
        runtime,
        provider,
        &authority()?,
        &input,
        limits(16 * 1024, 16 * 1024, Duration::from_millis(100))?,
    )
    .map_err(|_| "timeout launch")?;
    ensure(
        receipt.enforcement().timed_out()
            && !receipt.decisive_eligible()
            && receipt.termination() == ProcessTermination::Signaled { signal: 9 },
        "timeout process group enforcement",
    )?;
    thread::sleep(Duration::from_millis(850));
    ensure(!marker.exists(), "descendant escaped timeout cleanup")?;
    write_success("timeout-group", runtime)
}

fn run_descendant_cleanup(
    runtime: &QualifiedNativeRuntime,
    provider: &QualifiedNativeArtifact,
) -> Result<(), &'static str> {
    let marker_root = TempDir::new().map_err(|_| "marker root")?;
    let marker = marker_root.path().join("descendant-marker");
    let input = serde_json::to_vec(&json!({
        "mode": "exit_with_descendant",
        "marker_path": marker,
    }))
    .map_err(|_| "descendant input")?;
    let receipt = launch(
        runtime,
        provider,
        &authority()?,
        &input,
        limits(16 * 1024, 16 * 1024, Duration::from_secs(3))?,
    )
    .map_err(|_| "descendant launch")?;
    ensure(
        receipt.termination() == ProcessTermination::Exited { code: 0 }
            && receipt.decisive_eligible(),
        "natural exit receipt",
    )?;
    thread::sleep(Duration::from_millis(850));
    ensure(!marker.exists(), "descendant escaped terminal cleanup")?;
    write_success("descendant-cleanup", runtime)
}

fn run_secret_output(
    runtime: &QualifiedNativeRuntime,
    provider: &QualifiedNativeArtifact,
) -> Result<(), &'static str> {
    let authority = authority()?;
    let encoded_authority = authority
        .encode_for_pipe()
        .map_err(|_| "encoded authority")?;
    let input = serde_json::to_vec(&json!({"mode": "secret"})).map_err(|_| "secret input")?;
    let receipt = launch(
        runtime,
        provider,
        &authority,
        &input,
        limits(64 * 1024, 64 * 1024, Duration::from_secs(3))?,
    )
    .map_err(|_| "secret output launch")?;
    ensure(
        !receipt.decisive_eligible() && receipt.stdout().redacted() && receipt.stderr().redacted(),
        "secret output redaction",
    )?;
    for retained in [receipt.stdout().bytes(), receipt.stderr().bytes()] {
        ensure(
            !contains(retained, ENDPOINT.as_bytes())
                && !contains(retained, TOKEN.as_bytes())
                && !contains(retained, &encoded_authority),
            "secret retained in stream evidence",
        )?;
    }
    for rendered in [
        format!("{receipt:?}").into_bytes(),
        serde_json::to_vec(&receipt).map_err(|_| "receipt json")?,
    ] {
        ensure(
            !contains(&rendered, ENDPOINT.as_bytes())
                && !contains(&rendered, TOKEN.as_bytes())
                && !contains(&rendered, &encoded_authority),
            "secret retained in receipt",
        )?;
    }
    write_success("secret-output", runtime)
}

fn run_sensitive_stdin(
    runtime: &QualifiedNativeRuntime,
    provider: &QualifiedNativeArtifact,
) -> Result<(), &'static str> {
    let authority = authority()?;
    for sensitive in [
        ENDPOINT.as_bytes().to_vec(),
        TOKEN.as_bytes().to_vec(),
        authority
            .encode_for_pipe()
            .map_err(|_| "encoded authority")?,
    ] {
        let error = launch(
            runtime,
            provider,
            &authority,
            &sensitive,
            limits(1024, 1024, Duration::from_secs(1))?,
        )
        .expect_err("sensitive stdin must fail closed");
        ensure(
            matches!(error, SupervisorError::SensitiveStdin),
            "wrong sensitive stdin error",
        )?;
        let rendered = format!("{error:?} {error}");
        ensure(
            !rendered.contains(ENDPOINT) && !rendered.contains(TOKEN),
            "secret entered error",
        )?;
    }
    write_success("sensitive-stdin", runtime)
}

fn authority() -> Result<AuthorityDocument, &'static str> {
    AuthorityDocument::new(
        TARGET,
        format!("sha256:{}", "a".repeat(64)),
        CREDENTIAL_REVISION,
        ENDPOINT,
        TOKEN,
        2_000,
        64 * 1024,
    )
    .map_err(|_| "authority")
}

fn limits(
    stdout: usize,
    stderr: usize,
    wall_time: Duration,
) -> Result<ProcessLimits, &'static str> {
    ProcessLimits::new(64 * 1024, stdout, stderr, wall_time).map_err(|_| "limits")
}

fn stage_packages(
    fixture: &Path,
) -> Result<
    (
        TempDir,
        gooir_fleetd_direct_conversation_package_proof::VerifiedPackageSet,
    ),
    &'static str,
> {
    let source = TempDir::new().map_err(|_| "source root")?;
    fs::set_permissions(source.path(), fs::Permissions::from_mode(0o700))
        .map_err(|_| "source root mode")?;
    let base = fs::read(fixture).map_err(|_| "fixture bytes")?;
    let mut paths = Vec::new();
    for (name, marker) in [("reqwest", 1u8), ("ureq", 2), ("attester", 3)] {
        let path = source.path().join(name);
        let mut bytes = base.clone();
        bytes.extend_from_slice(b"\nproof-inert-trailing-marker:");
        bytes.push(marker);
        fs::write(&path, bytes).map_err(|_| "write fixture")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|_| "fixture mode")?;
        paths.push(path);
    }
    let package_root = source.path().join("packages");
    stage(StageRequest {
        reqwest_command: paths.remove(0),
        ureq_command: paths.remove(0),
        attester_command: paths.remove(0),
        output_root: package_root.clone(),
    })
    .map_err(|_| "stage packages")?;
    let packages = verify_package_set(&package_root).map_err(|_| "verify packages")?;
    let private_parent = TempDir::new().map_err(|_| "private parent")?;
    fs::set_permissions(private_parent.path(), fs::Permissions::from_mode(0o700))
        .map_err(|_| "private parent mode")?;
    Ok((private_parent, packages))
}

fn write_success(mode: &'static str, runtime: &QualifiedNativeRuntime) -> Result<(), &'static str> {
    write_json(&ProbeSuccess {
        mode,
        runtime_qualification_id: runtime.qualification().qualification_id(),
    })
}

fn ensure(condition: bool, error: &'static str) -> Result<(), &'static str> {
    if condition { Ok(()) } else { Err(error) }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[derive(Serialize)]
struct ProbeQualification<'a> {
    runtime_lock: &'a NativeRuntimeLock,
    runtime_qualification: &'a NativeRuntimeQualification,
    runtime_qualification_id: &'a str,
    provider_artifact_lock_id: &'a str,
    attester_artifact_lock_id: &'a str,
    provider_receipt_id: &'a str,
    attester_receipt_id: &'a str,
}

#[derive(Serialize)]
struct RecoveredProbe<'a> {
    runtime_lock: &'a NativeRuntimeLock,
    runtime_qualification_id: &'a str,
    artifact_lock_id: &'a str,
    receipt_runtime_qualification_id: &'a str,
    receipt_artifact_lock_id: &'a str,
    receipt_id: &'a str,
}

#[derive(Serialize)]
struct ProbeSuccess<'a> {
    mode: &'static str,
    runtime_qualification_id: &'a str,
}

fn write_json(value: &impl Serialize) -> Result<(), &'static str> {
    serde_json::to_writer(io::stdout().lock(), value).map_err(|_| "write result")
}
