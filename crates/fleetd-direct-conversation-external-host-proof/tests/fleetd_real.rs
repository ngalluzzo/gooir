//! Ignored optimized proof against the real Fleetd daemon and release commands.
//!
//! Build exact inputs before running:
//!
//!     cd "$FLEETD_REPO"
//!     cargo build --release --locked --bin fleetd
//!     cd "$GOOIR_REPO"
//!     cargo build --release --locked \
//!       -p fleetd-direct-conversation-reqwest-provider \
//!       -p fleetd-direct-conversation-ureq-provider \
//!       -p fleetd-direct-conversation-attester
//!     GOOIR_FLEETD_REPO="$FLEETD_REPO" \
//!     GOOIR_FLEETD_BINARY="$FLEETD_REPO/target/release/fleetd" \
//!     GOOIR_REQWEST_PROVIDER_BINARY="$GOOIR_REPO/target/release/fleetd-direct-conversation-reqwest-provider" \
//!     GOOIR_UREQ_PROVIDER_BINARY="$GOOIR_REPO/target/release/fleetd-direct-conversation-ureq-provider" \
//!     GOOIR_DIRECT_CONVERSATION_ATTESTER_BINARY="$GOOIR_REPO/target/release/fleetd-direct-conversation-attester" \
//!     cargo test --release -p fleetd-direct-conversation-external-host-proof \
//!       --test fleetd_real -- --ignored --exact \
//!       real_fleetd_two_provider_restart_and_terminal_replay
//!
//! This direct slice proves create/resolve through stable public state. The
//! separate `fleetd_crash` ignored proof closes the exact HTTP-status and
//! commit-before-response recovery window through a bounded loopback proxy.

#![cfg(target_os = "macos")]

#[path = "support/fleetd_http.rs"]
pub(crate) mod http;

#[path = "support/fleetd_crash.rs"]
#[allow(dead_code)]
pub(crate) mod crash;

#[path = "support/fleetd_semantic_matrix.rs"]
#[allow(dead_code)]
pub(crate) mod semantic_matrix;

#[path = "support/fleetd_attester.rs"]
#[allow(dead_code)]
pub(crate) mod attester;

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fleetd_direct_conversation_attester::implementation_id as attester_implementation_id;
use fleetd_direct_conversation_command_abi::AuthorityDocument;
use fleetd_direct_conversation_contract::{
    AgentId, DeliveryMode, DirectConversationRef, DirectMember, DirectPairIntent, FleetdTarget,
    direct_conversation_ref_suite_id, direct_conversation_ref_value_kind, intent_port_name,
    open_or_resolve_capability_spec,
};
use fleetd_direct_conversation_external_host_proof::driver::{
    AttemptProcessLimits, DriverProgress, DriverRequest, ParkReason, resume, start,
};
use fleetd_direct_conversation_external_host_proof::journal::{
    AttemptCheckpoint, AttemptJournal, AttemptPhase, AttemptResolution, RetainedReceipt,
};
use fleetd_direct_conversation_external_host_proof::native::{
    QualifiedNativeArtifact, qualify_attester, qualify_provider,
};
use fleetd_direct_conversation_external_host_proof::runtime::{
    QualifiedNativeRuntime, qualify_native_runtime,
};
use fleetd_direct_conversation_external_host_proof::supervisor::ProcessLimits;
use fleetd_direct_conversation_external_host_proof::target::{
    TargetDeployment, TargetExecutionGuard, TargetLock,
};
use gooir_capability::authority::{
    AdmissionAuthorityId, AdmissionLedger, AdmissionOutcome, AdmissionPolicy, AdmissionSnapshot,
    AuthorityBasis, ConformanceAttester, ConformanceAuthority, ObservationAuthority,
    ObservationSourceId, SourceObservation,
};
use gooir_capability::protocol::{
    AdmittedFactRef, ArtifactDigest, EvidenceDigest, EvidenceKindId, EvidenceRef, ImplementationId,
    LinkedInput,
};
use gooir_fleetd_direct_conversation_package_proof::{
    ProviderPackageBinding, REQWEST_PACKAGE, StageRequest, UREQ_PACKAGE, VerifiedPackageSet, stage,
    verify_package_set,
};
use gooir_planning::{InvocationLink, PlanLimits};
use reqwest::blocking::{Client, Response};
use reqwest::header::CONTENT_TYPE;
use reqwest::redirect::Policy;
use rustix::fs::{Dir, Mode, OFlags, fchmod, open, openat};
use rustix::process::{Pid, Signal, geteuid, kill_process};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const MAX_LOG_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_FLEETD_BINARY_BYTES: usize = 128 * 1024 * 1024;
const START_DEADLINE: Duration = Duration::from_secs(15);
const STOP_DEADLINE: Duration = Duration::from_secs(15);
const STAGED_FLEETD_NAME: &str = "fleetd";

#[test]
#[ignore = "requires freshly built release Fleetd/provider/attester paths; see module docs"]
fn real_fleetd_two_provider_restart_and_terminal_replay() {
    let coordinator = option_env!("CARGO_BIN_EXE_fleetd-real-proof")
        .unwrap_or_else(|| panic!("Cargo did not provide the real-proof coordinator binary"));
    let mut command = Command::new(coordinator);
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in [
        "GOOIR_FLEETD_REPO",
        "GOOIR_FLEETD_BINARY",
        "GOOIR_REQWEST_PROVIDER_BINARY",
        "GOOIR_UREQ_PROVIDER_BINARY",
        "GOOIR_DIRECT_CONVERSATION_ATTESTER_BINARY",
    ] {
        command.env(
            name,
            env::var_os(name)
                .unwrap_or_else(|| panic!("missing required ignored-proof environment variable")),
        );
    }
    let output = command
        .output()
        .unwrap_or_else(|_| panic!("single-thread real-proof coordinator failed to execute"));
    assert!(
        output.status.success() && output.stdout.is_empty() && output.stderr.is_empty(),
        "single-thread real-proof coordinator failed: code={:?}, stdout_len={}, stdout_digest={}, stderr_len={}, stderr_digest={}",
        output.status.code(),
        output.stdout.len(),
        sha256_identity(&output.stdout),
        output.stderr.len(),
        sha256_identity(&output.stderr),
    );
}

/// Run the exact proof in the private single-thread coordinator binary.
///
/// # Panics
///
/// Panics on any violated proof precondition, failed qualification, failed
/// target effect, recovery mismatch, or secret-retention finding.
pub fn run_child() {
    let external = ExternalInputs::load();
    let revision = clean_revision(&external.fleetd_repo);
    let fleetd = StagedFleetdExecutable::stage(&external.fleetd_binary);
    let openapi_digest = sha256_file(&external.fleetd_repo.join("openapi/fleetd-v1.json"));

    let package_parent = private_tempdir("gooir-real-packages-");
    let package_root = package_parent.path().join("packages");
    stage(StageRequest {
        reqwest_command: external.reqwest_binary,
        ureq_command: external.ureq_binary,
        attester_command: external.attester_binary,
        output_root: package_root.clone(),
    })
    .unwrap_or_else(|_| panic!("could not stage exact release packages"));
    let packages = verify_package_set(&package_root)
        .unwrap_or_else(|_| panic!("could not verify exact release packages"));
    let (reqwest_binding, ureq_binding) = provider_bindings(&packages);

    let native_parent = private_tempdir("gooir-real-native-");
    let reqwest_artifact = qualify_provider(&packages, reqwest_binding, native_parent.path())
        .unwrap_or_else(|_| panic!("Reqwest artifact qualification failed"));
    let ureq_artifact = qualify_provider(&packages, ureq_binding, native_parent.path())
        .unwrap_or_else(|_| panic!("Ureq artifact qualification failed"));
    let attester_artifact =
        qualify_attester(&packages, &packages.report().attester, native_parent.path())
            .unwrap_or_else(|_| panic!("attester artifact qualification failed"));
    let common = ProofInputs {
        fleetd: &fleetd,
        fleetd_revision: &revision,
        openapi_digest: &openapi_digest,
        packages: &packages,
        reqwest_binding,
        ureq_binding,
        reqwest_artifact: &reqwest_artifact,
        ureq_artifact: &ureq_artifact,
        attester_artifact: &attester_artifact,
    };
    let reqwest_first = run_matrix(&common, ProviderKind::Reqwest, ProviderKind::Ureq);
    let ureq_first = run_matrix(&common, ProviderKind::Ureq, ProviderKind::Reqwest);
    let all_agent_bearers = [
        &reqwest_first.agent_bearers[0],
        &reqwest_first.agent_bearers[1],
        &ureq_first.agent_bearers[0],
        &ureq_first.agent_bearers[1],
    ];
    for audit in [&reqwest_first, &ureq_first] {
        assert_journal_canaries_absent(
            &audit.journals,
            &audit.endpoint,
            audit.operator_bearer.as_str(),
            &audit.authority,
            &all_agent_bearers,
        );
        assert_log_canaries_absent(
            &audit.logs,
            &audit.endpoint,
            audit.operator_bearer.as_str(),
            &audit.authority,
            &all_agent_bearers,
        );
    }
    assert_eq!(clean_revision(&external.fleetd_repo), revision);
}

/// Drain one Fleetd log pipe in a separate process so the proof host remains
/// single-threaded at every native-runtime revalidation seam.
///
/// # Panics
///
/// Panics if arguments are invalid, the bounded private output cannot be
/// created or written, stdin cannot be drained, or the byte bound is exceeded.
pub fn run_log_pump(mut arguments: impl Iterator<Item = OsString>) {
    let output = PathBuf::from(
        arguments
            .next()
            .unwrap_or_else(|| panic!("log pump output path was missing")),
    );
    let bound = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| panic!("log pump byte bound was invalid"));
    assert!(
        arguments.next().is_none(),
        "log pump received extra arguments"
    );
    assert!(output.is_absolute(), "log pump output must be absolute");
    let mut retained = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .unwrap_or_else(|_| panic!("log pump output creation failed"));
    let mut input = std::io::stdin().lock();
    let mut buffer = [0_u8; 8 * 1024];
    let mut retained_len = 0_usize;
    let mut overflowed = false;
    loop {
        let count = input
            .read(&mut buffer)
            .unwrap_or_else(|_| panic!("log pump input read failed"));
        if count == 0 {
            break;
        }
        let available = bound.saturating_sub(retained_len);
        let keep = count.min(available);
        retained
            .write_all(&buffer[..keep])
            .unwrap_or_else(|_| panic!("log pump output write failed"));
        retained_len += keep;
        overflowed |= count > keep;
    }
    retained
        .sync_all()
        .unwrap_or_else(|_| panic!("log pump output sync failed"));
    assert!(!overflowed, "Fleetd log bound was exceeded");
}

struct ExternalInputs {
    fleetd_repo: PathBuf,
    fleetd_binary: PathBuf,
    reqwest_binary: PathBuf,
    ureq_binary: PathBuf,
    attester_binary: PathBuf,
}

impl ExternalInputs {
    fn load() -> Self {
        let fleetd_repo = required_path("GOOIR_FLEETD_REPO", false);
        let fleetd_binary = required_path("GOOIR_FLEETD_BINARY", true);
        assert!(fleetd_binary.starts_with(&fleetd_repo));
        assert!(fleetd_repo.join("openapi/fleetd-v1.json").is_file());
        Self {
            fleetd_repo,
            fleetd_binary,
            reqwest_binary: required_path("GOOIR_REQWEST_PROVIDER_BINARY", true),
            ureq_binary: required_path("GOOIR_UREQ_PROVIDER_BINARY", true),
            attester_binary: required_path("GOOIR_DIRECT_CONVERSATION_ATTESTER_BINARY", true),
        }
    }
}

/// Owner-only exact-byte staging for the measured Fleetd target executable.
///
/// Revalidation closes accidental or differently-owned replacement, but this
/// proof does not claim containment against a malicious process running as the
/// same effective user between the final check and kernel path resolution.
struct StagedFleetdExecutable {
    private_root: TempDir,
    _private_parent: TempDir,
    parent_path: PathBuf,
    parent: File,
    parent_identity: DirectoryIdentity,
    root_name: OsString,
    root: File,
    root_identity: DirectoryIdentity,
    executable: File,
    executable_identity: ExecutableIdentity,
    digest: String,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    links: u64,
    mode: u32,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ExecutableIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    links: u64,
    mode: u32,
    size: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SourceIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    links: u64,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl StagedFleetdExecutable {
    #[allow(
        clippy::too_many_lines,
        reason = "the exact-byte staging transaction is intentionally linear and auditable"
    )]
    fn stage(source_path: &Path) -> Self {
        assert!(source_path.is_absolute());
        let source = File::from(
            open(
                source_path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .unwrap_or_else(|_| panic!("Fleetd source descriptor open failed")),
        );
        let before = source_identity(&source);
        assert!(
            before.uid == geteuid().as_raw()
                && before.size > 0
                && before.size
                    <= u64::try_from(MAX_FLEETD_BINARY_BYTES)
                        .expect("Fleetd binary bound fits u64")
                && before.mode & 0o111 != 0,
            "Fleetd source executable metadata was invalid"
        );
        let bytes = read_exact_descriptor(&source, before.size, MAX_FLEETD_BINARY_BYTES);
        assert!(
            source_identity(&source) == before,
            "Fleetd source executable changed while staging"
        );
        let digest = sha256_identity(&bytes);

        let private_parent = private_tempdir("gooir-real-fleetd-executable-");
        let parent_path = private_parent
            .path()
            .canonicalize()
            .unwrap_or_else(|_| panic!("Fleetd staging parent canonicalization failed"));
        let parent = File::from(
            open(
                &parent_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap_or_else(|_| panic!("Fleetd staging parent open failed")),
        );
        directory_identity(&parent);

        let private_root = tempfile::Builder::new()
            .prefix(".fleetd-target-")
            .tempdir_in(&parent_path)
            .unwrap_or_else(|_| panic!("Fleetd staging root creation failed"));
        fs::set_permissions(private_root.path(), fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|_| panic!("Fleetd staging root permission failed"));
        let root_name = private_root
            .path()
            .file_name()
            .unwrap_or_else(|| panic!("Fleetd staging root name was unavailable"))
            .to_os_string();
        let root = File::from(
            openat(
                &parent,
                &root_name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap_or_else(|_| panic!("Fleetd staging root open failed")),
        );
        directory_identity(&root);

        let mut writer = File::from(
            openat(
                &root,
                STAGED_FLEETD_NAME,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap_or_else(|_| panic!("Fleetd staged executable creation failed")),
        );
        writer
            .write_all(&bytes)
            .unwrap_or_else(|_| panic!("Fleetd staged executable write failed"));
        writer
            .flush()
            .unwrap_or_else(|_| panic!("Fleetd staged executable flush failed"));
        writer
            .sync_all()
            .unwrap_or_else(|_| panic!("Fleetd staged executable sync failed"));
        assert!(
            descriptor_digest(&writer, before.size, MAX_FLEETD_BINARY_BYTES) == digest,
            "Fleetd staged executable readback changed"
        );
        fchmod(&writer, Mode::RUSR | Mode::XUSR)
            .unwrap_or_else(|_| panic!("Fleetd staged executable seal failed"));
        writer
            .sync_all()
            .unwrap_or_else(|_| panic!("Fleetd staged executable sealed sync failed"));
        let executable_identity = executable_identity(&writer, before.size);
        drop(writer);
        root.sync_all()
            .unwrap_or_else(|_| panic!("Fleetd staging root sync failed"));
        let executable = File::from(
            openat(
                &root,
                STAGED_FLEETD_NAME,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .unwrap_or_else(|_| panic!("Fleetd staged executable reopen failed")),
        );
        let root_identity = directory_identity(&root);
        let parent_identity = directory_identity(&parent);
        let staged = Self {
            private_root,
            _private_parent: private_parent,
            parent_path,
            parent,
            parent_identity,
            root_name,
            root,
            root_identity,
            executable,
            executable_identity,
            digest,
        };
        staged.revalidate();
        staged
    }

    fn digest(&self) -> &str {
        &self.digest
    }

    fn revalidated_spawn_path(&self) -> PathBuf {
        self.revalidate();
        self.private_root.path().join(STAGED_FLEETD_NAME)
    }

    fn revalidate(&self) {
        assert!(self.private_root.path().is_absolute());
        assert!(
            directory_identity(&self.parent) == self.parent_identity,
            "retained Fleetd staging parent changed"
        );
        let reopened_parent = File::from(
            open(
                &self.parent_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap_or_else(|_| panic!("Fleetd staging parent revalidation failed")),
        );
        assert!(
            directory_identity(&reopened_parent) == self.parent_identity,
            "Fleetd staging parent path changed"
        );
        assert!(
            directory_identity(&self.root) == self.root_identity,
            "retained Fleetd staging root changed"
        );
        let reopened_root = File::from(
            openat(
                &self.parent,
                &self.root_name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap_or_else(|_| panic!("Fleetd staging root revalidation failed")),
        );
        assert!(
            directory_identity(&reopened_root) == self.root_identity,
            "Fleetd staging root path changed"
        );
        validate_staged_root_entries(&reopened_root);
        assert!(
            executable_identity(&self.executable, self.executable_identity.size)
                == self.executable_identity,
            "retained Fleetd staged executable changed"
        );
        assert!(
            descriptor_digest(
                &self.executable,
                self.executable_identity.size,
                MAX_FLEETD_BINARY_BYTES,
            ) == self.digest,
            "retained Fleetd staged executable bytes changed"
        );
        let reopened_executable = File::from(
            openat(
                &reopened_root,
                STAGED_FLEETD_NAME,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .unwrap_or_else(|_| panic!("Fleetd staged executable path revalidation failed")),
        );
        assert!(
            executable_identity(&reopened_executable, self.executable_identity.size)
                == self.executable_identity,
            "Fleetd staged executable path changed"
        );
        assert!(
            descriptor_digest(
                &reopened_executable,
                self.executable_identity.size,
                MAX_FLEETD_BINARY_BYTES,
            ) == self.digest,
            "Fleetd staged executable path bytes changed"
        );
    }
}

fn source_identity(file: &File) -> SourceIdentity {
    let metadata = file
        .metadata()
        .unwrap_or_else(|_| panic!("Fleetd source executable inspection failed"));
    assert!(metadata.is_file(), "Fleetd source was not a regular file");
    SourceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        links: metadata.nlink(),
        mode: metadata.mode(),
        size: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn directory_identity(file: &File) -> DirectoryIdentity {
    let metadata = file
        .metadata()
        .unwrap_or_else(|_| panic!("Fleetd staging directory inspection failed"));
    assert!(
        metadata.is_dir()
            && metadata.uid() == geteuid().as_raw()
            && metadata.mode() & 0o777 == 0o700,
        "Fleetd staging directory metadata was invalid"
    );
    DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        links: metadata.nlink(),
        mode: metadata.mode(),
    }
}

fn executable_identity(file: &File, expected_size: u64) -> ExecutableIdentity {
    let metadata = file
        .metadata()
        .unwrap_or_else(|_| panic!("Fleetd staged executable inspection failed"));
    assert!(
        metadata.is_file()
            && metadata.uid() == geteuid().as_raw()
            && metadata.nlink() == 1
            && metadata.mode() & 0o777 == 0o500
            && metadata.len() == expected_size,
        "Fleetd staged executable metadata was invalid"
    );
    ExecutableIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        links: metadata.nlink(),
        mode: metadata.mode(),
        size: metadata.len(),
    }
}

fn validate_staged_root_entries(root: &File) {
    let mut entries =
        Dir::read_from(root).unwrap_or_else(|_| panic!("Fleetd staging root enumeration failed"));
    let mut executable = false;
    for entry in &mut entries {
        let entry = entry.unwrap_or_else(|_| panic!("Fleetd staging root entry failed"));
        match entry.file_name().to_bytes() {
            b"." | b".." => {}
            name if name == STAGED_FLEETD_NAME.as_bytes() && !executable => executable = true,
            _ => panic!("Fleetd staging root contained an unexpected entry"),
        }
    }
    assert!(executable, "Fleetd staging root lacked its executable");
}

fn read_exact_descriptor(file: &File, size: u64, bound: usize) -> Vec<u8> {
    assert!(
        size <= u64::try_from(bound).expect("descriptor byte bound fits u64"),
        "bounded descriptor exceeded its byte limit"
    );
    let length = usize::try_from(size).unwrap_or_else(|_| panic!("descriptor size was invalid"));
    let mut bytes = vec![0_u8; length];
    let mut read = 0_usize;
    while read < length {
        let count = file
            .read_at(
                &mut bytes[read..],
                u64::try_from(read).expect("descriptor offset fits u64"),
            )
            .unwrap_or_else(|_| panic!("bounded descriptor read failed"));
        assert!(count != 0, "bounded descriptor ended early");
        read += count;
    }
    let mut trailing = [0_u8; 1];
    assert_eq!(
        file.read_at(&mut trailing, size)
            .unwrap_or_else(|_| panic!("bounded descriptor trailing read failed")),
        0,
        "bounded descriptor grew while reading"
    );
    bytes
}

fn descriptor_digest(file: &File, size: u64, bound: usize) -> String {
    sha256_identity(&read_exact_descriptor(file, size, bound))
}

fn required_path(name: &str, executable: bool) -> PathBuf {
    let raw = env::var_os(name)
        .unwrap_or_else(|| panic!("missing required ignored-proof environment variable {name}"));
    let supplied = PathBuf::from(raw);
    assert!(
        supplied.is_absolute(),
        "ignored-proof paths must be absolute"
    );
    let path = supplied
        .canonicalize()
        .unwrap_or_else(|_| panic!("required ignored-proof path cannot be canonicalized"));
    let metadata = fs::symlink_metadata(&path)
        .unwrap_or_else(|_| panic!("required ignored-proof path cannot be inspected"));
    if executable {
        assert!(metadata.file_type().is_file());
        assert_ne!(metadata.mode() & 0o111, 0);
    } else {
        assert!(metadata.file_type().is_dir());
    }
    path
}

fn clean_revision(repo: &Path) -> String {
    assert!(git(repo, &["status", "--porcelain=v1"]).is_empty());
    let revision = git(repo, &["rev-parse", "HEAD"]);
    assert!(
        revision.len() == 40
            && revision
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    revision
}

fn git(repo: &Path, arguments: &[&str]) -> String {
    let output = Command::new("/usr/bin/git")
        .env_clear()
        .arg("-C")
        .arg(repo)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|_| panic!("fixed Git inspection failed to execute"));
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap_or_else(|_| panic!("Git inspection output was not UTF-8"))
        .trim()
        .to_owned()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderKind {
    Reqwest,
    Ureq,
}

struct ProofInputs<'a> {
    fleetd: &'a StagedFleetdExecutable,
    fleetd_revision: &'a str,
    openapi_digest: &'a str,
    packages: &'a VerifiedPackageSet,
    reqwest_binding: &'a ProviderPackageBinding,
    ureq_binding: &'a ProviderPackageBinding,
    reqwest_artifact: &'a QualifiedNativeArtifact,
    ureq_artifact: &'a QualifiedNativeArtifact,
    attester_artifact: &'a QualifiedNativeArtifact,
}

#[derive(Clone, Copy)]
struct ProviderSelection<'a> {
    binding: &'a ProviderPackageBinding,
    artifact: &'a QualifiedNativeArtifact,
}

struct MatrixSecrecyAudit {
    endpoint: String,
    operator_bearer: SecretCanary,
    authority: Vec<u8>,
    agent_bearers: [SecretCanary; 2],
    journals: Vec<u8>,
    logs: Vec<u8>,
}

impl ProofInputs<'_> {
    fn selected(&self, kind: ProviderKind) -> ProviderSelection<'_> {
        match kind {
            ProviderKind::Reqwest => ProviderSelection {
                binding: self.reqwest_binding,
                artifact: self.reqwest_artifact,
            },
            ProviderKind::Ureq => ProviderSelection {
                binding: self.ureq_binding,
                artifact: self.ureq_artifact,
            },
        }
    }
}

fn selected_runtime<'a>(
    kind: ProviderKind,
    reqwest: &'a QualifiedNativeRuntime,
    ureq: &'a QualifiedNativeRuntime,
) -> &'a QualifiedNativeRuntime {
    match kind {
        ProviderKind::Reqwest => reqwest,
        ProviderKind::Ureq => ureq,
    }
}

fn provider_bindings(
    packages: &VerifiedPackageSet,
) -> (&ProviderPackageBinding, &ProviderPackageBinding) {
    let reqwest = packages
        .report()
        .providers
        .iter()
        .find(|binding| binding.package.as_str() == REQWEST_PACKAGE)
        .unwrap_or_else(|| panic!("verified package set lacks Reqwest"));
    let ureq = packages
        .report()
        .providers
        .iter()
        .find(|binding| binding.package.as_str() == UREQ_PACKAGE)
        .unwrap_or_else(|| panic!("verified package set lacks Ureq"));
    (reqwest, ureq)
}

#[allow(clippy::too_many_lines)]
fn run_matrix(
    common: &ProofInputs<'_>,
    first: ProviderKind,
    second: ProviderKind,
) -> MatrixSecrecyAudit {
    assert_ne!(first, second);
    let target_root = private_tempdir("gooir-real-target-");
    let root = target_root.path();
    let database = root.join("fleetd.db");
    let token_file = root.join("operator.token");
    let mut daemon = FleetdDaemon::spawn(common.fleetd, root, &database, &token_file, None);
    let endpoint = daemon.endpoint();
    let listen = daemon.address();
    let token = SecretCanary(read_operator_token(&token_file));
    let client = public_client();
    let AgentRegistration {
        id: agent_a,
        bearer: inbox_bearer,
    } = create_agent(&client, &endpoint, token.as_str(), "proof-agent-a");
    let AgentRegistration {
        id: agent_b,
        bearer: stream_bearer,
    } = create_agent(&client, &endpoint, token.as_str(), "proof-agent-b");
    assert_no_public_conversations(&client, &endpoint, token.as_str());
    drop(client);
    let mut logs = daemon.stop();

    let target = unique_target(root, first, second);
    let data_identity = persist_marker(
        root,
        "data-directory.identity.json",
        &json!({
            "protocol": "org.gooi.proof/fleetd-data-directory-identity@0.1.0",
            "fleetd_target": target.as_str(),
            "marker": fresh_marker(root, "data")
        }),
    );
    let credential_revision = persist_marker(
        root,
        "credential-generation.identity.json",
        &json!({
            "protocol": "org.gooi.proof/fleetd-credential-generation@0.1.0",
            "fleetd_target": target.as_str(),
            "marker": fresh_marker(root, "credential")
        }),
    );
    let mapping_digest = digest_document(&json!({
        "protocol": "org.gooi.proof/fleetd-endpoint-mapping@0.1.0",
        "fleetd_target": target.as_str(),
        "endpoint": endpoint
    }));
    let target_lock = TargetLock::new(root.join("target-lock"))
        .unwrap_or_else(|_| panic!("could not create target lock"));
    let binding = target_lock
        .configure(
            TargetDeployment::new(
                target.clone(),
                common.fleetd.digest(),
                common.fleetd_revision,
                common.openapi_digest,
                data_identity,
                mapping_digest.clone(),
                credential_revision.clone(),
            )
            .unwrap_or_else(|_| panic!("could not construct target deployment")),
        )
        .unwrap_or_else(|_| panic!("could not publish target deployment"));
    let target_guard = target_lock
        .acquire_execution(&binding)
        .unwrap_or_else(|_| panic!("could not acquire target execution fence"));
    let authority = AuthorityDocument::new(
        target.as_str(),
        mapping_digest,
        credential_revision,
        &endpoint,
        token.as_str(),
        5_000,
        u64::try_from(MAX_RESPONSE_BYTES).expect("response bound fits u64"),
    )
    .unwrap_or_else(|_| panic!("could not construct live authority"));

    let intent = DirectPairIntent::new(
        target,
        [
            DirectMember::new(agent_a, DeliveryMode::Inbox),
            DirectMember::new(agent_b, DeliveryMode::StreamOnly),
        ],
    )
    .unwrap_or_else(|_| panic!("could not construct direct-pair intent"));
    let (baseline, admitted_intent) = observed_intent_baseline(&intent);
    let policy = candidate_policy(common.attester_artifact);
    let plan_limits = planning_limits();
    let process_limits = process_limits();

    // Provisioning has exercised the proof-host HTTP paths and the daemon log
    // pumps are joined. Qualify with only the coordinator thread live, then
    // permit no new proof-host runtime surface before either child spawn.
    let reqwest_runtime = qualify_native_runtime(
        common.reqwest_artifact.lock(),
        common.attester_artifact.lock(),
    )
    .unwrap_or_else(|error| panic!("Reqwest runtime qualification failed: {error}"));
    let ureq_runtime =
        qualify_native_runtime(common.ureq_artifact.lock(), common.attester_artifact.lock())
            .unwrap_or_else(|error| panic!("Ureq runtime qualification failed: {error}"));
    let mut daemon = FleetdDaemon::spawn(common.fleetd, root, &database, &token_file, Some(listen));
    assert!(
        daemon.endpoint() == endpoint,
        "Fleetd endpoint changed after restart"
    );
    assert!(
        read_operator_token(&token_file) == token.as_str(),
        "Fleetd operator credential changed after restart"
    );

    let first_selection = common.selected(first);
    let first_runtime = selected_runtime(first, &reqwest_runtime, &ureq_runtime);
    let first_invocation = link_invocation(
        common.packages,
        first_selection.binding,
        &intent,
        admitted_intent.clone(),
        plan_limits,
    );
    let first_journal = AttemptJournal::new(root.join("attempt-first"))
        .unwrap_or_else(|_| panic!("could not create first journal"));
    let first_checkpoint = {
        let session = first_journal
            .begin_session()
            .unwrap_or_else(|_| panic!("could not acquire first journal session"));
        terminal(start(
            &session,
            &driver_request(
                common,
                first_selection,
                first_runtime,
                &first_invocation,
                &baseline,
                &policy,
                &target_guard,
                &authority,
                plan_limits,
                process_limits,
            ),
        ))
    };
    assert_admitted_receipts(&first_checkpoint);
    let first_snapshot = admitted_snapshot(&first_checkpoint);
    let first_fact = conversation_fact(&first_snapshot);
    let first_reference = DirectConversationRef::from_fact(&first_fact)
        .unwrap_or_else(|_| panic!("first output was not a conversation reference"));
    assert_public_conversation(
        &public_client(),
        &endpoint,
        token.as_str(),
        &first_reference,
    );

    logs.extend(daemon.stop());
    let mut daemon = FleetdDaemon::spawn(common.fleetd, root, &database, &token_file, Some(listen));
    assert!(
        daemon.endpoint() == endpoint,
        "Fleetd endpoint changed after second restart"
    );
    assert!(
        read_operator_token(&token_file) == token.as_str(),
        "Fleetd operator credential changed after second restart"
    );
    assert_public_conversation(
        &public_client(),
        &endpoint,
        token.as_str(),
        &first_reference,
    );

    let second_selection = common.selected(second);
    let second_runtime = selected_runtime(second, &reqwest_runtime, &ureq_runtime);
    let second_invocation = link_invocation(
        common.packages,
        second_selection.binding,
        &intent,
        admitted_intent,
        plan_limits,
    );
    assert_ne!(
        first_invocation.invocation_id,
        second_invocation.invocation_id
    );
    let second_journal = AttemptJournal::new(root.join("attempt-second"))
        .unwrap_or_else(|_| panic!("could not create second journal"));
    let second_checkpoint = {
        let session = second_journal
            .begin_session()
            .unwrap_or_else(|_| panic!("could not acquire second journal session"));
        terminal(start(
            &session,
            &driver_request(
                common,
                second_selection,
                second_runtime,
                &second_invocation,
                &first_snapshot,
                &policy,
                &target_guard,
                &authority,
                plan_limits,
                process_limits,
            ),
        ))
    };
    assert_admitted_receipts(&second_checkpoint);
    let second_snapshot = admitted_snapshot(&second_checkpoint);
    let second_fact = conversation_fact(&second_snapshot);
    assert_eq!(first_fact, second_fact);
    let second_reference = DirectConversationRef::from_fact(&second_fact)
        .unwrap_or_else(|_| panic!("second output was not a conversation reference"));
    assert_eq!(first_reference, second_reference);
    assert_two_derived_authorities(&second_snapshot, &second_fact);
    assert_public_conversation(
        &public_client(),
        &endpoint,
        token.as_str(),
        &second_reference,
    );
    logs.extend(daemon.stop());

    let first_bytes = canonical_checkpoint(&first_checkpoint);
    let first_replay = {
        let session = first_journal
            .begin_session()
            .unwrap_or_else(|_| panic!("could not reopen first journal"));
        terminal(resume(
            &session,
            &driver_request(
                common,
                first_selection,
                first_runtime,
                &first_invocation,
                &baseline,
                &policy,
                &target_guard,
                &authority,
                plan_limits,
                process_limits,
            ),
        ))
    };
    assert_eq!(canonical_checkpoint(&first_replay), first_bytes);

    let second_bytes = canonical_checkpoint(&second_checkpoint);
    let second_replay = {
        let session = second_journal
            .begin_session()
            .unwrap_or_else(|_| panic!("could not reopen second journal"));
        terminal(resume(
            &session,
            &driver_request(
                common,
                second_selection,
                second_runtime,
                &second_invocation,
                &first_snapshot,
                &policy,
                &target_guard,
                &authority,
                plan_limits,
                process_limits,
            ),
        ))
    };
    assert_eq!(canonical_checkpoint(&second_replay), second_bytes);

    let authority_bytes = authority
        .encode_for_pipe()
        .unwrap_or_else(|_| panic!("authority encoding failed"));
    let mut journals = read_tree(first_journal.directory_path());
    journals.extend(read_tree(second_journal.directory_path()));
    MatrixSecrecyAudit {
        endpoint,
        operator_bearer: token,
        authority: authority_bytes,
        agent_bearers: [inbox_bearer, stream_bearer],
        journals,
        logs,
    }
}

#[allow(clippy::too_many_arguments)]
fn driver_request<'a>(
    common: &'a ProofInputs<'a>,
    selection: ProviderSelection<'a>,
    runtime: &'a QualifiedNativeRuntime,
    invocation: &'a gooir_capability::protocol::CapabilityInvocation,
    baseline: &'a AdmissionSnapshot,
    policy: &'a AdmissionPolicy,
    target: &'a TargetExecutionGuard,
    authority: &'a AuthorityDocument,
    planning_limits: PlanLimits,
    process_limits: AttemptProcessLimits,
) -> DriverRequest<'a> {
    DriverRequest {
        packages: common.packages,
        selected_provider: selection.binding,
        invocation,
        baseline,
        admission_policy: policy,
        provider_artifact: selection.artifact,
        attester_artifact: common.attester_artifact,
        runtime,
        target,
        authority,
        planning_limits,
        process_limits,
    }
}

fn terminal(
    result: Result<
        DriverProgress,
        fleetd_direct_conversation_external_host_proof::driver::DriverError,
    >,
) -> AttemptCheckpoint {
    match result.unwrap_or_else(|_| panic!("proof driver failed")) {
        DriverProgress::Terminal(checkpoint) => checkpoint,
        DriverProgress::Parked { reason, .. } => match reason {
            ParkReason::ProviderLaunch(error) => {
                panic!("real proof parked on provider launch: {error}")
            }
            ParkReason::AttesterLaunch(error) => {
                panic!("real proof parked on attester launch: {error}")
            }
            ParkReason::ProviderReceiptCapacity => {
                panic!("real proof exhausted provider receipt capacity")
            }
            ParkReason::AttesterReceiptCapacity => {
                panic!("real proof exhausted attester receipt capacity")
            }
        },
    }
}

fn assert_admitted_receipts(checkpoint: &AttemptCheckpoint) {
    assert_eq!(checkpoint.phase(), AttemptPhase::Admitted);
    assert!(matches!(
        checkpoint.resolution(),
        Some(AttemptResolution::Admitted { .. })
    ));
    assert!(checkpoint.provider_decisive().is_some());
    assert!(checkpoint.attester_decisive().is_some());
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
    checkpoint
        .validate()
        .unwrap_or_else(|_| panic!("terminal checkpoint validation failed"));
}

fn admitted_snapshot(checkpoint: &AttemptCheckpoint) -> AdmissionSnapshot {
    let Some(AttemptResolution::Admitted { admission_snapshot }) = checkpoint.resolution() else {
        panic!("terminal checkpoint did not contain admission");
    };
    let snapshot = serde_json::from_value::<AdmissionSnapshot>(admission_snapshot.value().clone())
        .unwrap_or_else(|_| panic!("admission snapshot decoding failed"));
    snapshot
        .validate()
        .unwrap_or_else(|_| panic!("admission snapshot validation failed"));
    snapshot
}

fn conversation_fact(snapshot: &AdmissionSnapshot) -> gooir_capability::Fact {
    let facts = snapshot
        .facts
        .iter()
        .filter(|fact| fact.value_kind == direct_conversation_ref_value_kind())
        .collect::<Vec<_>>();
    let [fact] = facts.as_slice() else {
        panic!("snapshot did not contain exactly one conversation Fact");
    };
    (*fact).clone()
}

fn assert_two_derived_authorities(snapshot: &AdmissionSnapshot, fact: &gooir_capability::Fact) {
    let records = snapshot
        .authority_records
        .iter()
        .filter(|record| record.fact == *fact)
        .filter(|record| matches!(record.basis, AuthorityBasis::Derived { .. }))
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    assert_ne!(
        records[0].authority_record_id,
        records[1].authority_record_id
    );
}

fn canonical_checkpoint(checkpoint: &AttemptCheckpoint) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(checkpoint)
        .unwrap_or_else(|_| panic!("checkpoint canonicalization failed"))
}

fn observed_intent_baseline(intent: &DirectPairIntent) -> (AdmissionSnapshot, AdmittedFactRef) {
    let fact = intent
        .to_fact()
        .unwrap_or_else(|_| panic!("intent Fact encoding failed"));
    let evidence_kind = EvidenceKindId::new(
        "org.gooi.proof.fleetd",
        "registered_direct_pair_intent",
        "0.1.0",
    );
    let observer_artifact = ArtifactDigest::parse(sha256_file(
        &env::current_exe().unwrap_or_else(|_| panic!("proof executable resolution failed")),
    ))
    .unwrap_or_else(|_| panic!("proof executable digest was invalid"));
    let observation_authority = ObservationAuthority::new(
        ObservationSourceId::new("org.gooi.proof.fleetd", "public_api", "0.1.0"),
        ImplementationId::new("org.gooi.proof.fleetd", "fixture_observer", "0.1.0"),
        observer_artifact,
        fact.value_kind.clone(),
        evidence_kind.clone(),
        BTreeMap::new(),
    )
    .unwrap_or_else(|_| panic!("source observation authority construction failed"));
    let observation = SourceObservation::new(
        fact,
        observation_authority.clone(),
        EvidenceRef::new(
            evidence_kind,
            EvidenceDigest::parse(digest_document(intent))
                .unwrap_or_else(|_| panic!("source evidence digest was invalid")),
            "opaque://fleetd-public-api/registered-agent-identities",
            BTreeMap::new(),
        )
        .unwrap_or_else(|_| panic!("source evidence construction failed")),
        Vec::new(),
        BTreeMap::new(),
    )
    .unwrap_or_else(|_| panic!("source observation construction failed"));
    let source_policy = AdmissionPolicy::new(
        AdmissionAuthorityId::new("org.gooi.proof.fleetd", "source", "0.1.0"),
        Vec::new(),
        vec![observation_authority],
        BTreeMap::new(),
    )
    .unwrap_or_else(|_| panic!("source admission policy construction failed"));
    let mut ledger = AdmissionLedger::new();
    let AdmissionOutcome::Admitted { links, .. } = ledger
        .admit_observation(&source_policy, &observation)
        .unwrap_or_else(|_| panic!("source observation admission failed"))
    else {
        panic!("source observation was withheld");
    };
    let [link] = links.as_slice() else {
        panic!("source observation did not yield one link");
    };
    (
        ledger
            .export()
            .unwrap_or_else(|_| panic!("baseline export failed")),
        link.reference.clone(),
    )
}

fn candidate_policy(attester: &QualifiedNativeArtifact) -> AdmissionPolicy {
    let attester_digest = ArtifactDigest::parse(attester.lock().resource_digest().to_owned())
        .unwrap_or_else(|_| panic!("attester digest was invalid"));
    let authority = ConformanceAuthority::new(
        direct_conversation_ref_suite_id(),
        ConformanceAttester::new(
            attester_implementation_id(),
            attester_digest,
            BTreeMap::new(),
        )
        .unwrap_or_else(|_| panic!("conformance attester construction failed")),
        BTreeMap::new(),
    )
    .unwrap_or_else(|_| panic!("conformance authority construction failed"));
    AdmissionPolicy::new(
        AdmissionAuthorityId::new("org.gooi.proof.fleetd", "candidate", "0.1.0"),
        vec![authority],
        Vec::new(),
        BTreeMap::new(),
    )
    .unwrap_or_else(|_| panic!("candidate policy construction failed"))
}

fn link_invocation(
    packages: &VerifiedPackageSet,
    selected: &ProviderPackageBinding,
    intent: &DirectPairIntent,
    admitted: AdmittedFactRef,
    limits: PlanLimits,
) -> gooir_capability::protocol::CapabilityInvocation {
    let fact = intent
        .to_fact()
        .unwrap_or_else(|_| panic!("linked Fact encoding failed"));
    let planner = packages
        .planner(limits)
        .unwrap_or_else(|_| panic!("planner reconstruction failed"));
    let plan = planner
        .plan(
            [fact.value_kind.clone()],
            direct_conversation_ref_value_kind(),
        )
        .unwrap_or_else(|_| panic!("semantic planning failed"));
    let offer = packages
        .provider_offer(selected)
        .unwrap_or_else(|| panic!("selected provider is absent"));
    let capability = open_or_resolve_capability_spec().id;
    planner
        .link_invocation(
            &plan,
            InvocationLink {
                capability: &capability,
                offer: &offer.offer_id,
                selection_extensions: BTreeMap::new(),
                inputs: vec![
                    LinkedInput::new(intent_port_name(), admitted, fact, BTreeMap::new())
                        .unwrap_or_else(|_| panic!("linked input construction failed")),
                ],
                conformance_suite: direct_conversation_ref_suite_id(),
                invocation_extensions: BTreeMap::new(),
            },
        )
        .unwrap_or_else(|_| panic!("explicit invocation linking failed"))
}

fn planning_limits() -> PlanLimits {
    let bound = NonZeroUsize::new(16).expect("fixed planning bound is nonzero");
    PlanLimits {
        max_capabilities: bound,
        max_value_kinds: bound,
        max_ports_per_capability: bound,
        max_total_ports: bound,
        max_offers_per_capability: bound,
        max_total_offers: bound,
    }
}

fn process_limits() -> AttemptProcessLimits {
    AttemptProcessLimits {
        provider: ProcessLimits::new(64 * 1024, 128 * 1024, 8 * 1024, Duration::from_secs(15))
            .unwrap_or_else(|_| panic!("provider limits were invalid")),
        attester: ProcessLimits::new(256 * 1024, 128 * 1024, 8 * 1024, Duration::from_secs(15))
            .unwrap_or_else(|_| panic!("attester limits were invalid")),
    }
}

fn unique_target(root: &Path, first: ProviderKind, second: ProviderKind) -> FleetdTarget {
    let seed = format!("{}:{first:?}:{second:?}", root.display());
    FleetdTarget::parse(format!(
        "fleetd:proof:{:x}",
        Sha256::digest(seed.as_bytes())
    ))
    .unwrap_or_else(|_| panic!("fresh target coordinate construction failed"))
}

fn fresh_marker(root: &Path, purpose: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| panic!("system clock is before Unix epoch"))
        .as_nanos();
    sha256_identity(format!("{}:{purpose}:{}:{now}", root.display(), std::process::id()).as_bytes())
}

fn persist_marker(root: &Path, name: &str, value: &Value) -> String {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .unwrap_or_else(|_| panic!("marker canonicalization failed"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(name))
        .unwrap_or_else(|_| panic!("marker creation failed"));
    file.write_all(&bytes)
        .unwrap_or_else(|_| panic!("marker write failed"));
    file.sync_all()
        .unwrap_or_else(|_| panic!("marker sync failed"));
    sha256_identity(&bytes)
}

fn digest_document(value: &impl serde::Serialize) -> String {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .unwrap_or_else(|_| panic!("proof document canonicalization failed"));
    sha256_identity(&bytes)
}

fn sha256_file(path: &Path) -> String {
    let mut file = File::open(path).unwrap_or_else(|_| panic!("measured file open failed"));
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .unwrap_or_else(|_| panic!("measured file read failed"));
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn sha256_identity(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn private_tempdir(prefix: &str) -> TempDir {
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .unwrap_or_else(|_| panic!("private proof directory creation failed"));
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|_| panic!("private proof directory permission failed"));
    let path = directory
        .path()
        .canonicalize()
        .unwrap_or_else(|_| panic!("private proof directory canonicalization failed"));
    let metadata =
        fs::metadata(path).unwrap_or_else(|_| panic!("private proof directory inspection failed"));
    assert_eq!(metadata.mode() & 0o777, 0o700);
    assert_eq!(metadata.uid(), rustix::process::getuid().as_raw());
    directory
}

struct FleetdDaemon {
    child: ManagedChild,
    address: SocketAddr,
    stdout: LogPump,
    stderr: LogPump,
    stopped: bool,
}

impl FleetdDaemon {
    fn spawn(
        binary: &StagedFleetdExecutable,
        working_directory: &Path,
        database: &Path,
        token_file: &Path,
        requested: Option<SocketAddr>,
    ) -> Self {
        let listen =
            requested.map_or_else(|| "127.0.0.1:0".to_owned(), |address| address.to_string());
        let missing_config = working_directory.join("missing-config.json");
        assert!(!missing_config.exists());
        let (stdout, stdout_writer) = LogPump::spawn(working_directory, "stdout");
        let (stderr, stderr_writer) = LogPump::spawn(working_directory, "stderr");
        let executable_path = binary.revalidated_spawn_path();
        let raw_child = Command::new(executable_path)
            .env_clear()
            .env("RUST_LOG", "fleetd=info")
            .arg("--fleet-config")
            .arg(missing_config)
            .arg("serve")
            .arg("--listen")
            .arg(&listen)
            .arg("--db")
            .arg(database)
            .arg("--operator-token-file")
            .arg(token_file)
            .current_dir(working_directory)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout_writer))
            .stderr(Stdio::from(stderr_writer))
            .spawn()
            .unwrap_or_else(|_| panic!("measured Fleetd direct execution failed"));
        let mut child = ManagedChild::new(raw_child);
        binary.revalidate();
        let deadline = Instant::now() + START_DEADLINE;
        let address = loop {
            if let Some(address) = parse_ready_address(&stdout.snapshot())
                .or_else(|| parse_ready_address(&stderr.snapshot()))
            {
                break address;
            }
            assert!(
                child
                    .try_wait()
                    .unwrap_or_else(|_| panic!("Fleetd startup observation failed"))
                    .is_none(),
                "Fleetd exited before readiness"
            );
            assert!(
                Instant::now() < deadline,
                "Fleetd readiness deadline expired"
            );
            thread::sleep(Duration::from_millis(10));
        };
        if requested.is_some() {
            assert_eq!(address.to_string(), listen);
        }
        let daemon = Self {
            child,
            address,
            stdout,
            stderr,
            stopped: false,
        };
        wait_for_health(&public_client(), &daemon.endpoint());
        daemon
    }

    const fn address(&self) -> SocketAddr {
        self.address
    }

    fn endpoint(&self) -> String {
        format!("http://{}/", self.address)
    }

    fn stop(&mut self) -> Vec<u8> {
        assert!(!self.stopped);
        let raw_pid = i32::try_from(self.child.id())
            .unwrap_or_else(|_| panic!("Fleetd PID did not fit platform PID"));
        let pid = Pid::from_raw(raw_pid).unwrap_or_else(|| panic!("Fleetd PID was invalid"));
        kill_process(pid, Signal::INT).unwrap_or_else(|_| panic!("Fleetd SIGINT delivery failed"));
        let deadline = Instant::now() + STOP_DEADLINE;
        let status = loop {
            if let Some(status) = self
                .child
                .try_wait()
                .unwrap_or_else(|_| panic!("Fleetd shutdown observation failed"))
            {
                break status;
            }
            if Instant::now() >= deadline {
                self.child
                    .kill()
                    .unwrap_or_else(|_| panic!("stalled Fleetd force-stop failed"));
                let _status = self
                    .child
                    .wait()
                    .unwrap_or_else(|_| panic!("stalled Fleetd reap failed"));
                panic!("Fleetd failed graceful SIGINT shutdown");
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert_clean_exit(status);
        self.stopped = true;
        let mut bytes = self.stdout.finish();
        bytes.extend(self.stderr.finish());
        bytes
    }
}

impl Drop for FleetdDaemon {
    fn drop(&mut self) {
        if !self.stopped {
            let _ignored = self.child.kill();
            let _ignored = self.child.wait();
        }
    }
}

struct ManagedChild {
    child: Child,
    reaped: bool,
}

impl ManagedChild {
    const fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        self.reaped |= status.is_some();
        Ok(status)
    }

    fn kill(&mut self) -> std::io::Result<()> {
        if self.reaped {
            Ok(())
        } else {
            self.child.kill()
        }
    }

    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ignored = self.child.kill();
            let _ignored = self.child.wait();
            self.reaped = true;
        }
    }
}

fn assert_clean_exit(status: ExitStatus) {
    assert!(
        status.success(),
        "Fleetd graceful shutdown was unsuccessful"
    );
}

struct LogPump {
    child: Child,
    output: PathBuf,
    finished: bool,
}

impl LogPump {
    fn spawn(working_directory: &Path, stream: &str) -> (Self, ChildStdin) {
        let identity = fresh_marker(working_directory, stream);
        let suffix = identity
            .strip_prefix("sha256:")
            .unwrap_or_else(|| panic!("log identity had an unexpected form"));
        let output = working_directory.join(format!(".{stream}-{suffix}.log"));
        assert!(!output.exists());
        let executable = env::current_exe()
            .unwrap_or_else(|_| panic!("log pump executable could not be located"));
        let child = Command::new(executable)
            .env_clear()
            .arg("--log-pump")
            .arg(&output)
            .arg(MAX_LOG_BYTES.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|_| panic!("Fleetd log pump failed to execute"));
        let mut pump = Self {
            child,
            output,
            finished: false,
        };
        let writer = pump
            .child
            .stdin
            .take()
            .unwrap_or_else(|| panic!("Fleetd log pump input was unavailable"));
        (pump, writer)
    }

    fn snapshot(&self) -> Vec<u8> {
        match fs::read(&self.output) {
            Ok(bytes) => {
                assert!(bytes.len() <= MAX_LOG_BYTES);
                bytes
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("Fleetd log snapshot failed: {:?}", error.kind()),
        }
    }

    fn finish(&mut self) -> Vec<u8> {
        assert!(!self.finished, "Fleetd log pump was already joined");
        let status = self
            .child
            .wait()
            .unwrap_or_else(|_| panic!("Fleetd log pump reap failed"));
        assert!(status.success(), "Fleetd log pump failed");
        self.finished = true;
        self.snapshot()
    }
}

impl Drop for LogPump {
    fn drop(&mut self) {
        if !self.finished {
            let _ignored = self.child.kill();
            let _ignored = self.child.wait();
        }
    }
}

fn parse_ready_address(bytes: &[u8]) -> Option<SocketAddr> {
    let output = std::str::from_utf8(bytes).ok()?;
    output.lines().find_map(|line| {
        line.contains("fleetd ready")
            .then(|| {
                line.split_ascii_whitespace()
                    .find_map(|field| field.strip_prefix("listen="))
                    .and_then(|address| address.parse().ok())
            })
            .flatten()
    })
}

fn public_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(Policy::none())
        .no_proxy()
        .build()
        .unwrap_or_else(|_| panic!("bounded public HTTP client construction failed"))
}

fn wait_for_health(client: &Client, endpoint: &str) {
    let deadline = Instant::now() + START_DEADLINE;
    loop {
        let response = client.get(format!("{endpoint}health")).send();
        if let Ok(response) = response
            && response.status() == reqwest::StatusCode::OK
            && read_json(response) == json!({"status": "ok"})
        {
            return;
        }
        assert!(Instant::now() < deadline, "Fleetd health deadline expired");
        thread::sleep(Duration::from_millis(10));
    }
}

struct AgentRegistration {
    id: AgentId,
    bearer: SecretCanary,
}

struct SecretCanary(String);

impl SecretCanary {
    fn as_str(&self) -> &str {
        &self.0
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

fn create_agent(client: &Client, endpoint: &str, token: &str, name: &str) -> AgentRegistration {
    let response = client
        .post(format!("{endpoint}v1/agents"))
        .bearer_auth(token)
        .header(CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_vec(&json!({"name": name, "metadata": {}}))
                .unwrap_or_else(|_| panic!("Fleetd agent request encoding failed")),
        )
        .send()
        .unwrap_or_else(|_| panic!("Fleetd agent registration failed"));
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    let mut body = read_json(response);
    let id = body
        .pointer("/agent/id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("Fleetd agent response lacked stable ID"))
        .to_owned();
    let credential = body
        .pointer_mut("/credential/token")
        .unwrap_or_else(|| panic!("Fleetd agent response lacked one-time credential"));
    let bearer = credential
        .take()
        .as_str()
        .unwrap_or_else(|| panic!("Fleetd agent credential was not a string"))
        .to_owned();
    AgentRegistration {
        id: AgentId::parse(id).unwrap_or_else(|_| panic!("Fleetd agent ID was invalid")),
        bearer: SecretCanary(bearer),
    }
}

fn read_json(mut response: Response) -> Value {
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    );
    if let Some(length) = response.content_length() {
        assert!(length <= u64::try_from(MAX_RESPONSE_BYTES).expect("response bound fits u64"));
    }
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(u64::try_from(MAX_RESPONSE_BYTES + 1).expect("response bound fits u64"))
        .read_to_end(&mut bytes)
        .unwrap_or_else(|_| panic!("Fleetd public response read failed"));
    assert!(bytes.len() <= MAX_RESPONSE_BYTES);
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| panic!("Fleetd public response was malformed JSON"))
}

#[derive(Deserialize)]
struct PublicConversation {
    id: String,
    kind: String,
    created_at_ms: i64,
    archived_at_ms: Option<i64>,
    members: Vec<PublicMember>,
}

#[derive(Deserialize)]
struct PublicMember {
    agent_id: String,
    delivery_mode: String,
}

fn assert_no_public_conversations(client: &Client, endpoint: &str, token: &str) {
    let response = client
        .get(format!("{endpoint}v1/conversations?include_archived=true"))
        .bearer_auth(token)
        .send()
        .unwrap_or_else(|_| panic!("Fleetd public warm-up observation failed"));
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let conversations = serde_json::from_value::<Vec<PublicConversation>>(read_json(response))
        .unwrap_or_else(|_| panic!("Fleetd warm-up conversation projection changed"));
    assert!(conversations.is_empty());
}

fn assert_public_conversation(
    client: &Client,
    endpoint: &str,
    token: &str,
    reference: &DirectConversationRef,
) {
    let response = client
        .get(format!("{endpoint}v1/conversations?include_archived=true"))
        .bearer_auth(token)
        .send()
        .unwrap_or_else(|_| panic!("Fleetd public reobservation failed"));
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let conversations = serde_json::from_value::<Vec<PublicConversation>>(read_json(response))
        .unwrap_or_else(|_| panic!("Fleetd conversation projection shape changed"));
    let [conversation] = conversations.as_slice() else {
        panic!("fresh Fleetd target did not contain exactly one conversation");
    };
    assert_eq!(conversation.id, reference.conversation_id().as_str());
    assert_eq!(conversation.kind, "direct");
    assert_eq!(conversation.created_at_ms, reference.created_at_ms());
    assert!(conversation.archived_at_ms.is_none());
    let members = conversation
        .members
        .iter()
        .map(|member| (member.agent_id.as_str(), member.delivery_mode.as_str()))
        .collect::<Vec<_>>();
    let expected = reference
        .members()
        .iter()
        .map(|member| {
            (
                member.agent_id().as_str(),
                match member.delivery_mode() {
                    DeliveryMode::Inbox => "inbox",
                    DeliveryMode::StreamOnly => "stream_only",
                },
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(members, expected);
}

fn read_operator_token(path: &Path) -> String {
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|_| panic!("operator token file inspection failed"));
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.mode() & 0o777, 0o600);
    let token = fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("operator token file read failed"))
        .trim()
        .to_owned();
    assert!(token.starts_with("fl_op_"));
    token
}

fn read_tree(root: &Path) -> Vec<u8> {
    let mut paths = fs::read_dir(root)
        .unwrap_or_else(|_| panic!("journal enumeration failed"))
        .map(|entry| {
            entry
                .unwrap_or_else(|_| panic!("journal entry inspection failed"))
                .path()
        })
        .collect::<Vec<_>>();
    paths.sort();
    let mut bytes = Vec::new();
    for path in paths {
        let metadata =
            fs::symlink_metadata(&path).unwrap_or_else(|_| panic!("journal entry metadata failed"));
        if metadata.file_type().is_dir() {
            bytes.extend(read_tree(&path));
        } else if metadata.file_type().is_file() {
            bytes.extend(fs::read(path).unwrap_or_else(|_| panic!("journal entry read failed")));
        } else {
            panic!("journal contained a non-file entry");
        }
    }
    bytes
}

fn assert_journal_canaries_absent(
    surface: &[u8],
    endpoint: &str,
    token: &str,
    authority: &[u8],
    agent_bearers: &[&SecretCanary],
) {
    for canary in endpoint_spellings(endpoint) {
        assert!(
            !contains_bytes(surface, &canary),
            "live endpoint spelling appeared in journal"
        );
    }
    assert!(
        !contains_bytes(surface, token.as_bytes()),
        "operator bearer appeared in journal"
    );
    assert!(
        !contains_bytes(surface, authority),
        "complete authority appeared in journal"
    );
    for bearer in agent_bearers {
        assert!(
            !contains_bytes(surface, bearer.as_bytes()),
            "one-time agent bearer appeared in journal"
        );
    }
}

fn assert_log_canaries_absent(
    surface: &[u8],
    endpoint: &str,
    token: &str,
    authority: &[u8],
    agent_bearers: &[&SecretCanary],
) {
    assert!(
        !contains_bytes(surface, token.as_bytes()),
        "operator bearer appeared in daemon logs"
    );
    assert!(
        !contains_bytes(surface, authority),
        "complete authority appeared in daemon logs"
    );
    for bearer in agent_bearers {
        assert!(
            !contains_bytes(surface, bearer.as_bytes()),
            "one-time agent bearer appeared in daemon logs"
        );
    }
    let endpoint_spellings = endpoint_spellings(endpoint);
    for line in surface.split(|byte| *byte == b'\n') {
        // Fleetd intentionally publishes its listen/browser origin on the one
        // readiness line. That public address is not claimed absent; all other
        // log lines remain subject to the endpoint-spelling scan.
        if contains_bytes(line, b"fleetd ready") {
            continue;
        }
        for spelling in &endpoint_spellings {
            assert!(
                !contains_bytes(line, spelling),
                "live endpoint spelling appeared outside the Fleetd readiness log"
            );
        }
    }
}

fn endpoint_spellings(endpoint: &str) -> [Vec<u8>; 4] {
    let raw = endpoint.trim_end_matches('/');
    [
        endpoint.as_bytes().to_vec(),
        raw.as_bytes().to_vec(),
        endpoint.replace('/', "\\/").into_bytes(),
        raw.replace('/', "\\/").into_bytes(),
    ]
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
