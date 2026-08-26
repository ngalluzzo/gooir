//! Proof-local bounded native process primitive.
//!
//! This module owns process mechanics only. It does not interpret provider or
//! attester output, mutate an attempt journal, grant replay, or derive a native
//! runtime identity. Process-group cleanup contains ordinary descendants but
//! cannot contain an artifact which deliberately creates a new session or
//! process group; trust in the exact qualified artifact digest is part of this
//! proof boundary.

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::sync::mpsc::{self, Sender};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use fleetd_direct_conversation_command_abi::{
    AUTHORITY_PROTOCOL, AuthorityDocument, MAX_AUTHORITY_DOCUMENT_BYTES, MAX_HTTP_TIMEOUT_MS,
    MAX_RESPONSE_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::native::{NativeQualificationError, QualifiedNativeArtifact};

#[cfg(target_os = "macos")]
mod darwin;

const MAX_STDIN_BYTES: usize = 16 * 1024 * 1024;
const MAX_STREAM_BYTES: usize = 384 * 1024;
const MAX_WALL_TIME: Duration = Duration::from_mins(5);
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const READ_CHUNK_BYTES: usize = 16 * 1024;
const MAX_TARGET_CHARS: usize = 256;
const MAX_CREDENTIAL_REVISION_CHARS: usize = 256;
const MAX_DARWIN_EXIT_CODE: i32 = 255;
const MAX_DARWIN_SIGNAL: i32 = 31;
/// Exact serialized receipt protocol.
pub const PROCESS_RECEIPT_PROTOCOL: &str =
    "org.gooi.proof.fleetd-native-command-process-receipt/v1";

/// Maximum canonical JSON size accepted for a supervisor receipt.
///
/// The retained stream ceilings reserve more than 1 MiB beneath this bound
/// after worst-case `Vec<u8>` JSON number encoding and fixed receipt fields.
pub const MAX_PROCESS_RECEIPT_JSON_BYTES: usize = crate::journal::MAX_EXACT_JSON_BYTES;

const RECEIPT_FIXED_JSON_RESERVE: usize = 4 * 1024;
const _: () = assert!(
    (2 * MAX_STREAM_BYTES * 4) + RECEIPT_FIXED_JSON_RESERVE <= MAX_PROCESS_RECEIPT_JSON_BYTES
);

/// Exact mechanics bound by [`NATIVE_SUPERVISOR_PROFILE_ID`].
///
/// This is qualification input for a later complete native-runtime profile;
/// it does not itself qualify a runtime or derive a journal lock.
pub const NATIVE_SUPERVISOR_PROFILE: &str = concat!(
    "org.gooi.proof/fleetd-native-command-supervisor@0.1.0;",
    "platform=darwin-aarch64;spawn=locked-direct-posix_spawn;argv0=fleetd-native-command;",
    "environment=empty;cwd=qualified-descriptor-addinherit-addfchdir-np-close;",
    "pipes=pipe-immediate-cloexec-explicit-source-close;",
    "fds=stdin-0,stdout-1,stderr-2,authority-3,cloexec-default-only;",
    "signals=empty-mask-defaults-reset;process-group=new;",
    "limits=stdin-16m,authority-abi-bound,stdout-384k,stderr-384k,wall-whole-ms-max-300s,receipt-json-4m;",
    "deadline=monotonic-before-revalidation-spawn-thread-start;",
    "pumps=concurrent-bounded-active-enforcement;",
    "exit-observation=waitid-p-pid-wexited-wnohang-wnowait;",
    "group-kill=zombie-anchor-eperm-esrch-only-after-wnowait-exit;",
    "terminal=kill-group-before-reap-once-before-joins,drop-kill-reap;",
    "redaction=exact-document-endpoint-bearer-and-bounded-prefix;",
    "receipt=protocol-profile-artifact-limits-input-digest-authority-correlation-stream-counts-derived-identity;",
    "eligibility=normal-exit-zero-and-intact-only;",
    "containment=process-group-only-qualified-artifact-trusted/v1"
);

/// Content identity of [`NATIVE_SUPERVISOR_PROFILE`].
pub const NATIVE_SUPERVISOR_PROFILE_ID: &str =
    "sha256:74ea77cac0bb0cdd0f510ae5d097d5e0a5fa8491f7a7fa35c38ec166fa4a35ed";

/// Exact caller-selected process bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLimits {
    max_stdin_bytes: usize,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
    wall_time: Duration,
}

impl ProcessLimits {
    /// Construct one closed set of process bounds.
    ///
    /// # Errors
    ///
    /// Refuses zero, sub-millisecond, non-whole-millisecond, or
    /// proof-profile-exceeding bounds.
    pub fn new(
        max_stdin_bytes: usize,
        max_stdout_bytes: usize,
        max_stderr_bytes: usize,
        wall_time: Duration,
    ) -> Result<Self, SupervisorError> {
        let Ok(wall_time_ms) = u64::try_from(wall_time.as_millis()) else {
            return Err(SupervisorError::InvalidLimits);
        };
        if max_stdin_bytes == 0
            || max_stdin_bytes > MAX_STDIN_BYTES
            || max_stdout_bytes == 0
            || max_stdout_bytes > MAX_STREAM_BYTES
            || max_stderr_bytes == 0
            || max_stderr_bytes > MAX_STREAM_BYTES
            || wall_time.is_zero()
            || wall_time > MAX_WALL_TIME
            || wall_time_ms == 0
            || Duration::from_millis(wall_time_ms) != wall_time
            || !wall_time.subsec_nanos().is_multiple_of(1_000_000)
        {
            return Err(SupervisorError::InvalidLimits);
        }
        Ok(Self {
            max_stdin_bytes,
            max_stdout_bytes,
            max_stderr_bytes,
            wall_time,
        })
    }

    #[must_use]
    pub const fn max_stdin_bytes(self) -> usize {
        self.max_stdin_bytes
    }

    #[must_use]
    pub const fn max_stdout_bytes(self) -> usize {
        self.max_stdout_bytes
    }

    #[must_use]
    pub const fn max_stderr_bytes(self) -> usize {
        self.max_stderr_bytes
    }

    #[must_use]
    pub const fn wall_time(self) -> Duration {
        self.wall_time
    }
}

/// Exact serializable limits applied to one supervised process.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedProcessLimits {
    max_stdin_bytes: u64,
    max_stdout_bytes: u64,
    max_stderr_bytes: u64,
    wall_time_ms: u64,
}

impl AppliedProcessLimits {
    fn from_limits(limits: ProcessLimits) -> Self {
        Self {
            max_stdin_bytes: u64::try_from(limits.max_stdin_bytes)
                .expect("closed stdin bound fits u64"),
            max_stdout_bytes: u64::try_from(limits.max_stdout_bytes)
                .expect("closed stdout bound fits u64"),
            max_stderr_bytes: u64::try_from(limits.max_stderr_bytes)
                .expect("closed stderr bound fits u64"),
            wall_time_ms: u64::try_from(limits.wall_time.as_millis())
                .expect("closed deadline fits u64 milliseconds"),
        }
    }

    fn as_limits(self) -> Result<ProcessLimits, SupervisorError> {
        ProcessLimits::new(
            usize::try_from(self.max_stdin_bytes).map_err(|_| SupervisorError::ReceiptInvalid)?,
            usize::try_from(self.max_stdout_bytes).map_err(|_| SupervisorError::ReceiptInvalid)?,
            usize::try_from(self.max_stderr_bytes).map_err(|_| SupervisorError::ReceiptInvalid)?,
            Duration::from_millis(self.wall_time_ms),
        )
        .map_err(|_| SupervisorError::ReceiptInvalid)
    }

    #[must_use]
    pub const fn max_stdin_bytes(self) -> u64 {
        self.max_stdin_bytes
    }

    #[must_use]
    pub const fn max_stdout_bytes(self) -> u64 {
        self.max_stdout_bytes
    }

    #[must_use]
    pub const fn max_stderr_bytes(self) -> u64 {
        self.max_stderr_bytes
    }

    #[must_use]
    pub const fn wall_time_ms(self) -> u64 {
        self.wall_time_ms
    }
}

/// Non-secret correlation copied from the exact authority document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCorrelation {
    protocol: String,
    target: String,
    endpoint_mapping_digest: String,
    credential_revision: String,
    http_timeout_ms: u64,
    max_response_bytes: u64,
}

impl AuthorityCorrelation {
    fn from_document(document: &AuthorityDocument) -> Self {
        Self {
            protocol: document.protocol().to_owned(),
            target: document.target().to_owned(),
            endpoint_mapping_digest: document.endpoint_mapping_digest().to_owned(),
            credential_revision: document.credential_revision().to_owned(),
            http_timeout_ms: document.http_timeout_ms(),
            max_response_bytes: document.max_response_bytes(),
        }
    }

    fn validate(&self) -> Result<(), SupervisorError> {
        if self.protocol != AUTHORITY_PROTOCOL
            || !valid_opaque(&self.target, MAX_TARGET_CHARS)
            || !valid_opaque(&self.credential_revision, MAX_CREDENTIAL_REVISION_CHARS)
            || self.http_timeout_ms == 0
            || self.http_timeout_ms > MAX_HTTP_TIMEOUT_MS
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(SupervisorError::ReceiptInvalid);
        }
        validate_sha256(&self.endpoint_mapping_digest)
    }

    #[must_use]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    #[must_use]
    pub fn endpoint_mapping_digest(&self) -> &str {
        &self.endpoint_mapping_digest
    }

    #[must_use]
    pub fn credential_revision(&self) -> &str {
        &self.credential_revision
    }

    #[must_use]
    pub const fn http_timeout_ms(&self) -> u64 {
        self.http_timeout_ms
    }

    #[must_use]
    pub const fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }
}

/// Exact stdin identity and non-secret authority correlation for one launch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessInputBinding {
    stdin_bytes: u64,
    stdin_digest: String,
    authority: AuthorityCorrelation,
}

impl ProcessInputBinding {
    fn from_request(stdin: &[u8], authority: &AuthorityDocument) -> Result<Self, SupervisorError> {
        let binding = Self {
            stdin_bytes: u64::try_from(stdin.len()).map_err(|_| SupervisorError::ReceiptInvalid)?,
            stdin_digest: sha256_identity(stdin),
            authority: AuthorityCorrelation::from_document(authority),
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), SupervisorError> {
        validate_sha256(&self.stdin_digest)?;
        self.authority.validate()
    }

    #[must_use]
    pub const fn stdin_bytes(&self) -> u64 {
        self.stdin_bytes
    }

    #[must_use]
    pub fn stdin_digest(&self) -> &str {
        &self.stdin_digest
    }

    #[must_use]
    pub const fn authority(&self) -> &AuthorityCorrelation {
        &self.authority
    }
}

/// OS-level child termination, without semantic interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum ProcessTermination {
    Exited { code: i32 },
    Signaled { signal: i32 },
    Other { raw_status: i32 },
}

/// Precision of the decimal observed-byte count.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedByteCount {
    /// The decimal count is exact.
    Exact,
    /// The decimal count saturated at `u64::MAX`.
    Saturated,
}

/// One independently bounded output stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedStream {
    bytes: Vec<u8>,
    observed_prefix_digest: String,
    retained_prefix_bytes: u64,
    observed_bytes: String,
    observed_byte_count: ObservedByteCount,
    overflowed: bool,
    read_failed: bool,
    redacted: bool,
}

impl CapturedStream {
    /// Retained prefix after mandatory authority redaction.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Digest of the exact retained prefix before authority redaction.
    #[must_use]
    pub fn observed_prefix_digest(&self) -> &str {
        &self.observed_prefix_digest
    }

    /// Exact retained-prefix length before authority redaction.
    #[must_use]
    pub const fn retained_prefix_bytes(&self) -> u64 {
        self.retained_prefix_bytes
    }

    /// Decimal count of all bytes drained, saturating at `u64::MAX`.
    #[must_use]
    pub fn observed_bytes(&self) -> &str {
        &self.observed_bytes
    }

    #[must_use]
    pub const fn observed_bytes_saturated(&self) -> bool {
        matches!(self.observed_byte_count, ObservedByteCount::Saturated)
    }

    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    #[must_use]
    pub const fn read_failed(&self) -> bool {
        self.read_failed
    }

    #[must_use]
    pub const fn redacted(&self) -> bool {
        self.redacted
    }

    fn validate(&self, limit: usize) -> Result<(), SupervisorError> {
        validate_sha256(&self.observed_prefix_digest)?;
        let observed = parse_decimal_u64(&self.observed_bytes)?;
        let saturated = self.observed_bytes_saturated();
        if saturated && observed != u64::MAX {
            return Err(SupervisorError::ReceiptInvalid);
        }
        let retained = usize::try_from(self.retained_prefix_bytes)
            .map_err(|_| SupervisorError::ReceiptInvalid)?;
        let limit_u64 = u64::try_from(limit).map_err(|_| SupervisorError::ReceiptInvalid)?;
        if retained > limit
            || self.bytes.len() > retained
            || (!saturated && observed < self.retained_prefix_bytes)
            || (self.overflowed && !saturated && observed <= limit_u64)
            || (!self.overflowed && (saturated || observed > limit_u64))
            || (!self.redacted && self.bytes.len() != retained)
            || (!self.redacted && sha256_identity(&self.bytes) != self.observed_prefix_digest)
        {
            return Err(SupervisorError::ReceiptInvalid);
        }
        Ok(())
    }
}

/// Enforcement observations which make a receipt ineligible for semantic use.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEnforcement {
    timed_out: bool,
    stdin_write_failed: bool,
    authority_write_failed: bool,
}

impl ProcessEnforcement {
    #[must_use]
    pub const fn timed_out(self) -> bool {
        self.timed_out
    }

    #[must_use]
    pub const fn stdin_write_failed(self) -> bool {
        self.stdin_write_failed
    }

    #[must_use]
    pub const fn authority_write_failed(self) -> bool {
        self.authority_write_failed
    }
}

/// Exact bounded native-process receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessReceipt {
    receipt_id: String,
    protocol: String,
    supervisor_profile_id: String,
    artifact_lock_id: String,
    limits: AppliedProcessLimits,
    input: ProcessInputBinding,
    termination: ProcessTermination,
    stdout: CapturedStream,
    stderr: CapturedStream,
    enforcement: ProcessEnforcement,
    decisive_eligible: bool,
}

impl ProcessReceipt {
    fn new(
        artifact_lock_id: &str,
        limits: ProcessLimits,
        input: ProcessInputBinding,
        termination: ProcessTermination,
        stdout: CapturedStream,
        stderr: CapturedStream,
        enforcement: ProcessEnforcement,
    ) -> Result<Self, SupervisorError> {
        let decisive_eligible = matches!(termination, ProcessTermination::Exited { code: 0 })
            && !enforcement.timed_out
            && !enforcement.stdin_write_failed
            && !enforcement.authority_write_failed
            && !stdout.overflowed
            && !stderr.overflowed
            && !stdout.read_failed
            && !stderr.read_failed
            && !stdout.redacted
            && !stderr.redacted;
        let mut receipt = Self {
            receipt_id: placeholder_identity(),
            protocol: PROCESS_RECEIPT_PROTOCOL.to_owned(),
            supervisor_profile_id: NATIVE_SUPERVISOR_PROFILE_ID.to_owned(),
            artifact_lock_id: artifact_lock_id.to_owned(),
            limits: AppliedProcessLimits::from_limits(limits),
            input,
            termination,
            stdout,
            stderr,
            enforcement,
            decisive_eligible,
        };
        receipt.receipt_id = receipt.derived_id()?;
        receipt.validate()?;
        Ok(receipt)
    }

    #[must_use]
    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    #[must_use]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    #[must_use]
    pub fn supervisor_profile_id(&self) -> &str {
        &self.supervisor_profile_id
    }

    #[must_use]
    pub fn artifact_lock_id(&self) -> &str {
        &self.artifact_lock_id
    }

    #[must_use]
    pub const fn limits(&self) -> AppliedProcessLimits {
        self.limits
    }

    #[must_use]
    pub const fn input(&self) -> &ProcessInputBinding {
        &self.input
    }

    #[must_use]
    pub const fn termination(&self) -> ProcessTermination {
        self.termination
    }

    #[must_use]
    pub const fn stdout(&self) -> &CapturedStream {
        &self.stdout
    }

    #[must_use]
    pub const fn stderr(&self) -> &CapturedStream {
        &self.stderr
    }

    #[must_use]
    pub const fn enforcement(&self) -> ProcessEnforcement {
        self.enforcement
    }

    /// Whether byte evidence is intact enough for a separate driver to
    /// interpret. This says nothing about provider or attester semantics.
    #[must_use]
    pub const fn decisive_eligible(&self) -> bool {
        self.decisive_eligible
    }

    /// Revalidate protocol/profile/artifact/limits, bounded stream evidence,
    /// eligibility, and the derived receipt identity.
    ///
    /// # Errors
    ///
    /// Refuses any malformed, oversized, inconsistent, or identity-drifting
    /// receipt.
    pub fn validate(&self) -> Result<(), SupervisorError> {
        validate_sha256(&self.receipt_id)?;
        validate_sha256(&self.artifact_lock_id)?;
        if self.protocol != PROCESS_RECEIPT_PROTOCOL
            || self.supervisor_profile_id != NATIVE_SUPERVISOR_PROFILE_ID
        {
            return Err(SupervisorError::ReceiptInvalid);
        }
        let limits = self.limits.as_limits()?;
        self.input.validate()?;
        if self.input.stdin_bytes > self.limits.max_stdin_bytes {
            return Err(SupervisorError::ReceiptInvalid);
        }
        self.stdout.validate(limits.max_stdout_bytes)?;
        self.stderr.validate(limits.max_stderr_bytes)?;
        match self.termination {
            ProcessTermination::Exited { code } if !(0..=MAX_DARWIN_EXIT_CODE).contains(&code) => {
                return Err(SupervisorError::ReceiptInvalid);
            }
            ProcessTermination::Signaled { signal }
                if !(1..=MAX_DARWIN_SIGNAL).contains(&signal) =>
            {
                return Err(SupervisorError::ReceiptInvalid);
            }
            _ => {}
        }
        let expected_eligibility =
            matches!(self.termination, ProcessTermination::Exited { code: 0 })
                && !self.enforcement.timed_out
                && !self.enforcement.stdin_write_failed
                && !self.enforcement.authority_write_failed
                && !self.stdout.overflowed
                && !self.stderr.overflowed
                && !self.stdout.read_failed
                && !self.stderr.read_failed
                && !self.stdout.redacted
                && !self.stderr.redacted;
        if self.decisive_eligible != expected_eligibility || self.receipt_id != self.derived_id()? {
            return Err(SupervisorError::ReceiptInvalid);
        }
        let canonical =
            serde_json_canonicalizer::to_vec(self).map_err(|_| SupervisorError::ReceiptInvalid)?;
        if canonical.len() > MAX_PROCESS_RECEIPT_JSON_BYTES {
            return Err(SupervisorError::ReceiptInvalid);
        }
        Ok(())
    }

    fn derived_id(&self) -> Result<String, SupervisorError> {
        #[derive(Serialize)]
        struct Body<'a> {
            protocol: &'a str,
            supervisor_profile_id: &'a str,
            artifact_lock_id: &'a str,
            limits: AppliedProcessLimits,
            input: &'a ProcessInputBinding,
            termination: ProcessTermination,
            stdout: &'a CapturedStream,
            stderr: &'a CapturedStream,
            enforcement: ProcessEnforcement,
            decisive_eligible: bool,
        }
        let canonical = serde_json_canonicalizer::to_vec(&Body {
            protocol: &self.protocol,
            supervisor_profile_id: &self.supervisor_profile_id,
            artifact_lock_id: &self.artifact_lock_id,
            limits: self.limits,
            input: &self.input,
            termination: self.termination,
            stdout: &self.stdout,
            stderr: &self.stderr,
            enforcement: self.enforcement,
            decisive_eligible: self.decisive_eligible,
        })
        .map_err(|_| SupervisorError::ReceiptInvalid)?;
        Ok(sha256_identity(&canonical))
    }
}

/// Launch one already-qualified artifact under exact process bounds.
///
/// Authority is encoded only at the inherited-pipe seam. The endpoint, bearer
/// token, and complete encoded document are rejected from stdin and removed
/// from retained streams. Any removal makes the receipt non-decisive.
///
/// # Errors
///
/// Refuses unqualified/tampered artifacts, invalid bounds, oversized or
/// authority-bearing stdin, authority encoding failure, unsupported hosts,
/// spawn/reap failure, or internal thread failure.
pub fn launch(
    artifact: &QualifiedNativeArtifact,
    authority: &AuthorityDocument,
    stdin: &[u8],
    limits: ProcessLimits,
) -> Result<ProcessReceipt, SupervisorError> {
    validate_limits(limits)?;
    if stdin.len() > limits.max_stdin_bytes {
        return Err(SupervisorError::StdinTooLarge);
    }
    let authority_bytes = authority
        .encode_for_pipe()
        .map_err(|_| SupervisorError::AuthorityEncoding)?;
    if authority_bytes.len() > MAX_AUTHORITY_DOCUMENT_BYTES {
        return Err(SupervisorError::AuthorityEncoding);
    }
    let endpoint = authority.endpoint().as_bytes();
    let bearer = authority.bearer_token().expose_secret().as_bytes();
    if contains(stdin, endpoint) || contains(stdin, bearer) || contains(stdin, &authority_bytes) {
        return Err(SupervisorError::SensitiveStdin);
    }
    let input_binding = ProcessInputBinding::from_request(stdin, authority)?;

    #[cfg(target_os = "macos")]
    {
        launch_macos(
            artifact,
            stdin,
            limits,
            &authority_bytes,
            input_binding,
            [endpoint, bearer],
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (artifact, authority_bytes, input_binding, endpoint, bearer);
        Err(SupervisorError::UnsupportedPlatform)
    }
}

fn validate_limits(limits: ProcessLimits) -> Result<(), SupervisorError> {
    ProcessLimits::new(
        limits.max_stdin_bytes,
        limits.max_stdout_bytes,
        limits.max_stderr_bytes,
        limits.wall_time,
    )
    .map(|_| ())
}

#[cfg(target_os = "macos")]
fn launch_macos(
    artifact: &QualifiedNativeArtifact,
    stdin: &[u8],
    limits: ProcessLimits,
    authority_bytes: &[u8],
    input_binding: ProcessInputBinding,
    individual_secrets: [&[u8]; 2],
) -> Result<ProcessReceipt, SupervisorError> {
    let deadline = Instant::now()
        .checked_add(limits.wall_time)
        .ok_or(SupervisorError::InvalidLimits)?;
    let access = artifact
        .revalidated_spawn_access()
        .map_err(SupervisorError::Qualification)?;
    let process = darwin::spawn(access.executable_path(), access.cwd())
        .map_err(|_| SupervisorError::Spawn)?;
    let run = supervise_process(process, stdin, authority_bytes, limits, deadline)?;
    let needles = [
        authority_bytes,
        individual_secrets[0],
        individual_secrets[1],
    ];
    let stdout = finish_capture(run.stdout, &needles);
    let stderr = finish_capture(run.stderr, &needles);
    ProcessReceipt::new(
        artifact.lock().lock_id(),
        limits,
        input_binding,
        run.termination.into(),
        stdout,
        stderr,
        run.enforcement,
    )
}

#[cfg(target_os = "macos")]
struct RawRun {
    termination: darwin::WaitStatus,
    stdout: RawCapture,
    stderr: RawCapture,
    enforcement: ProcessEnforcement,
}

#[cfg(target_os = "macos")]
fn supervise_process(
    process: darwin::SpawnedProcess,
    stdin: &[u8],
    authority_bytes: &[u8],
    limits: ProcessLimits,
    deadline: Instant,
) -> Result<RawRun, SupervisorError> {
    let darwin::SpawnedProcess {
        pid,
        stdin: child_stdin,
        authority: child_authority,
        stdout: child_stdout,
        stderr: child_stderr,
    } = process;
    let mut child = LiveChild::new(pid);
    let (events, event_rx) = mpsc::channel();
    let enforce_now = Arc::new(AtomicBool::new(false));

    let stdin_writer = spawn_writer(
        "fleetd-native-stdin",
        child_stdin,
        stdin.to_vec(),
        events.clone(),
        Arc::clone(&enforce_now),
    )?;
    let authority_writer = spawn_writer(
        "fleetd-native-authority",
        child_authority,
        authority_bytes.to_vec(),
        events.clone(),
        Arc::clone(&enforce_now),
    )?;
    let stdout_reader = spawn_reader(
        "fleetd-native-stdout",
        child_stdout,
        limits.max_stdout_bytes,
        events.clone(),
        Arc::clone(&enforce_now),
    )?;
    let stderr_reader = spawn_reader(
        "fleetd-native-stderr",
        child_stderr,
        limits.max_stderr_bytes,
        events,
        Arc::clone(&enforce_now),
    )?;

    let (termination, timed_out) = monitor_child(&mut child, &event_rx, &enforce_now, deadline)?;
    // monitor_child retains the leader until the group is killed, then reaps
    // it exactly once. Pipe joins therefore cannot outlive group cleanup.
    Ok(RawRun {
        termination,
        stdout: join(stdout_reader)?,
        stderr: join(stderr_reader)?,
        enforcement: ProcessEnforcement {
            timed_out,
            stdin_write_failed: join(stdin_writer)?,
            authority_write_failed: join(authority_writer)?,
        },
    })
}

#[cfg(target_os = "macos")]
fn monitor_child(
    child: &mut LiveChild,
    events: &mpsc::Receiver<()>,
    enforce_now: &AtomicBool,
    deadline: Instant,
) -> Result<(darwin::WaitStatus, bool), SupervisorError> {
    loop {
        if enforce_now.load(Ordering::Acquire) {
            child
                .kill_group()
                .map_err(|_| SupervisorError::Enforcement)?;
            return child
                .wait()
                .map(|status| (status, false))
                .map_err(|_| SupervisorError::Reap);
        }
        if child.has_exited().map_err(|_| SupervisorError::Reap)? {
            child
                .kill_group()
                .map_err(|_| SupervisorError::Enforcement)?;
            return child
                .wait()
                .map(|status| (status, false))
                .map_err(|_| SupervisorError::Reap);
        }
        let now = Instant::now();
        if now >= deadline {
            child
                .kill_group()
                .map_err(|_| SupervisorError::Enforcement)?;
            return child
                .wait()
                .map(|status| (status, true))
                .map_err(|_| SupervisorError::Reap);
        }
        let wait = POLL_INTERVAL.min(deadline.saturating_duration_since(now));
        match events.recv_timeout(wait) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => thread::sleep(wait),
        }
    }
}

#[cfg(target_os = "macos")]
impl From<darwin::WaitStatus> for ProcessTermination {
    fn from(value: darwin::WaitStatus) -> Self {
        match value {
            darwin::WaitStatus::Exited(code) => Self::Exited { code },
            darwin::WaitStatus::Signaled(signal) => Self::Signaled { signal },
            darwin::WaitStatus::Other(raw_status) => Self::Other { raw_status },
        }
    }
}

#[cfg(target_os = "macos")]
struct LiveChild {
    pid: libc::pid_t,
    reaped: bool,
}

#[cfg(target_os = "macos")]
impl LiveChild {
    const fn new(pid: libc::pid_t) -> Self {
        Self { pid, reaped: false }
    }

    fn has_exited(&self) -> std::io::Result<bool> {
        darwin::has_exited(self.pid)
    }

    fn wait(&mut self) -> std::io::Result<darwin::WaitStatus> {
        let status = darwin::wait(self.pid)?;
        self.reaped = true;
        Ok(status)
    }

    fn kill_group(&self) -> std::io::Result<()> {
        match darwin::kill_group(self.pid) {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(error.raw_os_error(), Some(libc::EPERM | libc::ESRCH))
                    && self.has_exited()? =>
            {
                // Darwin reports EPERM for a group containing only the
                // WNOWAIT-retained zombie leader. ESRCH likewise means no
                // signalable group remains. Any ordinary same-credential live
                // descendant makes the group signal succeed instead.
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for LiveChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.kill_group();
            let _ = darwin::wait(self.pid);
            self.reaped = true;
        }
    }
}

fn spawn_writer(
    name: &'static str,
    mut file: File,
    bytes: Vec<u8>,
    events: Sender<()>,
    enforce_now: Arc<AtomicBool>,
) -> Result<JoinHandle<bool>, SupervisorError> {
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let failed = file.write_all(&bytes).and_then(|()| file.flush()).is_err();
            if failed {
                enforce_now.store(true, Ordering::Release);
                let _ = events.send(());
            }
            failed
        })
        .map_err(|_| SupervisorError::ThreadStart)
}

fn spawn_reader(
    name: &'static str,
    file: File,
    limit: usize,
    events: Sender<()>,
    enforce_now: Arc<AtomicBool>,
) -> Result<JoinHandle<RawCapture>, SupervisorError> {
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || drain(file, limit, &events, &enforce_now))
        .map_err(|_| SupervisorError::ThreadStart)
}

fn drain(
    mut file: File,
    limit: usize,
    events: &Sender<()>,
    enforce_now: &AtomicBool,
) -> RawCapture {
    let mut bytes = Vec::with_capacity(limit.min(READ_CHUNK_BYTES));
    let mut buffer = [0_u8; READ_CHUNK_BYTES];
    let mut overflowed = false;
    let mut observed_bytes = 0_u64;
    let mut observed_bytes_saturated = false;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                observe_bytes(&mut observed_bytes, &mut observed_bytes_saturated, read);
                let remaining = limit.saturating_sub(bytes.len());
                bytes.extend_from_slice(&buffer[..read.min(remaining)]);
                if read > remaining && !overflowed {
                    overflowed = true;
                    enforce_now.store(true, Ordering::Release);
                    let _ = events.send(());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                enforce_now.store(true, Ordering::Release);
                let _ = events.send(());
                return RawCapture {
                    bytes,
                    observed_bytes,
                    observed_bytes_saturated,
                    overflowed,
                    read_failed: true,
                };
            }
        }
    }
    RawCapture {
        bytes,
        observed_bytes,
        observed_bytes_saturated,
        overflowed,
        read_failed: false,
    }
}

fn join<T>(handle: JoinHandle<T>) -> Result<T, SupervisorError> {
    handle.join().map_err(|_| SupervisorError::ThreadPanicked)
}

struct RawCapture {
    bytes: Vec<u8>,
    observed_bytes: u64,
    observed_bytes_saturated: bool,
    overflowed: bool,
    read_failed: bool,
}

fn finish_capture(raw: RawCapture, needles: &[&[u8]]) -> CapturedStream {
    let digest = sha256_identity(&raw.bytes);
    let retained_prefix_bytes = u64::try_from(raw.bytes.len()).expect("stream bound fits u64");
    let mut bytes = raw.bytes;
    let redacted = redact_exact(&mut bytes, needles);
    CapturedStream {
        bytes,
        observed_prefix_digest: digest,
        retained_prefix_bytes,
        observed_bytes: raw.observed_bytes.to_string(),
        observed_byte_count: if raw.observed_bytes_saturated {
            ObservedByteCount::Saturated
        } else {
            ObservedByteCount::Exact
        },
        overflowed: raw.overflowed,
        read_failed: raw.read_failed,
        redacted,
    }
}

fn observe_bytes(total: &mut u64, saturated: &mut bool, amount: usize) {
    if *saturated {
        return;
    }
    let Ok(amount) = u64::try_from(amount) else {
        *total = u64::MAX;
        *saturated = true;
        return;
    };
    if let Some(next) = total.checked_add(amount) {
        *total = next;
    } else {
        *total = u64::MAX;
        *saturated = true;
    }
}

fn redact_exact(bytes: &mut Vec<u8>, needles: &[&[u8]]) -> bool {
    let mut needles = needles
        .iter()
        .copied()
        .filter(|needle| !needle.is_empty())
        .collect::<Vec<_>>();
    needles.sort_by_key(|needle| std::cmp::Reverse(needle.len()));
    needles.dedup();
    let mut redacted = false;
    for needle in needles {
        let mut cursor = 0;
        while let Some(relative) = find(&bytes[cursor..], needle) {
            let start = cursor + relative;
            bytes.splice(start..start + needle.len(), [b'*']);
            cursor = start + 1;
            redacted = true;
        }
        // Bounded retention can end inside a sensitive value. Remove the
        // longest retained prefix at the stream boundary as well, so overflow
        // cannot disclose a token or authority-document prefix.
        let partial = (1..needle.len())
            .rev()
            .find(|length| bytes.ends_with(&needle[..*length]));
        if let Some(length) = partial {
            bytes.splice(bytes.len() - length.., [b'*']);
            redacted = true;
        }
    }
    redacted
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty() && needle.len() <= haystack.len())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        })
        .flatten()
}

fn sha256_identity(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn placeholder_identity() -> String {
    format!("sha256:{}", "0".repeat(64))
}

fn validate_sha256(value: &str) -> Result<(), SupervisorError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(SupervisorError::ReceiptInvalid);
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SupervisorError::ReceiptInvalid);
    }
    Ok(())
}

fn parse_decimal_u64(value: &str) -> Result<u64, SupervisorError> {
    if value.is_empty()
        || value.trim() != value
        || (value.starts_with('0') && value.len() != 1)
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(SupervisorError::ReceiptInvalid);
    }
    value.parse().map_err(|_| SupervisorError::ReceiptInvalid)
}

fn valid_opaque(value: &str, max_chars: usize) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.chars().count() <= max_chars
        && !value.chars().any(char::is_control)
}

/// Secret-free supervisor failure class.
#[derive(Debug)]
pub enum SupervisorError {
    InvalidLimits,
    StdinTooLarge,
    SensitiveStdin,
    AuthorityEncoding,
    UnsupportedPlatform,
    Qualification(NativeQualificationError),
    Spawn,
    Enforcement,
    Reap,
    ThreadStart,
    ThreadPanicked,
    ReceiptInvalid,
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimits => "native process limits are outside the closed proof profile",
            Self::StdinTooLarge => "native process stdin exceeds its exact byte bound",
            Self::SensitiveStdin => "native process stdin contains deployment authority",
            Self::AuthorityEncoding => "native process authority could not be encoded",
            Self::UnsupportedPlatform => "native supervisor supports only its Darwin profile",
            Self::Qualification(_) => "native artifact revalidation failed before spawn",
            Self::Spawn => "native process spawn failed",
            Self::Enforcement => "native process-group enforcement failed",
            Self::Reap => "native process reap failed",
            Self::ThreadStart => "native process I/O thread could not start",
            Self::ThreadPanicked => "native process I/O thread failed internally",
            Self::ReceiptInvalid => "native process receipt is invalid",
        })
    }
}

impl Error for SupervisorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Qualification(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CapturedStream, MAX_PROCESS_RECEIPT_JSON_BYTES, MAX_STREAM_BYTES,
        NATIVE_SUPERVISOR_PROFILE, NATIVE_SUPERVISOR_PROFILE_ID, ProcessEnforcement,
        ProcessInputBinding, ProcessLimits, ProcessReceipt, ProcessTermination, redact_exact,
        sha256_identity,
    };
    use std::time::Duration;

    #[test]
    fn limits_are_closed_and_redaction_never_grows_evidence() {
        assert_eq!(
            NATIVE_SUPERVISOR_PROFILE_ID,
            sha256_identity(NATIVE_SUPERVISOR_PROFILE.as_bytes())
        );
        assert!(ProcessLimits::new(1, 1, 1, Duration::from_millis(1)).is_ok());
        assert!(ProcessLimits::new(0, 1, 1, Duration::from_millis(1)).is_err());
        assert!(ProcessLimits::new(1, 1, 1, Duration::ZERO).is_err());
        assert!(ProcessLimits::new(1, 1, 1, Duration::from_nanos(1)).is_err());

        let mut bytes = b"before-secret-after-secret".to_vec();
        let original_len = bytes.len();
        assert!(redact_exact(&mut bytes, &[b"secret"]));
        assert_eq!(bytes, b"before-*-after-*");
        assert!(bytes.len() <= original_len);

        let mut truncated = b"ordinary-secret-pr".to_vec();
        assert!(redact_exact(&mut truncated, &[b"secret-private"]));
        assert_eq!(truncated, b"ordinary-*");
    }

    #[test]
    fn worst_case_receipt_fits_the_durable_exact_json_bound() {
        let stream = || {
            let bytes = vec![u8::MAX; MAX_STREAM_BYTES];
            CapturedStream {
                observed_prefix_digest: sha256_identity(&bytes),
                bytes,
                retained_prefix_bytes: u64::try_from(MAX_STREAM_BYTES).expect("stream bound"),
                observed_bytes: u64::try_from(MAX_STREAM_BYTES + 1)
                    .expect("observed bytes")
                    .to_string(),
                observed_byte_count: super::ObservedByteCount::Exact,
                overflowed: true,
                read_failed: true,
                redacted: false,
            }
        };
        let limits = ProcessLimits::new(
            super::MAX_STDIN_BYTES,
            MAX_STREAM_BYTES,
            MAX_STREAM_BYTES,
            super::MAX_WALL_TIME,
        )
        .expect("maximum limits");
        let authority = super::AuthorityDocument::new(
            "fleetd:receipt-bound-test",
            format!("sha256:{}", "b".repeat(64)),
            "credential/revision-receipt-test",
            "http://127.0.0.1:43123/",
            "receipt-bound-test-secret",
            1_000,
            64 * 1024,
        )
        .expect("authority");
        let input = ProcessInputBinding::from_request(b"maximum receipt input", &authority)
            .expect("input binding");
        let receipt = ProcessReceipt::new(
            &format!("sha256:{}", "a".repeat(64)),
            limits,
            input,
            ProcessTermination::Other {
                raw_status: i32::MIN,
            },
            stream(),
            stream(),
            ProcessEnforcement {
                timed_out: true,
                stdin_write_failed: true,
                authority_write_failed: true,
            },
        )
        .expect("maximum receipt");
        let canonical = serde_json_canonicalizer::to_vec(&receipt).expect("canonical receipt");
        assert!(canonical.len() <= MAX_PROCESS_RECEIPT_JSON_BYTES);
        let mut changed_artifact = receipt.clone();
        changed_artifact.artifact_lock_id = format!("sha256:{}", "c".repeat(64));
        assert!(changed_artifact.validate().is_err());
        let mut promoted = receipt.clone();
        promoted.decisive_eligible = true;
        assert!(promoted.validate().is_err());
        let mut impossible_exit = receipt.clone();
        impossible_exit.termination = ProcessTermination::Exited { code: -1 };
        assert!(impossible_exit.validate().is_err());
        let mut impossible_signal = receipt.clone();
        impossible_signal.termination = ProcessTermination::Signaled { signal: 32 };
        assert!(impossible_signal.validate().is_err());
        let mut impossible_authority = receipt.clone();
        impossible_authority.input.authority.target = "x".repeat(super::MAX_TARGET_CHARS + 1);
        assert!(impossible_authority.validate().is_err());
        let value = serde_json::to_value(receipt).expect("receipt value");
        crate::journal::ExactJson::new(value).expect("receipt fits durable exact JSON");
    }

    #[test]
    fn receipt_deserialization_rejects_unknown_termination_evidence() {
        let limits = ProcessLimits::new(1, 1, 1, Duration::from_millis(1)).expect("limits");
        let authority = super::AuthorityDocument::new(
            "fleetd:exact-shape-test",
            format!("sha256:{}", "b".repeat(64)),
            "credential/revision-exact-shape-test",
            "http://127.0.0.1:43123/",
            "exact-shape-test-secret",
            1_000,
            64 * 1024,
        )
        .expect("authority");
        let input = ProcessInputBinding::from_request(b"x", &authority).expect("input binding");
        let empty_stream = || CapturedStream {
            bytes: Vec::new(),
            observed_prefix_digest: sha256_identity(&[]),
            retained_prefix_bytes: 0,
            observed_bytes: "0".to_owned(),
            observed_byte_count: super::ObservedByteCount::Exact,
            overflowed: false,
            read_failed: false,
            redacted: false,
        };
        let receipt = ProcessReceipt::new(
            &format!("sha256:{}", "a".repeat(64)),
            limits,
            input,
            ProcessTermination::Exited { code: 0 },
            empty_stream(),
            empty_stream(),
            ProcessEnforcement {
                timed_out: false,
                stdin_write_failed: false,
                authority_write_failed: false,
            },
        )
        .expect("valid receipt");
        let mut value = serde_json::to_value(receipt).expect("receipt JSON");
        value
            .get_mut("termination")
            .and_then(serde_json::Value::as_object_mut)
            .expect("termination object")
            .insert(
                "unknown_nested_field".to_owned(),
                serde_json::Value::Bool(true),
            );

        assert!(serde_json::from_value::<ProcessReceipt>(value).is_err());
    }
}
