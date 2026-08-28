//! Bounded local stdio execution for explicitly installed provider and
//! attester artifacts.
//!
//! This is one narrow [`DerivationHost`](crate::DerivationHost), not a
//! universal runtime. Provider bytes come only from exact installed offers;
//! attester bytes come only from explicit package-resource bindings whose
//! copied digest matches the complete selected conformance authority. Each
//! artifact is materialized in a private temporary directory and invoked by
//! that exact path with no arguments or implicit discovery. The environment is
//! empty by default; a host may explicitly grant bounded variables to one
//! exact [`OfferId`], including `PATH` when it intentionally grants lookup.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::num::{NonZeroU64, NonZeroUsize};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use gooir_capability::assessment::AssessmentRequest;
use gooir_capability::authority::{ConformanceAssessment, ConformanceAuthority};
use gooir_capability::protocol::{
    CapabilityCandidate, CapabilityInvocation, CapabilityResult, OfferId,
};
use gooir_capability::strict_json;
use gooir_package::{PackageId, PackageRegistry, ResourceName};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::DerivationHost;

/// Mandatory positive bounds for every local stdio artifact invocation.
///
/// There is deliberately no default. A host must explicitly choose all four
/// limits before executing package bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalStdioLimits {
    pub max_stdin_bytes: NonZeroUsize,
    pub max_stdout_bytes: NonZeroUsize,
    pub max_stderr_bytes: NonZeroUsize,
    pub timeout_milliseconds: NonZeroU64,
}

impl LocalStdioLimits {
    fn timeout(self) -> Duration {
        Duration::from_millis(self.timeout_milliseconds.get())
    }
}

/// Explicit host configuration binding one complete conformance authority to
/// one exact resource in an explicitly installed package.
///
/// This is local host configuration, not a semantic package offer or an
/// executable discovery record.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalAttesterBinding {
    pub authority: ConformanceAuthority,
    pub package: PackageId,
    pub resource: ResourceName,
}

/// Explicit environment granted to one exact installed provider offer.
///
/// The default local stdio host supplies no environment. A binding is local
/// host configuration, not package metadata or a semantic fact. Because the
/// [`OfferId`] covers the capability, implementation, artifact digest, and
/// offer extensions, the same values cannot silently flow to a substituted
/// artifact.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalProviderEnvironmentBinding {
    pub offer: OfferId,
    pub variables: BTreeMap<String, String>,
}

const MAX_PROVIDER_ENVIRONMENT_VARIABLES: usize = 64;
const MAX_PROVIDER_ENVIRONMENT_NAME_BYTES: usize = 255;
const MAX_PROVIDER_ENVIRONMENT_VALUE_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_ENVIRONMENT_TOTAL_BYTES: usize = 1024 * 1024;

/// One bounded local execution host over a fixed copied package snapshot.
#[derive(Clone, Debug)]
pub struct LocalStdioHost {
    registry: PackageRegistry,
    attesters: Vec<LocalAttesterBinding>,
    provider_environments: BTreeMap<OfferId, BTreeMap<String, String>>,
    limits: LocalStdioLimits,
}

impl LocalStdioHost {
    /// Constructs one exact local host inventory.
    ///
    /// # Errors
    ///
    /// Refuses duplicate or invalid authorities, missing package resources,
    /// and every resource whose copied digest differs from its authority.
    pub fn new(
        registry: &PackageRegistry,
        attesters: impl IntoIterator<Item = LocalAttesterBinding>,
        limits: LocalStdioLimits,
    ) -> Result<Self, LocalStdioError> {
        Self::new_with_provider_environments(registry, attesters, [], limits)
    }

    /// Constructs a host with explicit environment bindings for exact offers.
    ///
    /// Attesters still receive no environment. Each provider binding must name
    /// one installed offer and satisfy fixed name, count, value, and aggregate
    /// bounds before any artifact is launched.
    ///
    /// # Errors
    ///
    /// Refuses invalid attester bindings, duplicate or unknown offer bindings,
    /// malformed environment names, NUL-bearing values, and bounds violations.
    pub fn new_with_provider_environments(
        registry: &PackageRegistry,
        attesters: impl IntoIterator<Item = LocalAttesterBinding>,
        provider_environments: impl IntoIterator<Item = LocalProviderEnvironmentBinding>,
        limits: LocalStdioLimits,
    ) -> Result<Self, LocalStdioError> {
        let mut exact = Vec::new();
        for binding in attesters {
            binding
                .authority
                .validate()
                .map_err(|error| LocalStdioError::InvalidAttester(error.to_string()))?;
            if exact
                .iter()
                .any(|existing: &LocalAttesterBinding| existing.authority == binding.authority)
            {
                return Err(LocalStdioError::DuplicateAttester);
            }
            validate_attester_binding(registry, &binding)?;
            exact.push(binding);
        }
        exact.sort_by(|left, right| {
            (
                left.authority.suite.to_string(),
                left.authority.attester.implementation.to_string(),
                left.authority.attester.artifact_digest.to_string(),
            )
                .cmp(&(
                    right.authority.suite.to_string(),
                    right.authority.attester.implementation.to_string(),
                    right.authority.attester.artifact_digest.to_string(),
                ))
        });

        let mut environments = BTreeMap::new();
        for binding in provider_environments {
            validate_provider_environment_binding(registry, &binding)?;
            if environments
                .insert(binding.offer.clone(), binding.variables)
                .is_some()
            {
                return Err(LocalStdioError::DuplicateProviderEnvironment(binding.offer));
            }
        }
        Ok(Self {
            registry: registry.clone(),
            attesters: exact,
            provider_environments: environments,
            limits,
        })
    }

    /// Exact complete conformance authorities this host can dispatch.
    pub fn authorities(&self) -> impl Iterator<Item = &ConformanceAuthority> {
        self.attesters.iter().map(|binding| &binding.authority)
    }

    fn invoke_artifact(
        &self,
        artifact: &[u8],
        request: &[u8],
        environment: &BTreeMap<String, String>,
    ) -> Result<Vec<u8>, LocalStdioError> {
        run_artifact(artifact, request, environment, self.limits)
    }
}

impl DerivationHost for LocalStdioHost {
    type Error = LocalStdioError;

    fn invoke(
        &mut self,
        invocation: &CapabilityInvocation,
    ) -> Result<CapabilityResult, Self::Error> {
        let offer_id = &invocation.selection.offer.offer_id;
        let installed = self
            .registry
            .offer(offer_id)
            .ok_or_else(|| LocalStdioError::UnknownOffer(offer_id.clone()))?;
        if installed != &invocation.selection.offer {
            return Err(LocalStdioError::SubstitutedOffer(offer_id.clone()));
        }
        let artifact = self
            .registry
            .offer_artifact(offer_id)
            .ok_or_else(|| LocalStdioError::UnknownOfferArtifact(offer_id.clone()))?;
        if artifact.digest().as_str() != installed.artifact_digest.as_str() {
            return Err(LocalStdioError::OfferArtifactDigestMismatch(
                offer_id.clone(),
            ));
        }
        let request = serde_json::to_vec(invocation)
            .map_err(|error| LocalStdioError::RequestJson(error.to_string()))?;
        let empty_environment = BTreeMap::new();
        let environment = self
            .provider_environments
            .get(offer_id)
            .unwrap_or(&empty_environment);
        let output = self.invoke_artifact(artifact.bytes(), &request, environment)?;
        decode_response(&output)
    }

    fn assess(
        &mut self,
        invocation: &CapabilityInvocation,
        result: &CapabilityResult,
        candidate: &CapabilityCandidate,
        authority: &ConformanceAuthority,
    ) -> Result<ConformanceAssessment, Self::Error> {
        let binding = self
            .attesters
            .iter()
            .find(|binding| &binding.authority == authority)
            .ok_or(LocalStdioError::AttesterUnavailable)?;
        validate_attester_binding(&self.registry, binding)?;
        let artifact = self
            .registry
            .resource(&binding.package, &binding.resource)
            .ok_or_else(|| LocalStdioError::MissingAttesterResource {
                package: binding.package.clone(),
                resource: binding.resource.clone(),
            })?;
        let request = AssessmentRequest::new(
            invocation.clone(),
            result.clone(),
            candidate.clone(),
            authority.clone(),
        )
        .map_err(|error| LocalStdioError::AssessmentRequest(error.to_string()))?;
        let request = serde_json::to_vec(&request)
            .map_err(|error| LocalStdioError::RequestJson(error.to_string()))?;
        let output = self.invoke_artifact(artifact.bytes(), &request, &BTreeMap::new())?;
        decode_response(&output)
    }
}

fn validate_provider_environment_binding(
    registry: &PackageRegistry,
    binding: &LocalProviderEnvironmentBinding,
) -> Result<(), LocalStdioError> {
    if registry.offer(&binding.offer).is_none() {
        return Err(LocalStdioError::UnknownProviderEnvironmentOffer(
            binding.offer.clone(),
        ));
    }
    if binding.variables.len() > MAX_PROVIDER_ENVIRONMENT_VARIABLES {
        return Err(LocalStdioError::ProviderEnvironmentVariableLimitExceeded {
            actual: binding.variables.len(),
            limit: MAX_PROVIDER_ENVIRONMENT_VARIABLES,
        });
    }
    let mut total = 0_usize;
    for (name, value) in &binding.variables {
        if !valid_environment_name(name) {
            return Err(LocalStdioError::InvalidProviderEnvironmentName(
                name.clone(),
            ));
        }
        if value.as_bytes().contains(&0) {
            return Err(LocalStdioError::InvalidProviderEnvironmentValue(
                name.clone(),
            ));
        }
        if value.len() > MAX_PROVIDER_ENVIRONMENT_VALUE_BYTES {
            return Err(LocalStdioError::ProviderEnvironmentValueLimitExceeded {
                name: name.clone(),
                actual: value.len(),
                limit: MAX_PROVIDER_ENVIRONMENT_VALUE_BYTES,
            });
        }
        total = total
            .checked_add(name.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or(LocalStdioError::ProviderEnvironmentTotalOverflow)?;
        if total > MAX_PROVIDER_ENVIRONMENT_TOTAL_BYTES {
            return Err(LocalStdioError::ProviderEnvironmentTotalLimitExceeded {
                actual: total,
                limit: MAX_PROVIDER_ENVIRONMENT_TOTAL_BYTES,
            });
        }
    }
    Ok(())
}

fn valid_environment_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
        && name.len() <= MAX_PROVIDER_ENVIRONMENT_NAME_BYTES
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn validate_attester_binding(
    registry: &PackageRegistry,
    binding: &LocalAttesterBinding,
) -> Result<(), LocalStdioError> {
    let resource = registry
        .resource(&binding.package, &binding.resource)
        .ok_or_else(|| LocalStdioError::MissingAttesterResource {
            package: binding.package.clone(),
            resource: binding.resource.clone(),
        })?;
    if resource.digest().as_str() != binding.authority.attester.artifact_digest.as_str() {
        return Err(LocalStdioError::AttesterArtifactDigestMismatch {
            authority: Box::new(binding.authority.clone()),
            actual: resource.digest().to_string(),
        });
    }
    Ok(())
}

fn decode_response<T: DeserializeOwned>(output: &[u8]) -> Result<T, LocalStdioError> {
    strict_json::from_slice(output)
        .map_err(|error| LocalStdioError::ResponseJson(error.to_string()))
}

fn run_artifact(
    artifact: &[u8],
    request: &[u8],
    environment: &BTreeMap<String, String>,
    limits: LocalStdioLimits,
) -> Result<Vec<u8>, LocalStdioError> {
    if artifact.is_empty() {
        return Err(LocalStdioError::EmptyArtifact);
    }
    if request.len() > limits.max_stdin_bytes.get() {
        return Err(LocalStdioError::StdinLimitExceeded {
            actual: request.len(),
            limit: limits.max_stdin_bytes.get(),
        });
    }
    let timeout = limits.timeout();
    if Instant::now().checked_add(timeout).is_none() {
        return Err(LocalStdioError::TimeoutOutsidePlatformRange);
    }

    let directory = tempfile::Builder::new()
        .prefix("gooir-local-stdio-")
        .tempdir()
        .map_err(LocalStdioError::PrepareArtifact)?;
    let path = directory.path().join("artifact");
    materialize_artifact(&path, artifact)?;
    let mut child = Command::new(&path)
        .env_clear()
        .envs(environment)
        .current_dir(directory.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(LocalStdioError::Spawn)?;
    let stdin = child.stdin.take().ok_or(LocalStdioError::MissingPipe)?;
    let stdout_pipe = child.stdout.take().ok_or(LocalStdioError::MissingPipe)?;
    let stderr_pipe = child.stderr.take().ok_or(LocalStdioError::MissingPipe)?;
    if let Err(error) = configure_nonblocking(&stdin)
        .and_then(|()| configure_nonblocking(&stdout_pipe))
        .and_then(|()| configure_nonblocking(&stderr_pipe))
    {
        let _ = kill_and_reap(&mut child);
        return Err(error);
    }

    let collected = collect_artifact_io(
        &mut child,
        stdin,
        stdout_pipe,
        stderr_pipe,
        request,
        limits,
        timeout,
    )?;
    if !collected.status.success() {
        return Err(LocalStdioError::ArtifactExit {
            status: collected.status,
            stderr: first_line(&String::from_utf8_lossy(&collected.stderr)).to_owned(),
        });
    }
    if collected.stdout.is_empty() {
        return Err(LocalStdioError::EmptyResponse);
    }
    Ok(collected.stdout)
}

fn collect_artifact_io(
    child: &mut std::process::Child,
    stdin: std::process::ChildStdin,
    mut stdout_pipe: std::process::ChildStdout,
    mut stderr_pipe: std::process::ChildStderr,
    request: &[u8],
    limits: LocalStdioLimits,
    timeout: Duration,
) -> Result<CollectedOutput, LocalStdioError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .expect("timeout range was checked before artifact launch");
    let mut stdin = Some(stdin);
    let mut stdin_offset = 0;
    let mut stdout = BoundedOutput::new(limits.max_stdout_bytes.get());
    let mut stderr = BoundedOutput::new(limits.max_stderr_bytes.get());
    let mut status = None;
    let mut failure = None;

    loop {
        let now = Instant::now();
        if now >= deadline {
            failure = Some(LocalStdioError::TimedOut);
            break;
        }

        let mut progressed = false;
        if let Some(pipe) = stdin.as_mut() {
            if stdin_offset < request.len() {
                match write_available(pipe, request, &mut stdin_offset) {
                    Ok(wrote) => progressed |= wrote,
                    Err(error) => {
                        failure = Some(LocalStdioError::WriteStdin(error));
                        break;
                    }
                }
            }
            if stdin_offset == request.len() {
                stdin.take();
                progressed = true;
            }
        }
        match stdout.read_available(&mut stdout_pipe) {
            Ok(read) => progressed |= read,
            Err(error) => {
                failure = Some(LocalStdioError::ReadOutput(error));
                break;
            }
        }
        match stderr.read_available(&mut stderr_pipe) {
            Ok(read) => progressed |= read,
            Err(error) => {
                failure = Some(LocalStdioError::ReadOutput(error));
                break;
            }
        }
        if stdout.limit_reached() {
            failure = Some(LocalStdioError::StdoutLimitExceeded(
                limits.max_stdout_bytes.get(),
            ));
            break;
        }
        if stderr.limit_reached() {
            failure = Some(LocalStdioError::StderrLimitExceeded(
                limits.max_stderr_bytes.get(),
            ));
            break;
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(reaped)) => {
                    status = Some(reaped);
                    progressed = true;
                }
                Ok(None) => {}
                Err(error) => {
                    failure = Some(LocalStdioError::Wait(error));
                    break;
                }
            }
        }
        if status.is_some() && stdin.is_none() && stdout.eof && stderr.eof {
            break;
        }
        if !progressed {
            let remaining = deadline.saturating_duration_since(Instant::now());
            std::thread::sleep(remaining.min(Duration::from_millis(1)));
        }
    }

    drop(stdin);
    if let Some(error) = failure {
        if status.is_none() {
            kill_and_reap(child)?;
        }
        return Err(error);
    }
    let status = status.expect("successful collection requires a reaped child");
    Ok(CollectedOutput {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

struct CollectedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn configure_nonblocking<Fd: rustix::fd::AsFd>(fd: &Fd) -> Result<(), LocalStdioError> {
    let flags =
        fcntl_getfl(fd).map_err(|error| LocalStdioError::ConfigurePipe(error.to_string()))?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK)
        .map_err(|error| LocalStdioError::ConfigurePipe(error.to_string()))
}

fn write_available(
    writer: &mut impl Write,
    input: &[u8],
    offset: &mut usize,
) -> Result<bool, std::io::Error> {
    match writer.write(&input[*offset..]) {
        Ok(0) => Err(std::io::ErrorKind::WriteZero.into()),
        Ok(written) => {
            *offset += written;
            Ok(true)
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn kill_and_reap(child: &mut std::process::Child) -> Result<ExitStatus, LocalStdioError> {
    if let Err(kill_error) = child.kill() {
        return match child.try_wait().map_err(LocalStdioError::Wait)? {
            Some(reaped) => Ok(reaped),
            None => Err(LocalStdioError::Kill(kill_error)),
        };
    }
    child.wait().map_err(LocalStdioError::Wait)
}

fn materialize_artifact(path: &Path, artifact: &[u8]) -> Result<(), LocalStdioError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(LocalStdioError::PrepareArtifact)?;
    file.write_all(artifact)
        .and_then(|()| file.flush())
        .map_err(LocalStdioError::PrepareArtifact)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o500))
        .map_err(LocalStdioError::PrepareArtifact)
}

struct BoundedOutput {
    bytes: Vec<u8>,
    limit: usize,
    eof: bool,
}

impl BoundedOutput {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            eof: false,
        }
    }

    fn read_available(&mut self, reader: &mut impl Read) -> Result<bool, std::io::Error> {
        if self.eof {
            return Ok(false);
        }
        let mut buffer = [0_u8; 8_192];
        let remaining = self
            .limit
            .saturating_add(1)
            .saturating_sub(self.bytes.len());
        let read_len = remaining.min(buffer.len());
        match reader.read(&mut buffer[..read_len]) {
            Ok(0) => {
                self.eof = true;
                Ok(true)
            }
            Ok(read) => {
                self.bytes.extend_from_slice(&buffer[..read]);
                Ok(true)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn limit_reached(&self) -> bool {
        self.bytes.len() > self.limit
    }
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or(text)
}

/// Local stdio host configuration, binding, lifecycle, or document failure.
#[derive(Debug)]
pub enum LocalStdioError {
    InvalidAttester(String),
    DuplicateAttester,
    DuplicateProviderEnvironment(OfferId),
    UnknownProviderEnvironmentOffer(OfferId),
    ProviderEnvironmentVariableLimitExceeded {
        actual: usize,
        limit: usize,
    },
    InvalidProviderEnvironmentName(String),
    InvalidProviderEnvironmentValue(String),
    ProviderEnvironmentValueLimitExceeded {
        name: String,
        actual: usize,
        limit: usize,
    },
    ProviderEnvironmentTotalOverflow,
    ProviderEnvironmentTotalLimitExceeded {
        actual: usize,
        limit: usize,
    },
    MissingAttesterResource {
        package: PackageId,
        resource: ResourceName,
    },
    AttesterArtifactDigestMismatch {
        authority: Box<ConformanceAuthority>,
        actual: String,
    },
    UnknownOffer(OfferId),
    SubstitutedOffer(OfferId),
    UnknownOfferArtifact(OfferId),
    OfferArtifactDigestMismatch(OfferId),
    AttesterUnavailable,
    AssessmentRequest(String),
    RequestJson(String),
    ResponseJson(String),
    EmptyArtifact,
    StdinLimitExceeded {
        actual: usize,
        limit: usize,
    },
    PrepareArtifact(std::io::Error),
    Spawn(std::io::Error),
    MissingPipe,
    ConfigurePipe(String),
    Wait(std::io::Error),
    Kill(std::io::Error),
    WriteStdin(std::io::Error),
    ReadOutput(std::io::Error),
    TimeoutOutsidePlatformRange,
    TimedOut,
    StdoutLimitExceeded(usize),
    StderrLimitExceeded(usize),
    ArtifactExit {
        status: ExitStatus,
        stderr: String,
    },
    EmptyResponse,
}

impl fmt::Display for LocalStdioError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAttester(detail) => write!(formatter, "invalid attester: {detail}"),
            Self::DuplicateAttester => formatter.write_str("duplicate exact attester binding"),
            Self::DuplicateProviderEnvironment(offer) => write!(
                formatter,
                "duplicate provider environment binding for offer `{offer}`"
            ),
            Self::UnknownProviderEnvironmentOffer(offer) => write!(
                formatter,
                "provider environment names uninstalled offer `{offer}`"
            ),
            Self::ProviderEnvironmentVariableLimitExceeded { actual, limit } => write!(
                formatter,
                "provider environment variable count {actual} exceeds bound {limit}"
            ),
            Self::InvalidProviderEnvironmentName(name) => {
                write!(formatter, "invalid provider environment name `{name}`")
            }
            Self::InvalidProviderEnvironmentValue(name) => write!(
                formatter,
                "provider environment value for `{name}` contains NUL"
            ),
            Self::ProviderEnvironmentValueLimitExceeded {
                name,
                actual,
                limit,
            } => write!(
                formatter,
                "provider environment value `{name}` size {actual} exceeds bound {limit}"
            ),
            Self::ProviderEnvironmentTotalOverflow => {
                formatter.write_str("provider environment aggregate size overflowed")
            }
            Self::ProviderEnvironmentTotalLimitExceeded { actual, limit } => write!(
                formatter,
                "provider environment aggregate size {actual} exceeds bound {limit}"
            ),
            Self::MissingAttesterResource { package, resource } => {
                write!(
                    formatter,
                    "attester resource `{package}/{resource}` is not installed"
                )
            }
            Self::AttesterArtifactDigestMismatch { authority, actual } => write!(
                formatter,
                "attester resource digest `{actual}` does not match authority {} / {}",
                authority.suite, authority.attester.implementation
            ),
            Self::UnknownOffer(offer) => write!(formatter, "offer `{offer}` is not installed"),
            Self::SubstitutedOffer(offer) => {
                write!(formatter, "offer `{offer}` differs from installed content")
            }
            Self::UnknownOfferArtifact(offer) => {
                write!(formatter, "offer `{offer}` has no copied artifact")
            }
            Self::OfferArtifactDigestMismatch(offer) => {
                write!(formatter, "offer `{offer}` artifact digest changed")
            }
            Self::AttesterUnavailable => formatter.write_str("selected attester is unavailable"),
            Self::AssessmentRequest(detail) => {
                write!(formatter, "assessment request is invalid: {detail}")
            }
            Self::RequestJson(detail) => write!(formatter, "request JSON failed: {detail}"),
            Self::ResponseJson(detail) => write!(formatter, "response JSON failed: {detail}"),
            Self::EmptyArtifact => formatter.write_str("local stdio artifact is empty"),
            Self::StdinLimitExceeded { actual, limit } => {
                write!(formatter, "stdin size {actual} exceeds bound {limit}")
            }
            Self::PrepareArtifact(error) => write!(formatter, "artifact staging failed: {error}"),
            Self::Spawn(error) => write!(formatter, "artifact launch failed: {error}"),
            Self::MissingPipe => formatter.write_str("artifact stdio pipe is unavailable"),
            Self::ConfigurePipe(detail) => {
                write!(formatter, "artifact stdio configuration failed: {detail}")
            }
            Self::Wait(error) => write!(formatter, "artifact wait failed: {error}"),
            Self::Kill(error) => write!(formatter, "artifact termination failed: {error}"),
            Self::WriteStdin(error) => write!(formatter, "artifact stdin failed: {error}"),
            Self::ReadOutput(error) => write!(formatter, "artifact output failed: {error}"),
            Self::TimeoutOutsidePlatformRange => {
                formatter.write_str("artifact timeout is outside the platform clock range")
            }
            Self::TimedOut => formatter.write_str("artifact execution exceeded its deadline"),
            Self::StdoutLimitExceeded(limit) => {
                write!(formatter, "artifact stdout reached bound {limit}")
            }
            Self::StderrLimitExceeded(limit) => {
                write!(formatter, "artifact stderr reached bound {limit}")
            }
            Self::ArtifactExit { status, stderr } if stderr.is_empty() => {
                write!(formatter, "artifact exited with {status}")
            }
            Self::ArtifactExit { status, stderr } => {
                write!(formatter, "artifact exited with {status}: {stderr}")
            }
            Self::EmptyResponse => formatter.write_str("artifact returned no stdout document"),
        }
    }
}

impl Error for LocalStdioError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PrepareArtifact(error)
            | Self::Spawn(error)
            | Self::Wait(error)
            | Self::Kill(error)
            | Self::WriteStdin(error)
            | Self::ReadOutput(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(stdin: usize, stdout: usize, stderr: usize, timeout_ms: u64) -> LocalStdioLimits {
        LocalStdioLimits {
            max_stdin_bytes: NonZeroUsize::new(stdin).unwrap(),
            max_stdout_bytes: NonZeroUsize::new(stdout).unwrap(),
            max_stderr_bytes: NonZeroUsize::new(stderr).unwrap(),
            timeout_milliseconds: NonZeroU64::new(timeout_ms).unwrap(),
        }
    }

    #[test]
    fn exact_copied_artifact_runs_from_staged_bytes() {
        let environment = BTreeMap::new();
        let output = run_artifact(
            b"#!/bin/sh\nread value\nprintf 'copied:%s' \"$value\"\n",
            b"input\n",
            &environment,
            limits(32, 32, 32, 1_000),
        )
        .unwrap();
        assert_eq!(output, b"copied:input");
    }

    #[test]
    fn environment_is_empty_by_default_and_exact_when_explicitly_supplied() {
        let artifact = b"#!/bin/sh\nprintf '%s' \"${GOOIR_TEST_AUTHORITY-unset}\"\n";
        let empty = BTreeMap::new();
        assert_eq!(
            run_artifact(artifact, b"", &empty, limits(32, 32, 32, 1_000)).unwrap(),
            b"unset"
        );

        let explicit =
            BTreeMap::from([("GOOIR_TEST_AUTHORITY".to_owned(), "exact-value".to_owned())]);
        assert_eq!(
            run_artifact(artifact, b"", &explicit, limits(32, 32, 32, 1_000)).unwrap(),
            b"exact-value"
        );
    }

    #[test]
    fn provider_environment_names_and_values_are_conservatively_bounded() {
        assert!(valid_environment_name("GOOIR_PRISMA_NODE"));
        for invalid in ["", "9START", "WITH-DASH", "WITH=EQUALS", "NUL\0NAME"] {
            assert!(!valid_environment_name(invalid), "accepted `{invalid:?}`");
        }
        assert!(!valid_environment_name(
            &"A".repeat(MAX_PROVIDER_ENVIRONMENT_NAME_BYTES + 1)
        ));
    }

    #[test]
    fn every_stdio_direction_has_an_enforced_bound() {
        let environment = BTreeMap::new();
        let stdin = run_artifact(
            b"#!/bin/sh\nprintf ok\n",
            b"too large",
            &environment,
            limits(2, 32, 32, 1_000),
        )
        .unwrap_err();
        assert!(matches!(stdin, LocalStdioError::StdinLimitExceeded { .. }));

        let stdout = run_artifact(
            b"#!/bin/sh\nprintf '12345'\n",
            b"",
            &environment,
            limits(32, 4, 32, 1_000),
        )
        .unwrap_err();
        assert!(
            matches!(stdout, LocalStdioError::StdoutLimitExceeded(4)),
            "unexpected stdout failure: {stdout:?}"
        );

        let stderr = run_artifact(
            b"#!/bin/sh\nprintf '12345' >&2\nprintf ok\n",
            b"",
            &environment,
            limits(32, 32, 4, 1_000),
        )
        .unwrap_err();
        assert!(matches!(stderr, LocalStdioError::StderrLimitExceeded(4)));
    }

    #[test]
    fn timeout_kills_and_reaps_the_exact_child() {
        let environment = BTreeMap::new();
        let started = Instant::now();
        let error = run_artifact(
            b"#!/bin/sh\nwhile :; do :; done\n",
            b"",
            &environment,
            limits(32, 32, 32, 25),
        )
        .unwrap_err();
        assert!(
            matches!(error, LocalStdioError::TimedOut),
            "unexpected timeout failure: {error:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn deadline_bounds_collection_when_a_descendant_retains_output_descriptors() {
        let environment = BTreeMap::new();
        let started = Instant::now();
        let error = run_artifact(
            br"#!/usr/bin/python3
import os, time

if os.fork() == 0:
    os.close(0)
    directory = os.getcwd()
    deadline = time.monotonic() + 5
    while os.path.isdir(directory) and time.monotonic() < deadline:
        time.sleep(0.01)
    os._exit(0)

while True:
    pass
",
            b"",
            &environment,
            limits(32, 32, 32, 25),
        )
        .unwrap_err();
        assert!(
            matches!(error, LocalStdioError::TimedOut),
            "unexpected output-retention failure: {error:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn deadline_bounds_stdin_when_a_descendant_keeps_it_open_without_reading() {
        let environment = BTreeMap::new();
        let input = vec![b'x'; 2 * 1024 * 1024];
        let started = Instant::now();
        let error = run_artifact(
            br"#!/usr/bin/python3
import os, time

if os.fork() == 0:
    os.close(1)
    os.close(2)
    directory = os.getcwd()
    deadline = time.monotonic() + 5
    while os.path.isdir(directory) and time.monotonic() < deadline:
        time.sleep(0.01)
    os._exit(0)

while True:
    pass
",
            &input,
            &environment,
            limits(input.len(), 32, 32, 25),
        )
        .unwrap_err();
        assert!(matches!(error, LocalStdioError::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn provider_result_rejects_nested_duplicate_payload_keys() {
        let error = decode_response::<CapabilityResult>(
            br#"{"outcome":{"outputs":[{"fact":{"payload":{"same":1,"same":2}}}]}}"#,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            LocalStdioError::ResponseJson(detail)
                if detail.contains("duplicate JSON object key `same`")
        ));
    }

    #[test]
    fn attester_assessment_rejects_nested_duplicate_extension_keys() {
        let error = decode_response::<ConformanceAssessment>(
            br#"{"checks":{"semantic":{"extensions":{"same":1,"same":2}}}}"#,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            LocalStdioError::ResponseJson(detail)
                if detail.contains("duplicate JSON object key `same`")
        ));
    }
}
