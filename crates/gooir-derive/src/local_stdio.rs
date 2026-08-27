//! Bounded local stdio execution for explicitly installed provider and
//! attester artifacts.
//!
//! This is one narrow [`DerivationHost`](crate::DerivationHost), not a
//! universal runtime. Provider bytes come only from exact installed offers;
//! attester bytes come only from explicit package-resource bindings whose
//! copied digest matches the complete selected conformance authority. Each
//! artifact is materialized in a private temporary directory and invoked by
//! that exact path with no arguments, environment, discovery, or `PATH`
//! lookup.

use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::num::{NonZeroU64, NonZeroUsize};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use gooir_capability::assessment::AssessmentRequest;
use gooir_capability::authority::{ConformanceAssessment, ConformanceAuthority};
use gooir_capability::protocol::{
    CapabilityCandidate, CapabilityInvocation, CapabilityResult, OfferId,
};
use gooir_package::{PackageId, PackageRegistry, ResourceName};
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

/// One bounded local execution host over a fixed copied package snapshot.
#[derive(Clone, Debug)]
pub struct LocalStdioHost {
    registry: PackageRegistry,
    attesters: Vec<LocalAttesterBinding>,
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
        Ok(Self {
            registry: registry.clone(),
            attesters: exact,
            limits,
        })
    }

    /// Exact complete conformance authorities this host can dispatch.
    pub fn authorities(&self) -> impl Iterator<Item = &ConformanceAuthority> {
        self.attesters.iter().map(|binding| &binding.authority)
    }

    fn invoke_artifact(&self, artifact: &[u8], request: &[u8]) -> Result<Vec<u8>, LocalStdioError> {
        run_artifact(artifact, request, self.limits)
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
        let output = self.invoke_artifact(artifact.bytes(), &request)?;
        serde_json::from_slice(&output)
            .map_err(|error| LocalStdioError::ResponseJson(error.to_string()))
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
        let output = self.invoke_artifact(artifact.bytes(), &request)?;
        serde_json::from_slice(&output)
            .map_err(|error| LocalStdioError::ResponseJson(error.to_string()))
    }
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

fn run_artifact(
    artifact: &[u8],
    request: &[u8],
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
        .current_dir(directory.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(LocalStdioError::Spawn)?;
    let mut stdin = child.stdin.take().ok_or(LocalStdioError::MissingPipe)?;
    let mut stdout = child.stdout.take().ok_or(LocalStdioError::MissingPipe)?;
    let mut stderr = child.stderr.take().ok_or(LocalStdioError::MissingPipe)?;
    let input = request.to_vec();
    let stdin_handle = thread::spawn(move || -> Result<(), std::io::Error> {
        stdin.write_all(&input)?;
        stdin.flush()
    });
    let stdout_limit = limits.max_stdout_bytes.get();
    let stdout_handle = thread::spawn(move || read_bounded(&mut stdout, stdout_limit));
    let stderr_limit = limits.max_stderr_bytes.get();
    let stderr_handle = thread::spawn(move || read_bounded(&mut stderr, stderr_limit));

    let deadline = Instant::now()
        .checked_add(timeout)
        .expect("timeout range was checked before artifact launch");
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait().map_err(LocalStdioError::Wait)? {
            break (status, false);
        }
        let now = Instant::now();
        if now >= deadline {
            // Kill is immediately followed by wait: a timeout never abandons
            // an unreaped child.
            let kill = child.kill();
            let reaped = child.wait().map_err(LocalStdioError::Wait)?;
            if let Err(error) = kill
                && reaped.success()
            {
                return Err(LocalStdioError::Kill(error));
            }
            break (reaped, true);
        }
        thread::sleep((deadline - now).min(Duration::from_millis(5)));
    };

    let stdin_result = stdin_handle
        .join()
        .map_err(|_| LocalStdioError::IoThreadPanicked)?;
    let stdout = stdout_handle
        .join()
        .map_err(|_| LocalStdioError::IoThreadPanicked)??;
    let stderr = stderr_handle
        .join()
        .map_err(|_| LocalStdioError::IoThreadPanicked)??;
    if timed_out {
        return Err(LocalStdioError::TimedOut);
    }
    stdin_result.map_err(LocalStdioError::WriteStdin)?;
    if stdout.limit_reached {
        return Err(LocalStdioError::StdoutLimitExceeded(
            limits.max_stdout_bytes.get(),
        ));
    }
    if stderr.limit_reached {
        return Err(LocalStdioError::StderrLimitExceeded(
            limits.max_stderr_bytes.get(),
        ));
    }
    if !status.success() {
        return Err(LocalStdioError::ArtifactExit {
            status,
            stderr: first_line(&String::from_utf8_lossy(&stderr.bytes)).to_owned(),
        });
    }
    if stdout.bytes.is_empty() {
        return Err(LocalStdioError::EmptyResponse);
    }
    Ok(stdout.bytes)
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

struct BoundedRead {
    bytes: Vec<u8>,
    limit_reached: bool,
}

fn read_bounded(reader: &mut impl Read, limit: usize) -> Result<BoundedRead, LocalStdioError> {
    let take = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    reader
        .take(take)
        .read_to_end(&mut bytes)
        .map_err(LocalStdioError::ReadOutput)?;
    let limit_reached = bytes.len() > limit;
    bytes.truncate(limit);
    Ok(BoundedRead {
        bytes,
        limit_reached,
    })
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or(text)
}

/// Local stdio host configuration, binding, lifecycle, or document failure.
#[derive(Debug)]
pub enum LocalStdioError {
    InvalidAttester(String),
    DuplicateAttester,
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
    Wait(std::io::Error),
    Kill(std::io::Error),
    WriteStdin(std::io::Error),
    ReadOutput(std::io::Error),
    IoThreadPanicked,
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
            Self::Wait(error) => write!(formatter, "artifact wait failed: {error}"),
            Self::Kill(error) => write!(formatter, "artifact termination failed: {error}"),
            Self::WriteStdin(error) => write!(formatter, "artifact stdin failed: {error}"),
            Self::ReadOutput(error) => write!(formatter, "artifact output failed: {error}"),
            Self::IoThreadPanicked => formatter.write_str("artifact I/O worker panicked"),
            Self::TimeoutOutsidePlatformRange => {
                formatter.write_str("artifact timeout is outside the platform clock range")
            }
            Self::TimedOut => formatter.write_str("artifact timed out and was killed and reaped"),
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
        let output = run_artifact(
            b"#!/bin/sh\nread value\nprintf 'copied:%s' \"$value\"\n",
            b"input\n",
            limits(32, 32, 32, 1_000),
        )
        .unwrap();
        assert_eq!(output, b"copied:input");
    }

    #[test]
    fn every_stdio_direction_has_an_enforced_bound() {
        let stdin = run_artifact(
            b"#!/bin/sh\nprintf ok\n",
            b"too large",
            limits(2, 32, 32, 1_000),
        )
        .unwrap_err();
        assert!(matches!(stdin, LocalStdioError::StdinLimitExceeded { .. }));

        let stdout = run_artifact(
            b"#!/bin/sh\nprintf '12345'\n",
            b"",
            limits(32, 4, 32, 1_000),
        )
        .unwrap_err();
        assert!(matches!(stdout, LocalStdioError::StdoutLimitExceeded(4)));

        let stderr = run_artifact(
            b"#!/bin/sh\nprintf '12345' >&2\nprintf ok\n",
            b"",
            limits(32, 32, 4, 1_000),
        )
        .unwrap_err();
        assert!(matches!(stderr, LocalStdioError::StderrLimitExceeded(4)));
    }

    #[test]
    fn timeout_kills_and_reaps_the_exact_child() {
        let started = Instant::now();
        let error = run_artifact(
            b"#!/bin/sh\nwhile :; do :; done\n",
            b"",
            limits(32, 32, 32, 25),
        )
        .unwrap_err();
        assert!(matches!(error, LocalStdioError::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
