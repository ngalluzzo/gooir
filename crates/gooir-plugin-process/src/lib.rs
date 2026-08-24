//! Invoking a capability provider that is a separate program.
//!
//! [Decision 0001](../../../docs/DECISIONS/0001_BOOTSTRAP_BOUNDARIES.md) chose
//! the portable boundary as serialized IR plus exact identities rather than a
//! Rust dynamic-library ABI, and then deferred loading. That deferral is what
//! this closes: a provider is any program that reads one JSON document and
//! writes another, so it need not be Rust, or compiled, or built here.
//!
//! Protocol is orthogonal to capability. The registry validates the outputs and
//! computes fact identities either way, so a process-backed provider is an
//! ordinary [`CapabilityProvider`] and the planner cannot tell the difference.
//!
//! # What this does not claim
//!
//! There is no sandbox. Running a plugin runs a program with this process's
//! privileges. The host therefore names each manifest explicitly; nothing is
//! discovered by scanning, because scanning a directory for executables to run
//! is a supply-chain hole, not a feature.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

use gooir_capability::{
    CapabilityId, CapabilityProvider, CapabilitySpec, FactInstance, ProducedFact,
    ProviderDescriptor, ProviderId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The wire contract version. Exact, like every other identity here.
pub const PROTOCOL: &str = "org.gooi.plugin/v1";

/// How long a plugin may take before it is killed.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PluginCommand {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
}

/// A plugin's declaration of itself.
///
/// It does **not** declare its implementation digest. The host measures that,
/// because the digest is what an admission policy binds — a provider that could
/// name its own digest could inherit a decision made about different code.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PluginManifest {
    pub protocol: String,
    pub provider: ProviderId,
    pub capability: CapabilityId,
    pub command: PluginCommand,
    /// Files whose bytes are covered by the measured digest, relative to the
    /// manifest. A plugin that under-declares this list gets a digest that does
    /// not change when its real code does; the count is reported so that is
    /// visible rather than hidden.
    #[serde(default)]
    pub implementation: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PluginRequest<'a> {
    protocol: &'static str,
    capability: &'a CapabilitySpec,
    inputs: &'a [FactInstance],
}

#[derive(Debug, Deserialize)]
struct PluginResponse {
    protocol: String,
    #[serde(default)]
    outputs: Vec<ProducedFact>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug)]
pub enum PluginError {
    Read(String),
    Parse(String),
    ProtocolMismatch { expected: String, actual: String },
    MissingImplementationFile(PathBuf),
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(m) => write!(f, "manifest could not be read: {m}"),
            Self::Parse(m) => write!(f, "manifest is not valid: {m}"),
            Self::ProtocolMismatch { expected, actual } => {
                write!(
                    f,
                    "manifest declares protocol {actual}, expected {expected}"
                )
            }
            Self::MissingImplementationFile(p) => {
                write!(f, "declared implementation file is absent: {}", p.display())
            }
        }
    }
}

impl std::error::Error for PluginError {}

/// A provider backed by a separate program.
#[derive(Debug)]
pub struct ProcessProvider {
    manifest: PluginManifest,
    /// Directory the manifest lives in; relative paths resolve against it.
    root: PathBuf,
    measured_digest: String,
    covered_files: usize,
    timeout: Duration,
}

impl ProcessProvider {
    /// Loads a manifest and measures the implementation it declares.
    pub fn load(manifest_path: impl AsRef<Path>) -> Result<Self, PluginError> {
        let manifest_path = manifest_path.as_ref();
        let bytes =
            fs::read(manifest_path).map_err(|error| PluginError::Read(error.to_string()))?;
        let manifest: PluginManifest = serde_json::from_slice(&bytes)
            .map_err(|error| PluginError::Parse(error.to_string()))?;
        if manifest.protocol != PROTOCOL {
            return Err(PluginError::ProtocolMismatch {
                expected: PROTOCOL.to_owned(),
                actual: manifest.protocol,
            });
        }
        let root = manifest_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();

        // The host measures. The manifest's own bytes are included, so changing
        // the command changes the identity.
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        for relative in &manifest.implementation {
            let path = root.join(relative);
            let contents = fs::read(&path)
                .map_err(|_| PluginError::MissingImplementationFile(path.clone()))?;
            hasher.update(relative.as_bytes());
            hasher.update(&contents);
        }
        let digest = hasher.finalize();
        let mut measured_digest = String::with_capacity(7 + digest.len() * 2);
        measured_digest.push_str("sha256:");
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(measured_digest, "{byte:02x}");
        }

        Ok(Self {
            covered_files: manifest.implementation.len(),
            manifest,
            root,
            measured_digest,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// How many declared files the measured digest covers. Zero means the
    /// digest reflects the manifest alone.
    pub fn covered_files(&self) -> usize {
        self.covered_files
    }

    pub fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }
}

impl CapabilityProvider for ProcessProvider {
    fn descriptor(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            id: self.manifest.provider.clone(),
            capability: self.manifest.capability.clone(),
            implementation_digest: self.measured_digest.clone(),
        }
    }

    fn invoke(
        &self,
        capability: &CapabilitySpec,
        inputs: &[FactInstance],
    ) -> Result<Vec<ProducedFact>, String> {
        let request = serde_json::to_vec(&PluginRequest {
            protocol: PROTOCOL,
            capability,
            inputs,
        })
        .map_err(|error| format!("request could not be serialized: {error}"))?;

        let mut child = Command::new(&self.manifest.command.program)
            .args(&self.manifest.command.args)
            .current_dir(&self.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                format!(
                    "could not start `{}`: {error}",
                    self.manifest.command.program
                )
            })?;

        child
            .stdin
            .take()
            .ok_or("plugin stdin was not available")?
            .write_all(&request)
            .map_err(|error| format!("plugin closed stdin early: {error}"))?;

        // A hung plugin must not hang the host.
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let result = child.wait_with_output();
            let _ = sender.send(result);
        });
        let output = match receiver.recv_timeout(self.timeout) {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => return Err(format!("plugin could not be waited on: {error}")),
            Err(_) => {
                return Err(format!(
                    "plugin exceeded {}s and was abandoned",
                    self.timeout.as_secs()
                ));
            }
        };
        let _ = handle.join();

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        if !output.status.success() {
            let code = output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signal".to_owned());
            return Err(if stderr.is_empty() {
                format!("plugin exited {code}")
            } else {
                format!("plugin exited {code}: {}", first_line(&stderr))
            });
        }
        if output.stdout.is_empty() {
            return Err(format!(
                "plugin produced no response{}",
                if stderr.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", first_line(&stderr))
                }
            ));
        }

        let response: PluginResponse = serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("plugin response is not valid: {error}"))?;
        if response.protocol != PROTOCOL {
            return Err(format!(
                "plugin answered protocol {}, expected {PROTOCOL}",
                response.protocol
            ));
        }
        if let Some(error) = response.error {
            return Err(format!("plugin reported: {error}"));
        }
        if response.outputs.is_empty() {
            return Err("plugin reported neither outputs nor an error".to_owned());
        }
        // Whether these are the *right* outputs is the registry's decision, not
        // this adapter's.
        Ok(response.outputs)
    }
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or(text)
}
