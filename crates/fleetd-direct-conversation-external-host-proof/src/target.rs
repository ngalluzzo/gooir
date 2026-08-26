//! Non-secret, host-qualified Fleetd target deployment locking.
//!
//! The filesystem discipline is intentionally the same proven shape as the
//! data-model external-host journal: an owner-only directory, retained parent
//! descriptor, stable sibling lock, bounded canonical JSON, atomic rename, and
//! directory synchronization. The document contains no endpoint or credential.

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fleetd_direct_conversation_contract::FleetdTarget;
use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, RenameFlags, flock, mkdirat, open, openat,
    renameat_with, unlinkat,
};
use rustix::process::geteuid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Exact protocol for one non-secret Fleetd deployment document.
pub const TARGET_DEPLOYMENT_PROTOCOL: &str =
    "org.gooi.proof.fleetd-direct-conversation-target-deployment/v1";

const DEPLOYMENT_NAME: &str = "deployment.json";
const LOCK_NAME: &str = "lock";
const TEMPORARY_NAME: &str = "deployment.next";
const MAX_DEPLOYMENT_BYTES: usize = 64 * 1024;
const MAX_AUTHORITY_COORDINATE_CHARS: usize = 256;

/// Exact non-secret description of one controlled Fleetd target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetDeployment {
    protocol: String,
    fleetd_target: FleetdTarget,
    fleetd_binary_digest: String,
    fleetd_revision: String,
    openapi_digest: String,
    data_directory_identity: String,
    endpoint_mapping_digest: String,
    credential_revision: String,
}

impl TargetDeployment {
    /// Construct one validated non-secret target deployment.
    ///
    /// # Errors
    ///
    /// Refuses empty or oversized coordinates and malformed SHA-256 identities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fleetd_target: FleetdTarget,
        fleetd_binary_digest: impl Into<String>,
        fleetd_revision: impl Into<String>,
        openapi_digest: impl Into<String>,
        data_directory_identity: impl Into<String>,
        endpoint_mapping_digest: impl Into<String>,
        credential_revision: impl Into<String>,
    ) -> Result<Self, TargetError> {
        let deployment = Self {
            protocol: TARGET_DEPLOYMENT_PROTOCOL.to_owned(),
            fleetd_target,
            fleetd_binary_digest: fleetd_binary_digest.into(),
            fleetd_revision: fleetd_revision.into(),
            openapi_digest: openapi_digest.into(),
            data_directory_identity: data_directory_identity.into(),
            endpoint_mapping_digest: endpoint_mapping_digest.into(),
            credential_revision: credential_revision.into(),
        };
        deployment.validate()?;
        Ok(deployment)
    }

    /// Exact semantic target coordinate.
    #[must_use]
    pub const fn fleetd_target(&self) -> &FleetdTarget {
        &self.fleetd_target
    }

    /// Exact Fleetd executable digest.
    #[must_use]
    pub fn fleetd_binary_digest(&self) -> &str {
        &self.fleetd_binary_digest
    }

    /// Pinned Fleetd source revision.
    #[must_use]
    pub fn fleetd_revision(&self) -> &str {
        &self.fleetd_revision
    }

    /// Pinned public `OpenAPI` digest.
    #[must_use]
    pub fn openapi_digest(&self) -> &str {
        &self.openapi_digest
    }

    /// Digest of the fixed identity marker for the controlled data directory.
    #[must_use]
    pub fn data_directory_identity(&self) -> &str {
        &self.data_directory_identity
    }

    /// Digest of the external target-to-endpoint mapping.
    #[must_use]
    pub fn endpoint_mapping_digest(&self) -> &str {
        &self.endpoint_mapping_digest
    }

    /// Non-secret credential resolver revision.
    #[must_use]
    pub fn credential_revision(&self) -> &str {
        &self.credential_revision
    }

    fn validate(&self) -> Result<(), TargetError> {
        if self.protocol != TARGET_DEPLOYMENT_PROTOCOL {
            return Err(invalid("target deployment protocol changed"));
        }
        FleetdTarget::parse(self.fleetd_target.as_str().to_owned())
            .map_err(|error| invalid(format!("Fleetd target is invalid: {error}")))?;
        validate_sha256("Fleetd binary digest", &self.fleetd_binary_digest)?;
        validate_git_commit(&self.fleetd_revision)?;
        validate_sha256("OpenAPI digest", &self.openapi_digest)?;
        validate_sha256(
            "controlled data-directory identity",
            &self.data_directory_identity,
        )?;
        validate_sha256("endpoint-mapping digest", &self.endpoint_mapping_digest)?;
        validate_authority_coordinate("credential revision", &self.credential_revision)
    }
}

/// Exact target document together with the digest of its canonical file bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetBinding {
    deployment: TargetDeployment,
    target_lock_file_digest: String,
}

impl TargetBinding {
    fn from_deployment(deployment: TargetDeployment) -> Result<Self, TargetError> {
        deployment.validate()?;
        let bytes = canonical_bytes(&deployment)?;
        let binding = Self {
            deployment,
            target_lock_file_digest: sha256_identity(&bytes),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Non-secret deployment document.
    #[must_use]
    pub const fn deployment(&self) -> &TargetDeployment {
        &self.deployment
    }

    /// Digest of the exact canonical deployment file bytes.
    #[must_use]
    pub fn target_lock_file_digest(&self) -> &str {
        &self.target_lock_file_digest
    }

    /// Revalidate the document and its file identity.
    ///
    /// # Errors
    ///
    /// Refuses malformed child fields or a changed file digest.
    pub fn validate(&self) -> Result<(), TargetError> {
        self.deployment.validate()?;
        validate_sha256("target lock-file digest", &self.target_lock_file_digest)?;
        let actual = sha256_identity(&canonical_bytes(&self.deployment)?);
        if actual != self.target_lock_file_digest {
            return Err(TargetError::ContentIdentityMismatch {
                expected: self.target_lock_file_digest.clone(),
                actual,
            });
        }
        Ok(())
    }
}

/// Owner-only authority directory for one target deployment.
#[derive(Clone, Debug)]
pub struct TargetLock {
    directory_path: PathBuf,
    deployment_path: PathBuf,
    directory: Arc<File>,
    lock_device: u64,
    lock_inode: u64,
}

impl TargetLock {
    /// Open or create one private target authority directory.
    ///
    /// # Errors
    ///
    /// Refuses unsafe paths, symlinks, wrong ownership, or permissive modes.
    pub fn new(directory_path: impl Into<PathBuf>) -> Result<Self, TargetError> {
        let directory_path = directory_path.into();
        let directory_name = directory_path
            .file_name()
            .ok_or_else(|| {
                invalid_filesystem(&directory_path, "target path must name a directory")
            })?
            .to_os_string();
        let parent_path = directory_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = File::from(
            open(
                parent_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| filesystem("open target parent", parent_path, error))?,
        );
        let created = match mkdirat(
            &parent,
            &directory_name,
            Mode::RUSR | Mode::WUSR | Mode::XUSR,
        ) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(error) => {
                return Err(filesystem(
                    "create private target directory",
                    &directory_path,
                    error,
                ));
            }
        };
        let directory = File::from(
            openat(
                &parent,
                &directory_name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| filesystem("open private target directory", &directory_path, error))?,
        );
        validate_authority_directory(&directory, &directory_path)?;
        if created {
            parent
                .sync_all()
                .map_err(|error| io_error("synchronize target parent", &directory_path, error))?;
        }
        let deployment_path = directory_path.join(DEPLOYMENT_NAME);
        let lock = open_lock_file(&directory, &deployment_path)?;
        let lock_metadata = lock
            .metadata()
            .map_err(|error| io_error("inspect stable target lock", &deployment_path, error))?;
        Ok(Self {
            deployment_path,
            directory_path,
            directory: Arc::new(directory),
            lock_device: lock_metadata.dev(),
            lock_inode: lock_metadata.ino(),
        })
    }

    /// Private target authority directory.
    #[must_use]
    pub fn directory_path(&self) -> &Path {
        &self.directory_path
    }

    /// Atomically publish or replace the non-secret deployment under a
    /// nonblocking exclusive reconfiguration fence.
    ///
    /// # Errors
    ///
    /// Refuses invalid deployment data or filesystem authority and returns
    /// [`TargetError::Busy`] while an execution guard is active.
    pub fn configure(&self, deployment: TargetDeployment) -> Result<TargetBinding, TargetError> {
        let lock = self.operation_lock(FlockOperation::NonBlockingLockExclusive)?;
        self.configure_locked(deployment, lock)
    }

    /// Acquire a shared execution fence and revalidate the exact expected lock.
    ///
    /// The returned guard must remain alive through authority construction,
    /// child execution, and durable receipt publication.
    ///
    /// # Errors
    ///
    /// Refuses missing, corrupt, changed, or unsafe target state.
    pub fn acquire_execution(
        &self,
        expected: &TargetBinding,
    ) -> Result<TargetExecutionGuard, TargetError> {
        expected.validate()?;
        let lock = self.operation_lock(FlockOperation::LockShared)?;
        let actual = self.load_locked()?;
        if actual != *expected {
            return Err(TargetError::LockMismatch {
                expected: expected.target_lock_file_digest.clone(),
                actual: actual.target_lock_file_digest,
            });
        }
        Ok(TargetExecutionGuard {
            binding: actual,
            _lock: lock,
        })
    }

    fn configure_locked(
        &self,
        deployment: TargetDeployment,
        _lock: File,
    ) -> Result<TargetBinding, TargetError> {
        validate_authority_directory(&self.directory, &self.directory_path)?;
        let binding = TargetBinding::from_deployment(deployment)?;
        let bytes = canonical_bytes(&binding.deployment)?;
        if bytes.len() > MAX_DEPLOYMENT_BYTES {
            return Err(invalid("target deployment exceeds the proof bound"));
        }
        match unlinkat(&*self.directory, TEMPORARY_NAME, AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => {
                return Err(filesystem(
                    "remove stale target sibling",
                    &self.deployment_path,
                    error,
                ));
            }
        }
        let mut temporary = TemporarySibling::create(
            Arc::clone(&self.directory),
            OsString::from(TEMPORARY_NAME),
            &self.deployment_path,
        )?;
        temporary
            .file
            .write_all(&bytes)
            .map_err(|error| io_error("write target sibling", &self.deployment_path, error))?;
        temporary
            .file
            .flush()
            .map_err(|error| io_error("flush target sibling", &self.deployment_path, error))?;
        temporary.file.sync_all().map_err(|error| {
            io_error("synchronize target sibling", &self.deployment_path, error)
        })?;
        renameat_with(
            &*self.directory,
            TEMPORARY_NAME,
            &*self.directory,
            DEPLOYMENT_NAME,
            RenameFlags::empty(),
        )
        .map_err(|error| filesystem("publish target deployment", &self.deployment_path, error))?;
        temporary.armed = false;
        self.directory.sync_all().map_err(|error| {
            io_error("synchronize target directory", &self.deployment_path, error)
        })?;
        let actual = self.load_locked()?;
        if actual != binding {
            return Err(TargetError::PublishedDeploymentMismatch);
        }
        Ok(binding)
    }

    fn load_locked(&self) -> Result<TargetBinding, TargetError> {
        validate_authority_directory(&self.directory, &self.directory_path)?;
        let descriptor = openat(
            &*self.directory,
            DEPLOYMENT_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| {
            if error == rustix::io::Errno::NOENT {
                TargetError::Missing(self.deployment_path.clone())
            } else {
                filesystem("open target deployment", &self.deployment_path, error)
            }
        })?;
        let mut file = File::from(descriptor);
        validate_authority_file(&file, &self.deployment_path, "target deployment")?;
        let metadata = file
            .metadata()
            .map_err(|error| io_error("inspect target deployment", &self.deployment_path, error))?;
        if metadata.len() > MAX_DEPLOYMENT_BYTES as u64 {
            return Err(invalid_filesystem(
                &self.deployment_path,
                "target deployment exceeds the proof bound",
            ));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| {
            invalid_filesystem(
                &self.deployment_path,
                "target deployment length cannot fit in memory",
            )
        })?);
        Read::by_ref(&mut file)
            .take(MAX_DEPLOYMENT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("read target deployment", &self.deployment_path, error))?;
        if bytes.len() as u64 != metadata.len() {
            return Err(invalid_filesystem(
                &self.deployment_path,
                "target deployment changed length while being read",
            ));
        }
        let deployment: TargetDeployment =
            serde_json::from_slice(&bytes).map_err(|error| TargetError::Decode {
                path: self.deployment_path.clone(),
                detail: error.to_string(),
            })?;
        if bytes != canonical_bytes(&deployment)? {
            return Err(TargetError::NonCanonical(self.deployment_path.clone()));
        }
        TargetBinding::from_deployment(deployment)
    }

    fn operation_lock(&self, operation: FlockOperation) -> Result<File, TargetError> {
        validate_authority_directory(&self.directory, &self.directory_path)?;
        let lock = self.open_lock()?;
        flock(&lock, operation).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK || error == rustix::io::Errno::AGAIN {
                TargetError::Busy
            } else {
                filesystem("lock target authority", &self.deployment_path, error)
            }
        })?;
        validate_authority_directory(&self.directory, &self.directory_path)?;
        validate_authority_file(&lock, &self.deployment_path, "target lock")?;
        Ok(lock)
    }

    fn open_lock(&self) -> Result<File, TargetError> {
        let lock = open_lock_file(&self.directory, &self.deployment_path)?;
        let metadata = lock.metadata().map_err(|error| {
            io_error("inspect stable target lock", &self.deployment_path, error)
        })?;
        if metadata.dev() != self.lock_device || metadata.ino() != self.lock_inode {
            return Err(invalid_filesystem(
                &self.deployment_path,
                "stable target lock inode changed",
            ));
        }
        Ok(lock)
    }
}

fn open_lock_file(directory: &File, display_path: &Path) -> Result<File, TargetError> {
    let lock = File::from(
        openat(
            directory,
            LOCK_NAME,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|error| filesystem("open stable target lock", display_path, error))?,
    );
    validate_authority_file(&lock, display_path, "target lock")?;
    Ok(lock)
}

/// Shared target configuration fence retained by one execution.
#[derive(Debug)]
pub struct TargetExecutionGuard {
    binding: TargetBinding,
    _lock: File,
}

impl TargetExecutionGuard {
    /// Exact target binding revalidated under this live fence.
    #[must_use]
    pub const fn binding(&self) -> &TargetBinding {
        &self.binding
    }
}

struct TemporarySibling {
    parent: Arc<File>,
    name: OsString,
    file: File,
    armed: bool,
}

impl TemporarySibling {
    fn create(parent: Arc<File>, name: OsString, display_path: &Path) -> Result<Self, TargetError> {
        let file = File::from(
            openat(
                &*parent,
                &name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|error| filesystem("create target sibling", display_path, error))?,
        );
        validate_authority_file(&file, display_path, "target sibling")?;
        Ok(Self {
            parent,
            name,
            file,
            armed: true,
        })
    }
}

impl Drop for TemporarySibling {
    fn drop(&mut self) {
        if self.armed {
            let _ignored = unlinkat(&*self.parent, &self.name, AtFlags::empty());
        }
    }
}

/// Closed target-lock failure.
#[derive(Debug)]
pub enum TargetError {
    Invalid(String),
    InvalidFilesystem { path: PathBuf, detail: String },
    Missing(PathBuf),
    Decode { path: PathBuf, detail: String },
    NonCanonical(PathBuf),
    ContentIdentityMismatch { expected: String, actual: String },
    LockMismatch { expected: String, actual: String },
    PublishedDeploymentMismatch,
    Busy,
}

impl fmt::Display for TargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(detail) => write!(formatter, "invalid target lock: {detail}"),
            Self::InvalidFilesystem { path, detail } => {
                write!(
                    formatter,
                    "invalid target authority `{}`: {detail}",
                    path.display()
                )
            }
            Self::Missing(path) => write!(
                formatter,
                "target deployment `{}` is missing",
                path.display()
            ),
            Self::Decode { path, detail } => {
                write!(
                    formatter,
                    "cannot decode target deployment `{}`: {detail}",
                    path.display()
                )
            }
            Self::NonCanonical(path) => {
                write!(
                    formatter,
                    "target deployment `{}` is not canonical",
                    path.display()
                )
            }
            Self::ContentIdentityMismatch { expected, actual } => write!(
                formatter,
                "target content identity changed: expected `{expected}`, found `{actual}`"
            ),
            Self::LockMismatch { expected, actual } => write!(
                formatter,
                "target deployment lock changed: expected `{expected}`, found `{actual}`"
            ),
            Self::PublishedDeploymentMismatch => {
                formatter.write_str("published target deployment differs from requested deployment")
            }
            Self::Busy => formatter.write_str("target deployment is fenced by an active execution"),
        }
    }
}

impl Error for TargetError {}

fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, TargetError> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|error| invalid(format!("canonical JSON encoding failed: {error}")))
}

fn sha256_identity(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn validate_sha256(label: &'static str, value: &str) -> Result<(), TargetError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(invalid(format!("{label} is not a SHA-256 identity")));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "{label} is not a lowercase SHA-256 identity"
        )));
    }
    Ok(())
}

fn validate_authority_coordinate(label: &'static str, value: &str) -> Result<(), TargetError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().count() > MAX_AUTHORITY_COORDINATE_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(invalid(format!(
            "{label} is empty, padded, oversized, or contains control characters"
        )));
    }
    Ok(())
}

fn validate_git_commit(value: &str) -> Result<(), TargetError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "Fleetd revision is not an exact lowercase 40-hex Git commit",
        ));
    }
    Ok(())
}

fn validate_authority_file(
    file: &File,
    display_path: &Path,
    label: &'static str,
) -> Result<(), TargetError> {
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect authority file", display_path, error))?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(invalid_filesystem(
            display_path,
            format!("{label} must be an owner-owned 0600 regular file with one link"),
        ));
    }
    Ok(())
}

fn validate_authority_directory(file: &File, path: &Path) -> Result<(), TargetError> {
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect authority directory", path, error))?;
    if !metadata.is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(invalid_filesystem(
            path,
            "target authority must be an owner-owned 0700 directory",
        ));
    }
    Ok(())
}

fn invalid(detail: impl Into<String>) -> TargetError {
    TargetError::Invalid(detail.into())
}

fn invalid_filesystem(path: &Path, detail: impl Into<String>) -> TargetError {
    TargetError::InvalidFilesystem {
        path: path.to_path_buf(),
        detail: detail.into(),
    }
}

fn filesystem(operation: &'static str, path: &Path, error: impl fmt::Display) -> TargetError {
    invalid_filesystem(path, format!("{operation}: {error}"))
}

fn io_error(operation: &'static str, path: &Path, error: impl fmt::Display) -> TargetError {
    invalid_filesystem(path, format!("{operation}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use serde_json::Value;
    use tempfile::TempDir;

    use fleetd_direct_conversation_contract::FleetdTarget;

    use super::{TargetDeployment, TargetError, TargetLock};

    const REVISION_A: &str = "e6628b054b8559d6da4e5857c888676fe322b2f9";
    const REVISION_B: &str = "89720d73f9dd75af804c27d87a71bf33c65b58c2";

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn deployment(revision: &str) -> TargetDeployment {
        TargetDeployment::new(
            FleetdTarget::parse("fleetd:local-proof").expect("target coordinate"),
            digest('a'),
            revision,
            digest('b'),
            digest('c'),
            digest('d'),
            "operator-credential/revision-1",
        )
        .expect("deployment")
    }

    #[test]
    fn deployment_document_and_binding_are_non_secret_and_exact() {
        let temp = TempDir::new().expect("temp");
        let target = TargetLock::new(temp.path().join("target")).expect("target");
        let binding = target.configure(deployment(REVISION_A)).expect("configure");
        binding.validate().expect("binding");
        let bytes = fs::read(temp.path().join("target/deployment.json")).expect("deployment bytes");
        let value: Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(value["fleetd_target"], "fleetd:local-proof");
        let fields = value.as_object().expect("deployment object");
        for secret_field in ["endpoint", "base_url", "bearer_token", "token"] {
            assert!(!fields.contains_key(secret_field));
        }
        let text = String::from_utf8(bytes).expect("UTF-8");
        assert!(!text.contains("http://"));
        assert_eq!(
            target.acquire_execution(&binding).expect("guard").binding(),
            &binding
        );
    }

    #[test]
    fn shared_execution_fences_exclude_reconfiguration() {
        let temp = TempDir::new().expect("temp");
        let target = TargetLock::new(temp.path().join("target")).expect("target");
        let first = target.configure(deployment(REVISION_A)).expect("configure");
        let guard_a = target
            .acquire_execution(&first)
            .expect("first shared guard");
        let guard_b = target
            .acquire_execution(&first)
            .expect("second shared guard");
        assert!(matches!(
            target.configure(deployment(REVISION_B)),
            Err(TargetError::Busy)
        ));
        drop((guard_a, guard_b));
        let second = target
            .configure(deployment(REVISION_B))
            .expect("reconfigure");
        assert_ne!(
            first.target_lock_file_digest(),
            second.target_lock_file_digest()
        );
        assert!(matches!(
            target.acquire_execution(&first),
            Err(TargetError::LockMismatch { .. })
        ));
    }

    #[test]
    fn corrupt_noncanonical_and_unknown_documents_fail_closed() {
        let temp = TempDir::new().expect("temp");
        let target = TargetLock::new(temp.path().join("target")).expect("target");
        let binding = target.configure(deployment(REVISION_A)).expect("configure");
        let path = temp.path().join("target/deployment.json");
        fs::write(&path, b"{ \"unknown\": true }").expect("corrupt");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        assert!(matches!(
            target.acquire_execution(&binding),
            Err(TargetError::Decode { .. })
        ));
    }

    #[test]
    fn wrong_directory_and_file_permissions_fail_closed() {
        let temp = TempDir::new().expect("temp");
        let directory = temp.path().join("target");
        fs::create_dir(&directory).expect("directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).expect("mode");
        assert!(matches!(
            TargetLock::new(&directory),
            Err(TargetError::InvalidFilesystem { .. })
        ));

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("mode");
        let target = TargetLock::new(&directory).expect("target");
        let binding = target.configure(deployment(REVISION_A)).expect("configure");
        let path = directory.join("deployment.json");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(matches!(
            target.acquire_execution(&binding),
            Err(TargetError::InvalidFilesystem { .. })
        ));
    }

    #[test]
    fn malformed_digests_and_control_coordinates_are_refused() {
        assert!(
            TargetDeployment::new(
                FleetdTarget::parse("fleetd:valid").expect("target"),
                "sha256:no",
                REVISION_A,
                digest('b'),
                digest('c'),
                digest('d'),
                "revision",
            )
            .is_err()
        );
        assert!(
            TargetDeployment::new(
                FleetdTarget::parse("fleetd:valid").expect("target"),
                digest('a'),
                REVISION_A,
                digest('b'),
                digest('c'),
                digest('d'),
                " padded-revision",
            )
            .is_err()
        );
        assert!(FleetdTarget::parse(format!("fleetd:{}", "x".repeat(257))).is_err());
    }

    #[test]
    fn retained_authority_and_stable_lock_are_revalidated_on_every_operation() {
        let temp = TempDir::new().expect("temp");
        let directory = temp.path().join("target");
        let target = TargetLock::new(&directory).expect("target");
        let binding = target.configure(deployment(REVISION_A)).expect("configure");

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).expect("widen mode");
        assert!(matches!(
            target.acquire_execution(&binding),
            Err(TargetError::InvalidFilesystem { .. })
        ));
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).expect("restore mode");

        let lock_path = directory.join("lock");
        fs::rename(&lock_path, directory.join("old-lock")).expect("replace lock inode");
        fs::write(&lock_path, b"").expect("new lock file");
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).expect("new lock mode");
        assert!(matches!(
            target.acquire_execution(&binding),
            Err(TargetError::InvalidFilesystem { .. })
        ));
    }

    #[test]
    fn late_target_opener_does_not_block_behind_a_live_execution_guard() {
        let temp = TempDir::new().expect("temp");
        let path = temp.path().join("target");
        let first = TargetLock::new(&path).expect("first target");
        let binding = first.configure(deployment(REVISION_A)).expect("configure");
        let _guard = first.acquire_execution(&binding).expect("execution guard");

        let second = TargetLock::new(&path).expect("late target opener");
        assert!(matches!(
            second.configure(deployment(REVISION_B)),
            Err(TargetError::Busy)
        ));
    }
}
