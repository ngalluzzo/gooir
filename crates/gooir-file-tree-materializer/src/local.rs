//! Bounded no-replace materialization into one local filesystem directory.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::fmt::Write as _;
use std::fs::File;
use std::io::Write as _;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};

use gooir_capability::FactId;
use gooir_capability::protocol::AuthorityRecordId;
use gooir_file_tree_v1::ContentDigest;
use rustix::fs::{
    AtFlags, Mode, OFlags, RawMode, RenameFlags, fchmod, fsync, mkdirat, open, openat,
    renameat_with, unlinkat,
};
use rustix::io::Errno;

use crate::AdmittedFileTree;

const STAGING_PREFIX: &str = ".gooir-materialize-";
const MAX_STAGING_NAME_ATTEMPTS: usize = 32;

/// Existing-destination behavior supported by the bounded local host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictPolicy {
    /// Atomically refuse when any filesystem entry already has the requested
    /// destination name. Nothing is overwritten, merged, or deleted.
    RefuseExisting,
}

/// Mandatory host-local limits checked before the first filesystem mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalMaterializationLimits {
    pub max_files: NonZeroUsize,
    pub max_directories: NonZeroUsize,
    pub max_file_bytes: NonZeroU64,
    pub max_total_bytes: NonZeroU64,
}

/// Explicit local publication policy.
///
/// Modes contain only ordinary Unix permission bits. Directory mode must keep
/// owner read, write, and execute permission so failures can be cleaned up
/// without broadening authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalMaterializationPolicy {
    conflict: ConflictPolicy,
    directory_mode: RawMode,
    file_mode: RawMode,
    limits: LocalMaterializationLimits,
}

impl LocalMaterializationPolicy {
    /// Constructs one explicit local publication policy.
    ///
    /// # Errors
    ///
    /// Refuses special permission bits, bits outside `0o777`, or a directory
    /// mode without complete owner access.
    pub fn new(
        conflict: ConflictPolicy,
        directory_mode: RawMode,
        file_mode: RawMode,
        limits: LocalMaterializationLimits,
    ) -> Result<Self, LocalMaterializationError> {
        if directory_mode > 0o777 || directory_mode & 0o700 != 0o700 {
            return Err(LocalMaterializationError::InvalidDirectoryMode(
                directory_mode,
            ));
        }
        if file_mode > 0o777 {
            return Err(LocalMaterializationError::InvalidFileMode(file_mode));
        }
        Ok(Self {
            conflict,
            directory_mode,
            file_mode,
            limits,
        })
    }

    #[must_use]
    pub fn conflict(&self) -> ConflictPolicy {
        self.conflict
    }

    #[must_use]
    pub fn directory_mode(&self) -> RawMode {
        self.directory_mode
    }

    #[must_use]
    pub fn file_mode(&self) -> RawMode {
        self.file_mode
    }

    #[must_use]
    pub fn limits(&self) -> LocalMaterializationLimits {
        self.limits
    }
}

/// Host-visible durability state after the atomic publish point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Durability {
    /// The destination rename and its parent directory were both synchronized.
    ParentDirectorySynced,
    /// Publication succeeded, but synchronizing the parent directory failed.
    /// Retrying as if nothing happened would be unsafe.
    Uncertain,
}

/// One exact file reported by a successful local materialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedFile {
    path: String,
    content_digest: ContentDigest,
    bytes: u64,
}

impl MaterializedFile {
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn content_digest(&self) -> &ContentDigest {
        &self.content_digest
    }

    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// Non-constructible in-process evidence that one local publication crossed
/// its atomic rename point.
///
/// The receipt describes the effect at return time. It does not claim that a
/// later actor cannot mutate the destination, and it is deliberately not a
/// semantic fact or stable serialized protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalMaterializationReceipt {
    authority_record_id: AuthorityRecordId,
    fact_id: FactId,
    destination: PathBuf,
    policy: LocalMaterializationPolicy,
    files: Vec<MaterializedFile>,
    durability: Durability,
}

impl LocalMaterializationReceipt {
    #[must_use]
    pub fn authority_record_id(&self) -> &AuthorityRecordId {
        &self.authority_record_id
    }

    #[must_use]
    pub fn fact_id(&self) -> &FactId {
        &self.fact_id
    }

    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    #[must_use]
    pub fn policy(&self) -> LocalMaterializationPolicy {
        self.policy
    }

    #[must_use]
    pub fn files(&self) -> &[MaterializedFile] {
        &self.files
    }

    #[must_use]
    pub fn durability(&self) -> Durability {
        self.durability
    }
}

/// Stateless bounded local filesystem materializer.
#[derive(Clone, Copy, Debug, Default)]
pub struct LocalFileTreeMaterializer;

impl LocalFileTreeMaterializer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Stages and atomically publishes an admitted tree at one absent path.
    ///
    /// The destination parent must already exist as a real directory. Its
    /// final component is never followed. Files and directories are created
    /// relative to retained descriptors under a private same-parent staging
    /// directory, synchronized, then published with atomic no-replace rename.
    /// The caller remains responsible for the origin and concurrent control of
    /// the supplied destination's ancestor namespace.
    ///
    /// # Errors
    ///
    /// Refuses exceeded host limits, malformed destinations, symlinked or
    /// unavailable parents, existing destinations, and pre-publication
    /// filesystem failures. An error never means that the final destination
    /// was published; cleanup failure is reported separately.
    pub fn materialize_local(
        &mut self,
        artifact: &AdmittedFileTree,
        destination: &Path,
        policy: &LocalMaterializationPolicy,
    ) -> Result<LocalMaterializationReceipt, LocalMaterializationError> {
        Self::materialize_local_with_filesystem(artifact, destination, policy, &SystemFilesystem)
    }

    fn materialize_local_with_filesystem(
        artifact: &AdmittedFileTree,
        destination: &Path,
        policy: &LocalMaterializationPolicy,
        filesystem: &dyn LocalFilesystem,
    ) -> Result<LocalMaterializationReceipt, LocalMaterializationError> {
        let prepared = preflight(artifact, policy.limits)?;
        let (parent_path, destination_name) = destination_parts(destination)?;
        let parent = open_parent(&parent_path)?;
        let mut stage = StagingTree::create(parent, filesystem)?;

        if let Err(error) = populate_stage(&mut stage, artifact, policy) {
            return Err(stage.failure_with_cleanup(error));
        }

        let mut receipt = LocalMaterializationReceipt {
            authority_record_id: artifact.authority_record_id().clone(),
            fact_id: artifact.fact_id().clone(),
            destination: destination.to_path_buf(),
            policy: *policy,
            files: prepared.files,
            durability: Durability::Uncertain,
        };

        let publish = match policy.conflict {
            ConflictPolicy::RefuseExisting => renameat_with(
                &stage.parent,
                stage.name.as_str(),
                &stage.parent,
                destination_name.as_os_str(),
                RenameFlags::NOREPLACE,
            ),
        };
        if let Err(error) = publish {
            let error = if error == Errno::EXIST {
                LocalMaterializationError::DestinationExists(destination.to_path_buf())
            } else {
                fs_error("publish staged file tree", error)
            };
            return Err(stage.failure_with_cleanup(error));
        }

        stage.published = true;
        receipt.durability = if stage.filesystem.sync_parent(&stage.parent).is_ok() {
            Durability::ParentDirectorySynced
        } else {
            Durability::Uncertain
        };
        Ok(receipt)
    }
}

struct PreparedMaterialization {
    files: Vec<MaterializedFile>,
}

fn preflight(
    artifact: &AdmittedFileTree,
    limits: LocalMaterializationLimits,
) -> Result<PreparedMaterialization, LocalMaterializationError> {
    if artifact.tree().files.len() > limits.max_files.get() {
        return Err(LocalMaterializationError::FileCountExceeded {
            actual: artifact.tree().files.len(),
            limit: limits.max_files.get(),
        });
    }

    let mut directories = BTreeSet::new();
    let mut total = 0_u64;
    let mut files = Vec::with_capacity(artifact.tree().files.len());
    for file in &artifact.tree().files {
        let size = u64::try_from(file.content.len())
            .map_err(|_| LocalMaterializationError::HostSizeOverflow)?;
        if size > limits.max_file_bytes.get() {
            return Err(LocalMaterializationError::FileBytesExceeded {
                path: file.path.clone(),
                actual: size,
                limit: limits.max_file_bytes.get(),
            });
        }
        total = total
            .checked_add(size)
            .ok_or(LocalMaterializationError::HostSizeOverflow)?;
        if total > limits.max_total_bytes.get() {
            return Err(LocalMaterializationError::TotalBytesExceeded {
                actual: total,
                limit: limits.max_total_bytes.get(),
            });
        }
        for (index, byte) in file.path.bytes().enumerate() {
            if byte == b'/' {
                directories.insert(file.path[..index].to_owned());
                if directories.len() > limits.max_directories.get() {
                    return Err(LocalMaterializationError::DirectoryCountExceeded {
                        actual: directories.len(),
                        limit: limits.max_directories.get(),
                    });
                }
            }
        }
        files.push(MaterializedFile {
            path: file.path.clone(),
            content_digest: file.content_digest.clone(),
            bytes: size,
        });
    }
    Ok(PreparedMaterialization { files })
}

trait LocalFilesystem {
    fn open_staging(&self, parent: &File, name: &str) -> Result<File, LocalMaterializationError>;

    fn remove_entry(
        &self,
        parent: &File,
        name: &str,
        flags: AtFlags,
        operation: &'static str,
    ) -> Result<(), LocalMaterializationError>;

    fn sync_staged_file(&self, file: &File) -> Result<(), LocalMaterializationError>;

    fn sync_parent(&self, parent: &File) -> Result<(), LocalMaterializationError>;
}

struct SystemFilesystem;

impl LocalFilesystem for SystemFilesystem {
    fn open_staging(&self, parent: &File, name: &str) -> Result<File, LocalMaterializationError> {
        open_directory_at(parent, name, "open staging tree")
    }

    fn remove_entry(
        &self,
        parent: &File,
        name: &str,
        flags: AtFlags,
        operation: &'static str,
    ) -> Result<(), LocalMaterializationError> {
        unlinkat(parent, name, flags).map_err(|error| fs_error(operation, error))
    }

    fn sync_staged_file(&self, file: &File) -> Result<(), LocalMaterializationError> {
        fsync(file).map_err(|error| fs_error("synchronize staged file", error))
    }

    fn sync_parent(&self, parent: &File) -> Result<(), LocalMaterializationError> {
        fsync(parent).map_err(|error| fs_error("synchronize destination parent", error))
    }
}

struct StagingTree<'filesystem> {
    parent: File,
    name: String,
    root: File,
    files: Vec<String>,
    directories: Vec<String>,
    published: bool,
    cleaned: bool,
    filesystem: &'filesystem dyn LocalFilesystem,
}

impl<'filesystem> StagingTree<'filesystem> {
    fn create(
        parent: File,
        filesystem: &'filesystem dyn LocalFilesystem,
    ) -> Result<Self, LocalMaterializationError> {
        for _ in 0..MAX_STAGING_NAME_ATTEMPTS {
            let name = random_staging_name()?;
            match mkdirat(&parent, name.as_str(), Mode::from_raw_mode(0o700)) {
                Ok(()) => {
                    let root = match filesystem.open_staging(&parent, name.as_str()) {
                        Ok(root) => root,
                        Err(error) => {
                            return match filesystem.remove_entry(
                                &parent,
                                name.as_str(),
                                AtFlags::REMOVEDIR,
                                "remove unopened staging tree",
                            ) {
                                Ok(()) => Err(error),
                                Err(cleanup) => Err(cleanup_after_failure(&error, &cleanup)),
                            };
                        }
                    };
                    return Ok(Self {
                        parent,
                        name,
                        root,
                        files: Vec::new(),
                        directories: Vec::new(),
                        published: false,
                        cleaned: false,
                        filesystem,
                    });
                }
                Err(Errno::EXIST) => {}
                Err(error) => return Err(fs_error("create staging tree", error)),
            }
        }
        Err(LocalMaterializationError::StagingNameExhausted)
    }

    fn failure_with_cleanup(
        &mut self,
        original: LocalMaterializationError,
    ) -> LocalMaterializationError {
        match self.cleanup() {
            Ok(()) => original,
            Err(cleanup) => cleanup_after_failure(&original, &cleanup),
        }
    }

    fn cleanup(&mut self) -> Result<(), LocalMaterializationError> {
        let mut first_error = None;
        for path in self.files.iter().rev() {
            let (parent, name) = split_relative_file(path);
            match open_relative_directory(&self.root, parent, "open cleanup file parent") {
                Ok(directory) => {
                    if let Err(error) = self.filesystem.remove_entry(
                        &directory,
                        name,
                        AtFlags::empty(),
                        "remove staged file",
                    ) && first_error.is_none()
                    {
                        first_error = Some(error);
                    }
                }
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        for path in self.directories.iter().rev() {
            let (parent, name) = split_relative_file(path);
            match open_relative_directory(&self.root, parent, "open cleanup directory parent") {
                Ok(directory) => {
                    if let Err(error) = self.filesystem.remove_entry(
                        &directory,
                        name,
                        AtFlags::REMOVEDIR,
                        "remove staged directory",
                    ) && first_error.is_none()
                    {
                        first_error = Some(error);
                    }
                }
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if let Err(error) = self.filesystem.remove_entry(
            &self.parent,
            self.name.as_str(),
            AtFlags::REMOVEDIR,
            "remove staging tree",
        ) && first_error.is_none()
        {
            first_error = Some(error);
        }
        self.cleaned = first_error.is_none();
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for StagingTree<'_> {
    fn drop(&mut self) {
        if !self.published && !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

fn populate_stage(
    stage: &mut StagingTree<'_>,
    artifact: &AdmittedFileTree,
    policy: &LocalMaterializationPolicy,
) -> Result<(), LocalMaterializationError> {
    let mut known_directories = BTreeSet::new();
    for entry in &artifact.tree().files {
        let (parent, name) = split_relative_file(&entry.path);
        let directory = ensure_directories(
            &stage.root,
            parent,
            &mut known_directories,
            &mut stage.directories,
        )?;
        let descriptor = openat(
            &directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|error| fs_error("create staged file", error))?;
        let mut file = File::from(descriptor);
        stage.files.push(entry.path.clone());
        file.write_all(&entry.content)
            .map_err(|error| fs_error("write staged file", error))?;
        fchmod(&file, Mode::from_raw_mode(policy.file_mode))
            .map_err(|error| fs_error("set staged file mode", error))?;
        stage.filesystem.sync_staged_file(&file)?;
        let metadata = file
            .metadata()
            .map_err(|error| fs_error("inspect staged file", error))?;
        if !metadata.is_file() || metadata.len() != entry.content.len() as u64 {
            return Err(LocalMaterializationError::StagedFileMismatch(
                entry.path.clone(),
            ));
        }
    }

    for directory in stage.directories.iter().rev() {
        let descriptor = open_relative_directory(&stage.root, directory, "open staged directory")?;
        fchmod(&descriptor, Mode::from_raw_mode(policy.directory_mode))
            .map_err(|error| fs_error("set staged directory mode", error))?;
        fsync(&descriptor).map_err(|error| fs_error("synchronize staged directory", error))?;
    }
    fchmod(&stage.root, Mode::from_raw_mode(policy.directory_mode))
        .map_err(|error| fs_error("set staged root mode", error))?;
    fsync(&stage.root).map_err(|error| fs_error("synchronize staged root", error))?;
    Ok(())
}

fn ensure_directories(
    root: &File,
    relative: &str,
    known: &mut BTreeSet<String>,
    created: &mut Vec<String>,
) -> Result<File, LocalMaterializationError> {
    let mut directory = root
        .try_clone()
        .map_err(|error| fs_error("clone staging root", error))?;
    if relative.is_empty() {
        return Ok(directory);
    }

    let mut prefix = String::new();
    for component in relative.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        if known.insert(prefix.clone()) {
            mkdirat(&directory, component, Mode::from_raw_mode(0o700))
                .map_err(|error| fs_error("create staged directory", error))?;
            created.push(prefix.clone());
        }
        directory = open_directory_at(&directory, component, "open staged directory")?;
    }
    Ok(directory)
}

fn open_relative_directory(
    root: &File,
    relative: &str,
    scope: &'static str,
) -> Result<File, LocalMaterializationError> {
    let mut directory = root
        .try_clone()
        .map_err(|error| fs_error("clone directory descriptor", error))?;
    if relative.is_empty() {
        return Ok(directory);
    }
    for component in relative.split('/') {
        directory = open_directory_at(&directory, component, scope)?;
    }
    Ok(directory)
}

fn open_directory_at(
    parent: &File,
    name: &str,
    scope: &'static str,
) -> Result<File, LocalMaterializationError> {
    let descriptor = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| fs_error(scope, error))?;
    let directory = File::from(descriptor);
    if !directory
        .metadata()
        .map_err(|error| fs_error(scope, error))?
        .is_dir()
    {
        return Err(LocalMaterializationError::Filesystem {
            operation: scope,
            detail: "opened entry is not a directory".to_owned(),
        });
    }
    Ok(directory)
}

fn open_parent(path: &Path) -> Result<File, LocalMaterializationError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| fs_error("open destination parent", error))?;
    let parent = File::from(descriptor);
    if !parent
        .metadata()
        .map_err(|error| fs_error("inspect destination parent", error))?
        .is_dir()
    {
        return Err(LocalMaterializationError::ParentNotDirectory(
            path.to_path_buf(),
        ));
    }
    Ok(parent)
}

fn destination_parts(destination: &Path) -> Result<(PathBuf, OsString), LocalMaterializationError> {
    let name = destination
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| LocalMaterializationError::InvalidDestination(destination.to_path_buf()))?;
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let parent = if parent.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        parent.to_path_buf()
    };
    Ok((parent, name.to_os_string()))
}

fn split_relative_file(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn random_staging_name() -> Result<String, LocalMaterializationError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|error| fs_error("generate staging name", error))?;
    let mut name = String::with_capacity(STAGING_PREFIX.len() + random.len() * 2);
    name.push_str(STAGING_PREFIX);
    for byte in random {
        write!(name, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(name)
}

fn fs_error(operation: &'static str, error: impl fmt::Display) -> LocalMaterializationError {
    LocalMaterializationError::Filesystem {
        operation,
        detail: error.to_string(),
    }
}

fn cleanup_after_failure(
    original: &LocalMaterializationError,
    cleanup: &LocalMaterializationError,
) -> LocalMaterializationError {
    LocalMaterializationError::CleanupAfterFailure {
        original: original.to_string(),
        cleanup: cleanup.to_string(),
    }
}

/// Host-side refusal or effect failure before successful publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalMaterializationError {
    InvalidDirectoryMode(RawMode),
    InvalidFileMode(RawMode),
    InvalidDestination(PathBuf),
    ParentNotDirectory(PathBuf),
    DestinationExists(PathBuf),
    FileCountExceeded {
        actual: usize,
        limit: usize,
    },
    DirectoryCountExceeded {
        actual: usize,
        limit: usize,
    },
    FileBytesExceeded {
        path: String,
        actual: u64,
        limit: u64,
    },
    TotalBytesExceeded {
        actual: u64,
        limit: u64,
    },
    HostSizeOverflow,
    StagingNameExhausted,
    StagedFileMismatch(String),
    Filesystem {
        operation: &'static str,
        detail: String,
    },
    CleanupAfterFailure {
        original: String,
        cleanup: String,
    },
}

impl fmt::Display for LocalMaterializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDirectoryMode(mode) => write!(
                formatter,
                "directory mode {mode:#o} must be within 0o777 and retain owner rwx"
            ),
            Self::InvalidFileMode(mode) => {
                write!(formatter, "file mode {mode:#o} must be within 0o777")
            }
            Self::InvalidDestination(path) => {
                write!(
                    formatter,
                    "`{}` is not a materializable destination",
                    path.display()
                )
            }
            Self::ParentNotDirectory(path) => {
                write!(
                    formatter,
                    "destination parent `{}` is not a directory",
                    path.display()
                )
            }
            Self::DestinationExists(path) => {
                write!(formatter, "destination `{}` already exists", path.display())
            }
            Self::FileCountExceeded { actual, limit } => {
                write!(
                    formatter,
                    "file tree has {actual} files; host limit is {limit}"
                )
            }
            Self::DirectoryCountExceeded { actual, limit } => write!(
                formatter,
                "file tree needs {actual} directories; host limit is {limit}"
            ),
            Self::FileBytesExceeded {
                path,
                actual,
                limit,
            } => write!(
                formatter,
                "file `{}` has {actual} bytes; host limit is {limit}",
                path.escape_debug()
            ),
            Self::TotalBytesExceeded { actual, limit } => write!(
                formatter,
                "file tree has {actual} content bytes; host limit is {limit}"
            ),
            Self::HostSizeOverflow => formatter.write_str("file-tree host size overflow"),
            Self::StagingNameExhausted => {
                formatter.write_str("could not reserve a private staging directory name")
            }
            Self::StagedFileMismatch(path) => write!(
                formatter,
                "staged file `{}` did not retain its exact regular-file size",
                path.escape_debug()
            ),
            Self::Filesystem { operation, detail } => {
                write!(formatter, "{operation} failed: {detail}")
            }
            Self::CleanupAfterFailure { original, cleanup } => write!(
                formatter,
                "materialization failed ({original}) and staging cleanup also failed ({cleanup})"
            ),
        }
    }
}

impl std::error::Error for LocalMaterializationError {}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use gooir_capability::authority::{
        AdmissionAuthorityId, AdmissionLedger, AdmissionOutcome, AdmissionPolicy,
        AssessmentOutcome, ConformanceAssessment, ConformanceAttester, ConformanceAuthority,
        ConformanceCheck, ObservationAuthority, ObservationSourceId, ResolvedFact,
        SourceObservation,
    };
    use gooir_capability::protocol::{
        AdmittedFactRef, ArtifactDigest, CapabilityCandidate, CapabilityOffer, CapabilityResult,
        ConformanceSuiteId, EvidenceDigest, EvidenceKindId, EvidenceRef, ImplementationId,
        ImplementationSelection, LinkedInput, NamedOutput,
    };
    use gooir_capability::{
        CapabilityId, CapabilitySpec, Fact, FactAcceptance, InputPort, OutputPort, PortName,
        ValueKindId,
    };
    use gooir_file_tree_v1::{FileEntry, FileTree, file_tree_value_kind};
    use serde_json::json;

    use super::*;
    use crate::{AdmittedFileTree, AdmittedFileTreeError, FileTreeMaterializer as _};

    fn sha(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn port(name: &str) -> PortName {
        PortName::parse(name).unwrap()
    }

    fn limits() -> LocalMaterializationLimits {
        LocalMaterializationLimits {
            max_files: NonZeroUsize::new(8).unwrap(),
            max_directories: NonZeroUsize::new(8).unwrap(),
            max_file_bytes: NonZeroU64::new(1_024).unwrap(),
            max_total_bytes: NonZeroU64::new(4_096).unwrap(),
        }
    }

    fn policy() -> LocalMaterializationPolicy {
        LocalMaterializationPolicy::new(ConflictPolicy::RefuseExisting, 0o750, 0o640, limits())
            .unwrap()
    }

    fn tree() -> FileTree {
        FileTree::new(vec![
            FileEntry::new("README.md", "text/markdown", b"generated\n".to_vec()).unwrap(),
            FileEntry::new(
                "src/data.bin",
                "application/octet-stream",
                vec![0, 159, 146, 150],
            )
            .unwrap(),
        ])
        .unwrap()
    }

    fn admitted_fact(fact: Fact) -> AdmittedFileTree {
        let (ledger, reference) = admit_fact_reference(fact, BTreeMap::new());
        AdmittedFileTree::resolve(&ledger, &reference).unwrap()
    }

    fn admit_fact_reference(
        fact: Fact,
        authority_extensions: BTreeMap<String, serde_json::Value>,
    ) -> (AdmissionLedger, AdmittedFactRef) {
        let evidence_kind = EvidenceKindId::new("test.evidence", "source", "1.0.0");
        let authority = ObservationAuthority::new(
            ObservationSourceId::new("test.source", "fixture", "1.0.0"),
            ImplementationId::new("test.observer", "fixture", "1.0.0"),
            ArtifactDigest::parse(sha('a')).unwrap(),
            fact.value_kind.clone(),
            evidence_kind.clone(),
            authority_extensions,
        )
        .unwrap();
        let observation = SourceObservation::new(
            fact,
            authority.clone(),
            EvidenceRef::new(
                evidence_kind,
                EvidenceDigest::parse(sha('b')).unwrap(),
                "memory://file-tree-fixture",
                BTreeMap::new(),
            )
            .unwrap(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let policy = AdmissionPolicy::new(
            AdmissionAuthorityId::new("test.admission", "local", "1.0.0"),
            Vec::new(),
            vec![authority],
            BTreeMap::new(),
        )
        .unwrap();
        let mut ledger = AdmissionLedger::new();
        let AdmissionOutcome::Admitted { links, .. } =
            ledger.admit_observation(&policy, &observation).unwrap()
        else {
            panic!("fixture observation must be admitted");
        };
        let reference = links[0].reference.clone();
        (ledger, reference)
    }

    fn admitted_tree() -> AdmittedFileTree {
        let fact = Fact::new(
            file_tree_value_kind(),
            serde_json::to_value(tree()).unwrap(),
        )
        .unwrap();
        admitted_fact(fact)
    }

    fn staging_entries(parent: &Path) -> Vec<OsString> {
        fs::read_dir(parent)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .filter(|name| name.to_string_lossy().starts_with(STAGING_PREFIX))
            .collect()
    }

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    enum InjectedFault {
        OpenStaging,
        RemoveStagedFile,
        RemoveStagingTree,
        SyncStagedFile,
        SyncParent,
    }

    #[derive(Default)]
    struct FaultFilesystem {
        faults: BTreeSet<InjectedFault>,
        removal_attempts: Cell<usize>,
    }

    impl FaultFilesystem {
        fn with(faults: impl IntoIterator<Item = InjectedFault>) -> Self {
            Self {
                faults: faults.into_iter().collect(),
                removal_attempts: Cell::new(0),
            }
        }
    }

    impl LocalFilesystem for FaultFilesystem {
        fn open_staging(
            &self,
            parent: &File,
            name: &str,
        ) -> Result<File, LocalMaterializationError> {
            if self.faults.contains(&InjectedFault::OpenStaging) {
                Err(injected_failure("open staging tree"))
            } else {
                SystemFilesystem.open_staging(parent, name)
            }
        }

        fn remove_entry(
            &self,
            parent: &File,
            name: &str,
            flags: AtFlags,
            operation: &'static str,
        ) -> Result<(), LocalMaterializationError> {
            self.removal_attempts
                .set(self.removal_attempts.get().saturating_add(1));
            if (flags.is_empty() && self.faults.contains(&InjectedFault::RemoveStagedFile))
                || (flags.contains(AtFlags::REMOVEDIR)
                    && name.starts_with(STAGING_PREFIX)
                    && self.faults.contains(&InjectedFault::RemoveStagingTree))
            {
                Err(injected_failure(operation))
            } else {
                SystemFilesystem.remove_entry(parent, name, flags, operation)
            }
        }

        fn sync_staged_file(&self, file: &File) -> Result<(), LocalMaterializationError> {
            if self.faults.contains(&InjectedFault::SyncStagedFile) {
                Err(injected_failure("synchronize staged file"))
            } else {
                SystemFilesystem.sync_staged_file(file)
            }
        }

        fn sync_parent(&self, parent: &File) -> Result<(), LocalMaterializationError> {
            if self.faults.contains(&InjectedFault::SyncParent) {
                Err(injected_failure("synchronize destination parent"))
            } else {
                SystemFilesystem.sync_parent(parent)
            }
        }
    }

    fn injected_failure(operation: &'static str) -> LocalMaterializationError {
        LocalMaterializationError::Filesystem {
            operation,
            detail: "injected test failure".to_owned(),
        }
    }

    struct ExpectedObservationAuthorityExtension;

    impl crate::AuthorityExtensionValidator for ExpectedObservationAuthorityExtension {
        fn validate(
            &mut self,
            extension: crate::AuthorityExtension<'_>,
        ) -> Result<(), crate::AuthorityExtensionError> {
            if extension.scope == crate::AuthorityExtensionScope::ObservationAuthority
                && extension.key == "org.example/authority-meaning"
                && extension.value == &json!(true)
            {
                Ok(())
            } else {
                Err(crate::AuthorityExtensionError::Unhandled)
            }
        }
    }

    #[test]
    fn admitted_gate_requires_the_exact_file_tree_kind() {
        let wrong = Fact::new(
            ValueKindId::new("test.kind", "other", "1.0.0"),
            json!({"value": true}),
        )
        .unwrap();
        let (ledger, reference) = admit_fact_reference(wrong, BTreeMap::new());
        assert!(matches!(
            AdmittedFileTree::resolve(&ledger, &reference),
            Err(AdmittedFileTreeError::WrongValueKind { .. })
        ));
    }

    #[test]
    fn admitted_gate_refuses_unhandled_semantic_extensions() {
        let fact = Fact::with_extensions(
            file_tree_value_kind(),
            serde_json::to_value(tree()).unwrap(),
            BTreeMap::from([("org.example/meaning".to_owned(), json!(true))]),
        )
        .unwrap();
        assert!(matches!(
            admitted_fact_result(fact),
            Err(AdmittedFileTreeError::UnhandledFactExtension(key))
                if key == "org.example/meaning"
        ));

        let extended_tree = FileTree::with_extensions(
            tree().files,
            BTreeMap::from([("org.example/meaning".to_owned(), json!(true))]),
        )
        .unwrap();
        let fact = Fact::new(
            file_tree_value_kind(),
            serde_json::to_value(extended_tree).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            admitted_fact_result(fact),
            Err(AdmittedFileTreeError::UnhandledTreeExtension(key))
                if key == "org.example/meaning"
        ));

        let extended_file = FileEntry::with_extensions(
            "generated.txt",
            "text/plain",
            b"generated".to_vec(),
            BTreeMap::from([("org.example/meaning".to_owned(), json!(true))]),
        )
        .unwrap();
        let fact = Fact::new(
            file_tree_value_kind(),
            serde_json::to_value(FileTree::new(vec![extended_file]).unwrap()).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            admitted_fact_result(fact),
            Err(AdmittedFileTreeError::UnhandledFileExtension { path, key })
                if path == "generated.txt" && key == "org.example/meaning"
        ));

        let fact = Fact::new(
            file_tree_value_kind(),
            serde_json::to_value(tree()).unwrap(),
        )
        .unwrap();
        let (ledger, reference) = admit_fact_reference(
            fact,
            BTreeMap::from([("org.example/authority-meaning".to_owned(), json!(true))]),
        );
        assert!(matches!(
            AdmittedFileTree::resolve(&ledger, &reference),
            Err(AdmittedFileTreeError::UnhandledAuthorityExtension { scope, key })
                if scope == "observation authority"
                    && key == "org.example/authority-meaning"
        ));
        assert!(
            AdmittedFileTree::resolve_with_authority_extensions(
                &ledger,
                &reference,
                &mut ExpectedObservationAuthorityExtension,
            )
            .is_ok()
        );

        let fact = Fact::new(
            file_tree_value_kind(),
            serde_json::to_value(tree()).unwrap(),
        )
        .unwrap();
        let (ledger, mut reference) = admit_fact_reference(fact, BTreeMap::new());
        reference
            .extensions
            .insert("org.example/selection".to_owned(), json!(true));
        assert!(matches!(
            AdmittedFileTree::resolve(&ledger, &reference),
            Err(AdmittedFileTreeError::UnhandledAuthorityExtension { scope, key })
                if scope == "admitted fact reference" && key == "org.example/selection"
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn admitted_gate_walks_derived_input_authority_ancestry() {
        let input_kind = ValueKindId::new("test.input", "source", "1.0.0");
        let input_fact = Fact::new(input_kind.clone(), json!({"value": 1})).unwrap();
        let evidence_kind = EvidenceKindId::new("test.evidence", "derived", "1.0.0");
        let source_authority = ObservationAuthority::new(
            ObservationSourceId::new("test.source", "upstream", "1.0.0"),
            ImplementationId::new("test.observer", "upstream", "1.0.0"),
            ArtifactDigest::parse(sha('1')).unwrap(),
            input_kind.clone(),
            evidence_kind.clone(),
            BTreeMap::from([("org.example/upstream-semantics".to_owned(), json!(true))]),
        )
        .unwrap();
        let observation = SourceObservation::new(
            input_fact.clone(),
            source_authority.clone(),
            EvidenceRef::new(
                evidence_kind.clone(),
                EvidenceDigest::parse(sha('2')).unwrap(),
                "memory://upstream",
                BTreeMap::new(),
            )
            .unwrap(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let source_policy = AdmissionPolicy::new(
            AdmissionAuthorityId::new("test.admission", "upstream", "1.0.0"),
            Vec::new(),
            vec![source_authority],
            BTreeMap::new(),
        )
        .unwrap();
        let mut ledger = AdmissionLedger::new();
        let AdmissionOutcome::Admitted { links, .. } = ledger
            .admit_observation(&source_policy, &observation)
            .unwrap()
        else {
            panic!("upstream fixture must be admitted");
        };
        let input_reference = links[0].reference.clone();

        let suite = ConformanceSuiteId::new("test.conformance", "file-tree", "1.0.0");
        let capability = CapabilityId::new("test.capability", "file-tree", "1.0.0");
        let specification = CapabilitySpec {
            id: capability.clone(),
            input_ports: vec![InputPort {
                name: port("source"),
                value_kind: input_kind,
                acceptance: FactAcceptance::CompleteOnly,
                extensions: BTreeMap::new(),
            }],
            output_ports: vec![OutputPort::new(port("tree"), file_tree_value_kind())],
            default_conformance_suite: suite.to_string(),
            extensions: BTreeMap::new(),
        };
        let offer = CapabilityOffer::new(
            ImplementationId::new("test.producer", "file-tree", "1.0.0"),
            ArtifactDigest::parse(sha('3')).unwrap(),
            capability,
            BTreeMap::new(),
        )
        .unwrap();
        let invocation = gooir_capability::protocol::CapabilityInvocation::new(
            specification,
            ImplementationSelection::new(offer, BTreeMap::new()).unwrap(),
            vec![
                LinkedInput::new(port("source"), input_reference, input_fact, BTreeMap::new())
                    .unwrap(),
            ],
            suite.clone(),
            BTreeMap::new(),
        )
        .unwrap();
        let tree_fact = Fact::new(
            file_tree_value_kind(),
            serde_json::to_value(tree()).unwrap(),
        )
        .unwrap();
        let result = CapabilityResult::produced(
            &invocation,
            vec![NamedOutput::new(port("tree"), tree_fact, BTreeMap::new()).unwrap()],
            BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let candidate =
            CapabilityCandidate::new(&invocation, result.clone(), BTreeMap::new()).unwrap();
        let conformance_authority = ConformanceAuthority::new(
            suite,
            ConformanceAttester::new(
                ImplementationId::new("test.attester", "file-tree", "1.0.0"),
                ArtifactDigest::parse(sha('4')).unwrap(),
                BTreeMap::new(),
            )
            .unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        let assessment = ConformanceAssessment::new(
            &invocation,
            &result,
            &candidate,
            conformance_authority.clone(),
            BTreeMap::from([(
                "exact-tree".to_owned(),
                ConformanceCheck::new(AssessmentOutcome::Passed, Vec::new(), BTreeMap::new())
                    .unwrap(),
            )]),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let derived_policy = AdmissionPolicy::new(
            AdmissionAuthorityId::new("test.admission", "derived", "1.0.0"),
            vec![conformance_authority],
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let AdmissionOutcome::Admitted { links, .. } = ledger
            .admit_candidate(
                &derived_policy,
                &invocation,
                &result,
                &candidate,
                &assessment,
            )
            .unwrap()
        else {
            panic!("derived fixture must be admitted");
        };

        assert!(matches!(
            AdmittedFileTree::resolve(&ledger, &links[0].reference),
            Err(AdmittedFileTreeError::UnhandledAuthorityExtension { scope, key })
                if scope == "observation authority"
                    && key == "org.example/upstream-semantics"
        ));
    }

    fn admitted_fact_result(fact: Fact) -> Result<AdmittedFileTree, AdmittedFileTreeError> {
        let evidence_kind = EvidenceKindId::new("test.evidence", "extension", "1.0.0");
        let authority = ObservationAuthority::new(
            ObservationSourceId::new("test.source", "extension", "1.0.0"),
            ImplementationId::new("test.observer", "extension", "1.0.0"),
            ArtifactDigest::parse(sha('e')).unwrap(),
            fact.value_kind.clone(),
            evidence_kind.clone(),
            BTreeMap::new(),
        )
        .unwrap();
        let observation = SourceObservation::new(
            fact,
            authority.clone(),
            EvidenceRef::new(
                evidence_kind,
                EvidenceDigest::parse(sha('f')).unwrap(),
                "memory://extension",
                BTreeMap::new(),
            )
            .unwrap(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let policy = AdmissionPolicy::new(
            AdmissionAuthorityId::new("test.admission", "extension", "1.0.0"),
            Vec::new(),
            vec![authority],
            BTreeMap::new(),
        )
        .unwrap();
        let mut ledger = AdmissionLedger::new();
        let AdmissionOutcome::Admitted { links, .. } =
            ledger.admit_observation(&policy, &observation).unwrap()
        else {
            panic!("fixture observation must be admitted");
        };
        AdmittedFileTree::resolve(&ledger, &links[0].reference)
    }

    #[test]
    fn exact_tree_is_published_with_receipt_modes_and_no_staging_residue() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("generated");
        let artifact = admitted_tree();
        let mut materializer = LocalFileTreeMaterializer::new();

        let receipt = materializer
            .materialize(&artifact, &destination, &policy())
            .unwrap();

        assert_eq!(
            fs::read(destination.join("README.md")).unwrap(),
            b"generated\n"
        );
        assert_eq!(
            fs::read(destination.join("src/data.bin")).unwrap(),
            vec![0, 159, 146, 150]
        );
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert_eq!(
            fs::metadata(destination.join("README.md"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        assert_eq!(
            receipt.authority_record_id(),
            artifact.authority_record_id()
        );
        assert_eq!(receipt.fact_id(), artifact.fact_id());
        assert_eq!(receipt.destination(), destination);
        assert_eq!(receipt.files().len(), 2);
        assert_eq!(receipt.durability(), Durability::ParentDirectorySynced);
        assert!(staging_entries(parent.path()).is_empty());
    }

    #[test]
    fn staging_open_failure_cleans_the_created_directory() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("generated");
        let filesystem = FaultFilesystem::with([InjectedFault::OpenStaging]);

        assert!(matches!(
            LocalFileTreeMaterializer::materialize_local_with_filesystem(
                &admitted_tree(),
                &destination,
                &policy(),
                &filesystem,
            ),
            Err(LocalMaterializationError::Filesystem {
                operation: "open staging tree",
                ..
            })
        ));
        assert_eq!(filesystem.removal_attempts.get(), 1);
        assert!(staging_entries(parent.path()).is_empty());
        assert!(!destination.exists());
    }

    #[test]
    fn staging_open_cleanup_failure_is_reported() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("generated");
        let filesystem =
            FaultFilesystem::with([InjectedFault::OpenStaging, InjectedFault::RemoveStagingTree]);

        let error = LocalFileTreeMaterializer::materialize_local_with_filesystem(
            &admitted_tree(),
            &destination,
            &policy(),
            &filesystem,
        )
        .unwrap_err();
        assert!(matches!(
            &error,
            LocalMaterializationError::CleanupAfterFailure { original, cleanup }
                if original.contains("open staging tree")
                    && cleanup.contains("remove unopened staging tree")
        ));
        assert_eq!(filesystem.removal_attempts.get(), 1);
        let residual = staging_entries(parent.path());
        assert_eq!(residual.len(), 1);
        fs::remove_dir(parent.path().join(&residual[0])).unwrap();
        assert!(!destination.exists());
    }

    #[test]
    fn partial_population_cleanup_failure_is_reported() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("generated");
        let filesystem = FaultFilesystem::with([
            InjectedFault::RemoveStagedFile,
            InjectedFault::SyncStagedFile,
        ]);

        let error = LocalFileTreeMaterializer::materialize_local_with_filesystem(
            &admitted_tree(),
            &destination,
            &policy(),
            &filesystem,
        )
        .unwrap_err();
        assert!(matches!(
            &error,
            LocalMaterializationError::CleanupAfterFailure { original, cleanup }
                if original.contains("synchronize staged file")
                    && cleanup.contains("remove staged file")
        ));
        assert!(filesystem.removal_attempts.get() >= 2);
        let residual = staging_entries(parent.path());
        assert_eq!(residual.len(), 1);
        fs::remove_dir_all(parent.path().join(&residual[0])).unwrap();
        assert!(!destination.exists());
    }

    #[test]
    fn post_publish_parent_sync_failure_returns_uncertain_receipt() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("generated");
        let filesystem = FaultFilesystem::with([InjectedFault::SyncParent]);

        let receipt = LocalFileTreeMaterializer::materialize_local_with_filesystem(
            &admitted_tree(),
            &destination,
            &policy(),
            &filesystem,
        )
        .unwrap();

        assert_eq!(receipt.durability(), Durability::Uncertain);
        assert_eq!(
            fs::read(destination.join("README.md")).unwrap(),
            b"generated\n"
        );
        assert!(staging_entries(parent.path()).is_empty());
    }

    #[test]
    fn existing_destination_is_never_changed_and_stage_is_removed() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("generated");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("owned.txt"), b"keep").unwrap();
        let mut materializer = LocalFileTreeMaterializer::new();

        assert!(matches!(
            materializer.materialize(&admitted_tree(), &destination, &policy()),
            Err(LocalMaterializationError::DestinationExists(path)) if path == destination
        ));
        assert_eq!(fs::read(destination.join("owned.txt")).unwrap(), b"keep");
        assert!(staging_entries(parent.path()).is_empty());
    }

    #[test]
    fn symlink_destination_and_symlink_parent_are_refused() {
        let parent = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let destination = parent.path().join("generated");
        symlink(elsewhere.path(), &destination).unwrap();
        let mut materializer = LocalFileTreeMaterializer::new();
        assert!(matches!(
            materializer.materialize(&admitted_tree(), &destination, &policy()),
            Err(LocalMaterializationError::DestinationExists(path)) if path == destination
        ));

        let linked_parent = parent.path().join("linked-parent");
        symlink(elsewhere.path(), &linked_parent).unwrap();
        let nested = linked_parent.join("generated");
        assert!(matches!(
            materializer.materialize(&admitted_tree(), &nested, &policy()),
            Err(LocalMaterializationError::Filesystem {
                operation: "open destination parent",
                ..
            })
        ));
        assert!(!elsewhere.path().join("generated").exists());
    }

    #[test]
    fn every_host_limit_fails_before_the_destination_or_stage_exists() {
        let parent = tempfile::tempdir().unwrap();
        let mut materializer = LocalFileTreeMaterializer::new();

        let file_count_limits = LocalMaterializationLimits {
            max_files: NonZeroUsize::new(1).unwrap(),
            ..limits()
        };
        let file_count_policy = LocalMaterializationPolicy::new(
            ConflictPolicy::RefuseExisting,
            0o700,
            0o600,
            file_count_limits,
        )
        .unwrap();
        let destination = parent.path().join("file-count");
        assert!(matches!(
            materializer.materialize(&admitted_tree(), &destination, &file_count_policy),
            Err(LocalMaterializationError::FileCountExceeded { .. })
        ));
        assert!(!destination.exists());

        let directory_limits = LocalMaterializationLimits {
            max_directories: NonZeroUsize::new(1).unwrap(),
            ..limits()
        };
        let directory_policy = LocalMaterializationPolicy::new(
            ConflictPolicy::RefuseExisting,
            0o700,
            0o600,
            directory_limits,
        )
        .unwrap();
        let nested = admitted_fact(
            Fact::new(
                file_tree_value_kind(),
                serde_json::to_value(
                    FileTree::new(vec![
                        FileEntry::new("a/b/file.txt", "text/plain", b"x".to_vec()).unwrap(),
                    ])
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let destination = parent.path().join("directory-count");
        assert!(matches!(
            materializer.materialize(&nested, &destination, &directory_policy),
            Err(LocalMaterializationError::DirectoryCountExceeded { .. })
        ));
        assert!(!destination.exists());

        let file_bytes_limits = LocalMaterializationLimits {
            max_file_bytes: NonZeroU64::new(1).unwrap(),
            ..limits()
        };
        let file_bytes_policy = LocalMaterializationPolicy::new(
            ConflictPolicy::RefuseExisting,
            0o700,
            0o600,
            file_bytes_limits,
        )
        .unwrap();
        let destination = parent.path().join("file-bytes");
        assert!(matches!(
            materializer.materialize(&admitted_tree(), &destination, &file_bytes_policy),
            Err(LocalMaterializationError::FileBytesExceeded { .. })
        ));
        assert!(!destination.exists());

        let total_bytes_limits = LocalMaterializationLimits {
            max_total_bytes: NonZeroU64::new(12).unwrap(),
            ..limits()
        };
        let total_bytes_policy = LocalMaterializationPolicy::new(
            ConflictPolicy::RefuseExisting,
            0o700,
            0o600,
            total_bytes_limits,
        )
        .unwrap();
        let destination = parent.path().join("total-bytes");
        assert!(matches!(
            materializer.materialize(&admitted_tree(), &destination, &total_bytes_policy),
            Err(LocalMaterializationError::TotalBytesExceeded { .. })
        ));
        assert!(!destination.exists());
        assert!(staging_entries(parent.path()).is_empty());
    }

    #[test]
    fn unsafe_permission_modes_are_refused() {
        assert_eq!(
            LocalMaterializationPolicy::new(
                ConflictPolicy::RefuseExisting,
                0o755,
                0o1_644,
                limits()
            ),
            Err(LocalMaterializationError::InvalidFileMode(0o1_644))
        );
        assert_eq!(
            LocalMaterializationPolicy::new(ConflictPolicy::RefuseExisting, 0o500, 0o600, limits()),
            Err(LocalMaterializationError::InvalidDirectoryMode(0o500))
        );
    }

    #[test]
    fn mismatched_reference_cannot_cross_the_authority_gate() {
        let different_fact = Fact::new(
            file_tree_value_kind(),
            serde_json::to_value(
                FileTree::new(vec![
                    FileEntry::new("different.txt", "text/plain", b"different".to_vec()).unwrap(),
                ])
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();

        let fact = Fact::new(
            file_tree_value_kind(),
            serde_json::to_value(tree()).unwrap(),
        )
        .unwrap();
        let (ledger, mut reference) = admit_fact_reference(fact, BTreeMap::new());
        reference.fact_id = different_fact.id;
        assert!(matches!(
            AdmittedFileTree::resolve(&ledger, &reference),
            Err(AdmittedFileTreeError::Resolution(_))
        ));
    }

    #[test]
    fn stale_authority_cannot_cross_the_authority_gate() {
        let mut authority = admitted_fact_record(tree());
        authority.fact.payload = json!({"files": []});
        let forged = ResolvedFact {
            fact: &authority.fact,
            authority: &authority,
        };
        assert!(matches!(
            AdmittedFileTree::from_resolved(
                &AdmissionLedger::new(),
                forged,
                &mut crate::RejectAllAuthorityExtensions,
            ),
            Err(AdmittedFileTreeError::InvalidAuthority(_))
        ));
    }

    fn admitted_fact_record(tree: FileTree) -> gooir_capability::authority::AuthorityRecord {
        let fact = Fact::new(file_tree_value_kind(), serde_json::to_value(tree).unwrap()).unwrap();
        let evidence_kind = EvidenceKindId::new("test.evidence", "record", "1.0.0");
        let authority = ObservationAuthority::new(
            ObservationSourceId::new("test.source", "record", "1.0.0"),
            ImplementationId::new("test.observer", "record", "1.0.0"),
            ArtifactDigest::parse(sha('1')).unwrap(),
            fact.value_kind.clone(),
            evidence_kind.clone(),
            BTreeMap::new(),
        )
        .unwrap();
        let observation = SourceObservation::new(
            fact,
            authority.clone(),
            EvidenceRef::new(
                evidence_kind,
                EvidenceDigest::parse(sha('2')).unwrap(),
                "memory://record",
                BTreeMap::new(),
            )
            .unwrap(),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let policy = AdmissionPolicy::new(
            AdmissionAuthorityId::new("test.admission", "record", "1.0.0"),
            Vec::new(),
            vec![authority],
            BTreeMap::new(),
        )
        .unwrap();
        let mut ledger = AdmissionLedger::new();
        let AdmissionOutcome::Admitted { links, .. } =
            ledger.admit_observation(&policy, &observation).unwrap()
        else {
            panic!("fixture observation must be admitted");
        };
        ledger
            .resolve(&links[0].reference)
            .unwrap()
            .authority
            .clone()
    }
}
