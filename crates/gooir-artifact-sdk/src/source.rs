//! Bounded, descriptor-anchored ingestion of one local source tree.
//!
//! This module performs host filesystem I/O only. It assigns no observation,
//! provider, or admission authority to the bytes it reads.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::{ContentSet, ContentSetError};

/// Explicit finite bounds for one recursive source-tree read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTreeLimits {
    pub max_files: usize,
    /// Maximum number of descendant directories; the declared root is excluded.
    pub max_directories: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
}

impl Default for SourceTreeLimits {
    fn default() -> Self {
        Self {
            max_files: 16_384,
            max_directories: 16_384,
            max_file_bytes: 64 * 1024 * 1024,
            max_total_bytes: 512 * 1024 * 1024,
        }
    }
}

/// Read-only local source-tree reader with explicit resource bounds.
#[derive(Clone, Debug, Default)]
pub struct LocalSourceTreeReader {
    limits: SourceTreeLimits,
}

impl LocalSourceTreeReader {
    /// Creates a reader with explicit finite bounds.
    ///
    /// # Errors
    ///
    /// Returns [`SourceTreeError::InvalidLimits`] when any bound is zero or
    /// when the combined entry bound cannot be represented on this host.
    pub fn new(limits: SourceTreeLimits) -> Result<Self, SourceTreeError> {
        validate_limits(limits)?;
        Ok(Self { limits })
    }

    /// Recursively reads one ordinary directory into a canonical content set.
    ///
    /// The root itself is a host-local anchor and is not included in content
    /// paths. Every descendant path must satisfy [`crate::ContentPath`].
    /// Symlinks and filesystem objects other than ordinary files and
    /// directories are refused. This operation confers no authority on the
    /// returned bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid root, invalid path, unsupported entry,
    /// exceeded bound, detected filesystem race, or I/O failure.
    pub fn read(&self, root: impl AsRef<Path>) -> Result<ContentSet, SourceTreeError> {
        validate_limits(self.limits)?;
        read_platform(root.as_ref(), self.limits)
    }

    #[must_use]
    pub const fn limits(&self) -> SourceTreeLimits {
        self.limits
    }
}

/// Failure to obtain one exact, bounded snapshot of a local source tree.
#[derive(Debug)]
pub enum SourceTreeError {
    InvalidLimits,
    UnsupportedPlatform,
    RootNotDirectory(PathBuf),
    NonUtf8Path(PathBuf),
    InvalidContentPath {
        path: PathBuf,
        source: ContentSetError,
    },
    UnsupportedEntry(PathBuf),
    FileLimitExceeded {
        limit: usize,
    },
    DirectoryLimitExceeded {
        limit: usize,
    },
    EntryLimitExceeded {
        limit: usize,
    },
    FileBytesExceeded {
        path: PathBuf,
        bytes: u64,
        limit: u64,
    },
    TotalBytesExceeded {
        limit: u64,
    },
    HostCapacityExceeded(PathBuf),
    Race(PathBuf),
    InvalidContentSet(ContentSetError),
    MissingMarker(PathBuf),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl fmt::Display for SourceTreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("source-tree limits must be nonzero"),
            Self::UnsupportedPlatform => formatter.write_str(
                "bounded local source-tree reading is supported only on macOS and Linux",
            ),
            Self::RootNotDirectory(path) => write!(
                formatter,
                "source-tree root `{}` is not an ordinary directory",
                path.display()
            ),
            Self::NonUtf8Path(path) => write!(
                formatter,
                "source-tree path `{}` is not portable UTF-8",
                path.display()
            ),
            Self::InvalidContentPath { path, source } => write!(
                formatter,
                "source-tree path `{}` is not portable: {source}",
                path.display()
            ),
            Self::UnsupportedEntry(path) => write!(
                formatter,
                "source-tree entry `{}` is neither an ordinary file nor a directory",
                path.display()
            ),
            Self::FileLimitExceeded { limit } => {
                write!(formatter, "source tree exceeds file limit {limit}")
            }
            Self::DirectoryLimitExceeded { limit } => {
                write!(formatter, "source tree exceeds directory limit {limit}")
            }
            Self::EntryLimitExceeded { limit } => {
                write!(
                    formatter,
                    "source tree exceeds combined entry limit {limit}"
                )
            }
            Self::FileBytesExceeded { path, bytes, limit } => write!(
                formatter,
                "source file `{}` has {bytes} bytes, exceeding per-file limit {limit}",
                path.display()
            ),
            Self::TotalBytesExceeded { limit } => {
                write!(
                    formatter,
                    "source tree exceeds aggregate byte limit {limit}"
                )
            }
            Self::HostCapacityExceeded(path) => write!(
                formatter,
                "source file `{}` is too large for this host",
                path.display()
            ),
            Self::Race(path) => write!(
                formatter,
                "source-tree entry `{}` changed while it was being read",
                path.display()
            ),
            Self::InvalidContentSet(source) => {
                write!(
                    formatter,
                    "source tree is not a valid content set: {source}"
                )
            }
            Self::MissingMarker(path) => write!(
                formatter,
                "managed tree is missing required marker `{}`",
                path.display()
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "{operation} `{}` failed: {source}",
                path.display()
            ),
        }
    }
}

#[derive(Debug)]
pub(crate) struct ManagedTreeRead {
    pub(crate) content: ContentSet,
    pub(crate) directories: BTreeSet<String>,
    pub(crate) marker: Option<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) struct ManagedTreeReadError {
    pub(crate) marker: Option<Vec<u8>>,
    pub(crate) source: SourceTreeError,
}

pub(crate) fn read_managed_tree(
    root: &Path,
    limits: SourceTreeLimits,
    max_manifest_bytes: u64,
    marker_required: bool,
) -> Result<ManagedTreeRead, ManagedTreeReadError> {
    validate_limits(limits).map_err(ManagedTreeReadError::before_marker)?;
    if max_manifest_bytes == 0 {
        return Err(ManagedTreeReadError::before_marker(
            SourceTreeError::InvalidLimits,
        ));
    }
    read_managed_platform(root, limits, max_manifest_bytes, marker_required)
}

impl ManagedTreeReadError {
    fn before_marker(source: SourceTreeError) -> Self {
        Self {
            marker: None,
            source,
        }
    }
}

impl Error for SourceTreeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidContentPath { source, .. } | Self::InvalidContentSet(source) => {
                Some(source)
            }
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn validate_limits(limits: SourceTreeLimits) -> Result<(), SourceTreeError> {
    if limits.max_files == 0
        || limits.max_directories == 0
        || limits.max_file_bytes == 0
        || limits.max_total_bytes == 0
        || limits
            .max_files
            .checked_add(limits.max_directories)
            .is_none()
    {
        return Err(SourceTreeError::InvalidLimits);
    }
    Ok(())
}

fn io_error(
    operation: &'static str,
    path: impl Into<PathBuf>,
    source: io::Error,
) -> SourceTreeError {
    SourceTreeError::Io {
        operation,
        path: path.into(),
        source,
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn read_platform(root: &Path, limits: SourceTreeLimits) -> Result<ContentSet, SourceTreeError> {
    platform::read(root, limits)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn read_managed_platform(
    root: &Path,
    limits: SourceTreeLimits,
    max_manifest_bytes: u64,
    marker_required: bool,
) -> Result<ManagedTreeRead, ManagedTreeReadError> {
    platform::read_managed(root, limits, max_manifest_bytes, marker_required)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_platform(_root: &Path, _limits: SourceTreeLimits) -> Result<ContentSet, SourceTreeError> {
    Err(SourceTreeError::UnsupportedPlatform)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_managed_platform(
    _root: &Path,
    _limits: SourceTreeLimits,
    _max_manifest_bytes: u64,
    _marker_required: bool,
) -> Result<ManagedTreeRead, ManagedTreeReadError> {
    Err(ManagedTreeReadError::before_marker(
        SourceTreeError::UnsupportedPlatform,
    ))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod platform {
    use std::collections::VecDeque;
    use std::ffi::CStr;
    use std::fs::File;
    use std::io::{Read as _, Take};

    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat, fstat, open, openat, statat};

    use super::{
        BTreeSet, ContentSet, ManagedTreeRead, ManagedTreeReadError, Path, PathBuf,
        SourceTreeError, SourceTreeLimits, io, io_error,
    };
    use crate::{ContentFile, ContentPath, MANAGED_OUTPUT_MARKER};

    struct DirectoryFrame {
        descriptor: File,
        local_path: PathBuf,
        content_prefix: String,
        baseline: Stat,
        names: Vec<Vec<u8>>,
        next: usize,
    }

    struct ReadState {
        limits: SourceTreeLimits,
        marker: MarkerMode,
        files: usize,
        directories: usize,
        discovered_entries: usize,
        total_bytes: u64,
        content: Vec<ContentFile>,
        directory_paths: BTreeSet<String>,
        marker_bytes: Option<Vec<u8>>,
        retained_marker: Option<RetainedMarker>,
        retained_directories: Vec<RetainedDirectory>,
        retained_files: Vec<RetainedFile>,
    }

    #[derive(Clone, Copy)]
    enum MarkerMode {
        Forbidden,
        Managed { max_bytes: u64, required: bool },
    }

    struct RetainedFile {
        descriptor: File,
        snapshot: Stat,
        path: PathBuf,
    }

    struct RetainedMarker {
        descriptor: File,
        parent: File,
        snapshot: Stat,
        path: PathBuf,
    }

    struct RetainedDirectory {
        descriptor: File,
        snapshot: Stat,
        names: Vec<Vec<u8>>,
        path: PathBuf,
    }

    pub(super) fn read(
        root: &Path,
        limits: SourceTreeLimits,
    ) -> Result<ContentSet, SourceTreeError> {
        read_with_hook(root, limits, MarkerMode::Forbidden, || {}).map(|read| read.content)
    }

    pub(super) fn read_managed(
        root: &Path,
        limits: SourceTreeLimits,
        max_manifest_bytes: u64,
        marker_required: bool,
    ) -> Result<ManagedTreeRead, ManagedTreeReadError> {
        read_core(
            root,
            limits,
            MarkerMode::Managed {
                max_bytes: max_manifest_bytes,
                required: marker_required,
            },
            || {},
        )
    }

    fn read_with_hook(
        root: &Path,
        limits: SourceTreeLimits,
        marker: MarkerMode,
        before_final_validation: impl FnOnce(),
    ) -> Result<ManagedTreeRead, SourceTreeError> {
        read_core(root, limits, marker, before_final_validation).map_err(|error| error.source)
    }

    fn read_core(
        root: &Path,
        limits: SourceTreeLimits,
        marker: MarkerMode,
        before_final_validation: impl FnOnce(),
    ) -> Result<ManagedTreeRead, ManagedTreeReadError> {
        let descriptor = open_root(root).map_err(ManagedTreeReadError::before_marker)?;
        let baseline = stat(&descriptor, "inspect source-tree root", root)
            .map_err(ManagedTreeReadError::before_marker)?;
        let mut state = ReadState {
            limits,
            marker,
            files: 0,
            directories: 0,
            discovered_entries: 0,
            total_bytes: 0,
            content: Vec::new(),
            directory_paths: BTreeSet::new(),
            marker_bytes: None,
            retained_marker: None,
            retained_directories: Vec::new(),
            retained_files: Vec::new(),
        };
        if let Err(error) = state.read_root_marker(&descriptor, root) {
            return Err(state.failure(error));
        }
        let root_frame = match state.frame(descriptor, root.to_owned(), String::new(), baseline) {
            Ok(frame) => frame,
            Err(error) => return Err(state.failure(error)),
        };
        let mut stack = VecDeque::from([root_frame]);

        while !stack.is_empty() {
            if stack
                .back()
                .is_some_and(|frame| frame.next == frame.names.len())
            {
                let frame = stack
                    .pop_back()
                    .expect("the completed directory frame is present");
                let current = match enumerate_names(
                    &frame.descriptor,
                    frame.names.len().saturating_add(1),
                    &frame.local_path,
                ) {
                    Ok(names) => names,
                    Err(error) => return Err(state.failure(error)),
                };
                let after = match stat(
                    &frame.descriptor,
                    "reinspect source directory",
                    &frame.local_path,
                ) {
                    Ok(after) => after,
                    Err(error) => return Err(state.failure(error)),
                };
                if current != frame.names || !same_snapshot(&frame.baseline, &after) {
                    return Err(state.failure(SourceTreeError::Race(frame.local_path.clone())));
                }
                state.retained_directories.push(RetainedDirectory {
                    descriptor: frame.descriptor,
                    snapshot: after,
                    names: frame.names,
                    path: frame.local_path,
                });
                continue;
            }

            let frame = stack
                .back_mut()
                .expect("the active directory frame is present");
            let name = frame.names[frame.next].clone();
            frame.next += 1;
            let parent_path = frame.local_path.clone();
            let prefix = frame.content_prefix.clone();
            let Some(frame) = stack.back() else {
                unreachable!("the active directory frame remains on the stack")
            };
            match state.read_entry(frame, &parent_path, &prefix, &name) {
                Ok(Some(child)) => stack.push_back(child),
                Ok(None) => {}
                Err(error) => return Err(state.failure(error)),
            }
        }

        before_final_validation();
        if let Err(error) = state.validate_retained_marker() {
            return Err(ManagedTreeReadError::before_marker(error));
        }
        if let Err(error) = state.validate_retained_directories() {
            return Err(state.failure(error));
        }
        if let Err(error) = state.validate_retained_files() {
            return Err(state.failure(error));
        }
        let content = match ContentSet::new(std::mem::take(&mut state.content)) {
            Ok(content) => content,
            Err(error) => return Err(state.failure(SourceTreeError::InvalidContentSet(error))),
        };
        Ok(ManagedTreeRead {
            content,
            directories: state.directory_paths,
            marker: state.marker_bytes,
        })
    }

    impl ReadState {
        fn read_root_marker(
            &mut self,
            root_descriptor: &File,
            root: &Path,
        ) -> Result<(), SourceTreeError> {
            let MarkerMode::Managed {
                max_bytes,
                required,
            } = self.marker
            else {
                return Ok(());
            };
            let path = root.join(MANAGED_OUTPUT_MARKER);
            let name = MANAGED_OUTPUT_MARKER.as_bytes();
            let nul_name = nul_terminated(name);
            let name_cstr = CStr::from_bytes_with_nul(&nul_name)
                .expect("the managed marker name contains no NUL");
            let before = match statat(root_descriptor, name_cstr, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(before) => before,
                Err(rustix::io::Errno::NOENT) if required => {
                    return Err(SourceTreeError::MissingMarker(path));
                }
                Err(rustix::io::Errno::NOENT) => return Ok(()),
                Err(error) => {
                    return Err(rustix_error("inspect managed marker", &path, error));
                }
            };
            if !FileType::from_raw_mode(before.st_mode).is_file() {
                return Err(SourceTreeError::UnsupportedEntry(path));
            }
            let parent = root_descriptor
                .try_clone()
                .map_err(|error| io_error("retain managed root", root, error))?;
            let (bytes, retained) =
                read_regular(root_descriptor, name, path.clone(), before, max_bytes)?;
            self.marker_bytes = Some(bytes);
            self.retained_marker = Some(RetainedMarker {
                descriptor: retained.descriptor,
                parent,
                snapshot: retained.snapshot,
                path,
            });
            Ok(())
        }

        fn frame(
            &mut self,
            descriptor: File,
            local_path: PathBuf,
            content_prefix: String,
            baseline: Stat,
        ) -> Result<DirectoryFrame, SourceTreeError> {
            let combined_limit = self
                .limits
                .max_files
                .checked_add(self.limits.max_directories)
                .ok_or(SourceTreeError::InvalidLimits)?;
            let remaining = combined_limit.checked_sub(self.discovered_entries).ok_or(
                SourceTreeError::EntryLimitExceeded {
                    limit: combined_limit,
                },
            )?;
            let root_marker_allowance = usize::from(
                content_prefix.is_empty() && matches!(self.marker, MarkerMode::Managed { .. }),
            );
            let names = enumerate_names(
                &descriptor,
                remaining.saturating_add(root_marker_allowance),
                &local_path,
            )?;
            let counted_entries = names.len().saturating_sub(usize::from(
                root_marker_allowance == 1
                    && names
                        .iter()
                        .any(|name| name.as_slice() == MANAGED_OUTPUT_MARKER.as_bytes()),
            ));
            self.discovered_entries = self.discovered_entries.checked_add(counted_entries).ok_or(
                SourceTreeError::EntryLimitExceeded {
                    limit: combined_limit,
                },
            )?;
            if self.discovered_entries > combined_limit {
                return Err(SourceTreeError::EntryLimitExceeded {
                    limit: combined_limit,
                });
            }
            Ok(DirectoryFrame {
                descriptor,
                local_path,
                content_prefix,
                baseline,
                names,
                next: 0,
            })
        }

        fn read_entry(
            &mut self,
            parent: &DirectoryFrame,
            parent_path: &Path,
            prefix: &str,
            name: &[u8],
        ) -> Result<Option<DirectoryFrame>, SourceTreeError> {
            let name_text = std::str::from_utf8(name).map_err(|_| {
                SourceTreeError::NonUtf8Path(parent_path.join(bytes_for_display(name)))
            })?;
            let content_path = if prefix.is_empty() {
                name_text.to_owned()
            } else {
                format!("{prefix}/{name_text}")
            };
            let local_path = parent_path.join(name_text);

            let before = statat(
                &parent.descriptor,
                CStr::from_bytes_with_nul(&nul_terminated(name))
                    .expect("directory entry names contain no NUL"),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(|error| rustix_error("inspect source-tree entry", &local_path, error))?;
            let kind = FileType::from_raw_mode(before.st_mode);
            if kind.is_symlink() || (!kind.is_file() && !kind.is_dir()) {
                return Err(SourceTreeError::UnsupportedEntry(local_path));
            }
            if prefix.is_empty()
                && name == MANAGED_OUTPUT_MARKER.as_bytes()
                && matches!(self.marker, MarkerMode::Managed { .. })
            {
                let Some(retained) = &self.retained_marker else {
                    return Err(SourceTreeError::Race(local_path));
                };
                if !same_snapshot(&before, &retained.snapshot) {
                    return Err(SourceTreeError::Race(local_path));
                }
                return Ok(None);
            }
            ContentPath::parse(&content_path).map_err(|source| {
                SourceTreeError::InvalidContentPath {
                    path: local_path.clone(),
                    source,
                }
            })?;
            if kind.is_dir() {
                return self
                    .open_directory(parent, name, local_path, content_path, before)
                    .map(Some);
            }
            self.read_file(parent, name, local_path, content_path, before)?;
            Ok(None)
        }

        fn open_directory(
            &mut self,
            parent: &DirectoryFrame,
            name: &[u8],
            local_path: PathBuf,
            content_prefix: String,
            before: Stat,
        ) -> Result<DirectoryFrame, SourceTreeError> {
            if self.directories == self.limits.max_directories {
                return Err(SourceTreeError::DirectoryLimitExceeded {
                    limit: self.limits.max_directories,
                });
            }
            let descriptor = open_child(
                &parent.descriptor,
                name,
                OFlags::RDONLY
                    | OFlags::DIRECTORY
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK,
                "open source directory without following symlinks",
                &local_path,
            )?;
            let opened = stat(&descriptor, "inspect opened source directory", &local_path)?;
            if !FileType::from_raw_mode(opened.st_mode).is_dir() || !same_entry(&before, &opened) {
                return Err(SourceTreeError::Race(local_path));
            }
            self.directories += 1;
            self.directory_paths.insert(content_prefix.clone());
            self.frame(descriptor, local_path, content_prefix, opened)
        }

        fn read_file(
            &mut self,
            parent: &DirectoryFrame,
            name: &[u8],
            local_path: PathBuf,
            content_path: String,
            before: Stat,
        ) -> Result<(), SourceTreeError> {
            if self.files == self.limits.max_files {
                return Err(SourceTreeError::FileLimitExceeded {
                    limit: self.limits.max_files,
                });
            }
            let size = u64::try_from(before.st_size)
                .map_err(|_| SourceTreeError::Race(local_path.clone()))?;
            if size > self.limits.max_file_bytes {
                return Err(SourceTreeError::FileBytesExceeded {
                    path: local_path,
                    bytes: size,
                    limit: self.limits.max_file_bytes,
                });
            }
            let remaining = self
                .limits
                .max_total_bytes
                .checked_sub(self.total_bytes)
                .ok_or(SourceTreeError::TotalBytesExceeded {
                    limit: self.limits.max_total_bytes,
                })?;
            if size > remaining {
                return Err(SourceTreeError::TotalBytesExceeded {
                    limit: self.limits.max_total_bytes,
                });
            }
            let read_limit = self.limits.max_file_bytes.min(remaining);
            let (bytes, retained) = read_regular(
                &parent.descriptor,
                name,
                local_path.clone(),
                before,
                read_limit,
            )?;
            let actual = u64::try_from(bytes.len())
                .map_err(|_| SourceTreeError::HostCapacityExceeded(local_path.clone()))?;
            if actual > self.limits.max_file_bytes {
                return Err(SourceTreeError::FileBytesExceeded {
                    path: local_path,
                    bytes: actual,
                    limit: self.limits.max_file_bytes,
                });
            }
            if actual > remaining {
                return Err(SourceTreeError::TotalBytesExceeded {
                    limit: self.limits.max_total_bytes,
                });
            }
            self.total_bytes = self.total_bytes.checked_add(actual).ok_or(
                SourceTreeError::TotalBytesExceeded {
                    limit: self.limits.max_total_bytes,
                },
            )?;
            self.files += 1;
            self.retained_files.push(retained);
            self.content.push(
                ContentFile::new(content_path, bytes)
                    .map_err(SourceTreeError::InvalidContentSet)?,
            );
            Ok(())
        }

        fn validate_retained_files(&self) -> Result<(), SourceTreeError> {
            for retained in &self.retained_files {
                let after = stat(
                    &retained.descriptor,
                    "final source file validation",
                    &retained.path,
                )?;
                if !same_snapshot(&retained.snapshot, &after) {
                    return Err(SourceTreeError::Race(retained.path.clone()));
                }
            }
            Ok(())
        }

        fn validate_retained_marker(&self) -> Result<(), SourceTreeError> {
            let Some(retained) = &self.retained_marker else {
                return Ok(());
            };
            let descriptor_after = stat(
                &retained.descriptor,
                "final managed marker validation",
                &retained.path,
            )?;
            let nul_name = nul_terminated(MANAGED_OUTPUT_MARKER.as_bytes());
            let name = CStr::from_bytes_with_nul(&nul_name)
                .expect("the managed marker name contains no NUL");
            let entry_after = match statat(&retained.parent, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(after) => after,
                Err(rustix::io::Errno::NOENT) => {
                    return Err(SourceTreeError::Race(retained.path.clone()));
                }
                Err(error) => {
                    return Err(rustix_error(
                        "reinspect managed marker",
                        &retained.path,
                        error,
                    ));
                }
            };
            if !same_snapshot(&retained.snapshot, &descriptor_after)
                || !same_snapshot(&retained.snapshot, &entry_after)
            {
                return Err(SourceTreeError::Race(retained.path.clone()));
            }
            Ok(())
        }

        fn failure(&self, source: SourceTreeError) -> ManagedTreeReadError {
            match self.validate_retained_marker() {
                Ok(()) => ManagedTreeReadError {
                    marker: self.marker_bytes.clone(),
                    source,
                },
                Err(marker_error) => ManagedTreeReadError::before_marker(marker_error),
            }
        }

        fn validate_retained_directories(&self) -> Result<(), SourceTreeError> {
            for retained in &self.retained_directories {
                let names = enumerate_names(
                    &retained.descriptor,
                    retained.names.len().saturating_add(1),
                    &retained.path,
                )?;
                let after = stat(
                    &retained.descriptor,
                    "final source directory validation",
                    &retained.path,
                )?;
                if names != retained.names || !same_snapshot(&retained.snapshot, &after) {
                    return Err(SourceTreeError::Race(retained.path.clone()));
                }
            }
            Ok(())
        }
    }

    fn read_regular(
        parent: &File,
        name: &[u8],
        local_path: PathBuf,
        before: Stat,
        max_bytes: u64,
    ) -> Result<(Vec<u8>, RetainedFile), SourceTreeError> {
        let size =
            u64::try_from(before.st_size).map_err(|_| SourceTreeError::Race(local_path.clone()))?;
        if size > max_bytes {
            return Err(SourceTreeError::FileBytesExceeded {
                path: local_path,
                bytes: size,
                limit: max_bytes,
            });
        }
        let descriptor = open_child(
            parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            "open source file without following symlinks",
            &local_path,
        )?;
        let opened = stat(&descriptor, "inspect opened source file", &local_path)?;
        if !FileType::from_raw_mode(opened.st_mode).is_file() || !same_snapshot(&before, &opened) {
            return Err(SourceTreeError::Race(local_path));
        }

        let capacity = usize::try_from(size)
            .map_err(|_| SourceTreeError::HostCapacityExceeded(local_path.clone()))?;
        let mut bytes = Vec::with_capacity(capacity);
        let mut bounded: Take<File> = descriptor.take(max_bytes.saturating_add(1));
        bounded
            .read_to_end(&mut bytes)
            .map_err(|error| io_error("read source file", &local_path, error))?;
        let after = stat(bounded.get_ref(), "reinspect source file", &local_path)?;
        let actual = u64::try_from(bytes.len())
            .map_err(|_| SourceTreeError::HostCapacityExceeded(local_path.clone()))?;
        if actual > max_bytes {
            return Err(SourceTreeError::FileBytesExceeded {
                path: local_path,
                bytes: actual,
                limit: max_bytes,
            });
        }
        if actual != size || !same_snapshot(&opened, &after) {
            return Err(SourceTreeError::Race(local_path));
        }
        Ok((
            bytes,
            RetainedFile {
                descriptor: bounded.into_inner(),
                snapshot: after,
                path: local_path,
            },
        ))
    }

    fn open_root(root: &Path) -> Result<File, SourceTreeError> {
        match std::fs::symlink_metadata(root) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(SourceTreeError::RootNotDirectory(root.to_owned())),
            Err(error) => return Err(io_error("inspect source-tree root", root, error)),
        }
        let descriptor = open(
            root,
            OFlags::RDONLY
                | OFlags::DIRECTORY
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| rustix_error("open source-tree root", root, error))?;
        let descriptor = File::from(descriptor);
        let metadata = stat(&descriptor, "inspect opened source-tree root", root)?;
        if !FileType::from_raw_mode(metadata.st_mode).is_dir() {
            return Err(SourceTreeError::RootNotDirectory(root.to_owned()));
        }
        Ok(descriptor)
    }

    fn open_child(
        directory: &File,
        name: &[u8],
        flags: OFlags,
        operation: &'static str,
        path: &Path,
    ) -> Result<File, SourceTreeError> {
        let nul_name = nul_terminated(name);
        let name =
            CStr::from_bytes_with_nul(&nul_name).expect("directory entry names contain no NUL");
        openat(directory, name, flags, Mode::empty())
            .map(File::from)
            .map_err(|error| rustix_error(operation, path, error))
    }

    fn enumerate_names(
        directory: &File,
        max_names: usize,
        path: &Path,
    ) -> Result<Vec<Vec<u8>>, SourceTreeError> {
        let mut stream = Dir::read_from(directory)
            .map_err(|error| rustix_error("open source directory stream", path, error))?;
        let mut names = Vec::new();
        for entry in &mut stream {
            let entry =
                entry.map_err(|error| rustix_error("read source directory", path, error))?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            if names.len() == max_names {
                return Err(SourceTreeError::EntryLimitExceeded { limit: max_names });
            }
            names.push(name.to_vec());
        }
        names.sort_unstable();
        Ok(names)
    }

    fn stat(
        descriptor: &File,
        operation: &'static str,
        path: &Path,
    ) -> Result<Stat, SourceTreeError> {
        fstat(descriptor).map_err(|error| rustix_error(operation, path, error))
    }

    fn same_entry(left: &Stat, right: &Stat) -> bool {
        left.st_dev == right.st_dev
            && left.st_ino == right.st_ino
            && left.st_mode == right.st_mode
            && left.st_nlink == right.st_nlink
    }

    fn same_snapshot(left: &Stat, right: &Stat) -> bool {
        same_entry(left, right)
            && left.st_size == right.st_size
            && left.st_mtime == right.st_mtime
            && left.st_mtime_nsec == right.st_mtime_nsec
            && left.st_ctime == right.st_ctime
            && left.st_ctime_nsec == right.st_ctime_nsec
    }

    fn nul_terminated(name: &[u8]) -> Vec<u8> {
        let mut terminated = Vec::with_capacity(name.len().saturating_add(1));
        terminated.extend_from_slice(name);
        terminated.push(0);
        terminated
    }

    fn bytes_for_display(name: &[u8]) -> std::ffi::OsString {
        use std::os::unix::ffi::OsStringExt as _;
        std::ffi::OsString::from_vec(name.to_vec())
    }

    fn rustix_error(
        operation: &'static str,
        path: impl Into<PathBuf>,
        source: rustix::io::Errno,
    ) -> SourceTreeError {
        io_error(
            operation,
            path,
            io::Error::from_raw_os_error(source.raw_os_error()),
        )
    }

    #[cfg(test)]
    mod tests {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;
        use std::os::unix::fs::symlink;

        use tempfile::TempDir;

        use super::{
            BTreeSet, ContentFile, MANAGED_OUTPUT_MARKER, MarkerMode, SourceTreeError,
            SourceTreeLimits, read_core, read_managed, read_with_hook,
        };

        #[test]
        fn already_read_file_mutated_before_final_validation_is_rejected() {
            let root = TempDir::new().unwrap();
            let file = root.path().join("first.txt");
            fs::write(&file, b"first").unwrap();

            let result = read_with_hook(
                root.path(),
                SourceTreeLimits::default(),
                MarkerMode::Forbidden,
                || fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap(),
            );

            assert!(matches!(result, Err(SourceTreeError::Race(path)) if path == file));
        }

        #[test]
        fn directory_mutated_after_traversal_is_rejected() {
            let root = TempDir::new().unwrap();
            fs::write(root.path().join("first.txt"), b"first").unwrap();
            let late = root.path().join("late.txt");

            let result = read_with_hook(
                root.path(),
                SourceTreeLimits::default(),
                MarkerMode::Forbidden,
                || fs::write(&late, b"late").unwrap(),
            );

            assert!(matches!(result, Err(SourceTreeError::Race(path)) if path == root.path()));
        }

        #[test]
        fn managed_read_returns_marker_content_and_descendant_directories_separately() {
            let root = TempDir::new().unwrap();
            fs::write(root.path().join(MANAGED_OUTPUT_MARKER), b"manifest").unwrap();
            fs::create_dir(root.path().join("empty")).unwrap();
            fs::create_dir(root.path().join("nested")).unwrap();
            fs::write(root.path().join("nested/file"), b"content").unwrap();

            let read = read_managed(root.path(), SourceTreeLimits::default(), 64, true).unwrap();

            assert_eq!(read.marker.as_deref(), Some(b"manifest".as_slice()));
            assert_eq!(
                read.content.files,
                [ContentFile::new("nested/file", b"content".to_vec()).unwrap()]
            );
            assert_eq!(
                read.directories,
                BTreeSet::from(["empty".to_owned(), "nested".to_owned()])
            );
        }

        #[test]
        fn optional_managed_marker_may_be_absent() {
            let root = TempDir::new().unwrap();
            let read = read_managed(root.path(), SourceTreeLimits::default(), 64, false).unwrap();

            assert!(read.marker.is_none());
            assert!(read.content.files.is_empty());
            assert!(read.directories.is_empty());
        }

        #[test]
        fn managed_marker_race_does_not_establish_marker_bytes() {
            let root = TempDir::new().unwrap();
            let marker = root.path().join(MANAGED_OUTPUT_MARKER);
            fs::write(&marker, b"manifest").unwrap();
            let marker_mode = fs::metadata(&marker).unwrap().permissions().mode();
            let changed_mode = (marker_mode ^ 0o100) & 0o777;

            let error = read_core(
                root.path(),
                SourceTreeLimits::default(),
                MarkerMode::Managed {
                    max_bytes: 64,
                    required: true,
                },
                || fs::set_permissions(&marker, fs::Permissions::from_mode(changed_mode)).unwrap(),
            )
            .unwrap_err();

            assert!(error.marker.is_none());
            assert!(matches!(error.source, SourceTreeError::Race(path) if path == marker));
        }

        #[test]
        fn content_error_after_stable_marker_retains_marker_bytes() {
            let root = TempDir::new().unwrap();
            let marker = root.path().join(MANAGED_OUTPUT_MARKER);
            fs::write(&marker, b"manifest").unwrap();
            let outside = TempDir::new().unwrap();
            let linked = root.path().join("linked");
            symlink(outside.path(), &linked).unwrap();

            let error =
                read_managed(root.path(), SourceTreeLimits::default(), 64, true).unwrap_err();

            assert_eq!(error.marker.as_deref(), Some(b"manifest".as_slice()));
            assert!(
                matches!(error.source, SourceTreeError::UnsupportedEntry(path) if path == linked)
            );
        }
    }
}
