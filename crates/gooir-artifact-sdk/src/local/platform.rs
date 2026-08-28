use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::io::{Read as _, Take};
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, RenameFlags};

use super::*;

pub(super) fn read_nofollow(path: &Path, max_bytes: u64) -> Result<Vec<u8>, PublishError> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| {
        io_error(
            "open regular file without following symlinks",
            path,
            std::io::Error::from_raw_os_error(error.raw_os_error()),
        )
    })?;
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|error| io_error("inspect opened file", path, error))?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(PublishError::Drift(path.to_owned()));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    let mut bounded: Take<File> = file.take(max_bytes.saturating_add(1));
    bounded
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read regular file", path, error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != metadata.len() {
        return Err(PublishError::Drift(path.to_owned()));
    }
    Ok(bytes)
}

pub(super) fn with_parent_lock<T>(
    output: &ManagedOutput,
    exclusive: bool,
    operation: impl FnOnce() -> Result<T, PublishError>,
) -> Result<T, PublishError> {
    let parent = output
        .destination()
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            PublishError::MissingParent(parent.to_owned())
        } else {
            io_error("inspect parent", parent, error)
        }
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(PublishError::Unmanaged(parent.to_owned()));
    }
    let directory = File::open(parent).map_err(|error| io_error("open parent", parent, error))?;
    let lock = if exclusive {
        FlockOperation::LockExclusive
    } else {
        FlockOperation::LockShared
    };
    rustix::fs::flock(&directory, lock).map_err(|error| {
        io_error(
            "lock parent",
            parent,
            std::io::Error::from_raw_os_error(error.raw_os_error()),
        )
    })?;
    let result = operation();
    // Unlock failure cannot invalidate the completed operation, and closing the
    // descriptor releases the advisory lock in all cases.
    let _ = rustix::fs::flock(&directory, FlockOperation::Unlock);
    result
}

pub(super) fn stage(
    output: &ManagedOutput,
    artifact: &Admitted<ContentSet>,
    manifest: &OwnershipManifest,
) -> Result<PathBuf, PublishError> {
    let parent = output
        .destination()
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stage = create_private_stage(
        parent,
        output.destination().file_name().expect("validated name"),
    )?;
    let result = populate_stage(&stage, artifact, manifest);
    if let Err(error) = result {
        return Err(super::clean_stage_after_error(&stage, error));
    }
    Ok(stage)
}

fn create_private_stage(
    parent: &Path,
    destination_name: &std::ffi::OsStr,
) -> Result<PathBuf, PublishError> {
    for _ in 0..16 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|error| {
            PublishError::UnsupportedRuntime(format!("secure staging name unavailable: {error}"))
        })?;
        let suffix = random.iter().fold(
            String::with_capacity(random.len() * 2),
            |mut encoded, byte| {
                write!(encoded, "{byte:02x}").expect("writing to a string cannot fail");
                encoded
            },
        );
        let stage = parent.join(format!(
            ".{}.gooir-stage-{suffix}",
            destination_name.to_string_lossy()
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&stage) {
            Ok(()) => {
                return Ok(stage);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error("create stage", &stage, error)),
        }
    }
    Err(PublishError::Race(
        "could not allocate a unique staging directory".to_owned(),
    ))
}

fn populate_stage(
    stage: &Path,
    artifact: &Admitted<ContentSet>,
    manifest: &OwnershipManifest,
) -> Result<(), PublishError> {
    let mut directories = BTreeSet::new();
    for content in &artifact.value().files {
        let path = stage.join(content.path.as_str());
        if let Some(parent) = path.parent() {
            create_directories(stage, parent, &mut directories)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| io_error("create staged file", &path, error))?;
        file.write_all(&content.content)
            .map_err(|error| io_error("write staged file", &path, error))?;
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|error| io_error("set staged file permissions", &path, error))?;
        file.sync_all()
            .map_err(|error| io_error("sync staged file", &path, error))?;
    }
    let marker = stage.join(crate::MANAGED_OUTPUT_MARKER);
    let mut marker_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .map_err(|error| io_error("create ownership marker", &marker, error))?;
    marker_file
        .write_all(&manifest.to_canonical_json()?)
        .map_err(|error| io_error("write ownership marker", &marker, error))?;
    marker_file
        .set_permissions(fs::Permissions::from_mode(0o644))
        .map_err(|error| io_error("set marker permissions", &marker, error))?;
    marker_file
        .sync_all()
        .map_err(|error| io_error("sync ownership marker", &marker, error))?;

    let mut directories: Vec<_> = directories.into_iter().collect();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))
            .map_err(|error| io_error("set staged directory permissions", &directory, error))?;
        File::open(&directory)
            .and_then(|file| file.sync_all())
            .map_err(|error| io_error("sync staged directory", &directory, error))?;
    }
    fs::set_permissions(stage, fs::Permissions::from_mode(0o755))
        .map_err(|error| io_error("set stage root permissions", stage, error))?;
    File::open(stage)
        .and_then(|file| file.sync_all())
        .map_err(|error| io_error("sync stage root", stage, error))?;
    Ok(())
}

fn create_directories(
    stage: &Path,
    directory: &Path,
    created: &mut BTreeSet<PathBuf>,
) -> Result<(), PublishError> {
    let relative = directory
        .strip_prefix(stage)
        .map_err(|_| PublishError::Race("staged path escaped its root".to_owned()))?;
    let mut current = stage.to_owned();
    for component in relative.components() {
        current.push(component);
        if created.insert(current.clone()) {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(&current)
                .map_err(|error| io_error("create staged directory", &current, error))?;
        }
    }
    Ok(())
}

pub(super) fn commit_create(output: &ManagedOutput, stage: &Path) -> Result<(), PublishError> {
    rename(
        output,
        stage,
        RenameFlags::NOREPLACE,
        "create managed output",
    )
}

pub(super) fn commit_exchange(output: &ManagedOutput, stage: &Path) -> Result<(), PublishError> {
    rename(
        output,
        stage,
        RenameFlags::EXCHANGE,
        "exchange managed output",
    )
}

fn rename(
    output: &ManagedOutput,
    stage: &Path,
    flags: RenameFlags,
    operation: &'static str,
) -> Result<(), PublishError> {
    let parent = output
        .destination()
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = File::open(parent).map_err(|error| io_error("open parent", parent, error))?;
    let stage_name = stage.file_name().expect("stage has a name");
    let destination_name = output.destination().file_name().expect("validated name");
    rustix::fs::renameat_with(&directory, stage_name, &directory, destination_name, flags).map_err(
        |error| {
            if matches!(
                error,
                rustix::io::Errno::NOSYS
                    | rustix::io::Errno::NOTSUP
                    | rustix::io::Errno::OPNOTSUPP
                    | rustix::io::Errno::INVAL
            ) {
                PublishError::UnsupportedRuntime(error.to_string())
            } else if error == rustix::io::Errno::EXIST {
                PublishError::Race("destination appeared before atomic create".to_owned())
            } else {
                io_error(
                    operation,
                    output.destination(),
                    std::io::Error::from_raw_os_error(error.raw_os_error()),
                )
            }
        },
    )
}

pub(super) fn sync_parent(output: &ManagedOutput) -> SyncStatus {
    let parent = output
        .destination()
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    match File::open(parent).and_then(|directory| directory.sync_all()) {
        Ok(()) => SyncStatus::DirectorySyncCompleted,
        Err(error) => SyncStatus::Uncertain {
            detail: error.to_string(),
        },
    }
}

pub(super) fn cleanup_retired(output: &ManagedOutput, stage: &Path) -> CleanupStatus {
    match fs::remove_dir_all(stage) {
        Ok(()) => match sync_parent(output) {
            SyncStatus::DirectorySyncCompleted => CleanupStatus::Complete,
            SyncStatus::Uncertain { detail } => CleanupStatus::PersistenceUncertain { detail },
            SyncStatus::NotApplicable => CleanupStatus::PersistenceUncertain {
                detail: "parent cleanup sync was not attempted".to_owned(),
            },
        },
        Err(error) => CleanupStatus::Partial {
            retained_path: stage.to_string_lossy().into_owned(),
            detail: error.to_string(),
        },
    }
}
