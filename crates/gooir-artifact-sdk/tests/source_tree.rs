#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::fs;

use gooir_artifact_sdk::{
    ContentFile, ContentSet, LocalSourceTreeReader, SourceTreeError, SourceTreeLimits,
};
use tempfile::TempDir;

fn limits(
    max_files: usize,
    max_directories: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
) -> SourceTreeLimits {
    SourceTreeLimits {
        max_files,
        max_directories,
        max_file_bytes,
        max_total_bytes,
    }
}

#[test]
fn nested_tree_is_canonical_and_independent_of_creation_order() {
    let first = TempDir::new().unwrap();
    fs::create_dir(first.path().join("z-dir")).unwrap();
    fs::write(first.path().join("z-dir/last.txt"), b"last").unwrap();
    fs::write(first.path().join("middle.txt"), b"middle").unwrap();
    fs::create_dir(first.path().join("a-dir")).unwrap();
    fs::write(first.path().join("a-dir/first.bin"), [0, 255, 1]).unwrap();

    let second = TempDir::new().unwrap();
    fs::create_dir(second.path().join("a-dir")).unwrap();
    fs::write(second.path().join("a-dir/first.bin"), [0, 255, 1]).unwrap();
    fs::create_dir(second.path().join("z-dir")).unwrap();
    fs::write(second.path().join("middle.txt"), b"middle").unwrap();
    fs::write(second.path().join("z-dir/last.txt"), b"last").unwrap();

    let reader = LocalSourceTreeReader::default();
    let first_set = reader.read(first.path()).unwrap();
    let second_set = reader.read(second.path()).unwrap();
    let expected = ContentSet::new(vec![
        ContentFile::new("z-dir/last.txt", b"last".to_vec()).unwrap(),
        ContentFile::new("middle.txt", b"middle".to_vec()).unwrap(),
        ContentFile::new("a-dir/first.bin", vec![0, 255, 1]).unwrap(),
    ])
    .unwrap();

    assert_eq!(first_set, expected);
    assert_eq!(second_set, expected);
    assert_eq!(
        first_set
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
        ["a-dir/first.bin", "middle.txt", "z-dir/last.txt"]
    );
}

#[test]
fn empty_tree_is_a_valid_empty_content_set() {
    let root = TempDir::new().unwrap();
    assert_eq!(
        LocalSourceTreeReader::default().read(root.path()).unwrap(),
        ContentSet::new(Vec::new()).unwrap()
    );
}

#[test]
fn every_limit_must_be_nonzero() {
    for invalid in [
        limits(0, 1, 1, 1),
        limits(1, 0, 1, 1),
        limits(1, 1, 0, 1),
        limits(1, 1, 1, 0),
    ] {
        assert!(matches!(
            LocalSourceTreeReader::new(invalid),
            Err(SourceTreeError::InvalidLimits)
        ));
    }
}

#[test]
fn file_count_is_bounded() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("a"), b"a").unwrap();
    fs::write(root.path().join("b"), b"b").unwrap();
    let reader = LocalSourceTreeReader::new(limits(1, 2, 8, 16)).unwrap();
    assert!(matches!(
        reader.read(root.path()),
        Err(SourceTreeError::FileLimitExceeded { limit: 1 })
    ));
}

#[test]
fn descendant_directory_count_is_bounded() {
    let root = TempDir::new().unwrap();
    fs::create_dir(root.path().join("a")).unwrap();
    fs::create_dir(root.path().join("b")).unwrap();
    let reader = LocalSourceTreeReader::new(limits(2, 1, 8, 16)).unwrap();
    assert!(matches!(
        reader.read(root.path()),
        Err(SourceTreeError::DirectoryLimitExceeded { limit: 1 })
    ));
}

#[test]
fn per_file_bytes_are_bounded_before_reading() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("large"), b"1234").unwrap();
    let reader = LocalSourceTreeReader::new(limits(2, 2, 3, 16)).unwrap();
    assert!(matches!(
        reader.read(root.path()),
        Err(SourceTreeError::FileBytesExceeded {
            bytes: 4,
            limit: 3,
            ..
        })
    ));
}

#[test]
fn aggregate_bytes_are_bounded() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("a"), b"123").unwrap();
    fs::write(root.path().join("b"), b"456").unwrap();
    let reader = LocalSourceTreeReader::new(limits(2, 2, 4, 5)).unwrap();
    assert!(matches!(
        reader.read(root.path()),
        Err(SourceTreeError::TotalBytesExceeded { limit: 5 })
    ));
}

#[test]
fn file_and_symlink_roots_are_refused() {
    use std::os::unix::fs::symlink;

    let fixture = TempDir::new().unwrap();
    let file = fixture.path().join("file");
    let link = fixture.path().join("link");
    fs::write(&file, b"bytes").unwrap();
    symlink(fixture.path(), &link).unwrap();
    let reader = LocalSourceTreeReader::default();

    assert!(matches!(
        reader.read(&file),
        Err(SourceTreeError::RootNotDirectory(path)) if path == file
    ));
    assert!(matches!(
        reader.read(&link),
        Err(SourceTreeError::RootNotDirectory(path)) if path == link
    ));
}

#[test]
fn descendant_symlinks_are_refused() {
    use std::os::unix::fs::symlink;

    let root = TempDir::new().unwrap();
    fs::write(root.path().join("target"), b"target").unwrap();
    symlink("target", root.path().join("link")).unwrap();
    assert!(matches!(
        LocalSourceTreeReader::default().read(root.path()),
        Err(SourceTreeError::UnsupportedEntry(path)) if path == root.path().join("link")
    ));
}

#[test]
fn managed_output_marker_is_reserved_for_public_source_reads() {
    let root = TempDir::new().unwrap();
    let marker = root.path().join(".gooir-managed-output.json");
    fs::write(&marker, b"not source").unwrap();
    assert!(matches!(
        LocalSourceTreeReader::default().read(root.path()),
        Err(SourceTreeError::InvalidContentPath { path, .. }) if path == marker
    ));
}

#[test]
fn nonportable_names_are_refused() {
    let root = TempDir::new().unwrap();
    fs::write(root.path().join("bad:name"), b"bad").unwrap();
    assert!(matches!(
        LocalSourceTreeReader::default().read(root.path()),
        Err(SourceTreeError::InvalidContentPath { path, .. })
            if path == root.path().join("bad:name")
    ));
}

#[test]
fn non_utf8_names_are_refused() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    let root = TempDir::new().unwrap();
    let name = OsString::from_vec(vec![b'b', b'a', b'd', 0xff]);
    let path = root.path().join(name);
    if let Err(error) = fs::write(&path, b"bad") {
        if error.kind() == std::io::ErrorKind::InvalidFilename
            || error.raw_os_error() == Some(rustix::io::Errno::ILSEQ.raw_os_error())
        {
            return;
        }
        panic!("could not create non-UTF-8 fixture: {error}");
    }
    assert!(matches!(
        LocalSourceTreeReader::default().read(root.path()),
        Err(SourceTreeError::NonUtf8Path(actual)) if actual == path
    ));
}

#[test]
#[cfg(target_os = "linux")]
fn fifo_is_refused_without_blocking() {
    use rustix::fs::{Mode, mkfifoat};

    let root = TempDir::new().unwrap();
    let fifo = root.path().join("pipe");
    mkfifoat(rustix::fs::CWD, &fifo, Mode::RUSR | Mode::WUSR).unwrap();
    assert!(matches!(
        LocalSourceTreeReader::default().read(root.path()),
        Err(SourceTreeError::UnsupportedEntry(path)) if path == fifo
    ));
}
