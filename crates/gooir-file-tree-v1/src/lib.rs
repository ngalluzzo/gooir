//! A portable, content-addressed virtual file-tree dialect.
//!
//! This crate describes exact relative file paths and bytes. It deliberately
//! carries no output directory, filesystem handle, overwrite policy,
//! permissions, deletion instruction, or claim that the files were written.
//! Materialization is a host effect outside this semantic contract.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use base64::Engine as _;
use gooir_identity::{DialectId, ValueKindId};
use gooir_package::{
    DialectDeclaration, PackageId, PackageManifest, ValueKindDeclaration, read_manifest,
};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Package identity for the first stable file-tree contract.
pub const PACKAGE_ID: &str = "org.gooi.artifact.file_tree@1.0.0";

/// Dialect package name for the first stable file-tree contract.
pub const DIALECT_PACKAGE: &str = "org.gooi.artifact.file_tree";

/// Exact dialect version for this contract.
pub const DIALECT_VERSION: &str = "1.0.0";

/// Name of the virtual file-tree value kind within the dialect.
pub const FILE_TREE_KIND: &str = "tree";

/// Maximum number of files accepted in one tree.
pub const MAX_FILES: usize = 4_096;

/// Maximum UTF-8 byte length of one relative path.
pub const MAX_PATH_BYTES: usize = 4_096;

/// Maximum UTF-8 byte length of one path component.
pub const MAX_PATH_COMPONENT_BYTES: usize = 255;

/// Maximum byte length of one media-type declaration.
pub const MAX_MEDIA_TYPE_BYTES: usize = 255;

/// Maximum content size of one file: 64 MiB.
pub const MAX_FILE_BYTES: usize = 64 * 1_024 * 1_024;

/// Maximum aggregate content size of one tree: 256 MiB.
pub const MAX_TREE_BYTES: usize = 256 * 1_024 * 1_024;

const MAX_BASE64_FILE_BYTES: usize = MAX_FILE_BYTES.div_ceil(3) * 4;

/// Checked-in package declaration for this dialect.
pub const PACKAGE_MANIFEST_JSON: &str = include_str!("../gooir-package.json");

/// Returns the exact dialect identity owned by this crate.
#[must_use]
pub fn dialect_id() -> DialectId {
    DialectId::new(DIALECT_PACKAGE, DIALECT_VERSION)
}

/// Returns the exact file-tree value-kind identity owned by this crate.
#[must_use]
pub fn file_tree_value_kind() -> ValueKindId {
    ValueKindId::in_dialect(dialect_id(), FILE_TREE_KIND)
}

/// Builds the package declaration from its semantic source of truth.
///
/// The package exports a value kind only. It offers no compiler,
/// materializer, filesystem authority, or conformance attester.
///
/// # Panics
///
/// Panics only if these static package declarations are changed into an
/// invalid combination. Repository tests exercise the same construction.
#[must_use]
pub fn build_package_manifest() -> PackageManifest {
    PackageManifest::new(
        PackageId::parse(PACKAGE_ID).expect("static package identity must be valid"),
        Vec::new(),
        Vec::new(),
        vec![DialectDeclaration {
            id: dialect_id(),
            value_kinds: vec![ValueKindDeclaration {
                id: file_tree_value_kind(),
                schema: None,
                extensions: BTreeMap::new(),
            }],
            extensions: BTreeMap::new(),
        }],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        BTreeMap::new(),
    )
    .expect("static file-tree package declaration must be valid")
}

/// Reads and validates the checked-in package declaration.
///
/// # Panics
///
/// Panics only when a repository edit makes the checked-in declaration
/// invalid. Tests require it to match [`build_package_manifest`] exactly.
#[must_use]
pub fn package_manifest() -> PackageManifest {
    read_manifest(PACKAGE_MANIFEST_JSON)
        .expect("checked-in file-tree package declaration must be valid")
}

/// Exact lowercase SHA-256 content identity of one file's bytes.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ContentDigest(String);

impl ContentDigest {
    /// Parses an exact lowercase `sha256:<64 hex digits>` identity.
    ///
    /// # Errors
    ///
    /// Returns an error for every other spelling.
    pub fn parse(value: impl Into<String>) -> Result<Self, FileTreeError> {
        let value = value.into();
        if is_sha256_identity(&value) {
            Ok(Self(value))
        } else {
            Err(FileTreeError::InvalidDigest(value))
        }
    }

    /// Derives the content identity of exact file bytes.
    #[must_use]
    pub fn for_bytes(bytes: &[u8]) -> Self {
        Self(sha256_identity(bytes))
    }

    /// Returns the exact digest spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContentDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// One exact file in a virtual [`FileTree`].
///
/// `path` is a portable relative path. `content` is held as exact bytes and
/// serialized as canonical padded Base64, preserving arbitrary non-UTF-8
/// content without expanding every byte into a JSON integer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub media_type: String,
    pub content_digest: ContentDigest,
    #[serde(with = "base64_bytes")]
    pub content: Vec<u8>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl FileEntry {
    /// Constructs and validates one file, deriving its content digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the path, media type, size, or extensions are
    /// outside this contract.
    pub fn new(
        path: impl Into<String>,
        media_type: impl Into<String>,
        content: impl Into<Vec<u8>>,
    ) -> Result<Self, FileTreeError> {
        Self::with_extensions(path, media_type, content, BTreeMap::new())
    }

    /// Constructs and validates one file while preserving extensions.
    ///
    /// # Errors
    ///
    /// Returns an error when the path, media type, size, digest, or extensions
    /// are outside this contract.
    pub fn with_extensions(
        path: impl Into<String>,
        media_type: impl Into<String>,
        content: impl Into<Vec<u8>>,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, FileTreeError> {
        let content = content.into();
        let file = Self {
            path: path.into(),
            media_type: media_type.into(),
            content_digest: ContentDigest::for_bytes(&content),
            content,
            extensions,
        };
        file.validate()?;
        Ok(file)
    }

    /// Revalidates an untrusted or deserialized file entry.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metadata, stale content identity, or an
    /// extension that shadows a contract field.
    pub fn validate(&self) -> Result<(), FileTreeError> {
        validate_path(&self.path)?;
        validate_media_type(&self.path, &self.media_type)?;
        validate_file_size(&self.path, self.content.len())?;
        validate_extensions(
            &format!("file `{}`", self.path),
            &self.extensions,
            &[
                "path",
                "media_type",
                "content_digest",
                "content",
                "extensions",
            ],
        )?;

        let expected = ContentDigest::for_bytes(&self.content);
        if self.content_digest != expected {
            return Err(FileTreeError::DigestMismatch {
                path: self.path.clone(),
                expected,
                actual: self.content_digest.clone(),
            });
        }
        Ok(())
    }
}

/// A deterministic, portable set of exact virtual files.
///
/// Entries are canonically sorted by exact path. The representation rejects
/// exact duplicates, ASCII-case aliases, and file/directory ancestor
/// collisions before any host is allowed to consider materialization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileTree {
    #[serde(deserialize_with = "deserialize_file_entries")]
    pub files: Vec<FileEntry>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl FileTree {
    /// Constructs a canonical tree, sorting entries by exact path.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, ambiguous, or invalid tree.
    pub fn new(files: Vec<FileEntry>) -> Result<Self, FileTreeError> {
        Self::with_extensions(files, BTreeMap::new())
    }

    /// Constructs a canonical tree while preserving extensions.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, ambiguous, or invalid tree,
    /// or when an extension shadows a contract field.
    pub fn with_extensions(
        mut files: Vec<FileEntry>,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, FileTreeError> {
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let tree = Self { files, extensions };
        tree.validate()?;
        Ok(tree)
    }

    /// Revalidates an untrusted or deserialized tree.
    ///
    /// # Errors
    ///
    /// Returns an error for noncanonical order, invalid files, ambiguous
    /// paths, exceeded limits, or an extension that shadows a contract field.
    pub fn validate(&self) -> Result<(), FileTreeError> {
        if self.files.is_empty() {
            return Err(FileTreeError::EmptyTree);
        }
        if self.files.len() > MAX_FILES {
            return Err(FileTreeError::TooManyFiles {
                actual: self.files.len(),
                limit: MAX_FILES,
            });
        }
        validate_extensions("file tree", &self.extensions, &["files", "extensions"])?;

        let mut exact_paths = BTreeSet::new();
        let mut portable_paths = BTreeMap::<String, String>::new();
        let mut total_size = 0usize;
        for file in &self.files {
            file.validate()?;
            total_size =
                total_size
                    .checked_add(file.content.len())
                    .ok_or(FileTreeError::TreeTooLarge {
                        actual: usize::MAX,
                        limit: MAX_TREE_BYTES,
                    })?;
            validate_tree_size(total_size)?;

            if !exact_paths.insert(file.path.clone()) {
                return Err(FileTreeError::DuplicatePath(file.path.clone()));
            }
            let portable = file.path.to_ascii_lowercase();
            if let Some(first) = portable_paths.insert(portable, file.path.clone()) {
                return Err(FileTreeError::PortablePathCollision {
                    first,
                    second: file.path.clone(),
                });
            }
        }

        for (portable_path, actual_path) in &portable_paths {
            for (index, byte) in portable_path.bytes().enumerate() {
                if byte == b'/' {
                    let portable_ancestor = &portable_path[..index];
                    let Some(actual_ancestor) = portable_paths.get(portable_ancestor) else {
                        continue;
                    };
                    return Err(FileTreeError::AncestorCollision {
                        file: actual_ancestor.clone(),
                        descendant: actual_path.clone(),
                    });
                }
            }
        }

        if self
            .files
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err(FileTreeError::NonCanonicalOrder);
        }
        Ok(())
    }
}

/// Structural failure of the portable file-tree contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileTreeError {
    EmptyTree,
    TooManyFiles {
        actual: usize,
        limit: usize,
    },
    InvalidPath(String),
    InvalidMediaType {
        path: String,
        media_type: String,
    },
    FileTooLarge {
        path: String,
        actual: usize,
        limit: usize,
    },
    TreeTooLarge {
        actual: usize,
        limit: usize,
    },
    InvalidDigest(String),
    DigestMismatch {
        path: String,
        expected: ContentDigest,
        actual: ContentDigest,
    },
    DuplicatePath(String),
    PortablePathCollision {
        first: String,
        second: String,
    },
    AncestorCollision {
        file: String,
        descendant: String,
    },
    NonCanonicalOrder,
    ReservedExtension {
        scope: String,
        key: String,
    },
}

impl fmt::Display for FileTreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTree => formatter.write_str("file tree must contain at least one file"),
            Self::TooManyFiles { actual, limit } => {
                write!(formatter, "file tree has {actual} files; limit is {limit}")
            }
            Self::InvalidPath(path) => write!(
                formatter,
                "`{}` is not a portable relative file path",
                path.escape_debug()
            ),
            Self::InvalidMediaType { path, media_type } => write!(
                formatter,
                "file `{}` has invalid media type `{}`",
                path.escape_debug(),
                media_type.escape_debug()
            ),
            Self::FileTooLarge {
                path,
                actual,
                limit,
            } => write!(
                formatter,
                "file `{}` has {actual} bytes; limit is {limit}",
                path.escape_debug()
            ),
            Self::TreeTooLarge { actual, limit } => {
                write!(
                    formatter,
                    "file tree has {actual} content bytes; limit is {limit}"
                )
            }
            Self::InvalidDigest(value) => write!(
                formatter,
                "`{}` is not an exact lowercase SHA-256 identity",
                value.escape_debug()
            ),
            Self::DigestMismatch {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "file `{}` digest mismatch: expected {expected}, got {actual}",
                path.escape_debug()
            ),
            Self::DuplicatePath(path) => {
                write!(
                    formatter,
                    "file tree repeats path `{}`",
                    path.escape_debug()
                )
            }
            Self::PortablePathCollision { first, second } => write!(
                formatter,
                "file paths `{}` and `{}` collide under portable ASCII case folding",
                first.escape_debug(),
                second.escape_debug()
            ),
            Self::AncestorCollision { file, descendant } => write!(
                formatter,
                "file `{}` is an ancestor of file `{}`",
                file.escape_debug(),
                descendant.escape_debug()
            ),
            Self::NonCanonicalOrder => {
                formatter.write_str("file entries are not in canonical path order")
            }
            Self::ReservedExtension { scope, key } => write!(
                formatter,
                "{scope} extension `{}` shadows a contract field",
                key.escape_debug()
            ),
        }
    }
}

impl Error for FileTreeError {}

fn validate_path(path: &str) -> Result<(), FileTreeError> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.starts_with('/')
        || path.starts_with('\\')
        || has_windows_drive_prefix(path)
        || path.contains('\\')
        || path.contains('\0')
    {
        return Err(FileTreeError::InvalidPath(path.to_owned()));
    }

    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.len() > MAX_PATH_COMPONENT_BYTES
            || component.ends_with('.')
            || component.ends_with(' ')
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || is_windows_device_name(component)
        {
            return Err(FileTreeError::InvalidPath(path.to_owned()));
        }
    }
    Ok(())
}

fn validate_media_type(path: &str, media_type: &str) -> Result<(), FileTreeError> {
    if media_type.is_empty()
        || media_type.len() > MAX_MEDIA_TYPE_BYTES
        || media_type.trim() != media_type
        || !media_type.is_ascii()
        || media_type.chars().any(char::is_control)
    {
        Err(FileTreeError::InvalidMediaType {
            path: path.to_owned(),
            media_type: media_type.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn validate_file_size(path: &str, size: usize) -> Result<(), FileTreeError> {
    if size > MAX_FILE_BYTES {
        Err(FileTreeError::FileTooLarge {
            path: path.to_owned(),
            actual: size,
            limit: MAX_FILE_BYTES,
        })
    } else {
        Ok(())
    }
}

fn validate_tree_size(size: usize) -> Result<(), FileTreeError> {
    if size > MAX_TREE_BYTES {
        Err(FileTreeError::TreeTooLarge {
            actual: size,
            limit: MAX_TREE_BYTES,
        })
    } else {
        Ok(())
    }
}

fn validate_extensions(
    scope: &str,
    extensions: &BTreeMap<String, Value>,
    reserved: &[&str],
) -> Result<(), FileTreeError> {
    if let Some(key) = reserved.iter().find(|key| extensions.contains_key(**key)) {
        Err(FileTreeError::ReservedExtension {
            scope: scope.to_owned(),
            key: (*key).to_owned(),
        })
    } else {
        Ok(())
    }
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn is_windows_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || upper
            .strip_prefix("COM")
            .or_else(|| upper.strip_prefix("LPT"))
            .is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
}

fn is_sha256_identity(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn sha256_identity(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut identity = String::with_capacity(71);
    identity.push_str("sha256:");
    for byte in digest {
        use fmt::Write as _;
        write!(identity, "{byte:02x}").expect("writing to a String cannot fail");
    }
    identity
}

mod base64_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        deserializer.deserialize_str(Base64Visitor)
    }

    struct Base64Visitor;

    impl<'de> Visitor<'de> for Base64Visitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_BASE64_FILE_BYTES} bytes of canonical padded Base64"
            )
        }

        fn visit_borrowed_str<E: serde::de::Error>(
            self,
            encoded: &'de str,
        ) -> Result<Self::Value, E> {
            decode(encoded)
        }

        fn visit_str<E: serde::de::Error>(self, encoded: &str) -> Result<Self::Value, E> {
            decode(encoded)
        }

        fn visit_string<E: serde::de::Error>(self, encoded: String) -> Result<Self::Value, E> {
            decode(&encoded)
        }
    }

    fn decode<E: serde::de::Error>(encoded: &str) -> Result<Vec<u8>, E> {
        validate_encoded_length(encoded.len()).map_err(E::custom)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(E::custom)?;
        if base64::engine::general_purpose::STANDARD.encode(&bytes) != encoded {
            return Err(E::custom("file content must use canonical padded Base64"));
        }
        Ok(bytes)
    }

    pub(super) fn validate_encoded_length(length: usize) -> Result<(), &'static str> {
        if length > MAX_BASE64_FILE_BYTES {
            Err("encoded file content exceeds the dialect byte limit")
        } else {
            Ok(())
        }
    }
}

fn deserialize_file_entries<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<FileEntry>, D::Error> {
    struct FileEntriesVisitor;

    impl<'de> Visitor<'de> for FileEntriesVisitor {
        type Value = Vec<FileEntry>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded sequence of file entries")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let size_hint = sequence.size_hint().unwrap_or(0);
            if size_hint > MAX_FILES {
                return Err(serde::de::Error::custom(
                    "decoded file count exceeds the dialect limit",
                ));
            }
            let mut files = Vec::with_capacity(size_hint);
            let mut total = 0usize;
            while let Some(file) = sequence.next_element::<FileEntry>()? {
                validate_decoded_entry_bounds(files.len(), total, file.content.len())
                    .map_err(serde::de::Error::custom)?;
                total += file.content.len();
                files.push(file);
            }
            Ok(files)
        }
    }

    deserializer.deserialize_seq(FileEntriesVisitor)
}

fn validate_decoded_entry_bounds(
    current_files: usize,
    current_bytes: usize,
    next_bytes: usize,
) -> Result<(), &'static str> {
    if current_files >= MAX_FILES {
        return Err("decoded file count exceeds the dialect limit");
    }
    let total = current_bytes
        .checked_add(next_bytes)
        .ok_or("decoded file content size overflow")?;
    if total > MAX_TREE_BYTES {
        return Err("decoded file content exceeds the aggregate dialect limit");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn file(path: &str, content: &[u8]) -> FileEntry {
        FileEntry::new(path, "application/octet-stream", content).unwrap()
    }

    #[test]
    fn tree_is_canonical_content_addressed_and_binary_safe() {
        let tree = FileTree::new(vec![
            file("src/z.bin", &[0, 159, 146, 150]),
            file("README.md", b"hello\n"),
        ])
        .unwrap();

        assert_eq!(tree.files[0].path, "README.md");
        assert_eq!(tree.files[1].path, "src/z.bin");
        assert_eq!(tree.files[1].content, vec![0, 159, 146, 150]);
        assert_eq!(
            tree.files[0].content_digest.as_str(),
            "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );

        let encoded = serde_json::to_string(&tree).unwrap();
        assert!(encoded.contains("\"content\":\"AJ+Slg==\""));
        let decoded: FileTree = serde_json::from_str(&encoded).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded, tree);
    }

    #[test]
    fn constructors_preserve_extensions_without_allowing_shadowing() {
        let mut file_extensions = BTreeMap::new();
        file_extensions.insert("org.example/source".to_owned(), json!("generator"));
        let entry = FileEntry::with_extensions(
            "generated/model.ts",
            "text/typescript; charset=utf-8",
            b"export {};\n".to_vec(),
            file_extensions,
        )
        .unwrap();
        let mut tree_extensions = BTreeMap::new();
        tree_extensions.insert("org.example/build".to_owned(), json!({"profile": "debug"}));
        let tree = FileTree::with_extensions(vec![entry], tree_extensions).unwrap();

        let decoded: FileTree =
            serde_json::from_str(&serde_json::to_string(&tree).unwrap()).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded, tree);

        let mut shadow = tree;
        shadow.extensions.insert("files".to_owned(), json!([]));
        assert!(matches!(
            shadow.validate(),
            Err(FileTreeError::ReservedExtension { key, .. }) if key == "files"
        ));
    }

    #[test]
    fn stale_file_digest_is_rejected() {
        let mut entry = file("schema.prisma", b"model User {}\n");
        entry.content.push(b'!');

        assert!(matches!(
            entry.validate(),
            Err(FileTreeError::DigestMismatch { path, .. }) if path == "schema.prisma"
        ));
    }

    #[test]
    fn unsafe_or_nonportable_paths_are_rejected() {
        for path in [
            "",
            "/etc/passwd",
            "../secret",
            "src/../secret",
            "src\\main.rs",
            "C:/main.rs",
            "src//main.rs",
            "src/.",
            "generated file.ts",
            "src/trailing.",
            "NUL",
            "aux.txt",
            "COM1.log",
        ] {
            assert!(
                matches!(
                    FileEntry::new(path, "text/plain", Vec::new()),
                    Err(FileTreeError::InvalidPath(actual)) if actual == path
                ),
                "accepted unsafe path {path:?}"
            );
        }
    }

    #[test]
    fn path_aliases_and_file_ancestor_collisions_are_rejected() {
        let duplicate = FileTree::new(vec![file("a.txt", b"a"), file("a.txt", b"b")]);
        assert!(matches!(duplicate, Err(FileTreeError::DuplicatePath(path)) if path == "a.txt"));

        let portable = FileTree::new(vec![file("README.md", b"a"), file("readme.md", b"b")]);
        assert!(matches!(
            portable,
            Err(FileTreeError::PortablePathCollision { .. })
        ));

        let ancestor = FileTree::new(vec![file("generated", b"a"), file("generated/a.ts", b"b")]);
        assert!(matches!(
            ancestor,
            Err(FileTreeError::AncestorCollision { file, descendant })
                if file == "generated" && descendant == "generated/a.ts"
        ));

        let portable_ancestor =
            FileTree::new(vec![file("GENERATED", b"a"), file("generated/a.ts", b"b")]);
        assert!(matches!(
            portable_ancestor,
            Err(FileTreeError::AncestorCollision { file, descendant })
                if file == "GENERATED" && descendant == "generated/a.ts"
        ));
    }

    #[test]
    fn deserialized_noncanonical_order_is_rejected() {
        let tree = FileTree {
            files: vec![file("z.txt", b"z"), file("a.txt", b"a")],
            extensions: BTreeMap::new(),
        };
        assert_eq!(tree.validate(), Err(FileTreeError::NonCanonicalOrder));
    }

    #[test]
    fn structural_limits_are_enforced_without_large_allocations() {
        let long_component = "a".repeat(MAX_PATH_COMPONENT_BYTES + 1);
        assert!(matches!(
            FileEntry::new(long_component, "text/plain", Vec::new()),
            Err(FileTreeError::InvalidPath(_))
        ));

        let long_media_type = "a".repeat(MAX_MEDIA_TYPE_BYTES + 1);
        assert!(matches!(
            FileEntry::new("a.txt", long_media_type, Vec::new()),
            Err(FileTreeError::InvalidMediaType { .. })
        ));

        assert!(matches!(
            validate_file_size("large.bin", MAX_FILE_BYTES + 1),
            Err(FileTreeError::FileTooLarge { .. })
        ));
        assert!(matches!(
            validate_tree_size(MAX_TREE_BYTES + 1),
            Err(FileTreeError::TreeTooLarge { .. })
        ));

        let too_many = (0..=MAX_FILES)
            .map(|index| file(&format!("generated/{index:04}.txt"), &[]))
            .collect();
        assert!(matches!(
            FileTree::new(too_many),
            Err(FileTreeError::TooManyFiles { .. })
        ));
    }

    #[test]
    fn digest_parser_refuses_noncanonical_spelling() {
        let uppercase = format!("sha256:{}", "A".repeat(64));
        let short = format!("sha256:{}", "a".repeat(63));
        assert!(matches!(
            ContentDigest::parse(uppercase),
            Err(FileTreeError::InvalidDigest(_))
        ));
        assert!(matches!(
            ContentDigest::parse(short),
            Err(FileTreeError::InvalidDigest(_))
        ));
    }

    #[test]
    fn content_decoder_refuses_noncanonical_base64() {
        let entry = file("empty.bin", &[]);
        let mut value = serde_json::to_value(entry).unwrap();
        value["content"] = json!("AB==");

        assert!(serde_json::from_value::<FileEntry>(value).is_err());
    }

    #[test]
    fn decoder_bounds_before_allocating_or_retaining_excess_content() {
        assert!(base64_bytes::validate_encoded_length(MAX_BASE64_FILE_BYTES + 1).is_err());
        assert!(validate_decoded_entry_bounds(MAX_FILES, 0, 0).is_err());
        assert!(validate_decoded_entry_bounds(0, MAX_TREE_BYTES, 1).is_err());

        let entry = serde_json::to_value(file("empty.bin", &[])).unwrap();
        let oversized = json!({"files": vec![entry; MAX_FILES + 1]});
        assert!(serde_json::from_value::<FileTree>(oversized).is_err());
    }

    #[test]
    fn package_manifest_matches_the_semantic_builder() {
        let expected = gooir_package::write_manifest(&build_package_manifest()).unwrap();
        assert_eq!(PACKAGE_MANIFEST_JSON.trim(), expected);
        assert_eq!(package_manifest(), build_package_manifest());
    }

    #[test]
    fn package_exports_only_the_file_tree_value_kind() {
        let manifest = build_package_manifest();
        assert!(manifest.dependencies.is_empty());
        assert!(manifest.resources.is_empty());
        assert!(manifest.capabilities.is_empty());
        assert!(manifest.implementation_offers.is_empty());
        assert!(manifest.conformance_suites.is_empty());
        assert_eq!(manifest.dialects.len(), 1);
        assert_eq!(manifest.dialects[0].id, dialect_id());
        assert_eq!(manifest.dialects[0].value_kinds.len(), 1);
        assert_eq!(
            manifest.dialects[0].value_kinds[0].id,
            file_tree_value_kind()
        );
    }
}
