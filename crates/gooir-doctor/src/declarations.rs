//! A source-level check, distinct from the graph report on purpose.
//!
//! `Report` describes the registry a host has *installed*, and is useful
//! anywhere. This scans Rust source, so it is only meaningful inside a
//! checkout. It exists because the drift GOOIR detects between an application's
//! layers is the same drift a project like this grows in itself: one idea, two
//! implementations, discovered far too late.
//!
//! It is consumed by a test rather than printed. A printed warning that nobody
//! reads guards nothing.

use std::{
    fs,
    path::{Path, PathBuf},
};

/// What a scan of the workspace's Rust source found.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Declarations {
    /// Crates that implement the exact-identity rule, as `name (macro|struct)`.
    /// More than one means two spellings of one idea.
    pub identity_implementations: Vec<String>,
}

/// Scans a `crates/` directory.
///
/// Test scaffolding is excluded: fixtures deliberately share identities in
/// order to exercise the registry, and counting them would make the guard
/// permanently red for a reason that is not drift.
pub fn scan(crates_dir: &Path) -> Declarations {
    let mut found = Declarations::default();

    let mut stack = vec![crates_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            let crate_name = crate_of(&path);

            // The needles are assembled from fragments so that this file's own
            // source does not match them. A tool that scans source must not
            // count itself — an earlier version did.
            let macro_needle = concat!("macro_rules!", " exact_identity");
            let legacy_needle = concat!("macro_rules!", " exact_id ");
            let declares_macro = text.contains(macro_needle) || text.contains(legacy_needle);
            let declares_struct = text.contains(concat!("pub ", "package: String"))
                && text.contains(concat!("pub ", "name: String"))
                && text.contains(concat!("pub ", "version: String"))
                && !declares_macro;
            if declares_macro || declares_struct {
                found.identity_implementations.push(format!(
                    "{crate_name} ({})",
                    if declares_macro { "macro" } else { "struct" }
                ));
            }
        }
    }

    found.identity_implementations.sort();
    found.identity_implementations.dedup();
    found
}

/// The workspace's `crates/` directory, from this crate's location.
pub fn workspace_crates() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("a crate lives two levels below the workspace root")
        .join("crates")
}

fn crate_of(path: &Path) -> String {
    path.components()
        .rev()
        .find_map(|c| {
            let s = c.as_os_str().to_string_lossy().into_owned();
            (s != "src" && s != "tests" && !s.ends_with(".rs")).then_some(s)
        })
        .unwrap_or_default()
}
