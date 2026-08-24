use std::{env, fs, path::Path, process};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let source_root = arguments.next().ok_or_else(usage)?;
    let protocol_lift_path = arguments.next().ok_or_else(usage)?;
    let authority = arguments.next().ok_or_else(usage)?;
    let revision = arguments.next().ok_or_else(usage)?;
    if arguments.next().is_some() {
        return Err(usage());
    }

    let source_root = Path::new(&source_root);
    let workspace_manifest = read_source(source_root, "Cargo.toml")?;
    let workspace_lock = read_source(source_root, "Cargo.lock")?;
    let cargo_config = read_source(source_root, ".cargo/config.toml")?;
    let relay_manifest = read_source(source_root, "crates/buzz-relay/Cargo.toml")?;
    let relay_crate_root = read_source(source_root, "crates/buzz-relay/src/lib.rs")?;
    let relay_handlers_module = read_source(source_root, "crates/buzz-relay/src/handlers/mod.rs")?;
    let ingest_source = read_source(source_root, "crates/buzz-relay/src/handlers/ingest.rs")?;
    let push_lease_source =
        read_source(source_root, "crates/buzz-relay/src/handlers/push_lease.rs")?;
    let core_manifest = read_source(source_root, "crates/buzz-core/Cargo.toml")?;
    let core_crate_root = read_source(source_root, "crates/buzz-core/src/lib.rs")?;
    let kind_source = read_source(source_root, "crates/buzz-core/src/kind.rs")?;
    let layouts = buzz_relay_lifter::RelayModuleLayouts {
        relay_handlers_file_layout: source_exists(source_root, "crates/buzz-relay/src/handlers.rs"),
        relay_handlers_dir_layout: true,
        ingest_file_layout: true,
        ingest_dir_layout: source_exists(
            source_root,
            "crates/buzz-relay/src/handlers/ingest/mod.rs",
        ),
        push_lease_file_layout: true,
        push_lease_dir_layout: source_exists(
            source_root,
            "crates/buzz-relay/src/handlers/push_lease/mod.rs",
        ),
        core_kind_file_layout: true,
        core_kind_dir_layout: source_exists(source_root, "crates/buzz-core/src/kind/mod.rs"),
    };
    let protocol_lift: buzz_protocol_lifter::ProtocolLift = serde_json::from_slice(
        &fs::read(&protocol_lift_path)
            .map_err(|error| format!("failed to read {protocol_lift_path}: {error}"))?,
    )
    .map_err(|error| format!("failed to parse {protocol_lift_path}: {error}"))?;

    let lift = buzz_relay_lifter::lift_relay_ingest(
        buzz_relay_lifter::RelayInputs {
            semantic: buzz_relay_lifter::RelaySemanticSources {
                ingest: &ingest_source,
                kind: &kind_source,
                push_lease: &push_lease_source,
            },
            compilation: buzz_relay_lifter::RelayCompilationSources {
                workspace_manifest: &workspace_manifest,
                workspace_lock: &workspace_lock,
                cargo_config: &cargo_config,
                relay_manifest: &relay_manifest,
                relay_crate_root: &relay_crate_root,
                relay_handlers_module: &relay_handlers_module,
                core_manifest: &core_manifest,
                core_crate_root: &core_crate_root,
                layouts,
            },
        },
        &protocol_lift,
        authority,
        revision,
    )
    .map_err(|error| format!("failed to lift relay package: {error}"))?;
    let output = serde_json::to_string_pretty(&lift)
        .map_err(|error| format!("failed to serialize lift: {error}"))?;
    println!("{output}");
    Ok(())
}

fn usage() -> String {
    "usage: buzz-relay-lifter <source-root> <protocol-lift-json> <authority> <revision>".to_owned()
}

fn read_source(root: &Path, relative: &str) -> Result<String, String> {
    let path = root.join(relative);
    fs::read_to_string(&path).map_err(|error| format!("failed to read {}: {error}", path.display()))
}

fn source_exists(root: &Path, relative: &str) -> bool {
    root.join(relative).exists()
}
