use std::{env, fs, process};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let source_path = arguments.next().ok_or_else(usage)?;
    let artifact = arguments.next().ok_or_else(usage)?;
    let authority = arguments.next().ok_or_else(usage)?;
    let revision = arguments.next().ok_or_else(usage)?;
    if arguments.next().is_some() {
        return Err(usage());
    }

    let source = fs::read_to_string(&source_path)
        .map_err(|error| format!("failed to read {source_path}: {error}"))?;
    let lift = buzz_cli_lifter::lift_command_tree(&source, authority, artifact, revision)
        .map_err(|error| format!("failed to lift {source_path}: {error}"))?;
    let output = serde_json::to_string_pretty(&lift)
        .map_err(|error| format!("failed to serialize lift: {error}"))?;
    println!("{output}");
    Ok(())
}

fn usage() -> String {
    "usage: buzz-cli-lifter <source-path> <artifact-id> <authority> <revision>".to_owned()
}
