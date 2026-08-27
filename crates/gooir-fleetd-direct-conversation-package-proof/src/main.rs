use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use gooir_fleetd_direct_conversation_package_proof::{StageRequest, stage, verify};

fn main() -> ExitCode {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    match run(&arguments) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("could not serialize proof report: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("{error}");
            eprintln!("{}", usage());
            ExitCode::FAILURE
        }
    }
}

fn run(
    arguments: &[std::ffi::OsString],
) -> Result<gooir_fleetd_direct_conversation_package_proof::ProofReport, String> {
    match arguments {
        [command, reqwest, ureq, attester, output] if command == "stage" => stage(StageRequest {
            reqwest_command: PathBuf::from(reqwest),
            ureq_command: PathBuf::from(ureq),
            attester_command: PathBuf::from(attester),
            output_root: PathBuf::from(output),
        })
        .map_err(|error| error.to_string()),
        [command, root] if command == "verify" => {
            verify(PathBuf::from(root)).map_err(|error| error.to_string())
        }
        _ => Err("invalid arguments".to_owned()),
    }
}

fn usage() -> &'static str {
    "usage:\n  gooir-fleetd-direct-conversation-package-proof stage <reqwest-command> <ureq-command> <attester-command> <fresh-output-root>\n  gooir-fleetd-direct-conversation-package-proof verify <staged-root>"
}
