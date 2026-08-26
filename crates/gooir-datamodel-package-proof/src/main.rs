use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use gooir_datamodel_package_proof::{StageRequest, stage, verify};

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
) -> Result<gooir_datamodel_package_proof::ProofReport, String> {
    match arguments {
        [command, provider, attester, output] if command == "stage" => stage(StageRequest {
            provider_module: PathBuf::from(provider),
            attester_module: PathBuf::from(attester),
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
    "usage:\n  gooir-datamodel-package-proof stage <provider-wasip1-module> <attester-wasip1-module> <fresh-output-root>\n  gooir-datamodel-package-proof verify <staged-root>"
}
