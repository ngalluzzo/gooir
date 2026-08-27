//! Credential-free JSON process boundary for the neutral author-data-model
//! provider.

use std::io::{self, Read};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("author-data-model provider refused invocation: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    gooir_datamodel_pack::neutral::invoke_json(&input).map_err(Into::into)
}
