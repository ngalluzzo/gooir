use std::io::{self, Read as _, Write as _};
use std::process::ExitCode;

use fleetd_direct_conversation_command_abi::read_authority_from_fd3;
use fleetd_direct_conversation_ureq_provider::invoke;
use gooir_capability::protocol::CapabilityInvocation;

const MAX_INVOCATION_BYTES: u64 = 1024 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Fleetd Ureq provider failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let authority = read_authority_from_fd3()?;
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_INVOCATION_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INVOCATION_BYTES {
        return Err("invocation exceeded the input limit".into());
    }
    let invocation: CapabilityInvocation = serde_json::from_slice(&bytes)?;
    let result = invoke(&invocation, &authority)?;
    let output = serde_json::to_vec(&result)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&output)?;
    stdout.flush()?;
    Ok(())
}
