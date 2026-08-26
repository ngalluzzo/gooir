#![forbid(unsafe_code)]

use std::error::Error;
use std::io::{self, Read, Write};

use fleetd_direct_conversation_command_abi::read_authority_from_fd3;
use fleetd_direct_conversation_reqwest_provider::execute;
use gooir_capability::protocol::CapabilityInvocation;

const MAX_INVOCATION_BYTES: u64 = 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        let _ = writeln!(io::stderr().lock(), "provider failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let authority = read_authority_from_fd3()?;
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_INVOCATION_BYTES + 1)
        .read_to_end(&mut input)?;
    if u64::try_from(input.len()).map_or(true, |length| length > MAX_INVOCATION_BYTES) {
        return Err("invocation exceeded the input limit".into());
    }
    let invocation: CapabilityInvocation = serde_json::from_slice(&input)?;
    let result = execute(&invocation, &authority)?;
    let output = serde_json::to_vec(&result)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&output)?;
    stdout.flush()?;
    Ok(())
}
