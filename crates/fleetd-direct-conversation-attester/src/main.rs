//! FD3/stdin/stdout boundary for the Fleetd direct-conversation attester.

#![forbid(unsafe_code)]

use std::io::{self, Read as _, Write as _};

use fleetd_direct_conversation_attester::{
    AssessmentRequest, MAX_ASSESSMENT_REQUEST_BYTES, assess,
};
use fleetd_direct_conversation_command_abi::read_authority_from_fd3;

fn run() -> Result<(), ()> {
    let authority = read_authority_from_fd3().map_err(|_| ())?;
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_ASSESSMENT_REQUEST_BYTES + 1)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    if input.is_empty() || input.len() as u64 > MAX_ASSESSMENT_REQUEST_BYTES {
        return Err(());
    }
    let request: AssessmentRequest = serde_json::from_slice(&input).map_err(|_| ())?;
    request.validate().map_err(|_| ())?;
    let assessment = assess(&request, &authority).map_err(|_| ())?;
    let output = serde_json::to_vec(&assessment).map_err(|_| ())?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&output).map_err(|_| ())?;
    stdout.flush().map_err(|_| ())
}

fn main() {
    if run().is_err() {
        eprintln!("fleetd direct-conversation attester failed");
        std::process::exit(1);
    }
}
