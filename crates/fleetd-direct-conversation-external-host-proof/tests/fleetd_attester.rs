//! Ignored real Fleetd attester operational-recovery and capacity proof.

#![cfg(target_os = "macos")]

use std::env;
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

#[test]
#[ignore = "requires freshly built release Fleetd/provider/attester paths; see fleetd_real docs"]
fn real_fleetd_attester_recovery_capacity_and_terminal_replay() {
    let coordinator = option_env!("CARGO_BIN_EXE_fleetd-attester-proof")
        .unwrap_or_else(|| panic!("Cargo did not provide the attester-proof coordinator binary"));
    let mut command = Command::new(coordinator);
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in [
        "GOOIR_FLEETD_REPO",
        "GOOIR_FLEETD_BINARY",
        "GOOIR_REQWEST_PROVIDER_BINARY",
        "GOOIR_UREQ_PROVIDER_BINARY",
        "GOOIR_DIRECT_CONVERSATION_ATTESTER_BINARY",
    ] {
        command.env(
            name,
            env::var_os(name)
                .unwrap_or_else(|| panic!("missing required ignored-proof environment variable")),
        );
    }
    let output = command
        .output()
        .unwrap_or_else(|_| panic!("attester-proof coordinator failed to execute"));
    assert!(
        output.status.success() && output.stdout.is_empty() && output.stderr.is_empty(),
        "attester-proof coordinator failed: code={:?}, stdout_len={}, stdout_digest=sha256:{:x}, stderr_len={}, stderr_digest=sha256:{:x}",
        output.status.code(),
        output.stdout.len(),
        Sha256::digest(&output.stdout),
        output.stderr.len(),
        Sha256::digest(&output.stderr),
    );
}
