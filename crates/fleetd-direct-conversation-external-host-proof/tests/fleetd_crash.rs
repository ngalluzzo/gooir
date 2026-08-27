//! Ignored real Fleetd commit-before-response crash/reexec proof.
//!
//! Build exact inputs before running:
//!
//!     cd "$FLEETD_REPO"
//!     cargo build --release --locked --bin fleetd
//!     cd "$GOOIR_REPO"
//!     cargo build --release --locked \
//!       -p fleetd-direct-conversation-reqwest-provider \
//!       -p fleetd-direct-conversation-ureq-provider \
//!       -p fleetd-direct-conversation-attester
//!     GOOIR_FLEETD_REPO="$FLEETD_REPO" \
//!     GOOIR_FLEETD_BINARY="$FLEETD_REPO/target/release/fleetd" \
//!     GOOIR_REQWEST_PROVIDER_BINARY="$GOOIR_REPO/target/release/fleetd-direct-conversation-reqwest-provider" \
//!     GOOIR_UREQ_PROVIDER_BINARY="$GOOIR_REPO/target/release/fleetd-direct-conversation-ureq-provider" \
//!     GOOIR_DIRECT_CONVERSATION_ATTESTER_BINARY="$GOOIR_REPO/target/release/fleetd-direct-conversation-attester" \
//!     cargo test --release -p fleetd-direct-conversation-external-host-proof \
//!       --test fleetd_crash -- --ignored --exact \
//!       real_fleetd_commit_before_response_recovers_exactly
//!
//! The proxy binds only loopback, retains only request-body length/digest and
//! response status/body-length/body-digest diagnostics, never forwards the first
//! complete backend `201`, and terminates the first proof host before closing
//! that client connection.

#![cfg(target_os = "macos")]

use std::env;
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

#[test]
#[ignore = "requires freshly built release Fleetd/provider/attester paths; see fleetd_real docs"]
fn real_fleetd_commit_before_response_recovers_exactly() {
    let coordinator = option_env!("CARGO_BIN_EXE_fleetd-crash-proof")
        .unwrap_or_else(|| panic!("Cargo did not provide the crash-proof coordinator binary"));
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
        .unwrap_or_else(|_| panic!("crash-proof coordinator failed to execute"));
    assert!(
        output.status.success() && output.stdout.is_empty() && output.stderr.is_empty(),
        "crash-proof coordinator failed: code={:?}, stdout_len={}, stdout_digest=sha256:{:x}, stderr_len={}, stderr_digest=sha256:{:x}",
        output.status.code(),
        output.stdout.len(),
        Sha256::digest(&output.stdout),
        output.stderr.len(),
        Sha256::digest(&output.stderr),
    );
}
