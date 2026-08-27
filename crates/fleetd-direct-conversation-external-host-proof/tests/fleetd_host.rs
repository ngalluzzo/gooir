//! Ignored optimized proof of a distinct opaque Host Fleetd coordinating a
//! credential-owning GOOIR runner against a separate Target Fleetd.

#![cfg(target_os = "macos")]

#[test]
#[ignore = "requires freshly built release Fleetd/provider/attester paths; see fleetd_real docs"]
fn distinct_host_fleetd_coordinates_recoverable_target_attempt() {
    let coordinator = option_env!("CARGO_BIN_EXE_fleetd-host-proof")
        .unwrap_or_else(|| panic!("Cargo did not provide the host-proof coordinator binary"));
    let mut command = std::process::Command::new(coordinator);
    command
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for name in [
        "GOOIR_FLEETD_REPO",
        "GOOIR_FLEETD_BINARY",
        "GOOIR_REQWEST_PROVIDER_BINARY",
        "GOOIR_UREQ_PROVIDER_BINARY",
        "GOOIR_DIRECT_CONVERSATION_ATTESTER_BINARY",
    ] {
        command.env(
            name,
            std::env::var_os(name)
                .unwrap_or_else(|| panic!("missing required ignored-proof environment variable")),
        );
    }
    let output = command
        .output()
        .unwrap_or_else(|_| panic!("single-thread host-proof coordinator failed to execute"));
    assert!(
        output.status.success() && output.stdout.is_empty() && output.stderr.is_empty(),
        "single-thread host-proof coordinator failed: code={:?}, stdout_len={}, stderr_len={}",
        output.status.code(),
        output.stdout.len(),
        output.stderr.len(),
    );
}
