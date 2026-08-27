//! Single-thread process entrypoints for the ignored Fleetd attester proof.

#[cfg(target_os = "macos")]
#[path = "../../tests/fleetd_real.rs"]
#[allow(dead_code)]
mod proof;

#[cfg(target_os = "macos")]
fn main() {
    proof::attester::dispatch();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("the real Fleetd attester proof requires macOS");
    std::process::exit(1);
}
