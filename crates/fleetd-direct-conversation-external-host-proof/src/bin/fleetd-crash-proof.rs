//! Single-thread process entrypoints for the ignored Fleetd crash proof.

#[cfg(target_os = "macos")]
#[path = "../../tests/fleetd_real.rs"]
#[allow(dead_code)]
mod proof;

#[cfg(target_os = "macos")]
fn main() {
    proof::crash::dispatch();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("the real Fleetd crash proof requires macOS");
    std::process::exit(1);
}
