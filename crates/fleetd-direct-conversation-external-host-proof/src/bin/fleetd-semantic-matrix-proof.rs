//! Single-thread process entrypoints for the ignored Fleetd semantic matrix.

#[cfg(target_os = "macos")]
#[path = "../../tests/fleetd_real.rs"]
#[allow(dead_code)]
mod proof;

#[cfg(target_os = "macos")]
fn main() {
    proof::semantic_matrix::dispatch();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("the real Fleetd semantic matrix requires macOS");
    std::process::exit(1);
}
