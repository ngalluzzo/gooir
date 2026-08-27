//! Single-thread dispatcher for the distinct Host-Fleetd dogfood proof.

#[cfg(target_os = "macos")]
#[path = "../../tests/fleetd_real.rs"]
#[allow(dead_code)]
mod proof;

#[cfg(target_os = "macos")]
fn main() {
    proof::host::dispatch();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("the distinct Host-Fleetd proof requires macOS");
    std::process::exit(1);
}
