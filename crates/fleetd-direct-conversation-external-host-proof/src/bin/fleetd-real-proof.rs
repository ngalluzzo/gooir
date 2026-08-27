//! Single-thread entrypoint for the ignored real Fleetd proof.
//!
//! Native-runtime qualification intentionally occurs outside libtest's worker
//! threads. The ignored integration test owns selection of explicit release
//! inputs and invokes this private proof coordinator as a subprocess.

#[cfg(target_os = "macos")]
#[path = "../../tests/fleetd_real.rs"]
mod proof;

#[cfg(target_os = "macos")]
fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    if arguments.next().as_deref() == Some(std::ffi::OsStr::new("--log-pump")) {
        proof::run_log_pump(arguments);
    } else {
        proof::run_child();
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("the real Fleetd native proof requires macOS");
    std::process::exit(1);
}
