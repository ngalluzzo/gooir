//! Test-only native command exercised through package qualification.

use std::fs;
use std::io::{Read, Write};
use std::process::Command;
use std::thread;
use std::time::Duration;

use fleetd_direct_conversation_command_abi::read_authority_from_fd3;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    mode: String,
    #[serde(default)]
    bytes: usize,
    #[serde(default)]
    probe_fd: i32,
    marker_path: Option<String>,
}

fn main() {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "descendant")
    {
        thread::sleep(Duration::from_millis(700));
        if let Some(path) = arguments.get(2) {
            let _ = fs::write(path, b"descendant survived");
        }
        return;
    }

    let authority = read_authority_from_fd3().expect("bounded authority on fd 3");
    let mut stdin = Vec::new();
    std::io::stdin()
        .read_to_end(&mut stdin)
        .expect("bounded stdin");
    let request: Request = serde_json::from_slice(&stdin).expect("fixture request");
    match request.mode.as_str() {
        "basic" => {
            let cwd_empty = fs::read_dir(".").expect("fixture cwd").next().is_none();
            let probe_open = FileProbe::new(request.probe_fd).is_open();
            let extra_open_fds = (4..256)
                .filter(|fd| FileProbe::new(*fd).is_open())
                .collect::<Vec<_>>();
            let output = json!({
                "argv": arguments.iter().map(|value| value.to_string_lossy()).collect::<Vec<_>>(),
                "cwd_empty": cwd_empty,
                "environment_count": std::env::vars_os().count(),
                "extra_open_fds": extra_open_fds,
                "probe_open": probe_open,
                "stdin_len": stdin.len(),
                "stdin_digest": format!("sha256:{:x}", Sha256::digest(&stdin)),
                "target": authority.target(),
            });
            serde_json::to_writer(std::io::stdout().lock(), &output).expect("fixture output");
        }
        "stdout_overflow" => {
            std::io::stdout()
                .write_all(&vec![b'o'; request.bytes])
                .expect("stdout overflow fixture");
        }
        "stderr_overflow" => {
            std::io::stderr()
                .write_all(&vec![b'e'; request.bytes])
                .expect("stderr overflow fixture");
        }
        "secret" => {
            let encoded = authority.encode_for_pipe().expect("authority encoding");
            let token = authority.bearer_token().expose_secret().as_bytes();
            let endpoint = authority.endpoint().as_bytes();
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&encoded).expect("authority echo");
            stdout.write_all(endpoint).expect("endpoint echo");
            stdout.write_all(token).expect("token echo");
            let mut stderr = std::io::stderr().lock();
            stderr.write_all(token).expect("stderr token echo");
            stderr.write_all(endpoint).expect("stderr endpoint echo");
        }
        "nonzero" => std::process::exit(23),
        "timeout_group" => {
            let marker = request.marker_path.expect("marker path");
            spawn_lingering_descendant(&marker);
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }
        "exit_with_descendant" => {
            let marker = request.marker_path.expect("marker path");
            spawn_lingering_descendant(&marker);
        }
        _ => panic!("unknown fixture mode"),
    }
}

// This fixture deliberately drops the child handle so the supervisor must
// clean a process-group descendant after the direct fixture exits.
#[allow(clippy::zombie_processes)]
fn spawn_lingering_descendant(marker: &str) {
    Command::new(std::env::current_exe().expect("fixture executable"))
        .arg("descendant")
        .arg(marker)
        .spawn()
        .expect("spawn descendant");
}

struct FileProbe(String);

impl FileProbe {
    fn new(fd: i32) -> Self {
        Self(format!("/dev/fd/{fd}"))
    }

    fn is_open(&self) -> bool {
        fs::File::open(&self.0).is_ok()
    }
}
