//! Ignored real Fleetd semantic and convergence matrix.
//!
//! Build the exact Fleetd, provider, and attester release binaries documented
//! by `fleetd_real`, export those five paths, then run:
//!
//!     cargo test --release -p fleetd-direct-conversation-external-host-proof \
//!       --test fleetd_semantic_matrix -- --ignored --exact \
//!       real_fleetd_concurrent_conflict_and_withholding_matrix

#![cfg(target_os = "macos")]

use std::collections::HashSet;
use std::env;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, kill_process_group, test_kill_process};

const PROCESS_OBSERVATION_BOUND: usize = 1024 * 1024;
const PROCESS_EXIT_DEADLINE: Duration = Duration::from_secs(15);

#[test]
#[ignore = "requires freshly built release Fleetd/provider/attester paths; see fleetd_real docs"]
fn real_fleetd_concurrent_conflict_and_withholding_matrix() {
    let coordinator = option_env!("CARGO_BIN_EXE_fleetd-semantic-matrix-proof")
        .unwrap_or_else(|| panic!("Cargo did not provide the semantic-matrix coordinator binary"));
    let mut command = Command::new(coordinator);
    command
        .env_clear()
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
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
    let raw_child = command
        .spawn()
        .unwrap_or_else(|_| panic!("semantic-matrix coordinator failed to execute"));
    let mut child = ManagedCoordinator::new(raw_child);
    let status = child.wait_bounded(Duration::from_mins(4));
    assert!(
        status.success(),
        "semantic-matrix coordinator failed: code={:?}",
        status.code(),
    );
}

struct ManagedCoordinator {
    child: Child,
    group: Pid,
    reaped: bool,
}

impl ManagedCoordinator {
    fn new(child: Child) -> Self {
        let group = i32::try_from(child.id())
            .ok()
            .and_then(Pid::from_raw)
            .unwrap_or_else(|| panic!("semantic-matrix coordinator PID was invalid"));
        Self {
            child,
            group,
            reaped: false,
        }
    }

    fn wait_bounded(&mut self, duration: Duration) -> ExitStatus {
        let deadline = Instant::now() + duration;
        loop {
            if let Some(status) = self
                .child
                .try_wait()
                .unwrap_or_else(|_| panic!("semantic-matrix coordinator observation failed"))
            {
                self.reaped = true;
                return status;
            }
            if Instant::now() >= deadline {
                self.terminate();
                panic!("semantic-matrix coordinator deadline expired");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn terminate(&mut self) {
        if self.reaped {
            return;
        }
        self.contain_and_reap()
            .unwrap_or_else(|()| panic!("semantic-matrix process-tree cleanup failed"));
    }

    fn contain_and_reap(&mut self) -> Result<(), ()> {
        signal_group(self.group, Signal::STOP)?;
        let first = descendant_processes(self.child.id())?;
        for group in process_groups(self.group, &first)? {
            signal_group(group, Signal::STOP)?;
        }
        let mut observed = descendant_processes(self.child.id())?;
        observed.extend(first);
        observed.sort_unstable_by_key(|process| process.pid);
        observed.dedup_by_key(|process| process.pid);
        let groups = process_groups(self.group, &observed)?;
        for group in groups.iter().copied().filter(|group| *group != self.group) {
            signal_group(group, Signal::KILL)?;
        }
        signal_group(self.group, Signal::KILL)?;
        self.child.wait().map_err(|_| ())?;
        self.reaped = true;
        wait_for_processes_to_disappear(&observed)?;
        Ok(())
    }
}

impl Drop for ManagedCoordinator {
    fn drop(&mut self) {
        if !self.reaped && self.contain_and_reap().is_err() {
            let _ignored = kill_process_group(self.group, Signal::KILL);
            let _ignored = self.child.wait();
            self.reaped = true;
        }
    }
}

#[derive(Clone, Copy)]
struct ObservedProcess {
    pid: u32,
    parent: u32,
    group: u32,
}

fn descendant_processes(root: u32) -> Result<Vec<ObservedProcess>, ()> {
    let output = Command::new("/bin/ps")
        .env_clear()
        .args(["-axo", "pid=,ppid=,pgid="])
        .stdin(Stdio::null())
        .output()
        .map_err(|_| ())?;
    if !output.status.success() || output.stdout.len() > PROCESS_OBSERVATION_BOUND {
        return Err(());
    }
    let table = std::str::from_utf8(&output.stdout).map_err(|_| ())?;
    let processes = table
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let process = ObservedProcess {
                pid: fields.next()?.parse().ok()?,
                parent: fields.next()?.parse().ok()?,
                group: fields.next()?.parse().ok()?,
            };
            fields.next().is_none().then_some(process)
        })
        .collect::<Vec<_>>();
    let mut descendants = HashSet::from([root]);
    loop {
        let prior = descendants.len();
        for process in &processes {
            if descendants.contains(&process.parent) {
                descendants.insert(process.pid);
            }
        }
        if descendants.len() == prior {
            break;
        }
    }
    Ok(processes
        .into_iter()
        .filter(|process| process.pid != root && descendants.contains(&process.pid))
        .collect())
}

fn process_groups(root: Pid, processes: &[ObservedProcess]) -> Result<HashSet<Pid>, ()> {
    let mut groups = HashSet::from([root]);
    for process in processes {
        groups.insert(
            i32::try_from(process.group)
                .ok()
                .and_then(Pid::from_raw)
                .ok_or(())?,
        );
    }
    Ok(groups)
}

fn signal_group(group: Pid, signal: Signal) -> Result<(), ()> {
    match kill_process_group(group, signal) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(_) => Err(()),
    }
}

fn wait_for_processes_to_disappear(processes: &[ObservedProcess]) -> Result<(), ()> {
    let deadline = Instant::now() + PROCESS_EXIT_DEADLINE;
    for process in processes {
        let pid = i32::try_from(process.pid)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or(())?;
        loop {
            match test_kill_process(pid) {
                Err(rustix::io::Errno::SRCH) => break,
                Ok(()) | Err(rustix::io::Errno::PERM) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                _ => return Err(()),
            }
        }
    }
    Ok(())
}
