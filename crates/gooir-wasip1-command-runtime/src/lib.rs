//! Bounded execution of one exact, credential-free `WASIp1` command module.
//!
//! Wasmtime, rather than proof-local process code, owns code isolation,
//! termination, and guest resource accounting. The guest receives exact stdin,
//! bounded stdout/stderr, no arguments, no environment, no preopened files,
//! and no network authority. This module deliberately knows nothing about
//! packages, capabilities, or the meaning of the byte streams.
//!
//! Compilation, linking, and instantiation are synchronous preparation work.
//! They are bounded by the module/profile ceilings but not by the guest epoch
//! deadline, so this boundary is for operator-selected installed modules—not
//! an unauthenticated arbitrary-module upload service.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasmparser::{Encoding, Parser, Payload, TypeRef};
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, TypedFunc};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};

/// Exact command-profile and trusted implementation identity. Persisted
/// qualifications and receipts bind evidence to this complete boundary rather
/// than to a host PID or platform wait-status encoding.
pub const RUNTIME_ID: &str = concat!(
    "org.gooi.runtime.wasip1-command-profile@1/",
    "wasmtime=48.0.1/wasmtime-wasi=48.0.1/wasmparser=0.254.0"
);

pub const MAX_MODULE_BYTES: usize = 64 * 1024 * 1024;
const MAX_STDIN_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CAPTURE_BYTES: usize = 256 * 1024;
/// Largest exactly representable integer in the journal's I-JSON domain.
pub const MAX_FUEL: u64 = (1_u64 << 53) - 1;
const MAX_MEMORY_BYTES: usize = 1024 * 1024 * 1024;
const MAX_TABLE_ELEMENTS: usize = 1_000_000;
const MAX_TIMEOUT: Duration = Duration::from_mins(5);

/// Explicit resource limits for one `WASIp1` command invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WasmLimits {
    pub timeout: Duration,
    pub fuel: u64,
    pub memory_bytes: usize,
    pub table_elements: usize,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
}

/// Platform-stable wire identity of the exact per-invocation limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmExecutionPolicy {
    pub timeout_nanoseconds: u64,
    pub fuel: u64,
    pub memory_bytes: u64,
    pub table_elements: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

/// Exact evidence that one module compiled, linked, and instantiated under the
/// complete command profile without starting the guest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmModuleQualification {
    pub runtime: String,
    pub module_digest: String,
}

impl WasmLimits {
    fn validate(self) -> Result<(), WasmError> {
        if self.timeout.is_zero()
            || self.timeout > MAX_TIMEOUT
            || self.fuel == 0
            || self.fuel > MAX_FUEL
            || self.memory_bytes == 0
            || self.memory_bytes > MAX_MEMORY_BYTES
            || self.table_elements == 0
            || self.table_elements > MAX_TABLE_ELEMENTS
            || self.stdout_bytes == 0
            || self.stdout_bytes > MAX_CAPTURE_BYTES
            || self.stderr_bytes == 0
            || self.stderr_bytes > MAX_CAPTURE_BYTES
        {
            return Err(WasmError::InvalidLimits);
        }
        Ok(())
    }

    /// Convert caller limits to their exact platform-stable receipt identity.
    ///
    /// # Errors
    ///
    /// Refuses limits outside the closed command profile.
    pub fn execution_policy(self) -> Result<WasmExecutionPolicy, WasmError> {
        self.validate()?;
        Ok(WasmExecutionPolicy {
            timeout_nanoseconds: u64::try_from(self.timeout.as_nanos())
                .map_err(|_| WasmError::InvalidLimits)?,
            fuel: self.fuel,
            memory_bytes: u64::try_from(self.memory_bytes).map_err(|_| WasmError::InvalidLimits)?,
            table_elements: u64::try_from(self.table_elements)
                .map_err(|_| WasmError::InvalidLimits)?,
            stdout_bytes: u64::try_from(self.stdout_bytes).map_err(|_| WasmError::InvalidLimits)?,
            stderr_bytes: u64::try_from(self.stderr_bytes).map_err(|_| WasmError::InvalidLimits)?,
        })
    }
}

/// Exact module and stdin bytes for one isolated invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmRequest {
    pub module: Vec<u8>,
    pub stdin: Vec<u8>,
    pub limits: WasmLimits,
}

impl WasmRequest {
    fn validate(&self) -> Result<(), WasmError> {
        self.limits.validate()?;
        validate_module_length(self.module.len())?;
        if self.stdin.len() > MAX_STDIN_BYTES {
            return Err(WasmError::InvalidRequest("stdin exceeds the proof bound"));
        }
        Ok(())
    }
}

fn validate_module_length(length: usize) -> Result<(), WasmError> {
    if length == 0 || length > MAX_MODULE_BYTES {
        return Err(WasmError::InvalidRequest(
            "module length is outside the profile bound",
        ));
    }
    Ok(())
}

/// Closed observable completion class.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WasmTermination {
    Returned,
    GuestExit {
        code: i32,
    },
    Enforced {
        timed_out: bool,
        fuel_exhausted: bool,
        stdout_limit_reached: bool,
        stderr_limit_reached: bool,
    },
    Trapped,
}

/// Content-bounded evidence returned by Wasmtime.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmReceipt {
    pub runtime: String,
    pub execution_policy: WasmExecutionPolicy,
    pub module_digest: String,
    pub stdin_digest: String,
    pub termination: WasmTermination,
    pub stdin_bytes_provided: u64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl WasmReceipt {
    /// Revalidates recovered receipt structure against the exact invocation.
    ///
    /// # Errors
    ///
    /// Refuses runtime substitution, changed stdin identity, output beyond the
    /// declared limits, or a completion class inconsistent with bounded output.
    pub fn validate_against(&self, request: &WasmRequest) -> Result<(), WasmError> {
        request.validate()?;
        if self.runtime != RUNTIME_ID {
            return Err(WasmError::InvalidReceipt("runtime identity changed"));
        }
        if self.execution_policy != request.limits.execution_policy()? {
            return Err(WasmError::InvalidReceipt("execution policy changed"));
        }
        if self.module_digest != sha256_identity(&request.module) {
            return Err(WasmError::InvalidReceipt("module identity changed"));
        }
        if self.stdin_digest != sha256_identity(&request.stdin) {
            return Err(WasmError::InvalidReceipt("stdin identity changed"));
        }
        if self.stdin_bytes_provided
            != u64::try_from(request.stdin.len()).map_err(|_| {
                WasmError::InvalidRequest("stdin length cannot be represented in a receipt")
            })?
        {
            return Err(WasmError::InvalidReceipt("stdin length changed"));
        }
        if self.stdout.len() > request.limits.stdout_bytes
            || self.stderr.len() > request.limits.stderr_bytes
        {
            return Err(WasmError::InvalidReceipt("captured output exceeds limits"));
        }
        match self.termination {
            WasmTermination::Returned => {
                if self.stdout.len() == request.limits.stdout_bytes
                    || self.stderr.len() == request.limits.stderr_bytes
                {
                    return Err(WasmError::InvalidReceipt(
                        "returned receipt reached an output bound",
                    ));
                }
            }
            WasmTermination::GuestExit { code } => {
                if !(0..126).contains(&code) {
                    return Err(WasmError::InvalidReceipt(
                        "guest exit code is outside the pinned WASI implementation range",
                    ));
                }
                if self.stdout.len() == request.limits.stdout_bytes
                    || self.stderr.len() == request.limits.stderr_bytes
                {
                    return Err(WasmError::InvalidReceipt(
                        "guest-exit receipt reached an output bound",
                    ));
                }
            }
            WasmTermination::Enforced {
                timed_out,
                fuel_exhausted,
                stdout_limit_reached,
                stderr_limit_reached,
            } => {
                if !(timed_out || fuel_exhausted || stdout_limit_reached || stderr_limit_reached) {
                    return Err(WasmError::InvalidReceipt(
                        "enforced receipt names no enforcement cause",
                    ));
                }
                if stdout_limit_reached != (self.stdout.len() == request.limits.stdout_bytes)
                    || stderr_limit_reached != (self.stderr.len() == request.limits.stderr_bytes)
                {
                    return Err(WasmError::InvalidReceipt(
                        "output-limit evidence disagrees with captured bounds",
                    ));
                }
            }
            WasmTermination::Trapped => {
                if self.stdout.len() == request.limits.stdout_bytes
                    || self.stderr.len() == request.limits.stderr_bytes
                {
                    return Err(WasmError::InvalidReceipt(
                        "trapped receipt reached an output bound",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Whether the command returned normally with no stderr evidence.
    #[must_use]
    pub fn is_clean_success(&self) -> bool {
        matches!(
            self.termination,
            WasmTermination::Returned | WasmTermination::GuestExit { code: 0 }
        ) && self.stderr.is_empty()
    }
}

/// Failures for which no trustworthy guest receipt can be produced.
#[derive(Debug)]
pub enum WasmError {
    InvalidLimits,
    InvalidRequest(&'static str),
    Compile(String),
    ForbiddenAuthority(String),
    Link(String),
    Configure(String),
    SpawnWatchdog(std::io::Error),
    InvalidReceipt(&'static str),
}

impl fmt::Display for WasmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("WASIp1 limits must all be nonzero"),
            Self::InvalidRequest(detail) => write!(formatter, "invalid WASIp1 request: {detail}"),
            Self::Compile(error) => write!(formatter, "could not compile WASIp1 module: {error}"),
            Self::ForbiddenAuthority(detail) => {
                write!(
                    formatter,
                    "WASIp1 module exceeds its authority profile: {detail}"
                )
            }
            Self::Link(error) => write!(formatter, "could not link WASIp1 module: {error}"),
            Self::Configure(error) => {
                write!(formatter, "could not configure WASIp1 execution: {error}")
            }
            Self::SpawnWatchdog(error) => write!(formatter, "could not start deadline: {error}"),
            Self::InvalidReceipt(detail) => write!(formatter, "invalid WASIp1 receipt: {detail}"),
        }
    }
}

impl Error for WasmError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SpawnWatchdog(error) => Some(error),
            Self::InvalidLimits
            | Self::InvalidRequest(_)
            | Self::Compile(_)
            | Self::ForbiddenAuthority(_)
            | Self::Link(_)
            | Self::Configure(_)
            | Self::InvalidReceipt(_) => None,
        }
    }
}

struct HostState {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

struct PreparedWatchdog {
    started: Arc<OnceLock<Instant>>,
    cancelled: Arc<AtomicBool>,
    timed_out: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl PreparedWatchdog {
    fn new(engine: Engine, timeout: Duration) -> Result<Self, WasmError> {
        let started = Arc::new(OnceLock::new());
        let cancelled = Arc::new(AtomicBool::new(false));
        let timed_out = Arc::new(AtomicBool::new(false));
        let thread_started = Arc::clone(&started);
        let thread_cancelled = Arc::clone(&cancelled);
        let thread_timed_out = Arc::clone(&timed_out);
        let handle = thread::Builder::new()
            .name("gooir-wasmtime-deadline".to_owned())
            .spawn(move || {
                let started = loop {
                    if thread_cancelled.load(Ordering::Acquire) {
                        return;
                    }
                    if let Some(started) = thread_started.get().copied() {
                        break started;
                    }
                    thread::park();
                };
                let deadline = started + timeout;
                loop {
                    if thread_cancelled.load(Ordering::Acquire) {
                        return;
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        thread_timed_out.store(true, Ordering::Release);
                        engine.increment_epoch();
                        return;
                    }
                    thread::park_timeout(deadline - now);
                }
            })
            .map_err(WasmError::SpawnWatchdog)?;
        Ok(Self {
            started,
            cancelled,
            timed_out,
            handle: Some(handle),
        })
    }

    fn start(&self, started: Instant) {
        let first_start = self.started.set(started).is_ok();
        debug_assert!(first_start, "prepared invocation starts at most once");
        if let Some(handle) = &self.handle {
            handle.thread().unpark();
        }
    }

    fn finish(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            handle.thread().unpark();
            let _ignored = handle.join();
        }
    }

    fn timed_out(&self) -> bool {
        self.timed_out.load(Ordering::Acquire)
    }
}

impl Drop for PreparedWatchdog {
    fn drop(&mut self) {
        self.finish();
    }
}

/// A fully compiled, linked, and instantiated command that has not started.
///
/// The execution host constructs this before durably arming an effect. After
/// arming it performs exactly one consuming [`Self::execute`] call.
pub struct PreparedWasmInvocation {
    store: Store<HostState>,
    start: TypedFunc<(), ()>,
    stdout: MemoryOutputPipe,
    stderr: MemoryOutputPipe,
    limits: WasmLimits,
    execution_policy: WasmExecutionPolicy,
    module_digest: String,
    stdin_digest: String,
    stdin_bytes_provided: u64,
    watchdog: PreparedWatchdog,
}

/// Compile, link, and instantiate one exact credential-free `WASIp1` command
/// without starting `_start`.
///
/// # Errors
///
/// Returns an error only when the host cannot validate limits, compile, link,
/// or configure the exact module.
pub fn prepare(request: &WasmRequest) -> Result<PreparedWasmInvocation, WasmError> {
    request.validate()?;
    let execution_policy = request.limits.execution_policy()?;
    validate_authority_surface(&request.module)?;

    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    let engine = Engine::new(&config).map_err(|error| WasmError::Configure(error.to_string()))?;
    let module = Module::new(&engine, &request.module)
        .map_err(|error| WasmError::Compile(error.to_string()))?;

    let stdin = MemoryInputPipe::new(request.stdin.clone());
    let stdout = MemoryOutputPipe::new(request.limits.stdout_bytes);
    let stderr = MemoryOutputPipe::new(request.limits.stderr_bytes);
    let wasi = WasiCtxBuilder::new()
        .stdin(stdin)
        .stdout(stdout.clone())
        .stderr(stderr.clone())
        .build_p1();
    let limits = StoreLimitsBuilder::new()
        .memory_size(request.limits.memory_bytes)
        .table_elements(request.limits.table_elements)
        .instances(1)
        .memories(1)
        .tables(1)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(&engine, HostState { wasi, limits });
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(request.limits.fuel)
        .map_err(|error| WasmError::Configure(error.to_string()))?;
    store.set_epoch_deadline(1);
    store.epoch_deadline_trap();

    let mut linker = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |state: &mut HostState| &mut state.wasi)
        .map_err(|error| WasmError::Link(error.to_string()))?;
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|error| WasmError::Link(error.to_string()))?;
    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .map_err(|error| WasmError::Link(error.to_string()))?;
    let stdin_bytes_provided = u64::try_from(request.stdin.len()).map_err(|_| {
        WasmError::InvalidRequest("stdin length cannot be represented in a receipt")
    })?;
    let watchdog = PreparedWatchdog::new(engine, request.limits.timeout)?;

    Ok(PreparedWasmInvocation {
        store,
        start,
        stdout,
        stderr,
        limits: request.limits,
        execution_policy,
        module_digest: sha256_identity(&request.module),
        stdin_digest: sha256_identity(&request.stdin),
        stdin_bytes_provided,
        watchdog,
    })
}

/// Compile, link, and instantiate a module against the full profile ceiling.
///
/// This proves that the exact bytes expose a typed `_start`, use only the
/// profile authority surface, and fit within the maximum runtime resource
/// envelope. It never calls `_start`; caller-selected invocation limits remain
/// separate and are bound into each later receipt.
///
/// # Errors
///
/// Refuses malformed, oversized, uncallable, over-authorized, or otherwise
/// uninstantiable modules.
pub fn qualify_module(module: &[u8]) -> Result<WasmModuleQualification, WasmError> {
    validate_module_length(module.len())?;
    let request = WasmRequest {
        module: module.to_vec(),
        stdin: Vec::new(),
        limits: WasmLimits {
            timeout: MAX_TIMEOUT,
            fuel: MAX_FUEL,
            memory_bytes: MAX_MEMORY_BYTES,
            table_elements: MAX_TABLE_ELEMENTS,
            stdout_bytes: MAX_CAPTURE_BYTES,
            stderr_bytes: MAX_CAPTURE_BYTES,
        },
    };
    let prepared = prepare(&request)?;
    drop(prepared);
    Ok(WasmModuleQualification {
        runtime: RUNTIME_ID.to_owned(),
        module_digest: sha256_identity(module),
    })
}

fn validate_authority_surface(module: &[u8]) -> Result<(), WasmError> {
    for payload in Parser::new(0).parse_all(module) {
        match payload.map_err(|error| WasmError::Compile(error.to_string()))? {
            Payload::Version { encoding, .. } if encoding != Encoding::Module => {
                return Err(WasmError::ForbiddenAuthority(
                    "components are not accepted by the WASIp1 command profile".to_owned(),
                ));
            }
            Payload::ImportSection(imports) => {
                for import in imports.into_imports() {
                    let import = import.map_err(|error| WasmError::Compile(error.to_string()))?;
                    let allowed = import.module == "wasi_snapshot_preview1"
                        && matches!(import.ty, TypeRef::Func(_))
                        && matches!(
                            import.name,
                            "fd_read"
                                | "fd_write"
                                | "proc_exit"
                                | "environ_get"
                                | "environ_sizes_get"
                        );
                    if !allowed {
                        return Err(WasmError::ForbiddenAuthority(format!(
                            "import `{}::{}` is not allowed",
                            import.module, import.name
                        )));
                    }
                }
            }
            Payload::StartSection { .. } => {
                return Err(WasmError::ForbiddenAuthority(
                    "a start section could execute before durable arming".to_owned(),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

impl PreparedWasmInvocation {
    /// Start and completely supervise the already-prepared command once.
    ///
    /// A host crash destroys the in-process Wasm store, so no guest process or
    /// PID can outlive the host. Fuel, memory, table, output, and wall-clock
    /// enforcement are owned by Wasmtime and its WASI implementation.
    ///
    /// All fallible infrastructure acquisition, including the parked deadline
    /// watchdog, happened in [`prepare`]. Guest exits and traps are closed
    /// receipt outcomes, so this post-arm operation has no error return.
    #[must_use]
    pub fn execute(mut self) -> WasmReceipt {
        let started = Instant::now();
        self.watchdog.start(started);
        let call = self.start.call(&mut self.store, ());
        let deadline_elapsed = started.elapsed() >= self.limits.timeout;
        self.watchdog.finish();
        let termination = classify_termination(
            call,
            self.watchdog.timed_out() || deadline_elapsed,
            &self.stdout,
            &self.stderr,
            self.limits,
        );
        self.receipt(termination)
    }

    fn receipt(&self, termination: WasmTermination) -> WasmReceipt {
        WasmReceipt {
            runtime: RUNTIME_ID.to_owned(),
            execution_policy: self.execution_policy,
            module_digest: self.module_digest.clone(),
            stdin_digest: self.stdin_digest.clone(),
            termination,
            stdin_bytes_provided: self.stdin_bytes_provided,
            stdout: self.stdout.contents().to_vec(),
            stderr: self.stderr.contents().to_vec(),
        }
    }
}

fn classify_termination(
    call: wasmtime::Result<()>,
    deadline_elapsed: bool,
    stdout: &MemoryOutputPipe,
    stderr: &MemoryOutputPipe,
    limits: WasmLimits,
) -> WasmTermination {
    let stdout_limit_reached = stdout.contents().len() == limits.stdout_bytes;
    let stderr_limit_reached = stderr.contents().len() == limits.stderr_bytes;
    match call {
        Ok(()) if !deadline_elapsed && !stdout_limit_reached && !stderr_limit_reached => {
            WasmTermination::Returned
        }
        Err(error) => {
            if let Some(exit) = error.downcast_ref::<wasmtime_wasi::I32Exit>()
                && !deadline_elapsed
                && !stdout_limit_reached
                && !stderr_limit_reached
            {
                WasmTermination::GuestExit { code: exit.0 }
            } else {
                let fuel_exhausted = error
                    .downcast_ref::<wasmtime::Trap>()
                    .is_some_and(|trap| *trap == wasmtime::Trap::OutOfFuel);
                if deadline_elapsed
                    || fuel_exhausted
                    || stdout_limit_reached
                    || stderr_limit_reached
                {
                    WasmTermination::Enforced {
                        timed_out: deadline_elapsed,
                        fuel_exhausted,
                        stdout_limit_reached,
                        stderr_limit_reached,
                    }
                } else {
                    WasmTermination::Trapped
                }
            }
        }
        Ok(()) => WasmTermination::Enforced {
            timed_out: deadline_elapsed,
            fuel_exhausted: false,
            stdout_limit_reached,
            stderr_limit_reached,
        },
    }
}

fn sha256_identity(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(source: &str) -> Vec<u8> {
        wat::parse_str(source).expect("valid test module")
    }

    fn request(source: &str) -> WasmRequest {
        WasmRequest {
            module: module(source),
            stdin: b"exact input".to_vec(),
            limits: WasmLimits {
                timeout: Duration::from_secs(1),
                fuel: 1_000_000,
                memory_bytes: 1024 * 1024,
                table_elements: 1024,
                stdout_bytes: 1024,
                stderr_bytes: 1024,
            },
        }
    }

    fn run(request: &WasmRequest) -> WasmReceipt {
        prepare(request).expect("prepare exact module").execute()
    }

    #[test]
    fn clean_return_is_bound_to_exact_module_and_stdin() {
        let request = request("(module (func (export \"_start\")))");
        let receipt = run(&request);

        assert_eq!(receipt.termination, WasmTermination::Returned);
        assert!(receipt.is_clean_success());
        receipt.validate_against(&request).expect("valid receipt");

        let mut changed = request.clone();
        changed.stdin.push(b'!');
        assert!(matches!(
            receipt.validate_against(&changed),
            Err(WasmError::InvalidReceipt("stdin identity changed"))
        ));

        let mut changed_policy = request.clone();
        changed_policy.limits.fuel += 1;
        assert!(matches!(
            receipt.validate_against(&changed_policy),
            Err(WasmError::InvalidReceipt("execution policy changed"))
        ));
    }

    #[test]
    fn execution_has_no_fallible_post_arm_infrastructure_path() {
        let execute: fn(PreparedWasmInvocation) -> WasmReceipt = PreparedWasmInvocation::execute;
        let request = request("(module (func (export \"_start\")))");
        let receipt = execute(prepare(&request).expect("all infrastructure prepared"));

        receipt.validate_against(&request).expect("valid receipt");
    }

    #[test]
    fn guest_exit_is_a_closed_receipt_not_a_host_error() {
        let request = request(
            r#"(module
                (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
                (memory (export "memory") 1)
                (func (export "_start")
                    i32.const 23
                    call $exit))"#,
        );
        let receipt = run(&request);

        assert_eq!(receipt.termination, WasmTermination::GuestExit { code: 23 });
        receipt.validate_against(&request).expect("valid receipt");
    }

    #[test]
    fn guest_exit_boundary_matches_the_pinned_wasi_implementation() {
        for (code, expected) in [
            (125, WasmTermination::GuestExit { code: 125 }),
            (126, WasmTermination::Trapped),
            (-1, WasmTermination::Trapped),
        ] {
            let request = request(&format!(
                r#"(module
                    (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
                    (memory (export "memory") 1)
                    (func (export "_start")
                        i32.const {code}
                        call $exit))"#
            ));
            let receipt = run(&request);

            assert_eq!(receipt.termination, expected);
            receipt.validate_against(&request).expect("valid receipt");
        }
    }

    #[test]
    fn fuel_exhaustion_is_enforced_by_wasmtime() {
        let mut request = request(
            r#"(module
                (func (export "_start")
                    (loop $again
                        br $again)))"#,
        );
        request.limits.fuel = 100;
        let receipt = run(&request);

        assert!(matches!(
            receipt.termination,
            WasmTermination::Enforced {
                fuel_exhausted: true,
                ..
            }
        ));
    }

    #[test]
    fn epoch_deadline_terminates_an_unbounded_guest() {
        let mut request = request(
            r#"(module
                (func (export "_start")
                    (loop $again
                        br $again)))"#,
        );
        request.limits.timeout = Duration::from_millis(10);
        request.limits.fuel = MAX_FUEL;
        let receipt = run(&request);

        assert!(matches!(
            receipt.termination,
            WasmTermination::Enforced {
                timed_out: true,
                ..
            }
        ));
    }

    #[test]
    fn reaching_stdout_bound_fails_closed_with_exact_bounded_bytes() {
        let mut request = request(
            r#"(module
                (import "wasi_snapshot_preview1" "fd_write"
                    (func $fd_write (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "\08\00\00\00\05\00\00\00hello")
                (func (export "_start")
                    i32.const 1
                    i32.const 0
                    i32.const 1
                    i32.const 32
                    call $fd_write
                    drop))"#,
        );
        request.limits.stdout_bytes = 5;
        let receipt = run(&request);

        assert_eq!(receipt.stdout, b"hello");
        assert!(matches!(
            receipt.termination,
            WasmTermination::Enforced {
                stdout_limit_reached: true,
                stderr_limit_reached: false,
                ..
            }
        ));
        receipt.validate_against(&request).expect("valid receipt");
    }

    #[test]
    fn guest_memory_minimum_cannot_exceed_host_limit() {
        let mut request = request(
            r#"(module
                (memory 2)
                (func (export "_start")))"#,
        );
        request.limits.memory_bytes = 64 * 1024;

        assert!(matches!(prepare(&request), Err(WasmError::Link(_))));
    }

    #[test]
    fn recovered_receipts_reject_internal_contradictions() {
        let request = request("(module (func (export \"_start\")))");
        let mut receipt = run(&request);
        receipt.termination = WasmTermination::Enforced {
            timed_out: false,
            fuel_exhausted: false,
            stdout_limit_reached: false,
            stderr_limit_reached: false,
        };

        assert!(matches!(
            receipt.validate_against(&request),
            Err(WasmError::InvalidReceipt(
                "enforced receipt names no enforcement cause"
            ))
        ));
    }

    #[test]
    fn malformed_and_oversized_requests_are_refused_before_arming() {
        let mut malformed = request("(module (func (export \"_start\")))");
        malformed.module = b"not wasm".to_vec();
        assert!(matches!(prepare(&malformed), Err(WasmError::Compile(_))));

        let oversized_module = vec![0; MAX_MODULE_BYTES + 1];
        assert!(matches!(
            qualify_module(&oversized_module),
            Err(WasmError::InvalidRequest(
                "module length is outside the profile bound"
            ))
        ));

        let mut oversized = request("(module (func (export \"_start\")))");
        oversized.stdin = vec![0; MAX_STDIN_BYTES + 1];
        assert!(matches!(
            prepare(&oversized),
            Err(WasmError::InvalidRequest("stdin exceeds the proof bound"))
        ));

        let mut inexact_policy = request("(module (func (export \"_start\")))");
        inexact_policy.limits.fuel = MAX_FUEL + 1;
        assert!(matches!(
            prepare(&inexact_policy),
            Err(WasmError::InvalidLimits)
        ));
    }

    #[test]
    fn start_sections_and_unneeded_wasi_authority_are_refused_before_arming() {
        let with_start = request(
            r#"(module
                (func $implicit_start)
                (start $implicit_start)
                (func (export "_start")))"#,
        );
        assert!(matches!(
            prepare(&with_start),
            Err(WasmError::ForbiddenAuthority(detail))
                if detail.contains("before durable arming")
        ));

        let with_clock = request(
            r#"(module
                (import "wasi_snapshot_preview1" "clock_time_get"
                    (func $clock_time_get (param i32 i64 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "_start")))"#,
        );
        assert!(matches!(
            prepare(&with_clock),
            Err(WasmError::ForbiddenAuthority(detail))
                if detail.contains("clock_time_get")
        ));
    }

    #[test]
    fn qualification_requires_an_invokable_profile_module() {
        let valid = module("(module (func (export \"_start\")))");
        let qualification = qualify_module(&valid).expect("qualified module");
        assert_eq!(qualification.runtime, RUNTIME_ID);
        assert_eq!(qualification.module_digest, sha256_identity(&valid));

        let no_start = module("(module)");
        assert!(matches!(qualify_module(&no_start), Err(WasmError::Link(_))));
    }
}
