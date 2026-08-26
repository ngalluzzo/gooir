//! Audited Darwin `posix_spawn` boundary for the proof-local supervisor.
//!
//! Unsafe code is confined to direct calls whose contracts are documented at
//! each site. The safe caller receives owned pipes plus a PID and never handles
//! raw spawn structures or pointers.
//!
//! Darwin exposes no `pipe2`; pipe creation and immediate `FD_CLOEXEC`
//! normalization are serialized across this supervisor's spawn calls. The
//! proof host must not introduce an unsynchronized second process-launch path.

#![allow(unsafe_code)]

use std::ffi::{CString, c_char, c_short};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::sync::{Mutex, OnceLock};

const FIRST_PRIVATE_FD: RawFd = 10;

unsafe extern "C" {
    fn posix_spawn_file_actions_addfchdir_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        fd: libc::c_int,
    ) -> libc::c_int;

    fn posix_spawn_file_actions_addinherit_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        fd: libc::c_int,
    ) -> libc::c_int;
}

pub(super) struct SpawnedProcess {
    pub(super) pid: libc::pid_t,
    pub(super) stdin: File,
    pub(super) authority: File,
    pub(super) stdout: File,
    pub(super) stderr: File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WaitStatus {
    Exited(i32),
    Signaled(i32),
    Other(i32),
}

pub(super) fn spawn(executable: &Path, cwd: BorrowedFd<'_>) -> io::Result<SpawnedProcess> {
    let _spawn_guard = spawn_lock()
        .lock()
        .map_err(|_| io::Error::other("native spawn lock is poisoned"))?;
    let executable = CString::new(executable.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "executable path contains NUL"))?;
    let stdin = Pipe::new()?;
    let stdout = Pipe::new()?;
    let stderr = Pipe::new()?;
    let authority = Pipe::new()?;
    let cwd = duplicate_private(cwd.as_raw_fd())?;

    let mut actions = FileActions::new()?;
    actions.add_dup2(stdin.reader.as_raw_fd(), libc::STDIN_FILENO)?;
    actions.add_dup2(stdout.writer.as_raw_fd(), libc::STDOUT_FILENO)?;
    actions.add_dup2(stderr.writer.as_raw_fd(), libc::STDERR_FILENO)?;
    actions.add_dup2(authority.reader.as_raw_fd(), 3)?;
    for source in [
        stdin.reader.as_raw_fd(),
        stdout.writer.as_raw_fd(),
        stderr.writer.as_raw_fd(),
        authority.reader.as_raw_fd(),
    ] {
        actions.add_close(source)?;
    }
    actions.add_inherit(cwd.as_raw_fd())?;
    actions.add_fchdir(cwd.as_raw_fd())?;
    actions.add_close(cwd.as_raw_fd())?;

    let mut attributes = SpawnAttributes::new()?;
    attributes.configure()?;

    let argv0 = c"fleetd-native-command";
    let mut argv = [argv0.as_ptr().cast_mut(), ptr::null_mut::<c_char>()];
    let mut environment = [ptr::null_mut::<c_char>()];
    let mut pid = 0;
    // SAFETY: every pointer refers to initialized storage retained through the
    // call; argv/envp are null terminated; actions and attributes are live.
    cvt_spawn(unsafe {
        libc::posix_spawn(
            &raw mut pid,
            executable.as_ptr(),
            actions.as_ptr(),
            attributes.as_ptr(),
            argv.as_mut_ptr(),
            environment.as_mut_ptr(),
        )
    })?;

    drop(stdin.reader);
    drop(stdout.writer);
    drop(stderr.writer);
    drop(authority.reader);
    Ok(SpawnedProcess {
        pid,
        stdin: File::from(stdin.writer),
        authority: File::from(authority.writer),
        stdout: File::from(stdout.reader),
        stderr: File::from(stderr.reader),
    })
}

fn spawn_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub(super) fn has_exited(pid: libc::pid_t) -> io::Result<bool> {
    let id = libc::id_t::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "child pid does not fit id_t"))?;
    loop {
        // SAFETY: `information` is zero-initialized writable storage; P_PID
        // names the exact unreaped child. WNOWAIT observes without consuming
        // its exit status, retaining the PID/PGID anchor through group kill.
        let mut information = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        // SAFETY: all arguments satisfy waitid's contract documented above.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                id,
                &raw mut information,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            return Ok(information.si_pid != 0);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(super) fn wait(pid: libc::pid_t) -> io::Result<WaitStatus> {
    let mut status = 0;
    loop {
        // SAFETY: `status` is writable and `pid` is the exact child returned by spawn.
        let result = unsafe { libc::waitpid(pid, &raw mut status, 0) };
        if result == pid {
            return Ok(decode_wait_status(status));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(super) fn kill_group(pid: libc::pid_t) -> io::Result<()> {
    // SAFETY: a negative child PID addresses the process group created atomically at spawn.
    let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
    if result == 0 {
        return Ok(());
    }
    Err(io::Error::last_os_error())
}

fn decode_wait_status(status: i32) -> WaitStatus {
    if libc::WIFEXITED(status) {
        WaitStatus::Exited(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        WaitStatus::Signaled(libc::WTERMSIG(status))
    } else {
        WaitStatus::Other(status)
    }
}

struct Pipe {
    reader: OwnedFd,
    writer: OwnedFd,
}

impl Pipe {
    fn new() -> io::Result<Self> {
        let mut descriptors = [-1; 2];
        // SAFETY: `descriptors` provides writable storage for both returned fds.
        if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful `pipe` returned two newly owned descriptors.
        let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        // SAFETY: successful `pipe` returned two newly owned descriptors.
        let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        Ok(Self {
            reader: normalize_private(reader)?,
            writer: normalize_private(writer)?,
        })
    }
}

fn normalize_private(fd: OwnedFd) -> io::Result<OwnedFd> {
    if fd.as_raw_fd() >= FIRST_PRIVATE_FD {
        set_cloexec(fd.as_raw_fd())?;
        return Ok(fd);
    }
    duplicate_private(fd.as_raw_fd())
}

fn duplicate_private(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC duplicates the live numeric descriptor on success.
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, FIRST_PRIVATE_FD) };
    if duplicated < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: successful fcntl returned one newly owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
    }
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: F_GETFD reads flags from a live numeric descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFD updates flags on the same live descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

struct FileActions(libc::posix_spawn_file_actions_t);

impl FileActions {
    fn new() -> io::Result<Self> {
        let mut actions = MaybeUninit::uninit();
        // SAFETY: Darwin initializes `actions` on success.
        cvt_spawn(unsafe { libc::posix_spawn_file_actions_init(actions.as_mut_ptr()) })?;
        // SAFETY: initialization succeeded.
        Ok(Self(unsafe { actions.assume_init() }))
    }

    fn as_ptr(&self) -> *const libc::posix_spawn_file_actions_t {
        &raw const self.0
    }

    fn as_mut_ptr(&mut self) -> *mut libc::posix_spawn_file_actions_t {
        &raw mut self.0
    }

    fn add_dup2(&mut self, source: RawFd, target: RawFd) -> io::Result<()> {
        // SAFETY: the initialized action object accepts numeric fd operands.
        cvt_spawn(unsafe {
            libc::posix_spawn_file_actions_adddup2(self.as_mut_ptr(), source, target)
        })
    }

    fn add_close(&mut self, fd: RawFd) -> io::Result<()> {
        // SAFETY: the initialized action object accepts a numeric fd operand.
        cvt_spawn(unsafe { libc::posix_spawn_file_actions_addclose(self.as_mut_ptr(), fd) })
    }

    fn add_inherit(&mut self, fd: RawFd) -> io::Result<()> {
        // SAFETY: the initialized action object and live fd remain valid through spawn.
        cvt_spawn(unsafe { posix_spawn_file_actions_addinherit_np(self.as_mut_ptr(), fd) })
    }

    fn add_fchdir(&mut self, fd: RawFd) -> io::Result<()> {
        // SAFETY: the initialized action object and directory fd remain valid through spawn.
        cvt_spawn(unsafe { posix_spawn_file_actions_addfchdir_np(self.as_mut_ptr(), fd) })
    }
}

impl Drop for FileActions {
    fn drop(&mut self) {
        // SAFETY: initialized exactly once and destroyed exactly once.
        let _ = unsafe { libc::posix_spawn_file_actions_destroy(self.as_mut_ptr()) };
    }
}

struct SpawnAttributes(libc::posix_spawnattr_t);

impl SpawnAttributes {
    fn new() -> io::Result<Self> {
        let mut attributes = MaybeUninit::uninit();
        // SAFETY: Darwin initializes `attributes` on success.
        cvt_spawn(unsafe { libc::posix_spawnattr_init(attributes.as_mut_ptr()) })?;
        // SAFETY: initialization succeeded.
        Ok(Self(unsafe { attributes.assume_init() }))
    }

    fn as_ptr(&self) -> *const libc::posix_spawnattr_t {
        &raw const self.0
    }

    fn as_mut_ptr(&mut self) -> *mut libc::posix_spawnattr_t {
        &raw mut self.0
    }

    fn configure(&mut self) -> io::Result<()> {
        // SAFETY: zeroed sigset storage is immediately initialized by sigemptyset.
        let mut empty_mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        // SAFETY: the pointer references writable signal-set storage.
        cvt_errno(unsafe { libc::sigemptyset(&raw mut empty_mask) })?;
        // SAFETY: zeroed sigset storage is immediately initialized by sigfillset.
        let mut defaults = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        // SAFETY: the pointer references writable signal-set storage.
        cvt_errno(unsafe { libc::sigfillset(&raw mut defaults) })?;
        // SAFETY: SIGKILL and SIGSTOP are valid members to remove from the set.
        cvt_errno(unsafe { libc::sigdelset(&raw mut defaults, libc::SIGKILL) })?;
        // SAFETY: SIGKILL and SIGSTOP are valid members to remove from the set.
        cvt_errno(unsafe { libc::sigdelset(&raw mut defaults, libc::SIGSTOP) })?;
        // SAFETY: all values are initialized and live through each call.
        cvt_spawn(unsafe {
            libc::posix_spawnattr_setsigmask(self.as_mut_ptr(), &raw const empty_mask)
        })?;
        // SAFETY: all values are initialized and live through each call.
        cvt_spawn(unsafe {
            libc::posix_spawnattr_setsigdefault(self.as_mut_ptr(), &raw const defaults)
        })?;
        // SAFETY: pgroup 0 requests a new group whose id is the spawned child's pid.
        cvt_spawn(unsafe { libc::posix_spawnattr_setpgroup(self.as_mut_ptr(), 0) })?;
        let flags = c_short::try_from(
            libc::POSIX_SPAWN_CLOEXEC_DEFAULT
                | libc::POSIX_SPAWN_SETPGROUP
                | libc::POSIX_SPAWN_SETSIGMASK
                | libc::POSIX_SPAWN_SETSIGDEF,
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "spawn flags do not fit"))?;
        // SAFETY: every flag is defined by Darwin spawn.h for this attribute object.
        cvt_spawn(unsafe { libc::posix_spawnattr_setflags(self.as_mut_ptr(), flags) })
    }
}

impl Drop for SpawnAttributes {
    fn drop(&mut self) {
        // SAFETY: initialized exactly once and destroyed exactly once.
        let _ = unsafe { libc::posix_spawnattr_destroy(self.as_mut_ptr()) };
    }
}

fn cvt_spawn(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result))
    }
}

fn cvt_errno(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
