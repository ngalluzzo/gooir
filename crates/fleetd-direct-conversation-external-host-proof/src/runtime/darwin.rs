#![allow(unsafe_code)]
#![allow(deprecated)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, Metadata};
use std::os::darwin::fs::MetadataExt as DarwinMetadataExt;
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;

use object::macho::{self, DyldCacheHeader};
use object::read::macho::{
    DyldCache, DyldSubCacheSlice, FatArch, LoadCommandVariant, MachHeader, MachOFatFile32,
    MachOFatFile64, MachOFile64,
};
use object::read::{
    Architecture, FileKind, Object, ObjectSegment, ReadCache, ReadCacheOps, ReadRef,
};
use object::{Endianness, SegmentFlags};
use rustix::fs::{Mode, OFlags, open, openat};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    ActiveCacheFileIdentity, DarwinPlatformIdentity, DyldIdentity, NativeRuntimeQualification,
    ProofHostIdentity, RuntimeFileMetadata, RuntimeQualificationError, SharedCacheFileIdentity,
    SharedCacheIdentity, SharedCacheImageIdentity, document_digest, sha256_identity,
};

const CACHE_CANDIDATES: [&str; 2] = [
    "/System/Cryptexes/OS/System/Library/dyld",
    "/System/Library/dyld",
];
const CACHE_BASENAME: &str = "dyld_shared_cache_arm64e";
const DYLD_PATH: &str = "/usr/lib/dyld";
const LIBSYSTEM_PATH: &str = "/usr/lib/libSystem.B.dylib";
const LIBICONV_PATH: &str = "/usr/lib/libiconv.2.dylib";
const TASK_DYLD_INFO: u32 = 17;
const TASK_DYLD_INFO_FORMAT_64: c_int = 1;
const TASK_DYLD_INFO_COUNT: u32 = 5;
const KERN_SUCCESS: c_int = 0;
const PROC_PIDPATHINFO_MAXSIZE: usize = libc::PROC_PIDPATHINFO_MAXSIZE as usize;
const MAX_SYSCTL_BYTES: usize = 4096;
const MAX_DYLD_VERSION_BYTES: usize = 256;
const MAX_CACHE_FILES: usize = 64;
const MAX_CACHE_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_CACHE_TOTAL_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_IMAGES: usize = 4096;
const MAX_LOAD_COMMAND_BYTES: usize = 1024 * 1024;
const MAX_READ_CACHE_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_READ_CACHE_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_HOST_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DYLD_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SUFFIX_BYTES: usize = 31;
const CPU_SUBTYPE_ARM64E: u32 = 2;
const SF_RESTRICTED: u32 = 0x0008_0000;

#[repr(C, packed(4))]
#[derive(Clone, Copy)]
#[allow(
    clippy::struct_field_names,
    reason = "field names mirror the authoritative Darwin C ABI"
)]
struct TaskDyldInfo {
    all_image_info_addr: u64,
    all_image_info_size: u64,
    all_image_info_format: c_int,
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
#[allow(
    clippy::struct_field_names,
    reason = "field names mirror the authoritative Darwin C ABI"
)]
struct DyldAllImageInfos {
    version: u32,
    info_array_count: u32,
    info_array: *const c_void,
    notification: *const c_void,
    process_detached_from_shared_region: bool,
    libsystem_initialized: bool,
    dyld_image_load_address: *const c_void,
    jit_info: *const c_void,
    dyld_version: *const c_char,
    error_message: *const c_char,
    termination_flags: usize,
    core_symbolication_shm_page: *const c_void,
    system_order_flag: usize,
    uuid_array_count: usize,
    uuid_array: *const c_void,
    dyld_all_image_infos_address: *const c_void,
    initial_image_count: usize,
    error_kind: usize,
    error_client_of_dylib_path: *const c_char,
    error_target_dylib_path: *const c_char,
    error_symbol: *const c_char,
    shared_cache_slide: usize,
    shared_cache_uuid: [u8; 16],
    shared_cache_base_address: usize,
    info_array_change_timestamp: u64,
    dyld_path: *const c_char,
    notify_ports: [u32; 8],
    reserved: [usize; 7],
    shared_cache_fsid: u64,
    shared_cache_fs_object_id: u64,
    compact_dyld_image_info_addr: usize,
    compact_dyld_image_info_size: usize,
    platform: u32,
    aot_info_count: u32,
    aot_info_array: *const c_void,
    aot_info_array_change_timestamp: u64,
    aot_shared_cache_base_address: usize,
    aot_shared_cache_uuid: [u8; 16],
}

const _: () = assert!(std::mem::size_of::<TaskDyldInfo>() == 20);
const _: () = assert!(std::mem::align_of::<TaskDyldInfo>() == 4);
const _: () = assert!(
    std::mem::size_of::<TaskDyldInfo>() / std::mem::size_of::<u32>()
        == TASK_DYLD_INFO_COUNT as usize
);
const _: () = assert!(std::mem::size_of::<DyldAllImageInfos>() == 368);

#[derive(Clone)]
struct TaskSnapshot {
    all_image_info_addr: u64,
    all_image_info_size: u64,
    all_image_info_format: c_int,
    infos_version: u32,
    image_count: u32,
    dyld_image_load_address: usize,
    shared_cache_slide: usize,
    shared_cache_uuid: [u8; 16],
    shared_cache_base_address: usize,
    change_timestamp: u64,
    dyld_version: String,
}

struct RetainedFile {
    file: File,
    metadata: RuntimeFileMetadata,
}

struct PathAuthority {
    parent: File,
    name: OsString,
    retained: RetainedFile,
    system_owned: bool,
}

struct CacheAuthority {
    parent: File,
    parent_metadata: DirectoryMetadata,
    main: RetainedFile,
    suffixes: Vec<OsString>,
    subcaches: Vec<RetainedFile>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectoryMetadata {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    flags: u32,
}

pub(super) struct LiveDarwinAuthority {
    host: PathAuthority,
    dyld: PathAuthority,
    cache: CacheAuthority,
    task: TaskSnapshot,
}

pub(super) struct DarwinSnapshot {
    pub(super) platform: DarwinPlatformIdentity,
    pub(super) proof_host: ProofHostIdentity,
    pub(super) dyld: DyldIdentity,
    pub(super) shared_cache: SharedCacheIdentity,
    pub(super) loaded_image_count: String,
    pub(super) loaded_image_set_sha256: String,
    pub(super) dyld_all_image_infos_version: String,
    pub(super) task_dyld_info_format: String,
    pub(super) task_dyld_info_returned_count: String,
}

impl LiveDarwinAuthority {
    pub(super) fn revalidate(
        &mut self,
        expected: &NativeRuntimeQualification,
    ) -> Result<(), RuntimeQualificationError> {
        ensure_single_threaded()?;
        validate_path_authority(&self.host)?;
        validate_path_authority(&self.dyld)?;
        validate_cache_authority(&self.cache)?;
        let current_task = capture_task_snapshot()?;
        if !same_task_runtime(&self.task, &current_task) {
            return Err(RuntimeQualificationError::HostRuntimeChanged);
        }
        let current = build_snapshot(
            &self.host,
            &self.dyld,
            &self.cache,
            &current_task,
            false,
            Some(&expected.shared_cache),
        )?;
        let post_build_task = capture_task_snapshot()?;
        if !same_task_runtime(&current_task, &post_build_task) {
            return Err(RuntimeQualificationError::HostRuntimeChanged);
        }
        validate_path_authority(&self.host)?;
        validate_path_authority(&self.dyld)?;
        validate_cache_authority(&self.cache)?;
        let final_task = capture_task_snapshot()?;
        if !same_task_runtime(&post_build_task, &final_task) {
            return Err(RuntimeQualificationError::HostRuntimeChanged);
        }
        if current.platform != expected.platform
            || current.proof_host != expected.proof_host
            || current.dyld != expected.dyld
            || current.shared_cache != expected.shared_cache
            || current.loaded_image_count != expected.loaded_image_count
            || current.loaded_image_set_sha256 != expected.loaded_image_set_sha256
            || current.dyld_all_image_infos_version != expected.dyld_all_image_infos_version
            || current.task_dyld_info_format != expected.task_dyld_info_format
            || current.task_dyld_info_returned_count != expected.task_dyld_info_returned_count
        {
            return Err(RuntimeQualificationError::HostRuntimeChanged);
        }
        Ok(())
    }
}

pub(super) fn capture() -> Result<(DarwinSnapshot, LiveDarwinAuthority), RuntimeQualificationError>
{
    ensure_single_threaded()?;
    let first_task = capture_task_snapshot()?;
    let host = open_host_executable()?;
    let dyld = open_path_authority(Path::new(DYLD_PATH), true)?;
    let cache = locate_active_cache(first_task.shared_cache_uuid)?;
    let snapshot = build_snapshot(&host, &dyld, &cache, &first_task, true, None)?;
    let second_task = capture_task_snapshot()?;
    if !same_task_runtime(&first_task, &second_task) {
        return Err(RuntimeQualificationError::HostRuntimeChanged);
    }
    validate_path_authority(&host)?;
    validate_path_authority(&dyld)?;
    validate_cache_authority(&cache)?;
    let final_task = capture_task_snapshot()?;
    if !same_task_runtime(&second_task, &final_task) {
        return Err(RuntimeQualificationError::HostRuntimeChanged);
    }
    Ok((
        snapshot,
        LiveDarwinAuthority {
            host,
            dyld,
            cache,
            task: final_task,
        },
    ))
}

#[allow(clippy::too_many_lines)]
fn build_snapshot(
    host: &PathAuthority,
    dyld: &PathAuthority,
    cache: &CacheAuthority,
    task: &TaskSnapshot,
    hash_all_cache_files: bool,
    previous_cache: Option<&SharedCacheIdentity>,
) -> Result<DarwinSnapshot, RuntimeQualificationError> {
    let proof_host = inspect_host(host, task)?;
    let dyld_identity = inspect_dyld(dyld, task)?;
    let cache_analysis = inspect_cache(cache, task, hash_all_cache_files, previous_cache)?;
    if dyld_identity.stable_commands_sha256 != cache_analysis.dyld_stable_commands_sha256 {
        return Err(RuntimeQualificationError::HostRuntimeChanged);
    }
    Ok(DarwinSnapshot {
        platform: platform_identity()?,
        proof_host,
        dyld: dyld_identity,
        shared_cache: cache_analysis.identity,
        loaded_image_count: cache_analysis.loaded_count,
        loaded_image_set_sha256: cache_analysis.loaded_digest,
        dyld_all_image_infos_version: task.infos_version.to_string(),
        task_dyld_info_format: task.all_image_info_format.to_string(),
        task_dyld_info_returned_count: TASK_DYLD_INFO_COUNT.to_string(),
    })
}

fn ensure_single_threaded() -> Result<(), RuntimeQualificationError> {
    // SAFETY: proc_taskinfo is a plain C numeric record; all-zero is a valid initial bit pattern.
    let mut task: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    // SAFETY: proc_pidinfo writes at most the exact size of the local proc_taskinfo record for
    // our own pid and the fixed PROC_PIDTASKINFO flavor.
    let returned = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDTASKINFO,
            0,
            (&raw mut task).cast(),
            i32::try_from(std::mem::size_of::<libc::proc_taskinfo>())
                .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?,
        )
    };
    if returned
        != i32::try_from(std::mem::size_of::<libc::proc_taskinfo>())
            .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?
        || task.pti_threadnum != 1
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    Ok(())
}

fn capture_task_snapshot() -> Result<TaskSnapshot, RuntimeQualificationError> {
    let mut task_info_data = TaskDyldInfo {
        all_image_info_addr: 0,
        all_image_info_size: 0,
        all_image_info_format: 0,
    };
    let mut count = TASK_DYLD_INFO_COUNT;
    // SAFETY: querying our own task writes at most `count` natural_t values into the correctly
    // sized and aligned TaskDyldInfo buffer.
    let status = unsafe {
        libc::task_info(
            libc::mach_task_self(),
            TASK_DYLD_INFO,
            (&raw mut task_info_data).cast::<c_int>(),
            &raw mut count,
        )
    };
    let all_image_info_addr = task_info_data.all_image_info_addr;
    let all_image_info_size = task_info_data.all_image_info_size;
    let all_image_info_format = task_info_data.all_image_info_format;
    if status != KERN_SUCCESS
        || count != TASK_DYLD_INFO_COUNT
        || all_image_info_format != TASK_DYLD_INFO_FORMAT_64
        || all_image_info_addr == 0
        || all_image_info_size
            != u64::try_from(std::mem::size_of::<DyldAllImageInfos>())
                .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let address = usize::try_from(all_image_info_addr)
        .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?;
    // SAFETY: TASK_DYLD_INFO for our own task returned a mapped, naturally aligned address and
    // a size covering the exact SDK-compatible prefix copied here. Volatile copies fence dyld's
    // published change timestamp; the snapshot is accepted only after a second stable read.
    let infos = unsafe { std::ptr::read_volatile(address as *const DyldAllImageInfos) };
    if infos.version != 17
        || infos.process_detached_from_shared_region
        || !infos.libsystem_initialized
        || infos.info_array.is_null()
        || infos.dyld_image_load_address.is_null()
        || infos.dyld_all_image_infos_address as usize != address
        || infos.platform != macho::PLATFORM_MACOS
        || infos.uuid_array_count != 1
        || infos.uuid_array.is_null()
        || infos.initial_image_count != 1
        || infos.shared_cache_base_address == 0
        || infos.shared_cache_uuid == [0; 16]
        || infos.info_array_count == 0
        || usize::try_from(infos.info_array_count).unwrap_or(usize::MAX) > MAX_IMAGES
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let dyld_version = bounded_c_string(infos.dyld_version, MAX_DYLD_VERSION_BYTES)?;
    if bounded_c_string(infos.dyld_path, 64)? != DYLD_PATH {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let timestamp = infos.info_array_change_timestamp;
    // SAFETY: same self-task pointer and layout justification as the first volatile copy.
    let confirm = unsafe { std::ptr::read_volatile(address as *const DyldAllImageInfos) };
    if confirm.info_array_change_timestamp != timestamp
        || confirm.version != infos.version
        || confirm.shared_cache_uuid != infos.shared_cache_uuid
        || confirm.shared_cache_base_address != infos.shared_cache_base_address
        || confirm.dyld_image_load_address != infos.dyld_image_load_address
    {
        return Err(RuntimeQualificationError::HostRuntimeChanged);
    }
    Ok(TaskSnapshot {
        all_image_info_addr,
        all_image_info_size,
        all_image_info_format,
        infos_version: infos.version,
        image_count: infos.info_array_count,
        dyld_image_load_address: infos.dyld_image_load_address as usize,
        shared_cache_slide: infos.shared_cache_slide,
        shared_cache_uuid: infos.shared_cache_uuid,
        shared_cache_base_address: infos.shared_cache_base_address,
        change_timestamp: infos.info_array_change_timestamp,
        dyld_version,
    })
}

fn same_task_runtime(left: &TaskSnapshot, right: &TaskSnapshot) -> bool {
    left.all_image_info_addr == right.all_image_info_addr
        && left.all_image_info_size == right.all_image_info_size
        && left.all_image_info_format == right.all_image_info_format
        && left.infos_version == right.infos_version
        && left.change_timestamp == right.change_timestamp
        && left.image_count == right.image_count
        && left.shared_cache_uuid == right.shared_cache_uuid
        && left.shared_cache_base_address == right.shared_cache_base_address
        && left.shared_cache_slide == right.shared_cache_slide
        && left.dyld_image_load_address == right.dyld_image_load_address
        && left.dyld_version == right.dyld_version
}

fn bounded_c_string(
    pointer: *const c_char,
    bound: usize,
) -> Result<String, RuntimeQualificationError> {
    if pointer.is_null() {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    // SAFETY: dyld publishes these immutable process-lifetime pointers. We manually bound the
    // first NUL scan before constructing CStr, so malformed state cannot trigger an unbounded read.
    let length = unsafe {
        (0..bound)
            .find(|offset| *pointer.add(*offset) == 0)
            .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?
    };
    // SAFETY: the bounded scan above proved one terminator at exactly `length`.
    let value = unsafe { CStr::from_ptr(pointer).to_bytes() };
    if value.len() != length {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)
}

fn open_host_executable() -> Result<PathAuthority, RuntimeQualificationError> {
    let mut bytes = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: proc_pidpath writes at most the stated initialized buffer length for our own pid.
    let length = unsafe {
        libc::proc_pidpath(
            libc::getpid(),
            bytes.as_mut_ptr().cast::<c_void>(),
            u32::try_from(bytes.len())
                .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?,
        )
    };
    if length <= 0 {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let length =
        usize::try_from(length).map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?;
    if length >= bytes.len() || bytes[length] != 0 || bytes[..length].contains(&0) {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    bytes.truncate(length);
    open_path_authority(Path::new(&OsString::from_vec(bytes)), false)
}

fn open_path_authority(
    path: &Path,
    system_owned: bool,
) -> Result<PathAuthority, RuntimeQualificationError> {
    let canonical = fs::canonicalize(path).map_err(invalid)?;
    let name = canonical
        .file_name()
        .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?
        .to_os_string();
    let parent_path = canonical
        .parent()
        .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
    let parent = File::from(
        open(
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(invalid)?,
    );
    let file = File::from(
        openat(
            &parent,
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(invalid)?,
    );
    let metadata = file_metadata(&file, system_owned)?;
    Ok(PathAuthority {
        parent,
        name,
        retained: RetainedFile { file, metadata },
        system_owned,
    })
}

fn validate_path_authority(authority: &PathAuthority) -> Result<(), RuntimeQualificationError> {
    let retained = file_metadata(&authority.retained.file, authority.system_owned)?;
    if retained != authority.retained.metadata {
        return Err(RuntimeQualificationError::HostRuntimeChanged);
    }
    let reopened = File::from(
        openat(
            &authority.parent,
            &authority.name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(changed)?,
    );
    if file_metadata(&reopened, authority.system_owned)? != authority.retained.metadata {
        return Err(RuntimeQualificationError::HostRuntimeChanged);
    }
    Ok(())
}

fn locate_active_cache(active_uuid: [u8; 16]) -> Result<CacheAuthority, RuntimeQualificationError> {
    let mut match_authority = None;
    let mut seen = BTreeSet::new();
    for candidate in CACHE_CANDIDATES {
        let Ok(canonical) = fs::canonicalize(candidate) else {
            continue;
        };
        let Ok(parent_fd) = open(
            &canonical,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) else {
            continue;
        };
        let parent = File::from(parent_fd);
        let Ok(parent_metadata) = directory_metadata(&parent) else {
            continue;
        };
        if !seen.insert((parent_metadata.device, parent_metadata.inode)) {
            continue;
        }
        let Ok(main_fd) = openat(
            &parent,
            CACHE_BASENAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) else {
            continue;
        };
        let main_file = File::from(main_fd);
        let Ok(main_metadata) = file_metadata(&main_file, true) else {
            continue;
        };
        let Ok(main_uuid) = cache_uuid(&main_file) else {
            continue;
        };
        if main_uuid != active_uuid {
            continue;
        }
        if match_authority.is_some() {
            return Err(RuntimeQualificationError::HostRuntimeInvalid);
        }
        let suffixes = validated_suffixes(&main_file)?;
        if suffixes.len() + 1 > MAX_CACHE_FILES {
            return Err(RuntimeQualificationError::HostRuntimeInvalid);
        }
        let mut subcaches = Vec::with_capacity(suffixes.len());
        let mut total = main_metadata
            .byte_len
            .parse::<u64>()
            .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?;
        for suffix in &suffixes {
            let mut name = OsString::from(CACHE_BASENAME);
            name.push(suffix);
            let file = File::from(
                openat(
                    &parent,
                    &name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                    Mode::empty(),
                )
                .map_err(invalid)?,
            );
            let metadata = file_metadata(&file, true)?;
            total = total
                .checked_add(
                    metadata
                        .byte_len
                        .parse::<u64>()
                        .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?,
                )
                .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
            if total > MAX_CACHE_TOTAL_BYTES {
                return Err(RuntimeQualificationError::HostRuntimeInvalid);
            }
            subcaches.push(RetainedFile { file, metadata });
        }
        match_authority = Some(CacheAuthority {
            parent,
            parent_metadata,
            main: RetainedFile {
                file: main_file,
                metadata: main_metadata,
            },
            suffixes,
            subcaches,
        });
    }
    match_authority.ok_or(RuntimeQualificationError::HostRuntimeInvalid)
}

fn validate_cache_authority(cache: &CacheAuthority) -> Result<(), RuntimeQualificationError> {
    if directory_metadata(&cache.parent)? != cache.parent_metadata
        || file_metadata(&cache.main.file, true)? != cache.main.metadata
        || cache.subcaches.len() != cache.suffixes.len()
    {
        return Err(RuntimeQualificationError::HostRuntimeChanged);
    }
    let reopened_main = File::from(
        openat(
            &cache.parent,
            CACHE_BASENAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(changed)?,
    );
    if file_metadata(&reopened_main, true)? != cache.main.metadata
        || validated_suffixes(&reopened_main)? != cache.suffixes
    {
        return Err(RuntimeQualificationError::HostRuntimeChanged);
    }
    for (suffix, retained) in cache.suffixes.iter().zip(&cache.subcaches) {
        if file_metadata(&retained.file, true)? != retained.metadata {
            return Err(RuntimeQualificationError::HostRuntimeChanged);
        }
        let mut name = OsString::from(CACHE_BASENAME);
        name.push(suffix);
        let reopened = File::from(
            openat(
                &cache.parent,
                &name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(changed)?,
        );
        if file_metadata(&reopened, true)? != retained.metadata {
            return Err(RuntimeQualificationError::HostRuntimeChanged);
        }
    }
    Ok(())
}

fn directory_metadata(file: &File) -> Result<DirectoryMetadata, RuntimeQualificationError> {
    let metadata = file.metadata().map_err(invalid)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.st_flags() & SF_RESTRICTED == 0
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    Ok(DirectoryMetadata {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode(),
        flags: metadata.st_flags(),
    })
}

fn file_metadata(
    file: &File,
    require_system: bool,
) -> Result<RuntimeFileMetadata, RuntimeQualificationError> {
    let metadata = file.metadata().map_err(invalid)?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.nlink() == 0
        || metadata.len() > MAX_CACHE_FILE_BYTES
        || (require_system
            && (metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
                || metadata.st_flags() & SF_RESTRICTED == 0))
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    Ok(metadata_document(&metadata))
}

fn metadata_document(metadata: &Metadata) -> RuntimeFileMetadata {
    RuntimeFileMetadata {
        device: metadata.dev().to_string(),
        inode: metadata.ino().to_string(),
        byte_len: metadata.len().to_string(),
        uid: metadata.uid().to_string(),
        gid: metadata.gid().to_string(),
        mode: metadata.mode().to_string(),
        link_count: metadata.nlink().to_string(),
        flags: metadata.st_flags().to_string(),
        modified_seconds: metadata.mtime().to_string(),
        modified_nanoseconds: metadata.mtime_nsec().to_string(),
        changed_seconds: metadata.ctime().to_string(),
        changed_nanoseconds: metadata.ctime_nsec().to_string(),
    }
}

fn cache_uuid(file: &File) -> Result<[u8; 16], RuntimeQualificationError> {
    let read = read_cache(file)?;
    let header = DyldCacheHeader::<Endianness>::parse(&read).map_err(invalid)?;
    let (architecture, _) = header.parse_magic().map_err(invalid)?;
    if architecture != Architecture::Aarch64 || &header.magic != b"dyld_v1  arm64e\0" {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    Ok(header.uuid)
}

fn validated_suffixes(file: &File) -> Result<Vec<OsString>, RuntimeQualificationError> {
    let read = read_cache(file)?;
    let header = DyldCacheHeader::<Endianness>::parse(&read).map_err(invalid)?;
    let (_, endian) = header.parse_magic().map_err(invalid)?;
    let mut suffixes = Vec::new();
    if let Some(subcaches) = header.subcaches(endian, &read).map_err(invalid)? {
        match subcaches {
            DyldSubCacheSlice::V1(entries) => {
                for index in 1..=entries.len() {
                    suffixes.push(OsString::from(format!(".{index}")));
                }
            }
            DyldSubCacheSlice::V2(entries) => {
                for entry in entries {
                    suffixes.push(OsString::from_vec(
                        validate_suffix_bytes(&entry.file_suffix)?.to_vec(),
                    ));
                }
            }
            _ => return Err(RuntimeQualificationError::HostRuntimeInvalid),
        }
    }
    if header.symbols_subcache_uuid(endian).is_some() {
        suffixes.push(OsString::from(".symbols"));
    }
    if suffixes.len() >= MAX_CACHE_FILES {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let unique: BTreeSet<_> = suffixes.iter().collect();
    if unique.len() != suffixes.len() {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let object_suffixes = DyldCache::<Endianness, _>::subcache_suffixes(&read).map_err(invalid)?;
    if object_suffixes
        .iter()
        .map(OsStr::new)
        .ne(suffixes.iter().map(OsString::as_os_str))
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    Ok(suffixes)
}

fn validate_suffix_bytes(raw: &[u8; 32]) -> Result<&[u8], RuntimeQualificationError> {
    let nul = raw
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
    let suffix = &raw[..nul];
    if suffix.is_empty()
        || suffix.len() > MAX_SUFFIX_BYTES
        || suffix[0] != b'.'
        || suffix
            .iter()
            .any(|byte| !byte.is_ascii() || *byte == b'/' || *byte == b'\\')
        || suffix.windows(2).any(|window| window == b"..")
        || raw[nul + 1..].iter().any(|byte| *byte != 0)
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    Ok(suffix)
}

struct CacheAnalysis {
    identity: SharedCacheIdentity,
    loaded_count: String,
    loaded_digest: String,
    dyld_stable_commands_sha256: String,
}

#[derive(Clone)]
struct ParsedImage {
    uuid: String,
    header_digest: String,
    source_ordinal: usize,
    address: u64,
    segment_digest: Option<String>,
}

struct LoadedImageObservation {
    index: u32,
    path: String,
    header: usize,
    slide: isize,
}

#[allow(clippy::too_many_lines)]
fn inspect_cache(
    authority: &CacheAuthority,
    task: &TaskSnapshot,
    hash_all: bool,
    previous: Option<&SharedCacheIdentity>,
) -> Result<CacheAnalysis, RuntimeQualificationError> {
    let main_read = read_cache(&authority.main.file)?;
    let sub_reads: Vec<_> = authority
        .subcaches
        .iter()
        .map(|file| read_cache(&file.file))
        .collect::<Result<_, _>>()?;
    let subrefs: Vec<_> = sub_reads.iter().collect();
    let cache = DyldCache::<Endianness, _>::parse(&main_read, &subrefs).map_err(invalid)?;
    if cache.architecture() != Architecture::Aarch64 {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let header = DyldCacheHeader::<Endianness>::parse(&main_read).map_err(invalid)?;
    let (_, endian) = header.parse_magic().map_err(invalid)?;
    if &header.magic != b"dyld_v1  arm64e\0"
        || header.platform.get(endian) != macho::PLATFORM_MACOS
        || header.cache_type.get(endian) != 0
        || header.os_version.get(endian) == 0
        || header.uuid != task.shared_cache_uuid
        || usize::try_from(header.shared_region_start.get(endian))
            .ok()
            .and_then(|base| base.checked_add(task.shared_cache_slide))
            != Some(task.shared_cache_base_address)
    {
        return Err(RuntimeQualificationError::HostRuntimeChanged);
    }
    let mut main = SharedCacheFileIdentity {
        ordinal: "0".to_owned(),
        uuid: hex_uuid(header.uuid),
        file_sha256: file_sha256(&authority.main.file, MAX_CACHE_FILE_BYTES)?,
        metadata: authority.main.metadata.clone(),
    };
    let mut subcaches = Vec::with_capacity(authority.subcaches.len());
    for (index, retained) in authority.subcaches.iter().enumerate() {
        let uuid = cache_uuid(&retained.file)?;
        let digest = if hash_all {
            file_sha256(&retained.file, MAX_CACHE_FILE_BYTES)?
        } else {
            previous
                .and_then(|cache| cache.subcaches.get(index))
                .ok_or(RuntimeQualificationError::HostRuntimeChanged)?
                .file_sha256
                .clone()
        };
        subcaches.push(SharedCacheFileIdentity {
            ordinal: (index + 1).to_string(),
            uuid: hex_uuid(uuid),
            file_sha256: digest,
            metadata: retained.metadata.clone(),
        });
    }
    if !hash_all {
        let expected = previous.ok_or(RuntimeQualificationError::HostRuntimeChanged)?;
        if main.file_sha256 != expected.main.file_sha256 {
            return Err(RuntimeQualificationError::HostRuntimeChanged);
        }
        main.file_sha256.clone_from(&expected.main.file_sha256);
    }

    let mut parsed_images = BTreeMap::new();
    let loaded_observations = loaded_image_observations(task)?;
    let loaded_cache_paths: BTreeSet<_> = loaded_observations
        .iter()
        .filter(|observation| observation.index != 0)
        .map(|observation| observation.path.clone())
        .collect();
    if loaded_cache_paths.len() + 1 != loaded_observations.len() {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let mut declared_paths = BTreeSet::new();
    let mut declared_count = 0usize;
    let mut cached_dyld = None;
    let mut cached_dyld_stable = None;
    let mut libsystem = None;
    let mut libiconv = None;
    for image in cache.images() {
        declared_count = declared_count
            .checked_add(1)
            .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
        if declared_count > MAX_IMAGES {
            return Err(RuntimeQualificationError::HostRuntimeInvalid);
        }
        let path = image.path().map_err(invalid)?;
        if !valid_system_install_name(path) {
            return Err(RuntimeQualificationError::HostRuntimeInvalid);
        }
        if !declared_paths.insert(path.to_owned()) {
            return Err(RuntimeQualificationError::HostRuntimeInvalid);
        }
        if path != DYLD_PATH
            && path != LIBSYSTEM_PATH
            && path != LIBICONV_PATH
            && !loaded_cache_paths.contains(path)
        {
            continue;
        }
        let (data, offset) = image.image_data_and_offset().map_err(invalid)?;
        let source_ordinal =
            if std::ptr::eq(std::ptr::from_ref(data), std::ptr::from_ref(&main_read)) {
                0
            } else {
                subrefs
                    .iter()
                    .position(|candidate| std::ptr::eq(data, *candidate))
                    .map(|index| index + 1)
                    .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?
            };
        let object = image.parse_object().map_err(invalid)?;
        if object.architecture() != Architecture::Aarch64 {
            return Err(RuntimeQualificationError::HostRuntimeInvalid);
        }
        let uuid = object
            .mach_uuid()
            .map_err(invalid)?
            .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
        let header_digest = header_commands_digest(data, offset)?;
        let segment_digest = if path == DYLD_PATH || path == LIBSYSTEM_PATH || path == LIBICONV_PATH
        {
            Some(segment_manifest(&object)?)
        } else {
            None
        };
        let parsed = ParsedImage {
            uuid: hex_uuid(uuid),
            header_digest,
            source_ordinal,
            address: image.info().address.get(endian),
            segment_digest,
        };
        if parsed_images
            .insert(path.to_owned(), parsed.clone())
            .is_some()
        {
            return Err(RuntimeQualificationError::HostRuntimeInvalid);
        }
        if path == DYLD_PATH {
            cached_dyld = Some(cache_image_identity("dyld", &parsed)?);
            let object::File::MachO64(macho) = &object else {
                return Err(RuntimeQualificationError::HostRuntimeInvalid);
            };
            cached_dyld_stable = Some(dyld_stable_commands(macho, true)?);
        } else if path == LIBSYSTEM_PATH {
            libsystem = Some(cache_image_identity("libsystem", &parsed)?);
        } else if path == LIBICONV_PATH {
            libiconv = Some(cache_image_identity("libiconv", &parsed)?);
        }
    }
    let cached_dyld = cached_dyld.ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
    if loaded_cache_paths
        .iter()
        .any(|path| !parsed_images.contains_key(path))
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let cached_dyld_stable =
        cached_dyld_stable.ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
    let cached_dyld_image = parsed_images
        .get(DYLD_PATH)
        .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
    if usize::try_from(cached_dyld_image.address)
        .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?
        .checked_add(task.shared_cache_slide)
        .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?
        != task.dyld_image_load_address
        || cached_dyld.macho_uuid != mapped_uuid(task.dyld_image_load_address as *const c_void)?
        || cached_dyld.header_commands_sha256
            != mapped_header_commands_digest(task.dyld_image_load_address as *const c_void)?
    {
        return Err(RuntimeQualificationError::HostRuntimeChanged);
    }
    let (loaded_count, loaded_digest) =
        loaded_image_identity(task, &parsed_images, &loaded_observations)?;
    let active_file_identity = ActiveCacheFileIdentity::UnavailableBeforeV18;
    Ok(CacheAnalysis {
        identity: SharedCacheIdentity {
            active_uuid: hex_uuid(task.shared_cache_uuid),
            active_file_identity,
            architecture: "aarch64".to_owned(),
            platform: header.platform.get(endian).to_string(),
            cache_type: header.cache_type.get(endian).to_string(),
            cache_os_version: header.os_version.get(endian).to_string(),
            main,
            subcaches,
            dyld: cached_dyld,
            libsystem: libsystem.ok_or(RuntimeQualificationError::HostRuntimeInvalid)?,
            libiconv: libiconv.ok_or(RuntimeQualificationError::HostRuntimeInvalid)?,
        },
        loaded_count,
        loaded_digest,
        dyld_stable_commands_sha256: cached_dyld_stable,
    })
}

fn loaded_image_observations(
    task: &TaskSnapshot,
) -> Result<Vec<LoadedImageObservation>, RuntimeQualificationError> {
    // SAFETY: the enclosing v17 task snapshot is stable and the caller brackets this complete
    // enumeration with a second TASK_DYLD_INFO snapshot.
    let count = unsafe { libc::_dyld_image_count() };
    if count == 0 || count != task.image_count || count as usize > MAX_IMAGES {
        return Err(RuntimeQualificationError::HostRuntimeChanged);
    }
    let mut observations = Vec::with_capacity(count as usize);
    for index in 0..count {
        // SAFETY: index is strictly beneath the stable count.
        let name = unsafe { libc::_dyld_get_image_name(index) };
        // SAFETY: index is strictly beneath the stable count.
        let header = unsafe { libc::_dyld_get_image_header(index) };
        // SAFETY: index is strictly beneath the stable count.
        let slide = unsafe { libc::_dyld_get_image_vmaddr_slide(index) };
        if header.is_null() || slide < 0 {
            return Err(RuntimeQualificationError::HostRuntimeInvalid);
        }
        let path = bounded_c_string(name, 4096)?;
        if index != 0 && !valid_system_install_name(&path) {
            return Err(RuntimeQualificationError::HostRuntimeInvalid);
        }
        observations.push(LoadedImageObservation {
            index,
            path,
            header: header as usize,
            slide,
        });
    }
    Ok(observations)
}

fn valid_system_install_name(path: &str) -> bool {
    path.len() <= 4096
        && (path.starts_with("/usr/lib/")
            || path.starts_with("/System/Library/")
            || path.starts_with("/System/iOSSupport/"))
        && !path
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
        && path
            .split('/')
            .all(|component| component != "." && component != "..")
}

fn cache_image_identity(
    role: &str,
    image: &ParsedImage,
) -> Result<SharedCacheImageIdentity, RuntimeQualificationError> {
    Ok(SharedCacheImageIdentity {
        role: role.to_owned(),
        source_cache_ordinal: image.source_ordinal.to_string(),
        macho_uuid: image.uuid.clone(),
        header_commands_sha256: image.header_digest.clone(),
        segment_manifest_sha256: image
            .segment_digest
            .clone()
            .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?,
    })
}

#[derive(Serialize)]
struct SegmentIdentity {
    name_sha256: String,
    address: String,
    memory_size: String,
    alignment: String,
    file_offset: String,
    file_size: String,
    flags: String,
    max_protection: String,
    initial_protection: String,
    readable: bool,
    writable: bool,
    executable: bool,
    content_binding: String,
}

fn segment_manifest<'data>(
    object: &object::File<'data, &'data ReadCache<PreadFile>>,
) -> Result<String, RuntimeQualificationError> {
    let mut segments = Vec::new();
    for segment in object.segments() {
        let SegmentFlags::MachO {
            flags,
            maxprot,
            initprot,
        } = segment.flags()
        else {
            return Err(RuntimeQualificationError::HostRuntimeInvalid);
        };
        let (file_offset, file_size) = segment.file_range();
        let permissions = segment.permissions();
        segments.push(SegmentIdentity {
            name_sha256: sha256_identity(
                segment
                    .name_bytes()
                    .map_err(invalid)?
                    .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?,
            ),
            address: segment.address().to_string(),
            memory_size: segment.size().to_string(),
            alignment: segment.align().to_string(),
            file_offset: file_offset.to_string(),
            file_size: file_size.to_string(),
            flags: flags.to_string(),
            max_protection: maxprot.to_string(),
            initial_protection: initprot.to_string(),
            readable: permissions.readable(),
            writable: permissions.writable(),
            executable: permissions.executable(),
            content_binding: "complete-source-cache-file-sha256".to_owned(),
        });
    }
    if segments.is_empty() || segments.len() > 128 {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    document_digest(&segments)
}

#[derive(Serialize)]
struct LoadedImageIdentity {
    coordinate: String,
    macho_uuid: String,
    header_commands_sha256: String,
}

fn loaded_image_identity(
    task: &TaskSnapshot,
    cache_images: &BTreeMap<String, ParsedImage>,
    observations: &[LoadedImageObservation],
) -> Result<(String, String), RuntimeQualificationError> {
    if observations.is_empty()
        || observations.len() > MAX_IMAGES
        || observations.len()
            != usize::try_from(task.image_count)
                .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?
    {
        return Err(RuntimeQualificationError::HostRuntimeChanged);
    }
    let mut loaded = Vec::with_capacity(observations.len());
    let mut loose_host = 0usize;
    for observation in observations {
        if let Some(image) = cache_images.get(&observation.path) {
            let mapped_uuid_value = mapped_uuid(observation.header as *const c_void)?;
            let mapped_digest = mapped_header_commands_digest(observation.header as *const c_void)?;
            if usize::try_from(observation.slide)
                .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?
                != task.shared_cache_slide
                || observation.header
                    != usize::try_from(image.address)
                        .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?
                        .checked_add(task.shared_cache_slide)
                        .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?
                || mapped_uuid_value != image.uuid
                || mapped_digest != image.header_digest
            {
                return Err(RuntimeQualificationError::HostRuntimeChanged);
            }
            loaded.push(LoadedImageIdentity {
                coordinate: sha256_identity(observation.path.as_bytes()),
                macho_uuid: image.uuid.clone(),
                header_commands_sha256: image.header_digest.clone(),
            });
        } else if observation.index == 0 {
            loose_host += 1;
            loaded.push(LoadedImageIdentity {
                coordinate: "proof-host".to_owned(),
                macho_uuid: mapped_uuid(observation.header as *const c_void)?,
                header_commands_sha256: mapped_header_commands_digest(
                    observation.header as *const c_void,
                )?,
            });
        } else {
            return Err(RuntimeQualificationError::HostRuntimeInvalid);
        }
    }
    if loose_host != 1 {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    loaded.sort_by(|left, right| left.coordinate.cmp(&right.coordinate));
    if loaded
        .windows(2)
        .any(|pair| pair[0].coordinate == pair[1].coordinate)
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    Ok((observations.len().to_string(), document_digest(&loaded)?))
}

fn inspect_host(
    authority: &PathAuthority,
    _task: &TaskSnapshot,
) -> Result<ProofHostIdentity, RuntimeQualificationError> {
    let bytes = bounded_file_bytes(&authority.retained.file, MAX_HOST_BYTES)?;
    let file = object::File::parse(bytes.as_slice()).map_err(invalid)?;
    if file.format() != object::BinaryFormat::MachO || file.architecture() != Architecture::Aarch64
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let uuid = file
        .mach_uuid()
        .map_err(invalid)?
        .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
    // SAFETY: Dl_info is a C record made entirely of pointers; all-zero is a valid initial state.
    let mut dl_info: libc::Dl_info = unsafe { std::mem::zeroed() };
    // SAFETY: proof_host_marker is a live local text address and dl_info points to writable storage.
    if unsafe {
        libc::dladdr(
            (proof_host_marker as *const ()).cast::<c_void>(),
            &raw mut dl_info,
        )
    } == 0
        || dl_info.dli_fbase.is_null()
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let dl_path = bounded_c_string(dl_info.dli_fname, PROC_PIDPATHINFO_MAXSIZE)?;
    let dl_authority = open_path_authority(Path::new(&dl_path), false)?;
    if dl_authority.retained.metadata != authority.retained.metadata {
        return Err(RuntimeQualificationError::HostRuntimeChanged);
    }
    // SAFETY: dyld image index zero is the main executable in the current process.
    let mapped = unsafe { libc::_dyld_get_image_header(0) };
    if mapped.is_null()
        || mapped.cast::<c_void>() != dl_info.dli_fbase
        || mapped_uuid(mapped.cast())? != hex_uuid(uuid)
        || mapped_header_commands_digest(mapped.cast())?
            != header_commands_digest(bytes.as_slice(), 0)?
    {
        return Err(RuntimeQualificationError::HostRuntimeChanged);
    }
    Ok(ProofHostIdentity {
        file_sha256: sha256_identity(&bytes),
        metadata: authority.retained.metadata.clone(),
        macho_uuid: hex_uuid(uuid),
        header_commands_sha256: header_commands_digest(bytes.as_slice(), 0)?,
    })
}

#[inline(never)]
fn proof_host_marker() {}

fn inspect_dyld(
    authority: &PathAuthority,
    task: &TaskSnapshot,
) -> Result<DyldIdentity, RuntimeQualificationError> {
    let bytes = bounded_file_bytes(&authority.retained.file, MAX_DYLD_BYTES)?;
    let slice = select_arm64e_slice(&bytes)?;
    let file = object::File::parse(slice).map_err(invalid)?;
    if file.format() != object::BinaryFormat::MachO || file.architecture() != Architecture::Aarch64
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let uuid = file
        .mach_uuid()
        .map_err(invalid)?
        .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
    let digest = header_commands_digest(slice, 0)?;
    let macho = MachOFile64::<Endianness>::parse(slice).map_err(invalid)?;
    let stable_commands_sha256 = dyld_stable_commands(&macho, false)?;
    let mapped = task.dyld_image_load_address as *const c_void;
    let mapped_uuid_value = mapped_uuid(mapped)?;
    let mapped_digest = mapped_header_commands_digest(mapped)?;
    if mapped_uuid_value != hex_uuid(uuid) {
        return Err(RuntimeQualificationError::HostRuntimeChanged);
    }
    Ok(DyldIdentity {
        file_sha256: sha256_identity(&bytes),
        metadata: authority.retained.metadata.clone(),
        arm64e_uuid: hex_uuid(uuid),
        header_commands_sha256: digest,
        mapped_header_commands_sha256: mapped_digest,
        stable_commands_sha256,
        loaded_version: task.dyld_version.clone(),
    })
}

#[derive(Serialize)]
struct DyldStableCommands {
    cpu_type: String,
    cpu_subtype: String,
    file_type: String,
    base_flags: String,
    id_dylinker_sha256: String,
    uuid: String,
    build_version_sha256: String,
    source_version_sha256: String,
}

fn dyld_stable_commands<'data, R: ReadRef<'data>>(
    file: &MachOFile64<'data, Endianness, R>,
    cached: bool,
) -> Result<String, RuntimeQualificationError> {
    let endian = file.endian();
    let header = file.macho_header();
    let cpu_subtype = header.cpusubtype.get(endian);
    let flags = header.flags.get(endian);
    if !header.is_little_endian()
        || header.cputype.get(endian) != macho::CPU_TYPE_ARM64
        || cpu_subtype & 0x00ff_ffff != CPU_SUBTYPE_ARM64E
        || header.filetype.get(endian) != macho::MH_DYLINKER
        || header.reserved.get(endian) != 0
        || cached != (flags & macho::MH_DYLIB_IN_CACHE != 0)
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let mut id_dylinker = None;
    let mut uuid = None;
    let mut build_version = None;
    let mut source_version = None;
    let mut commands = file.macho_load_commands().map_err(invalid)?;
    let mut command_count = 0usize;
    while let Some(command) = commands.next().map_err(invalid)? {
        command_count = command_count
            .checked_add(1)
            .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
        if command_count > 128 {
            return Err(RuntimeQualificationError::HostRuntimeInvalid);
        }
        match command.variant().map_err(invalid)? {
            LoadCommandVariant::IdDylinker(dylinker) => {
                if id_dylinker.is_some()
                    || command.raw_data().len() != 32
                    || dylinker.name.offset.get(endian) != 12
                    || command.string(endian, dylinker.name).map_err(invalid)?
                        != DYLD_PATH.as_bytes()
                    || &command.raw_data()[12..26] != b"/usr/lib/dyld\0"
                    || command.raw_data()[26..].iter().any(|byte| *byte != 0)
                {
                    return Err(RuntimeQualificationError::HostRuntimeInvalid);
                }
                id_dylinker = Some(sha256_identity(command.raw_data()));
            }
            LoadCommandVariant::Uuid(value)
                if command.raw_data().len()
                    != std::mem::size_of::<macho::UuidCommand<Endianness>>()
                    || uuid.replace(hex_uuid(value.uuid)).is_some() =>
            {
                return Err(RuntimeQualificationError::HostRuntimeInvalid);
            }
            LoadCommandVariant::BuildVersion(value) => {
                let expected = std::mem::size_of::<macho::BuildVersionCommand<Endianness>>()
                    .checked_add(
                        usize::try_from(value.ntools.get(endian))
                            .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?
                            .checked_mul(std::mem::size_of::<macho::BuildToolVersion<Endianness>>())
                            .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?,
                    )
                    .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
                if build_version.is_some()
                    || value.platform.get(endian) != macho::PLATFORM_MACOS
                    || command.raw_data().len() != expected
                {
                    return Err(RuntimeQualificationError::HostRuntimeInvalid);
                }
                build_version = Some(sha256_identity(command.raw_data()));
            }
            LoadCommandVariant::SourceVersion(_)
                if command.raw_data().len()
                    != std::mem::size_of::<macho::SourceVersionCommand<Endianness>>()
                    || source_version
                        .replace(sha256_identity(command.raw_data()))
                        .is_some() =>
            {
                return Err(RuntimeQualificationError::HostRuntimeInvalid);
            }
            _ => {}
        }
    }
    document_digest(&DyldStableCommands {
        cpu_type: header.cputype.get(endian).to_string(),
        cpu_subtype: cpu_subtype.to_string(),
        file_type: header.filetype.get(endian).to_string(),
        base_flags: (flags & !macho::MH_DYLIB_IN_CACHE).to_string(),
        id_dylinker_sha256: id_dylinker.ok_or(RuntimeQualificationError::HostRuntimeInvalid)?,
        uuid: uuid.ok_or(RuntimeQualificationError::HostRuntimeInvalid)?,
        build_version_sha256: build_version.ok_or(RuntimeQualificationError::HostRuntimeInvalid)?,
        source_version_sha256: source_version
            .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?,
    })
}

fn select_arm64e_slice(bytes: &[u8]) -> Result<&[u8], RuntimeQualificationError> {
    match FileKind::parse(bytes).map_err(invalid)? {
        FileKind::MachOFat32 => select_fat32(bytes),
        FileKind::MachOFat64 => select_fat64(bytes),
        _ => Err(RuntimeQualificationError::HostRuntimeInvalid),
    }
}

fn select_fat32(bytes: &[u8]) -> Result<&[u8], RuntimeQualificationError> {
    let fat = MachOFatFile32::parse(bytes).map_err(invalid)?;
    select_fat_arch(bytes, fat.arches())
}

fn select_fat64(bytes: &[u8]) -> Result<&[u8], RuntimeQualificationError> {
    let fat = MachOFatFile64::parse(bytes).map_err(invalid)?;
    select_fat_arch(bytes, fat.arches())
}

fn select_fat_arch<'a, A: FatArch>(
    bytes: &'a [u8],
    arches: &[A],
) -> Result<&'a [u8], RuntimeQualificationError> {
    let mut selected = None;
    for arch in arches {
        if arch.cputype() == macho::CPU_TYPE_ARM64
            && arch.cpusubtype() & 0x00ff_ffff == CPU_SUBTYPE_ARM64E
        {
            if selected.is_some() {
                return Err(RuntimeQualificationError::HostRuntimeInvalid);
            }
            selected = Some(arch.data(bytes).map_err(invalid)?);
        }
    }
    selected.ok_or(RuntimeQualificationError::HostRuntimeInvalid)
}

fn header_commands_digest<'data, R: ReadRef<'data>>(
    data: R,
    offset: u64,
) -> Result<String, RuntimeQualificationError> {
    let header = data.read_bytes_at(offset, 32).map_err(invalid)?;
    if u32::from_le_bytes(
        header[0..4]
            .try_into()
            .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?,
    ) != macho::MH_MAGIC_64
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let commands = usize::try_from(u32::from_le_bytes(
        header[20..24]
            .try_into()
            .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?,
    ))
    .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?;
    if commands == 0 || commands > MAX_LOAD_COMMAND_BYTES {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let total = 32usize
        .checked_add(commands)
        .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
    let bytes = data
        .read_bytes_at(
            offset,
            u64::try_from(total).map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?,
        )
        .map_err(invalid)?;
    parse_header_identity(bytes).map(|(_, digest)| digest)
}

fn mapped_header_commands_digest(
    pointer: *const c_void,
) -> Result<String, RuntimeQualificationError> {
    if pointer.is_null() {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    // SAFETY: caller supplies a dyld-published mapped Mach-O header. We first copy the fixed
    // header, validate magic and the bounded sizeofcmds, then copy exactly that mapped prefix.
    let fixed = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), 32) };
    if u32::from_le_bytes(
        fixed[0..4]
            .try_into()
            .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?,
    ) != macho::MH_MAGIC_64
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let commands = usize::try_from(u32::from_le_bytes(
        fixed[20..24]
            .try_into()
            .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?,
    ))
    .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?;
    if commands == 0 || commands > MAX_LOAD_COMMAND_BYTES {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let total = 32usize
        .checked_add(commands)
        .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
    // SAFETY: validated Mach-O header declares a bounded mapped load-command region.
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), total) };
    parse_header_identity(bytes).map(|(_, digest)| digest)
}

fn mapped_uuid(pointer: *const c_void) -> Result<String, RuntimeQualificationError> {
    if pointer.is_null() {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    mapped_header_commands_digest(pointer)?;
    // SAFETY: the preceding header validation establishes the bounded mapped prefix.
    let fixed = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), 32) };
    let commands = usize::try_from(u32::from_le_bytes(
        fixed[20..24]
            .try_into()
            .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?,
    ))
    .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?;
    let total = 32usize
        .checked_add(commands)
        .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
    // SAFETY: same mapped Mach-O prefix validation as above.
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), total) };
    parse_header_identity(bytes).map(|(uuid, _)| hex_uuid(uuid))
}

fn parse_header_identity(bytes: &[u8]) -> Result<([u8; 16], String), RuntimeQualificationError> {
    let header = macho::MachHeader64::<Endianness>::parse(bytes, 0).map_err(invalid)?;
    let endian = header.endian().map_err(invalid)?;
    if !header.is_little_endian()
        || header.cputype(endian) != macho::CPU_TYPE_ARM64
        || header.ncmds(endian) == 0
        || header.ncmds(endian) > 128
        || usize::try_from(header.sizeofcmds(endian)).map_err(invalid)? > MAX_LOAD_COMMAND_BYTES
        || bytes.len()
            != 32usize
                .checked_add(usize::try_from(header.sizeofcmds(endian)).map_err(invalid)?)
                .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let mut commands = header.load_commands(endian, bytes, 0).map_err(invalid)?;
    let mut seen = 0u32;
    let mut uuid = None;
    while let Some(command) = commands.next().map_err(invalid)? {
        seen = seen
            .checked_add(1)
            .ok_or(RuntimeQualificationError::HostRuntimeInvalid)?;
        if let Some(command_uuid) = command.uuid().map_err(invalid)?
            && uuid.replace(command_uuid.uuid).is_some()
        {
            return Err(RuntimeQualificationError::HostRuntimeInvalid);
        }
    }
    if seen != header.ncmds(endian) {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    Ok((
        uuid.ok_or(RuntimeQualificationError::HostRuntimeInvalid)?,
        sha256_identity(bytes),
    ))
}

fn file_sha256(file: &File, max: u64) -> Result<String, RuntimeQualificationError> {
    let metadata = file.metadata().map_err(invalid)?;
    if metadata.len() == 0 || metadata.len() > max {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut offset = 0u64;
    while offset < metadata.len() {
        let remaining = usize::try_from((metadata.len() - offset).min(buffer.len() as u64))
            .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?;
        read_exact_at(file, &mut buffer[..remaining], offset)?;
        digest.update(&buffer[..remaining]);
        offset +=
            u64::try_from(remaining).map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?;
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn bounded_file_bytes(file: &File, max: u64) -> Result<Vec<u8>, RuntimeQualificationError> {
    let length = file.metadata().map_err(invalid)?.len();
    if length == 0 || length > max {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let mut bytes = vec![
        0;
        usize::try_from(length)
            .map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?
    ];
    read_exact_at(file, &mut bytes, 0)?;
    Ok(bytes)
}

fn read_exact_at(
    file: &File,
    mut bytes: &mut [u8],
    mut offset: u64,
) -> Result<(), RuntimeQualificationError> {
    while !bytes.is_empty() {
        let read = file.read_at(bytes, offset).map_err(invalid)?;
        if read == 0 {
            return Err(RuntimeQualificationError::HostRuntimeInvalid);
        }
        offset += u64::try_from(read).map_err(|_| RuntimeQualificationError::HostRuntimeInvalid)?;
        bytes = &mut bytes[read..];
    }
    Ok(())
}

struct PreadFile {
    file: File,
    position: u64,
    length: u64,
    total_read: u64,
}

impl ReadCacheOps for PreadFile {
    fn len(&mut self) -> Result<u64, ()> {
        Ok(self.length)
    }

    fn seek(&mut self, position: u64) -> Result<u64, ()> {
        if position > self.length {
            return Err(());
        }
        self.position = position;
        Ok(position)
    }

    fn read(&mut self, bytes: &mut [u8]) -> Result<usize, ()> {
        self.reserve_read(bytes.len())?;
        let read = self.file.read_at(bytes, self.position).map_err(|_| ())?;
        self.position = self.position.checked_add(read as u64).ok_or(())?;
        Ok(read)
    }

    fn read_exact(&mut self, mut bytes: &mut [u8]) -> Result<(), ()> {
        self.reserve_read(bytes.len())?;
        while !bytes.is_empty() {
            let read = self.file.read_at(bytes, self.position).map_err(|_| ())?;
            if read == 0 {
                return Err(());
            }
            self.position = self.position.checked_add(read as u64).ok_or(())?;
            bytes = &mut bytes[read..];
        }
        Ok(())
    }
}

impl PreadFile {
    fn reserve_read(&mut self, length: usize) -> Result<(), ()> {
        if length > MAX_READ_CACHE_REQUEST_BYTES {
            return Err(());
        }
        self.total_read = self
            .total_read
            .checked_add(u64::try_from(length).map_err(|_| ())?)
            .ok_or(())?;
        if self.total_read > MAX_READ_CACHE_TOTAL_BYTES {
            return Err(());
        }
        Ok(())
    }
}

fn read_cache(file: &File) -> Result<ReadCache<PreadFile>, RuntimeQualificationError> {
    let length = file.metadata().map_err(invalid)?.len();
    if length == 0 || length > MAX_CACHE_FILE_BYTES {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    Ok(ReadCache::new(PreadFile {
        file: file.try_clone().map_err(invalid)?,
        position: 0,
        length,
        total_read: 0,
    }))
}

fn platform_identity() -> Result<DarwinPlatformIdentity, RuntimeQualificationError> {
    Ok(DarwinPlatformIdentity {
        kernel_uuid: sysctl_string("kern.uuid")?,
        os_product_version: sysctl_string("kern.osproductversion")?,
        os_build_version: sysctl_string("kern.osversion")?,
        os_release: sysctl_string("kern.osrelease")?,
        kernel_version: sysctl_string("kern.version")?,
        machine: sysctl_string("hw.machine")?,
        model: sysctl_string("hw.model")?,
        cpu_type: sysctl_i32("hw.cputype")?.to_string(),
        cpu_subtype: sysctl_i32("hw.cpusubtype")?.to_string(),
        arm64_capability: sysctl_i32("hw.optional.arm64")?.to_string(),
    })
}

fn sysctl_string(name: &str) -> Result<String, RuntimeQualificationError> {
    let name = CString::new(name).map_err(invalid)?;
    let mut length = 0usize;
    // SAFETY: first sysctlbyname query supplies no output buffer and receives its required size.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &raw mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || length == 0
        || length > MAX_SYSCTL_BYTES
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    let mut bytes = vec![0u8; length];
    // SAFETY: the allocated buffer is exactly `length`; no input value is provided.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            &raw mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || length == 0
        || length > bytes.len()
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    bytes.truncate(length);
    if bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    bytes.pop();
    let value = String::from_utf8(bytes).map_err(invalid)?;
    if value.is_empty() {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    Ok(value)
}

fn sysctl_i32(name: &str) -> Result<i32, RuntimeQualificationError> {
    let name = CString::new(name).map_err(invalid)?;
    let mut value = 0i32;
    let mut length = std::mem::size_of::<i32>();
    // SAFETY: the output pointer and exact size refer to an initialized i32 local.
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&raw mut value).cast(),
            &raw mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || length != std::mem::size_of::<i32>()
    {
        return Err(RuntimeQualificationError::HostRuntimeInvalid);
    }
    Ok(value)
}

fn hex_uuid(uuid: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(32);
    for byte in uuid {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn invalid<T>(_error: T) -> RuntimeQualificationError {
    RuntimeQualificationError::HostRuntimeInvalid
}

fn changed<T>(_error: T) -> RuntimeQualificationError {
    RuntimeQualificationError::HostRuntimeChanged
}

#[cfg(test)]
mod tests {
    use super::validate_suffix_bytes;

    #[test]
    fn suffix_validation_rejects_cross_boundary_names() {
        for malformed in [
            &b"../evil"[..],
            &b".\\evil"[..],
            &b"./evil"[..],
            &b".a..b"[..],
        ] {
            let mut raw = [0u8; 32];
            raw[..malformed.len()].copy_from_slice(malformed);
            assert!(validate_suffix_bytes(&raw).is_err());
        }
    }

    #[test]
    fn suffix_validation_requires_exact_nul_padding() {
        let mut unterminated = [b'a'; 32];
        unterminated[0] = b'.';
        assert!(validate_suffix_bytes(&unterminated).is_err());

        let mut trailing = [0u8; 32];
        trailing[..3].copy_from_slice(b".01");
        trailing[4] = b'x';
        assert!(validate_suffix_bytes(&trailing).is_err());
    }
}
