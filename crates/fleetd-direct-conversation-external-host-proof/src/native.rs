//! Proof-local qualification and private materialization of native artifacts.
//!
//! Qualification consumes only package-loader-owned bytes reached through the
//! exact Fleetd package proof. It never executes a command and deliberately
//! makes no process-isolation claim. Mach-O interpretation is delegated to the
//! pinned `object` parser rather than reproduced here.

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use gooir_fleetd_direct_conversation_package_proof::{
    AttesterDeploymentLock, ProviderPackageBinding, VerifiedPackageSet,
};
use gooir_package::OwnedResource;
use object::read::macho::{LoadCommandVariant, MachOFile64, Segment};
use object::{Architecture, FileKind, Object, ObjectKind, macho};
use rustix::fs::{Dir, Mode, OFlags, fchmod, mkdirat, open, openat};
use rustix::process::geteuid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// Exact artifact-qualification profile identity.
pub const NATIVE_ARTIFACT_QUALIFICATION_ID: &str =
    "org.gooi.proof/fleetd-native-command-private-materialization@0.1.0";

const QUALIFICATION_PROTOCOL: &str =
    "org.gooi.proof.fleetd-native-command-artifact-qualification/v1";
const ARTIFACT_LOCK_PROTOCOL: &str = "org.gooi.proof.fleetd-native-command-artifact-lock/v1";
const TARGET_TRIPLE: &str = "aarch64-apple-darwin";
const FORMAT: &str = "mach-o-64";
const ARCHITECTURE: &str = "aarch64";
const KIND: &str = "executable";
const PARSER: &str = "object@0.39.1/read::macho::MachOFile64";
const MATERIALIZATION_PROFILE: &str =
    "owner-only-fresh-root-descriptor-anchored-exact-bytes-no-execution/v1";
const LOADER_PROFILE: &str = "thin-arm64-macho64;commands=segment64,dyld-info-only,symtab,dysymtab,load-dylinker,uuid,build-version,source-version,main,load-dylib,function-starts,data-in-code,code-signature;dyld=/usr/lib/dyld;dylibs=/usr/lib/libiconv.2.dylib,/usr/lib/libSystem.B.dylib;dylib-use-flags=absent;platform=single-macos-build-version;entry=single-main-in-file;header=little-endian,cpu-type-arm64,cpu-subtype-arm64-all,reserved-zero,flags-noundefs+dyldlink+twolevel+pie+has-tlv-descriptors;max-commands=64/v1";
const EXECUTABLE_NAME: &str = "artifact";
const CWD_NAME: &str = "cwd";
const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_OPAQUE_BYTES: usize = 4 * 1024;
const REQUIRED_MACHO_FLAGS: u32 = macho::MH_NOUNDEFS
    | macho::MH_DYLDLINK
    | macho::MH_TWOLEVEL
    | macho::MH_PIE
    | macho::MH_HAS_TLV_DESCRIPTORS;

/// Closed artifact role bound before qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeArtifactRole {
    Provider,
    Attester,
}

/// Content-addressed qualification of native artifact format and materialization.
///
/// This deliberately makes no claim about launch, inherited authority,
/// process supervision, or isolation. It closes the artifact's declared
/// loader/dependency names and header surface, but the identities and behavior
/// of dyld and the named system libraries remain deliberately unqualified for
/// the later complete native-runtime qualification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifactQualification {
    qualification_id: String,
    protocol: String,
    profile: String,
    target_triple: String,
    format: String,
    architecture: String,
    kind: String,
    parser: String,
    materialization_profile: String,
    loader_profile: String,
}

impl NativeArtifactQualification {
    fn current() -> Result<Self, NativeQualificationError> {
        ensure_supported_platform()?;
        let mut qualification = Self {
            qualification_id: placeholder_identity(),
            protocol: QUALIFICATION_PROTOCOL.to_owned(),
            profile: NATIVE_ARTIFACT_QUALIFICATION_ID.to_owned(),
            target_triple: TARGET_TRIPLE.to_owned(),
            format: FORMAT.to_owned(),
            architecture: ARCHITECTURE.to_owned(),
            kind: KIND.to_owned(),
            parser: PARSER.to_owned(),
            materialization_profile: MATERIALIZATION_PROFILE.to_owned(),
            loader_profile: LOADER_PROFILE.to_owned(),
        };
        qualification.qualification_id = qualification.derived_id()?;
        qualification.validate()?;
        Ok(qualification)
    }

    /// Content identity of this exact closed profile.
    #[must_use]
    pub fn qualification_id(&self) -> &str {
        &self.qualification_id
    }

    /// Exact proof-local artifact qualification profile.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Revalidate every closed profile field and content identity.
    ///
    /// # Errors
    ///
    /// Refuses unsupported hosts or any profile/identity drift.
    pub fn validate(&self) -> Result<(), NativeQualificationError> {
        ensure_supported_platform()?;
        if self.protocol != QUALIFICATION_PROTOCOL
            || self.profile != NATIVE_ARTIFACT_QUALIFICATION_ID
            || self.target_triple != TARGET_TRIPLE
            || self.format != FORMAT
            || self.architecture != ARCHITECTURE
            || self.kind != KIND
            || self.parser != PARSER
            || self.materialization_profile != MATERIALIZATION_PROFILE
            || self.loader_profile != LOADER_PROFILE
        {
            return Err(NativeQualificationError::QualificationIdentityChanged);
        }
        validate_sha256(&self.qualification_id)?;
        if self.qualification_id != self.derived_id()? {
            return Err(NativeQualificationError::QualificationIdentityChanged);
        }
        Ok(())
    }

    fn derived_id(&self) -> Result<String, NativeQualificationError> {
        #[derive(Serialize)]
        struct Body<'a> {
            protocol: &'a str,
            profile: &'a str,
            target_triple: &'a str,
            format: &'a str,
            architecture: &'a str,
            kind: &'a str,
            parser: &'a str,
            materialization_profile: &'a str,
            loader_profile: &'a str,
        }
        document_digest(&Body {
            protocol: &self.protocol,
            profile: &self.profile,
            target_triple: &self.target_triple,
            format: &self.format,
            architecture: &self.architecture,
            kind: &self.kind,
            parser: &self.parser,
            materialization_profile: &self.materialization_profile,
            loader_profile: &self.loader_profile,
        })
    }
}

/// Persistent, path-free lock for one qualified package-owned artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedNativeArtifactLock {
    lock_id: String,
    protocol: String,
    role: NativeArtifactRole,
    implementation: String,
    package: String,
    package_digest: String,
    resource: String,
    resource_digest: String,
    qualification: NativeArtifactQualification,
}

impl QualifiedNativeArtifactLock {
    fn new(
        role: NativeArtifactRole,
        implementation: impl Into<String>,
        package: impl Into<String>,
        package_digest: impl Into<String>,
        resource: impl Into<String>,
        resource_digest: impl Into<String>,
        qualification: NativeArtifactQualification,
    ) -> Result<Self, NativeQualificationError> {
        let mut lock = Self {
            lock_id: placeholder_identity(),
            protocol: ARTIFACT_LOCK_PROTOCOL.to_owned(),
            role,
            implementation: implementation.into(),
            package: package.into(),
            package_digest: package_digest.into(),
            resource: resource.into(),
            resource_digest: resource_digest.into(),
            qualification,
        };
        lock.lock_id = lock.derived_id()?;
        lock.validate()?;
        Ok(lock)
    }

    /// Content identity of the complete role/package/artifact-qualification lock.
    #[must_use]
    pub fn lock_id(&self) -> &str {
        &self.lock_id
    }

    /// Closed provider or attester role.
    #[must_use]
    pub const fn role(&self) -> NativeArtifactRole {
        self.role
    }

    /// Exact implementation selected by the verified package proof.
    #[must_use]
    pub fn implementation(&self) -> &str {
        &self.implementation
    }

    /// Exact package identity.
    #[must_use]
    pub fn package(&self) -> &str {
        &self.package
    }

    /// Exact package manifest digest.
    #[must_use]
    pub fn package_digest(&self) -> &str {
        &self.package_digest
    }

    /// Exact package-local resource name.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Independently rehashed exact artifact digest.
    #[must_use]
    pub fn resource_digest(&self) -> &str {
        &self.resource_digest
    }

    /// Exact native artifact qualification.
    #[must_use]
    pub const fn qualification(&self) -> &NativeArtifactQualification {
        &self.qualification
    }

    /// Revalidate the complete path-free lock and identity.
    ///
    /// # Errors
    ///
    /// Refuses malformed coordinates, digest drift, or qualification drift.
    pub fn validate(&self) -> Result<(), NativeQualificationError> {
        if self.protocol != ARTIFACT_LOCK_PROTOCOL {
            return Err(NativeQualificationError::ArtifactLockChanged);
        }
        validate_opaque(&self.implementation)?;
        validate_opaque(&self.package)?;
        validate_sha256(&self.package_digest)?;
        validate_opaque(&self.resource)?;
        validate_sha256(&self.resource_digest)?;
        self.qualification.validate()?;
        validate_sha256(&self.lock_id)?;
        if self.lock_id != self.derived_id()? {
            return Err(NativeQualificationError::ArtifactLockChanged);
        }
        Ok(())
    }

    fn derived_id(&self) -> Result<String, NativeQualificationError> {
        #[derive(Serialize)]
        struct Body<'a> {
            protocol: &'a str,
            role: NativeArtifactRole,
            implementation: &'a str,
            package: &'a str,
            package_digest: &'a str,
            resource: &'a str,
            resource_digest: &'a str,
            qualification: &'a NativeArtifactQualification,
        }
        document_digest(&Body {
            protocol: &self.protocol,
            role: self.role,
            implementation: &self.implementation,
            package: &self.package,
            package_digest: &self.package_digest,
            resource: &self.resource,
            resource_digest: &self.resource_digest,
            qualification: &self.qualification,
        })
    }
}

/// Live private materialization of one qualified package-owned artifact.
///
/// Its custom debug representation deliberately excludes all private paths.
pub struct QualifiedNativeArtifact {
    lock: QualifiedNativeArtifactLock,
    private_root: TempDir,
    private_parent_path: PathBuf,
    private_parent: File,
    private_parent_identity: DirectoryIdentity,
    root_name: OsString,
    root: File,
    executable: File,
    cwd: File,
    root_identity: DirectoryIdentity,
    executable_identity: FileIdentity,
    cwd_identity: DirectoryIdentity,
}

impl fmt::Debug for QualifiedNativeArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedNativeArtifact")
            .field("lock", &self.lock)
            .field("private_materialization", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl QualifiedNativeArtifact {
    /// Persistent, path-free role/package/artifact-qualification lock.
    #[must_use]
    pub const fn lock(&self) -> &QualifiedNativeArtifactLock {
        &self.lock
    }

    /// Revalidate root, executable, and empty cwd through retained descriptors.
    ///
    /// # Errors
    ///
    /// Refuses path replacement, links, ownership/mode/size changes, byte
    /// tampering, a nonempty cwd, or persistent lock drift.
    pub fn revalidate(&self) -> Result<(), NativeQualificationError> {
        self.lock.validate()?;
        if !self.private_root.path().is_absolute() {
            return Err(NativeQualificationError::PrivateRootChanged);
        }
        validate_private_parent(
            &self.private_parent_path,
            &self.private_parent,
            &self.private_parent_identity,
        )?;
        validate_private_root_path(
            &self.private_parent,
            &self.root_name,
            &self.root_identity,
            &self.root,
        )?;
        validate_materialized_executable(
            &self.root,
            &self.executable,
            &self.executable_identity,
            self.lock.resource_digest(),
        )?;
        validate_empty_cwd(&self.root, &self.cwd, &self.cwd_identity)
    }

    /// Revalidate and borrow the minimum authority required by one immediate
    /// proof-local spawn. The executable path and cwd descriptor cannot escape
    /// this crate or outlive the qualified materialization.
    pub(super) fn revalidated_spawn_access(
        &self,
    ) -> Result<NativeSpawnAccess<'_>, NativeQualificationError> {
        self.revalidate()?;
        Ok(NativeSpawnAccess {
            executable_path: self.private_root.path().join(EXECUTABLE_NAME),
            cwd: self.cwd.as_fd(),
        })
    }
}

/// Borrow-scoped, path-private spawn authority for the supervisor module.
pub(super) struct NativeSpawnAccess<'artifact> {
    executable_path: PathBuf,
    cwd: BorrowedFd<'artifact>,
}

impl NativeSpawnAccess<'_> {
    pub(super) fn executable_path(&self) -> &Path {
        &self.executable_path
    }

    pub(super) fn cwd(&self) -> BorrowedFd<'_> {
        self.cwd
    }
}

/// Qualify and privately materialize one exactly selected provider artifact.
///
/// # Errors
///
/// Refuses unsupported hosts, a binding not retained by the verified package
/// set, changed bytes, non-thin/non-arm64/non-executable Mach-O, or unsafe
/// private materialization.
pub fn qualify_provider(
    packages: &VerifiedPackageSet,
    binding: &ProviderPackageBinding,
    private_parent: &Path,
) -> Result<QualifiedNativeArtifact, NativeQualificationError> {
    let resource = packages.provider_artifact(binding).ok_or(
        NativeQualificationError::PackageBindingMismatch(NativeArtifactRole::Provider),
    )?;
    let lock = QualifiedNativeArtifactLock::new(
        NativeArtifactRole::Provider,
        binding.implementation.clone(),
        binding.package.as_str(),
        binding.package_digest.as_str(),
        binding.resource.as_str(),
        binding.resource_digest.as_str(),
        NativeArtifactQualification::current()?,
    )?;
    qualify_owned_resource(resource, lock, NativeArtifactRole::Provider, private_parent)
}

/// Qualify and privately materialize the exact independently packaged attester.
///
/// # Errors
///
/// Refuses unsupported hosts, a binding not retained by the verified package
/// set, changed bytes, non-thin/non-arm64/non-executable Mach-O, or unsafe
/// private materialization.
pub fn qualify_attester(
    packages: &VerifiedPackageSet,
    binding: &AttesterDeploymentLock,
    private_parent: &Path,
) -> Result<QualifiedNativeArtifact, NativeQualificationError> {
    let resource = packages.attester_resource(binding).ok_or(
        NativeQualificationError::PackageBindingMismatch(NativeArtifactRole::Attester),
    )?;
    let lock = QualifiedNativeArtifactLock::new(
        NativeArtifactRole::Attester,
        binding.implementation.clone(),
        binding.package.as_str(),
        binding.package_digest.as_str(),
        binding.resource.as_str(),
        binding.resource_digest.as_str(),
        NativeArtifactQualification::current()?,
    )?;
    qualify_owned_resource(resource, lock, NativeArtifactRole::Attester, private_parent)
}

fn qualify_owned_resource(
    resource: &OwnedResource,
    lock: QualifiedNativeArtifactLock,
    expected_role: NativeArtifactRole,
    private_parent: &Path,
) -> Result<QualifiedNativeArtifact, NativeQualificationError> {
    ensure_supported_platform()?;
    lock.validate()?;
    if lock.role != expected_role {
        return Err(NativeQualificationError::RoleMismatch);
    }
    if resource.name().as_str() != lock.resource
        || resource.digest().as_str() != lock.resource_digest
        || resource.media_type() != "application/octet-stream"
    {
        return Err(NativeQualificationError::PackageBindingMismatch(
            expected_role,
        ));
    }
    let bytes = resource.bytes();
    if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(NativeQualificationError::ArtifactSizeInvalid);
    }
    let digest = sha256_identity(bytes);
    if digest != resource.digest().as_str() || digest != lock.resource_digest {
        return Err(NativeQualificationError::ResourceDigestMismatch);
    }
    validate_macho(bytes)?;
    materialize(bytes, lock, private_parent)
}

fn validate_macho(bytes: &[u8]) -> Result<(), NativeQualificationError> {
    if FileKind::parse(bytes).map_err(|_| NativeQualificationError::InvalidMachO)?
        != FileKind::MachO64
    {
        return Err(NativeQualificationError::InvalidMachO);
    }
    let file = MachOFile64::<object::Endianness>::parse(bytes)
        .map_err(|_| NativeQualificationError::InvalidMachO)?;
    if !file.is_little_endian() {
        return Err(NativeQualificationError::WrongArchitecture);
    }
    if file.architecture() != Architecture::Aarch64 {
        return Err(NativeQualificationError::WrongArchitecture);
    }
    let endian = file.endian();
    let header = file.macho_header();
    if header.cputype.get(endian) != macho::CPU_TYPE_ARM64
        || header.cpusubtype.get(endian) != macho::CPU_SUBTYPE_ARM64_ALL
    {
        return Err(NativeQualificationError::WrongArchitecture);
    }
    if header.reserved.get(endian) != 0 {
        return Err(NativeQualificationError::DynamicLinkageRejected);
    }
    if header.flags.get(endian) != REQUIRED_MACHO_FLAGS {
        return Err(NativeQualificationError::DynamicLinkageRejected);
    }
    if file.kind() != ObjectKind::Executable {
        return Err(NativeQualificationError::NotExecutable);
    }
    validate_dynamic_linkage(&file)?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the closed load-command allowlist is clearer when audited as one exhaustive match"
)]
fn validate_dynamic_linkage(
    file: &MachOFile64<'_, object::Endianness>,
) -> Result<(), NativeQualificationError> {
    const DYLD: &[u8] = b"/usr/lib/dyld";
    const LIBICONV: &[u8] = b"/usr/lib/libiconv.2.dylib";
    const LIBSYSTEM: &[u8] = b"/usr/lib/libSystem.B.dylib";
    const MAX_LOAD_COMMANDS: usize = 64;

    let endian = file.endian();
    let data = file.data();
    let mut commands = file
        .macho_load_commands()
        .map_err(|_| NativeQualificationError::InvalidMachO)?;
    let mut command_count = 0_usize;
    let mut segment = false;
    let mut dyld_info = false;
    let mut symtab = false;
    let mut dysymtab = false;
    let mut dyld = false;
    let mut uuid = false;
    let mut build_version = false;
    let mut source_version = false;
    let mut entry_point = false;
    let mut libiconv = false;
    let mut libsystem = false;
    let mut function_starts = false;
    let mut data_in_code = false;
    let mut code_signature = false;
    while let Some(command) = commands
        .next()
        .map_err(|_| NativeQualificationError::InvalidMachO)?
    {
        command_count = command_count
            .checked_add(1)
            .ok_or(NativeQualificationError::DynamicLinkageRejected)?;
        if command_count > MAX_LOAD_COMMANDS {
            return Err(NativeQualificationError::DynamicLinkageRejected);
        }
        let variant = command
            .variant()
            .map_err(|_| NativeQualificationError::InvalidMachO)?;
        match variant {
            LoadCommandVariant::Segment64(segment_command, section_data)
                if command.cmd() == macho::LC_SEGMENT_64 =>
            {
                segment_command
                    .data(endian, data)
                    .map_err(|()| NativeQualificationError::InvalidMachO)?;
                segment_command
                    .sections(endian, section_data)
                    .map_err(|_| NativeQualificationError::InvalidMachO)?;
                segment = true;
            }
            LoadCommandVariant::DyldInfo(info)
                if command.cmd() == macho::LC_DYLD_INFO_ONLY && !dyld_info =>
            {
                for (offset, size) in [
                    (info.rebase_off.get(endian), info.rebase_size.get(endian)),
                    (info.bind_off.get(endian), info.bind_size.get(endian)),
                    (
                        info.weak_bind_off.get(endian),
                        info.weak_bind_size.get(endian),
                    ),
                    (
                        info.lazy_bind_off.get(endian),
                        info.lazy_bind_size.get(endian),
                    ),
                    (info.export_off.get(endian), info.export_size.get(endian)),
                ] {
                    validate_file_range(offset, size, data.len())?;
                }
                dyld_info = true;
            }
            LoadCommandVariant::Symtab(table) if command.cmd() == macho::LC_SYMTAB && !symtab => {
                table
                    .symbols::<macho::MachHeader64<object::Endianness>, _>(endian, data)
                    .map_err(|_| NativeQualificationError::InvalidMachO)?;
                validate_file_range(
                    table.stroff.get(endian),
                    table.strsize.get(endian),
                    data.len(),
                )?;
                symtab = true;
            }
            LoadCommandVariant::Dysymtab(table)
                if command.cmd() == macho::LC_DYSYMTAB && !dysymtab =>
            {
                table
                    .indirect_symbols(endian, data)
                    .map_err(|_| NativeQualificationError::InvalidMachO)?;
                dysymtab = true;
            }
            LoadCommandVariant::LoadDylinker(dylinker) => {
                let name = command
                    .string(endian, dylinker.name)
                    .map_err(|_| NativeQualificationError::InvalidMachO)?;
                if dyld || name != DYLD {
                    return Err(NativeQualificationError::DynamicLinkageRejected);
                }
                dyld = true;
            }
            LoadCommandVariant::Uuid(_) if command.cmd() == macho::LC_UUID && !uuid => {
                uuid = true;
            }
            LoadCommandVariant::BuildVersion(build)
                if command.cmd() == macho::LC_BUILD_VERSION && !build_version =>
            {
                let tool_bytes = usize::try_from(build.ntools.get(endian))
                    .ok()
                    .and_then(|count| {
                        count.checked_mul(
                            mem::size_of::<macho::BuildToolVersion<object::Endianness>>(),
                        )
                    })
                    .and_then(|size| {
                        mem::size_of::<macho::BuildVersionCommand<object::Endianness>>()
                            .checked_add(size)
                    })
                    .ok_or(NativeQualificationError::InvalidMachO)?;
                if command.raw_data().len() != tool_bytes {
                    return Err(NativeQualificationError::InvalidMachO);
                }
                if build.platform.get(endian) != macho::PLATFORM_MACOS {
                    return Err(NativeQualificationError::DynamicLinkageRejected);
                }
                build_version = true;
            }
            LoadCommandVariant::SourceVersion(_)
                if command.cmd() == macho::LC_SOURCE_VERSION && !source_version =>
            {
                source_version = true;
            }
            LoadCommandVariant::EntryPoint(entry)
                if command.cmd() == macho::LC_MAIN && !entry_point =>
            {
                let offset = entry.entryoff.get(endian);
                if offset == 0 || offset >= data.len() as u64 {
                    return Err(NativeQualificationError::NotExecutable);
                }
                entry_point = true;
            }
            LoadCommandVariant::Dylib(dylib) => {
                if command.cmd() != macho::LC_LOAD_DYLIB {
                    return Err(NativeQualificationError::DynamicLinkageRejected);
                }
                if command
                    .dylib_use_flags(endian, dylib)
                    .map_err(|_| NativeQualificationError::InvalidMachO)?
                    .is_some()
                {
                    return Err(NativeQualificationError::DynamicLinkageRejected);
                }
                let name = command
                    .string(endian, dylib.dylib.name)
                    .map_err(|_| NativeQualificationError::InvalidMachO)?;
                match name {
                    LIBICONV if !libiconv => libiconv = true,
                    LIBSYSTEM if !libsystem => libsystem = true,
                    _ => return Err(NativeQualificationError::DynamicLinkageRejected),
                }
            }
            LoadCommandVariant::LinkeditData(linkedit) => {
                validate_file_range(
                    linkedit.dataoff.get(endian),
                    linkedit.datasize.get(endian),
                    data.len(),
                )?;
                match command.cmd() {
                    macho::LC_FUNCTION_STARTS if !function_starts => {
                        let mut starts = linkedit
                            .function_starts(endian, data, 0)
                            .map_err(|_| NativeQualificationError::InvalidMachO)?;
                        while starts
                            .next()
                            .map_err(|_| NativeQualificationError::InvalidMachO)?
                            .is_some()
                        {}
                        function_starts = true;
                    }
                    macho::LC_DATA_IN_CODE if !data_in_code => data_in_code = true,
                    macho::LC_CODE_SIGNATURE if !code_signature => code_signature = true,
                    _ => return Err(NativeQualificationError::DynamicLinkageRejected),
                }
            }
            _ => return Err(NativeQualificationError::DynamicLinkageRejected),
        }
    }
    if !segment
        || !dyld_info
        || !symtab
        || !dysymtab
        || !dyld
        || !uuid
        || !build_version
        || !source_version
        || !entry_point
        || !libiconv
        || !libsystem
        || !function_starts
        || !data_in_code
        || !code_signature
    {
        return Err(NativeQualificationError::DynamicLinkageRejected);
    }
    Ok(())
}

fn validate_file_range(
    offset: u32,
    size: u32,
    file_size: usize,
) -> Result<(), NativeQualificationError> {
    let offset = usize::try_from(offset).map_err(|_| NativeQualificationError::InvalidMachO)?;
    let size = usize::try_from(size).map_err(|_| NativeQualificationError::InvalidMachO)?;
    let end = offset
        .checked_add(size)
        .ok_or(NativeQualificationError::InvalidMachO)?;
    if end > file_size {
        return Err(NativeQualificationError::InvalidMachO);
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the materialization transaction is intentionally linear and auditable"
)]
fn materialize(
    bytes: &[u8],
    lock: QualifiedNativeArtifactLock,
    private_parent: &Path,
) -> Result<QualifiedNativeArtifact, NativeQualificationError> {
    if !private_parent.is_absolute() {
        return Err(NativeQualificationError::PrivateParentInvalid);
    }
    let parent_metadata = fs::symlink_metadata(private_parent)
        .map_err(|_| NativeQualificationError::PrivateParentInvalid)?;
    if parent_metadata.file_type().is_symlink() {
        return Err(NativeQualificationError::PrivateParentInvalid);
    }
    let canonical_parent = fs::canonicalize(private_parent)
        .map_err(|_| NativeQualificationError::PrivateParentInvalid)?;
    let private_parent_descriptor = File::from(
        open(
            &canonical_parent,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| NativeQualificationError::PrivateParentInvalid)?,
    );
    let private_parent_identity = validate_directory(&private_parent_descriptor, 0o700)
        .map_err(|_| NativeQualificationError::PrivateParentInvalid)?;
    let private_root = tempfile::Builder::new()
        .prefix(".fleetd-direct-conversation-native-")
        .tempdir_in(&canonical_parent)
        .map_err(|source| filesystem("create private materialization root", source))?;
    fs::set_permissions(
        private_root.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .map_err(|source| filesystem("set private root permissions", source))?;
    let root_name = private_root
        .path()
        .file_name()
        .ok_or(NativeQualificationError::PrivateRootChanged)?
        .to_os_string();
    let root = File::from(
        openat(
            &private_parent_descriptor,
            &root_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| filesystem("open private materialization root", source))?,
    );
    validate_directory(&root, 0o700)?;

    mkdirat(&root, CWD_NAME, Mode::RUSR | Mode::WUSR | Mode::XUSR)
        .map_err(|source| filesystem("create empty private cwd", source))?;
    let cwd = File::from(
        openat(
            &root,
            CWD_NAME,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| filesystem("open empty private cwd", source))?,
    );
    let cwd_identity = validate_directory(&cwd, 0o700)?;

    let mut writer = File::from(
        openat(
            &root,
            EXECUTABLE_NAME,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|source| filesystem("create private executable", source))?,
    );
    writer
        .write_all(bytes)
        .map_err(|source| filesystem("write exact private executable bytes", source))?;
    writer
        .flush()
        .map_err(|source| filesystem("flush private executable", source))?;
    writer
        .sync_all()
        .map_err(|source| filesystem("synchronize private executable bytes", source))?;
    writer
        .seek(SeekFrom::Start(0))
        .map_err(|source| filesystem("rewind private executable", source))?;
    let mut readback = Vec::with_capacity(bytes.len());
    Read::by_ref(&mut writer)
        .take(MAX_ARTIFACT_BYTES as u64 + 1)
        .read_to_end(&mut readback)
        .map_err(|source| filesystem("read back private executable", source))?;
    if readback != bytes || sha256_identity(&readback) != lock.resource_digest {
        return Err(NativeQualificationError::MaterializedDigestMismatch);
    }
    fchmod(&writer, Mode::RUSR | Mode::XUSR)
        .map_err(|source| filesystem("seal private executable permissions", source))?;
    writer
        .sync_all()
        .map_err(|source| filesystem("synchronize sealed private executable", source))?;
    let executable_identity = validate_executable_metadata(&writer, bytes.len())?;
    drop(writer);

    root.sync_all()
        .map_err(|source| filesystem("synchronize private root", source))?;
    // This materialization is ephemeral authority and is deliberately rebuilt
    // after a crash, so the temporary root's parent entry does not need a
    // durability fsync. The complete root itself is synchronized above.
    let executable = File::from(
        openat(
            &root,
            EXECUTABLE_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|source| filesystem("reopen sealed private executable", source))?,
    );
    let root_identity = validate_directory(&root, 0o700)?;
    let artifact = QualifiedNativeArtifact {
        lock,
        private_root,
        private_parent_path: canonical_parent,
        private_parent: private_parent_descriptor,
        private_parent_identity,
        root_name,
        root,
        executable,
        cwd,
        root_identity,
        executable_identity,
        cwd_identity,
    };
    artifact.revalidate()?;
    Ok(artifact)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
}

fn validate_private_root_path(
    parent: &File,
    root_name: &std::ffi::OsStr,
    expected: &DirectoryIdentity,
    retained: &File,
) -> Result<(), NativeQualificationError> {
    let retained_identity = validate_directory(retained, 0o700)?;
    if &retained_identity != expected {
        return Err(NativeQualificationError::PrivateRootChanged);
    }
    let reopened = File::from(
        openat(
            parent,
            root_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| filesystem("reopen private root", source))?,
    );
    if validate_directory(&reopened, 0o700)? != *expected {
        return Err(NativeQualificationError::PrivateRootChanged);
    }
    validate_private_root_entries(&reopened)?;
    Ok(())
}

fn validate_private_parent(
    path: &Path,
    retained: &File,
    expected: &DirectoryIdentity,
) -> Result<(), NativeQualificationError> {
    if validate_directory(retained, 0o700)? != *expected {
        return Err(NativeQualificationError::PrivateParentInvalid);
    }
    let reopened = File::from(
        open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| NativeQualificationError::PrivateParentInvalid)?,
    );
    if validate_directory(&reopened, 0o700)? != *expected {
        return Err(NativeQualificationError::PrivateParentInvalid);
    }
    Ok(())
}

fn validate_private_root_entries(root: &File) -> Result<(), NativeQualificationError> {
    let mut entries = Dir::read_from(root)
        .map_err(|source| filesystem("inspect private root entries", source))?;
    let mut artifact = false;
    let mut cwd = false;
    for entry in &mut entries {
        let entry = entry.map_err(|source| filesystem("inspect private root entry", source))?;
        match entry.file_name().to_bytes() {
            b"." | b".." => {}
            name if name == EXECUTABLE_NAME.as_bytes() && !artifact => artifact = true,
            name if name == CWD_NAME.as_bytes() && !cwd => cwd = true,
            _ => return Err(NativeQualificationError::PrivateRootChanged),
        }
    }
    if !artifact || !cwd {
        return Err(NativeQualificationError::PrivateRootChanged);
    }
    Ok(())
}

fn validate_materialized_executable(
    root: &File,
    retained: &File,
    expected: &FileIdentity,
    expected_digest: &str,
) -> Result<(), NativeQualificationError> {
    let expected_size = usize::try_from(expected.size)
        .map_err(|_| NativeQualificationError::ArtifactSizeInvalid)?;
    if validate_executable_metadata(retained, expected_size)? != *expected {
        return Err(NativeQualificationError::MaterializedFileChanged);
    }
    let mut reopened = File::from(
        openat(
            root,
            EXECUTABLE_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|source| filesystem("reopen private executable", source))?,
    );
    if validate_executable_metadata(&reopened, expected_size)? != *expected {
        return Err(NativeQualificationError::MaterializedFileChanged);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(expected.size)
            .map_err(|_| NativeQualificationError::ArtifactSizeInvalid)?,
    );
    Read::by_ref(&mut reopened)
        .take(MAX_ARTIFACT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| filesystem("rehash private executable", source))?;
    if bytes.len() as u64 != expected.size || sha256_identity(&bytes) != expected_digest {
        return Err(NativeQualificationError::MaterializedDigestMismatch);
    }
    Ok(())
}

fn validate_empty_cwd(
    root: &File,
    retained: &File,
    expected: &DirectoryIdentity,
) -> Result<(), NativeQualificationError> {
    if validate_directory(retained, 0o700)? != *expected {
        return Err(NativeQualificationError::PrivateCwdChanged);
    }
    let reopened = File::from(
        openat(
            root,
            CWD_NAME,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| filesystem("reopen private cwd", source))?,
    );
    if validate_directory(&reopened, 0o700)? != *expected {
        return Err(NativeQualificationError::PrivateCwdChanged);
    }
    let mut entries =
        Dir::read_from(&reopened).map_err(|source| filesystem("inspect private cwd", source))?;
    for entry in &mut entries {
        let entry = entry.map_err(|source| filesystem("inspect private cwd entry", source))?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            return Err(NativeQualificationError::PrivateCwdNotEmpty);
        }
    }
    Ok(())
}

fn validate_executable_metadata(
    file: &File,
    expected_size: usize,
) -> Result<FileIdentity, NativeQualificationError> {
    let metadata = file
        .metadata()
        .map_err(|source| filesystem("inspect private executable", source))?;
    if !metadata.is_file()
        || metadata.uid() != geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o500
        || metadata.len()
            != u64::try_from(expected_size)
                .map_err(|_| NativeQualificationError::ArtifactSizeInvalid)?
    {
        return Err(NativeQualificationError::MaterializedFileChanged);
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
    })
}

fn validate_directory(
    file: &File,
    mode: u32,
) -> Result<DirectoryIdentity, NativeQualificationError> {
    let metadata = file
        .metadata()
        .map_err(|source| filesystem("inspect private directory", source))?;
    if !metadata.is_dir() || metadata.uid() != geteuid().as_raw() || metadata.mode() & 0o777 != mode
    {
        return Err(NativeQualificationError::PrivateDirectoryInvalid);
    }
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn ensure_supported_platform() -> Result<(), NativeQualificationError> {
    ensure_supported_platform_name(std::env::consts::OS, std::env::consts::ARCH)
}

fn ensure_supported_platform_name(
    operating_system: &str,
    architecture: &str,
) -> Result<(), NativeQualificationError> {
    if operating_system == "macos" && architecture == "aarch64" {
        Ok(())
    } else {
        Err(NativeQualificationError::UnsupportedPlatform)
    }
}

/// Closed qualification/materialization failure. Private paths and bytes are
/// intentionally absent from every variant and display string.
#[derive(Debug)]
pub enum NativeQualificationError {
    UnsupportedPlatform,
    PackageBindingMismatch(NativeArtifactRole),
    RoleMismatch,
    ResourceDigestMismatch,
    ArtifactSizeInvalid,
    InvalidMachO,
    WrongArchitecture,
    NotExecutable,
    DynamicLinkageRejected,
    QualificationIdentityChanged,
    ArtifactLockChanged,
    MaterializedDigestMismatch,
    MaterializedFileChanged,
    PrivateRootChanged,
    PrivateParentInvalid,
    PrivateDirectoryInvalid,
    PrivateCwdChanged,
    PrivateCwdNotEmpty,
    Filesystem {
        operation: &'static str,
        source: std::io::Error,
    },
}

impl fmt::Display for NativeQualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("native qualification supports only aarch64-apple-darwin")
            }
            Self::PackageBindingMismatch(role) => {
                write!(
                    formatter,
                    "verified package does not retain the exact {role:?} binding"
                )
            }
            Self::RoleMismatch => formatter.write_str("native artifact role changed"),
            Self::ResourceDigestMismatch => {
                formatter.write_str("package-owned artifact bytes changed digest")
            }
            Self::ArtifactSizeInvalid => {
                formatter.write_str("native artifact size is outside the proof bound")
            }
            Self::InvalidMachO => formatter.write_str("artifact is not one thin 64-bit Mach-O"),
            Self::WrongArchitecture => formatter.write_str("Mach-O artifact is not plain arm64"),
            Self::NotExecutable => {
                formatter.write_str("Mach-O artifact is not an executable with an entry point")
            }
            Self::DynamicLinkageRejected => {
                formatter.write_str("Mach-O dynamic-loader authority is outside the closed profile")
            }
            Self::QualificationIdentityChanged => {
                formatter.write_str("native artifact qualification changed")
            }
            Self::ArtifactLockChanged => formatter.write_str("native artifact lock changed"),
            Self::MaterializedDigestMismatch => {
                formatter.write_str("materialized artifact bytes changed")
            }
            Self::MaterializedFileChanged => formatter
                .write_str("materialized artifact ownership, links, mode, size, or inode changed"),
            Self::PrivateRootChanged => formatter.write_str("private root identity changed"),
            Self::PrivateParentInvalid => {
                formatter.write_str("private parent is not an absolute owner-only directory")
            }
            Self::PrivateDirectoryInvalid => {
                formatter.write_str("private directory authority is invalid")
            }
            Self::PrivateCwdChanged => formatter.write_str("private cwd identity changed"),
            Self::PrivateCwdNotEmpty => formatter.write_str("private cwd is not empty"),
            Self::Filesystem { operation, source } => {
                write!(formatter, "{operation}: {source}")
            }
        }
    }
}

impl Error for NativeQualificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Filesystem { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn filesystem(
    operation: &'static str,
    source: impl Into<std::io::Error>,
) -> NativeQualificationError {
    NativeQualificationError::Filesystem {
        operation,
        source: source.into(),
    }
}

fn document_digest(value: &impl Serialize) -> Result<String, NativeQualificationError> {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .map_err(|_| NativeQualificationError::QualificationIdentityChanged)?;
    Ok(sha256_identity(&bytes))
}

fn sha256_identity(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn placeholder_identity() -> String {
    format!("sha256:{}", "0".repeat(64))
}

fn validate_sha256(value: &str) -> Result<(), NativeQualificationError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(NativeQualificationError::ArtifactLockChanged);
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(NativeQualificationError::ArtifactLockChanged);
    }
    Ok(())
}

fn validate_opaque(value: &str) -> Result<(), NativeQualificationError> {
    if value.is_empty()
        || value.len() > MAX_OPAQUE_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(NativeQualificationError::ArtifactLockChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::OnceLock;

    use gooir_fleetd_direct_conversation_package_proof::{StageRequest, stage, verify_package_set};
    use tempfile::TempDir;

    use super::{
        NativeArtifactRole, NativeQualificationError, QualifiedNativeArtifact,
        ensure_supported_platform_name, qualify_attester, qualify_owned_resource, qualify_provider,
        validate_macho,
    };

    fn executable_bytes(marker: u8) -> Vec<u8> {
        let mut bytes = fs::read(std::env::current_exe().expect("test executable path"))
            .expect("test executable bytes");
        bytes.extend_from_slice(b"\nproof-inert-trailing-marker:");
        bytes.push(marker);
        bytes
    }

    fn executable_path(artifact: &QualifiedNativeArtifact) -> std::path::PathBuf {
        artifact.private_root.path().join(super::EXECUTABLE_NAME)
    }

    fn cwd_path(artifact: &QualifiedNativeArtifact) -> std::path::PathBuf {
        artifact.private_root.path().join(super::CWD_NAME)
    }

    fn fat_wrapper(thin: &[u8], fat64: bool) -> Vec<u8> {
        const OFFSET: usize = 4096;
        let mut bytes = Vec::with_capacity(OFFSET + thin.len());
        bytes.extend_from_slice(
            &(if fat64 {
                object::macho::FAT_MAGIC_64
            } else {
                object::macho::FAT_MAGIC
            })
            .to_be_bytes(),
        );
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&object::macho::CPU_TYPE_ARM64.to_be_bytes());
        bytes.extend_from_slice(&object::macho::CPU_SUBTYPE_ARM64_ALL.to_be_bytes());
        if fat64 {
            bytes.extend_from_slice(&(OFFSET as u64).to_be_bytes());
            bytes.extend_from_slice(&(thin.len() as u64).to_be_bytes());
        } else {
            bytes.extend_from_slice(
                &u32::try_from(OFFSET)
                    .expect("fixture offset fits u32")
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(
                &u32::try_from(thin.len())
                    .expect("fixture artifact fits u32")
                    .to_be_bytes(),
            );
        }
        bytes.extend_from_slice(&12_u32.to_be_bytes());
        if fat64 {
            bytes.extend_from_slice(&0_u32.to_be_bytes());
        }
        bytes.resize(OFFSET, 0);
        bytes.extend_from_slice(thin);
        bytes
    }

    fn load_command_offset(bytes: &[u8], wanted: u32) -> usize {
        let file = object::read::macho::MachOFile64::<object::Endianness>::parse(bytes)
            .expect("test Mach-O");
        let mut commands = file.macho_load_commands().expect("load commands");
        let base = bytes.as_ptr() as usize;
        while let Some(command) = commands.next().expect("valid load command") {
            if command.cmd() == wanted {
                return command.raw_data().as_ptr() as usize - base;
            }
        }
        panic!("test Mach-O does not contain command {wanted:#x}");
    }

    struct TestPackageSet {
        packages: gooir_fleetd_direct_conversation_package_proof::VerifiedPackageSet,
        deleted_source_root: std::path::PathBuf,
    }

    fn test_packages() -> &'static TestPackageSet {
        static PACKAGES: OnceLock<TestPackageSet> = OnceLock::new();
        PACKAGES.get_or_init(|| {
            let temporary = TempDir::new().expect("fixture root");
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
                .expect("fixture root mode");
            let reqwest = temporary.path().join("reqwest");
            let ureq = temporary.path().join("ureq");
            let attester = temporary.path().join("attester");
            let reqwest_base = executable_bytes(1);
            fs::write(&ureq, executable_bytes(2)).expect("ureq source");
            fs::write(&attester, executable_bytes(3)).expect("attester source");
            fs::write(&reqwest, &reqwest_base).expect("reqwest source");
            for path in [&reqwest, &ureq, &attester] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o777)).expect("source mode");
            }
            let package_root = temporary.path().join("packages");
            stage(StageRequest {
                reqwest_command: reqwest,
                ureq_command: ureq,
                attester_command: attester,
                output_root: package_root.clone(),
            })
            .expect("stage package set exactly once");
            let packages = verify_package_set(&package_root).expect("verify package set");
            let deleted_source_root = temporary.path().to_path_buf();
            drop(temporary);
            assert!(!deleted_source_root.exists());
            TestPackageSet {
                packages,
                deleted_source_root,
            }
        })
    }

    fn private_parent() -> TempDir {
        let parent = TempDir::new().expect("private parent");
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700))
            .expect("private parent mode");
        parent
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn qualifies_exact_provider_and_attester_into_private_path_free_locks() {
        let packages = &test_packages().packages;
        let parent = private_parent();
        let provider = qualify_provider(packages, &packages.report().providers[0], parent.path())
            .expect("qualified provider");
        let attester = qualify_attester(packages, &packages.report().attester, parent.path())
            .expect("qualified attester");
        for (artifact, role) in [
            (&provider, NativeArtifactRole::Provider),
            (&attester, NativeArtifactRole::Attester),
        ] {
            artifact.revalidate().expect("revalidate");
            assert_eq!(artifact.lock().role(), role);
            artifact
                .lock()
                .qualification()
                .validate()
                .expect("artifact qualification");
            let encoded = serde_json::to_string(artifact.lock()).expect("lock JSON");
            assert!(!encoded.contains(executable_path(artifact).to_string_lossy().as_ref()));
            assert!(
                !format!("{artifact:?}")
                    .contains(executable_path(artifact).to_string_lossy().as_ref())
            );
            assert_eq!(
                fs::metadata(executable_path(artifact))
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o500
            );
            assert!(
                fs::read_dir(cwd_path(artifact))
                    .expect("cwd")
                    .next()
                    .is_none()
            );
        }
        assert_ne!(provider.lock().lock_id(), attester.lock().lock_id());
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn owned_package_bytes_survive_source_tree_deletion() {
        let test_set = test_packages();
        assert!(!test_set.deleted_source_root.exists());
        let packages = &test_set.packages;
        let parent = private_parent();
        let binding = packages.report().providers[0].clone();
        let artifact =
            qualify_provider(packages, &binding, parent.path()).expect("qualify retained bytes");
        artifact.revalidate().expect("revalidate");
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn binding_and_role_substitution_fail_closed() {
        let packages = &test_packages().packages;
        let parent = private_parent();
        let mut changed = packages.report().providers[0].clone();
        changed.implementation = packages.report().attester.implementation.clone();
        assert!(matches!(
            qualify_provider(packages, &changed, parent.path()),
            Err(NativeQualificationError::PackageBindingMismatch(
                NativeArtifactRole::Provider
            ))
        ));

        let binding = &packages.report().providers[0];
        let resource = packages.provider_artifact(binding).expect("resource");
        let valid = qualify_provider(packages, binding, parent.path()).expect("valid provider");
        let mut wrong_role_lock = valid.lock().clone();
        wrong_role_lock.role = NativeArtifactRole::Attester;
        wrong_role_lock.lock_id = wrong_role_lock.derived_id().expect("lock id");
        assert!(matches!(
            qualify_owned_resource(
                resource,
                wrong_role_lock,
                NativeArtifactRole::Provider,
                parent.path(),
            ),
            Err(NativeQualificationError::RoleMismatch)
        ));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn authoritative_parser_rejects_wrong_format_architecture_kind_and_fat_container() {
        let valid = executable_bytes(1);
        let mut wrong_architecture = valid.clone();
        wrong_architecture[4..8].copy_from_slice(&[7, 0, 0, 1]);
        assert!(matches!(
            validate_macho(&wrong_architecture),
            Err(NativeQualificationError::WrongArchitecture)
        ));

        let mut wrong_kind = valid.clone();
        wrong_kind[12..16].copy_from_slice(&1_u32.to_le_bytes());
        assert!(matches!(
            validate_macho(&wrong_kind),
            Err(NativeQualificationError::NotExecutable)
        ));

        assert!(matches!(
            validate_macho(b"not a Mach-O executable"),
            Err(NativeQualificationError::InvalidMachO)
        ));

        for (fat64, kind) in [
            (false, object::FileKind::MachOFat32),
            (true, object::FileKind::MachOFat64),
        ] {
            let wrapped = fat_wrapper(&valid, fat64);
            assert_eq!(
                object::FileKind::parse(wrapped.as_slice()).expect("fat kind"),
                kind
            );
            assert!(matches!(
                validate_macho(&wrapped),
                Err(NativeQualificationError::InvalidMachO)
            ));
        }
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn exhaustive_load_command_validation_rejects_relative_dylib_and_late_corruption() {
        let mut relative_dylib = executable_bytes(1);
        let original = b"/usr/lib/libiconv.2.dylib";
        let replacement = b"@rpath/libiconv.2.dylib\0\0";
        assert_eq!(original.len(), replacement.len());
        let offset = relative_dylib
            .windows(original.len())
            .position(|window| window == original)
            .expect("libiconv load command");
        relative_dylib[offset..offset + original.len()].copy_from_slice(replacement);
        assert!(matches!(
            validate_macho(&relative_dylib),
            Err(NativeQualificationError::DynamicLinkageRejected)
        ));

        let mut malformed = executable_bytes(1);
        let last_command_offset = {
            let file =
                object::read::macho::MachOFile64::<object::Endianness>::parse(malformed.as_slice())
                    .expect("test Mach-O");
            let mut commands = file.macho_load_commands().expect("load commands");
            let base = malformed.as_ptr() as usize;
            let mut last = None;
            while let Some(command) = commands.next().expect("valid load command") {
                last = Some(command.raw_data().as_ptr() as usize - base);
            }
            last.expect("at least one load command")
        };
        malformed[last_command_offset + 4..last_command_offset + 8]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            validate_macho(&malformed),
            Err(NativeQualificationError::InvalidMachO)
        ));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn loader_profile_rejects_non_macos_duplicate_main_and_noncanonical_header() {
        let valid = executable_bytes(1);

        let mut non_macos = valid.clone();
        let build = load_command_offset(&non_macos, object::macho::LC_BUILD_VERSION);
        non_macos[build + 8..build + 12]
            .copy_from_slice(&object::macho::PLATFORM_IOS.to_le_bytes());
        assert!(matches!(
            validate_macho(&non_macos),
            Err(NativeQualificationError::DynamicLinkageRejected)
        ));

        let mut duplicate_main = valid.clone();
        let uuid = load_command_offset(&duplicate_main, object::macho::LC_UUID);
        let main = load_command_offset(&duplicate_main, object::macho::LC_MAIN);
        let entryoff = duplicate_main[main + 8..main + 16].to_vec();
        duplicate_main[uuid..uuid + 4].copy_from_slice(&object::macho::LC_MAIN.to_le_bytes());
        duplicate_main[uuid + 8..uuid + 16].copy_from_slice(&entryoff);
        duplicate_main[uuid + 16..uuid + 24].fill(0);
        assert!(matches!(
            validate_macho(&duplicate_main),
            Err(NativeQualificationError::DynamicLinkageRejected)
        ));

        let mut wrong_subtype = valid.clone();
        wrong_subtype[8..12].copy_from_slice(&object::macho::CPU_SUBTYPE_ARM64_V8.to_le_bytes());
        assert!(matches!(
            validate_macho(&wrong_subtype),
            Err(NativeQualificationError::WrongArchitecture)
        ));

        let mut nonzero_reserved = valid.clone();
        nonzero_reserved[28..32].copy_from_slice(&1_u32.to_le_bytes());
        assert!(matches!(
            validate_macho(&nonzero_reserved),
            Err(NativeQualificationError::DynamicLinkageRejected)
        ));

        let mut unsafe_flags = valid.clone();
        let flags = u32::from_le_bytes(unsafe_flags[24..28].try_into().expect("header flags"));
        unsafe_flags[24..28].copy_from_slice(
            &((flags & !object::macho::MH_PIE) | object::macho::MH_ALLOW_STACK_EXECUTION)
                .to_le_bytes(),
        );
        assert!(matches!(
            validate_macho(&unsafe_flags),
            Err(NativeQualificationError::DynamicLinkageRejected)
        ));

        let mut additional_header_flag = valid.clone();
        additional_header_flag[24..28]
            .copy_from_slice(&(flags | object::macho::MH_APP_EXTENSION_SAFE).to_le_bytes());
        assert!(matches!(
            validate_macho(&additional_header_flag),
            Err(NativeQualificationError::DynamicLinkageRejected)
        ));

        let mut dylib_use_extension = valid;
        let dylib = load_command_offset(&dylib_use_extension, object::macho::LC_LOAD_DYLIB);
        dylib_use_extension[dylib + 8..dylib + 12].copy_from_slice(&28_u32.to_le_bytes());
        dylib_use_extension[dylib + 12..dylib + 16]
            .copy_from_slice(&object::macho::DYLIB_USE_MARKER.to_le_bytes());
        assert!(matches!(
            validate_macho(&dylib_use_extension),
            Err(NativeQualificationError::DynamicLinkageRejected)
        ));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn revalidation_rejects_byte_permission_and_cwd_tampering() {
        let packages = &test_packages().packages;
        let parent = private_parent();
        let qualify = || {
            qualify_provider(packages, &packages.report().providers[0], parent.path())
                .expect("qualified provider")
        };
        let artifact = qualify();
        let executable = executable_path(&artifact);
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).expect("writable");
        let mut bytes = fs::read(&executable).expect("bytes");
        bytes.push(0);
        fs::write(&executable, bytes).expect("tamper");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).expect("reseal");
        assert!(matches!(
            artifact.revalidate(),
            Err(NativeQualificationError::MaterializedFileChanged
                | NativeQualificationError::MaterializedDigestMismatch)
        ));

        let artifact = qualify();
        fs::set_permissions(
            executable_path(&artifact),
            fs::Permissions::from_mode(0o700),
        )
        .expect("change mode");
        assert!(matches!(
            artifact.revalidate(),
            Err(NativeQualificationError::MaterializedFileChanged)
        ));

        let artifact = qualify();
        fs::write(cwd_path(&artifact).join("unexpected"), b"x").expect("cwd file");
        assert!(matches!(
            artifact.revalidate(),
            Err(NativeQualificationError::PrivateCwdNotEmpty)
        ));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn revalidation_rejects_hardlink_symlink_and_path_replacement() {
        let packages = &test_packages().packages;
        let parent = private_parent();
        let qualify = || {
            qualify_provider(packages, &packages.report().providers[0], parent.path())
                .expect("qualified provider")
        };
        let artifact = qualify();
        fs::hard_link(
            executable_path(&artifact),
            cwd_path(&artifact).join("hardlink"),
        )
        .expect("hardlink");
        assert!(matches!(
            artifact.revalidate(),
            Err(NativeQualificationError::MaterializedFileChanged)
        ));

        let artifact = qualify();
        let executable = executable_path(&artifact);
        let displaced = cwd_path(&artifact).join("displaced");
        fs::rename(&executable, &displaced).expect("displace");
        std::os::unix::fs::symlink(&displaced, &executable).expect("symlink");
        assert!(artifact.revalidate().is_err());

        let artifact = qualify();
        let executable = executable_path(&artifact);
        let displaced = cwd_path(&artifact).join("displaced");
        fs::rename(&executable, &displaced).expect("displace");
        fs::copy(&displaced, &executable).expect("replacement");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).expect("mode");
        assert!(matches!(
            artifact.revalidate(),
            Err(NativeQualificationError::MaterializedFileChanged)
        ));
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn private_parent_must_be_absolute_owner_only_and_not_a_symlink() {
        let packages = &test_packages().packages;
        let parent = private_parent();
        let binding = &packages.report().providers[0];
        assert!(matches!(
            qualify_provider(packages, binding, std::path::Path::new(".")),
            Err(NativeQualificationError::PrivateParentInvalid)
        ));

        let permissive = parent.path().join("permissive-parent");
        fs::create_dir(&permissive).expect("permissive parent");
        fs::set_permissions(&permissive, fs::Permissions::from_mode(0o755))
            .expect("permissive mode");
        assert!(matches!(
            qualify_provider(packages, binding, &permissive),
            Err(NativeQualificationError::PrivateParentInvalid)
        ));

        let linked = parent.path().join("linked-parent");
        std::os::unix::fs::symlink(parent.path(), &linked).expect("parent symlink");
        assert!(matches!(
            qualify_provider(packages, binding, &linked),
            Err(NativeQualificationError::PrivateParentInvalid)
        ));
    }

    #[test]
    fn platform_profile_is_closed_to_aarch64_macos() {
        assert!(ensure_supported_platform_name("macos", "aarch64").is_ok());
        for (operating_system, architecture) in [
            ("macos", "x86_64"),
            ("linux", "aarch64"),
            ("linux", "x86_64"),
        ] {
            assert!(matches!(
                ensure_supported_platform_name(operating_system, architecture),
                Err(NativeQualificationError::UnsupportedPlatform)
            ));
        }
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    #[test]
    fn public_qualification_fails_closed_on_this_platform() {
        assert!(matches!(
            super::NativeArtifactQualification::current(),
            Err(NativeQualificationError::UnsupportedPlatform)
        ));
    }
}
