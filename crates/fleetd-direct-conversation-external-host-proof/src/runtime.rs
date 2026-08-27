//! Exact, proof-local qualification of the shared Darwin native runtime.
//!
//! The durable half is path-free and content identified. The live half retains
//! the descriptors and mapped-image observations needed to fail closed before
//! every provider or attester spawn. This is deliberately not a generic GOOIR
//! runtime abstraction.

use std::error::Error;
use std::fmt;
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::journal::NativeRuntimeLock;
use crate::native::{NativeArtifactRole, QualifiedNativeArtifactLock};
use crate::supervisor::NATIVE_SUPERVISOR_PROFILE_ID;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod darwin;

/// Exact durable coordinate for this closed runtime qualification.
pub const NATIVE_RUNTIME_PROFILE: &str = "org.gooi.proof/fleetd-darwin-native-runtime@0.1.0";

const RUNTIME_PROTOCOL: &str = "org.gooi.proof.fleetd-darwin-native-runtime-qualification/v1";
const TARGET_TRIPLE: &str = "aarch64-apple-darwin";
const OBJECT_PROFILE: &str =
    "object@0.39.1/read::macho::{MachOFile64,DyldCache,ObjectSegment,ReadCacheOps}";
const RUSTIX_PROFILE: &str = "rustix@1.1.4/fs::{open,openat,O_NOFOLLOW,O_CLOEXEC}";
const LIBC_PROFILE: &str = "libc@0.2.189/darwin";
const SHA_PROFILE: &str = "sha2@0.10.9/SHA-256";
const CANONICAL_PROFILE: &str = "serde_json_canonicalizer@0.3.2/RFC8785";
const FFI_PROFILE: &str = concat!(
    "darwin-arm64;task_info=TASK_DYLD_INFO-17-format64-pack4-size20-count5;",
    "dyld-all-image-infos=v17-size368-exact-change-timestamp-cache-uuid-base-dyld;",
    "cache-file-id=v17-explicitly-absent,v18-unsupported;cache-lookup=closed-cryptex-or-system-dyld-root;",
    "cache-install-names=/usr/lib+,/System/Library+,/System/iOSSupport+;",
    "images=one-bounded-_dyld-snapshot+validate-all-cache-install-names+parse-exact-loaded-cache-set-and-dyld-libsystem-libiconv+each-loaded-address-global-slide-uuid-header;",
    "host=proc_pidpath+dladdr-marker+mapped-header;dyld=standalone+cache+mapped+stable-commands;",
    "os=sysctlbyname-complete-closed-set;files=pread+descriptor-metadata+sf-restricted;",
    "cache-parser=pread-readcache-request-1m-total-64m;",
    "trust=root-sip-cache-nonprivileged-stable-boot-no-post-qualification-dlopen/v1"
);

/// Exact finite limitations of the proof-local runtime qualification.
pub const NATIVE_RUNTIME_LIMITATIONS: &str = concat!(
    "no-apple-signature-or-signer-verification;",
    "no-root-privileged-task-port-or-in-memory-patch-resistance;",
    "no-page-for-page-child-attestation;",
    "root-sf-restricted-cache-immutability-assumed;stable-boot-and-no-post-qualification-dlopen;",
    "same-uid-malicious-proof-host-writer-out-of-scope;",
    "cache-activation-closed-to-current-mapped-uuid-and-retained-graph;",
    "small-os-activation-race-remains/v1"
);

/// Canonical decimal-string file metadata without a path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeFileMetadata {
    pub(crate) device: String,
    pub(crate) inode: String,
    pub(crate) byte_len: String,
    pub(crate) uid: String,
    pub(crate) gid: String,
    pub(crate) mode: String,
    pub(crate) link_count: String,
    pub(crate) flags: String,
    pub(crate) modified_seconds: String,
    pub(crate) modified_nanoseconds: String,
    pub(crate) changed_seconds: String,
    pub(crate) changed_nanoseconds: String,
}

/// Exact content identity of the running proof-host executable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofHostIdentity {
    pub(crate) file_sha256: String,
    pub(crate) metadata: RuntimeFileMetadata,
    pub(crate) macho_uuid: String,
    pub(crate) header_commands_sha256: String,
}

/// Exact content identity of the loaded Darwin dynamic linker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DyldIdentity {
    pub(crate) file_sha256: String,
    pub(crate) metadata: RuntimeFileMetadata,
    pub(crate) arm64e_uuid: String,
    pub(crate) header_commands_sha256: String,
    pub(crate) mapped_header_commands_sha256: String,
    pub(crate) stable_commands_sha256: String,
    pub(crate) loaded_version: String,
}

/// Exact content and descriptor identity of one shared-cache file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedCacheFileIdentity {
    pub(crate) ordinal: String,
    pub(crate) uuid: String,
    pub(crate) file_sha256: String,
    pub(crate) metadata: RuntimeFileMetadata,
}

/// Exact identity of one logical image in the active shared cache.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedCacheImageIdentity {
    pub(crate) role: String,
    pub(crate) source_cache_ordinal: String,
    pub(crate) macho_uuid: String,
    pub(crate) header_commands_sha256: String,
    pub(crate) segment_manifest_sha256: String,
}

/// Whether dyld exposed the main cache file identity in its ABI version.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "availability", deny_unknown_fields)]
pub enum ActiveCacheFileIdentity {
    /// `dyld_all_image_infos` before version 18 has no FSID/object-id fields.
    UnavailableBeforeV18,
    /// Exact active filesystem and object identifiers, encoded as decimal strings.
    Present { fsid: String, object_id: String },
}

/// Exact active shared-cache graph and required image identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedCacheIdentity {
    pub(crate) active_uuid: String,
    pub(crate) active_file_identity: ActiveCacheFileIdentity,
    pub(crate) architecture: String,
    pub(crate) platform: String,
    pub(crate) cache_type: String,
    pub(crate) cache_os_version: String,
    pub(crate) main: SharedCacheFileIdentity,
    pub(crate) subcaches: Vec<SharedCacheFileIdentity>,
    pub(crate) dyld: SharedCacheImageIdentity,
    pub(crate) libsystem: SharedCacheImageIdentity,
    pub(crate) libiconv: SharedCacheImageIdentity,
}

/// Exact non-secret Darwin hardware and OS build identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DarwinPlatformIdentity {
    pub(crate) kernel_uuid: String,
    pub(crate) os_product_version: String,
    pub(crate) os_build_version: String,
    pub(crate) os_release: String,
    pub(crate) kernel_version: String,
    pub(crate) machine: String,
    pub(crate) model: String,
    pub(crate) cpu_type: String,
    pub(crate) cpu_subtype: String,
    pub(crate) arm64_capability: String,
}

/// Complete path-free deployment qualification shared by the provider and attester.
///
/// This is deliberately the identity of one exact selected composition, not a
/// provider-independent generic runtime coordinate. The named artifact lock
/// IDs prevent either role from reusing runtime authority minted for another
/// deployment composition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRuntimeQualification {
    qualification_id: String,
    protocol: String,
    profile: String,
    target_triple: String,
    provider_artifact_lock_id: String,
    attester_artifact_lock_id: String,
    platform: DarwinPlatformIdentity,
    proof_host: ProofHostIdentity,
    dyld: DyldIdentity,
    shared_cache: SharedCacheIdentity,
    loaded_image_count: String,
    loaded_image_set_sha256: String,
    dyld_all_image_infos_version: String,
    task_dyld_info_format: String,
    task_dyld_info_returned_count: String,
    object_profile: String,
    rustix_profile: String,
    libc_profile: String,
    sha_profile: String,
    canonical_profile: String,
    artifact_profile: String,
    ffi_profile: String,
    supervisor_profile_id: String,
    limitations: String,
}

impl NativeRuntimeQualification {
    fn new(
        provider: &QualifiedNativeArtifactLock,
        attester: &QualifiedNativeArtifactLock,
        snapshot: darwin_api::DarwinSnapshot,
    ) -> Result<Self, RuntimeQualificationError> {
        let mut qualification = Self {
            qualification_id: placeholder_identity(),
            protocol: RUNTIME_PROTOCOL.to_owned(),
            profile: NATIVE_RUNTIME_PROFILE.to_owned(),
            target_triple: TARGET_TRIPLE.to_owned(),
            provider_artifact_lock_id: provider.lock_id().to_owned(),
            attester_artifact_lock_id: attester.lock_id().to_owned(),
            platform: snapshot.platform,
            proof_host: snapshot.proof_host,
            dyld: snapshot.dyld,
            shared_cache: snapshot.shared_cache,
            loaded_image_count: snapshot.loaded_image_count,
            loaded_image_set_sha256: snapshot.loaded_image_set_sha256,
            dyld_all_image_infos_version: snapshot.dyld_all_image_infos_version,
            task_dyld_info_format: snapshot.task_dyld_info_format,
            task_dyld_info_returned_count: snapshot.task_dyld_info_returned_count,
            object_profile: OBJECT_PROFILE.to_owned(),
            rustix_profile: RUSTIX_PROFILE.to_owned(),
            libc_profile: LIBC_PROFILE.to_owned(),
            sha_profile: SHA_PROFILE.to_owned(),
            canonical_profile: CANONICAL_PROFILE.to_owned(),
            artifact_profile: crate::native::NATIVE_ARTIFACT_QUALIFICATION_ID.to_owned(),
            ffi_profile: FFI_PROFILE.to_owned(),
            supervisor_profile_id: NATIVE_SUPERVISOR_PROFILE_ID.to_owned(),
            limitations: NATIVE_RUNTIME_LIMITATIONS.to_owned(),
        };
        qualification.qualification_id = qualification.derived_id()?;
        qualification.validate()?;
        Ok(qualification)
    }

    /// Content identity of the complete shared runtime qualification.
    #[must_use]
    pub fn qualification_id(&self) -> &str {
        &self.qualification_id
    }

    /// Named provider artifact lock covered by this shared runtime.
    #[must_use]
    pub fn provider_artifact_lock_id(&self) -> &str {
        &self.provider_artifact_lock_id
    }

    /// Named attester artifact lock covered by this shared runtime.
    #[must_use]
    pub fn attester_artifact_lock_id(&self) -> &str {
        &self.attester_artifact_lock_id
    }

    /// Exact active shared-cache qualification.
    #[must_use]
    pub const fn shared_cache(&self) -> &SharedCacheIdentity {
        &self.shared_cache
    }

    /// Revalidate the closed durable document and its identity.
    ///
    /// # Errors
    ///
    /// Refuses protocol/profile drift, malformed identities, or content drift.
    pub fn validate(&self) -> Result<(), RuntimeQualificationError> {
        if self.protocol != RUNTIME_PROTOCOL
            || self.profile != NATIVE_RUNTIME_PROFILE
            || self.target_triple != TARGET_TRIPLE
            || self.object_profile != OBJECT_PROFILE
            || self.rustix_profile != RUSTIX_PROFILE
            || self.libc_profile != LIBC_PROFILE
            || self.sha_profile != SHA_PROFILE
            || self.canonical_profile != CANONICAL_PROFILE
            || self.artifact_profile != crate::native::NATIVE_ARTIFACT_QUALIFICATION_ID
            || self.ffi_profile != FFI_PROFILE
            || self.supervisor_profile_id != NATIVE_SUPERVISOR_PROFILE_ID
            || self.limitations != NATIVE_RUNTIME_LIMITATIONS
            || self.provider_artifact_lock_id == self.attester_artifact_lock_id
            || self.shared_cache.active_uuid != self.shared_cache.main.uuid
            || self.shared_cache.libsystem.role != "libsystem"
            || self.shared_cache.libiconv.role != "libiconv"
            || self.shared_cache.dyld.role != "dyld"
            || self.dyld.arm64e_uuid != self.shared_cache.dyld.macho_uuid
            || self.dyld.mapped_header_commands_sha256
                != self.shared_cache.dyld.header_commands_sha256
        {
            return Err(RuntimeQualificationError::QualificationChanged);
        }
        for digest in [
            &self.provider_artifact_lock_id,
            &self.attester_artifact_lock_id,
            &self.loaded_image_set_sha256,
            &self.proof_host.file_sha256,
            &self.proof_host.header_commands_sha256,
            &self.dyld.file_sha256,
            &self.dyld.header_commands_sha256,
            &self.dyld.mapped_header_commands_sha256,
            &self.dyld.stable_commands_sha256,
            &self.shared_cache.main.file_sha256,
            &self.shared_cache.libsystem.header_commands_sha256,
            &self.shared_cache.libsystem.segment_manifest_sha256,
            &self.shared_cache.libiconv.header_commands_sha256,
            &self.shared_cache.libiconv.segment_manifest_sha256,
            &self.shared_cache.dyld.header_commands_sha256,
            &self.shared_cache.dyld.segment_manifest_sha256,
            &self.supervisor_profile_id,
            &self.qualification_id,
        ] {
            validate_sha256(digest)?;
        }
        for file in &self.shared_cache.subcaches {
            validate_sha256(&file.file_sha256)?;
            validate_uuid(&file.uuid)?;
        }
        validate_uuid(&self.proof_host.macho_uuid)?;
        validate_uuid(&self.dyld.arm64e_uuid)?;
        validate_uuid(&self.shared_cache.active_uuid)?;
        validate_uuid(&self.shared_cache.main.uuid)?;
        validate_uuid(&self.shared_cache.libsystem.macho_uuid)?;
        validate_uuid(&self.shared_cache.libiconv.macho_uuid)?;
        validate_uuid(&self.shared_cache.dyld.macho_uuid)?;
        validate_runtime_shape(self)?;
        if self.qualification_id != self.derived_id()? {
            return Err(RuntimeQualificationError::QualificationChanged);
        }
        Ok(())
    }

    fn derived_id(&self) -> Result<String, RuntimeQualificationError> {
        #[derive(Serialize)]
        struct Body<'a> {
            protocol: &'a str,
            profile: &'a str,
            target_triple: &'a str,
            provider_artifact_lock_id: &'a str,
            attester_artifact_lock_id: &'a str,
            platform: &'a DarwinPlatformIdentity,
            proof_host: &'a ProofHostIdentity,
            dyld: &'a DyldIdentity,
            shared_cache: &'a SharedCacheIdentity,
            loaded_image_count: &'a str,
            loaded_image_set_sha256: &'a str,
            dyld_all_image_infos_version: &'a str,
            task_dyld_info_format: &'a str,
            task_dyld_info_returned_count: &'a str,
            object_profile: &'a str,
            rustix_profile: &'a str,
            libc_profile: &'a str,
            sha_profile: &'a str,
            canonical_profile: &'a str,
            artifact_profile: &'a str,
            ffi_profile: &'a str,
            supervisor_profile_id: &'a str,
            limitations: &'a str,
        }
        document_digest(&Body {
            protocol: &self.protocol,
            profile: &self.profile,
            target_triple: &self.target_triple,
            provider_artifact_lock_id: &self.provider_artifact_lock_id,
            attester_artifact_lock_id: &self.attester_artifact_lock_id,
            platform: &self.platform,
            proof_host: &self.proof_host,
            dyld: &self.dyld,
            shared_cache: &self.shared_cache,
            loaded_image_count: &self.loaded_image_count,
            loaded_image_set_sha256: &self.loaded_image_set_sha256,
            dyld_all_image_infos_version: &self.dyld_all_image_infos_version,
            task_dyld_info_format: &self.task_dyld_info_format,
            task_dyld_info_returned_count: &self.task_dyld_info_returned_count,
            object_profile: &self.object_profile,
            rustix_profile: &self.rustix_profile,
            libc_profile: &self.libc_profile,
            sha_profile: &self.sha_profile,
            canonical_profile: &self.canonical_profile,
            artifact_profile: &self.artifact_profile,
            ffi_profile: &self.ffi_profile,
            supervisor_profile_id: &self.supervisor_profile_id,
            limitations: &self.limitations,
        })
    }
}

/// Live descriptor-backed authority for one exact shared runtime.
pub struct QualifiedNativeRuntime {
    qualification: NativeRuntimeQualification,
    lock: NativeRuntimeLock,
    live: Mutex<darwin_api::LiveDarwinAuthority>,
}

impl fmt::Debug for QualifiedNativeRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedNativeRuntime")
            .field("qualification", &self.qualification)
            .field("lock", &self.lock)
            .field("live_authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl QualifiedNativeRuntime {
    /// Complete durable runtime qualification.
    #[must_use]
    pub const fn qualification(&self) -> &NativeRuntimeQualification {
        &self.qualification
    }

    /// Existing journal lock minted from the exact qualification identity.
    #[must_use]
    pub const fn lock(&self) -> &NativeRuntimeLock {
        &self.lock
    }

    /// Revalidate the live runtime and fence one immediate role-correct spawn.
    ///
    /// # Errors
    ///
    /// Refuses role substitution, lock drift, OS/runtime drift, descriptor
    /// replacement, changes to the exactly selected runtime surfaces, or
    /// post-qualification image loading. Unselected subcache bytes remain under
    /// the explicitly bound root/SIP immutability assumption.
    pub fn revalidated_spawn_guard<'runtime>(
        &'runtime self,
        chosen: &QualifiedNativeArtifactLock,
    ) -> Result<NativeRuntimeSpawnGuard<'runtime>, RuntimeQualificationError> {
        chosen
            .validate()
            .map_err(|_| RuntimeQualificationError::ArtifactLockInvalid)?;
        let expected = match chosen.role() {
            NativeArtifactRole::Provider => &self.qualification.provider_artifact_lock_id,
            NativeArtifactRole::Attester => &self.qualification.attester_artifact_lock_id,
        };
        if chosen.lock_id() != expected {
            return Err(RuntimeQualificationError::ArtifactLockMismatch);
        }
        self.qualification.validate()?;
        let mut live = self
            .live
            .lock()
            .map_err(|_| RuntimeQualificationError::AuthorityUnavailable)?;
        live.revalidate(&self.qualification)?;
        Ok(NativeRuntimeSpawnGuard {
            qualification_id: &self.qualification.qualification_id,
            chosen_artifact_lock_id: chosen.lock_id().to_owned(),
            chosen_role: chosen.role(),
            _live: live,
        })
    }
}

/// Borrow-scoped proof that the runtime was revalidated for an immediate spawn.
pub struct NativeRuntimeSpawnGuard<'runtime> {
    qualification_id: &'runtime str,
    chosen_artifact_lock_id: String,
    chosen_role: NativeArtifactRole,
    _live: MutexGuard<'runtime, darwin_api::LiveDarwinAuthority>,
}

impl NativeRuntimeSpawnGuard<'_> {
    /// Exact qualification identity to bind into the process receipt.
    #[must_use]
    pub fn qualification_id(&self) -> &str {
        self.qualification_id
    }

    pub(crate) fn chosen_artifact_lock_id(&self) -> &str {
        &self.chosen_artifact_lock_id
    }

    pub(crate) const fn chosen_role(&self) -> NativeArtifactRole {
        self.chosen_role
    }
}

/// Qualify the current Darwin runtime for one provider/attester pair.
///
/// # Errors
///
/// Refuses invalid roles/locks or any unsupported, ambiguous, mutable, or
/// unqualified host runtime surface.
pub fn qualify_native_runtime(
    provider: &QualifiedNativeArtifactLock,
    attester: &QualifiedNativeArtifactLock,
) -> Result<QualifiedNativeRuntime, RuntimeQualificationError> {
    validate_artifact_pair(provider, attester)?;
    let (snapshot, live) = darwin_api::capture()?;
    let qualification = NativeRuntimeQualification::new(provider, attester, snapshot)?;
    let lock = NativeRuntimeLock::new(NATIVE_RUNTIME_PROFILE, qualification.qualification_id())
        .map_err(|_| RuntimeQualificationError::QualificationChanged)?;
    Ok(QualifiedNativeRuntime {
        qualification,
        lock,
        live: Mutex::new(live),
    })
}

/// Reconstruct and compare the current runtime against one journal lock.
///
/// # Errors
///
/// Refuses any role, artifact, runtime coordinate, or content mismatch.
pub fn recover_native_runtime(
    expected: &NativeRuntimeLock,
    provider: &QualifiedNativeArtifactLock,
    attester: &QualifiedNativeArtifactLock,
) -> Result<QualifiedNativeRuntime, RuntimeQualificationError> {
    let runtime = qualify_native_runtime(provider, attester)?;
    if expected.runtime() != runtime.lock.runtime()
        || expected.runtime_digest() != runtime.lock.runtime_digest()
    {
        return Err(RuntimeQualificationError::JournalLockMismatch);
    }
    Ok(runtime)
}

fn validate_artifact_pair(
    provider: &QualifiedNativeArtifactLock,
    attester: &QualifiedNativeArtifactLock,
) -> Result<(), RuntimeQualificationError> {
    provider
        .validate()
        .map_err(|_| RuntimeQualificationError::ArtifactLockInvalid)?;
    attester
        .validate()
        .map_err(|_| RuntimeQualificationError::ArtifactLockInvalid)?;
    if provider.role() != NativeArtifactRole::Provider
        || attester.role() != NativeArtifactRole::Attester
        || provider.lock_id() == attester.lock_id()
    {
        return Err(RuntimeQualificationError::ArtifactRoleMismatch);
    }
    Ok(())
}

fn document_digest(value: &impl Serialize) -> Result<String, RuntimeQualificationError> {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .map_err(|_| RuntimeQualificationError::QualificationChanged)?;
    Ok(sha256_identity(&bytes))
}

pub(crate) fn sha256_identity(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn placeholder_identity() -> String {
    format!("sha256:{}", "0".repeat(64))
}

fn validate_sha256(value: &str) -> Result<(), RuntimeQualificationError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(RuntimeQualificationError::QualificationChanged);
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RuntimeQualificationError::QualificationChanged);
    }
    Ok(())
}

fn validate_uuid(value: &str) -> Result<(), RuntimeQualificationError> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RuntimeQualificationError::QualificationChanged);
    }
    Ok(())
}

fn validate_runtime_shape(
    qualification: &NativeRuntimeQualification,
) -> Result<(), RuntimeQualificationError> {
    for value in [
        &qualification.loaded_image_count,
        &qualification.dyld_all_image_infos_version,
        &qualification.task_dyld_info_format,
        &qualification.task_dyld_info_returned_count,
        &qualification.platform.cpu_type,
        &qualification.platform.cpu_subtype,
        &qualification.platform.arm64_capability,
        &qualification.shared_cache.platform,
        &qualification.shared_cache.cache_type,
        &qualification.shared_cache.cache_os_version,
    ] {
        validate_decimal(value)?;
    }
    let image_count = qualification
        .loaded_image_count
        .parse::<usize>()
        .map_err(|_| RuntimeQualificationError::QualificationChanged)?;
    if image_count == 0 || image_count > 4_096 {
        return Err(RuntimeQualificationError::QualificationChanged);
    }
    let infos_version = qualification
        .dyld_all_image_infos_version
        .parse::<u32>()
        .map_err(|_| RuntimeQualificationError::QualificationChanged)?;
    if infos_version != 17
        || qualification.task_dyld_info_format != "1"
        || qualification.task_dyld_info_returned_count != "5"
    {
        return Err(RuntimeQualificationError::QualificationChanged);
    }
    match &qualification.shared_cache.active_file_identity {
        ActiveCacheFileIdentity::UnavailableBeforeV18 => {}
        ActiveCacheFileIdentity::Present { .. } => {
            return Err(RuntimeQualificationError::QualificationChanged);
        }
    }

    validate_bounded_text(&qualification.platform.kernel_uuid, 128)?;
    validate_kernel_uuid(&qualification.platform.kernel_uuid)?;
    validate_bounded_text(&qualification.platform.os_product_version, 64)?;
    validate_bounded_text(&qualification.platform.os_build_version, 64)?;
    validate_bounded_text(&qualification.platform.os_release, 64)?;
    validate_bounded_text(&qualification.platform.kernel_version, 512)?;
    validate_bounded_text(&qualification.platform.machine, 64)?;
    validate_bounded_text(&qualification.platform.model, 128)?;
    if qualification.platform.machine != "arm64"
        || qualification.platform.cpu_type != object::macho::CPU_TYPE_ARM64.to_string()
        || qualification.platform.cpu_subtype != "2"
        || qualification.platform.arm64_capability != "1"
        || qualification.shared_cache.architecture != "aarch64"
        || qualification.shared_cache.platform != object::macho::PLATFORM_MACOS.to_string()
        || qualification.shared_cache.cache_type != "0"
        || qualification.shared_cache.cache_os_version == "0"
        || qualification.shared_cache.libsystem.macho_uuid
            == qualification.shared_cache.libiconv.macho_uuid
    {
        return Err(RuntimeQualificationError::QualificationChanged);
    }
    validate_bounded_text(&qualification.dyld.loaded_version, 256)?;
    validate_file_metadata(&qualification.proof_host.metadata, false)?;
    validate_file_metadata(&qualification.dyld.metadata, true)?;
    validate_metadata_size(&qualification.proof_host.metadata, 256 * 1024 * 1024)?;
    validate_metadata_size(&qualification.dyld.metadata, 64 * 1024 * 1024)?;
    validate_file_metadata(&qualification.shared_cache.main.metadata, true)?;

    if qualification.shared_cache.main.ordinal != "0"
        || qualification.shared_cache.subcaches.is_empty()
        || qualification.shared_cache.subcaches.len() > 64
    {
        return Err(RuntimeQualificationError::QualificationChanged);
    }
    let mut uuids = std::collections::BTreeSet::new();
    let mut logical_cache_bytes = validate_cache_file_size(&qualification.shared_cache.main)?;
    uuids.insert(qualification.shared_cache.main.uuid.as_str());
    for (index, file) in qualification.shared_cache.subcaches.iter().enumerate() {
        if file.ordinal != (index + 1).to_string() || !uuids.insert(file.uuid.as_str()) {
            return Err(RuntimeQualificationError::QualificationChanged);
        }
        validate_file_metadata(&file.metadata, true)?;
        logical_cache_bytes = logical_cache_bytes
            .checked_add(validate_cache_file_size(file)?)
            .ok_or(RuntimeQualificationError::QualificationChanged)?;
    }
    if logical_cache_bytes > 8 * 1024 * 1024 * 1024 {
        return Err(RuntimeQualificationError::QualificationChanged);
    }
    for image in [
        &qualification.shared_cache.dyld,
        &qualification.shared_cache.libsystem,
        &qualification.shared_cache.libiconv,
    ] {
        validate_decimal(&image.source_cache_ordinal)?;
        let source = image
            .source_cache_ordinal
            .parse::<usize>()
            .map_err(|_| RuntimeQualificationError::QualificationChanged)?;
        if source > qualification.shared_cache.subcaches.len() {
            return Err(RuntimeQualificationError::QualificationChanged);
        }
    }
    Ok(())
}

fn validate_kernel_uuid(value: &str) -> Result<(), RuntimeQualificationError> {
    if value.len() != 36 {
        return Err(RuntimeQualificationError::QualificationChanged);
    }
    for (index, byte) in value.bytes().enumerate() {
        if [8, 13, 18, 23].contains(&index) {
            if byte != b'-' {
                return Err(RuntimeQualificationError::QualificationChanged);
            }
        } else if !(byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)) {
            return Err(RuntimeQualificationError::QualificationChanged);
        }
    }
    Ok(())
}

fn validate_cache_file_size(
    file: &SharedCacheFileIdentity,
) -> Result<u64, RuntimeQualificationError> {
    let size = file
        .metadata
        .byte_len
        .parse::<u64>()
        .map_err(|_| RuntimeQualificationError::QualificationChanged)?;
    if size == 0 || size > 4 * 1024 * 1024 * 1024 {
        return Err(RuntimeQualificationError::QualificationChanged);
    }
    Ok(size)
}

fn validate_metadata_size(
    metadata: &RuntimeFileMetadata,
    maximum: u64,
) -> Result<(), RuntimeQualificationError> {
    let size = metadata
        .byte_len
        .parse::<u64>()
        .map_err(|_| RuntimeQualificationError::QualificationChanged)?;
    if size == 0 || size > maximum {
        return Err(RuntimeQualificationError::QualificationChanged);
    }
    Ok(())
}

fn validate_decimal(value: &str) -> Result<(), RuntimeQualificationError> {
    if value.is_empty()
        || value.len() > 32
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(RuntimeQualificationError::QualificationChanged);
    }
    Ok(())
}

fn validate_bounded_text(value: &str, max: usize) -> Result<(), RuntimeQualificationError> {
    if value.is_empty()
        || value.len() > max
        || value
            .bytes()
            .any(|byte| byte == 0 || (!byte.is_ascii_graphic() && byte != b' '))
    {
        return Err(RuntimeQualificationError::QualificationChanged);
    }
    Ok(())
}

fn validate_file_metadata(
    metadata: &RuntimeFileMetadata,
    require_system: bool,
) -> Result<(), RuntimeQualificationError> {
    for value in [
        &metadata.device,
        &metadata.inode,
        &metadata.byte_len,
        &metadata.uid,
        &metadata.gid,
        &metadata.mode,
        &metadata.link_count,
        &metadata.flags,
        &metadata.modified_seconds,
        &metadata.modified_nanoseconds,
        &metadata.changed_seconds,
        &metadata.changed_nanoseconds,
    ] {
        validate_decimal(value)?;
    }
    let mode = metadata
        .mode
        .parse::<u32>()
        .map_err(|_| RuntimeQualificationError::QualificationChanged)?;
    let byte_len = metadata
        .byte_len
        .parse::<u64>()
        .map_err(|_| RuntimeQualificationError::QualificationChanged)?;
    let links = metadata
        .link_count
        .parse::<u64>()
        .map_err(|_| RuntimeQualificationError::QualificationChanged)?;
    let modified_nanoseconds = metadata
        .modified_nanoseconds
        .parse::<u32>()
        .map_err(|_| RuntimeQualificationError::QualificationChanged)?;
    let changed_nanoseconds = metadata
        .changed_nanoseconds
        .parse::<u32>()
        .map_err(|_| RuntimeQualificationError::QualificationChanged)?;
    if mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFREG)
        || byte_len == 0
        || links == 0
        || modified_nanoseconds >= 1_000_000_000
        || changed_nanoseconds >= 1_000_000_000
        || (require_system
            && (metadata.uid != "0"
                || mode & 0o022 != 0
                || metadata
                    .flags
                    .parse::<u32>()
                    .map_err(|_| RuntimeQualificationError::QualificationChanged)?
                    & 0x0008_0000
                    == 0))
    {
        return Err(RuntimeQualificationError::QualificationChanged);
    }
    Ok(())
}

/// Secret- and path-free runtime qualification failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeQualificationError {
    UnsupportedPlatform,
    ArtifactLockInvalid,
    ArtifactRoleMismatch,
    ArtifactLockMismatch,
    HostRuntimeInvalid,
    HostRuntimeChanged,
    AuthorityUnavailable,
    QualificationChanged,
    JournalLockMismatch,
}

impl fmt::Display for RuntimeQualificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedPlatform => "native runtime qualification supports only arm64 Darwin",
            Self::ArtifactLockInvalid => "native runtime artifact lock is invalid",
            Self::ArtifactRoleMismatch => "native runtime artifact roles are invalid",
            Self::ArtifactLockMismatch => {
                "native runtime artifact lock does not match its named role"
            }
            Self::HostRuntimeInvalid => "Darwin native runtime surface is unsupported or invalid",
            Self::HostRuntimeChanged => "Darwin native runtime changed after qualification",
            Self::AuthorityUnavailable => "Darwin native runtime authority is unavailable",
            Self::QualificationChanged => "native runtime qualification identity changed",
            Self::JournalLockMismatch => {
                "journal native runtime lock does not match the current runtime"
            }
        })
    }
}

impl Error for RuntimeQualificationError {}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod darwin_api {
    pub(super) use super::darwin::{DarwinSnapshot, LiveDarwinAuthority, capture};
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn metadata(system: bool, inode: u64, size: u64) -> RuntimeFileMetadata {
        RuntimeFileMetadata {
            device: "1".to_owned(),
            inode: inode.to_string(),
            byte_len: size.to_string(),
            uid: if system { "0" } else { "501" }.to_owned(),
            gid: "0".to_owned(),
            mode: (u32::from(libc::S_IFREG) | 0o555).to_string(),
            link_count: "1".to_owned(),
            flags: if system { "524288" } else { "0" }.to_owned(),
            modified_seconds: "1".to_owned(),
            modified_nanoseconds: "0".to_owned(),
            changed_seconds: "1".to_owned(),
            changed_nanoseconds: "0".to_owned(),
        }
    }

    fn image(role: &str, ordinal: usize, uuid_byte: char) -> SharedCacheImageIdentity {
        SharedCacheImageIdentity {
            role: role.to_owned(),
            source_cache_ordinal: ordinal.to_string(),
            macho_uuid: uuid_byte.to_string().repeat(32),
            header_commands_sha256: digest(uuid_byte),
            segment_manifest_sha256: digest(uuid_byte),
        }
    }

    fn qualification() -> NativeRuntimeQualification {
        let dyld_uuid = "d".repeat(32);
        let mapped_dyld = digest('d');
        let mut value = NativeRuntimeQualification {
            qualification_id: placeholder_identity(),
            protocol: RUNTIME_PROTOCOL.to_owned(),
            profile: NATIVE_RUNTIME_PROFILE.to_owned(),
            target_triple: TARGET_TRIPLE.to_owned(),
            provider_artifact_lock_id: digest('1'),
            attester_artifact_lock_id: digest('2'),
            platform: DarwinPlatformIdentity {
                kernel_uuid: "2E07893B-DECC-3684-B1CF-D3695C617A3E".to_owned(),
                os_product_version: "26.5.2".to_owned(),
                os_build_version: "25F84".to_owned(),
                os_release: "25.5.0".to_owned(),
                kernel_version: "Darwin Kernel Version 25.5.0".to_owned(),
                machine: "arm64".to_owned(),
                model: "Mac15,14".to_owned(),
                cpu_type: object::macho::CPU_TYPE_ARM64.to_string(),
                cpu_subtype: "2".to_owned(),
                arm64_capability: "1".to_owned(),
            },
            proof_host: ProofHostIdentity {
                file_sha256: digest('3'),
                metadata: metadata(false, 10, 1024),
                macho_uuid: "3".repeat(32),
                header_commands_sha256: digest('4'),
            },
            dyld: DyldIdentity {
                file_sha256: digest('5'),
                metadata: metadata(true, 11, 2048),
                arm64e_uuid: dyld_uuid.clone(),
                header_commands_sha256: digest('6'),
                mapped_header_commands_sha256: mapped_dyld.clone(),
                stable_commands_sha256: digest('7'),
                loaded_version: "dyld-1300.1".to_owned(),
            },
            shared_cache: SharedCacheIdentity {
                active_uuid: "a".repeat(32),
                active_file_identity: ActiveCacheFileIdentity::UnavailableBeforeV18,
                architecture: "aarch64".to_owned(),
                platform: object::macho::PLATFORM_MACOS.to_string(),
                cache_type: "0".to_owned(),
                cache_os_version: "311272".to_owned(),
                main: SharedCacheFileIdentity {
                    ordinal: "0".to_owned(),
                    uuid: "a".repeat(32),
                    file_sha256: digest('8'),
                    metadata: metadata(true, 12, 4096),
                },
                subcaches: vec![SharedCacheFileIdentity {
                    ordinal: "1".to_owned(),
                    uuid: "b".repeat(32),
                    file_sha256: digest('9'),
                    metadata: metadata(true, 13, 4096),
                }],
                dyld: SharedCacheImageIdentity {
                    role: "dyld".to_owned(),
                    source_cache_ordinal: "1".to_owned(),
                    macho_uuid: dyld_uuid,
                    header_commands_sha256: mapped_dyld,
                    segment_manifest_sha256: digest('a'),
                },
                libsystem: image("libsystem", 1, 'b'),
                libiconv: image("libiconv", 1, 'c'),
            },
            loaded_image_count: "47".to_owned(),
            loaded_image_set_sha256: digest('e'),
            dyld_all_image_infos_version: "17".to_owned(),
            task_dyld_info_format: "1".to_owned(),
            task_dyld_info_returned_count: "5".to_owned(),
            object_profile: OBJECT_PROFILE.to_owned(),
            rustix_profile: RUSTIX_PROFILE.to_owned(),
            libc_profile: LIBC_PROFILE.to_owned(),
            sha_profile: SHA_PROFILE.to_owned(),
            canonical_profile: CANONICAL_PROFILE.to_owned(),
            artifact_profile: crate::native::NATIVE_ARTIFACT_QUALIFICATION_ID.to_owned(),
            ffi_profile: FFI_PROFILE.to_owned(),
            supervisor_profile_id: NATIVE_SUPERVISOR_PROFILE_ID.to_owned(),
            limitations: NATIVE_RUNTIME_LIMITATIONS.to_owned(),
        };
        value.qualification_id = value.derived_id().expect("sample identity");
        value
    }

    fn reidentify(value: &mut NativeRuntimeQualification) {
        value.qualification_id = value.derived_id().expect("recompute identity");
    }

    #[test]
    fn exact_runtime_document_rejects_unknown_and_identity_tampering() {
        let value = qualification();
        value.validate().expect("valid sample qualification");
        let mut json = serde_json::to_value(&value).expect("qualification JSON");
        json.as_object_mut()
            .expect("qualification object")
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<NativeRuntimeQualification>(json).is_err());

        let mut changed = value;
        changed.loaded_image_set_sha256 = digest('f');
        assert!(changed.validate().is_err());
    }

    #[test]
    fn recomputed_identity_cannot_bypass_closed_nested_shape() {
        let mut cases = Vec::new();
        let mut non_v17 = qualification();
        non_v17.dyld_all_image_infos_version = "18".to_owned();
        cases.push(non_v17);
        let mut non_macos = qualification();
        non_macos.shared_cache.platform = "2".to_owned();
        cases.push(non_macos);
        let mut duplicate_roles = qualification();
        duplicate_roles.attester_artifact_lock_id =
            duplicate_roles.provider_artifact_lock_id.clone();
        cases.push(duplicate_roles);
        let mut bad_ordinal = qualification();
        bad_ordinal.shared_cache.subcaches[0].ordinal = "2".to_owned();
        cases.push(bad_ordinal);
        let mut bad_metadata = qualification();
        bad_metadata.shared_cache.main.metadata.mode = "438".to_owned();
        cases.push(bad_metadata);
        let mut wrong_dyld = qualification();
        wrong_dyld.shared_cache.dyld.header_commands_sha256 = digest('f');
        cases.push(wrong_dyld);

        for value in &mut cases {
            reidentify(value);
            assert!(value.validate().is_err());
        }
    }

    #[test]
    fn durable_runtime_document_contains_no_live_authority_coordinates() {
        let bytes = serde_json::to_vec(&qualification()).expect("qualification JSON");
        for forbidden in [b"http://".as_slice(), b"bearer", b"/private/", b"/tmp/"] {
            assert!(
                !bytes
                    .windows(forbidden.len())
                    .any(|window| window == forbidden)
            );
        }
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
mod darwin_api {
    use super::RuntimeQualificationError;

    pub(super) struct DarwinSnapshot {
        pub(super) platform: super::DarwinPlatformIdentity,
        pub(super) proof_host: super::ProofHostIdentity,
        pub(super) dyld: super::DyldIdentity,
        pub(super) shared_cache: super::SharedCacheIdentity,
        pub(super) loaded_image_count: String,
        pub(super) loaded_image_set_sha256: String,
        pub(super) dyld_all_image_infos_version: String,
        pub(super) task_dyld_info_format: String,
        pub(super) task_dyld_info_returned_count: String,
    }

    pub(super) struct LiveDarwinAuthority;

    impl LiveDarwinAuthority {
        pub(super) fn revalidate(
            &mut self,
            _expected: &super::NativeRuntimeQualification,
        ) -> Result<(), RuntimeQualificationError> {
            Err(RuntimeQualificationError::UnsupportedPlatform)
        }
    }

    pub(super) fn capture()
    -> Result<(DarwinSnapshot, LiveDarwinAuthority), RuntimeQualificationError> {
        Err(RuntimeQualificationError::UnsupportedPlatform)
    }
}
