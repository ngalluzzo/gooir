//! Recurrence evidence for the provisional interaction-activation contract.
//!
//! This crate does not parse arbitrary React, Vue, or Ink programs. It reads a
//! checked-in, revision-pinned audit corpus, verifies every source byte against
//! its locked SHA-256 digest, and admits observations produced by pinned,
//! ecosystem-specific AST projectors. Upstream test declarations corroborate
//! the static callable paths; they are not represented as durable test runs.
//! These are source-scoped observations, not a general UI lifter.

use lift_defeasible::{Completeness, Defeasible, Defeat, DefeatKind};
use semantics_interaction_activation_v0::{ActionActivation, ActivationOutcome};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const LOCK_PROTOCOL: &str = "org.gooi.fixture.interaction_activation_authorities/v1";
pub const DEFEATER_SET: &str =
    "org.gooi.recurrence.interaction_activation/source_scoped_defeaters@1";
/// Audit-local label pinned by `authorities.lock.json`.
///
/// This string selects the corpus question. It is not a semantic observation:
/// only a generated `observations.lift.json` may supply those.
pub const LOCKED_AUDIT_CANDIDATE: &str = "bound_activation_invokes_registered_handler";
pub const OBSERVATIONS_PROTOCOL: &str = "org.gooi.fixture.interaction_activation_observations/v1";
const CANONICAL_OBSERVATIONS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/interaction/activation/observations.lift.json"
));

/// Default checked-in corpus. Kept as a path rather than embedded bytes so the
/// same verifier can check a freshly cloned audit corpus before it is copied in.
pub fn default_corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/interaction/activation")
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityManifest {
    pub protocol: String,
    pub recurrence: RecurrenceLock,
    pub authorities: Vec<AuthorityEntry>,
    pub licenses: Vec<LicenseEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecurrenceLock {
    pub candidate: String,
    pub independent_authority_groups: Vec<String>,
    pub same_system_participants: Vec<String>,
    pub claim: String,
    pub limit: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEntry {
    pub id: String,
    pub ecosystem: String,
    pub authority_group: String,
    pub authority_class: String,
    pub role: String,
    pub repository: RepositoryPin,
    pub source_path: String,
    pub snapshot_path: String,
    pub sha256: String,
    pub license_snapshot: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicenseEntry {
    pub ecosystem: String,
    pub repository: RepositoryPin,
    pub source_path: String,
    pub snapshot_path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPin {
    pub url: String,
    pub commit: String,
}

#[derive(Clone, Debug)]
pub struct VerifiedCorpus {
    root: PathBuf,
    manifest: AuthorityManifest,
}

impl VerifiedCorpus {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn manifest(&self) -> &AuthorityManifest {
        &self.manifest
    }

    pub fn authority(&self, id: &str) -> Option<&AuthorityEntry> {
        self.manifest
            .authorities
            .iter()
            .find(|authority| authority.id == id)
    }

    pub fn ecosystem(&self, ecosystem: &str) -> Vec<&AuthorityEntry> {
        self.manifest
            .authorities
            .iter()
            .filter(|authority| authority.ecosystem == ecosystem)
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CorpusError {
    Io(String),
    Parse(String),
    Protocol {
        expected: String,
        actual: String,
    },
    DuplicateAuthority(String),
    DuplicateSnapshot(String),
    UnsafeSnapshot(String),
    InvalidCommit {
        authority: String,
        commit: String,
    },
    InvalidDigest {
        authority: String,
        digest: String,
    },
    CandidateMismatch {
        expected: String,
        actual: String,
    },
    DuplicateGroupDeclaration {
        class: String,
        group: String,
    },
    UnknownAuthorityClass {
        authority: String,
        class: String,
    },
    MixedAuthorityClasses(String),
    GroupRepositoryMismatch(String),
    RepositorySharedAcrossGroups {
        repository: String,
        groups: Vec<String>,
    },
    AuthorityGroupsMismatch {
        class: String,
        declared: Vec<String>,
        derived: Vec<String>,
    },
    InvalidAuthorityClassification {
        group: String,
        expected: String,
        actual: String,
    },
    MissingAuthorityRole {
        group: String,
        role: String,
    },
    MissingLicense {
        authority: String,
        snapshot: String,
    },
    DigestMismatch {
        authority: String,
        expected: String,
        actual: String,
    },
    MissingCoreAuthority(String),
    MissingLiftedObservations(String),
    LiftProtocol {
        expected: String,
        actual: String,
    },
    AuthorityLockDigestMismatch {
        expected: String,
        actual: String,
    },
    InvalidLift(String),
}

impl fmt::Display for CorpusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) => write!(formatter, "could not read activation corpus: {message}"),
            Self::Parse(message) => {
                write!(formatter, "activation authority lock is invalid: {message}")
            }
            Self::Protocol { expected, actual } => {
                write!(
                    formatter,
                    "authority lock declares {actual}, expected {expected}"
                )
            }
            Self::DuplicateAuthority(id) => write!(formatter, "duplicate authority id `{id}`"),
            Self::DuplicateSnapshot(path) => write!(formatter, "duplicate snapshot `{path}`"),
            Self::UnsafeSnapshot(path) => write!(formatter, "unsafe snapshot path `{path}`"),
            Self::InvalidCommit { authority, commit } => {
                write!(
                    formatter,
                    "authority `{authority}` has invalid full commit `{commit}`"
                )
            }
            Self::InvalidDigest { authority, digest } => {
                write!(
                    formatter,
                    "authority `{authority}` has invalid SHA-256 `{digest}`"
                )
            }
            Self::CandidateMismatch { expected, actual } => {
                write!(
                    formatter,
                    "recurrence candidate is `{actual}`, expected `{expected}`"
                )
            }
            Self::DuplicateGroupDeclaration { class, group } => write!(
                formatter,
                "authority lock declares `{group}` more than once as {class}"
            ),
            Self::UnknownAuthorityClass { authority, class } => write!(
                formatter,
                "authority `{authority}` has unknown authority class `{class}`"
            ),
            Self::MixedAuthorityClasses(group) => write!(
                formatter,
                "authority group `{group}` mixes independent and same-system entries"
            ),
            Self::GroupRepositoryMismatch(group) => write!(
                formatter,
                "authority group `{group}` is not pinned to exactly one repository revision"
            ),
            Self::RepositorySharedAcrossGroups { repository, groups } => write!(
                formatter,
                "repository `{repository}` is assigned to multiple authority groups: {}",
                groups.join(", ")
            ),
            Self::AuthorityGroupsMismatch {
                class,
                declared,
                derived,
            } => write!(
                formatter,
                "declared {class} groups {declared:?} do not equal entry-derived groups {derived:?}"
            ),
            Self::InvalidAuthorityClassification {
                group,
                expected,
                actual,
            } => write!(
                formatter,
                "authority group `{group}` is classified as `{actual}`, expected `{expected}`"
            ),
            Self::MissingAuthorityRole { group, role } => write!(
                formatter,
                "independent authority group `{group}` has no `{role}` evidence"
            ),
            Self::MissingLicense {
                authority,
                snapshot,
            } => write!(
                formatter,
                "authority `{authority}` references unpinned license `{snapshot}`"
            ),
            Self::DigestMismatch {
                authority,
                expected,
                actual,
            } => write!(
                formatter,
                "authority `{authority}` digest mismatch: expected {expected}, got {actual}"
            ),
            Self::MissingCoreAuthority(ecosystem) => {
                write!(
                    formatter,
                    "no runtime/conformance authority for `{ecosystem}`"
                )
            }
            Self::MissingLiftedObservations(path) => {
                write!(
                    formatter,
                    "generated activation observations are missing at `{path}`"
                )
            }
            Self::LiftProtocol { expected, actual } => write!(
                formatter,
                "activation observations declare {actual}, expected {expected}"
            ),
            Self::AuthorityLockDigestMismatch { expected, actual } => write!(
                formatter,
                "activation observations pin authority lock {actual}, expected {expected}"
            ),
            Self::InvalidLift(message) => {
                write!(
                    formatter,
                    "generated activation observations are invalid: {message}"
                )
            }
        }
    }
}

impl std::error::Error for CorpusError {}

/// Loads and byte-verifies the complete checked-in authority lock.
pub fn load_corpus(root: impl AsRef<Path>) -> Result<VerifiedCorpus, CorpusError> {
    let root = root.as_ref();
    let lock_path = root.join("authorities.lock.json");
    let lock =
        fs::read_to_string(&lock_path).map_err(|error| CorpusError::Io(error.to_string()))?;
    let manifest: AuthorityManifest =
        serde_json::from_str(&lock).map_err(|error| CorpusError::Parse(error.to_string()))?;
    verify_manifest(root, &manifest)?;
    Ok(VerifiedCorpus {
        root: root.to_path_buf(),
        manifest,
    })
}

fn verify_manifest(root: &Path, manifest: &AuthorityManifest) -> Result<(), CorpusError> {
    if manifest.protocol != LOCK_PROTOCOL {
        return Err(CorpusError::Protocol {
            expected: LOCK_PROTOCOL.to_owned(),
            actual: manifest.protocol.clone(),
        });
    }
    if manifest.recurrence.candidate != LOCKED_AUDIT_CANDIDATE {
        return Err(CorpusError::CandidateMismatch {
            expected: LOCKED_AUDIT_CANDIDATE.to_owned(),
            actual: manifest.recurrence.candidate.clone(),
        });
    }

    let mut ids = BTreeSet::new();
    let mut snapshots = BTreeSet::new();
    for authority in &manifest.authorities {
        if !ids.insert(authority.id.clone()) {
            return Err(CorpusError::DuplicateAuthority(authority.id.clone()));
        }
        if !snapshots.insert(authority.snapshot_path.clone()) {
            return Err(CorpusError::DuplicateSnapshot(
                authority.snapshot_path.clone(),
            ));
        }
        if !safe_relative_path(&authority.snapshot_path) {
            return Err(CorpusError::UnsafeSnapshot(authority.snapshot_path.clone()));
        }
        if !is_lower_hex(&authority.repository.commit, 40) {
            return Err(CorpusError::InvalidCommit {
                authority: authority.id.clone(),
                commit: authority.repository.commit.clone(),
            });
        }
        if !is_lower_hex(&authority.sha256, 64) {
            return Err(CorpusError::InvalidDigest {
                authority: authority.id.clone(),
                digest: authority.sha256.clone(),
            });
        }
        let bytes = fs::read(root.join(&authority.snapshot_path))
            .map_err(|error| CorpusError::Io(error.to_string()))?;
        let actual = sha256(&bytes);
        if actual != authority.sha256 {
            return Err(CorpusError::DigestMismatch {
                authority: authority.id.clone(),
                expected: authority.sha256.clone(),
                actual,
            });
        }
    }

    verify_authority_topology(manifest)?;

    for license in &manifest.licenses {
        if !snapshots.insert(license.snapshot_path.clone()) {
            return Err(CorpusError::DuplicateSnapshot(
                license.snapshot_path.clone(),
            ));
        }
        verify_source(
            root,
            &format!("{} license", license.ecosystem),
            &license.repository,
            &license.snapshot_path,
            &license.sha256,
        )?;
    }
    for authority in &manifest.authorities {
        let licensed = manifest.licenses.iter().any(|license| {
            license.snapshot_path == authority.license_snapshot
                && license.repository == authority.repository
        });
        if !licensed {
            return Err(CorpusError::MissingLicense {
                authority: authority.id.clone(),
                snapshot: authority.license_snapshot.clone(),
            });
        }
    }

    Ok(())
}

fn verify_authority_topology(manifest: &AuthorityManifest) -> Result<(), CorpusError> {
    const INDEPENDENT: &str = "independent_runtime";
    const PARTICIPANT: &str = "same_system_participant";

    let declared_independent = unique_declared_groups(
        INDEPENDENT,
        &manifest.recurrence.independent_authority_groups,
    )?;
    let declared_participants =
        unique_declared_groups(PARTICIPANT, &manifest.recurrence.same_system_participants)?;
    if let Some(group) = declared_independent
        .intersection(&declared_participants)
        .next()
    {
        return Err(CorpusError::MixedAuthorityClasses(group.clone()));
    }

    let mut group_classes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut group_repositories: BTreeMap<String, BTreeSet<RepositoryPin>> = BTreeMap::new();
    let mut repository_groups: BTreeMap<RepositoryPin, BTreeSet<String>> = BTreeMap::new();
    let mut group_roles: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for authority in &manifest.authorities {
        if authority.authority_class != INDEPENDENT && authority.authority_class != PARTICIPANT {
            return Err(CorpusError::UnknownAuthorityClass {
                authority: authority.id.clone(),
                class: authority.authority_class.clone(),
            });
        }
        group_classes
            .entry(authority.authority_group.clone())
            .or_default()
            .insert(authority.authority_class.clone());
        group_repositories
            .entry(authority.authority_group.clone())
            .or_default()
            .insert(authority.repository.clone());
        repository_groups
            .entry(authority.repository.clone())
            .or_default()
            .insert(authority.authority_group.clone());
        group_roles
            .entry(authority.authority_group.clone())
            .or_default()
            .insert(authority.role.clone());
    }

    for (group, classes) in &group_classes {
        if classes.len() != 1 {
            return Err(CorpusError::MixedAuthorityClasses(group.clone()));
        }
    }
    for (group, repositories) in &group_repositories {
        if repositories.len() != 1 {
            return Err(CorpusError::GroupRepositoryMismatch(group.clone()));
        }
    }
    for (repository, groups) in repository_groups {
        if groups.len() > 1 {
            return Err(CorpusError::RepositorySharedAcrossGroups {
                repository: format!("{}@{}", repository.url, repository.commit),
                groups: groups.into_iter().collect(),
            });
        }
    }

    let derived_independent = groups_for_class(&group_classes, INDEPENDENT);
    let derived_participants = groups_for_class(&group_classes, PARTICIPANT);
    exact_groups(INDEPENDENT, &declared_independent, &derived_independent)?;
    exact_groups(PARTICIPANT, &declared_participants, &derived_participants)?;

    // React DOM and Vue runtime-dom are independently implemented dispatch
    // authorities. Ink is a React renderer and therefore evidence of
    // same-system reach, not a third independent vote.
    for (group, expected) in [
        ("react_dom", INDEPENDENT),
        ("vue_runtime_dom", INDEPENDENT),
        ("ink_terminal", PARTICIPANT),
    ] {
        let actual = group_classes
            .get(group)
            .and_then(|classes| classes.first())
            .map(String::as_str)
            .unwrap_or("missing");
        if actual != expected {
            return Err(CorpusError::InvalidAuthorityClassification {
                group: group.to_owned(),
                expected: expected.to_owned(),
                actual: actual.to_owned(),
            });
        }
    }

    for group in &derived_independent {
        let roles = &group_roles[group];
        if !roles
            .iter()
            .any(|role| role == "runtime" || role == "runtime_policy")
        {
            return Err(CorpusError::MissingAuthorityRole {
                group: group.clone(),
                role: "runtime".to_owned(),
            });
        }
        if !roles
            .iter()
            .any(|role| role == "conformance" || role == "conformance_fixture")
        {
            return Err(CorpusError::MissingAuthorityRole {
                group: group.clone(),
                role: "conformance".to_owned(),
            });
        }
    }
    Ok(())
}

fn unique_declared_groups(class: &str, groups: &[String]) -> Result<BTreeSet<String>, CorpusError> {
    let mut unique = BTreeSet::new();
    for group in groups {
        if !unique.insert(group.clone()) {
            return Err(CorpusError::DuplicateGroupDeclaration {
                class: class.to_owned(),
                group: group.clone(),
            });
        }
    }
    Ok(unique)
}

fn groups_for_class(
    group_classes: &BTreeMap<String, BTreeSet<String>>,
    class: &str,
) -> BTreeSet<String> {
    group_classes
        .iter()
        .filter(|(_, classes)| classes.contains(class))
        .map(|(group, _)| group.clone())
        .collect()
}

fn exact_groups(
    class: &str,
    declared: &BTreeSet<String>,
    derived: &BTreeSet<String>,
) -> Result<(), CorpusError> {
    if declared != derived {
        return Err(CorpusError::AuthorityGroupsMismatch {
            class: class.to_owned(),
            declared: declared.iter().cloned().collect(),
            derived: derived.iter().cloned().collect(),
        });
    }
    Ok(())
}

fn verify_source(
    root: &Path,
    authority: &str,
    repository: &RepositoryPin,
    snapshot_path: &str,
    expected_digest: &str,
) -> Result<(), CorpusError> {
    if !safe_relative_path(snapshot_path) {
        return Err(CorpusError::UnsafeSnapshot(snapshot_path.to_owned()));
    }
    if !is_lower_hex(&repository.commit, 40) {
        return Err(CorpusError::InvalidCommit {
            authority: authority.to_owned(),
            commit: repository.commit.clone(),
        });
    }
    if !is_lower_hex(expected_digest, 64) {
        return Err(CorpusError::InvalidDigest {
            authority: authority.to_owned(),
            digest: expected_digest.to_owned(),
        });
    }
    let bytes =
        fs::read(root.join(snapshot_path)).map_err(|error| CorpusError::Io(error.to_string()))?;
    let actual = sha256(&bytes);
    if actual != expected_digest {
        return Err(CorpusError::DigestMismatch {
            authority: authority.to_owned(),
            expected: expected_digest.to_owned(),
            actual,
        });
    }
    Ok(())
}

fn safe_relative_path(path: &str) -> bool {
    let path = Path::new(path);
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut rendered = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(rendered, "{byte:02x}");
    }
    rendered
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    ReactDom,
    VueRuntimeDom,
    Ink,
}

impl Ecosystem {
    pub fn authority_group(self) -> &'static str {
        match self {
            Self::ReactDom => "react_dom",
            Self::VueRuntimeDom => "vue_runtime_dom",
            Self::Ink => "ink_terminal",
        }
    }

    pub fn extension_key(self) -> &'static str {
        match self {
            Self::ReactDom => "org.reactjs.native.activation",
            Self::VueRuntimeDom => "org.vuejs.native.activation",
            Self::Ink => "dev.ink.native.activation",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationRole {
    IndependentVote,
    SameSystemParticipant,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLineage {
    React,
    Vue,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageParticipation {
    Authority,
    Renderer,
}

impl LineageParticipation {
    fn role(self) -> ObservationRole {
        match self {
            Self::Authority => ObservationRole::IndependentVote,
            Self::Renderer => ObservationRole::SameSystemParticipant,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLineage {
    pub runtime: RuntimeLineage,
    pub participation: LineageParticipation,
    pub evidence: Vec<LineageEvidence>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LineageEvidence {
    pub relation: String,
    pub source: String,
    pub node_type: String,
    pub loc: Value,
    pub span: Value,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// Exact references to the audited source bytes supporting one generated
/// observation. Audit annotations are intentionally absent: this projection is
/// admitted only by generated source locations and byte-locked authorities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSource {
    pub authority_id: String,
    pub repository: RepositoryPin,
    pub source_path: String,
    pub snapshot_path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceChain {
    pub binding: Value,
    pub stimulus: Value,
    pub assertion: Value,
    /// The target runtime's concrete call site that invokes the registered
    /// handler. Without this edge, a test declaration alone is not a callable
    /// positive witness.
    pub runtime_handler_invocation: Value,
    /// Parser-specific evidence stays available to later consumers.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// Target-native meaning that deliberately does not enter the shared contract.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NativeActivationExtension {
    pub audit_subject_id: String,
    pub authority_group: String,
    pub ecosystem: Ecosystem,
    pub host: Value,
    pub binding_form: Value,
    pub stimulus_form: Value,
    pub assertion_form: Value,
    pub suppression: Value,
    pub chain: EvidenceChain,
    pub sources: Vec<ObservationSource>,
    /// Generator-native additions survive admission without entering the
    /// shared comparison contract.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NativeObservation {
    pub audit_subject_id: String,
    pub authority_group: String,
    pub role: ObservationRole,
    pub lineage: SourceLineage,
    pub ecosystem: Ecosystem,
    pub activation: Defeasible<ActionActivation>,
    pub scoped_defeats: Vec<ScopedDefeat>,
    pub native: NativeActivationExtension,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefeatImpact {
    Blocking,
    DisjointFromPositiveWitness,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedDefeat {
    pub impact: DefeatImpact,
    pub defeat: Defeat,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiftedObservationDocument {
    protocol: String,
    generator: LiftGenerator,
    observations: Vec<LiftedObservation>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiftGenerator {
    name: String,
    version: String,
    implementation_paths: Vec<String>,
    implementation_sha256: String,
    package_lock_path: String,
    package_lock_sha256: String,
    parser: ParserPin,
    authority_lock_sha256: String,
    evidence_kind: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParserPin {
    package: String,
    version: String,
    config: Value,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiftedObservation {
    audit_subject_id: String,
    authority_group: String,
    ecosystem: Ecosystem,
    lineage: SourceLineage,
    semantic: ActionActivation,
    chain: EvidenceChain,
    native: LiftedNative,
    sources: Vec<ObservationSource>,
    #[serde(default)]
    defeats: Vec<LiftedScopedDefeat>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiftedScopedDefeat {
    impact: DefeatImpact,
    defeat: LiftedDefeat,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LiftedDefeat {
    kind: DefeatKind,
    subject: String,
    reason: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
struct LiftedNative {
    host: Value,
    binding_form: Value,
    stimulus_form: Value,
    assertion_form: Value,
    suppression: Value,
    #[serde(flatten)]
    extensions: BTreeMap<String, Value>,
}

/// Loads the generated source projection and admits it against the verified
/// authority lock. This function never interprets `establishes` or `defeats`
/// labels from the audit lock.
pub fn observed_core_authorities(
    corpus: &VerifiedCorpus,
) -> Result<Vec<NativeObservation>, CorpusError> {
    load_lifted_observations(corpus, corpus.root.join("observations.lift.json"))
}

pub fn load_lifted_observations(
    corpus: &VerifiedCorpus,
    path: impl AsRef<Path>,
) -> Result<Vec<NativeObservation>, CorpusError> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            CorpusError::MissingLiftedObservations(path.display().to_string())
        } else {
            CorpusError::Io(error.to_string())
        }
    })?;
    if bytes != CANONICAL_OBSERVATIONS {
        return Err(CorpusError::InvalidLift(format!(
            "observation projection digest {} does not equal canonical generated digest {}",
            sha256(&bytes),
            sha256(CANONICAL_OBSERVATIONS)
        )));
    }
    let document: LiftedObservationDocument = serde_json::from_slice(&bytes)
        .map_err(|error| CorpusError::InvalidLift(error.to_string()))?;
    if document.protocol != OBSERVATIONS_PROTOCOL {
        return Err(CorpusError::LiftProtocol {
            expected: OBSERVATIONS_PROTOCOL.to_owned(),
            actual: document.protocol,
        });
    }
    if document.generator.name.trim().is_empty()
        || document.generator.version.trim().is_empty()
        || document.generator.parser.package.trim().is_empty()
        || document.generator.parser.version.trim().is_empty()
        || document.generator.evidence_kind.trim().is_empty()
        || !meaningful(&document.generator.parser.config)
    {
        return Err(CorpusError::InvalidLift(
            "generator, parser, parser configuration, and evidence identities must be non-blank"
                .to_owned(),
        ));
    }
    verify_generator_pin(&document.generator)?;
    let authority_lock = fs::read(corpus.root.join("authorities.lock.json"))
        .map_err(|error| CorpusError::Io(error.to_string()))?;
    let expected_lock_digest = sha256(&authority_lock);
    if document.generator.authority_lock_sha256 != expected_lock_digest {
        return Err(CorpusError::AuthorityLockDigestMismatch {
            expected: expected_lock_digest,
            actual: document.generator.authority_lock_sha256,
        });
    }

    let mut seen_groups = BTreeSet::new();
    let mut observations = Vec::new();
    for lifted in document.observations {
        if !seen_groups.insert(lifted.authority_group.clone()) {
            return Err(CorpusError::InvalidLift(format!(
                "duplicate observation for authority group `{}`",
                lifted.authority_group
            )));
        }
        observations.push(admit_observation(corpus, lifted)?);
    }
    let expected_groups = ["react_dom", "vue_runtime_dom", "ink_terminal"]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if seen_groups != expected_groups {
        return Err(CorpusError::InvalidLift(format!(
            "observation groups {seen_groups:?} do not equal required source projections {expected_groups:?}"
        )));
    }
    Ok(observations)
}

fn verify_generator_pin(generator: &LiftGenerator) -> Result<(), CorpusError> {
    const TOOL_NAME: &str = "@gooir/interaction-activation-lifters";
    const TOOL_VERSION: &str = "0.1.0";
    const PARSER_PACKAGE: &str = "@babel/parser";
    const PARSER_VERSION: &str = "7.29.8";
    const EVIDENCE_KIND: &str = "static_source_path_with_declared_test_corroboration";
    const IMPLEMENTATION_PATHS: [&str; 7] = [
        "tools/interaction-activation-lifters/package.json",
        "tools/interaction-activation-lifters/src/ast.mjs",
        "tools/interaction-activation-lifters/src/cli.mjs",
        "tools/interaction-activation-lifters/src/ink.mjs",
        "tools/interaction-activation-lifters/src/lift.mjs",
        "tools/interaction-activation-lifters/src/react.mjs",
        "tools/interaction-activation-lifters/src/vue.mjs",
    ];
    const PACKAGE_LOCK_PATH: &str = "tools/interaction-activation-lifters/package-lock.json";

    if generator.name != TOOL_NAME
        || generator.version != TOOL_VERSION
        || generator.parser.package != PARSER_PACKAGE
        || generator.parser.version != PARSER_VERSION
        || generator.evidence_kind != EVIDENCE_KIND
    {
        return Err(CorpusError::InvalidLift(format!(
            "generator identity must be {TOOL_NAME}@{TOOL_VERSION}, parser must be {PARSER_PACKAGE}@{PARSER_VERSION}, and evidence kind must be `{EVIDENCE_KIND}`"
        )));
    }
    let expected_parser_config = json!({
        "source_type": "unambiguous",
        "error_recovery": false,
        "variants": {
            "flow_jsx": {"plugins": ["flow", "jsx"]},
            "typescript_jsx": {"plugins": ["typescript", "jsx"]}
        },
        "authority_variants": {
            "react_dom.simple_event_plugin.runtime": "typescript_jsx",
            "react_dom.dom_plugin_event_system.runtime": "typescript_jsx",
            "react_dom.simple_event_plugin.conformance": "flow_jsx",
            "vue_runtime_dom.events.runtime": "typescript_jsx",
            "vue_runtime_dom.patch_events.conformance": "typescript_jsx",
            "ink.use_input.runtime": "typescript_jsx",
            "ink.reconciler.runtime": "typescript_jsx",
            "ink.use_input_multiple.fixture": "typescript_jsx",
            "ink.use_input.conformance": "typescript_jsx"
        }
    });
    if generator.parser.config != expected_parser_config {
        return Err(CorpusError::InvalidLift(
            "parser configuration does not equal the admitted Babel configuration".to_owned(),
        ));
    }
    if generator.implementation_paths
        != IMPLEMENTATION_PATHS
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    {
        return Err(CorpusError::InvalidLift(
            "generator implementation path set is not the admitted canonical tool".to_owned(),
        ));
    }
    if generator.package_lock_path != PACKAGE_LOCK_PATH {
        return Err(CorpusError::InvalidLift(format!(
            "generator package lock `{}` is not `{PACKAGE_LOCK_PATH}`",
            generator.package_lock_path
        )));
    }
    if !is_lower_hex(&generator.implementation_sha256, 64)
        || !is_lower_hex(&generator.package_lock_sha256, 64)
    {
        return Err(CorpusError::InvalidLift(
            "generator implementation and package-lock digests must be lower-case SHA-256"
                .to_owned(),
        ));
    }

    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut implementation_hash = Sha256::new();
    for relative in &generator.implementation_paths {
        if !safe_relative_path(relative) {
            return Err(CorpusError::InvalidLift(format!(
                "unsafe generator implementation path `{relative}`"
            )));
        }
        implementation_hash.update(relative.as_bytes());
        implementation_hash.update([0]);
        let bytes = fs::read(repository_root.join(relative))
            .map_err(|error| CorpusError::InvalidLift(error.to_string()))?;
        implementation_hash.update(bytes);
        implementation_hash.update([0]);
    }
    let actual_implementation = lower_hex_digest(implementation_hash.finalize());
    if actual_implementation != generator.implementation_sha256 {
        return Err(CorpusError::InvalidLift(format!(
            "generator implementation digest mismatch: expected {}, got {actual_implementation}",
            generator.implementation_sha256
        )));
    }

    let package_lock_bytes = fs::read(repository_root.join(PACKAGE_LOCK_PATH))
        .map_err(|error| CorpusError::InvalidLift(error.to_string()))?;
    let actual_package_lock = sha256(&package_lock_bytes);
    if actual_package_lock != generator.package_lock_sha256 {
        return Err(CorpusError::InvalidLift(format!(
            "generator package-lock digest mismatch: expected {}, got {actual_package_lock}",
            generator.package_lock_sha256
        )));
    }
    let package_lock: Value = serde_json::from_slice(&package_lock_bytes)
        .map_err(|error| CorpusError::InvalidLift(error.to_string()))?;
    let package_key = format!("node_modules/{}", generator.parser.package);
    let locked_version = package_lock
        .get("packages")
        .and_then(|packages| packages.get(&package_key))
        .and_then(|package| package.get("version"))
        .and_then(Value::as_str);
    if locked_version != Some(generator.parser.version.as_str()) {
        return Err(CorpusError::InvalidLift(format!(
            "parser {}@{} is not pinned by the generator package lock",
            generator.parser.package, generator.parser.version
        )));
    }
    Ok(())
}

fn lower_hex_digest(digest: impl AsRef<[u8]>) -> String {
    let bytes = digest.as_ref();
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(rendered, "{byte:02x}");
    }
    rendered
}

fn admit_observation(
    corpus: &VerifiedCorpus,
    lifted: LiftedObservation,
) -> Result<NativeObservation, CorpusError> {
    if lifted.audit_subject_id.trim().is_empty() {
        return Err(CorpusError::InvalidLift(
            "audit_subject_id must be non-blank".to_owned(),
        ));
    }
    if lifted.authority_group != lifted.ecosystem.authority_group() {
        return Err(CorpusError::InvalidLift(format!(
            "ecosystem {:?} does not own authority group `{}`",
            lifted.ecosystem, lifted.authority_group
        )));
    }
    let expected_lineage = match lifted.ecosystem {
        Ecosystem::ReactDom => (RuntimeLineage::React, LineageParticipation::Authority),
        Ecosystem::VueRuntimeDom => (RuntimeLineage::Vue, LineageParticipation::Authority),
        Ecosystem::Ink => (RuntimeLineage::React, LineageParticipation::Renderer),
    };
    if (lifted.lineage.runtime, lifted.lineage.participation) != expected_lineage {
        return Err(CorpusError::InvalidLift(format!(
            "ecosystem {:?} has source lineage {:?}/{:?}, expected {expected_lineage:?}",
            lifted.ecosystem, lifted.lineage.runtime, lifted.lineage.participation
        )));
    }
    validate_lineage(&lifted)?;
    if lifted.semantic.action_id != lifted.audit_subject_id {
        return Err(CorpusError::InvalidLift(format!(
            "generated semantic identity `{}` does not equal audit subject `{}`",
            lifted.semantic.action_id, lifted.audit_subject_id
        )));
    }
    lifted.semantic.verify().map_err(|errors| {
        CorpusError::InvalidLift(format!(
            "audit subject `{}` failed semantic verification: {errors:?}",
            lifted.audit_subject_id
        ))
    })?;
    for (dimension, value) in [
        ("host", &lifted.native.host),
        ("binding_form", &lifted.native.binding_form),
        ("stimulus_form", &lifted.native.stimulus_form),
        ("assertion_form", &lifted.native.assertion_form),
        ("suppression", &lifted.native.suppression),
        ("chain.binding", &lifted.chain.binding),
        ("chain.stimulus", &lifted.chain.stimulus),
        ("chain.assertion", &lifted.chain.assertion),
        (
            "chain.runtime_handler_invocation",
            &lifted.chain.runtime_handler_invocation,
        ),
    ] {
        if !meaningful(value) {
            return Err(CorpusError::InvalidLift(format!(
                "audit subject `{}` is missing required native dimension `{dimension}`",
                lifted.audit_subject_id
            )));
        }
    }

    let group_entries = corpus
        .manifest
        .authorities
        .iter()
        .filter(|entry| entry.authority_group == lifted.authority_group)
        .collect::<Vec<_>>();
    if group_entries.is_empty() {
        return Err(CorpusError::MissingCoreAuthority(lifted.authority_group));
    }
    let classes = group_entries
        .iter()
        .map(|entry| entry.authority_class.as_str())
        .collect::<BTreeSet<_>>();
    let role = lifted.lineage.participation.role();
    let expected_class = match role {
        ObservationRole::IndependentVote => "independent_runtime",
        ObservationRole::SameSystemParticipant => "same_system_participant",
    };
    match classes.iter().copied().collect::<Vec<_>>().as_slice() {
        [actual] if *actual == expected_class => {}
        _ => {
            return Err(CorpusError::InvalidLift(format!(
                "source-derived lineage role for `{}` does not agree with its lock classification",
                lifted.audit_subject_id
            )));
        }
    }

    let mut seen_sources = BTreeSet::new();
    let mut source_roles = BTreeSet::new();
    for source in &lifted.sources {
        if !seen_sources.insert(source.authority_id.clone()) {
            return Err(CorpusError::InvalidLift(format!(
                "audit subject `{}` duplicates source `{}`",
                lifted.audit_subject_id, source.authority_id
            )));
        }
        let authority = corpus.authority(&source.authority_id).ok_or_else(|| {
            CorpusError::InvalidLift(format!(
                "audit subject `{}` cites unknown authority `{}`",
                lifted.audit_subject_id, source.authority_id
            ))
        })?;
        if authority.authority_group != lifted.authority_group
            || authority.repository != source.repository
            || authority.source_path != source.source_path
            || authority.snapshot_path != source.snapshot_path
            || authority.sha256 != source.sha256
        {
            return Err(CorpusError::InvalidLift(format!(
                "source `{}` does not exactly match its locked authority entry",
                source.authority_id
            )));
        }
        source_roles.insert(authority.role.as_str());
    }
    if !source_roles
        .iter()
        .any(|role| *role == "runtime" || *role == "runtime_policy")
        || !source_roles
            .iter()
            .any(|role| *role == "conformance" || *role == "conformance_fixture")
    {
        return Err(CorpusError::InvalidLift(format!(
            "audit subject `{}` must cite runtime and conformance source projections",
            lifted.audit_subject_id
        )));
    }
    validate_evidence_projection(
        corpus,
        &lifted.audit_subject_id,
        &seen_sources,
        &lifted.lineage,
        &lifted.chain,
        &lifted.native.suppression,
    )?;

    let native = NativeActivationExtension {
        audit_subject_id: lifted.audit_subject_id.clone(),
        authority_group: lifted.authority_group.clone(),
        ecosystem: lifted.ecosystem,
        host: lifted.native.host,
        binding_form: lifted.native.binding_form,
        stimulus_form: lifted.native.stimulus_form,
        assertion_form: lifted.native.assertion_form,
        suppression: lifted.native.suppression,
        chain: lifted.chain,
        sources: lifted.sources,
        extensions: lifted.native.extensions,
    };
    let mut semantic = lifted.semantic;
    let extension_key = lifted.ecosystem.extension_key().to_owned();
    if semantic.extensions.contains_key(&extension_key) {
        return Err(CorpusError::InvalidLift(format!(
            "generated semantic fact already occupies recurrence extension `{extension_key}`"
        )));
    }
    semantic.extensions.insert(
        extension_key,
        serde_json::to_value(&native)
            .map_err(|error| CorpusError::InvalidLift(error.to_string()))?,
    );
    let scoped_defeats = lifted
        .defeats
        .into_iter()
        .map(|scoped| ScopedDefeat {
            impact: scoped.impact,
            defeat: Defeat::new(
                scoped.defeat.kind,
                scoped.defeat.subject,
                scoped.defeat.reason,
            ),
        })
        .collect::<Vec<_>>();
    let mut activation = Defeasible::new(semantic, DEFEATER_SET);
    for scoped in &scoped_defeats {
        activation.defeat(scoped.defeat.clone());
    }

    Ok(NativeObservation {
        audit_subject_id: lifted.audit_subject_id,
        authority_group: lifted.authority_group,
        role,
        lineage: lifted.lineage,
        ecosystem: lifted.ecosystem,
        activation,
        scoped_defeats,
        native,
    })
}

fn meaningful(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => !values.is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

fn validate_lineage(lifted: &LiftedObservation) -> Result<(), CorpusError> {
    let actual = lifted
        .lineage
        .evidence
        .iter()
        .map(|evidence| {
            (
                evidence.relation.as_str(),
                evidence.source.as_str(),
                evidence.node_type.as_str(),
                evidence.extensions.get("module").and_then(Value::as_str),
            )
        })
        .collect::<BTreeSet<_>>();
    if actual.len() != lifted.lineage.evidence.len() {
        return Err(CorpusError::InvalidLift(format!(
            "audit subject `{}` has duplicate lineage evidence",
            lifted.audit_subject_id
        )));
    }
    let expected = match (lifted.lineage.runtime, lifted.lineage.participation) {
        (RuntimeLineage::React, LineageParticipation::Authority) => [
            (
                "defines_plugin_extractor",
                "react_dom.simple_event_plugin.runtime",
                "FunctionDeclaration",
                None,
            ),
            (
                "defines_dispatch_executor",
                "react_dom.dom_plugin_event_system.runtime",
                "FunctionDeclaration",
                None,
            ),
        ]
        .into_iter()
        .collect(),
        (RuntimeLineage::Vue, LineageParticipation::Authority) => [
            (
                "defines_runtime_event_patch",
                "vue_runtime_dom.events.runtime",
                "FunctionDeclaration",
                None,
            ),
            (
                "invokes_runtime_handler",
                "vue_runtime_dom.events.runtime",
                "CallExpression",
                None,
            ),
        ]
        .into_iter()
        .collect(),
        (RuntimeLineage::React, LineageParticipation::Renderer) => [
            (
                "imports_local_reconciler",
                "ink.use_input.runtime",
                "ImportDeclaration",
                Some("../reconciler.js"),
            ),
            (
                "imports_react_reconciler",
                "ink.reconciler.runtime",
                "ImportDeclaration",
                Some("react-reconciler"),
            ),
            (
                "imports_react_runtime",
                "ink.reconciler.runtime",
                "ImportDeclaration",
                Some("react"),
            ),
        ]
        .into_iter()
        .collect(),
        (RuntimeLineage::Vue, LineageParticipation::Renderer) => {
            return Err(CorpusError::InvalidLift(format!(
                "audit subject `{}` declares an unsupported Vue renderer lineage",
                lifted.audit_subject_id
            )));
        }
    };
    if actual != expected {
        return Err(CorpusError::InvalidLift(format!(
            "audit subject `{}` lineage evidence {actual:?} does not equal required source-derived evidence {expected:?}",
            lifted.audit_subject_id
        )));
    }
    Ok(())
}

fn validate_evidence_projection(
    corpus: &VerifiedCorpus,
    audit_subject_id: &str,
    admitted_sources: &BTreeSet<String>,
    lineage: &SourceLineage,
    chain: &EvidenceChain,
    suppression: &Value,
) -> Result<(), CorpusError> {
    let mut contents = BTreeMap::new();
    for authority_id in admitted_sources {
        let authority = corpus.authority(authority_id).ok_or_else(|| {
            CorpusError::InvalidLift(format!("unknown admitted source `{authority_id}`"))
        })?;
        let source = fs::read_to_string(corpus.root.join(&authority.snapshot_path))
            .map_err(|error| CorpusError::InvalidLift(error.to_string()))?;
        contents.insert(authority_id.clone(), source);
    }

    let chain_value =
        serde_json::to_value(chain).map_err(|error| CorpusError::InvalidLift(error.to_string()))?;
    let mut referenced = BTreeSet::new();
    let lineage_value = serde_json::to_value(lineage)
        .map_err(|error| CorpusError::InvalidLift(error.to_string()))?;
    validate_evidence_value(
        audit_subject_id,
        "lineage",
        &lineage_value,
        &contents,
        &mut referenced,
    )?;
    validate_evidence_value(
        audit_subject_id,
        "chain",
        &chain_value,
        &contents,
        &mut referenced,
    )?;
    validate_evidence_value(
        audit_subject_id,
        "native.suppression",
        suppression,
        &contents,
        &mut referenced,
    )?;
    if &referenced != admitted_sources {
        return Err(CorpusError::InvalidLift(format!(
            "audit subject `{audit_subject_id}` evidence references {referenced:?}, but its admitted sources are {admitted_sources:?}"
        )));
    }
    Ok(())
}

fn validate_evidence_value(
    audit_subject_id: &str,
    path: &str,
    value: &Value,
    contents: &BTreeMap<String, String>,
    referenced: &mut BTreeSet<String>,
) -> Result<(), CorpusError> {
    match value {
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_evidence_value(
                    audit_subject_id,
                    &format!("{path}[{index}]"),
                    child,
                    contents,
                    referenced,
                )?;
            }
        }
        Value::Object(object) => {
            if object.contains_key("source")
                || object.contains_key("node_type")
                || object.contains_key("loc")
                || object.contains_key("span")
            {
                validate_evidence_item(audit_subject_id, path, object, contents, referenced)?;
            }
            for (field, child) in object {
                validate_evidence_value(
                    audit_subject_id,
                    &format!("{path}.{field}"),
                    child,
                    contents,
                    referenced,
                )?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn validate_evidence_item(
    audit_subject_id: &str,
    path: &str,
    object: &serde_json::Map<String, Value>,
    contents: &BTreeMap<String, String>,
    referenced: &mut BTreeSet<String>,
) -> Result<(), CorpusError> {
    let invalid = |reason: &str| {
        CorpusError::InvalidLift(format!(
            "audit subject `{audit_subject_id}` has invalid evidence `{path}`: {reason}"
        ))
    };
    let source_id = object
        .get("source")
        .and_then(Value::as_str)
        .filter(|source| !source.trim().is_empty())
        .ok_or_else(|| invalid("missing source"))?;
    let source = contents
        .get(source_id)
        .ok_or_else(|| invalid("source is not in the observation's admitted source set"))?;
    let _node_type = object
        .get("node_type")
        .and_then(Value::as_str)
        .filter(|node_type| !node_type.trim().is_empty())
        .ok_or_else(|| invalid("missing node_type"))?;
    let utf16_start = evidence_offset(object, &["span", "utf16", "start"])
        .ok_or_else(|| invalid("missing UTF-16 start offset"))?;
    let utf16_end = evidence_offset(object, &["span", "utf16", "end"])
        .ok_or_else(|| invalid("missing UTF-16 end offset"))?;
    let utf8_start = evidence_offset(object, &["span", "utf8_bytes", "start"])
        .ok_or_else(|| invalid("missing UTF-8 start offset"))?;
    let utf8_end = evidence_offset(object, &["span", "utf8_bytes", "end"])
        .ok_or_else(|| invalid("missing UTF-8 end offset"))?;
    if utf16_end <= utf16_start || utf8_end <= utf8_start {
        return Err(invalid("span is empty or reversed"));
    }
    let derived_start = utf16_offset_to_byte(source, utf16_start)
        .ok_or_else(|| invalid("UTF-16 start is not a source boundary"))?;
    let derived_end = utf16_offset_to_byte(source, utf16_end)
        .ok_or_else(|| invalid("UTF-16 end is not a source boundary"))?;
    if (utf8_start, utf8_end) != (derived_start, derived_end) {
        return Err(invalid("UTF-8 byte offsets do not match the UTF-16 span"));
    }

    let start_line = evidence_offset(object, &["loc", "start", "line"])
        .ok_or_else(|| invalid("missing start line"))?;
    let start_column = evidence_offset(object, &["loc", "start", "column"])
        .ok_or_else(|| invalid("missing start column"))?;
    let end_line = evidence_offset(object, &["loc", "end", "line"])
        .ok_or_else(|| invalid("missing end line"))?;
    let end_column = evidence_offset(object, &["loc", "end", "column"])
        .ok_or_else(|| invalid("missing end column"))?;
    if source_location(source, derived_start) != Some((start_line, start_column))
        || source_location(source, derived_end) != Some((end_line, end_column))
    {
        return Err(invalid(
            "line/column location does not match the source span",
        ));
    }
    referenced.insert(source_id.to_owned());
    Ok(())
}

fn evidence_offset(object: &serde_json::Map<String, Value>, path: &[&str]) -> Option<usize> {
    let mut value = object.get(*path.first()?)?;
    for component in &path[1..] {
        value = value.get(*component)?;
    }
    usize::try_from(value.as_u64()?).ok()
}

fn utf16_offset_to_byte(source: &str, target: usize) -> Option<usize> {
    let mut utf16_offset = 0;
    for (byte_offset, character) in source.char_indices() {
        if utf16_offset == target {
            return Some(byte_offset);
        }
        utf16_offset += character.len_utf16();
        if utf16_offset > target {
            return None;
        }
    }
    (utf16_offset == target).then_some(source.len())
}

fn source_location(source: &str, byte_offset: usize) -> Option<(usize, usize)> {
    if byte_offset > source.len() || !source.is_char_boundary(byte_offset) {
        return None;
    }
    let prefix = &source[..byte_offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let line_start = prefix.rfind('\n').map_or(0, |offset| offset + 1);
    let column = prefix[line_start..].encode_utf16().count();
    Some((line, column))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceDimension {
    Host,
    BindingForm,
    StimulusForm,
    AssertionForm,
    Suppression,
}

impl DivergenceDimension {
    fn field(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::BindingForm => "binding_form",
            Self::StimulusForm => "stimulus_form",
            Self::AssertionForm => "assertion_form",
            Self::Suppression => "suppression",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeDivergence {
    pub dimension: DivergenceDimension,
    pub values: BTreeMap<Ecosystem, Value>,
    /// Every divergence emitted here was recovered from the opaque extension
    /// carried by that authority's semantic fact.
    pub preserved_extension_keys: BTreeMap<Ecosystem, String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecurrenceReport {
    pub independent_authorities: usize,
    pub same_system_participants: usize,
    pub established_observations: usize,
    pub compared_shared_attributes: usize,
    pub recurring_outcome: Option<ActivationOutcome>,
    pub coverage: Completeness,
    pub defeats: Vec<Defeat>,
    pub blocking_defeats: Vec<Defeat>,
    /// Blocking defeats belonging to independent authority lineages. Only
    /// these can prevent the recurrence claim.
    pub recurrence_blocking_defeats: Vec<Defeat>,
    /// Participant defects remain visible without granting a same-lineage
    /// renderer a veto over independent recurrence.
    pub participant_blocking_defeats: Vec<Defeat>,
    pub disjoint_defeats: Vec<Defeat>,
    pub evidence_gaps: Vec<EvidenceGap>,
    pub compared_native_dimensions: Vec<DivergenceDimension>,
    pub equal_native_dimensions: Vec<DivergenceDimension>,
    pub native_divergences: Vec<NativeDivergence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceGap {
    pub audit_subject_id: String,
    pub dimension: Option<DivergenceDimension>,
    pub reason: String,
}

fn record_blocking_defeat(
    defeat: Defeat,
    affects_independent_recurrence: bool,
    defeats: &mut Vec<Defeat>,
    blocking_defeats: &mut Vec<Defeat>,
    recurrence_blocking_defeats: &mut Vec<Defeat>,
    participant_blocking_defeats: &mut Vec<Defeat>,
) {
    defeats.push(defeat.clone());
    blocking_defeats.push(defeat.clone());
    if affects_independent_recurrence {
        recurrence_blocking_defeats.push(defeat);
    } else {
        participant_blocking_defeats.push(defeat);
    }
}

pub fn compare(observations: &[NativeObservation]) -> RecurrenceReport {
    let authority_count = observations
        .iter()
        .filter(|observation| observation.lineage.participation == LineageParticipation::Authority)
        .map(|observation| observation.lineage.runtime)
        .collect::<BTreeSet<_>>()
        .len();
    let participant_count = observations
        .iter()
        .filter(|observation| observation.lineage.participation == LineageParticipation::Renderer)
        .map(|observation| observation.ecosystem)
        .collect::<BTreeSet<_>>()
        .len();
    let mut defeats = Vec::new();
    let mut blocking_defeats = Vec::new();
    let mut recurrence_blocking_defeats = Vec::new();
    let mut participant_blocking_defeats = Vec::new();
    let mut disjoint_defeats = Vec::new();
    let mut evidence_gaps = Vec::new();
    let mut seen_ecosystems = BTreeSet::new();
    let mut established_observations = 0;

    for observation in observations {
        let affects_independent_recurrence =
            observation.lineage.participation == LineageParticipation::Authority;
        if !seen_ecosystems.insert(observation.ecosystem) {
            let defeat = Defeat::new(
                DefeatKind::LookedAndBlocked,
                format!("{}.authority_identity", observation.authority_group),
                "comparison received more than one observation for the same ecosystem",
            );
            record_blocking_defeat(
                defeat,
                affects_independent_recurrence,
                &mut defeats,
                &mut blocking_defeats,
                &mut recurrence_blocking_defeats,
                &mut participant_blocking_defeats,
            );
        }
        if observation.authority_group != observation.ecosystem.authority_group()
            || observation.native.audit_subject_id != observation.audit_subject_id
            || observation.native.authority_group != observation.authority_group
            || observation.native.ecosystem != observation.ecosystem
            || observation.role != observation.lineage.participation.role()
        {
            let defeat = Defeat::new(
                DefeatKind::LookedAndBlocked,
                format!("{}.observation_identity", observation.audit_subject_id),
                "outer observation, source authority group, and preserved native projection identities disagree",
            );
            record_blocking_defeat(
                defeat,
                affects_independent_recurrence,
                &mut defeats,
                &mut blocking_defeats,
                &mut recurrence_blocking_defeats,
                &mut participant_blocking_defeats,
            );
        }
        if observation.activation.value.verify().is_ok()
            && observation.activation.value.action_id == observation.audit_subject_id
        {
            established_observations += 1;
        } else {
            let defeat = Defeat::new(
                DefeatKind::LookedAndBlocked,
                format!("{}.semantic_activation", observation.audit_subject_id),
                format!(
                    "generated activation failed verification or does not retain its audit-local subject identity: {:?}",
                    observation.activation.value.verify().err()
                ),
            );
            record_blocking_defeat(
                defeat,
                affects_independent_recurrence,
                &mut defeats,
                &mut blocking_defeats,
                &mut recurrence_blocking_defeats,
                &mut participant_blocking_defeats,
            );
        }
        let scoped_raw = observation
            .scoped_defeats
            .iter()
            .map(|scoped| scoped.defeat.clone())
            .collect::<Vec<_>>();
        if scoped_raw != observation.activation.defeats {
            let defeat = Defeat::new(
                DefeatKind::LookedAndBlocked,
                format!("{}.defeat_admission", observation.audit_subject_id),
                "raw activation defeats do not exactly match their typed admitted impacts",
            );
            record_blocking_defeat(
                defeat,
                affects_independent_recurrence,
                &mut defeats,
                &mut blocking_defeats,
                &mut recurrence_blocking_defeats,
                &mut participant_blocking_defeats,
            );
        }
        for scoped in &observation.scoped_defeats {
            defeats.push(scoped.defeat.clone());
            match scoped.impact {
                DefeatImpact::Blocking => {
                    blocking_defeats.push(scoped.defeat.clone());
                    if affects_independent_recurrence {
                        recurrence_blocking_defeats.push(scoped.defeat.clone());
                    } else {
                        participant_blocking_defeats.push(scoped.defeat.clone());
                    }
                }
                DefeatImpact::DisjointFromPositiveWitness => {
                    disjoint_defeats.push(scoped.defeat.clone());
                }
            }
        }
        let key = observation.ecosystem.extension_key();
        match observation.activation.value.extensions.get(key) {
            Some(extension)
                if serde_json::to_value(&observation.native)
                    .is_ok_and(|native| native == *extension) => {}
            _ => {
                let defeat = Defeat::new(
                    DefeatKind::LookedAndBlocked,
                    format!("{}.native_extension", observation.audit_subject_id),
                    format!(
                        "required native extension `{key}` is missing or disagrees with the admitted projection"
                    ),
                );
                record_blocking_defeat(
                    defeat,
                    affects_independent_recurrence,
                    &mut defeats,
                    &mut blocking_defeats,
                    &mut recurrence_blocking_defeats,
                    &mut participant_blocking_defeats,
                );
                evidence_gaps.push(EvidenceGap {
                    audit_subject_id: observation.audit_subject_id.clone(),
                    dimension: None,
                    reason: format!("missing or inconsistent `{key}`"),
                });
            }
        }
    }

    let expected_ecosystems = [Ecosystem::ReactDom, Ecosystem::VueRuntimeDom]
        .into_iter()
        .collect::<BTreeSet<_>>();
    for missing in expected_ecosystems.difference(&seen_ecosystems) {
        let defeat = Defeat::new(
            DefeatKind::NotLooked,
            format!("{}.observation", missing.authority_group()),
            "required generated source projection is absent",
        );
        record_blocking_defeat(
            defeat,
            true,
            &mut defeats,
            &mut blocking_defeats,
            &mut recurrence_blocking_defeats,
            &mut participant_blocking_defeats,
        );
        evidence_gaps.push(EvidenceGap {
            audit_subject_id: missing.authority_group().to_owned(),
            dimension: None,
            reason: "required ecosystem observation is absent".to_owned(),
        });
    }

    let independent_lineages = observations
        .iter()
        .filter(|observation| observation.lineage.participation == LineageParticipation::Authority)
        .map(|observation| observation.lineage.runtime)
        .collect::<BTreeSet<_>>();
    let expected_independent = [RuntimeLineage::React, RuntimeLineage::Vue]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if independent_lineages != expected_independent {
        let defeat = Defeat::new(
            DefeatKind::AuthorityCannotExpress,
            "interaction_activation.independent_lineages",
            format!(
                "independent runtime lineages {independent_lineages:?} do not equal React and Vue"
            ),
        );
        record_blocking_defeat(
            defeat,
            true,
            &mut defeats,
            &mut blocking_defeats,
            &mut recurrence_blocking_defeats,
            &mut participant_blocking_defeats,
        );
    }

    let dimensions = [
        DivergenceDimension::Host,
        DivergenceDimension::BindingForm,
        DivergenceDimension::StimulusForm,
        DivergenceDimension::AssertionForm,
        DivergenceDimension::Suppression,
    ];
    let mut compared_native_dimensions = Vec::new();
    let mut equal_native_dimensions = Vec::new();
    let mut native_divergences = Vec::new();
    for dimension in dimensions {
        match compare_dimension(observations, dimension) {
            Ok(Some(divergence)) => {
                compared_native_dimensions.push(dimension);
                native_divergences.push(divergence);
            }
            Ok(None) => {
                compared_native_dimensions.push(dimension);
                equal_native_dimensions.push(dimension);
            }
            Err(gaps) => {
                for gap in gaps {
                    let affects_independent_recurrence = observations
                        .iter()
                        .find(|observation| observation.audit_subject_id == gap.audit_subject_id)
                        .is_none_or(|observation| {
                            observation.lineage.participation == LineageParticipation::Authority
                        });
                    let defeat = Defeat::new(
                        DefeatKind::LookedAndBlocked,
                        format!("{}.{}", gap.audit_subject_id, dimension.field()),
                        gap.reason.clone(),
                    );
                    record_blocking_defeat(
                        defeat,
                        affects_independent_recurrence,
                        &mut defeats,
                        &mut blocking_defeats,
                        &mut recurrence_blocking_defeats,
                        &mut participant_blocking_defeats,
                    );
                    evidence_gaps.push(gap);
                }
            }
        }
    }

    let independent_outcomes = observations
        .iter()
        .filter(|observation| observation.lineage.participation == LineageParticipation::Authority)
        .filter_map(|observation| observation.activation.value.outcome)
        .collect::<Vec<_>>();
    let recurring_outcome = if recurrence_blocking_defeats.is_empty()
        && independent_outcomes.len() == 2
        && independent_outcomes
            .windows(2)
            .all(|pair| pair[0] == pair[1])
    {
        independent_outcomes.first().copied()
    } else {
        None
    };
    let coverage = if defeats.is_empty() {
        Completeness::Exhaustive
    } else {
        Completeness::Partial
    };

    RecurrenceReport {
        independent_authorities: authority_count,
        same_system_participants: participant_count,
        established_observations,
        compared_shared_attributes: usize::from(recurring_outcome.is_some()),
        recurring_outcome,
        coverage,
        defeats,
        blocking_defeats,
        recurrence_blocking_defeats,
        participant_blocking_defeats,
        disjoint_defeats,
        evidence_gaps,
        compared_native_dimensions,
        equal_native_dimensions,
        native_divergences,
    }
}

fn compare_dimension(
    observations: &[NativeObservation],
    dimension: DivergenceDimension,
) -> Result<Option<NativeDivergence>, Vec<EvidenceGap>> {
    let mut values = BTreeMap::new();
    let mut preserved_extension_keys = BTreeMap::new();
    let mut gaps = Vec::new();
    for observation in observations {
        let key = observation.ecosystem.extension_key();
        let Some(extension) = observation.activation.value.extensions.get(key) else {
            gaps.push(EvidenceGap {
                audit_subject_id: observation.audit_subject_id.clone(),
                dimension: Some(dimension),
                reason: format!("native extension `{key}` is absent"),
            });
            continue;
        };
        let Some(value) = extension
            .get(dimension.field())
            .filter(|value| meaningful(value))
        else {
            gaps.push(EvidenceGap {
                audit_subject_id: observation.audit_subject_id.clone(),
                dimension: Some(dimension),
                reason: format!(
                    "required native dimension `{}` is absent or empty",
                    dimension.field()
                ),
            });
            continue;
        };
        values.insert(observation.ecosystem, value);
        preserved_extension_keys.insert(observation.ecosystem, key.to_owned());
    }
    if !gaps.is_empty() {
        return Err(gaps);
    }
    let mut comparable = values.values();
    let Some(first) = comparable.next() else {
        return Err(vec![EvidenceGap {
            audit_subject_id: "interaction_activation".to_owned(),
            dimension: Some(dimension),
            reason: "no observations were available for comparison".to_owned(),
        }]);
    };
    let differs = comparable.any(|value| value != first);
    Ok(differs.then_some(NativeDivergence {
        dimension,
        values: values
            .into_iter()
            .map(|(ecosystem, value)| (ecosystem, value.clone()))
            .collect(),
        preserved_extension_keys,
    }))
}

/// A compact source-bound summary useful in diagnostics and golden outputs.
pub fn source_summary(observation: &NativeObservation) -> Value {
    json!({
        "ecosystem": observation.ecosystem,
        "audit_subject_id": observation.audit_subject_id,
        "authority_group": observation.authority_group,
        "role": observation.role,
        "lineage": observation.lineage,
        "outcome": observation.activation.value.outcome,
        "sources": observation.native.sources.iter().map(|source| json!({
            "authority": source.authority_id,
            "repository": source.repository,
            "path": source.source_path,
            "sha256": source.sha256,
        })).collect::<Vec<_>>(),
        "scoped_defeats": observation.scoped_defeats,
    })
}
