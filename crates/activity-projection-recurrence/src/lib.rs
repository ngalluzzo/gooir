//! Integrity and recurrence checks for the production activity-projection probe.
//!
//! Source-specific parser projectors generate the observation document. This
//! crate binds that output to the exact authority lock, source bytes, parser
//! implementation, and behavioral selector witnesses. It does not parse an
//! arbitrary application or infer projection meaning from syntax alone.

use semantics_activity_projection_v0::ActivityProjection;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const LOCK_PROTOCOL: &str = "org.gooi.fixture.activity_projection_authorities/v1";
pub const OBSERVATION_PROTOCOL: &str = "org.gooi.fixture.activity_projection_observations/v1";
pub const BEHAVIOR_PROTOCOL: &str = "org.gooi.fixture.activity_projection_behavior/v2";
const GENERATOR_NAME: &str = "@gooir/activity-projection-lifters";
const GENERATOR_VERSION: &str = "0.1.0";
const ACTIVITY_CONTRACT: &str = "org.gooi.semantics.activity_projection/ordered_activity@0.1.0";
const CANONICAL_OBSERVATION_SHA256: &str =
    "22a6ceae2e73da2f7d3cf964dd05cb4d9d865372e277a50afdceba8a9c889dd3";
const GENERATOR_PATHS: [&str; 9] = [
    "package.json",
    "src/cli.mjs",
    "src/evidence.mjs",
    "src/lift.mjs",
    "src/parsers.mjs",
    "src/projectors.mjs",
    "src/react-history.mjs",
    "src/react-history-worker.mjs",
    "src/refresh.mjs",
];

pub fn default_corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/activity/projection")
}

fn tool_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/activity-projection-lifters")
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityManifest {
    pub protocol: String,
    pub products: Vec<Product>,
    pub authorities: Vec<Authority>,
    pub licenses: Vec<License>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Product {
    pub id: String,
    pub governance_group: String,
    pub declared_ecosystem: String,
    pub projector: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPin {
    pub url: String,
    pub commit: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub id: String,
    pub product_id: String,
    pub role: String,
    pub parser_variant: String,
    pub repository: RepositoryPin,
    pub source_path: String,
    pub snapshot_path: String,
    pub sha256: String,
    pub license_snapshot: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct License {
    pub id: String,
    pub product_id: String,
    pub repository: RepositoryPin,
    pub source_path: String,
    pub snapshot_path: String,
    pub sha256: String,
}

#[derive(Clone, Debug)]
pub struct VerifiedProbe {
    manifest: AuthorityManifest,
    observations: Value,
    report: RecurrenceReport,
}

impl VerifiedProbe {
    pub fn manifest(&self) -> &AuthorityManifest {
        &self.manifest
    }

    pub fn observations(&self) -> &Value {
        &self.observations
    }

    pub fn report(&self) -> &RecurrenceReport {
        &self.report
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecurrenceReport {
    pub product_count: usize,
    pub declared_governance_groups: BTreeSet<String>,
    pub declared_ecosystems: BTreeSet<String>,
    pub contract: String,
    pub rejected: BTreeSet<String>,
    pub verified_projection_products: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProbeError {
    Io(String),
    Json(String),
    Protocol {
        expected: String,
        actual: String,
    },
    InvalidLock(String),
    DigestMismatch {
        subject: String,
        expected: String,
        actual: String,
    },
    GeneratorMismatch(String),
    InvalidObservation(String),
    InvalidBehavior(String),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) => write!(formatter, "activity probe I/O failed: {message}"),
            Self::Json(message) => write!(formatter, "activity probe JSON is invalid: {message}"),
            Self::Protocol { expected, actual } => {
                write!(formatter, "protocol is `{actual}`, expected `{expected}`")
            }
            Self::InvalidLock(message) => {
                write!(formatter, "activity authority lock is invalid: {message}")
            }
            Self::DigestMismatch {
                subject,
                expected,
                actual,
            } => write!(
                formatter,
                "digest mismatch for {subject}: expected {expected}, observed {actual}"
            ),
            Self::GeneratorMismatch(message) => {
                write!(
                    formatter,
                    "activity observation generator mismatch: {message}"
                )
            }
            Self::InvalidObservation(message) => {
                write!(formatter, "activity observation is invalid: {message}")
            }
            Self::InvalidBehavior(message) => {
                write!(formatter, "activity behavior is invalid: {message}")
            }
        }
    }
}

impl std::error::Error for ProbeError {}

fn read(path: &Path) -> Result<Vec<u8>, ProbeError> {
    fs::read(path).map_err(|error| ProbeError::Io(format!("{}: {error}", path.display())))
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn exact_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_relative(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn object<'a>(
    value: &'a Value,
    subject: &str,
) -> Result<&'a serde_json::Map<String, Value>, ProbeError> {
    value
        .as_object()
        .ok_or_else(|| ProbeError::InvalidObservation(format!("{subject} must be an object")))
}

fn string_field<'a>(value: &'a Value, field: &str, subject: &str) -> Result<&'a str, ProbeError> {
    value.get(field).and_then(Value::as_str).ok_or_else(|| {
        ProbeError::InvalidObservation(format!("{subject}.{field} must be a string"))
    })
}

pub fn load_probe(root: impl AsRef<Path>) -> Result<VerifiedProbe, ProbeError> {
    let root = root.as_ref();
    let lock_bytes = read(&root.join("authorities.lock.json"))?;
    let manifest: AuthorityManifest =
        serde_json::from_slice(&lock_bytes).map_err(|error| ProbeError::Json(error.to_string()))?;
    verify_manifest(root, &manifest)?;

    let observation_bytes = read(&root.join("observations.lift.json"))?;
    let observation_digest = sha256(&observation_bytes);
    if observation_digest != CANONICAL_OBSERVATION_SHA256 {
        return Err(ProbeError::DigestMismatch {
            subject: "canonical generated observations".to_owned(),
            expected: CANONICAL_OBSERVATION_SHA256.to_owned(),
            actual: observation_digest,
        });
    }
    let observations: Value = serde_json::from_slice(&observation_bytes)
        .map_err(|error| ProbeError::Json(error.to_string()))?;
    let report = verify_observations(root, &manifest, &lock_bytes, &observations)?;
    Ok(VerifiedProbe {
        manifest,
        observations,
        report,
    })
}

fn verify_manifest(root: &Path, manifest: &AuthorityManifest) -> Result<(), ProbeError> {
    if manifest.protocol != LOCK_PROTOCOL {
        return Err(ProbeError::Protocol {
            expected: LOCK_PROTOCOL.to_owned(),
            actual: manifest.protocol.clone(),
        });
    }
    if manifest.products.is_empty()
        || manifest.authorities.is_empty()
        || manifest.licenses.is_empty()
    {
        return Err(ProbeError::InvalidLock(
            "products, authorities, and licenses must be nonempty".to_owned(),
        ));
    }

    let mut product_ids = BTreeSet::new();
    let mut governance = BTreeSet::new();
    let mut projectors = BTreeSet::new();
    for product in &manifest.products {
        if product.id.trim().is_empty()
            || product.governance_group.trim().is_empty()
            || product.declared_ecosystem.trim().is_empty()
            || product.projector.trim().is_empty()
        {
            return Err(ProbeError::InvalidLock(
                "product fields must be nonblank".to_owned(),
            ));
        }
        if !product_ids.insert(product.id.clone())
            || !governance.insert(product.governance_group.clone())
            || !projectors.insert(product.projector.clone())
        {
            return Err(ProbeError::InvalidLock(
                "product ids, governance groups, and projectors must be unique".to_owned(),
            ));
        }
    }

    let mut ids = BTreeSet::new();
    let mut snapshots = BTreeSet::new();
    for authority in &manifest.authorities {
        if authority.id.trim().is_empty()
            || authority.role.trim().is_empty()
            || authority.parser_variant.trim().is_empty()
            || !safe_relative(&authority.source_path)
            || !ids.insert(authority.id.clone())
        {
            return Err(ProbeError::InvalidLock(format!(
                "invalid or duplicate authority `{}`",
                authority.id
            )));
        }
        if !product_ids.contains(&authority.product_id) {
            return Err(ProbeError::InvalidLock(format!(
                "unknown product `{}`",
                authority.product_id
            )));
        }
        verify_pin(&authority.repository, &authority.id)?;
        verify_snapshot(
            root,
            &authority.id,
            &authority.snapshot_path,
            &authority.sha256,
            &mut snapshots,
        )?;
        let license = manifest.licenses.iter().find(|license| {
            license.product_id == authority.product_id
                && license.snapshot_path == authority.license_snapshot
                && license.repository == authority.repository
        });
        if license.is_none() {
            return Err(ProbeError::InvalidLock(format!(
                "{} has no same-revision product license",
                authority.id
            )));
        }
    }
    for license in &manifest.licenses {
        if license.id.trim().is_empty()
            || !safe_relative(&license.source_path)
            || !ids.insert(license.id.clone())
        {
            return Err(ProbeError::InvalidLock(format!(
                "invalid or duplicate authority/license id `{}`",
                license.id
            )));
        }
        if !product_ids.contains(&license.product_id) {
            return Err(ProbeError::InvalidLock(format!(
                "unknown product `{}`",
                license.product_id
            )));
        }
        verify_pin(&license.repository, &license.id)?;
        verify_snapshot(
            root,
            &license.id,
            &license.snapshot_path,
            &license.sha256,
            &mut snapshots,
        )?;
    }

    let mut repository_owners = BTreeMap::new();
    for product in &manifest.products {
        let repositories: BTreeSet<_> = manifest
            .authorities
            .iter()
            .filter(|authority| authority.product_id == product.id)
            .map(|authority| (&authority.repository.url, &authority.repository.commit))
            .chain(
                manifest
                    .licenses
                    .iter()
                    .filter(|license| license.product_id == product.id)
                    .map(|license| (&license.repository.url, &license.repository.commit)),
            )
            .collect();
        if repositories.len() != 1 {
            return Err(ProbeError::InvalidLock(format!(
                "{} must resolve to one exact repository revision",
                product.id
            )));
        }
        let (url, _) = repositories.into_iter().next().expect("length checked");
        if let Some(owner) = repository_owners.insert(url, product.id.as_str()) {
            return Err(ProbeError::InvalidLock(format!(
                "products `{owner}` and `{}` share repository `{url}`",
                product.id
            )));
        }
    }
    Ok(())
}

fn verify_pin(pin: &RepositoryPin, subject: &str) -> Result<(), ProbeError> {
    if !pin.url.starts_with("https://") || !exact_lower_hex(&pin.commit, 40) {
        return Err(ProbeError::InvalidLock(format!(
            "{subject} has an invalid repository pin"
        )));
    }
    Ok(())
}

fn verify_snapshot(
    root: &Path,
    subject: &str,
    snapshot: &str,
    expected: &str,
    seen: &mut BTreeSet<String>,
) -> Result<(), ProbeError> {
    if !safe_relative(snapshot)
        || !exact_lower_hex(expected, 64)
        || !seen.insert(snapshot.to_owned())
    {
        return Err(ProbeError::InvalidLock(format!(
            "{subject} has an unsafe, duplicate, or invalid snapshot"
        )));
    }
    let bytes = read(&root.join(snapshot))?;
    let actual = sha256(&bytes);
    if actual != expected {
        return Err(ProbeError::DigestMismatch {
            subject: subject.to_owned(),
            expected: expected.to_owned(),
            actual,
        });
    }
    Ok(())
}

fn verify_observations(
    root: &Path,
    manifest: &AuthorityManifest,
    lock_bytes: &[u8],
    document: &Value,
) -> Result<RecurrenceReport, ProbeError> {
    let protocol = string_field(document, "protocol", "observations")?;
    if protocol != OBSERVATION_PROTOCOL {
        return Err(ProbeError::Protocol {
            expected: OBSERVATION_PROTOCOL.to_owned(),
            actual: protocol.to_owned(),
        });
    }
    let generator = object(
        document.get("generator").unwrap_or(&Value::Null),
        "generator",
    )?;
    let locked = generator
        .get("authority_lock_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| ProbeError::GeneratorMismatch("missing authority lock digest".to_owned()))?;
    let actual_lock = sha256(lock_bytes);
    if locked != actual_lock {
        return Err(ProbeError::DigestMismatch {
            subject: "authority lock".to_owned(),
            expected: locked.to_owned(),
            actual: actual_lock,
        });
    }
    verify_generator(generator)?;

    let recurrence = object(
        document.get("recurrence").unwrap_or(&Value::Null),
        "recurrence",
    )?;
    verify_recurrence_authorities(recurrence, manifest)?;
    if recurrence.get("status")
        != Some(&json!(
            "three_product_concrete_vertical_with_six_product_static_corroboration"
        ))
    {
        return Err(ProbeError::InvalidObservation(
            "recurrence status changed".to_owned(),
        ));
    }
    let contract_vertical = recurrence
        .get("contract_vertical")
        .ok_or_else(|| ProbeError::InvalidObservation("contract vertical is missing".to_owned()))?;
    if contract_vertical
        != &json!({
            "contract": ACTIVITY_CONTRACT,
            "products": ["open_webui", "chat_ui", "gemini_cli"],
            "concrete_projection_count": 3
        })
    {
        return Err(ProbeError::InvalidObservation(
            "contract vertical changed".to_owned(),
        ));
    }

    let rejected = recurrence
        .get("rejected")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProbeError::InvalidObservation("recurrence.rejected must be an array".to_owned())
        })?
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                ProbeError::InvalidObservation("rejected values must be strings".to_owned())
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    for required in [
        "canonical_transcript",
        "global_chronology",
        "universal_actor_enum",
        "portable_payload",
        "backing_branch_graph",
        "singular_current_input_or_decision_locus",
        "stream_delta_as_durable_activity",
    ] {
        if !rejected.contains(required) {
            return Err(ProbeError::InvalidObservation(format!(
                "missing rejected candidate `{required}`"
            )));
        }
    }

    let authority_by_id: BTreeMap<_, _> = manifest
        .authorities
        .iter()
        .map(|authority| (authority.id.as_str(), authority))
        .collect();
    let product_by_id: BTreeMap<_, _> = manifest
        .products
        .iter()
        .map(|product| (product.id.as_str(), product))
        .collect();
    let observations = document
        .get("observations")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProbeError::InvalidObservation("observations must be an array".to_owned())
        })?;
    if observations.len() != manifest.products.len() {
        return Err(ProbeError::InvalidObservation(
            "one observation per product is required".to_owned(),
        ));
    }
    let mut observed_products = BTreeSet::new();
    for observation in observations {
        verify_product_observation(
            root,
            observation,
            &product_by_id,
            &authority_by_id,
            &rejected,
            &mut observed_products,
        )?;
    }
    let product_ids: BTreeSet<_> = manifest
        .products
        .iter()
        .map(|product| product.id.clone())
        .collect();
    if observed_products != product_ids {
        return Err(ProbeError::InvalidObservation(
            "observed product set differs from lock".to_owned(),
        ));
    }

    let verified_projection_products =
        verify_behavior(document.get("behavior").unwrap_or(&Value::Null))?;
    Ok(RecurrenceReport {
        product_count: manifest.products.len(),
        declared_governance_groups: manifest
            .products
            .iter()
            .map(|product| product.governance_group.clone())
            .collect(),
        declared_ecosystems: manifest
            .products
            .iter()
            .map(|product| product.declared_ecosystem.clone())
            .collect(),
        contract: ACTIVITY_CONTRACT.to_owned(),
        rejected,
        verified_projection_products,
    })
}

fn verify_recurrence_authorities(
    recurrence: &serde_json::Map<String, Value>,
    manifest: &AuthorityManifest,
) -> Result<(), ProbeError> {
    let expected_governance = Value::Array(
        manifest
            .products
            .iter()
            .map(|product| Value::String(product.governance_group.clone()))
            .collect(),
    );
    let expected_ecosystems = Value::Array(
        manifest
            .products
            .iter()
            .map(|product| Value::String(product.declared_ecosystem.clone()))
            .collect(),
    );
    if recurrence.get("declared_governance_groups") != Some(&expected_governance)
        || recurrence.get("declared_ecosystems") != Some(&expected_ecosystems)
    {
        return Err(ProbeError::InvalidObservation(
            "recurrence authorities differ from the exact product lock".to_owned(),
        ));
    }
    Ok(())
}

fn verify_generator(generator: &serde_json::Map<String, Value>) -> Result<(), ProbeError> {
    if generator.get("name") != Some(&json!(GENERATOR_NAME))
        || generator.get("version") != Some(&json!(GENERATOR_VERSION))
        || generator.get("evidence_kind")
            != Some(&json!(
                "static_product_state_corroboration_plus_reviewed_exact_isolated_and_react_execution"
            ))
        || generator.get("parsers")
            != Some(&json!({
                "typescript": "@babel/parser@7.29.8",
                "svelte": "svelte/compiler@5.56.10",
                "python": "tree-sitter-python@0.23.6",
                "rust": "tree-sitter-rust@0.24.0",
                "toml": "smol-toml@1.8.0",
                "behavior_transpiler": "typescript@5.9.3",
                "behavior_react": "react@19.2.4",
                "behavior_react_renderer": "react-test-renderer@19.2.4"
            }))
    {
        return Err(ProbeError::GeneratorMismatch(
            "generator identity, parser pins, or evidence kind changed".to_owned(),
        ));
    }
    let paths = generator
        .get("implementation_paths")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProbeError::GeneratorMismatch("implementation paths are missing".to_owned())
        })?;
    if paths != &GENERATOR_PATHS.map(Value::from) {
        return Err(ProbeError::GeneratorMismatch(
            "implementation path set or order changed".to_owned(),
        ));
    }
    let mut hash = Sha256::new();
    let root = tool_root();
    for path in paths {
        let path = path.as_str().ok_or_else(|| {
            ProbeError::GeneratorMismatch("implementation path is not a string".to_owned())
        })?;
        if !safe_relative(path) {
            return Err(ProbeError::GeneratorMismatch(format!(
                "unsafe implementation path `{path}`"
            )));
        }
        hash.update(path.as_bytes());
        hash.update([0]);
        hash.update(read(&root.join(path))?);
        hash.update([0]);
    }
    let actual = {
        let mut output = String::new();
        for byte in hash.finalize() {
            use std::fmt::Write as _;
            let _ = write!(output, "{byte:02x}");
        }
        output
    };
    let expected = generator
        .get("implementation_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProbeError::GeneratorMismatch("implementation digest is missing".to_owned())
        })?;
    if actual != expected {
        return Err(ProbeError::DigestMismatch {
            subject: "generator implementation".to_owned(),
            expected: expected.to_owned(),
            actual,
        });
    }
    let lock_path = generator
        .get("package_lock_path")
        .and_then(Value::as_str)
        .ok_or_else(|| ProbeError::GeneratorMismatch("package lock path is missing".to_owned()))?;
    if lock_path != "package-lock.json" || !safe_relative(lock_path) {
        return Err(ProbeError::GeneratorMismatch(
            "package lock path is unsafe".to_owned(),
        ));
    }
    let actual = sha256(&read(&root.join(lock_path))?);
    let expected = generator
        .get("package_lock_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProbeError::GeneratorMismatch("package lock digest is missing".to_owned())
        })?;
    if actual != expected {
        return Err(ProbeError::DigestMismatch {
            subject: "generator package lock".to_owned(),
            expected: expected.to_owned(),
            actual,
        });
    }
    Ok(())
}

fn verify_product_observation(
    root: &Path,
    observation: &Value,
    product_by_id: &BTreeMap<&str, &Product>,
    authority_by_id: &BTreeMap<&str, &Authority>,
    rejected_candidates: &BTreeSet<String>,
    observed_products: &mut BTreeSet<String>,
) -> Result<(), ProbeError> {
    let product = string_field(observation, "product_id", "observation")?;
    if !observed_products.insert(product.to_owned()) {
        return Err(ProbeError::InvalidObservation(format!(
            "duplicate product `{product}`"
        )));
    }
    let product_lock = product_by_id.get(product).ok_or_else(|| {
        ProbeError::InvalidObservation(format!("observation names unknown product `{product}`"))
    })?;
    if observation.get("governance_group") != Some(&json!(product_lock.governance_group))
        || observation.get("declared_ecosystem") != Some(&json!(product_lock.declared_ecosystem))
    {
        return Err(ProbeError::InvalidObservation(format!(
            "{product} authority metadata differs from the product lock"
        )));
    }
    if observation.get("semantic").is_some() {
        return Err(ProbeError::InvalidObservation(format!(
            "{product} carries an authored semantic verdict"
        )));
    }
    let references = observation
        .get("source_references")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProbeError::InvalidObservation(format!("{product} source references are missing"))
        })?;
    if references.is_empty() {
        return Err(ProbeError::InvalidObservation(format!(
            "{product} has no source references"
        )));
    }
    let mut referenced_ids = BTreeSet::new();
    for reference in references {
        let id = string_field(reference, "authority_id", "source reference")?;
        if !referenced_ids.insert(id) {
            return Err(ProbeError::InvalidObservation(format!(
                "{product} repeats source reference `{id}`"
            )));
        }
        let authority = authority_by_id
            .get(id)
            .ok_or_else(|| ProbeError::InvalidObservation(format!("unknown authority `{id}`")))?;
        if authority.product_id != product
            || reference.get("repository")
                != Some(
                    &serde_json::to_value(&authority.repository)
                        .map_err(|error| ProbeError::Json(error.to_string()))?,
                )
            || reference.get("source_path") != Some(&json!(authority.source_path))
            || reference.get("snapshot_path") != Some(&json!(authority.snapshot_path))
            || reference.get("sha256") != Some(&json!(authority.sha256))
        {
            return Err(ProbeError::InvalidObservation(format!(
                "{product} source reference `{id}` differs from lock"
            )));
        }
    }
    let expected_references: BTreeSet<_> = authority_by_id
        .values()
        .filter(|authority| authority.product_id == product)
        .map(|authority| authority.id.as_str())
        .collect();
    if referenced_ids != expected_references {
        return Err(ProbeError::InvalidObservation(format!(
            "{product} source references are not exhaustive"
        )));
    }
    let evidence = observation
        .get("evidence")
        .and_then(Value::as_array)
        .ok_or_else(|| ProbeError::InvalidObservation(format!("{product} evidence is missing")))?;
    if evidence.is_empty() {
        return Err(ProbeError::InvalidObservation(format!(
            "{product} has no evidence"
        )));
    }
    for span in evidence {
        let id = string_field(span, "source", "evidence")?;
        let authority = authority_by_id.get(id).ok_or_else(|| {
            ProbeError::InvalidObservation(format!("evidence names unknown authority `{id}`"))
        })?;
        if authority.product_id != product {
            return Err(ProbeError::InvalidObservation(format!(
                "{product} evidence crosses product authority"
            )));
        }
        let bytes = read(&root.join(&authority.snapshot_path))?;
        let byte_span = span
            .pointer("/span/utf8_bytes")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ProbeError::InvalidObservation(format!("{product} evidence lacks byte span"))
            })?;
        let start = byte_span
            .get("start")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX) as usize;
        let end = byte_span
            .get("end")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX) as usize;
        if start >= end || end > bytes.len() {
            return Err(ProbeError::InvalidObservation(format!(
                "{product} evidence span is invalid"
            )));
        }
        let expected_digest = string_field(span, "sha256", "evidence")?;
        let actual_digest = sha256(&bytes[start..end]);
        if expected_digest != actual_digest {
            return Err(ProbeError::DigestMismatch {
                subject: format!("{product} evidence `{id}`"),
                expected: expected_digest.to_owned(),
                actual: actual_digest,
            });
        }
    }
    let defeats = observation
        .get("defeats")
        .and_then(Value::as_array)
        .ok_or_else(|| ProbeError::InvalidObservation(format!("{product} defeats are missing")))?;
    if defeats.is_empty() {
        return Err(ProbeError::InvalidObservation(format!(
            "{product} must retain native limits"
        )));
    }
    for defeat in defeats {
        let kind = string_field(defeat, "kind", "defeat")?;
        if !matches!(
            kind,
            "out_of_scope" | "looked_and_blocked" | "authority_cannot_express"
        ) {
            return Err(ProbeError::InvalidObservation(format!(
                "{product} has an untyped defeat"
            )));
        }
        let affects = string_field(defeat, "affects", "defeat")?;
        let impact = string_field(defeat, "impact", "defeat")?;
        if impact != "disjoint" || !rejected_candidates.contains(affects) {
            return Err(ProbeError::InvalidObservation(format!(
                "{product} has a blocking or unscoped defeat"
            )));
        }
        string_field(defeat, "subject", "defeat")?;
        string_field(defeat, "reason", "defeat")?;
    }
    Ok(())
}

fn verify_behavior(value: &Value) -> Result<BTreeSet<String>, ProbeError> {
    let protocol = string_field(value, "protocol", "behavior")?;
    if protocol != BEHAVIOR_PROTOCOL {
        return Err(ProbeError::Protocol {
            expected: BEHAVIOR_PROTOCOL.to_owned(),
            actual: protocol.to_owned(),
        });
    }
    let cases = value
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| ProbeError::InvalidBehavior("behavior cases are missing".to_owned()))?;
    if cases.len() != 2 {
        return Err(ProbeError::InvalidBehavior(
            "exactly two source-specific behavior cases are required".to_owned(),
        ));
    }
    let branch_case = &cases[0];
    if branch_case.get("id") != Some(&json!("selected_branch_to_ordered_projection"))
        || branch_case.get("products") != Some(&json!(["open_webui", "chat_ui"]))
        || branch_case.pointer("/fixture/selected") != Some(&json!("assistant_b"))
        || branch_case.pointer("/fixture/native_inputs/open_webui/currentId") != Some(&json!("b"))
        || branch_case.pointer("/fixture/native_inputs/open_webui/messages/b/parentId")
            != Some(&json!("u"))
        || branch_case.pointer("/fixture/native_inputs/chat_ui/rootMessageId") != Some(&json!("s"))
        || branch_case.pointer("/fixture/native_inputs/chat_ui/messages/3/ancestors")
            != Some(&json!(["s", "u"]))
    {
        return Err(ProbeError::InvalidBehavior(
            "the exact native selector inputs changed".to_owned(),
        ));
    }
    if branch_case.get("alternate_selection")
        != Some(&json!({
            "selected": "assistant_a",
            "open_webui": ["s", "u", "a"],
            "chat_ui": ["s", "u", "a"]
        }))
        || branch_case.get("malformed_topology")
            != Some(&json!({
                "open_webui": {
                    "result": ["b"],
                    "classification": "partial_projection"
                },
                "chat_ui": {
                    "error": "Ancestor not found",
                    "classification": "blocking_unknown"
                },
                "admitted": false
            }))
    {
        return Err(ProbeError::InvalidBehavior(
            "alternate selection or malformed-topology defeat changed".to_owned(),
        ));
    }

    let trace_digest = "d9b2bb6441cbc729e9b9b4536ad7921d7b5cffbf75ee13c2ced04ffa571bed6a";
    let react_case = &cases[1];
    if react_case
        != &json!({
            "id": "react_history_action_trace",
            "products": ["gemini_cli"],
            "fixture": {
                "initial_history": [
                    {"id": 20, "type": "info", "text": "loaded-first"},
                    {"id": 10, "type": "user", "text": "same"}
                ],
                "actions": [
                    {"kind": "add", "item": {"type": "user", "text": "same"}, "base_timestamp": 5},
                    {"kind": "add", "item": {"type": "gemini", "text": "answer"}, "base_timestamp": 5},
                    {"kind": "update", "id": 10, "updates": {"text": "same-updated"}}
                ]
            },
            "fixture_sha256": trace_digest,
            "allocated_ids": [21, 22],
            "settled_history": [
                {"id": 20, "type": "info", "text": "loaded-first"},
                {"id": 10, "type": "user", "text": "same-updated"},
                {"id": 22, "type": "gemini", "text": "answer"}
            ],
            "establishes": [
                "load_preserves_vector_order",
                "duplicate_add_allocates_but_does_not_emit",
                "later_add_retains_id_gap",
                "update_preserves_position"
            ]
        })
    {
        return Err(ProbeError::InvalidBehavior(
            "Gemini React history action trace changed".to_owned(),
        ));
    }

    let observations = value
        .get("observations")
        .and_then(Value::as_array)
        .ok_or_else(|| ProbeError::InvalidBehavior("observations are missing".to_owned()))?;
    if observations.len() != 3 {
        return Err(ProbeError::InvalidBehavior(
            "exactly three concrete projections are required".to_owned(),
        ));
    }
    let expected_source_ids = json!(["s", "u", "b"]);
    let expected_projection_keys = json!(["20", "10", "22"]);
    let mut products = BTreeSet::new();
    for observation in observations {
        let product = observation
            .get("product_id")
            .and_then(Value::as_str)
            .ok_or_else(|| ProbeError::InvalidBehavior("product id is missing".to_owned()))?;
        if !products.insert(product.to_owned()) {
            return Err(ProbeError::InvalidBehavior(
                "behavioral product repeats".to_owned(),
            ));
        }
        let projection_value = observation.get("activity_projection").ok_or_else(|| {
            ProbeError::InvalidBehavior(format!(
                "{product} did not produce an ActivityProjection value"
            ))
        })?;
        let projection: ActivityProjection = serde_json::from_value(projection_value.clone())
            .map_err(|error| {
                ProbeError::InvalidBehavior(format!(
                    "{product} ActivityProjection is not decodable: {error}"
                ))
            })?;
        projection.verify().map_err(|errors| {
            ProbeError::InvalidBehavior(format!(
                "{product} ActivityProjection failed contract verification: {errors:?}"
            ))
        })?;
        if !projection.is_full()
            || projection.extensions.get("source_product") != Some(&json!(product))
        {
            return Err(ProbeError::InvalidBehavior(format!(
                "{product} concrete projection has the wrong extent or product"
            )));
        }

        match product {
            "open_webui" | "chat_ui" => {
                if observation.get("ordered_source_ids") != Some(&expected_source_ids)
                    || observation.get("ordered_projection_keys").is_some()
                {
                    return Err(ProbeError::InvalidBehavior(format!(
                        "{product} selected-branch output changed"
                    )));
                }
                let projected_ids = projection
                    .entries
                    .iter()
                    .map(|entry| match entry.source_refs.as_slice() {
                        [reference] if entry.projection_key.is_none() => {
                            Some(reference.id.as_str())
                        }
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>();
                let (expected_scope_namespaces, expected_selector) = if product == "open_webui" {
                    (
                        ["open_webui.history_root", "open_webui.history_head"],
                        "createMessagesList(history, history.currentId)",
                    )
                } else {
                    (
                        ["chat_ui.root_message", "chat_ui.selected_message"],
                        "buildSubtree(conversation, 'b')",
                    )
                };
                let scope_namespaces: Vec<_> = projection
                    .scope_refs
                    .iter()
                    .map(|reference| reference.namespace.as_str())
                    .collect();
                if projected_ids != Some(vec!["s", "u", "b"])
                    || scope_namespaces != expected_scope_namespaces
                    || projection.extensions.get("native_selector")
                        != Some(&json!(expected_selector))
                    || projection.extensions.get("verifier_fixture")
                        != Some(&json!("selected_branch_to_ordered_projection/v1"))
                {
                    return Err(ProbeError::InvalidBehavior(format!(
                        "{product} concrete projection differs from selector output"
                    )));
                }
            }
            "gemini_cli" => {
                if observation.get("ordered_projection_keys") != Some(&expected_projection_keys)
                    || observation.get("ordered_source_ids").is_some()
                {
                    return Err(ProbeError::InvalidBehavior(
                        "Gemini settled history keys changed".to_owned(),
                    ));
                }
                let projected_keys = projection
                    .entries
                    .iter()
                    .map(|entry| {
                        if entry.source_refs.is_empty() {
                            entry.projection_key.as_deref()
                        } else {
                            None
                        }
                    })
                    .collect::<Option<Vec<_>>>();
                let scope_is_exact = matches!(
                    projection.scope_refs.as_slice(),
                    [reference]
                        if reference.namespace == "gemini_cli.useHistory_action_trace"
                            && reference.id == trace_digest
                            && reference.extensions.is_empty()
                );
                if projected_keys != Some(vec!["20", "10", "22"])
                    || !scope_is_exact
                    || projection.extensions.get("native_selector")
                        != Some(&json!("useHistory settled UseHistoryManagerReturn.history"))
                    || projection.extensions.get("verifier_fixture")
                        != Some(&json!("react_history_action_trace/v1"))
                    || projection.extensions.get("runtime") != Some(&json!("react@19.2.4"))
                    || projection.extensions.get("renderer_lineage")
                        != Some(&json!(
                            "AppContainer UIState -> App normal branch -> DefaultAppLayout -> MainContent -> ink alias npm:@jrichman/ink@6.6.9"
                        ))
                    || observation.pointer("/source_node/source")
                        != Some(&json!("gemini.history_manager"))
                    || observation.pointer("/source_node/sha256")
                        != Some(&json!(
                            "01b769034ac7fb9ff1cb934ff6a1863b29efe02517657aa3ba70da3b0fa4dc3c"
                        ))
                {
                    return Err(ProbeError::InvalidBehavior(
                        "Gemini concrete projection differs from settled React history".to_owned(),
                    ));
                }
            }
            _ => {
                return Err(ProbeError::InvalidBehavior(format!(
                    "unexpected behavioral product `{product}`"
                )));
            }
        }
    }
    if products
        != BTreeSet::from([
            "chat_ui".to_owned(),
            "gemini_cli".to_owned(),
            "open_webui".to_owned(),
        ])
    {
        return Err(ProbeError::InvalidBehavior(
            "unexpected behavioral product set".to_owned(),
        ));
    }
    Ok(products)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_probe_is_bound_to_sources_generator_and_behavior() {
        let probe = load_probe(default_corpus_root()).expect("checked-in activity probe verifies");
        assert_eq!(probe.report.product_count, 6);
        assert_eq!(probe.manifest.authorities.len(), 33);
        assert_eq!(probe.manifest.licenses.len(), 8);
        assert_eq!(probe.report.declared_governance_groups.len(), 6);
        assert_eq!(probe.report.declared_ecosystems.len(), 4);
        assert_eq!(probe.report.verified_projection_products.len(), 3);
        assert_eq!(probe.report.contract, ACTIVITY_CONTRACT);
        assert!(probe.report.rejected.contains("canonical_transcript"));
        assert!(probe.report.rejected.contains("universal_actor_enum"));
    }

    #[test]
    fn source_extent_and_gooir_evidence_completeness_are_not_conflated() {
        let probe = load_probe(default_corpus_root()).unwrap();
        let codex = probe.observations["observations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|observation| observation["product_id"] == "codex")
            .unwrap();
        assert_eq!(
            codex["native"]["native_extent"],
            json!(["not_loaded", "summary", "full"])
        );
        for observation in probe.observations["behavior"]["observations"]
            .as_array()
            .unwrap()
        {
            assert_eq!(observation["activity_projection"]["extent"], "full");
        }
    }

    #[test]
    fn every_product_retains_at_least_one_typed_limit() {
        let probe = load_probe(default_corpus_root()).unwrap();
        for observation in probe.observations["observations"].as_array().unwrap() {
            let defeats = observation["defeats"].as_array().unwrap();
            assert!(!defeats.is_empty());
            for defeat in defeats {
                assert!(matches!(
                    defeat["kind"].as_str(),
                    Some("out_of_scope" | "looked_and_blocked" | "authority_cannot_express")
                ));
                assert_eq!(defeat["impact"], "disjoint");
                assert!(
                    probe
                        .report
                        .rejected
                        .contains(defeat["affects"].as_str().unwrap())
                );
            }
        }
    }

    #[test]
    fn gemini_projection_conformance_is_exact_not_merely_structural() {
        fn projection(value: &mut Value) -> &mut Value {
            value["observations"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|observation| observation["product_id"] == "gemini_cli")
                .map(|observation| &mut observation["activity_projection"])
                .unwrap()
        }

        fn rejected(value: &Value) {
            assert!(matches!(
                verify_behavior(value),
                Err(ProbeError::InvalidBehavior(_))
            ));
        }

        let probe = load_probe(default_corpus_root()).unwrap();
        let behavior = probe.observations["behavior"].clone();

        let mut swapped = behavior.clone();
        projection(&mut swapped)["entries"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        rejected(&swapped);

        let mut omitted = behavior.clone();
        projection(&mut omitted)["entries"]
            .as_array_mut()
            .unwrap()
            .pop();
        rejected(&omitted);

        let mut miskeyed = behavior.clone();
        projection(&mut miskeyed)["entries"][1]["projection_key"] = json!("999");
        rejected(&miskeyed);

        let mut rescope = behavior.clone();
        projection(&mut rescope)["scope_refs"][0]["id"] = json!("another-trace");
        rejected(&rescope);

        let mut windowed = behavior;
        projection(&mut windowed)["extent"] = json!("windowed");
        rejected(&windowed);
    }
}
