//! Implementation-independent contract for authoring a neutral data model.
//!
//! This package owns the authored source value kind, the typed capability
//! promise, and its exact conformance obligation. It contains no parser,
//! provider, attester, transport, or execution-host policy.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use gooir_capability::protocol::ConformanceSuiteId;
use gooir_capability::{
    CapabilityId, CapabilitySpec, DialectId, InputPort, OutputPort, PortName, ValueKindId,
};
use gooir_package::{
    ConformanceSuiteDeclaration, DialectDeclaration, InstalledPackage, PackageDependency,
    PackageDigest, PackageId, PackageManifest, PackageManifestError, PackageResource,
    ResourceDigest, ResourceName, ValueKindDeclaration, read_manifest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Exact package coordinate for this implementation-independent contract.
pub const CONTRACT_PACKAGE: &str = "org.gooi.capability.author_data_model@0.2.0";

/// Package-local path of the authored-source JSON Schema.
pub const AUTHORED_SPEC_SCHEMA_PATH: &str = "resources/authored-spec.schema.json";

/// Exact authored-source JSON Schema bytes measured by the package manifest.
pub const AUTHORED_SPEC_SCHEMA_BYTES: &[u8] =
    include_bytes!("../resources/authored-spec.schema.json");

/// A hand-written entity specification and its exact source coordinate.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoredSpec {
    pub origin: String,
    pub text: String,
}

/// Exact package identity for this contract.
#[must_use]
pub fn contract_package_id() -> PackageId {
    PackageId::parse(CONTRACT_PACKAGE).expect("the fixed contract package coordinate is valid")
}

/// Exact value kind of a hand-written entity specification.
#[must_use]
pub fn authored_entity_spec_value_kind() -> ValueKindId {
    ValueKindId::new("org.gooi.source.authored", "entity_spec", "0.1.0")
}

/// Exact authoring capability identity.
#[must_use]
pub fn author_data_model_capability_id() -> CapabilityId {
    CapabilityId::new("org.gooi.capability", "author_data_model", "0.2.0")
}

/// Exact conformance obligation named by the authoring capability.
#[must_use]
pub fn author_data_model_suite_id() -> ConformanceSuiteId {
    ConformanceSuiteId::new(
        "org.gooi.conformance",
        "author_data_model_tasks_entities",
        "1.1.0",
    )
}

/// Complete implementation-independent authoring promise.
#[must_use]
pub fn author_data_model_spec() -> CapabilitySpec {
    CapabilitySpec {
        id: author_data_model_capability_id(),
        input_ports: vec![InputPort::complete(
            port("source"),
            authored_entity_spec_value_kind(),
        )],
        output_ports: vec![OutputPort::new(
            port("model"),
            semantics_data_model_v1::model_contract(),
        )],
        default_conformance_suite: author_data_model_suite_id().to_string(),
        extensions: BTreeMap::new(),
    }
}

/// Constructs the exact contract package against one already installed
/// vocabulary package.
///
/// Accepting a non-forgeable installed handle makes the direct dependency
/// digest an observed package identity rather than a placeholder copied into
/// source. The expected vocabulary manifest and exported model value kind are
/// checked before the dependency is recorded.
///
/// # Errors
///
/// Refuses a different package coordinate, any content other than the checked
/// vocabulary manifest, a missing model value kind, or an invalid manifest.
pub fn package_manifest(
    data_model_vocabulary: &InstalledPackage,
) -> Result<PackageManifest, ContractPackageError> {
    let expected = read_manifest(semantics_data_model_v1::PACKAGE_MANIFEST)
        .map_err(ContractPackageError::VocabularyManifest)?;
    if data_model_vocabulary.package_id() != &expected.package {
        return Err(ContractPackageError::UnexpectedVocabularyPackage {
            expected: expected.package,
            actual: data_model_vocabulary.package_id().clone(),
        });
    }
    if data_model_vocabulary.digest() != &expected.content_digest {
        return Err(ContractPackageError::UnexpectedVocabularyDigest {
            expected: expected.content_digest,
            actual: data_model_vocabulary.digest().clone(),
        });
    }
    if !data_model_vocabulary
        .manifest()
        .dialects
        .iter()
        .flat_map(|dialect| &dialect.value_kinds)
        .any(|kind| kind.id == semantics_data_model_v1::model_contract())
    {
        return Err(ContractPackageError::MissingModelValueKind);
    }

    let authored_dialect = DialectId::new("org.gooi.source.authored", "0.1.0");
    PackageManifest::new(
        contract_package_id(),
        vec![PackageDependency {
            package: data_model_vocabulary.package_id().clone(),
            digest: data_model_vocabulary.digest().clone(),
            extensions: BTreeMap::new(),
        }],
        vec![schema_resource()?],
        vec![DialectDeclaration {
            id: authored_dialect,
            value_kinds: vec![ValueKindDeclaration {
                id: authored_entity_spec_value_kind(),
                schema: Some(schema_resource_name()),
                extensions: BTreeMap::new(),
            }],
            extensions: BTreeMap::new(),
        }],
        vec![ConformanceSuiteDeclaration {
            id: author_data_model_suite_id(),
            extensions: BTreeMap::new(),
        }],
        vec![author_data_model_spec()],
        Vec::new(),
        BTreeMap::new(),
    )
    .map_err(ContractPackageError::Manifest)
}

fn schema_resource_name() -> ResourceName {
    ResourceName::parse("authored-spec-schema")
        .expect("the fixed authored schema resource name is valid")
}

fn schema_resource() -> Result<PackageResource, ContractPackageError> {
    Ok(PackageResource {
        name: schema_resource_name(),
        path: AUTHORED_SPEC_SCHEMA_PATH.to_owned(),
        media_type: "application/schema+json".to_owned(),
        size: AUTHORED_SPEC_SCHEMA_BYTES.len() as u64,
        digest: ResourceDigest::parse(sha256_identity(AUTHORED_SPEC_SCHEMA_BYTES))
            .map_err(|error| ContractPackageError::SchemaDigest(error.to_string()))?,
        extensions: BTreeMap::new(),
    })
}

fn port(name: &str) -> PortName {
    PortName::parse(name).expect("the fixed authoring port name is valid")
}

fn sha256_identity(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut identity = String::with_capacity(71);
    identity.push_str("sha256:");
    for byte in digest {
        use fmt::Write as _;
        write!(identity, "{byte:02x}").expect("writing to a string cannot fail");
    }
    identity
}

/// Failure to bind the contract to its exact vocabulary dependency.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractPackageError {
    VocabularyManifest(PackageManifestError),
    UnexpectedVocabularyPackage {
        expected: PackageId,
        actual: PackageId,
    },
    UnexpectedVocabularyDigest {
        expected: PackageDigest,
        actual: PackageDigest,
    },
    MissingModelValueKind,
    SchemaDigest(String),
    Manifest(PackageManifestError),
}

impl fmt::Display for ContractPackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VocabularyManifest(error) => {
                write!(formatter, "checked vocabulary manifest is invalid: {error}")
            }
            Self::UnexpectedVocabularyPackage { expected, actual } => write!(
                formatter,
                "expected vocabulary package {expected}, got {actual}"
            ),
            Self::UnexpectedVocabularyDigest { expected, actual } => write!(
                formatter,
                "expected vocabulary package digest {expected}, got {actual}"
            ),
            Self::MissingModelValueKind => formatter.write_str(
                "installed vocabulary package does not export the exact data-model value kind",
            ),
            Self::SchemaDigest(error) => write!(formatter, "schema digest failed: {error}"),
            Self::Manifest(error) => write!(formatter, "contract package is invalid: {error}"),
        }
    }
}

impl Error for ContractPackageError {}
