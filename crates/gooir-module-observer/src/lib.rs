//! Explicit observation of facts contained by an admitted GOOIR module.
//!
//! This adapter verifies one exact operation occurrence through the authority
//! of its enclosing module, emits canonical containment evidence, and returns
//! an ordinary untrusted [`SourceObservation`]. It does not transfer or inherit
//! the module's authority. A local [`gooir_capability::authority::AdmissionPolicy`]
//! must separately accept
//! the exact observer before the child becomes an ordinary linkable fact.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use gooir_capability::authority::{
    AdmissionLedger, AuthorityError, ObservationAuthority, ObservationSourceId, SourceObservation,
};
use gooir_capability::protocol::{
    AdmittedFactRef, ArtifactDigest, EvidenceDigest, EvidenceKindId, EvidenceRef, ImplementationId,
    ProtocolError,
};
use gooir_capability::strict_json::{self, StrictJsonError};
use gooir_capability::{Fact, FactId, ValueKindId, canonical_digest};
use gooir_module_planning::ModuleOperationRef;
use gooir_module_v0::{ModuleError, ModuleFact, SymbolName};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub const PACKAGE: &str = "org.gooi.module";
pub const VERSION: &str = "0.1.0";
pub const CONTAINMENT_WITNESS_PROTOCOL: &str = "org.gooi.module.containment-witness/v0";
pub const CONTAINMENT_WITNESS_EXTENSION: &str = "org.gooi.module/containment-witness";

const MAX_EXTENSIONS_PER_SCOPE: usize = 1_024;
const MAX_EXTENSION_KEY_BYTES: usize = 512;

/// Exact source identity for deterministic module containment observation.
#[must_use]
pub fn containment_source_id() -> ObservationSourceId {
    ObservationSourceId::new(PACKAGE, "contained-operation", VERSION)
}

/// Exact kind of canonical containment-witness evidence.
#[must_use]
pub fn containment_evidence_kind() -> EvidenceKindId {
    EvidenceKindId::new(PACKAGE, "containment-witness", VERSION)
}

/// Content identity of one exact module containment witness.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ContainmentWitnessId(String);

impl ContainmentWitnessId {
    /// Parses an exact lowercase SHA-256 identity.
    ///
    /// # Errors
    ///
    /// Refuses every noncanonical digest spelling.
    pub fn parse(value: impl Into<String>) -> Result<Self, ModuleObserverError> {
        let value = value.into();
        if is_sha256(&value) {
            Ok(Self(value))
        } else {
            Err(ModuleObserverError::InvalidWitnessId(value))
        }
    }

    /// Returns the exact digest spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContainmentWitnessId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContainmentWitnessId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Content-identified proof that one exact fact occurs at one exact ordinal
/// inside one exact admitted module.
///
/// The witness is evidence produced by an observer, not an authority record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ContainmentWitness {
    pub witness_id: ContainmentWitnessId,
    pub protocol: String,
    pub admitted_module: AdmittedFactRef,
    pub operation: ModuleOperationRef,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl ContainmentWitness {
    /// Constructs one witness with no extensions.
    ///
    /// # Errors
    ///
    /// Refuses malformed coordinates or a module-reference mismatch.
    pub fn new(
        admitted_module: AdmittedFactRef,
        operation: ModuleOperationRef,
    ) -> Result<Self, ModuleObserverError> {
        let mut witness = Self {
            witness_id: placeholder_witness_id(),
            protocol: CONTAINMENT_WITNESS_PROTOCOL.to_owned(),
            admitted_module,
            operation,
            extensions: BTreeMap::new(),
        };
        witness.validate_structure()?;
        witness.witness_id = ContainmentWitnessId::parse(witness_digest(&witness)?)?;
        Ok(witness)
    }

    /// Revalidates structure and this witness's content identity.
    ///
    /// # Errors
    ///
    /// Refuses malformed fields, reserved extensions, or changed identity.
    pub fn validate(&self) -> Result<(), ModuleObserverError> {
        self.validate_structure()?;
        let expected = witness_digest(self)?;
        if self.witness_id.as_str() != expected {
            return Err(ModuleObserverError::WitnessIdentityMismatch {
                expected,
                actual: self.witness_id.to_string(),
            });
        }
        Ok(())
    }

    /// Revalidates exact containment through the current admission ledger.
    ///
    /// Unknown witness, module-reference, or operation-reference extensions
    /// are refused because they may alter containment semantics.
    ///
    /// # Errors
    ///
    /// Refuses an unresolved module authority, wrong module contract, changed
    /// ordinal/fact/kind/symbol, or unsupported extension semantics.
    pub fn validate_against(&self, ledger: &AdmissionLedger) -> Result<(), ModuleObserverError> {
        self.validate()?;
        reject_witness_extensions(self)?;
        exact_contained_fact(ledger, &self.admitted_module, &self.operation).map(|_| ())
    }

    /// Exact canonical bytes whose SHA-256 digest is `witness_id`.
    ///
    /// The self-referential identity field is omitted from these evidence
    /// bytes. The complete witness remains embedded in the source observation.
    ///
    /// # Errors
    ///
    /// Refuses an invalid or extension-augmented witness and canonicalization
    /// failures.
    pub fn evidence_bytes(&self) -> Result<Vec<u8>, ModuleObserverError> {
        self.validate()?;
        reject_witness_extensions(self)?;
        witness_body_bytes(self)
    }

    /// Evidence digest corresponding exactly to [`Self::evidence_bytes`].
    ///
    /// # Errors
    ///
    /// Refuses an invalid witness identity.
    pub fn evidence_digest(&self) -> Result<EvidenceDigest, ModuleObserverError> {
        self.validate()?;
        reject_witness_extensions(self)?;
        EvidenceDigest::parse(self.witness_id.to_string())
            .map_err(|error| ModuleObserverError::InvalidEvidenceDigest(error.to_string()))
    }

    fn validate_structure(&self) -> Result<(), ModuleObserverError> {
        ContainmentWitnessId::parse(self.witness_id.to_string())?;
        if self.protocol != CONTAINMENT_WITNESS_PROTOCOL {
            return Err(ModuleObserverError::ProtocolMismatch {
                actual: self.protocol.clone(),
            });
        }
        self.admitted_module
            .validate()
            .map_err(ModuleObserverError::Protocol)?;
        validate_operation_reference(&self.operation)?;
        if self.admitted_module.fact_id != self.operation.module_fact_id {
            return Err(ModuleObserverError::SourceModuleMismatch {
                admitted: self.admitted_module.fact_id.clone(),
                operation: self.operation.module_fact_id.clone(),
            });
        }
        validate_extensions(
            "containment witness",
            &self.extensions,
            &["witness_id", "protocol", "admitted_module", "operation"],
        )
    }
}

/// Exact observer implementation used to project module containment evidence.
#[derive(Clone, Debug, PartialEq)]
pub struct ModuleObserver {
    implementation: ImplementationId,
    artifact_digest: ArtifactDigest,
}

impl ModuleObserver {
    /// Binds the observer semantics to one exact implementation and measured
    /// artifact digest.
    ///
    /// # Errors
    ///
    /// Refuses a malformed implementation identity.
    pub fn new(
        implementation: ImplementationId,
        artifact_digest: ArtifactDigest,
    ) -> Result<Self, ModuleObserverError> {
        if !implementation.is_well_formed() {
            return Err(ModuleObserverError::InvalidObserverImplementation(
                implementation,
            ));
        }
        Ok(Self {
            implementation,
            artifact_digest,
        })
    }

    /// Exact source-observation authority this observer uses for one child kind.
    ///
    /// A policy must accept this complete value before a projected child can
    /// become linkable.
    ///
    /// # Errors
    ///
    /// Refuses a malformed child value kind.
    pub fn authority_for(
        &self,
        value_kind: ValueKindId,
    ) -> Result<ObservationAuthority, ModuleObserverError> {
        ObservationAuthority::new(
            containment_source_id(),
            self.implementation.clone(),
            self.artifact_digest.clone(),
            value_kind,
            containment_evidence_kind(),
            BTreeMap::new(),
        )
        .map_err(ModuleObserverError::from)
    }

    /// Observes one exact operation through an admitted enclosing module.
    ///
    /// The result is untrusted observation data. This method never calls
    /// [`AdmissionLedger::admit_observation`]; the caller must explicitly
    /// apply its own policy afterward.
    ///
    /// # Errors
    ///
    /// Refuses unresolved authority, containment substitution, unsupported
    /// extensions, blank evidence locators, or observation construction
    /// failures.
    pub fn observe(
        &self,
        ledger: &AdmissionLedger,
        admitted_module: &AdmittedFactRef,
        operation: &ModuleOperationRef,
        evidence_locator: impl Into<String>,
        additional_evidence: Vec<EvidenceRef>,
    ) -> Result<ObservedContainedOperation, ModuleObserverError> {
        let fact = exact_contained_fact(ledger, admitted_module, operation)?;
        let witness = ContainmentWitness::new(admitted_module.clone(), operation.clone())?;
        witness.validate_against(ledger)?;
        let primary_evidence = EvidenceRef::new(
            containment_evidence_kind(),
            witness.evidence_digest()?,
            evidence_locator,
            BTreeMap::new(),
        )
        .map_err(ModuleObserverError::Protocol)?;
        let extensions = BTreeMap::from([(
            CONTAINMENT_WITNESS_EXTENSION.to_owned(),
            serde_json::to_value(&witness)
                .map_err(|error| ModuleObserverError::Serialization(error.to_string()))?,
        )]);
        let observation = SourceObservation::new(
            fact,
            self.authority_for(operation.value_kind.clone())?,
            primary_evidence,
            additional_evidence,
            extensions,
        )
        .map_err(ModuleObserverError::from)?;
        let observed = ObservedContainedOperation {
            witness,
            observation,
        };
        observed.validate_against(ledger, self)?;
        Ok(observed)
    }
}

/// Exact witness and ordinary untrusted source observation for one child fact.
#[derive(Clone, Debug, PartialEq)]
pub struct ObservedContainedOperation {
    pub witness: ContainmentWitness,
    pub observation: SourceObservation,
}

impl ObservedContainedOperation {
    /// Revalidates the complete observation against the current module ledger
    /// and exact observer implementation.
    ///
    /// # Errors
    ///
    /// Refuses witness, fact, authority, evidence, extension, or containment
    /// substitution.
    pub fn validate_against(
        &self,
        ledger: &AdmissionLedger,
        observer: &ModuleObserver,
    ) -> Result<(), ModuleObserverError> {
        self.witness.validate_against(ledger)?;
        self.observation
            .validate()
            .map_err(ModuleObserverError::from)?;
        let fact = exact_contained_fact(
            ledger,
            &self.witness.admitted_module,
            &self.witness.operation,
        )?;
        if self.observation.fact != fact {
            return Err(ModuleObserverError::ObservationFactMismatch);
        }
        let expected_authority = observer.authority_for(fact.value_kind.clone())?;
        if self.observation.authority != expected_authority {
            return Err(ModuleObserverError::ObservationAuthorityMismatch);
        }
        if self.observation.primary_evidence.kind != containment_evidence_kind()
            || self.observation.primary_evidence.digest != self.witness.evidence_digest()?
            || !self.observation.primary_evidence.extensions.is_empty()
        {
            return Err(ModuleObserverError::ObservationEvidenceMismatch);
        }
        let expected_extensions = BTreeMap::from([(
            CONTAINMENT_WITNESS_EXTENSION.to_owned(),
            serde_json::to_value(&self.witness)
                .map_err(|error| ModuleObserverError::Serialization(error.to_string()))?,
        )]);
        if self.observation.extensions != expected_extensions {
            return Err(ModuleObserverError::ObservationExtensionMismatch);
        }
        Ok(())
    }
}

/// Reads and validates one standalone containment witness.
///
/// Unknown namespaced extensions survive structural round trips. Duplicate
/// keys are rejected recursively before typed decoding.
///
/// # Errors
///
/// Returns an error for malformed JSON, duplicate keys, or invalid identity.
pub fn read_containment_witness(json: &str) -> Result<ContainmentWitness, ModuleObserverError> {
    let witness: ContainmentWitness =
        strict_json::from_str(json).map_err(ModuleObserverError::StrictJson)?;
    witness.validate()?;
    Ok(witness)
}

/// Writes one structurally valid containment witness.
///
/// # Errors
///
/// Returns an error for invalid structure or JSON serialization failure.
pub fn write_containment_witness(
    witness: &ContainmentWitness,
) -> Result<String, ModuleObserverError> {
    witness.validate()?;
    serde_json::to_string(witness)
        .map_err(|error| ModuleObserverError::Serialization(error.to_string()))
}

/// Exact refusal from containment observation.
#[derive(Debug)]
pub enum ModuleObserverError {
    InvalidWitnessId(String),
    InvalidEvidenceDigest(String),
    InvalidObserverImplementation(ImplementationId),
    ProtocolMismatch { actual: String },
    InvalidFactId(String),
    InvalidValueKind(ValueKindId),
    SourceModuleMismatch { admitted: FactId, operation: FactId },
    OperationOrdinalOutOfRange(u32),
    OperationMismatch(u32),
    WitnessIdentityMismatch { expected: String, actual: String },
    UnsupportedExtensions(&'static str),
    ObservationFactMismatch,
    ObservationAuthorityMismatch,
    ObservationEvidenceMismatch,
    ObservationExtensionMismatch,
    ReservedExtension { scope: &'static str, key: String },
    InvalidExtensionKey { scope: &'static str, key: String },
    TooManyExtensions { actual: usize, maximum: usize },
    Protocol(ProtocolError),
    Authority(Box<AuthorityError>),
    Module(ModuleError),
    StrictJson(StrictJsonError),
    Serialization(String),
}

impl fmt::Display for ModuleObserverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWitnessId(value) => write!(
                formatter,
                "`{value}` is not an exact lowercase SHA-256 containment witness ID"
            ),
            Self::InvalidEvidenceDigest(detail) => {
                write!(formatter, "invalid containment evidence digest: {detail}")
            }
            Self::InvalidObserverImplementation(implementation) => {
                write!(formatter, "invalid module observer `{implementation}`")
            }
            Self::ProtocolMismatch { actual } => {
                write!(
                    formatter,
                    "unsupported containment witness protocol `{actual}`"
                )
            }
            Self::InvalidFactId(detail) => write!(formatter, "invalid fact ID: {detail}"),
            Self::InvalidValueKind(kind) => write!(formatter, "invalid value kind `{kind}`"),
            Self::SourceModuleMismatch {
                admitted,
                operation,
            } => write!(
                formatter,
                "operation names module `{operation}`, not admitted module `{admitted}`"
            ),
            Self::OperationOrdinalOutOfRange(ordinal) => {
                write!(
                    formatter,
                    "module operation ordinal {ordinal} is out of range"
                )
            }
            Self::OperationMismatch(ordinal) => write!(
                formatter,
                "module operation ordinal {ordinal} does not match the exact contained fact"
            ),
            Self::WitnessIdentityMismatch { expected, actual } => write!(
                formatter,
                "containment witness identity mismatch: expected {expected}, got {actual}"
            ),
            Self::UnsupportedExtensions(scope) => {
                write!(
                    formatter,
                    "{scope} extensions are not understood for observation"
                )
            }
            Self::ObservationFactMismatch => {
                formatter.write_str("observed fact differs from the exact contained operation")
            }
            Self::ObservationAuthorityMismatch => formatter
                .write_str("source observation names a different module observer authority"),
            Self::ObservationEvidenceMismatch => formatter
                .write_str("source observation evidence differs from the containment witness"),
            Self::ObservationExtensionMismatch => formatter
                .write_str("source observation does not embed the exact containment witness"),
            Self::ReservedExtension { scope, key } => {
                write!(formatter, "{scope} extension `{key}` shadows a known field")
            }
            Self::InvalidExtensionKey { scope, key } => {
                write!(formatter, "{scope} extension key `{key}` is invalid")
            }
            Self::TooManyExtensions { actual, maximum } => write!(
                formatter,
                "extension count {actual} exceeds maximum {maximum}"
            ),
            Self::Protocol(error) => write!(formatter, "invalid containment protocol: {error}"),
            Self::Authority(error) => write!(formatter, "invalid containment authority: {error}"),
            Self::Module(error) => write!(formatter, "invalid module: {error}"),
            Self::StrictJson(error) => write!(formatter, "invalid witness JSON: {error}"),
            Self::Serialization(detail) => {
                write!(formatter, "containment serialization failed: {detail}")
            }
        }
    }
}

impl Error for ModuleObserverError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Authority(error) => Some(error.as_ref()),
            Self::Module(error) => Some(error),
            Self::StrictJson(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AuthorityError> for ModuleObserverError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(Box::new(error))
    }
}

fn exact_contained_fact(
    ledger: &AdmissionLedger,
    admitted_module: &AdmittedFactRef,
    operation: &ModuleOperationRef,
) -> Result<Fact, ModuleObserverError> {
    if !admitted_module.extensions.is_empty() {
        return Err(ModuleObserverError::UnsupportedExtensions(
            "admitted module reference",
        ));
    }
    validate_operation_reference(operation)?;
    if !operation.extensions.is_empty() {
        return Err(ModuleObserverError::UnsupportedExtensions(
            "module operation reference",
        ));
    }
    if admitted_module.fact_id != operation.module_fact_id {
        return Err(ModuleObserverError::SourceModuleMismatch {
            admitted: admitted_module.fact_id.clone(),
            operation: operation.module_fact_id.clone(),
        });
    }
    let resolved = ledger
        .resolve(admitted_module)
        .map_err(ModuleObserverError::from)?;
    let module = ModuleFact::from_fact(resolved.fact).map_err(ModuleObserverError::Module)?;
    if !module.extensions.is_empty() {
        return Err(ModuleObserverError::UnsupportedExtensions("module fact"));
    }
    if !module.module.extensions.is_empty() {
        return Err(ModuleObserverError::UnsupportedExtensions("module"));
    }
    let ordinal = usize::try_from(operation.ordinal)
        .map_err(|_| ModuleObserverError::OperationOrdinalOutOfRange(operation.ordinal))?;
    let contained = module.module.operations.get(ordinal).ok_or(
        ModuleObserverError::OperationOrdinalOutOfRange(operation.ordinal),
    )?;
    if !contained.extensions.is_empty() {
        return Err(ModuleObserverError::UnsupportedExtensions(
            "module operation",
        ));
    }
    if contained
        .references
        .iter()
        .any(|reference| !reference.extensions.is_empty())
    {
        return Err(ModuleObserverError::UnsupportedExtensions(
            "module operation reference",
        ));
    }
    if contained.fact.id != operation.fact_id
        || contained.fact.value_kind != operation.value_kind
        || contained.symbol != operation.symbol
    {
        return Err(ModuleObserverError::OperationMismatch(operation.ordinal));
    }
    Ok(contained.fact.clone())
}

fn validate_operation_reference(operation: &ModuleOperationRef) -> Result<(), ModuleObserverError> {
    parse_fact_id(&operation.module_fact_id)?;
    parse_fact_id(&operation.fact_id)?;
    if !operation.value_kind.is_well_formed() {
        return Err(ModuleObserverError::InvalidValueKind(
            operation.value_kind.clone(),
        ));
    }
    if let Some(symbol) = &operation.symbol {
        SymbolName::parse(symbol.to_string()).map_err(ModuleObserverError::Module)?;
    }
    validate_extensions(
        "module operation reference",
        &operation.extensions,
        &[
            "module_fact_id",
            "ordinal",
            "fact_id",
            "value_kind",
            "symbol",
        ],
    )
}

fn reject_witness_extensions(witness: &ContainmentWitness) -> Result<(), ModuleObserverError> {
    if !witness.extensions.is_empty() {
        return Err(ModuleObserverError::UnsupportedExtensions(
            "containment witness",
        ));
    }
    if !witness.admitted_module.extensions.is_empty() {
        return Err(ModuleObserverError::UnsupportedExtensions(
            "admitted module reference",
        ));
    }
    if !witness.operation.extensions.is_empty() {
        return Err(ModuleObserverError::UnsupportedExtensions(
            "module operation reference",
        ));
    }
    Ok(())
}

fn parse_fact_id(fact_id: &FactId) -> Result<(), ModuleObserverError> {
    FactId::parse(fact_id.to_string())
        .map(|_| ())
        .map_err(|error| ModuleObserverError::InvalidFactId(error.to_string()))
}

fn validate_extensions(
    scope: &'static str,
    extensions: &BTreeMap<String, Value>,
    reserved: &[&str],
) -> Result<(), ModuleObserverError> {
    if let Some(key) = reserved.iter().find(|key| extensions.contains_key(**key)) {
        return Err(ModuleObserverError::ReservedExtension {
            scope,
            key: (*key).to_owned(),
        });
    }
    if extensions.len() > MAX_EXTENSIONS_PER_SCOPE {
        return Err(ModuleObserverError::TooManyExtensions {
            actual: extensions.len(),
            maximum: MAX_EXTENSIONS_PER_SCOPE,
        });
    }
    for key in extensions.keys() {
        let namespaced = key
            .split_once('/')
            .is_some_and(|(namespace, name)| !namespace.is_empty() && !name.is_empty());
        if key.len() > MAX_EXTENSION_KEY_BYTES
            || key.trim() != key
            || key.chars().any(char::is_control)
            || !namespaced
        {
            return Err(ModuleObserverError::InvalidExtensionKey {
                scope,
                key: key.clone(),
            });
        }
    }
    Ok(())
}

fn witness_digest(witness: &ContainmentWitness) -> Result<String, ModuleObserverError> {
    let body = witness_body(witness)?;
    canonical_digest(&body).map_err(ModuleObserverError::Serialization)
}

fn witness_body_bytes(witness: &ContainmentWitness) -> Result<Vec<u8>, ModuleObserverError> {
    let body = witness_body(witness)?;
    serde_json_canonicalizer::to_vec(&body)
        .map_err(|error| ModuleObserverError::Serialization(error.to_string()))
}

fn witness_body(witness: &ContainmentWitness) -> Result<Value, ModuleObserverError> {
    let mut value = serde_json::to_value(witness)
        .map_err(|error| ModuleObserverError::Serialization(error.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| ModuleObserverError::Serialization("witness is not an object".to_owned()))?
        .remove("witness_id")
        .ok_or_else(|| {
            ModuleObserverError::Serialization("witness omitted witness_id".to_owned())
        })?;
    Ok(value)
}

fn placeholder_witness_id() -> ContainmentWitnessId {
    ContainmentWitnessId::parse(format!("sha256:{}", "0".repeat(64)))
        .expect("the witness identity placeholder is exact")
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(test)]
mod tests {
    use gooir_capability::PortName;
    use gooir_capability::authority::{
        AdmissionAuthorityId, AdmissionOutcome, AdmissionPolicy, AuthorityBasis,
    };
    use gooir_capability::protocol::{AuthorityRecordId, LinkedInput};
    use gooir_module_v0::{Module, ModuleFact, ModuleOperation, ReferenceName, SymbolReference};
    use serde_json::json;

    use super::*;

    const TEST_VERSION: &str = "1.0.0";

    struct Fixture {
        ledger: AdmissionLedger,
        admitted_module: AdmittedFactRef,
        module_fact: Fact,
        child: Fact,
        operation: ModuleOperationRef,
        observer: ModuleObserver,
    }

    fn sha(byte: char) -> String {
        format!("sha256:{}", byte.to_string().repeat(64))
    }

    fn artifact(byte: char) -> ArtifactDigest {
        ArtifactDigest::parse(sha(byte)).unwrap()
    }

    fn evidence_digest(byte: char) -> EvidenceDigest {
        EvidenceDigest::parse(sha(byte)).unwrap()
    }

    fn kind(name: &str) -> ValueKindId {
        ValueKindId::new("org.example.values", name, TEST_VERSION)
    }

    fn symbol(name: &str) -> SymbolName {
        SymbolName::parse(format!("@{name}")).unwrap()
    }

    fn evidence(kind_name: &str, byte: char, locator: &str) -> EvidenceRef {
        EvidenceRef::new(
            EvidenceKindId::new("org.example.evidence", kind_name, TEST_VERSION),
            evidence_digest(byte),
            locator,
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn module_authority(value_kind: ValueKindId) -> ObservationAuthority {
        ObservationAuthority::new(
            ObservationSourceId::new("org.example.source", "module", TEST_VERSION),
            ImplementationId::new("org.example.observer", "module", TEST_VERSION),
            artifact('a'),
            value_kind,
            EvidenceKindId::new("org.example.evidence", "module", TEST_VERSION),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn policy(authorities: Vec<ObservationAuthority>, name: &str) -> AdmissionPolicy {
        AdmissionPolicy::new(
            AdmissionAuthorityId::new("org.example.admission", name, TEST_VERSION),
            Vec::new(),
            authorities,
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn admitted_link(outcome: AdmissionOutcome) -> AdmittedFactRef {
        let AdmissionOutcome::Admitted { links, .. } = outcome else {
            panic!("expected admitted fact");
        };
        assert_eq!(links.len(), 1);
        links[0].reference.clone()
    }

    fn fixture() -> Fixture {
        let child_kind = kind("child");
        let child = Fact::new(child_kind.clone(), json!({"name": "child"})).unwrap();
        let module = Module::new(
            vec![child_kind.dialect()],
            vec![ModuleOperation::new(child.clone(), Some(symbol("child")), Vec::new()).unwrap()],
        )
        .unwrap();
        let module_fact = module.into_fact().unwrap();
        let authority = module_authority(module_fact.value_kind.clone());
        let observation = SourceObservation::new(
            module_fact.clone(),
            authority.clone(),
            evidence("module", 'b', "memory://module"),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let mut ledger = AdmissionLedger::new();
        let admitted_module = admitted_link(
            ledger
                .admit_observation(&policy(vec![authority], "module"), &observation)
                .unwrap(),
        );
        let operation = ModuleOperationRef {
            module_fact_id: module_fact.id.clone(),
            ordinal: 0,
            fact_id: child.id.clone(),
            value_kind: child_kind,
            symbol: Some(symbol("child")),
            extensions: BTreeMap::new(),
        };
        let observer = ModuleObserver::new(
            ImplementationId::new("org.example.observer", "containment", TEST_VERSION),
            artifact('c'),
        )
        .unwrap();
        Fixture {
            ledger,
            admitted_module,
            module_fact,
            child,
            operation,
            observer,
        }
    }

    fn assert_projection_refuses(
        observer: &ModuleObserver,
        module_fact: Fact,
        ordinal: u32,
        selected: &Fact,
    ) {
        let authority = module_authority(module_fact.value_kind.clone());
        let observation = SourceObservation::new(
            module_fact.clone(),
            authority.clone(),
            evidence("module", '4', "memory://extended-module"),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let mut ledger = AdmissionLedger::new();
        let admitted_module = admitted_link(
            ledger
                .admit_observation(&policy(vec![authority], "extended"), &observation)
                .unwrap(),
        );
        let operation = ModuleOperationRef {
            module_fact_id: module_fact.id,
            ordinal,
            fact_id: selected.id.clone(),
            value_kind: selected.value_kind.clone(),
            symbol: Some(symbol("child")),
            extensions: BTreeMap::new(),
        };
        assert!(matches!(
            observer.observe(
                &ledger,
                &admitted_module,
                &operation,
                "memory://containment",
                Vec::new(),
            ),
            Err(ModuleObserverError::UnsupportedExtensions(_))
        ));
    }

    #[test]
    fn projection_is_untrusted_until_normal_policy_admits_the_child() {
        let mut fixture = fixture();
        let observed = fixture
            .observer
            .observe(
                &fixture.ledger,
                &fixture.admitted_module,
                &fixture.operation,
                "memory://containment",
                Vec::new(),
            )
            .unwrap();

        assert_eq!(observed.observation.fact, fixture.child);
        assert!(
            fixture
                .ledger
                .authorities_for(&observed.observation.fact.id)
                .is_empty()
        );
        assert_eq!(
            observed.witness.evidence_digest().unwrap().as_str(),
            observed.witness.witness_id.as_str()
        );
        assert_eq!(
            canonical_digest(&witness_body(&observed.witness).unwrap()).unwrap(),
            observed.witness.witness_id.to_string()
        );
        assert!(!observed.witness.evidence_bytes().unwrap().is_empty());

        let denied = fixture
            .ledger
            .admit_observation(
                &AdmissionPolicy::deny_all(
                    AdmissionAuthorityId::new("org.example.admission", "deny", TEST_VERSION),
                    BTreeMap::new(),
                )
                .unwrap(),
                &observed.observation,
            )
            .unwrap();
        assert!(matches!(denied, AdmissionOutcome::Withheld { .. }));
        assert!(
            fixture
                .ledger
                .authorities_for(&observed.observation.fact.id)
                .is_empty()
        );

        let observer_authority = fixture
            .observer
            .authority_for(fixture.child.value_kind.clone())
            .unwrap();
        let child_reference = admitted_link(
            fixture
                .ledger
                .admit_observation(
                    &policy(vec![observer_authority], "child"),
                    &observed.observation,
                )
                .unwrap(),
        );
        let resolved = fixture.ledger.resolve(&child_reference).unwrap();
        assert_eq!(resolved.fact, &fixture.child);
        let AuthorityBasis::Source { observation, .. } = &resolved.authority.basis else {
            panic!("contained observation must remain an explicit source basis");
        };
        assert_eq!(
            observation.extensions.get(CONTAINMENT_WITNESS_EXTENSION),
            Some(&serde_json::to_value(&observed.witness).unwrap())
        );

        let linked = LinkedInput::new(
            PortName::parse("child").unwrap(),
            child_reference,
            fixture.child,
            BTreeMap::new(),
        )
        .unwrap();
        assert!(fixture.ledger.resolve(&linked.admitted).is_ok());
    }

    #[test]
    fn exact_authority_module_and_occurrence_are_required() {
        let fixture = fixture();
        let mut unknown = fixture.admitted_module.clone();
        unknown.authority_record_id = AuthorityRecordId::parse(sha('d')).unwrap();
        assert!(matches!(
            fixture.observer.observe(
                &fixture.ledger,
                &unknown,
                &fixture.operation,
                "memory://containment",
                Vec::new(),
            ),
            Err(ModuleObserverError::Authority(_))
        ));

        let mut wrong_module = fixture.operation.clone();
        wrong_module.module_fact_id = fixture.child.id.clone();
        assert!(matches!(
            fixture.observer.observe(
                &fixture.ledger,
                &fixture.admitted_module,
                &wrong_module,
                "memory://containment",
                Vec::new(),
            ),
            Err(ModuleObserverError::SourceModuleMismatch { .. })
        ));

        let mut wrong_ordinal = fixture.operation.clone();
        wrong_ordinal.ordinal = 1;
        assert!(matches!(
            fixture.observer.observe(
                &fixture.ledger,
                &fixture.admitted_module,
                &wrong_ordinal,
                "memory://containment",
                Vec::new(),
            ),
            Err(ModuleObserverError::OperationOrdinalOutOfRange(1))
        ));

        let mut wrong_symbol = fixture.operation.clone();
        wrong_symbol.symbol = Some(symbol("other"));
        assert!(matches!(
            fixture.observer.observe(
                &fixture.ledger,
                &fixture.admitted_module,
                &wrong_symbol,
                "memory://containment",
                Vec::new(),
            ),
            Err(ModuleObserverError::OperationMismatch(0))
        ));
    }

    #[test]
    fn unknown_container_extensions_refuse_projection() {
        let child_kind = kind("child");
        let dependency = Fact::new(child_kind.clone(), json!({"name": "dependency"})).unwrap();
        let child = Fact::new(child_kind.clone(), json!({"name": "child"})).unwrap();
        let observer = ModuleObserver::new(
            ImplementationId::new("org.example.observer", "containment", TEST_VERSION),
            artifact('3'),
        )
        .unwrap();

        let plain_operation =
            || ModuleOperation::new(child.clone(), Some(symbol("child")), Vec::new()).unwrap();
        let plain_module =
            || Module::new(vec![child_kind.dialect()], vec![plain_operation()]).unwrap();

        let outer_extended = ModuleFact::with_extensions(
            plain_module(),
            BTreeMap::from([("org.example.module/future".to_owned(), json!(true))]),
        )
        .unwrap()
        .into_fact()
        .unwrap();
        assert_projection_refuses(&observer, outer_extended, 0, &child);

        let module_extended = Module::with_extensions(
            vec![child_kind.dialect()],
            vec![plain_operation()],
            BTreeMap::from([("org.example.module/future".to_owned(), json!(true))]),
        )
        .unwrap()
        .into_fact()
        .unwrap();
        assert_projection_refuses(&observer, module_extended, 0, &child);

        let operation_extended = Module::new(
            vec![child_kind.dialect()],
            vec![
                ModuleOperation::with_extensions(
                    child.clone(),
                    Some(symbol("child")),
                    Vec::new(),
                    BTreeMap::from([("org.example.operation/future".to_owned(), json!(true))]),
                )
                .unwrap(),
            ],
        )
        .unwrap()
        .into_fact()
        .unwrap();
        assert_projection_refuses(&observer, operation_extended, 0, &child);

        let mut reference = SymbolReference::new(
            ReferenceName::parse("dependency").unwrap(),
            symbol("dependency"),
            child_kind.clone(),
        )
        .unwrap();
        reference
            .extensions
            .insert("org.example.reference/future".to_owned(), json!(true));
        let reference_extended = Module::new(
            vec![child_kind.dialect()],
            vec![
                ModuleOperation::new(dependency, Some(symbol("dependency")), Vec::new()).unwrap(),
                ModuleOperation::new(child.clone(), Some(symbol("child")), vec![reference])
                    .unwrap(),
            ],
        )
        .unwrap()
        .into_fact()
        .unwrap();
        assert_projection_refuses(&observer, reference_extended, 1, &child);
    }

    #[test]
    fn identical_facts_at_distinct_ordinals_have_distinct_witnesses() {
        let child_kind = kind("child");
        let child = Fact::new(child_kind.clone(), json!({"same": true})).unwrap();
        let module_fact = Module::new(
            vec![child_kind.dialect()],
            vec![
                ModuleOperation::new(child.clone(), None, Vec::new()).unwrap(),
                ModuleOperation::new(child.clone(), None, Vec::new()).unwrap(),
            ],
        )
        .unwrap()
        .into_fact()
        .unwrap();
        let authority = module_authority(module_fact.value_kind.clone());
        let observation = SourceObservation::new(
            module_fact.clone(),
            authority.clone(),
            evidence("module", 'e', "memory://duplicate-module"),
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let mut ledger = AdmissionLedger::new();
        let admitted_module = admitted_link(
            ledger
                .admit_observation(&policy(vec![authority], "duplicates"), &observation)
                .unwrap(),
        );
        let observer = ModuleObserver::new(
            ImplementationId::new("org.example.observer", "containment", TEST_VERSION),
            artifact('f'),
        )
        .unwrap();
        let operation = |ordinal| ModuleOperationRef {
            module_fact_id: module_fact.id.clone(),
            ordinal,
            fact_id: child.id.clone(),
            value_kind: child_kind.clone(),
            symbol: None,
            extensions: BTreeMap::new(),
        };

        let first = observer
            .observe(
                &ledger,
                &admitted_module,
                &operation(0),
                "memory://first",
                Vec::new(),
            )
            .unwrap();
        let second = observer
            .observe(
                &ledger,
                &admitted_module,
                &operation(1),
                "memory://second",
                Vec::new(),
            )
            .unwrap();

        assert_eq!(first.observation.fact.id, second.observation.fact.id);
        assert_ne!(first.witness.witness_id, second.witness.witness_id);
        assert_ne!(
            first.observation.observation_id,
            second.observation.observation_id
        );
    }

    #[test]
    fn witness_tampering_extensions_and_duplicate_json_fail_closed() {
        let fixture = fixture();
        let observed = fixture
            .observer
            .observe(
                &fixture.ledger,
                &fixture.admitted_module,
                &fixture.operation,
                "memory://containment",
                Vec::new(),
            )
            .unwrap();
        let json = write_containment_witness(&observed.witness).unwrap();
        assert_eq!(read_containment_witness(&json).unwrap(), observed.witness);

        let mut changed = observed.witness.clone();
        changed.operation.symbol = Some(symbol("other"));
        assert!(matches!(
            changed.validate(),
            Err(ModuleObserverError::WitnessIdentityMismatch { .. })
        ));

        let mut extended = observed.witness.clone();
        extended
            .extensions
            .insert("org.example/future".to_owned(), json!(true));
        extended.witness_id =
            ContainmentWitnessId::parse(witness_digest(&extended).unwrap()).unwrap();
        assert!(extended.validate().is_ok());
        assert!(matches!(
            extended.validate_against(&fixture.ledger),
            Err(ModuleObserverError::UnsupportedExtensions(
                "containment witness"
            ))
        ));

        let fact_id = format!("\"fact_id\":\"{}\"", fixture.module_fact.id);
        let malformed = json.replacen(&fact_id, &format!("{fact_id},{fact_id}"), 1);
        assert!(matches!(
            read_containment_witness(&malformed),
            Err(ModuleObserverError::StrictJson(_))
        ));
    }

    #[test]
    fn observation_authority_and_evidence_substitution_are_rejected() {
        let fixture = fixture();
        let observed = fixture
            .observer
            .observe(
                &fixture.ledger,
                &fixture.admitted_module,
                &fixture.operation,
                "memory://containment",
                Vec::new(),
            )
            .unwrap();
        let other_observer = ModuleObserver::new(
            ImplementationId::new("org.example.observer", "other", TEST_VERSION),
            artifact('1'),
        )
        .unwrap();
        assert!(matches!(
            observed.validate_against(&fixture.ledger, &other_observer),
            Err(ModuleObserverError::ObservationAuthorityMismatch)
        ));

        let wrong_evidence = EvidenceRef::new(
            containment_evidence_kind(),
            evidence_digest('2'),
            "memory://wrong",
            BTreeMap::new(),
        )
        .unwrap();
        let changed_observation = SourceObservation::new(
            observed.observation.fact.clone(),
            observed.observation.authority.clone(),
            wrong_evidence,
            observed.observation.additional_evidence.clone(),
            observed.observation.extensions.clone(),
        )
        .unwrap();
        let changed = ObservedContainedOperation {
            witness: observed.witness,
            observation: changed_observation,
        };
        assert!(matches!(
            changed.validate_against(&fixture.ledger, &fixture.observer),
            Err(ModuleObserverError::ObservationEvidenceMismatch)
        ));
    }
}
