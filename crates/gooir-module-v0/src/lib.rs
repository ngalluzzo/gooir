//! Foundational, target-independent composition for heterogeneous GOOIR values.
//!
//! A module is one content-identified GOOIR fact whose ordered operations wrap
//! ordinary content-identified facts. The module adds only structure: exact
//! dialect declarations, local symbols, and named typed references. Operation
//! payload meaning remains owned by the operation's value-kind dialect.
//!
//! This crate does not define a compiler pipeline, target, provider, execution
//! policy, or domain operation. A future module compiler can present the
//! contained facts to the existing capability graph and replace only the
//! operations a selected lowering understands, preserving every other
//! operation and extension verbatim.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use gooir_capability::strict_json::{self, StrictJsonError};
use gooir_capability::{DialectId, Fact, FactIdentityError, ValueKindId};
use gooir_package::{
    DialectDeclaration, PackageId, PackageManifest, PackageManifestError, ValueKindDeclaration,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub const PACKAGE: &str = "org.gooi.module";
pub const VERSION: &str = "0.1.0";
pub const MODULE_PROTOCOL: &str = "org.gooi.module/v0";
pub const PACKAGE_MANIFEST: &str = include_str!("../gooir-package.json");

const MAX_SYMBOL_BYTES: usize = 512;
const MAX_REFERENCE_NAME_BYTES: usize = 128;
const MAX_EXTENSION_KEY_BYTES: usize = 512;
const MAX_DIALECTS: usize = 4_096;
const MAX_OPERATIONS: usize = 4_096;
const MAX_REFERENCES_PER_OPERATION: usize = 4_096;
const MAX_EXTENSIONS_PER_SCOPE: usize = 1_024;

/// The exact foundational module vocabulary.
#[must_use]
pub fn dialect_id() -> DialectId {
    DialectId::new(PACKAGE, VERSION)
}

/// The exact value kind of a heterogeneous module payload.
#[must_use]
pub fn module_contract() -> ValueKindId {
    ValueKindId::in_dialect(dialect_id(), "module")
}

/// Constructs the exact installable declaration for the module dialect.
///
/// # Errors
///
/// Returns an error only if the static identities cease to satisfy the
/// package protocol.
///
/// # Panics
///
/// Panics if the crate's static package identity is changed to an invalid
/// exact coordinate.
pub fn build_package_manifest() -> Result<PackageManifest, PackageManifestError> {
    PackageManifest::new(
        PackageId::parse(format!("{PACKAGE}@{VERSION}")).expect("static package ID is valid"),
        Vec::new(),
        Vec::new(),
        vec![DialectDeclaration {
            id: dialect_id(),
            value_kinds: vec![ValueKindDeclaration {
                id: module_contract(),
                schema: None,
                extensions: BTreeMap::new(),
            }],
            extensions: BTreeMap::new(),
        }],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        BTreeMap::new(),
    )
}

/// Reads and validates the checked-in exact package declaration.
///
/// # Errors
///
/// Returns an error if the declaration is malformed or its content identity
/// is stale.
pub fn package_manifest() -> Result<PackageManifest, PackageManifestError> {
    gooir_package::read_manifest(PACKAGE_MANIFEST)
}

/// One exact module-local symbol such as `@fleetd.agents.list`.
///
/// Symbols are language-independent. Source-language paths belong in a
/// source or implementation dialect, never in this structural vocabulary.
/// Spelling is code-point exact; no Unicode normalization is performed.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SymbolName(String);

impl SymbolName {
    /// Parses an absolute, dot-separated module-local symbol.
    ///
    /// # Errors
    ///
    /// Returns an error unless the value starts with `@` and every segment is
    /// a non-empty Unicode identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, ModuleError> {
        let value = value.into();
        let Some(body) = value.strip_prefix('@') else {
            return Err(ModuleError::InvalidSymbol(value));
        };
        if value.len() > MAX_SYMBOL_BYTES || body.is_empty() || !body.split('.').all(is_identifier)
        {
            return Err(ModuleError::InvalidSymbol(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SymbolName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SymbolName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// The exact role of one symbol reference within an operation.
/// Spelling is code-point exact; no Unicode normalization is performed.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ReferenceName(String);

impl ReferenceName {
    /// Parses one bounded Unicode identifier.
    ///
    /// # Errors
    ///
    /// Returns an error for a blank, oversized, or non-identifier role.
    pub fn parse(value: impl Into<String>) -> Result<Self, ModuleError> {
        let value = value.into();
        if value.len() > MAX_REFERENCE_NAME_BYTES || !is_identifier(&value) {
            return Err(ModuleError::InvalidReferenceName(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReferenceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ReferenceName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// One named, typed use of a symbol declared by another operation.
///
/// The expected value kind lets structural validation reject a reference that
/// resolves by spelling but not by semantic type.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SymbolReference {
    pub name: ReferenceName,
    pub symbol: SymbolName,
    pub value_kind: ValueKindId,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl SymbolReference {
    /// Constructs and validates one typed reference with no extensions.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed expected value kind.
    pub fn new(
        name: ReferenceName,
        symbol: SymbolName,
        value_kind: ValueKindId,
    ) -> Result<Self, ModuleError> {
        let reference = Self {
            name,
            symbol,
            value_kind,
            extensions: BTreeMap::new(),
        };
        reference.validate()?;
        Ok(reference)
    }

    fn validate(&self) -> Result<(), ModuleError> {
        ReferenceName::parse(self.name.as_str())?;
        SymbolName::parse(self.symbol.as_str())?;
        if !self.value_kind.is_well_formed() {
            return Err(ModuleError::InvalidValueKind(self.value_kind.clone()));
        }
        validate_extensions(
            "symbol reference",
            &self.extensions,
            &["name", "symbol", "value_kind"],
        )
    }
}

/// One ordered operation in a module.
///
/// The nested fact is the operation's semantic value and content identity.
/// An optional symbol declares that fact to the module; references describe
/// named dependencies on other declared operation facts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModuleOperation {
    pub fact: Fact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<SymbolName>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<SymbolReference>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl ModuleOperation {
    /// Constructs one operation and canonicalizes its set-like references.
    ///
    /// # Errors
    ///
    /// Returns an error when the fact, symbol, references, or extensions are
    /// invalid or contain duplicate reference names.
    pub fn new(
        fact: Fact,
        symbol: Option<SymbolName>,
        references: Vec<SymbolReference>,
    ) -> Result<Self, ModuleError> {
        Self::with_extensions(fact, symbol, references, BTreeMap::new())
    }

    /// Constructs one operation with explicitly preserved envelope extensions.
    ///
    /// # Errors
    ///
    /// Returns an error when any operation structure is invalid.
    pub fn with_extensions(
        fact: Fact,
        symbol: Option<SymbolName>,
        references: Vec<SymbolReference>,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ModuleError> {
        let mut operation = Self {
            fact,
            symbol,
            references,
            extensions,
        };
        operation.canonicalize();
        operation.validate()?;
        Ok(operation)
    }

    /// Sorts the set-like references without changing operation meaning.
    pub fn canonicalize(&mut self) {
        self.references.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.symbol.cmp(&right.symbol))
        });
    }

    /// Validates the operation independently of module-local resolution.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid fact identity, symbol, reference,
    /// canonical order, duplicate reference name, or reserved extension.
    pub fn validate(&self) -> Result<(), ModuleError> {
        self.fact
            .validate()
            .map_err(|error| ModuleError::InvalidOperationFact(error.to_string()))?;
        if let Some(symbol) = &self.symbol {
            SymbolName::parse(symbol.as_str())?;
        }
        validate_extensions(
            "module operation",
            &self.extensions,
            &["fact", "symbol", "references"],
        )?;
        validate_count(
            "operation references",
            self.references.len(),
            MAX_REFERENCES_PER_OPERATION,
        )?;

        let mut previous: Option<&ReferenceName> = None;
        for reference in &self.references {
            reference.validate()?;
            if previous.is_some_and(|prior| prior >= &reference.name) {
                return if previous == Some(&reference.name) {
                    Err(ModuleError::DuplicateReferenceName(reference.name.clone()))
                } else {
                    Err(ModuleError::NonCanonical("operation references"))
                };
            }
            previous = Some(&reference.name);
        }
        Ok(())
    }
}

/// One target-independent, heterogeneous compilation unit.
///
/// Operation order is meaningful and never canonicalized. Dialects and each
/// operation's named references are set-like and therefore identity-sorted.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Module {
    pub protocol: String,
    pub dialects: Vec<DialectId>,
    pub operations: Vec<ModuleOperation>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl Module {
    /// Constructs a module and canonicalizes only its set-like members.
    ///
    /// # Errors
    ///
    /// Returns an error if any dialect, operation, symbol, reference, or
    /// extension is invalid.
    pub fn new(
        dialects: Vec<DialectId>,
        operations: Vec<ModuleOperation>,
    ) -> Result<Self, ModuleError> {
        Self::with_extensions(dialects, operations, BTreeMap::new())
    }

    /// Constructs a module with explicitly preserved semantic extensions.
    ///
    /// # Errors
    ///
    /// Returns an error if any module structure is invalid.
    pub fn with_extensions(
        dialects: Vec<DialectId>,
        operations: Vec<ModuleOperation>,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ModuleError> {
        let mut module = Self {
            protocol: MODULE_PROTOCOL.to_owned(),
            dialects,
            operations,
            extensions,
        };
        module.canonicalize();
        module.validate()?;
        Ok(module)
    }

    /// Sorts set-like members while preserving meaningful operation order.
    pub fn canonicalize(&mut self) {
        self.dialects.sort();
        for operation in &mut self.operations {
            operation.canonicalize();
        }
    }

    /// Validates complete module structure and local symbol resolution.
    ///
    /// This proves structural consistency only. It does not interpret an
    /// operation payload or establish conformance, authority, or target
    /// legality for any contained dialect.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong protocol, malformed or non-canonical
    /// dialect declarations, invalid operations, duplicate symbols, unresolved
    /// references, reference type mismatches, or reserved extensions.
    pub fn validate(&self) -> Result<(), ModuleError> {
        if self.protocol != MODULE_PROTOCOL {
            return Err(ModuleError::ProtocolMismatch {
                actual: self.protocol.clone(),
            });
        }
        validate_extensions(
            "module",
            &self.extensions,
            &["protocol", "dialects", "operations"],
        )?;
        validate_count("module dialects", self.dialects.len(), MAX_DIALECTS)?;
        validate_count("module operations", self.operations.len(), MAX_OPERATIONS)?;

        let mut declared_dialects = BTreeSet::new();
        let mut previous_dialect: Option<&DialectId> = None;
        for dialect in &self.dialects {
            if !dialect.is_well_formed() {
                return Err(ModuleError::InvalidDialect(dialect.clone()));
            }
            if !declared_dialects.insert(dialect.clone()) {
                return Err(ModuleError::DuplicateDialect(dialect.clone()));
            }
            if previous_dialect.is_some_and(|previous| previous >= dialect) {
                return Err(ModuleError::NonCanonical("module dialects"));
            }
            previous_dialect = Some(dialect);
        }

        let mut symbols = BTreeMap::new();
        for (index, operation) in self.operations.iter().enumerate() {
            operation
                .validate()
                .map_err(|error| ModuleError::InvalidOperation {
                    index,
                    detail: error.to_string(),
                })?;
            let operation_dialect = operation.fact.value_kind.dialect();
            if !declared_dialects.contains(&operation_dialect) {
                return Err(ModuleError::UndeclaredDialect {
                    index,
                    dialect: operation_dialect,
                });
            }
            if let Some(symbol) = &operation.symbol
                && symbols
                    .insert(symbol.clone(), operation.fact.value_kind.clone())
                    .is_some()
            {
                return Err(ModuleError::DuplicateSymbol(symbol.clone()));
            }
        }

        for (index, operation) in self.operations.iter().enumerate() {
            for reference in &operation.references {
                let Some(actual) = symbols.get(&reference.symbol) else {
                    return Err(ModuleError::UnresolvedSymbol {
                        index,
                        symbol: reference.symbol.clone(),
                    });
                };
                if actual != &reference.value_kind {
                    return Err(ModuleError::ReferenceTypeMismatch {
                        index,
                        symbol: reference.symbol.clone(),
                        expected: Box::new(reference.value_kind.clone()),
                        actual: Box::new(actual.clone()),
                    });
                }
            }
        }
        Ok(())
    }

    /// Resolves one exact module-local symbol.
    ///
    /// No case folding, prefix matching, aliasing, version substitution, or
    /// iteration-order fallback is performed.
    ///
    /// # Errors
    ///
    /// Returns an error if the module is invalid or the exact symbol is not
    /// declared.
    pub fn resolve(&self, symbol: &SymbolName) -> Result<&ModuleOperation, ModuleError> {
        self.validate()?;
        self.operations
            .iter()
            .find(|operation| operation.symbol.as_ref() == Some(symbol))
            .ok_or_else(|| ModuleError::SymbolNotFound(symbol.clone()))
    }

    /// Wraps this module as one content-identified GOOIR fact.
    ///
    /// # Errors
    ///
    /// Returns an error if the module is invalid or cannot be represented as
    /// canonical JSON.
    pub fn into_fact(self) -> Result<Fact, ModuleError> {
        ModuleFact::new(self)?.into_fact()
    }
}

/// A decoded module plus semantic extensions on its outer GOOIR fact.
///
/// Keeping this envelope explicit prevents typed module decoding from
/// silently discarding future fact-level semantics.
#[derive(Clone, Debug, PartialEq)]
pub struct ModuleFact {
    pub module: Module,
    pub extensions: BTreeMap<String, Value>,
}

impl ModuleFact {
    /// Constructs a module fact with no outer semantic extensions.
    ///
    /// # Errors
    ///
    /// Returns an error if the module is structurally invalid.
    pub fn new(module: Module) -> Result<Self, ModuleError> {
        Self::with_extensions(module, BTreeMap::new())
    }

    /// Constructs a module fact with explicitly preserved outer extensions.
    ///
    /// # Errors
    ///
    /// Returns an error if the module or fact extensions are invalid.
    pub fn with_extensions(
        module: Module,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ModuleError> {
        module.validate()?;
        let envelope = Self { module, extensions };
        envelope.clone().into_fact()?;
        Ok(envelope)
    }

    /// Decodes and validates an exact module fact without losing extensions.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid fact identity, wrong value kind,
    /// malformed module payload, or invalid module structure.
    pub fn from_fact(fact: &Fact) -> Result<Self, ModuleError> {
        fact.validate().map_err(ModuleError::InvalidFact)?;
        if fact.value_kind != module_contract() {
            return Err(ModuleError::WrongFactKind(fact.value_kind.clone()));
        }
        let module: Module = serde_json::from_value(fact.payload.clone())
            .map_err(|error| ModuleError::Json(error.to_string()))?;
        module.validate()?;
        Ok(Self {
            module,
            extensions: fact.extensions.clone(),
        })
    }

    /// Encodes this envelope as an exact content-identified module fact.
    ///
    /// # Errors
    ///
    /// Returns an error if module validation, serialization, or fact identity
    /// construction fails.
    pub fn into_fact(self) -> Result<Fact, ModuleError> {
        self.module.validate()?;
        let payload = serde_json::to_value(self.module)
            .map_err(|error| ModuleError::Json(error.to_string()))?;
        Fact::with_extensions(module_contract(), payload, self.extensions)
            .map_err(ModuleError::InvalidFact)
    }
}

/// Reads and validates one standalone module payload.
///
/// Duplicate JSON keys are rejected recursively before typed decoding.
///
/// # Errors
///
/// Returns an error for malformed JSON, duplicate keys, or invalid module
/// structure.
pub fn read_module(json: &str) -> Result<Module, ModuleError> {
    let module: Module = strict_json::from_str(json).map_err(ModuleError::StrictJson)?;
    module.validate()?;
    Ok(module)
}

/// Writes one validated standalone module payload.
///
/// # Errors
///
/// Returns an error for invalid structure or JSON serialization failure.
pub fn write_module(module: &Module) -> Result<String, ModuleError> {
    module.validate()?;
    serde_json::to_string(module).map_err(|error| ModuleError::Json(error.to_string()))
}

/// Structural failure in the foundational module vocabulary.
#[derive(Clone, Debug, PartialEq)]
pub enum ModuleError {
    ProtocolMismatch {
        actual: String,
    },
    InvalidDialect(DialectId),
    DuplicateDialect(DialectId),
    UndeclaredDialect {
        index: usize,
        dialect: DialectId,
    },
    InvalidSymbol(String),
    InvalidReferenceName(String),
    InvalidValueKind(ValueKindId),
    DuplicateSymbol(SymbolName),
    SymbolNotFound(SymbolName),
    DuplicateReferenceName(ReferenceName),
    UnresolvedSymbol {
        index: usize,
        symbol: SymbolName,
    },
    ReferenceTypeMismatch {
        index: usize,
        symbol: SymbolName,
        expected: Box<ValueKindId>,
        actual: Box<ValueKindId>,
    },
    InvalidOperationFact(String),
    InvalidOperation {
        index: usize,
        detail: String,
    },
    NonCanonical(&'static str),
    ReservedExtension {
        scope: &'static str,
        key: String,
    },
    InvalidExtensionKey {
        scope: &'static str,
        key: String,
    },
    TooMany {
        scope: &'static str,
        actual: usize,
        maximum: usize,
    },
    WrongFactKind(ValueKindId),
    InvalidFact(FactIdentityError),
    StrictJson(StrictJsonError),
    Json(String),
}

impl fmt::Display for ModuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolMismatch { actual } => write!(
                formatter,
                "module protocol mismatch: expected {MODULE_PROTOCOL}, got {actual}"
            ),
            Self::InvalidDialect(dialect) => write!(formatter, "invalid dialect `{dialect}`"),
            Self::DuplicateDialect(dialect) => write!(formatter, "duplicate dialect `{dialect}`"),
            Self::UndeclaredDialect { index, dialect } => write!(
                formatter,
                "operation {index} uses undeclared dialect `{dialect}`"
            ),
            Self::InvalidSymbol(symbol) => write!(formatter, "invalid symbol `{symbol}`"),
            Self::InvalidReferenceName(name) => {
                write!(formatter, "invalid reference name `{name}`")
            }
            Self::InvalidValueKind(kind) => write!(formatter, "invalid value kind `{kind}`"),
            Self::DuplicateSymbol(symbol) => write!(formatter, "duplicate symbol `{symbol}`"),
            Self::SymbolNotFound(symbol) => write!(formatter, "unknown symbol `{symbol}`"),
            Self::DuplicateReferenceName(name) => {
                write!(formatter, "duplicate reference name `{name}`")
            }
            Self::UnresolvedSymbol { index, symbol } => {
                write!(
                    formatter,
                    "operation {index} references unknown symbol `{symbol}`"
                )
            }
            Self::ReferenceTypeMismatch {
                index,
                symbol,
                expected,
                actual,
            } => write!(
                formatter,
                "operation {index} expects symbol `{symbol}` to be `{expected}`, got `{actual}`"
            ),
            Self::InvalidOperationFact(detail) => {
                write!(formatter, "invalid operation fact: {detail}")
            }
            Self::InvalidOperation { index, detail } => {
                write!(formatter, "invalid operation {index}: {detail}")
            }
            Self::NonCanonical(scope) => write!(formatter, "{scope} are not canonical"),
            Self::ReservedExtension { scope, key } => {
                write!(formatter, "{scope} extension `{key}` shadows a known field")
            }
            Self::InvalidExtensionKey { scope, key } => {
                write!(formatter, "{scope} extension key `{key}` is invalid")
            }
            Self::TooMany {
                scope,
                actual,
                maximum,
            } => write!(
                formatter,
                "{scope} count {actual} exceeds maximum {maximum}"
            ),
            Self::WrongFactKind(kind) => write!(
                formatter,
                "expected module fact kind `{}`, got `{kind}`",
                module_contract()
            ),
            Self::InvalidFact(error) => write!(formatter, "invalid module fact: {error}"),
            Self::StrictJson(error) => write!(formatter, "invalid module JSON: {error}"),
            Self::Json(detail) => write!(formatter, "module JSON failed: {detail}"),
        }
    }
}

impl Error for ModuleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidFact(error) => Some(error),
            Self::StrictJson(error) => Some(error),
            _ => None,
        }
    }
}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character.is_alphabetic() || character == '_')
        && characters.all(|character| character.is_alphanumeric() || character == '_')
}

fn validate_extensions(
    scope: &'static str,
    extensions: &BTreeMap<String, Value>,
    reserved: &[&str],
) -> Result<(), ModuleError> {
    if let Some(key) = reserved.iter().find(|key| extensions.contains_key(**key)) {
        return Err(ModuleError::ReservedExtension {
            scope,
            key: (*key).to_owned(),
        });
    }
    validate_count("extensions", extensions.len(), MAX_EXTENSIONS_PER_SCOPE)?;
    for key in extensions.keys() {
        let namespaced = key
            .split_once('/')
            .is_some_and(|(namespace, name)| !namespace.is_empty() && !name.is_empty());
        if key.len() > MAX_EXTENSION_KEY_BYTES
            || key.trim() != key
            || key.chars().any(char::is_control)
            || !namespaced
        {
            return Err(ModuleError::InvalidExtensionKey {
                scope,
                key: key.clone(),
            });
        }
    }
    Ok(())
}

fn validate_count(scope: &'static str, actual: usize, maximum: usize) -> Result<(), ModuleError> {
    if actual > maximum {
        Err(ModuleError::TooMany {
            scope,
            actual,
            maximum,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gooir_capability::FactId;
    use serde_json::json;

    fn operations_kind() -> ValueKindId {
        ValueKindId::new("org.example.operations", "function", "1.0.0")
    }

    fn http_kind() -> ValueKindId {
        ValueKindId::new("org.example.http", "route", "1.0.0")
    }

    fn operation(
        kind: ValueKindId,
        payload: Value,
        symbol: Option<&str>,
        references: Vec<SymbolReference>,
    ) -> ModuleOperation {
        ModuleOperation::new(
            Fact::new(kind, payload).unwrap(),
            symbol.map(|value| SymbolName::parse(value).unwrap()),
            references,
        )
        .unwrap()
    }

    fn reference(name: &str, symbol: &str, kind: ValueKindId) -> SymbolReference {
        SymbolReference::new(
            ReferenceName::parse(name).unwrap(),
            SymbolName::parse(symbol).unwrap(),
            kind,
        )
        .unwrap()
    }

    fn heterogeneous_module() -> Module {
        Module::new(
            vec![operations_kind().dialect(), http_kind().dialect()],
            vec![
                operation(
                    operations_kind(),
                    json!({"input": "none", "output": "agent_list"}),
                    Some("@fleetd.agents.list"),
                    Vec::new(),
                ),
                operation(
                    http_kind(),
                    json!({"method": "GET", "path": "/v1/agents"}),
                    Some("@fleetd.http.list_agents"),
                    vec![reference(
                        "operation",
                        "@fleetd.agents.list",
                        operations_kind(),
                    )],
                ),
            ],
        )
        .unwrap()
    }

    #[test]
    fn exact_static_identities_are_well_formed() {
        assert!(dialect_id().is_well_formed());
        assert!(module_contract().is_well_formed());
        assert_eq!(module_contract().dialect(), dialect_id());
    }

    #[test]
    fn an_empty_module_is_valid() {
        let module = Module::new(Vec::new(), Vec::new()).unwrap();
        module.validate().unwrap();
        ModuleFact::from_fact(&module.into_fact().unwrap()).unwrap();
    }

    #[test]
    fn checked_in_package_manifest_matches_the_constructed_declaration() {
        let expected = gooir_package::write_manifest(&build_package_manifest().unwrap()).unwrap();
        assert_eq!(PACKAGE_MANIFEST.trim(), expected);
        assert_eq!(
            package_manifest().unwrap(),
            build_package_manifest().unwrap()
        );
    }

    #[test]
    fn a_heterogeneous_module_is_one_content_identified_fact() {
        let mut module = heterogeneous_module();
        module.extensions.insert(
            "org.example.module/annotation".to_owned(),
            json!({"unknown": [1, 2, 3]}),
        );
        module.operations[1].extensions.insert(
            "org.example.operation/hint".to_owned(),
            json!("preserve me"),
        );
        module.operations[1].fact = Fact::with_extensions(
            http_kind(),
            module.operations[1].fact.payload.clone(),
            BTreeMap::from([("org.example.http/future".to_owned(), json!(true))]),
        )
        .unwrap();
        module.validate().unwrap();

        let envelope = ModuleFact::with_extensions(
            module.clone(),
            BTreeMap::from([("org.example.fact/provenance".to_owned(), json!("future"))]),
        )
        .unwrap();
        let fact = envelope.clone().into_fact().unwrap();
        fact.validate().unwrap();
        assert_eq!(fact.value_kind, module_contract());

        let decoded = ModuleFact::from_fact(&fact).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.into_fact().unwrap(), fact);
    }

    #[test]
    fn operation_order_is_meaningful_while_set_members_are_canonicalized() {
        let module = heterogeneous_module();
        let mut reversed = Module::new(
            module.dialects.iter().cloned().rev().collect(),
            module.operations.iter().cloned().rev().collect(),
        )
        .unwrap();
        assert_eq!(reversed.dialects, module.dialects);
        assert_ne!(reversed.operations, module.operations);
        assert_ne!(
            reversed.clone().into_fact().unwrap().id,
            module.into_fact().unwrap().id
        );

        reversed.dialects.reverse();
        assert_eq!(
            reversed.validate(),
            Err(ModuleError::NonCanonical("module dialects"))
        );
    }

    #[test]
    fn references_must_resolve_by_symbol_and_exact_value_kind() {
        let mut unresolved = heterogeneous_module();
        unresolved.operations[1].references[0].symbol =
            SymbolName::parse("@fleetd.agents.missing").unwrap();
        assert!(matches!(
            unresolved.validate(),
            Err(ModuleError::UnresolvedSymbol { index: 1, .. })
        ));

        let mut wrong_kind = heterogeneous_module();
        wrong_kind.operations[1].references[0].value_kind = http_kind();
        assert!(matches!(
            wrong_kind.validate(),
            Err(ModuleError::ReferenceTypeMismatch { index: 1, .. })
        ));

        let mut wrong_version = heterogeneous_module();
        wrong_version.operations[1].references[0].value_kind =
            ValueKindId::new("org.example.operations", "function", "1.0.1");
        assert!(matches!(
            wrong_version.validate(),
            Err(ModuleError::ReferenceTypeMismatch { index: 1, .. })
        ));
    }

    #[test]
    fn symbol_resolution_is_exact_case_sensitive_and_unicode_preserving() {
        let mut module = heterogeneous_module();
        module.operations[0].symbol = Some(SymbolName::parse("@fléetd.agents.list").unwrap());
        module.operations[1].references[0].symbol =
            SymbolName::parse("@fléetd.agents.list").unwrap();
        module.validate().unwrap();

        let symbol = SymbolName::parse("@fléetd.agents.list").unwrap();
        assert_eq!(module.resolve(&symbol).unwrap(), &module.operations[0]);
        assert_eq!(
            module.resolve(&SymbolName::parse("@Fléetd.agents.list").unwrap()),
            Err(ModuleError::SymbolNotFound(
                SymbolName::parse("@Fléetd.agents.list").unwrap()
            ))
        );

        let round_trip = read_module(&write_module(&module).unwrap()).unwrap();
        assert_eq!(round_trip, module);
    }

    #[test]
    fn duplicate_symbols_and_reference_names_fail_closed() {
        let mut symbols = heterogeneous_module();
        symbols.operations[1].symbol = Some(SymbolName::parse("@fleetd.agents.list").unwrap());
        assert!(matches!(
            symbols.validate(),
            Err(ModuleError::DuplicateSymbol(_))
        ));

        let mut references = heterogeneous_module();
        let duplicate = references.operations[1].references[0].clone();
        references.operations[1].references.push(duplicate);
        assert!(matches!(
            references.validate(),
            Err(ModuleError::InvalidOperation { index: 1, detail })
                if detail.contains("duplicate reference name")
        ));
    }

    #[test]
    fn every_operation_dialect_must_be_declared_exactly() {
        let mut undeclared = heterogeneous_module();
        undeclared
            .dialects
            .retain(|dialect| dialect != &http_kind().dialect());
        assert_eq!(
            undeclared.validate(),
            Err(ModuleError::UndeclaredDialect {
                index: 1,
                dialect: http_kind().dialect(),
            })
        );

        let mut duplicate = heterogeneous_module();
        duplicate.dialects.insert(1, duplicate.dialects[0].clone());
        assert!(matches!(
            duplicate.validate(),
            Err(ModuleError::DuplicateDialect(_))
        ));
    }

    #[test]
    fn tampered_nested_and_outer_fact_identities_are_rejected() {
        let mut nested = heterogeneous_module();
        nested.operations[0].fact.payload = json!({"tampered": true});
        assert!(matches!(
            nested.validate(),
            Err(ModuleError::InvalidOperation { index: 0, .. })
        ));

        let mut outer = heterogeneous_module().into_fact().unwrap();
        outer.id = FactId::parse(format!("sha256:{}", "0".repeat(64))).unwrap();
        assert!(matches!(
            ModuleFact::from_fact(&outer),
            Err(ModuleError::InvalidFact(
                FactIdentityError::IdentityMismatch { .. }
            ))
        ));
    }

    #[test]
    fn reserved_extensions_and_duplicate_json_keys_are_rejected() {
        let mut module = heterogeneous_module();
        module.extensions.insert("operations".to_owned(), json!([]));
        assert!(matches!(
            module.validate(),
            Err(ModuleError::ReservedExtension { key, .. }) if key == "operations"
        ));

        let mut malformed = heterogeneous_module();
        malformed
            .extensions
            .insert("not_namespaced".to_owned(), json!(true));
        assert!(matches!(
            malformed.validate(),
            Err(ModuleError::InvalidExtensionKey { key, .. }) if key == "not_namespaced"
        ));

        let json = r#"{
            "protocol":"org.gooi.module/v0",
            "dialects":[],
            "operations":[],
            "org.example/future":{"same":1,"same":2}
        }"#;
        assert_eq!(
            read_module(json),
            Err(ModuleError::StrictJson(
                StrictJsonError::DuplicateObjectKey("same".to_owned())
            ))
        );
    }

    #[test]
    fn standalone_json_round_trips_unknown_operations_verbatim() {
        let module = heterogeneous_module();
        let written = write_module(&module).unwrap();
        let decoded = read_module(&written).unwrap();
        assert_eq!(decoded, module);
        assert_eq!(write_module(&decoded).unwrap(), written);
    }

    #[test]
    fn all_structural_scopes_are_bounded() {
        let too_many_dialects = Module {
            protocol: MODULE_PROTOCOL.to_owned(),
            dialects: vec![operations_kind().dialect(); MAX_DIALECTS + 1],
            operations: Vec::new(),
            extensions: BTreeMap::new(),
        };
        assert_eq!(
            too_many_dialects.validate(),
            Err(ModuleError::TooMany {
                scope: "module dialects",
                actual: MAX_DIALECTS + 1,
                maximum: MAX_DIALECTS,
            })
        );

        let mut too_many_references = heterogeneous_module().operations.remove(1);
        too_many_references.references =
            vec![too_many_references.references[0].clone(); MAX_REFERENCES_PER_OPERATION + 1];
        assert_eq!(
            too_many_references.validate(),
            Err(ModuleError::TooMany {
                scope: "operation references",
                actual: MAX_REFERENCES_PER_OPERATION + 1,
                maximum: MAX_REFERENCES_PER_OPERATION,
            })
        );

        let repeated = operation(
            operations_kind(),
            json!({"input": "none", "output": "none"}),
            None,
            Vec::new(),
        );
        let too_many_operations = Module {
            protocol: MODULE_PROTOCOL.to_owned(),
            dialects: vec![operations_kind().dialect()],
            operations: vec![repeated; MAX_OPERATIONS + 1],
            extensions: BTreeMap::new(),
        };
        assert_eq!(
            too_many_operations.validate(),
            Err(ModuleError::TooMany {
                scope: "module operations",
                actual: MAX_OPERATIONS + 1,
                maximum: MAX_OPERATIONS,
            })
        );

        let too_many_extensions = Module {
            protocol: MODULE_PROTOCOL.to_owned(),
            dialects: Vec::new(),
            operations: Vec::new(),
            extensions: (0..=MAX_EXTENSIONS_PER_SCOPE)
                .map(|index| (format!("org.example/{index}"), Value::Null))
                .collect(),
        };
        assert_eq!(
            too_many_extensions.validate(),
            Err(ModuleError::TooMany {
                scope: "extensions",
                actual: MAX_EXTENSIONS_PER_SCOPE + 1,
                maximum: MAX_EXTENSIONS_PER_SCOPE,
            })
        );
    }

    #[test]
    fn structural_names_and_extension_keys_are_byte_bounded() {
        let longest_symbol = format!("@{}", "a".repeat(MAX_SYMBOL_BYTES - 1));
        assert!(SymbolName::parse(longest_symbol).is_ok());
        assert!(SymbolName::parse(format!("@{}", "a".repeat(MAX_SYMBOL_BYTES))).is_err());

        assert!(ReferenceName::parse("a".repeat(MAX_REFERENCE_NAME_BYTES)).is_ok());
        assert!(ReferenceName::parse("a".repeat(MAX_REFERENCE_NAME_BYTES + 1)).is_err());

        let mut module = Module::new(Vec::new(), Vec::new()).unwrap();
        module.extensions.insert(
            format!("org.example/{}", "a".repeat(MAX_EXTENSION_KEY_BYTES)),
            Value::Null,
        );
        assert!(matches!(
            module.validate(),
            Err(ModuleError::InvalidExtensionKey { .. })
        ));
    }

    #[test]
    fn every_structural_change_changes_the_module_fact_identity() {
        let module = heterogeneous_module();
        let original = module.clone().into_fact().unwrap().id;

        let mut changed_symbol = module.clone();
        changed_symbol.operations[1].symbol =
            Some(SymbolName::parse("@fleetd.http.list_agents_v2").unwrap());
        assert_ne!(changed_symbol.into_fact().unwrap().id, original);

        let mut changed_extension = module.clone();
        changed_extension.operations[1].references[0]
            .extensions
            .insert(
                "org.example.reference/future".to_owned(),
                json!({"preserved": true}),
            );
        assert_ne!(changed_extension.into_fact().unwrap().id, original);

        let mut changed_payload = module;
        changed_payload.operations[1].fact =
            Fact::new(http_kind(), json!({"method": "POST", "path": "/v1/agents"})).unwrap();
        assert_ne!(changed_payload.into_fact().unwrap().id, original);
    }

    #[test]
    fn symbol_and_reference_spelling_is_exact() {
        for invalid in [
            "fleetd.agents.list",
            "@",
            "@fleetd..list",
            "@fleetd.agents-list",
            "@1fleetd.list",
        ] {
            assert!(SymbolName::parse(invalid).is_err(), "{invalid}");
        }
        assert_eq!(
            SymbolName::parse("@fléetd.agents.list").unwrap().as_str(),
            "@fléetd.agents.list"
        );
        for invalid in ["", "operation-name", "1operation", " operation"] {
            assert!(ReferenceName::parse(invalid).is_err(), "{invalid}");
        }
    }
}
