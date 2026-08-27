//! Typed authoring for neutral v1 capability providers.
//!
//! The SDK owns protocol validation, exact capability and implementation
//! matching, typed named-port decoding, result construction, and JSON/stdin
//! framing. A provider author owns only the semantic transformation.
//!
//! ```text
//! validated invocation -> typed named inputs -> transformation -> typed named outputs
//! ```
//!
//! Lifting, lowering, generation, and analysis all use this one surface. Those
//! words describe ecosystem meaning; they are not different execution
//! mechanisms.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io::{Read, Write};

use gooir_capability::protocol::{
    AdmittedFactRef, CapabilityFailure, CapabilityInvocation, CapabilityResult, EvidenceRef,
    FailureKindId, ImplementationId, NamedOutput, ProtocolError,
};
use gooir_capability::{CapabilityId, CapabilitySpec, Fact, PortName, canonical_digest};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// One exact neutral provider implementation.
#[derive(Clone, Debug)]
pub struct Provider {
    specification: CapabilitySpec,
    specification_digest: String,
    implementation: ImplementationId,
}

impl Provider {
    /// Binds an implementation to the exact capability specification it serves.
    ///
    /// This validates declaration shape before the provider accepts an
    /// invocation. Offers and artifact identity remain package/host-owned.
    pub fn new(
        specification: CapabilitySpec,
        implementation: ImplementationId,
    ) -> Result<Self, ProviderError> {
        specification
            .validate()
            .map_err(|error| ProviderError::InvalidSpecification(error.to_string()))?;
        if !implementation.is_well_formed() {
            return Err(ProviderError::InvalidImplementation(implementation));
        }
        let specification_digest =
            canonical_digest(&specification).map_err(ProviderError::InvalidSpecification)?;
        Ok(Self {
            specification,
            specification_digest,
            implementation,
        })
    }

    /// The exact implementation-independent contract this provider accepts.
    #[must_use]
    pub const fn specification(&self) -> &CapabilitySpec {
        &self.specification
    }

    /// The exact semantic identity of this implementation.
    #[must_use]
    pub const fn implementation(&self) -> &ImplementationId {
        &self.implementation
    }

    /// Validates and evaluates one complete neutral invocation.
    ///
    /// The handler is never called unless the invocation is structurally
    /// valid and names this exact capability specification and implementation.
    pub fn invoke<F>(
        &self,
        invocation: &CapabilityInvocation,
        handler: F,
    ) -> Result<CapabilityResult, ProviderError>
    where
        F: FnOnce(&Context<'_>) -> Result<Outcome, ProviderError>,
    {
        invocation.validate().map_err(ProviderError::Protocol)?;
        if invocation.specification != self.specification {
            let actual_digest = canonical_digest(&invocation.specification)
                .map_err(ProviderError::InvalidSpecification)?;
            return Err(ProviderError::SpecificationMismatch {
                expected: Box::new(self.specification.id.clone()),
                actual: Box::new(invocation.specification.id.clone()),
                expected_digest: self.specification_digest.clone(),
                actual_digest,
            });
        }
        if invocation.selection.offer.implementation != self.implementation {
            return Err(ProviderError::ImplementationMismatch {
                expected: Box::new(self.implementation.clone()),
                actual: Box::new(invocation.selection.offer.implementation.clone()),
            });
        }

        let context = Context { invocation };
        let outcome = handler(&context)?;
        match outcome.kind {
            OutcomeKind::Produced(outputs) => CapabilityResult::produced(
                invocation,
                outputs,
                outcome.outcome_extensions,
                outcome.evidence,
                outcome.result_extensions,
            ),
            OutcomeKind::Unable(failure) => CapabilityResult::unable(
                invocation,
                failure,
                outcome.outcome_extensions,
                outcome.evidence,
                outcome.result_extensions,
            ),
        }
        .map_err(ProviderError::Protocol)
    }

    /// Parses one invocation document and returns one result document.
    pub fn invoke_json<F>(&self, input: &str, handler: F) -> Result<String, ProviderError>
    where
        F: FnOnce(&Context<'_>) -> Result<Outcome, ProviderError>,
    {
        let invocation = serde_json::from_str(input)
            .map_err(|error| ProviderError::InvocationJson(error.to_string()))?;
        let result = self.invoke(&invocation, handler)?;
        serde_json::to_string(&result).map_err(|error| ProviderError::ResultJson(error.to_string()))
    }

    /// Serves one complete invocation over caller-supplied streams.
    pub fn serve_once<R, W, F>(
        &self,
        mut input: R,
        mut output: W,
        handler: F,
    ) -> Result<(), ProviderError>
    where
        R: Read,
        W: Write,
        F: FnOnce(&Context<'_>) -> Result<Outcome, ProviderError>,
    {
        let mut document = String::new();
        input
            .read_to_string(&mut document)
            .map_err(|error| ProviderError::Io(error.to_string()))?;
        let result = self.invoke_json(&document, handler)?;
        output
            .write_all(result.as_bytes())
            .and_then(|()| output.flush())
            .map_err(|error| ProviderError::Io(error.to_string()))
    }

    /// Serves one complete invocation over stdin/stdout.
    ///
    /// Process lifecycle, limits, and launch authority remain external-host
    /// concerns. This helper only owns the credential-free document framing.
    pub fn serve_stdio<F>(&self, handler: F) -> Result<(), ProviderError>
    where
        F: FnOnce(&Context<'_>) -> Result<Outcome, ProviderError>,
    {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        self.serve_once(stdin.lock(), stdout.lock(), handler)
    }
}

/// Typed access to one validated invocation.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    invocation: &'a CapabilityInvocation,
}

impl<'a> Context<'a> {
    /// The complete validated invocation for advanced protocol-aware providers.
    #[must_use]
    pub const fn invocation(&self) -> &'a CapabilityInvocation {
        self.invocation
    }

    /// Decodes one named semantic input whose fact has no extensions.
    ///
    /// Refusing extensions by default prevents a typed payload from silently
    /// discarding meaning it does not understand. Providers that explicitly
    /// handle extensions use [`Context::input_with_extensions`].
    pub fn input<T>(&self, port: &str) -> Result<T, ProviderError>
    where
        T: DeserializeOwned,
    {
        let linked = self.linked_input(port)?;
        if !linked.fact.extensions.is_empty() {
            return Err(ProviderError::UnsupportedInputExtensions {
                port: linked.port.clone(),
                keys: linked.fact.extensions.keys().cloned().collect(),
            });
        }
        serde_json::from_value(linked.fact.payload.clone()).map_err(|error| {
            ProviderError::InputPayload {
                port: linked.port.clone(),
                detail: error.to_string(),
            }
        })
    }

    /// Decodes one named input while exposing its complete semantic envelope.
    pub fn input_with_extensions<T>(&self, port: &str) -> Result<DecodedInput<'a, T>, ProviderError>
    where
        T: DeserializeOwned,
    {
        let linked = self.linked_input(port)?;
        let value = serde_json::from_value(linked.fact.payload.clone()).map_err(|error| {
            ProviderError::InputPayload {
                port: linked.port.clone(),
                detail: error.to_string(),
            }
        })?;
        Ok(DecodedInput {
            value,
            fact: &linked.fact,
            admitted: &linked.admitted,
            link_extensions: &linked.extensions,
        })
    }

    /// Starts a produced result whose outputs are named in any authoring order.
    ///
    /// [`Produced::finish`] verifies completeness and emits outputs in the
    /// capability declaration's exact order.
    #[must_use]
    pub fn produced(&self) -> Produced<'a> {
        Produced {
            invocation: self.invocation,
            outputs: BTreeMap::new(),
        }
    }

    /// Constructs an inability with typed JSON detail.
    pub fn unable<T>(&self, kind: FailureKindId, detail: T) -> Result<Outcome, ProviderError>
    where
        T: Serialize,
    {
        self.unable_with_extensions(kind, detail, BTreeMap::new())
    }

    /// Constructs an inability with explicitly handled failure extensions.
    pub fn unable_with_extensions<T>(
        &self,
        kind: FailureKindId,
        detail: T,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Outcome, ProviderError>
    where
        T: Serialize,
    {
        let detail = serde_json::to_value(detail)
            .map_err(|error| ProviderError::FailureDetail(error.to_string()))?;
        let failure =
            CapabilityFailure::new(kind, detail, extensions).map_err(ProviderError::Protocol)?;
        Ok(Outcome::new(OutcomeKind::Unable(failure)))
    }

    fn linked_input(
        &self,
        port: &str,
    ) -> Result<&'a gooir_capability::protocol::LinkedInput, ProviderError> {
        self.invocation
            .inputs
            .iter()
            .find(|input| input.port.as_str() == port)
            .ok_or_else(|| ProviderError::UnknownInputPort(port.to_owned()))
    }
}

/// One decoded input plus the exact semantic and linking envelope it arrived in.
#[derive(Debug)]
pub struct DecodedInput<'a, T> {
    pub value: T,
    pub fact: &'a Fact,
    pub admitted: &'a AdmittedFactRef,
    pub link_extensions: &'a BTreeMap<String, Value>,
}

/// Builder for one complete produced result.
#[derive(Debug)]
pub struct Produced<'a> {
    invocation: &'a CapabilityInvocation,
    outputs: BTreeMap<PortName, NamedOutput>,
}

impl<'a> Produced<'a> {
    /// Adds one named output with no semantic or envelope extensions.
    pub fn output<T>(self, port: &str, value: T) -> Result<Self, ProviderError>
    where
        T: Serialize,
    {
        self.output_with_extensions(port, value, BTreeMap::new(), BTreeMap::new())
    }

    /// Adds one named output with explicitly handled semantic and envelope extensions.
    pub fn output_with_extensions<T>(
        mut self,
        port: &str,
        value: T,
        fact_extensions: BTreeMap<String, Value>,
        output_extensions: BTreeMap<String, Value>,
    ) -> Result<Self, ProviderError>
    where
        T: Serialize,
    {
        let declaration = self
            .invocation
            .specification
            .output_ports
            .iter()
            .find(|candidate| candidate.name.as_str() == port)
            .ok_or_else(|| ProviderError::UnknownOutputPort(port.to_owned()))?;
        if self.outputs.contains_key(&declaration.name) {
            return Err(ProviderError::DuplicateOutputPort(declaration.name.clone()));
        }
        let payload =
            serde_json::to_value(value).map_err(|error| ProviderError::OutputPayload {
                port: declaration.name.clone(),
                detail: error.to_string(),
            })?;
        let fact = Fact::with_extensions(declaration.value_kind.clone(), payload, fact_extensions)
            .map_err(|error| ProviderError::OutputFact {
                port: declaration.name.clone(),
                detail: error.to_string(),
            })?;
        let output = NamedOutput::new(declaration.name.clone(), fact, output_extensions)
            .map_err(ProviderError::Protocol)?;
        self.outputs.insert(declaration.name.clone(), output);
        Ok(self)
    }

    /// Completes the result after every declared output has been supplied.
    pub fn finish(mut self) -> Result<Outcome, ProviderError> {
        let missing = self
            .invocation
            .specification
            .output_ports
            .iter()
            .filter(|port| !self.outputs.contains_key(&port.name))
            .map(|port| port.name.clone())
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(ProviderError::MissingOutputs(missing));
        }
        let outputs = self
            .invocation
            .specification
            .output_ports
            .iter()
            .map(|port| {
                self.outputs
                    .remove(&port.name)
                    .expect("every declared output was checked above")
            })
            .collect();
        Ok(Outcome::new(OutcomeKind::Produced(outputs)))
    }
}

/// A complete semantic result before protocol framing.
#[derive(Debug)]
pub struct Outcome {
    kind: OutcomeKind,
    outcome_extensions: BTreeMap<String, Value>,
    evidence: Vec<EvidenceRef>,
    result_extensions: BTreeMap<String, Value>,
}

impl Outcome {
    fn new(kind: OutcomeKind) -> Self {
        Self {
            kind,
            outcome_extensions: BTreeMap::new(),
            evidence: Vec::new(),
            result_extensions: BTreeMap::new(),
        }
    }

    /// Adds externally meaningful evidence references to the result.
    #[must_use]
    pub fn with_evidence(mut self, evidence: impl IntoIterator<Item = EvidenceRef>) -> Self {
        self.evidence.extend(evidence);
        self
    }

    /// Adds explicitly handled extensions to the produced/unable outcome.
    #[must_use]
    pub fn with_outcome_extensions(mut self, extensions: BTreeMap<String, Value>) -> Self {
        self.outcome_extensions = extensions;
        self
    }

    /// Adds explicitly handled extensions to the complete result document.
    #[must_use]
    pub fn with_result_extensions(mut self, extensions: BTreeMap<String, Value>) -> Self {
        self.result_extensions = extensions;
        self
    }
}

#[derive(Debug)]
enum OutcomeKind {
    Produced(Vec<NamedOutput>),
    Unable(CapabilityFailure),
}

/// A provider-authoring or neutral framing failure.
#[derive(Debug)]
pub enum ProviderError {
    InvalidSpecification(String),
    InvalidImplementation(ImplementationId),
    Protocol(ProtocolError),
    SpecificationMismatch {
        expected: Box<CapabilityId>,
        actual: Box<CapabilityId>,
        expected_digest: String,
        actual_digest: String,
    },
    ImplementationMismatch {
        expected: Box<ImplementationId>,
        actual: Box<ImplementationId>,
    },
    UnknownInputPort(String),
    UnsupportedInputExtensions {
        port: PortName,
        keys: Vec<String>,
    },
    InputPayload {
        port: PortName,
        detail: String,
    },
    UnknownOutputPort(String),
    DuplicateOutputPort(PortName),
    MissingOutputs(Vec<PortName>),
    OutputPayload {
        port: PortName,
        detail: String,
    },
    OutputFact {
        port: PortName,
        detail: String,
    },
    FailureDetail(String),
    Implementation(String),
    InvocationJson(String),
    ResultJson(String),
    Io(String),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSpecification(detail) => {
                write!(formatter, "invalid capability specification: {detail}")
            }
            Self::InvalidImplementation(implementation) => {
                write!(
                    formatter,
                    "invalid implementation identity `{implementation}`"
                )
            }
            Self::Protocol(error) => write!(formatter, "invalid neutral protocol: {error}"),
            Self::SpecificationMismatch {
                expected,
                actual,
                expected_digest,
                actual_digest,
            } => write!(
                formatter,
                "invocation specification `{actual}` ({actual_digest}) does not match provider contract `{expected}` ({expected_digest})"
            ),
            Self::ImplementationMismatch { expected, actual } => write!(
                formatter,
                "invocation implementation `{actual}` does not match provider `{expected}`"
            ),
            Self::UnknownInputPort(port) => write!(formatter, "unknown input port `{port}`"),
            Self::UnsupportedInputExtensions { port, keys } => write!(
                formatter,
                "input `{port}` has unhandled semantic extensions: {}",
                keys.join(", ")
            ),
            Self::InputPayload { port, detail } => {
                write!(
                    formatter,
                    "input `{port}` payload cannot be decoded: {detail}"
                )
            }
            Self::UnknownOutputPort(port) => write!(formatter, "unknown output port `{port}`"),
            Self::DuplicateOutputPort(port) => {
                write!(formatter, "output `{port}` was supplied more than once")
            }
            Self::MissingOutputs(ports) => write!(
                formatter,
                "missing declared outputs: {}",
                ports
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::OutputPayload { port, detail } => {
                write!(formatter, "output `{port}` cannot be serialized: {detail}")
            }
            Self::OutputFact { port, detail } => {
                write!(formatter, "output `{port}` is not a valid fact: {detail}")
            }
            Self::FailureDetail(detail) => {
                write!(formatter, "inability detail cannot be serialized: {detail}")
            }
            Self::Implementation(detail) => {
                write!(formatter, "provider implementation failed: {detail}")
            }
            Self::InvocationJson(detail) => {
                write!(formatter, "invocation JSON cannot be decoded: {detail}")
            }
            Self::ResultJson(detail) => {
                write!(formatter, "result JSON cannot be encoded: {detail}")
            }
            Self::Io(detail) => write!(formatter, "provider stdio failed: {detail}"),
        }
    }
}

impl Error for ProviderError {}

impl ProviderError {
    /// Converts a transformation failure into a non-semantic provider failure.
    ///
    /// Use [`Context::unable`] instead when inability to produce the requested
    /// value is itself a declared semantic outcome.
    pub fn implementation(error: impl fmt::Display) -> Self {
        Self::Implementation(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeMap;

    use gooir_capability::protocol::{
        AdmittedFactRef, ArtifactDigest, AuthorityRecordId, CapabilityInvocation, CapabilityOffer,
        CapabilityOutcome, CapabilityResult, ConformanceSuiteId, FailureKindId, ImplementationId,
        ImplementationSelection, LinkedInput,
    };
    use gooir_capability::{
        CapabilityId, CapabilitySpec, Fact, InputPort, OutputPort, PortName, ValueKindId,
    };
    use serde_json::json;

    use super::{Provider, ProviderError};

    fn port(name: &str) -> PortName {
        PortName::parse(name).expect("test port is valid")
    }

    fn number_kind() -> ValueKindId {
        ValueKindId::new("org.example.math", "number", "1.0.0")
    }

    fn result_kind(name: &str) -> ValueKindId {
        ValueKindId::new("org.example.math", name, "1.0.0")
    }

    fn specification() -> CapabilitySpec {
        CapabilitySpec {
            id: CapabilityId::new("org.example.math", "combine", "1.0.0"),
            input_ports: vec![
                InputPort::complete(port("left"), number_kind()),
                InputPort::complete(port("right"), number_kind()),
            ],
            output_ports: vec![
                OutputPort::new(port("sum"), result_kind("sum")),
                OutputPort::new(port("product"), result_kind("product")),
            ],
            default_conformance_suite: "org.example.suite/math@1.0.0".to_owned(),
            extensions: BTreeMap::new(),
        }
    }

    fn implementation(name: &str) -> ImplementationId {
        ImplementationId::new("org.example.implementation", name, "1.0.0")
    }

    fn provider() -> Provider {
        Provider::new(specification(), implementation("combine_rust"))
            .expect("test provider is valid")
    }

    fn fallible_lowering() -> Result<u64, &'static str> {
        Err("lowering backend rejected the source")
    }

    fn artifact() -> ArtifactDigest {
        ArtifactDigest::parse(format!("sha256:{}", "11".repeat(32))).expect("test digest is valid")
    }

    fn offer(provider: &Provider) -> CapabilityOffer {
        let mut extensions = BTreeMap::new();
        extensions.insert("org.example.package.variant".to_owned(), json!("release"));
        CapabilityOffer::new(
            provider.implementation().clone(),
            artifact(),
            provider.specification().id.clone(),
            extensions,
        )
        .expect("test package offer is valid")
    }

    fn authority(byte: &str) -> AuthorityRecordId {
        AuthorityRecordId::parse(format!("sha256:{}", byte.repeat(32)))
            .expect("test authority is valid")
    }

    fn input(name: &str, fact: Fact, authority_byte: &str) -> LinkedInput {
        let admitted =
            AdmittedFactRef::new(fact.id.clone(), authority(authority_byte), BTreeMap::new())
                .expect("test admission reference is valid");
        LinkedInput::new(port(name), admitted, fact, BTreeMap::new())
            .expect("test linked input is valid")
    }

    fn invocation_for(provider: &Provider, left: Fact, right: Fact) -> CapabilityInvocation {
        let selection = ImplementationSelection::new(offer(provider), BTreeMap::new())
            .expect("test selection is valid");
        CapabilityInvocation::new(
            provider.specification().clone(),
            selection,
            vec![input("left", left, "22"), input("right", right, "33")],
            ConformanceSuiteId::new("org.example.suite", "math", "1.0.0"),
            BTreeMap::new(),
        )
        .expect("test invocation is valid")
    }

    fn invocation(provider: &Provider) -> CapabilityInvocation {
        invocation_for(
            provider,
            Fact::new(number_kind(), json!(6)).expect("test fact is valid"),
            Fact::new(number_kind(), json!(7)).expect("test fact is valid"),
        )
    }

    #[test]
    fn a_multi_input_multi_output_provider_is_one_typed_function() {
        let provider = provider();
        let invocation = invocation(&provider);

        let result = provider
            .invoke(&invocation, |context| {
                let left: u64 = context.input("left")?;
                let right: u64 = context.input("right")?;
                context
                    .produced()
                    // Authoring order is deliberately different from the contract.
                    .output("product", left * right)?
                    .output("sum", left + right)?
                    .finish()
            })
            .expect("provider invocation succeeds");

        assert_eq!(
            invocation.selection.offer.extensions["org.example.package.variant"],
            json!("release")
        );

        let CapabilityOutcome::Produced { outputs, .. } = result.outcome else {
            panic!("provider should produce outputs");
        };
        assert_eq!(
            outputs
                .iter()
                .map(|output| output.port.as_str())
                .collect::<Vec<_>>(),
            vec!["sum", "product"]
        );
        assert_eq!(outputs[0].fact.payload, json!(13));
        assert_eq!(outputs[1].fact.payload, json!(42));
    }

    #[test]
    fn every_declared_output_is_required() {
        let provider = provider();
        let invocation = invocation(&provider);

        let error = provider
            .invoke(&invocation, |context| {
                context.produced().output("sum", 13)?.finish()
            })
            .expect_err("missing output must be refused");

        assert!(matches!(
            error,
            ProviderError::MissingOutputs(ports) if ports == vec![port("product")]
        ));
    }

    #[test]
    fn unknown_and_duplicate_outputs_are_refused() {
        let provider = provider();
        let invocation = invocation(&provider);

        let unknown = provider
            .invoke(&invocation, |context| {
                context.produced().output("difference", 1)?.finish()
            })
            .expect_err("unknown output must be refused");
        assert!(matches!(unknown, ProviderError::UnknownOutputPort(port) if port == "difference"));

        let duplicate = provider
            .invoke(&invocation, |context| {
                context
                    .produced()
                    .output("sum", 13)?
                    .output("sum", 14)?
                    .finish()
            })
            .expect_err("duplicate output must be refused");
        assert!(matches!(
            duplicate,
            ProviderError::DuplicateOutputPort(found) if found == port("sum")
        ));
    }

    #[test]
    fn simple_input_decoding_refuses_unhandled_semantic_extensions() {
        let provider = provider();
        let mut extensions = BTreeMap::new();
        extensions.insert("org.example.precision".to_owned(), json!("exact"));
        let left = Fact::with_extensions(number_kind(), json!(6), extensions)
            .expect("extended test fact is valid");
        let right = Fact::new(number_kind(), json!(7)).expect("test fact is valid");
        let invocation = invocation_for(&provider, left, right);

        let error = provider
            .invoke(&invocation, |context| {
                let _: u64 = context.input("left")?;
                unreachable!("unhandled extensions must stop the handler")
            })
            .expect_err("extensions must not disappear during typed decoding");

        assert!(matches!(
            error,
            ProviderError::UnsupportedInputExtensions { port: found, keys }
                if found == port("left") && keys == vec!["org.example.precision"]
        ));
    }

    #[test]
    fn extension_aware_input_exposes_the_complete_envelope() {
        let provider = provider();
        let mut extensions = BTreeMap::new();
        extensions.insert("org.example.precision".to_owned(), json!("exact"));
        let left = Fact::with_extensions(number_kind(), json!(6), extensions)
            .expect("extended test fact is valid");
        let right = Fact::new(number_kind(), json!(7)).expect("test fact is valid");
        let invocation = invocation_for(&provider, left, right);

        let result = provider
            .invoke(&invocation, |context| {
                let left = context.input_with_extensions::<u64>("left")?;
                assert_eq!(left.value, 6);
                assert_eq!(
                    left.fact.extensions["org.example.precision"],
                    json!("exact")
                );
                assert_eq!(left.admitted.fact_id, left.fact.id);
                assert!(left.link_extensions.is_empty());
                context
                    .produced()
                    .output("sum", 13)?
                    .output("product", 42)?
                    .finish()
            })
            .expect("extension-aware provider succeeds");

        assert!(result.is_produced());
    }

    #[test]
    fn inability_is_distinct_from_provider_failure() {
        let provider = provider();
        let invocation = invocation(&provider);
        let kind = FailureKindId::new("org.example.failure", "overflow", "1.0.0");

        let result = provider
            .invoke(&invocation, |context| {
                context.unable(kind.clone(), json!({ "bits": 8 }))
            })
            .expect("inability is a valid provider result");

        let CapabilityOutcome::Unable { failure, .. } = result.outcome else {
            panic!("provider should report inability");
        };
        assert_eq!(failure.kind, kind);
        assert_eq!(failure.detail, json!({ "bits": 8 }));
    }

    #[test]
    fn fallible_transformations_have_a_non_semantic_failure_channel() {
        let provider = provider();
        let invocation = invocation(&provider);

        let error = provider
            .invoke(&invocation, |context| {
                let _: u64 = context.input("left")?;
                let _: u64 = fallible_lowering().map_err(ProviderError::implementation)?;
                unreachable!("the transformation failed")
            })
            .expect_err("implementation failure must remain outside semantic inability");

        assert!(matches!(
            error,
            ProviderError::Implementation(detail)
                if detail == "lowering backend rejected the source"
        ));
    }

    #[test]
    fn exact_provider_binding_is_checked_before_the_handler_runs() {
        let provider = provider();
        let other = Provider::new(specification(), implementation("other_rust"))
            .expect("other provider is valid");
        let invocation = invocation(&other);
        let called = Cell::new(false);

        let error = provider
            .invoke(&invocation, |_| {
                called.set(true);
                unreachable!("mismatched implementation must not run")
            })
            .expect_err("mismatched implementation must be refused");

        assert!(matches!(
            error,
            ProviderError::ImplementationMismatch { .. }
        ));
        assert!(!called.get());
    }

    #[test]
    fn same_identity_contract_drift_reports_both_exact_digests() {
        let provider = provider();
        let mut changed = specification();
        changed.output_ports.swap(0, 1);
        let changed_provider = Provider::new(changed, provider.implementation().clone())
            .expect("changed provider declaration remains structurally valid");
        let invocation = invocation(&changed_provider);
        let called = Cell::new(false);

        let error = provider
            .invoke(&invocation, |_| {
                called.set(true);
                unreachable!("contract drift must not run")
            })
            .expect_err("same-ID contract drift must be refused");

        let ProviderError::SpecificationMismatch {
            expected,
            actual,
            expected_digest,
            actual_digest,
        } = error
        else {
            panic!("contract drift should retain exact specification identities")
        };
        assert_eq!(expected, actual);
        assert_ne!(expected_digest, actual_digest);
        assert!(!called.get());
    }

    #[test]
    fn explicit_extensions_survive_every_output_and_result_scope() {
        let provider = provider();
        let invocation = invocation(&provider);
        let fact_extensions = BTreeMap::from([("org.example.unit".to_owned(), json!("count"))]);
        let output_extensions =
            BTreeMap::from([("org.example.output.note".to_owned(), json!("derived"))]);
        let outcome_extensions =
            BTreeMap::from([("org.example.outcome.mode".to_owned(), json!("exact"))]);
        let result_extensions =
            BTreeMap::from([("org.example.result.trace".to_owned(), json!("local"))]);

        let result = provider
            .invoke(&invocation, |context| {
                Ok(context
                    .produced()
                    .output_with_extensions(
                        "sum",
                        13,
                        fact_extensions.clone(),
                        output_extensions.clone(),
                    )?
                    .output("product", 42)?
                    .finish()?
                    .with_outcome_extensions(outcome_extensions.clone())
                    .with_result_extensions(result_extensions.clone()))
            })
            .expect("explicit extensions produce an exact result");

        let CapabilityOutcome::Produced {
            outputs,
            extensions,
        } = result.outcome
        else {
            panic!("provider should produce outputs")
        };
        assert_eq!(outputs[0].fact.extensions, fact_extensions);
        assert_eq!(outputs[0].extensions, output_extensions);
        assert_eq!(extensions, outcome_extensions);
        assert_eq!(result.extensions, result_extensions);
    }

    #[test]
    fn reserved_extensions_are_still_refused_by_protocol_construction() {
        let provider = provider();
        let invocation = invocation(&provider);

        let error = provider
            .invoke(&invocation, |context| {
                Ok(context
                    .produced()
                    .output("sum", 13)?
                    .output("product", 42)?
                    .finish()?
                    .with_outcome_extensions(BTreeMap::from([(
                        "outputs".to_owned(),
                        json!("shadow"),
                    )])))
            })
            .expect_err("reserved output extension must be refused");

        assert!(matches!(error, ProviderError::Protocol(_)));
    }

    #[test]
    fn json_framing_round_trips_the_neutral_documents() {
        let provider = provider();
        let invocation = invocation(&provider);
        let input = serde_json::to_string(&invocation).expect("invocation encodes");

        let output = provider
            .invoke_json(&input, |context| {
                let left: u64 = context.input("left")?;
                let right: u64 = context.input("right")?;
                context
                    .produced()
                    .output("sum", left + right)?
                    .output("product", left * right)?
                    .finish()
            })
            .expect("JSON invocation succeeds");
        let result: CapabilityResult = serde_json::from_str(&output).expect("result decodes");

        result
            .validate_against(&invocation)
            .expect("framed result remains exact");
    }

    #[test]
    fn stream_framing_writes_one_exact_result_document() {
        let provider = provider();
        let invocation = invocation(&provider);
        let input = serde_json::to_vec(&invocation).expect("invocation encodes");
        let mut output = Vec::new();

        provider
            .serve_once(input.as_slice(), &mut output, |context| {
                let left: u64 = context.input("left")?;
                let right: u64 = context.input("right")?;
                context
                    .produced()
                    .output("sum", left + right)?
                    .output("product", left * right)?
                    .finish()
            })
            .expect("stream invocation succeeds");
        let result: CapabilityResult =
            serde_json::from_slice(&output).expect("stream result decodes");

        result
            .validate_against(&invocation)
            .expect("stream result remains exact");
    }
}
