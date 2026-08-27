//! Neutral, credential-free provider boundary for authored data models.
//!
//! The provider validates one complete semantic invocation and performs only
//! the transformation declared by the author-data-model contract. An external
//! execution host must resolve every admitted input reference, verify the
//! selected artifact, and manage process lifecycle before calling this module.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use gooir_author_data_model_contract::{
    AuthoredSpec, author_data_model_capability_id, author_data_model_spec,
};
use gooir_capability::protocol::{
    ArtifactDigest, CapabilityFailure, CapabilityInvocation, CapabilityOffer, CapabilityResult,
    FailureKindId, ImplementationId, NamedOutput, ProtocolError,
};
use gooir_capability::{CapabilitySpec, Fact};
use serde_json::json;

/// Exact semantic identity of this entity-spec implementation.
pub fn implementation_id() -> ImplementationId {
    ImplementationId::new("org.gooi.implementation", "entity_spec_rust", "1.1.0")
}

/// Exact inability emitted when the mature parser cannot establish a complete
/// data model from a structurally valid [`AuthoredSpec`].
pub fn unparsable_source_failure_kind() -> FailureKindId {
    FailureKindId::new("org.gooi.failure", "entity_spec_unparsable", "1.0.0")
}

/// Returns the complete implementation-independent authoring promise.
///
/// The provider consumes the separately governed contract directly. It does
/// not recover its meaning from the legacy lowering pack.
#[must_use]
pub fn capability_spec() -> CapabilitySpec {
    author_data_model_spec()
}

/// Constructs one availability offer from a host-measured artifact digest.
///
/// This does not select the offer or claim that the supplied digest matches a
/// running process. The credential-owning host must make and verify that
/// binding before launch.
pub fn capability_offer(
    artifact_digest: ArtifactDigest,
) -> Result<CapabilityOffer, NeutralProviderError> {
    CapabilityOffer::new(
        implementation_id(),
        artifact_digest,
        author_data_model_capability_id(),
        BTreeMap::new(),
    )
    .map_err(NeutralProviderError::Protocol)
}

/// Validates and evaluates one complete neutral invocation.
///
/// Structural validation does not resolve the invocation's authority-record
/// reference. The external host must resolve it against its contextual
/// admission ledger and compare the resolved fact before launching this child.
pub fn invoke(invocation: &CapabilityInvocation) -> Result<CapabilityResult, NeutralProviderError> {
    invocation
        .validate()
        .map_err(NeutralProviderError::Protocol)?;

    let expected = capability_spec();
    if invocation.specification != expected {
        return Err(NeutralProviderError::SpecificationMismatch);
    }
    let selected = &invocation.selection.offer;
    let expected_implementation = implementation_id();
    if selected.implementation != expected_implementation {
        return Err(NeutralProviderError::ImplementationMismatch {
            expected: Box::new(expected_implementation),
            actual: Box::new(selected.implementation.clone()),
        });
    }

    let [source] = invocation.inputs.as_slice() else {
        return Err(NeutralProviderError::UnsupportedDeclarationShape);
    };
    if !source.fact.extensions.is_empty() {
        return Err(NeutralProviderError::UnsupportedSourceFactExtensions(
            source.fact.extensions.keys().cloned().collect(),
        ));
    }
    let authored: AuthoredSpec = serde_json::from_value(source.fact.payload.clone())
        .map_err(|error| NeutralProviderError::AuthoredSpecPayload(error.to_string()))?;
    let parsed = entity_spec::parse_entity_spec(&authored.text);

    if !parsed.is_exhaustive() {
        let failure = CapabilityFailure::new(
            unparsable_source_failure_kind(),
            json!({
                "defeater_set": parsed.defeater_set,
                "defeats": parsed.defeats,
            }),
            BTreeMap::new(),
        )
        .map_err(NeutralProviderError::Protocol)?;
        return CapabilityResult::unable(
            invocation,
            failure,
            BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
        )
        .map_err(NeutralProviderError::Protocol);
    }

    let [output] = expected.output_ports.as_slice() else {
        return Err(NeutralProviderError::UnsupportedDeclarationShape);
    };
    let payload = serde_json::to_value(parsed)
        .map_err(|error| NeutralProviderError::Serialization(error.to_string()))?;
    let fact = Fact::new(output.value_kind.clone(), payload)
        .map_err(|error| NeutralProviderError::Fact(error.to_string()))?;
    let named = NamedOutput::new(output.name.clone(), fact, BTreeMap::new())
        .map_err(NeutralProviderError::Protocol)?;
    CapabilityResult::produced(
        invocation,
        vec![named],
        BTreeMap::new(),
        Vec::new(),
        BTreeMap::new(),
    )
    .map_err(NeutralProviderError::Protocol)
}

/// Parses one complete invocation document and returns one complete result
/// document. This is the complete JSON boundary used by the thin executable.
pub fn invoke_json(input: &str) -> Result<String, NeutralProviderError> {
    let invocation: CapabilityInvocation = serde_json::from_str(input)
        .map_err(|error| NeutralProviderError::InvocationJson(error.to_string()))?;
    let result = invoke(&invocation)?;
    serde_json::to_string(&result)
        .map_err(|error| NeutralProviderError::Serialization(error.to_string()))
}

/// A failure to validate or evaluate the provider's exact semantic boundary.
#[derive(Debug)]
pub enum NeutralProviderError {
    UnsupportedDeclarationShape,
    Protocol(ProtocolError),
    SpecificationMismatch,
    ImplementationMismatch {
        expected: Box<ImplementationId>,
        actual: Box<ImplementationId>,
    },
    UnsupportedSourceFactExtensions(Vec<String>),
    AuthoredSpecPayload(String),
    InvocationJson(String),
    Fact(String),
    Serialization(String),
}

impl fmt::Display for NeutralProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedDeclarationShape => formatter.write_str(
                "author-data-model contract is not the supported one-input, one-output transformation",
            ),
            Self::Protocol(error) => {
                write!(formatter, "invalid capability protocol document: {error}")
            }
            Self::SpecificationMismatch => formatter
                .write_str("invocation specification differs from the author-data-model contract"),
            Self::ImplementationMismatch { expected, actual } => write!(
                formatter,
                "invocation selected implementation {actual}, expected {expected}"
            ),
            Self::UnsupportedSourceFactExtensions(keys) => write!(
                formatter,
                "authored-spec fact carries unsupported semantic extensions: {}",
                keys.join(", ")
            ),
            Self::AuthoredSpecPayload(error) => {
                write!(formatter, "authored-spec fact payload is invalid: {error}")
            }
            Self::InvocationJson(error) => {
                write!(formatter, "invocation JSON is invalid: {error}")
            }
            Self::Fact(error) => write!(formatter, "could not construct output fact: {error}"),
            Self::Serialization(error) => write!(formatter, "JSON serialization failed: {error}"),
        }
    }
}

impl Error for NeutralProviderError {}

#[cfg(test)]
mod tests {
    use super::*;

    use gooir_capability::protocol::{
        AdmittedFactRef, AuthorityRecordId, CapabilityOutcome, ImplementationSelection, LinkedInput,
    };
    use gooir_capability::{FactAcceptance, PortName, ValueKindId};
    use serde_json::{Value, json};

    const SPEC: &str = r#"
entity User
  id uuid pk = uuid
  email text unique
"#;

    fn digest(byte: char) -> ArtifactDigest {
        ArtifactDigest::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn authority(byte: char) -> AuthorityRecordId {
        AuthorityRecordId::parse(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn authored_source(payload: Value) -> Fact {
        Fact::new(
            gooir_author_data_model_contract::authored_entity_spec_value_kind(),
            payload,
        )
        .unwrap()
    }

    fn invocation_with(
        specification: CapabilitySpec,
        offer: CapabilityOffer,
        fact: Fact,
    ) -> Result<CapabilityInvocation, ProtocolError> {
        let admitted = AdmittedFactRef::new(fact.id.clone(), authority('a'), BTreeMap::new())?;
        let input = LinkedInput::new(
            PortName::parse("source").unwrap(),
            admitted,
            fact,
            BTreeMap::new(),
        )?;
        CapabilityInvocation::new(
            specification,
            ImplementationSelection::new(offer, BTreeMap::new())?,
            vec![input],
            gooir_author_data_model_contract::author_data_model_suite_id(),
            BTreeMap::new(),
        )
    }

    fn valid_invocation() -> CapabilityInvocation {
        let payload = serde_json::to_value(AuthoredSpec {
            origin: "gooir://examples/tasks.entities@test".to_owned(),
            text: SPEC.to_owned(),
        })
        .unwrap();
        invocation_with(
            capability_spec(),
            capability_offer(digest('1')).unwrap(),
            authored_source(payload),
        )
        .unwrap()
    }

    #[test]
    fn provider_uses_the_complete_external_contract() {
        let spec = capability_spec();
        assert_eq!(spec.id, author_data_model_capability_id());
        assert_eq!(spec, author_data_model_spec());
        assert_eq!(spec.input_ports.len(), 1);
        assert_eq!(spec.input_ports[0].name.as_str(), "source");
        assert_eq!(spec.input_ports[0].acceptance, FactAcceptance::CompleteOnly);
        assert_eq!(spec.output_ports.len(), 1);
        assert_eq!(spec.output_ports[0].name.as_str(), "model");
    }

    #[test]
    fn offer_uses_only_the_explicit_artifact_digest() {
        let first = capability_offer(digest('1')).unwrap();
        let second = capability_offer(digest('2')).unwrap();
        assert_eq!(first.implementation, implementation_id());
        assert_eq!(first.capability, author_data_model_capability_id());
        assert_eq!(first.artifact_digest, digest('1'));
        assert_ne!(first.offer_id, second.offer_id);
    }

    #[test]
    fn exact_produced_output_is_deterministic() {
        let invocation = valid_invocation();
        let first = invoke(&invocation).unwrap();
        let replay = invoke(&invocation).unwrap();
        assert_eq!(first, replay);
        first.validate_against(&invocation).unwrap();

        let CapabilityOutcome::Produced { outputs, .. } = &first.outcome else {
            panic!("valid entity spec must produce a model");
        };
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].port.as_str(), "model");
        assert_eq!(outputs[0].fact.value_kind, crate::data_model_fact());
        let model: lift_defeasible::Defeasible<semantics_data_model_v1::DataModel> =
            serde_json::from_value(outputs[0].fact.payload.clone()).unwrap();
        assert!(model.is_exhaustive());
        assert_eq!(model.value.entities.len(), 1);
    }

    #[test]
    fn domain_parse_failure_is_a_typed_unable_result() {
        let fact = authored_source(
            serde_json::to_value(AuthoredSpec {
                origin: "test".to_owned(),
                text: "field_before_entity text".to_owned(),
            })
            .unwrap(),
        );
        let invocation = invocation_with(
            capability_spec(),
            capability_offer(digest('1')).unwrap(),
            fact,
        )
        .unwrap();
        let result = invoke(&invocation).unwrap();
        result.validate_against(&invocation).unwrap();
        let CapabilityOutcome::Unable { failure, .. } = result.outcome else {
            panic!("unparsable text must not publish partial output");
        };
        assert_eq!(failure.kind, unparsable_source_failure_kind());
        assert!(!failure.detail["defeats"].as_array().unwrap().is_empty());
    }

    #[test]
    fn every_different_specification_scope_is_rejected() {
        let declared = capability_spec();
        let mut capability_extension = declared.clone();
        capability_extension
            .extensions
            .insert("example.semantic/revision".to_owned(), json!(2));
        let mut input_extension = declared.clone();
        input_extension.input_ports[0]
            .extensions
            .insert("example.semantic/revision".to_owned(), json!(2));
        let mut output_extension = declared.clone();
        output_extension.output_ports[0]
            .extensions
            .insert("example.semantic/revision".to_owned(), json!(2));
        let mut conformance = declared;
        conformance.default_conformance_suite = "example.conformance/other@1.0.0".to_owned();

        for specification in [
            capability_extension,
            input_extension,
            output_extension,
            conformance,
        ] {
            let invocation = invocation_with(
                specification,
                capability_offer(digest('1')).unwrap(),
                authored_source(
                    serde_json::to_value(AuthoredSpec {
                        origin: "test".to_owned(),
                        text: SPEC.to_owned(),
                    })
                    .unwrap(),
                ),
            )
            .unwrap();
            assert!(matches!(
                invoke(&invocation),
                Err(NeutralProviderError::SpecificationMismatch)
            ));
        }
    }

    #[test]
    fn a_different_selected_implementation_is_rejected() {
        let offer = CapabilityOffer::new(
            ImplementationId::new("example.implementation", "other", "1.0.0"),
            digest('1'),
            author_data_model_capability_id(),
            BTreeMap::new(),
        )
        .unwrap();
        let invocation = invocation_with(
            capability_spec(),
            offer,
            authored_source(
                serde_json::to_value(AuthoredSpec {
                    origin: "test".to_owned(),
                    text: SPEC.to_owned(),
                })
                .unwrap(),
            ),
        )
        .unwrap();
        assert!(matches!(
            invoke(&invocation),
            Err(NeutralProviderError::ImplementationMismatch { .. })
        ));
    }

    #[test]
    fn a_different_offered_capability_fails_before_provider_evaluation() {
        let offer = CapabilityOffer::new(
            implementation_id(),
            digest('1'),
            gooir_capability::CapabilityId::new("example.capability", "other", "1.0.0"),
            BTreeMap::new(),
        )
        .unwrap();
        let fact = authored_source(
            serde_json::to_value(AuthoredSpec {
                origin: "test".to_owned(),
                text: SPEC.to_owned(),
            })
            .unwrap(),
        );
        assert!(matches!(
            invocation_with(capability_spec(), offer, fact),
            Err(ProtocolError::OfferCapabilityMismatch { .. })
        ));
    }

    #[test]
    fn a_different_port_declaration_is_rejected() {
        let mut spec = capability_spec();
        spec.input_ports[0].name = PortName::parse("document").unwrap();
        let fact = authored_source(
            serde_json::to_value(AuthoredSpec {
                origin: "test".to_owned(),
                text: SPEC.to_owned(),
            })
            .unwrap(),
        );
        let admitted =
            AdmittedFactRef::new(fact.id.clone(), authority('a'), BTreeMap::new()).unwrap();
        let input = LinkedInput::new(
            PortName::parse("document").unwrap(),
            admitted,
            fact,
            BTreeMap::new(),
        )
        .unwrap();
        let invocation = CapabilityInvocation::new(
            spec,
            ImplementationSelection::new(capability_offer(digest('1')).unwrap(), BTreeMap::new())
                .unwrap(),
            vec![input],
            gooir_author_data_model_contract::author_data_model_suite_id(),
            BTreeMap::new(),
        )
        .unwrap();
        assert!(matches!(
            invoke(&invocation),
            Err(NeutralProviderError::SpecificationMismatch)
        ));
    }

    #[test]
    fn wrong_input_kind_fails_before_provider_evaluation() {
        let fact = Fact::new(
            ValueKindId::new("example.source", "wrong", "1.0.0"),
            serde_json::to_value(AuthoredSpec {
                origin: "test".to_owned(),
                text: SPEC.to_owned(),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(
            invocation_with(
                capability_spec(),
                capability_offer(digest('1')).unwrap(),
                fact,
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_or_unknown_authored_payload_is_rejected() {
        for payload in [
            json!({"origin": "test"}),
            json!({"origin": "test", "text": SPEC, "credential": "must-not-be-ignored"}),
        ] {
            let invocation = invocation_with(
                capability_spec(),
                capability_offer(digest('1')).unwrap(),
                authored_source(payload),
            )
            .unwrap();
            assert!(matches!(
                invoke(&invocation),
                Err(NeutralProviderError::AuthoredSpecPayload(_))
            ));
        }
    }

    #[test]
    fn unknown_semantic_source_fact_extensions_are_not_ignored() {
        let mut extensions = BTreeMap::new();
        extensions.insert("example.semantic/meaning".to_owned(), json!("different"));
        let fact = Fact::with_extensions(
            gooir_author_data_model_contract::authored_entity_spec_value_kind(),
            serde_json::to_value(AuthoredSpec {
                origin: "test".to_owned(),
                text: SPEC.to_owned(),
            })
            .unwrap(),
            extensions,
        )
        .unwrap();
        let invocation = invocation_with(
            capability_spec(),
            capability_offer(digest('1')).unwrap(),
            fact,
        )
        .unwrap();
        assert!(matches!(
            invoke(&invocation),
            Err(NeutralProviderError::UnsupportedSourceFactExtensions(_))
        ));
    }

    #[test]
    fn malformed_invocation_json_is_rejected() {
        assert!(matches!(
            invoke_json(r#"{"protocol":"org.gooi.capability.invocation/v1"}"#),
            Err(NeutralProviderError::InvocationJson(_))
        ));
    }

    #[test]
    fn tampered_invocation_identity_is_revalidated() {
        let invocation = valid_invocation();
        let mut wire = serde_json::to_value(&invocation).unwrap();
        wire["invocation_id"] = json!(format!("sha256:{}", "f".repeat(64)));
        let wire = serde_json::to_string(&wire).unwrap();
        assert!(matches!(
            invoke_json(&wire),
            Err(NeutralProviderError::Protocol(
                ProtocolError::ContentIdentityMismatch { .. }
            ))
        ));
    }

    #[test]
    fn provider_documents_have_no_execution_host_fields() {
        const FORBIDDEN: [&str; 14] = [
            "host",
            "process",
            "command",
            "transport",
            "lease",
            "session",
            "retry",
            "credential",
            "attempt",
            "fleetd",
            "priority",
            "provider",
            "deadline",
            "owner",
        ];
        let invocation = valid_invocation();
        let result = invoke(&invocation).unwrap();
        for document in [
            serde_json::to_value(capability_offer(digest('1')).unwrap()).unwrap(),
            serde_json::to_value(invocation).unwrap(),
            serde_json::to_value(result).unwrap(),
        ] {
            assert_no_forbidden_keys(&document, &FORBIDDEN);
        }
    }

    fn assert_no_forbidden_keys(value: &Value, forbidden: &[&str]) {
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    assert!(
                        !forbidden.contains(&key.as_str()),
                        "provider document leaked execution-host field `{key}`"
                    );
                    assert_no_forbidden_keys(child, forbidden);
                }
            }
            Value::Array(values) => {
                for child in values {
                    assert_no_forbidden_keys(child, forbidden);
                }
            }
            _ => {}
        }
    }
}
