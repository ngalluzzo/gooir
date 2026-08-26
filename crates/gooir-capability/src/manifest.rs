//! Declaring a capability graph as data.
//!
//! A capability is a promise about types: what it requires, what it produces,
//! and which suite a provider must eventually pass. None of that is code, and
//! writing it as Rust struct literals meant a graph could only be declared by
//! someone compiling this workspace.
//!
//! Fact types are *not* listed separately. They are exactly the identities the
//! capabilities mention, so a separate list could only agree or drift.
//!
//! Provider implementations stay code, because they are code. What binds an
//! out-of-process one to a capability is its own manifest — see
//! `gooir-plugin-process`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    CapabilityId, CapabilityPack, CapabilityRegistry, CapabilitySpec, FactAcceptance, FactType,
    InputPort, OutputPort, PortName, RegistryError, validate_extension_keys, validate_spec,
};

/// The manifest contract version. Exact, like every other identity here.
pub const PACK_PROTOCOL: &str = "org.gooi.pack/v2";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ManifestInputPort {
    pub name: String,
    /// A value-kind identity in display form, `package/name@version`.
    pub value_kind: String,
    pub acceptance: FactAcceptance,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ManifestOutputPort {
    pub name: String,
    /// A value-kind identity in display form, `package/name@version`.
    pub value_kind: String,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ManifestCapability {
    pub id: String,
    #[serde(default)]
    pub input_ports: Vec<ManifestInputPort>,
    pub output_ports: Vec<ManifestOutputPort>,
    pub default_conformance_suite: String,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PackManifest {
    pub protocol: String,
    pub capabilities: Vec<ManifestCapability>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackManifestError {
    Parse(String),
    ProtocolMismatch { expected: String, actual: String },
    Identity { capability: String, detail: String },
    ReservedExtension { scope: String, key: String },
    Serialization(String),
    Registry(RegistryError),
}

impl std::fmt::Display for PackManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(m) => write!(f, "pack manifest is not valid: {m}"),
            Self::ProtocolMismatch { expected, actual } => {
                write!(f, "pack declares protocol {actual}, expected {expected}")
            }
            Self::Identity { capability, detail } => {
                write!(f, "in capability `{capability}`: {detail}")
            }
            Self::ReservedExtension { scope, key } => {
                write!(f, "{scope} extension `{key}` shadows a known field")
            }
            Self::Serialization(error) => write!(f, "pack serialization failed: {error}"),
            Self::Registry(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PackManifestError {}

/// Reads a manifest into a semantic pack, without registering its capabilities.
pub fn read_pack(json: &str) -> Result<CapabilityPack, PackManifestError> {
    #[derive(Deserialize)]
    struct Header {
        protocol: String,
    }
    let header: Header =
        serde_json::from_str(json).map_err(|e| PackManifestError::Parse(e.to_string()))?;
    if header.protocol != PACK_PROTOCOL {
        return Err(PackManifestError::ProtocolMismatch {
            expected: PACK_PROTOCOL.to_owned(),
            actual: header.protocol,
        });
    }
    let manifest: PackManifest =
        serde_json::from_str(json).map_err(|e| PackManifestError::Parse(e.to_string()))?;

    let mut specs = Vec::with_capacity(manifest.capabilities.len());
    for declared in manifest.capabilities {
        let fail = |detail: String| PackManifestError::Identity {
            capability: declared.id.clone(),
            detail,
        };
        let id = CapabilityId::parse(&declared.id).map_err(|e| fail(e.to_string()))?;
        let mut input_ports = Vec::with_capacity(declared.input_ports.len());
        for port in &declared.input_ports {
            input_ports.push(InputPort {
                name: PortName::parse(&port.name).map_err(|e| fail(e.to_string()))?,
                value_kind: FactType::parse(&port.value_kind).map_err(|e| fail(e.to_string()))?,
                acceptance: port.acceptance,
                extensions: port.extensions.clone(),
            });
        }
        let mut output_ports = Vec::with_capacity(declared.output_ports.len());
        for port in &declared.output_ports {
            output_ports.push(OutputPort {
                name: PortName::parse(&port.name).map_err(|e| fail(e.to_string()))?,
                value_kind: FactType::parse(&port.value_kind).map_err(|e| fail(e.to_string()))?,
                extensions: port.extensions.clone(),
            });
        }
        specs.push(CapabilitySpec {
            id,
            input_ports,
            output_ports,
            default_conformance_suite: declared.default_conformance_suite,
            extensions: declared.extensions,
        });
    }
    Ok(CapabilityPack {
        capabilities: specs,
        extensions: manifest.extensions,
    })
}

/// Renders a semantic pack to validated protocol-v2 JSON.
///
/// Returning bytes rather than a mutable wire DTO keeps reserved-field
/// validation on every public serialization path.
pub fn write_pack(pack: &CapabilityPack) -> Result<String, PackManifestError> {
    if validate_extension_keys("pack root", &pack.extensions, &["protocol", "capabilities"])
        .is_err()
    {
        let key = ["protocol", "capabilities"]
            .into_iter()
            .find(|key| pack.extensions.contains_key(*key))
            .expect("reserved extension was found");
        return Err(PackManifestError::ReservedExtension {
            scope: "pack root".to_owned(),
            key: key.to_owned(),
        });
    }
    for spec in &pack.capabilities {
        validate_spec(spec).map_err(PackManifestError::Registry)?;
    }
    let manifest = PackManifest {
        protocol: PACK_PROTOCOL.to_owned(),
        capabilities: pack
            .capabilities
            .iter()
            .map(|spec| ManifestCapability {
                id: spec.id.to_string(),
                input_ports: spec
                    .input_ports
                    .iter()
                    .map(|port| ManifestInputPort {
                        name: port.name.to_string(),
                        value_kind: port.value_kind.to_string(),
                        acceptance: port.acceptance,
                        extensions: port.extensions.clone(),
                    })
                    .collect(),
                output_ports: spec
                    .output_ports
                    .iter()
                    .map(|port| ManifestOutputPort {
                        name: port.name.to_string(),
                        value_kind: port.value_kind.to_string(),
                        extensions: port.extensions.clone(),
                    })
                    .collect(),
                default_conformance_suite: spec.default_conformance_suite.clone(),
                extensions: spec.extensions.clone(),
            })
            .collect(),
        extensions: pack.extensions.clone(),
    };
    serde_json::to_string(&manifest)
        .map_err(|error| PackManifestError::Serialization(error.to_string()))
}

/// Reads a manifest and registers every capability it declares.
///
/// The registry validates each spec exactly as it would a hand-written one, so
/// a manifest cannot declare something the kernel would otherwise refuse.
pub fn register_pack(
    registry: &mut CapabilityRegistry,
    json: &str,
) -> Result<(), PackManifestError> {
    for spec in read_pack(json)?.capabilities {
        registry
            .register_spec(spec)
            .map_err(PackManifestError::Registry)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACK: &str = r#"{
      "protocol": "org.gooi.pack/v2",
      "capabilities": [
        {
          "id": "test.capability/make@1.0.0",
          "input_ports": [
            { "name": "source", "value_kind": "test.fact/source@1.0.0", "acceptance": "complete_only" }
          ],
          "output_ports": [
            { "name": "result", "value_kind": "test.fact/made@1.0.0" }
          ],
          "default_conformance_suite": "test.suite/make@1.0.0"
        }
      ]
    }"#;

    #[test]
    fn a_declared_graph_becomes_ordinary_specs() {
        let pack = read_pack(PACK).expect("manifest reads");
        let specs = &pack.capabilities;
        assert_eq!(specs.len(), 1);
        assert_eq!(
            specs[0].id,
            CapabilityId::new("test.capability", "make", "1.0.0")
        );
        assert_eq!(
            specs[0].input_ports[0].acceptance,
            FactAcceptance::CompleteOnly
        );
        assert_eq!(
            specs[0].output_ports[0].value_kind,
            FactType::new("test.fact", "made", "1.0.0")
        );
    }

    #[test]
    fn a_registered_manifest_plans_like_any_other_graph() {
        let mut registry = CapabilityRegistry::default();
        register_pack(&mut registry, PACK).expect("registers");
        let plan = registry
            .plan(
                [FactType::new("test.fact", "source", "1.0.0")],
                &FactType::new("test.fact", "made", "1.0.0"),
            )
            .expect("route exists");
        assert_eq!(plan.steps.len(), 1);
        assert!(
            !plan.has_provider_for_every_step(),
            "declared, but nobody implements it"
        );
        assert_eq!(plan.needs.len(), 1);
    }

    #[test]
    fn another_protocol_is_refused() {
        let other = PACK.replace("org.gooi.pack/v2", "org.gooi.pack/v99");
        assert!(matches!(
            read_pack(&other),
            Err(PackManifestError::ProtocolMismatch { .. })
        ));
    }

    #[test]
    fn v1_anonymous_shapes_fail_as_a_protocol_mismatch_before_schema_parsing() {
        let old = r#"{
          "protocol": "org.gooi.pack/v1",
          "capabilities": [{
            "id": "test.capability/make@1.0.0",
            "requires": [],
            "produces": ["test.fact/made@1.0.0"],
            "default_conformance_suite": "test.suite/make@1.0.0"
          }]
        }"#;
        assert!(matches!(
            read_pack(old),
            Err(PackManifestError::ProtocolMismatch { expected, actual })
                if expected == PACK_PROTOCOL && actual == "org.gooi.pack/v1"
        ));
    }

    #[test]
    fn a_malformed_identity_names_the_capability_it_broke() {
        let bad = PACK.replace("test.fact/made@1.0.0", "not-an-identity");
        let error = read_pack(&bad).expect_err("must refuse");
        let text = error.to_string();
        assert!(text.contains("test.capability/make@1.0.0"), "{text}");
        assert!(text.contains("not-an-identity"), "{text}");
    }

    #[test]
    fn the_registry_still_validates_what_a_manifest_declares() {
        // A capability that produces nothing is refused whether it was written
        // in Rust or in JSON.
        let empty = PACK.replace(
            r#""output_ports": [
            { "name": "result", "value_kind": "test.fact/made@1.0.0" }
          ]"#,
            r#""output_ports": []"#,
        );
        assert!(matches!(
            register_pack(&mut CapabilityRegistry::default(), &empty),
            Err(PackManifestError::Registry(_))
        ));
    }

    #[test]
    fn specs_survive_a_trip_out_to_data_and_back() {
        let pack = read_pack(PACK).unwrap();
        let exported = write_pack(&pack).unwrap();
        assert_eq!(read_pack(&exported).unwrap(), pack);
    }

    #[test]
    fn a_manifest_round_trips_through_serialisation() {
        let manifest: PackManifest = serde_json::from_str(PACK).unwrap();
        let encoded = serde_json::to_string(&manifest).unwrap();
        assert_eq!(read_pack(&encoded).unwrap(), read_pack(PACK).unwrap());
    }

    #[test]
    fn repeated_kinds_and_exact_port_spelling_survive_manifest_round_trip() {
        let repeated = PACK.replace(
            r#"{ "name": "source", "value_kind": "test.fact/source@1.0.0", "acceptance": "complete_only" }"#,
            r#"{ "name": "输入.Left-v1", "value_kind": "test.fact/source@1.0.0", "acceptance": "complete_only" },
            { "name": "输入.Right-v1", "value_kind": "test.fact/source@1.0.0", "acceptance": "complete_only" }"#,
        ).replace(
            r#"{ "name": "result", "value_kind": "test.fact/made@1.0.0" }"#,
            r#"{ "name": "Primary.Result", "value_kind": "test.fact/made@1.0.0" },
            { "name": "Secondary.Result", "value_kind": "test.fact/made@1.0.0" }"#,
        );
        let pack = read_pack(&repeated).unwrap();
        let specs = &pack.capabilities;
        register_pack(&mut CapabilityRegistry::default(), &repeated).unwrap();
        assert_eq!(specs[0].input_ports[0].name.as_str(), "输入.Left-v1");
        assert_eq!(
            specs[0].input_ports[0].value_kind,
            specs[0].input_ports[1].value_kind
        );
        assert_eq!(
            specs[0].output_ports[0].value_kind,
            specs[0].output_ports[1].value_kind
        );
        let encoded = write_pack(&pack).unwrap();
        assert_eq!(read_pack(&encoded).unwrap(), pack);
    }

    #[test]
    fn malformed_and_duplicate_port_names_are_rejected() {
        let blank = PACK.replace(r#""name": "source""#, r#""name": " ""#);
        assert!(matches!(
            read_pack(&blank),
            Err(PackManifestError::Identity { .. })
        ));

        let duplicate = PACK.replace(
            r#"{ "name": "source", "value_kind": "test.fact/source@1.0.0", "acceptance": "complete_only" }"#,
            r#"{ "name": "source", "value_kind": "test.fact/source@1.0.0", "acceptance": "complete_only" },
            { "name": "source", "value_kind": "test.fact/other@1.0.0", "acceptance": "complete_only" }"#,
        );
        assert!(matches!(
            register_pack(&mut CapabilityRegistry::default(), &duplicate),
            Err(PackManifestError::Registry(
                RegistryError::InvalidCapability { .. }
            ))
        ));
    }

    #[test]
    fn unknown_extensions_survive_every_pack_declaration_level() {
        let extended = PACK
            .replace(
                r#""capabilities": ["#,
                r#""x.root": {"opaque": [3, 2, 1]}, "capabilities": ["#,
            )
            .replace(
                r#""default_conformance_suite": "test.suite/make@1.0.0""#,
                r#""default_conformance_suite": "test.suite/make@1.0.0", "x.capability": {"mode": "future"}"#,
            )
            .replace(
                r#""acceptance": "complete_only" }"#,
                r#""acceptance": "complete_only", "x.input": ["verbatim", 7] }"#,
            )
            .replace(
                r#""value_kind": "test.fact/made@1.0.0" }"#,
                r#""value_kind": "test.fact/made@1.0.0", "x.output": false }"#,
            );

        let pack = read_pack(&extended).unwrap();
        assert_eq!(
            pack.extensions["x.root"]["opaque"],
            serde_json::json!([3, 2, 1])
        );
        assert_eq!(
            pack.capabilities[0].extensions["x.capability"]["mode"],
            "future"
        );
        assert_eq!(
            pack.capabilities[0].input_ports[0].extensions["x.input"],
            serde_json::json!(["verbatim", 7])
        );
        assert_eq!(
            pack.capabilities[0].output_ports[0].extensions["x.output"],
            serde_json::json!(false)
        );

        let written = write_pack(&pack).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&written).unwrap(),
            serde_json::from_str::<Value>(&extended).unwrap()
        );
        assert_eq!(read_pack(&written).unwrap(), pack);
    }

    #[test]
    fn public_pack_writes_reject_reserved_extension_keys_at_every_level() {
        let mut root = read_pack(PACK).unwrap();
        root.extensions
            .insert("protocol".to_owned(), Value::String("shadow".to_owned()));
        assert!(matches!(
            write_pack(&root),
            Err(PackManifestError::ReservedExtension { .. })
        ));

        let mut capability = read_pack(PACK).unwrap();
        capability.capabilities[0]
            .extensions
            .insert("id".to_owned(), Value::Null);
        assert!(matches!(
            write_pack(&capability),
            Err(PackManifestError::Registry(
                RegistryError::InvalidCapability { .. }
            ))
        ));

        let mut input = read_pack(PACK).unwrap();
        input.capabilities[0].input_ports[0]
            .extensions
            .insert("acceptance".to_owned(), Value::Null);
        assert!(matches!(
            write_pack(&input),
            Err(PackManifestError::Registry(
                RegistryError::InvalidCapability { .. }
            ))
        ));

        let mut output = read_pack(PACK).unwrap();
        output.capabilities[0].output_ports[0]
            .extensions
            .insert("value_kind".to_owned(), Value::Null);
        assert!(matches!(
            write_pack(&output),
            Err(PackManifestError::Registry(
                RegistryError::InvalidCapability { .. }
            ))
        ));
    }
}
