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

use serde::{Deserialize, Serialize};

use crate::{
    CapabilityId, CapabilityRegistry, CapabilitySpec, FactAcceptance, FactType, RegistryError,
    Requirement,
};

/// The manifest contract version. Exact, like every other identity here.
pub const PACK_PROTOCOL: &str = "org.gooi.pack/v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ManifestRequirement {
    /// A fact identity in display form, `package/name@version`.
    pub fact: String,
    pub acceptance: FactAcceptance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ManifestCapability {
    pub id: String,
    #[serde(default)]
    pub requires: Vec<ManifestRequirement>,
    pub produces: Vec<String>,
    pub default_conformance_suite: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackManifest {
    pub protocol: String,
    pub capabilities: Vec<ManifestCapability>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PackManifestError {
    Parse(String),
    ProtocolMismatch { expected: String, actual: String },
    Identity { capability: String, detail: String },
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
            Self::Registry(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PackManifestError {}

/// Reads a manifest into specs, without registering them.
pub fn read_pack(json: &str) -> Result<Vec<CapabilitySpec>, PackManifestError> {
    let manifest: PackManifest =
        serde_json::from_str(json).map_err(|e| PackManifestError::Parse(e.to_string()))?;
    if manifest.protocol != PACK_PROTOCOL {
        return Err(PackManifestError::ProtocolMismatch {
            expected: PACK_PROTOCOL.to_owned(),
            actual: manifest.protocol,
        });
    }

    let mut specs = Vec::with_capacity(manifest.capabilities.len());
    for declared in manifest.capabilities {
        let fail = |detail: String| PackManifestError::Identity {
            capability: declared.id.clone(),
            detail,
        };
        let id = CapabilityId::parse(&declared.id).map_err(|e| fail(e.to_string()))?;
        let mut requires = Vec::with_capacity(declared.requires.len());
        for requirement in &declared.requires {
            requires.push(Requirement {
                fact: FactType::parse(&requirement.fact).map_err(|e| fail(e.to_string()))?,
                acceptance: requirement.acceptance,
            });
        }
        let mut produces = Vec::with_capacity(declared.produces.len());
        for produced in &declared.produces {
            produces.push(FactType::parse(produced).map_err(|e| fail(e.to_string()))?);
        }
        specs.push(CapabilitySpec {
            id,
            requires,
            produces,
            default_conformance_suite: declared.default_conformance_suite,
        });
    }
    Ok(specs)
}

/// Renders specs back into a manifest, so a graph declared in code can be
/// exported as data and a host can publish what it installed.
pub fn write_pack(specs: &[CapabilitySpec]) -> PackManifest {
    PackManifest {
        protocol: PACK_PROTOCOL.to_owned(),
        capabilities: specs
            .iter()
            .map(|spec| ManifestCapability {
                id: spec.id.to_string(),
                requires: spec
                    .requires
                    .iter()
                    .map(|r| ManifestRequirement {
                        fact: r.fact.to_string(),
                        acceptance: r.acceptance,
                    })
                    .collect(),
                produces: spec.produces.iter().map(FactType::to_string).collect(),
                default_conformance_suite: spec.default_conformance_suite.clone(),
            })
            .collect(),
    }
}

/// Reads a manifest and registers every capability it declares.
///
/// The registry validates each spec exactly as it would a hand-written one, so
/// a manifest cannot declare something the kernel would otherwise refuse.
pub fn register_pack(
    registry: &mut CapabilityRegistry,
    json: &str,
) -> Result<(), PackManifestError> {
    for spec in read_pack(json)? {
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
      "protocol": "org.gooi.pack/v1",
      "capabilities": [
        {
          "id": "test.capability/make@1.0.0",
          "requires": [
            { "fact": "test.fact/source@1.0.0", "acceptance": "complete_only" }
          ],
          "produces": ["test.fact/made@1.0.0"],
          "default_conformance_suite": "test.suite/make@1.0.0"
        }
      ]
    }"#;

    #[test]
    fn a_declared_graph_becomes_ordinary_specs() {
        let specs = read_pack(PACK).expect("manifest reads");
        assert_eq!(specs.len(), 1);
        assert_eq!(
            specs[0].id,
            CapabilityId::new("test.capability", "make", "1.0.0")
        );
        assert_eq!(
            specs[0].requires[0].acceptance,
            FactAcceptance::CompleteOnly
        );
        assert_eq!(
            specs[0].produces[0],
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
        assert!(!plan.is_executable(), "declared, but nobody implements it");
        assert_eq!(plan.needs.len(), 1);
    }

    #[test]
    fn another_protocol_is_refused() {
        let other = PACK.replace("org.gooi.pack/v1", "org.gooi.pack/v99");
        assert!(matches!(
            read_pack(&other),
            Err(PackManifestError::ProtocolMismatch { .. })
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
            r#""produces": ["test.fact/made@1.0.0"]"#,
            r#""produces": []"#,
        );
        assert!(matches!(
            register_pack(&mut CapabilityRegistry::default(), &empty),
            Err(PackManifestError::Registry(_))
        ));
    }

    #[test]
    fn specs_survive_a_trip_out_to_data_and_back() {
        let specs = read_pack(PACK).unwrap();
        let exported = serde_json::to_string(&write_pack(&specs)).unwrap();
        assert_eq!(read_pack(&exported).unwrap(), specs);
    }

    #[test]
    fn a_manifest_round_trips_through_serialisation() {
        let manifest: PackManifest = serde_json::from_str(PACK).unwrap();
        let encoded = serde_json::to_string(&manifest).unwrap();
        assert_eq!(read_pack(&encoded).unwrap(), read_pack(PACK).unwrap());
    }
}
