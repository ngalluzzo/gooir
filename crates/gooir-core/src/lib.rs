use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Exact identity of a semantic contract. Compatibility is never inferred from
/// the version string; it requires an explicit bridge.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct ContractId {
    pub package: String,
    pub name: String,
    pub version: String,
}

impl ContractId {
    pub fn new(
        package: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            package: package.into(),
            name: name.into(),
            version: version.into(),
        }
    }

    pub fn is_other_version_of(&self, other: &Self) -> bool {
        self.package == other.package && self.name == other.name && self.version != other.version
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Declared,
    StaticInferred,
    RuntimeObserved,
    Verified,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceRef {
    pub authority: String,
    pub artifact: String,
    pub revision: String,
    pub span: Option<String>,
}

impl SourceRef {
    pub fn new(
        authority: impl Into<String>,
        artifact: impl Into<String>,
        revision: impl Into<String>,
    ) -> Self {
        Self {
            authority: authority.into(),
            artifact: artifact.into(),
            revision: revision.into(),
            span: None,
        }
    }

    pub fn with_span(mut self, span: impl Into<String>) -> Self {
        self.span = Some(span.into());
        self
    }
}

/// An exact conformance-result reference transported with a claim.
///
/// This record is an attestation, not an intrinsic proof. An analysis host must
/// validate and explicitly admit the exact record before a resolver may treat
/// the associated claim as trusted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConformanceEvidence {
    /// Opaque identity of the authority that issued the result.
    pub attester: String,
    /// Exact identity and version of the conformance suite.
    pub suite: String,
    /// Digest of the adapter, bridge, or implementation exercised by the suite.
    pub subject_digest: String,
    /// Digest of the immutable conformance-result document.
    pub result_digest: String,
}

impl ConformanceEvidence {
    /// Creates an exact conformance-result reference.
    pub fn new(
        attester: impl Into<String>,
        suite: impl Into<String>,
        subject_digest: impl Into<String>,
        result_digest: impl Into<String>,
    ) -> Self {
        Self {
            attester: attester.into(),
            suite: suite.into(),
            subject_digest: subject_digest.into(),
            result_digest: result_digest.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub status: EvidenceStatus,
    pub source: SourceRef,
    pub conformance: Option<ConformanceEvidence>,
}

impl Evidence {
    /// Records a declared claim with no conformance attestation.
    pub fn declared(source: SourceRef) -> Self {
        Self {
            status: EvidenceStatus::Declared,
            source,
            conformance: None,
        }
    }

    /// Records that an attester reported successful verification.
    ///
    /// The claim is not trusted until the active analysis policy admits the
    /// exact conformance record.
    pub fn verified(source: SourceRef, conformance: ConformanceEvidence) -> Self {
        Self {
            status: EvidenceStatus::Verified,
            source,
            conformance: Some(conformance),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub contract: ContractId,
    pub payload: Value,
    pub evidence: Evidence,
}

impl Claim {
    pub fn new(contract: ContractId, payload: Value, evidence: Evidence) -> Self {
        Self {
            contract,
            payload,
            evidence,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    pub id: String,
    pub dialect: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<Claim>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<Vec<Operation>>,
    /// Unknown top-level fields survive even when the dialect plugin is absent.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl Operation {
    pub fn new(id: impl Into<String>, dialect: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            dialect: dialect.into(),
            name: name.into(),
            attributes: BTreeMap::new(),
            claims: Vec::new(),
            regions: Vec::new(),
            extensions: BTreeMap::new(),
        }
    }

    pub fn with_claim(mut self, claim: Claim) -> Self {
        self.claims.push(claim);
        self
    }

    pub fn with_region(mut self, operations: Vec<Operation>) -> Self {
        self.regions.push(operations);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Program {
    pub format_version: String,
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl Program {
    pub fn new(operations: Vec<Operation>) -> Self {
        Self {
            format_version: "0.1.0".to_owned(),
            operations,
            extensions: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Program;
    use serde_json::Value;

    #[test]
    fn unknown_dialect_data_round_trips_without_a_plugin() {
        let input: Value = serde_json::from_str(
            r#"{
                "format_version": "0.1.0",
                "producer_extension": {"opaque": true},
                "operations": [{
                    "id": "vendor-op",
                    "dialect": "vendor.private",
                    "name": "do_the_thing",
                    "attributes": {"nested": {"answer": 42}},
                    "vendor_top_level": ["must", "survive"]
                }]
            }"#,
        )
        .expect("fixture is valid JSON");

        let program: Program =
            serde_json::from_value(input.clone()).expect("unknown dialect can be loaded");
        let output = serde_json::to_value(program).expect("program can be serialized");

        assert_eq!(output, input);
    }
}
