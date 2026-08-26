//! A narrow semantic waist for one selected, ordered activity projection.
//!
//! Current agent products do not share a transcript model. Some retain a
//! branching graph and select a path; others materialize one ordered history.
//! What recurs is smaller: for an exact source scope and selector snapshot, an
//! authority emits activity entries in an observable order. Entry payload,
//! contributor classification, graph topology, pending interaction requests,
//! and rendering remain separate facts.

use gooir_identity::{DialectId, ValueKindId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const PACKAGE: &str = "org.gooi.semantics.activity_projection";
pub const MODEL: &str = "ordered_activity";
pub const VERSION: &str = "0.1.0";

/// Exact identity of the vocabulary family governing this value kind.
pub fn dialect_id() -> DialectId {
    DialectId::new(PACKAGE, VERSION)
}

/// Exact identity of this provisional semantic value kind.
pub fn activity_projection_contract() -> ValueKindId {
    ValueKindId::in_dialect(dialect_id(), MODEL)
}

/// An authority-local reference.
///
/// `namespace` and `id` are opaque and matched exactly. A consumer must not
/// assume that a namespace is global, that an id survives another revision,
/// or that two differently named namespaces identify different real objects.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OpaqueRef {
    pub namespace: String,
    pub id: String,
    /// Authority-local metadata survives without becoming reference identity.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl OpaqueRef {
    pub fn new(namespace: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            id: id.into(),
            extensions: BTreeMap::new(),
        }
    }

    pub fn is_well_formed(&self) -> bool {
        !self.namespace.trim().is_empty() && !self.id.trim().is_empty()
    }
}

/// How much activity the authority says is present in this exact projection.
///
/// This is deliberately not a boolean. An empty `not_loaded`, `summary`, or
/// `unknown` projection is not evidence that its scope contains no activity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionExtent {
    /// The authority explicitly did not load activity entries.
    NotLoaded,
    /// Entries are only a summary selected by the authority.
    Summary,
    /// Entries are bounded by a page, viewport, limit, or other exact window.
    Windowed,
    /// Every entry available from the named source scope after the named
    /// selection rules was included. This never means every sibling branch or
    /// every activity that could exist outside that scope.
    Full,
    /// The authority did not establish the extent.
    Unknown,
}

/// One position in an observed activity projection.
///
/// Vector position is the only portable order. It is not necessarily
/// chronological or causal. The source-observed order of `source_refs` is
/// preserved but carries no portable relationship or priority. `source_refs`
/// may be empty for an authority-created synthetic entry, and may contain
/// several records when a product groups them. `projection_key`, when present,
/// is local to this exact projection and is not a durable source identity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActivityEntryRef {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<OpaqueRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_key: Option<String>,
    /// Source-native payload, kinds, contributor hints, grouping data, and
    /// future fields survive here without acquiring portable meaning.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// One source-scoped, selection-relative ordered activity projection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActivityProjection {
    /// Opaque facts that establish the exact source scope. Composite products
    /// may need several refs. Their source-observed order is preserved, but no
    /// relationship, precedence, or normalization among them is implied.
    pub scope_refs: Vec<OpaqueRef>,
    pub extent: ProjectionExtent,
    /// The emitted ordinal is the vector position.
    pub entries: Vec<ActivityEntryRef>,
    /// Selector snapshots, window bounds, overlay rules, native lineage, and
    /// future fields survive without interpretation.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionVerificationError {
    MissingScope,
    BlankScopeRef,
    DuplicateScopeRef,
    EntryHasNoLocator,
    BlankProjectionKey,
    BlankSourceRef,
    DuplicateEntrySourceRef,
    NotLoadedHasEntries,
    ReservedExtensionKey,
}

impl ActivityProjection {
    /// Checks structural obligations only; it never upgrades source extent.
    pub fn verify(&self) -> Result<(), Vec<ProjectionVerificationError>> {
        let mut errors = Vec::new();

        if self.scope_refs.is_empty() {
            errors.push(ProjectionVerificationError::MissingScope);
        }
        let mut scope_refs = BTreeSet::new();
        for reference in &self.scope_refs {
            if !reference.is_well_formed() {
                errors.push(ProjectionVerificationError::BlankScopeRef);
            }
            if !scope_refs.insert((&reference.namespace, &reference.id)) {
                errors.push(ProjectionVerificationError::DuplicateScopeRef);
            }
            if reference.extensions.contains_key("namespace")
                || reference.extensions.contains_key("id")
            {
                errors.push(ProjectionVerificationError::ReservedExtensionKey);
            }
        }

        if self.extent == ProjectionExtent::NotLoaded && !self.entries.is_empty() {
            errors.push(ProjectionVerificationError::NotLoadedHasEntries);
        }

        for entry in &self.entries {
            if entry.source_refs.is_empty() && entry.projection_key.is_none() {
                errors.push(ProjectionVerificationError::EntryHasNoLocator);
            }
            if entry
                .projection_key
                .as_ref()
                .is_some_and(|key| key.trim().is_empty())
            {
                errors.push(ProjectionVerificationError::BlankProjectionKey);
            }
            let mut source_refs = BTreeSet::new();
            for reference in &entry.source_refs {
                if !reference.is_well_formed() {
                    errors.push(ProjectionVerificationError::BlankSourceRef);
                }
                if !source_refs.insert((&reference.namespace, &reference.id)) {
                    errors.push(ProjectionVerificationError::DuplicateEntrySourceRef);
                }
                if reference.extensions.contains_key("namespace")
                    || reference.extensions.contains_key("id")
                {
                    errors.push(ProjectionVerificationError::ReservedExtensionKey);
                }
            }
            if entry.extensions.contains_key("source_refs")
                || entry.extensions.contains_key("projection_key")
            {
                errors.push(ProjectionVerificationError::ReservedExtensionKey);
            }
        }

        if self.extensions.contains_key("scope_refs")
            || self.extensions.contains_key("extent")
            || self.extensions.contains_key("entries")
        {
            errors.push(ProjectionVerificationError::ReservedExtensionKey);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// True only when the authority claims full coverage of its exact selected
    /// scope. Structure and source extent are intentionally separate checks.
    pub fn is_full(&self) -> bool {
        self.verify().is_ok() && self.extent == ProjectionExtent::Full
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn projection() -> ActivityProjection {
        ActivityProjection {
            scope_refs: vec![OpaqueRef::new("example.thread", "thread-1")],
            extent: ProjectionExtent::Windowed,
            entries: vec![
                ActivityEntryRef {
                    source_refs: vec![OpaqueRef::new("example.message", "m-1")],
                    projection_key: None,
                    extensions: BTreeMap::new(),
                },
                ActivityEntryRef {
                    source_refs: vec![
                        OpaqueRef::new("example.message", "m-2"),
                        OpaqueRef::new("example.tool", "t-1"),
                    ],
                    projection_key: Some("group-0".to_owned()),
                    extensions: BTreeMap::from([("native_role".to_owned(), json!("agent"))]),
                },
            ],
            extensions: BTreeMap::from([("window".to_owned(), json!({"limit": 50}))]),
        }
    }

    #[test]
    fn contract_identity_is_exact_and_versioned() {
        assert_eq!(
            activity_projection_contract(),
            ValueKindId::new(
                "org.gooi.semantics.activity_projection",
                "ordered_activity",
                "0.1.0"
            )
        );
        assert_eq!(activity_projection_contract().dialect(), dialect_id());
    }

    #[test]
    fn selected_order_and_opaque_extensions_round_trip() {
        let input = json!({
            "scope_refs": [{
                "namespace": "example.thread",
                "id": "thread-1",
                "native_partition": "west"
            }],
            "extent": "windowed",
            "entries": [
                {"source_refs": [{
                    "namespace": "example.message",
                    "id": "m-1",
                    "native_generation": 2
                }]},
                {
                    "source_refs": [
                        {"namespace": "example.message", "id": "m-2"},
                        {"namespace": "example.tool", "id": "t-1"}
                    ],
                    "projection_key": "group-0",
                    "native_role": "agent"
                }
            ],
            "window": {"limit": 50}
        });
        let decoded: ActivityProjection = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap(), input);
        assert_eq!(decoded.entries[0].source_refs[0].id, "m-1");
        assert_eq!(decoded.entries[1].source_refs[0].id, "m-2");
        assert_eq!(
            decoded.scope_refs[0].extensions["native_partition"],
            json!("west")
        );
        assert_eq!(
            decoded.entries[0].source_refs[0].extensions["native_generation"],
            json!(2)
        );
        assert!(decoded.verify().is_ok());
    }

    #[test]
    fn vector_position_is_preserved_not_normalized() {
        let mut first = projection();
        let mut second = first.clone();
        second.entries.reverse();

        assert!(first.verify().is_ok());
        assert!(second.verify().is_ok());
        assert_ne!(first, second);
        first.entries.reverse();
        assert_eq!(first, second);
    }

    #[test]
    fn grouped_and_synthetic_entries_do_not_claim_one_stable_source_id() {
        let mut value = projection();
        value.entries.push(ActivityEntryRef {
            source_refs: Vec::new(),
            projection_key: Some("synthetic-summary-2".to_owned()),
            extensions: BTreeMap::from([("native_group".to_owned(), json!(true))]),
        });
        assert!(value.verify().is_ok());
    }

    #[test]
    fn absent_locator_is_unknown_not_an_anonymous_valid_entry() {
        let mut value = projection();
        value.entries.push(ActivityEntryRef {
            source_refs: Vec::new(),
            projection_key: None,
            extensions: BTreeMap::new(),
        });
        assert_eq!(
            value.verify(),
            Err(vec![ProjectionVerificationError::EntryHasNoLocator])
        );
    }

    #[test]
    fn an_empty_unloaded_projection_is_not_full() {
        let mut value = projection();
        value.entries.clear();
        value.extent = ProjectionExtent::NotLoaded;
        assert!(value.verify().is_ok());
        assert!(!value.is_full());

        value.extent = ProjectionExtent::Full;
        assert!(value.is_full(), "an authority may establish an empty scope");
    }

    #[test]
    fn not_loaded_cannot_carry_entries() {
        let mut value = projection();
        value.extent = ProjectionExtent::NotLoaded;
        assert_eq!(
            value.verify(),
            Err(vec![ProjectionVerificationError::NotLoadedHasEntries])
        );
    }

    #[test]
    fn duplicates_and_blank_refs_fail_closed() {
        let mut value = projection();
        value.scope_refs.push(value.scope_refs[0].clone());
        value.entries[0].source_refs.push(OpaqueRef::new("", "m-2"));
        let duplicate = value.entries[1].source_refs[0].clone();
        value.entries[1].source_refs.push(duplicate);
        assert_eq!(
            value.verify(),
            Err(vec![
                ProjectionVerificationError::DuplicateScopeRef,
                ProjectionVerificationError::BlankSourceRef,
                ProjectionVerificationError::DuplicateEntrySourceRef,
            ])
        );
    }

    #[test]
    fn reserved_extensions_cannot_shadow_contract_fields() {
        let mut value = projection();
        value.extensions.insert("extent".to_owned(), json!("full"));
        value.entries[0]
            .extensions
            .insert("source_refs".to_owned(), json!([]));
        value.scope_refs[0]
            .extensions
            .insert("id".to_owned(), json!("shadow"));
        assert_eq!(
            value.verify(),
            Err(vec![
                ProjectionVerificationError::ReservedExtensionKey,
                ProjectionVerificationError::ReservedExtensionKey,
                ProjectionVerificationError::ReservedExtensionKey,
            ])
        );
    }
}
