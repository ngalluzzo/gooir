//! The neutral data-model waist.
//!
//! This vocabulary is deliberately small and deliberately lossy. It exists so
//! that many authorities can converge on one middle and many targets can be
//! lowered from it, turning N x M work into N + M.
//!
//! It is a *waist*, so it must not be any authority's native model: nothing
//! here is Prisma-shaped, Postgres-shaped, or target-shaped. It carries no
//! laws. Its correctness is established by independent authorities converging
//! on it, never by constraints authored alongside it.

use gooir_core::ContractId;
use serde::{Deserialize, Serialize};

pub const PACKAGE: &str = "org.gooi.semantics.data_model";
pub const VERSION: &str = "1.0.0";

pub fn entity_contract() -> ContractId {
    ContractId::new(PACKAGE, "entity", VERSION)
}

pub fn relation_contract() -> ContractId {
    ContractId::new(PACKAGE, "relation", VERSION)
}

/// Neutral scalar domains. This set is smaller than any real authority's type
/// system; narrowing is an explicit projection, and what an authority knows
/// beyond this is lost here on purpose.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalarType {
    Text,
    Integer,
    BigInteger,
    Float,
    Decimal,
    Boolean,
    Timestamp,
    Date,
    Time,
    Json,
    Bytes,
    Uuid,
    /// A closed set of named alternatives. The member names are not carried at
    /// this version.
    Enumeration,
    /// The authority named a domain this waist does not model.
    Other,
}

/// A fact an authority may be unable to establish either way.
///
/// Every attribute in this waist needs this shape. A boolean forces a lifter to
/// answer a question its authority cannot see -- a JSON Schema has no notion of
/// a primary key, so reporting `false` would assert something never established.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tri {
    Yes,
    No,
    Unknown,
}

impl Tri {
    /// Lifts a boolean an authority *could* determine.
    pub fn known(value: bool) -> Self {
        if value { Self::Yes } else { Self::No }
    }

    /// True only when the fact was established affirmatively.
    pub fn is_yes(self) -> bool {
        self == Self::Yes
    }
}

/// Whether a field must carry a value.
///
/// Three-valued because authorities differ in what they can express. Prisma
/// collapses "absent" and "empty" for list fields, so it cannot report
/// nullability for them at all; a boolean would force it to invent an answer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    Required,
    Optional,
    /// This authority cannot express presence for this field.
    Unknown,
}

/// Where a field's value comes from when none is supplied.
///
/// Splitting this out is not cosmetic. A schema source and a database catalog
/// disagree about "has a default" for a large share of real fields, because a
/// client-generated value (`cuid()`) and a database-generated value (`now()`)
/// are different facts. Collapsing them into a boolean makes two correct
/// authorities look like they contradict each other.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultOrigin {
    /// Established that nothing supplies a value.
    None,
    /// The store supplies it.
    Database,
    /// The writing application supplies it.
    Application,
    /// This authority cannot see whether anything supplies a value.
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    Scalar(ScalarType),
    /// The authority could not be read for this field.
    Unknown,
}

/// A closed set of named alternatives.
///
/// Carried by name *and* members: every authority in use can express both, and
/// dropping the members leaves a target unable to validate a value or render a
/// choice -- which is most of what makes a generated form useful.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Enumeration {
    pub name: String,
    /// Members in whatever order the source authority reported them.
    ///
    /// Order is **source-local and not portable**: a schema lists declaration
    /// order while a store reports the order values were added, and real
    /// schemas disagree on this while agreeing on membership. The order is kept
    /// rather than normalised so nothing is destroyed, but membership is the
    /// only part that compares across authorities -- see
    /// [`Enumeration::member_set`].
    pub members: Vec<String>,
}

impl Enumeration {
    /// Membership in a canonical order, for comparison across authorities.
    pub fn member_set(&self) -> Vec<String> {
        let mut m = self.members.clone();
        m.sort();
        m.dedup();
        m
    }
}

/// One stored attribute of an entity.
///
/// A field is always storage. A reference between entities is a
/// [`RelationEdge`], never a field -- that is the one structural commitment
/// this waist makes, and it is what lets a source-file authority and a
/// database-catalog authority describe the same model.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FieldShape {
    pub name: String,
    pub ty: FieldType,
    pub nullable: Presence,
    pub list: bool,
    pub identity: Tri,
    /// Set only when this field alone is unique. Uniqueness across a *set* of
    /// fields is a property of the set, carried by
    /// [`EntityShape::unique_sets`] -- claiming it per field would assert
    /// something strictly stronger than the authority established.
    pub unique: Tri,
    pub default: DefaultOrigin,
    /// The default's literal text, when an authority supplied one.
    ///
    /// Expression *formatting* is authority-local (a store rewrites `now()`
    /// and re-qualifies casts), so this is carried but deliberately not
    /// compared across authorities -- the same treatment as enum member order.
    /// It is verified behaviourally instead: the value a lowering emits must be
    /// the value the target ends up with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    /// Present exactly when `ty` is [`ScalarType::Enumeration`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enumeration: Option<Enumeration>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EntityShape {
    pub name: String,
    pub fields: Vec<FieldShape>,
    /// Field sets that are jointly unique. Order within a set is not meaningful
    /// here; membership is.
    #[serde(default)]
    pub unique_sets: Vec<Vec<String>>,
}

impl EntityShape {
    /// Resolves a field by name, preferring an exact match.
    ///
    /// Normalization is a fallback and is only trusted when it is unambiguous.
    /// Real schemas do contain both `createdAt` and `created_at` in one entity
    /// meaning different things, so a normalized match that hits more than one
    /// field resolves to nothing rather than to an arbitrary one.
    pub fn field(&self, name: &str) -> Option<&FieldShape> {
        if let Some(exact) = self.fields.iter().find(|f| f.name == name) {
            return Some(exact);
        }
        let want = normalize(name);
        let mut hits = self.fields.iter().filter(|f| normalize(&f.name) == want);
        let first = hits.next()?;
        match hits.next() {
            None => Some(first),
            Some(_) => None,
        }
    }

    /// Field names whose normalized forms collide inside this entity. Such
    /// names cannot be matched across authorities by normalization.
    pub fn ambiguous_field_names(&self) -> Vec<String> {
        let mut out = Vec::new();
        for f in &self.fields {
            let n = normalize(&f.name);
            if self
                .fields
                .iter()
                .filter(|o| normalize(&o.name) == n)
                .count()
                > 1
            {
                out.push(f.name.clone());
            }
        }
        out
    }
}

/// A directed reference from one entity to another, carried as an edge rather
/// than as a field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelationEdge {
    pub from_entity: String,
    /// The storage fields on `from_entity` that carry the reference. Empty when
    /// the authority declares the relation without naming its storage.
    pub from_fields: Vec<String>,
    pub to_entity: String,
    pub to_fields: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DataModel {
    pub entities: Vec<EntityShape>,
    pub relations: Vec<RelationEdge>,
}

impl DataModel {
    pub fn entity(&self, name: &str) -> Option<&EntityShape> {
        let want = normalize(name);
        self.entities.iter().find(|e| normalize(&e.name) == want)
    }

    pub fn entity_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.entities.iter().map(|e| normalize(&e.name)).collect();
        names.sort();
        names
    }
}

/// Comparison form for an identifier.
///
/// Authorities disagree on casing and word separators for the same concept
/// (`emailVerified` against `email_verified`, `User` against `users`). Folding
/// case and separators is the minimum needed to compare them; it deliberately
/// does not stem or pluralize, because that would invent matches.
pub fn normalize(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '_' && *c != '-')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_folds_case_and_separators_only() {
        assert_eq!(normalize("emailVerified"), normalize("email_verified"));
        assert_eq!(normalize("User"), normalize("user"));
        assert_ne!(normalize("user"), normalize("users"), "must not pluralize");
        assert_ne!(normalize("poll"), normalize("polls"));
    }

    #[test]
    fn a_reference_is_an_edge_not_a_field() {
        // The waist offers no FieldType variant for "points at another entity".
        // This is the commitment that lets two unlike authorities converge.
        let f = FieldShape {
            name: "authorId".to_owned(),
            ty: FieldType::Scalar(ScalarType::Text),
            nullable: Presence::Required,
            list: false,
            identity: Tri::No,
            unique: Tri::No,
            default: DefaultOrigin::None,
            default_value: None,
            enumeration: None,
        };
        assert!(matches!(f.ty, FieldType::Scalar(_)));
    }

    #[test]
    fn normalization_collisions_resolve_to_nothing_not_to_an_arbitrary_field() {
        let e = EntityShape {
            name: "Account".to_owned(),
            unique_sets: Vec::new(),
            fields: vec![
                FieldShape {
                    name: "createdAt".to_owned(),
                    ty: FieldType::Scalar(ScalarType::Timestamp),
                    nullable: Presence::Required,
                    list: false,
                    identity: Tri::No,
                    unique: Tri::No,
                    default: DefaultOrigin::Database,
                    default_value: None,
                    enumeration: None,
                },
                FieldShape {
                    name: "created_at".to_owned(),
                    ty: FieldType::Scalar(ScalarType::Integer),
                    nullable: Presence::Optional,
                    list: false,
                    identity: Tri::No,
                    unique: Tri::No,
                    default: DefaultOrigin::None,
                    default_value: None,
                    enumeration: None,
                },
            ],
        };
        // exact names still resolve
        assert_eq!(
            e.field("createdAt").unwrap().ty,
            FieldType::Scalar(ScalarType::Timestamp)
        );
        assert_eq!(
            e.field("created_at").unwrap().ty,
            FieldType::Scalar(ScalarType::Integer)
        );
        // an inexact name that collides resolves to nothing
        assert!(e.field("CreatedAT").is_none());
        assert_eq!(e.ambiguous_field_names().len(), 2);
    }

    #[test]
    fn compound_uniqueness_is_not_a_field_property() {
        let e = EntityShape {
            name: "Membership".to_owned(),
            fields: Vec::new(),
            unique_sets: vec![vec!["userId".to_owned(), "teamId".to_owned()]],
        };
        assert_eq!(e.unique_sets.len(), 1);
        assert_eq!(e.unique_sets[0].len(), 2);
    }

    #[test]
    fn lookup_is_normalization_insensitive() {
        let m = DataModel {
            entities: vec![EntityShape {
                unique_sets: Vec::new(),
                name: "user_account".to_owned(),
                fields: vec![FieldShape {
                    name: "email_verified".to_owned(),
                    ty: FieldType::Scalar(ScalarType::Boolean),
                    nullable: Presence::Optional,
                    list: false,
                    identity: Tri::No,
                    unique: Tri::No,
                    default: DefaultOrigin::None,
                    default_value: None,
                    enumeration: None,
                }],
            }],
            relations: Vec::new(),
        };
        let e = m
            .entity("UserAccount")
            .expect("entity found by normalized name");
        assert!(e.field("emailVerified").is_some());
    }
}
