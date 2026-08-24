//! Lifts a PostgreSQL catalog introspection into the neutral data-model waist.
//!
//! PostgreSQL itself is the authoritative parser here: the input is what the
//! server reports about its own catalog, so this lifter only projects.
//!
//! A catalog is a different *kind* of authority from a schema source file. It
//! observes what is enforced, not what was intended. Where that distinction
//! costs information, this lifter records a defeat rather than presenting an
//! enforced-only view as complete.

use lift_defeasible::{Defeasible, Defeat, DefeatKind};
use semantics_data_model_v1::{
    DataModel, DefaultOrigin, EntityShape, Enumeration, FieldShape, FieldType, Presence,
    RelationEdge, ScalarType, Tri,
};
use serde::Deserialize;

pub const DEFEATER_SET: &str = "org.gooi.lifter.postgres_catalog/defeaters@1";

#[derive(Debug, Deserialize)]
pub struct Catalog {
    pub tables: Vec<Table>,
}

#[derive(Debug, Deserialize)]
pub struct Table {
    pub name: String,
    pub columns: Vec<Column>,
    pub constraints: Vec<Constraint>,
    #[serde(default)]
    pub unique_sets: Vec<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct Column {
    pub name: String,
    pub udt: String,
    pub not_null: bool,
    pub has_default: bool,
    #[serde(default)]
    pub is_enum: Option<bool>,
    /// True when a single-column unique index covers this column. Prisma's
    /// `@unique` produces an index, which may have no matching constraint row,
    /// so the index is the authoritative source.
    #[serde(default)]
    pub unique_single: Option<bool>,
    #[serde(default)]
    pub enum_name: Option<String>,
    #[serde(default)]
    pub enum_members: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Constraint {
    /// PostgreSQL `pg_constraint.contype`: p = primary key, u = unique, f = foreign key.
    #[serde(rename = "type")]
    pub kind: String,
    pub cols: Vec<String>,
    pub ref_table: Option<String>,
    #[serde(default)]
    pub ref_cols: Vec<String>,
}

/// Maps a PostgreSQL type name onto the neutral domain set.
/// Unlike Prisma, PostgreSQL has a first-class `uuid` domain.
fn scalar(udt: &str) -> Option<ScalarType> {
    let base = udt.trim_end_matches("[]");
    let head = base.split('(').next().unwrap_or(base).trim();
    Some(match head {
        "text" | "character varying" | "character" | "varchar" | "char" | "citext" | "name" => {
            ScalarType::Text
        }
        "integer" | "smallint" | "int4" | "int2" | "serial" => ScalarType::Integer,
        "bigint" | "int8" | "bigserial" => ScalarType::BigInteger,
        "double precision" | "real" | "float8" | "float4" => ScalarType::Float,
        "numeric" | "decimal" | "money" => ScalarType::Decimal,
        "boolean" | "bool" => ScalarType::Boolean,
        "timestamp without time zone"
        | "timestamp with time zone"
        | "timestamp"
        | "timestamptz" => ScalarType::Timestamp,
        "date" => ScalarType::Date,
        "time without time zone" | "time with time zone" | "time" | "timetz" => ScalarType::Time,
        "json" | "jsonb" => ScalarType::Json,
        "bytea" => ScalarType::Bytes,
        "uuid" => ScalarType::Uuid,
        _ => return None,
    })
}

pub fn lift_catalog(json: &str) -> Result<Defeasible<DataModel>, String> {
    let catalog: Catalog =
        serde_json::from_str(json).map_err(|e| format!("catalog is not valid JSON: {e}"))?;
    Ok(lift(catalog))
}

pub fn lift(catalog: Catalog) -> Defeasible<DataModel> {
    let mut lifted = Defeasible::new(DataModel::default(), DEFEATER_SET);
    let mut out = DataModel::default();
    let mut total_fks = 0usize;

    for table in &catalog.tables {
        let pk: Vec<String> = table
            .constraints
            .iter()
            .filter(|c| c.kind == "p")
            .flat_map(|c| c.cols.clone())
            .collect();
        // Only singleton unique constraints bear on a single field.
        let uniques: Vec<String> = table
            .constraints
            .iter()
            .filter(|c| c.kind == "u" && c.cols.len() == 1)
            .flat_map(|c| c.cols.clone())
            .collect();
        let mut unique_sets: Vec<Vec<String>> = table
            .constraints
            .iter()
            .filter(|c| c.kind == "u" && c.cols.len() > 1)
            .map(|c| c.cols.clone())
            .collect();
        for s in &table.unique_sets {
            if s.len() > 1 && !unique_sets.contains(s) {
                unique_sets.push(s.clone());
            }
        }

        for c in table.constraints.iter().filter(|c| c.kind == "f") {
            total_fks += 1;
            let Some(ref_table) = &c.ref_table else {
                lifted.defeat(Defeat::new(
                    DefeatKind::LookedAndBlocked,
                    table.name.clone(),
                    "foreign key names no referenced table",
                ));
                continue;
            };
            out.relations.push(RelationEdge {
                from_entity: table.name.clone(),
                from_fields: c.cols.clone(),
                to_entity: ref_table.clone(),
                to_fields: c.ref_cols.clone(),
            });
        }

        let mut fields = Vec::new();
        for col in &table.columns {
            let list = col.udt.ends_with("[]");
            let ty = if col.is_enum.unwrap_or(false) {
                FieldType::Scalar(ScalarType::Enumeration)
            } else if let Some(s) = scalar(&col.udt) {
                FieldType::Scalar(s)
            } else {
                lifted.defeat(Defeat::new(
                    DefeatKind::LookedAndBlocked,
                    format!("{}.{}", table.name, col.name),
                    format!("no neutral domain for PostgreSQL type `{}`", col.udt),
                ));
                FieldType::Unknown
            };
            fields.push(FieldShape {
                name: col.name.clone(),
                ty,
                nullable: if col.not_null {
                    Presence::Required
                } else {
                    Presence::Optional
                },
                list,
                identity: Tri::known(pk.contains(&col.name)),
                unique: Tri::known(
                    col.unique_single.unwrap_or(false) || uniques.contains(&col.name),
                ),
                // A catalog sees store-side defaults only. Absence of one is not
                // evidence that nothing supplies a value.
                default_value: None,
                enumeration: col.enum_name.as_ref().map(|n| Enumeration {
                    name: n.clone(),
                    members: col.enum_members.clone(),
                }),
                default: if col.has_default {
                    DefaultOrigin::Database
                } else {
                    DefaultOrigin::Unknown
                },
            });
        }

        out.entities.push(EntityShape {
            name: table.name.clone(),
            fields,
            unique_sets,
        });
    }

    // A catalog observes enforcement, not intent. If nothing is enforced, the
    // absence of relations is not evidence that there are none.
    if total_fks == 0 && out.entities.len() > 1 {
        lifted.defeat(Defeat::new(
            DefeatKind::AuthorityCannotExpress,
            "relations",
            "the catalog declares no foreign keys; a catalog observes only enforced \
             constraints, so relations cannot be established from this authority",
        ));
    }

    if out.entities.is_empty() {
        lifted.defeat(Defeat::new(
            DefeatKind::SubjectUnresolvable,
            "catalog",
            "no base tables were reported",
        ));
    }

    lifted.value = out;
    lifted
}

#[cfg(test)]
mod tests {
    use super::*;

    const TWO_TABLES: &str = r#"{"tables":[
      {"name":"users","columns":[
        {"name":"id","udt":"uuid","not_null":true,"has_default":true,"is_enum":false},
        {"name":"email","udt":"text","not_null":true,"has_default":false,"is_enum":false}],
       "unique_sets":[],"constraints":[{"type":"p","cols":["id"],"ref_table":null,"ref_cols":[]},
                      {"type":"u","cols":["email"],"ref_table":null,"ref_cols":[]}]},
      {"name":"posts","columns":[
        {"name":"id","udt":"uuid","not_null":true,"has_default":true,"is_enum":false},
        {"name":"author_id","udt":"uuid","not_null":false,"has_default":false,"is_enum":false}],
       "constraints":[{"type":"p","cols":["id"],"ref_table":null,"ref_cols":[]},
                      {"type":"f","cols":["author_id"],"ref_table":"users","ref_cols":["id"]}]}]}"#;

    #[test]
    fn lifts_tables_columns_keys_and_foreign_keys() {
        let l = lift_catalog(TWO_TABLES).expect("valid catalog");
        assert!(l.is_exhaustive(), "unexpected defeats: {:?}", l.defeats);
        assert_eq!(l.value.entity_names(), vec!["posts", "users"]);
        let users = l.value.entity("users").unwrap();
        assert!(users.field("id").unwrap().identity.is_yes());
        assert!(users.field("email").unwrap().unique.is_yes());
        assert_eq!(users.field("id").unwrap().default, DefaultOrigin::Database);
        assert_eq!(
            users.field("email").unwrap().default,
            DefaultOrigin::Unknown
        );
        assert_eq!(
            users.field("id").unwrap().ty,
            FieldType::Scalar(ScalarType::Uuid)
        );
        assert_eq!(l.value.relations.len(), 1);
        assert_eq!(l.value.relations[0].to_entity, "users");
        assert_eq!(
            l.value
                .entity("posts")
                .unwrap()
                .field("author_id")
                .unwrap()
                .nullable,
            Presence::Optional
        );
    }

    #[test]
    fn no_foreign_keys_means_relations_are_unknown_not_absent() {
        let json = r#"{"tables":[
          {"name":"a","columns":[{"name":"id","udt":"text","not_null":true,"has_default":false,"is_enum":false}],"constraints":[]},
          {"name":"b","columns":[{"name":"a_id","udt":"text","not_null":true,"has_default":false,"is_enum":false}],"constraints":[]}]}"#;
        let l = lift_catalog(json).expect("valid catalog");
        assert!(l.value.relations.is_empty());
        assert!(
            !l.is_exhaustive(),
            "zero relations must not be reported as exhaustive"
        );
        assert!(
            l.defeats_of(DefeatKind::AuthorityCannotExpress)
                .any(|d| d.subject == "relations")
        );
    }

    #[test]
    fn unmapped_postgres_type_degrades_to_unknown() {
        let json = r#"{"tables":[{"name":"t","columns":[
          {"name":"loc","udt":"geography","not_null":true,"has_default":false,"is_enum":false}],
          "constraints":[]}]}"#;
        let l = lift_catalog(json).expect("valid catalog");
        assert_eq!(
            l.value.entity("t").unwrap().field("loc").unwrap().ty,
            FieldType::Unknown
        );
        assert!(l.defeats_of(DefeatKind::LookedAndBlocked).count() > 0);
    }

    #[test]
    fn array_columns_are_lists_of_their_base_domain() {
        let json = r#"{"tables":[{"name":"t","columns":[
          {"name":"tags","udt":"text[]","not_null":true,"has_default":false,"is_enum":false}],
          "constraints":[]}]}"#;
        let l = lift_catalog(json).expect("valid catalog");
        let f = l.value.entity("t").unwrap().field("tags").unwrap();
        assert!(f.list);
        assert_eq!(f.ty, FieldType::Scalar(ScalarType::Text));
    }
}
