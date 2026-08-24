//! Lowers the neutral data-model waist into PostgreSQL DDL.
//!
//! This target has a property the Prisma target does not: the store validates
//! the output. A round trip through a real database cannot be fooled by a
//! symmetric mistake, because PostgreSQL is an independent implementation
//! sitting in the middle -- it rejects DDL that a matched pair of my own
//! lifter and lowerer would happily agree on.

use std::fmt::Write as _;

use semantics_data_model_v1::{
    DataModel, DefaultOrigin, FieldShape, FieldType, Presence, ScalarType,
};

pub const LOWERING_ID: &str = "org.gooi.lowering.sql_ddl.postgres@1";

/// Fallback type name for an enumeration whose name the waist did not carry.
pub const ENUM_FALLBACK: &str = "gooi_enumeration";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lossy {
    pub subject: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default)]
pub struct Lowered {
    pub ddl: String,
    pub lossy: Vec<Lossy>,
}

fn quote(ident: &str) -> String {
    format!("\"{}\"", ident.replace('"', "\"\""))
}

fn sql_type(ty: FieldType) -> Option<&'static str> {
    Some(match ty {
        FieldType::Scalar(s) => match s {
            ScalarType::Text => "text",
            ScalarType::Integer => "integer",
            ScalarType::BigInteger => "bigint",
            ScalarType::Float => "double precision",
            ScalarType::Decimal => "numeric",
            ScalarType::Boolean => "boolean",
            ScalarType::Timestamp => "timestamp",
            ScalarType::Date => "date",
            ScalarType::Time => "time",
            ScalarType::Json => "jsonb",
            ScalarType::Bytes => "bytea",
            ScalarType::Uuid => "uuid",
            ScalarType::Enumeration => ENUM_FALLBACK,
            ScalarType::Other => "text",
        },
        FieldType::Unknown => return None,
    })
}

/// A store-side default the waist knows exists but cannot describe. The
/// expression is a stand-in chosen to be valid for the column's domain.
/// Renders an authored default as a SQL literal for the column's domain.
/// A bare `now` / `current_date` style token is passed through as a call.
fn store_literal(value: &str, ty: FieldType, list: bool) -> String {
    const CALLS: [&str; 4] = ["now", "current_date", "current_time", "current_timestamp"];
    if CALLS.contains(&value.to_lowercase().as_str()) {
        return match value.to_lowercase().as_str() {
            "now" => "now()".to_owned(),
            other => other.to_uppercase(),
        };
    }
    if list {
        return placeholder_default(ty, true);
    }
    match ty {
        FieldType::Scalar(ScalarType::Integer)
        | FieldType::Scalar(ScalarType::BigInteger)
        | FieldType::Scalar(ScalarType::Float)
        | FieldType::Scalar(ScalarType::Decimal) => value.to_owned(),
        FieldType::Scalar(ScalarType::Boolean) => value.to_lowercase(),
        _ => format!("'{}'", value.replace('\'', "''")),
    }
}

fn placeholder_default(ty: FieldType, list: bool) -> String {
    let base = placeholder_scalar(ty);
    if !list {
        return base.to_owned();
    }
    // An array column needs an array literal; a scalar placeholder is rejected.
    match sql_type(ty) {
        Some(t) => format!("'{{}}'::{t}[]"),
        None => "NULL".to_owned(),
    }
}

fn placeholder_scalar(ty: FieldType) -> &'static str {
    match ty {
        FieldType::Scalar(s) => match s {
            ScalarType::Text | ScalarType::Other => "''::text",
            ScalarType::Integer | ScalarType::BigInteger => "0",
            ScalarType::Float | ScalarType::Decimal => "0",
            ScalarType::Boolean => "false",
            ScalarType::Timestamp => "now()",
            ScalarType::Date => "CURRENT_DATE",
            ScalarType::Time => "CURRENT_TIME",
            ScalarType::Json => "'{}'::jsonb",
            ScalarType::Bytes => "'\\x'::bytea",
            ScalarType::Uuid => "gen_random_uuid()",
            ScalarType::Enumeration => "'PLACEHOLDER'::gooi_enumeration",
        },
        FieldType::Unknown => "NULL",
    }
}

fn column(field: &FieldShape, out: &mut Lowered, entity: &str) -> Option<String> {
    if let Some(e) = field.enumeration.as_ref().filter(|e| !e.members.is_empty()) {
        let mut ty = quote(&e.name);
        if field.list {
            ty.push_str("[]");
        }
        let mut s = format!("  {} {}", quote(&field.name), ty);
        if field.nullable == Presence::Required && !field.list {
            s.push_str(" NOT NULL");
        }
        if field.default == DefaultOrigin::Database {
            let chosen = match field.default_value.as_deref() {
                Some(v) if e.members.iter().any(|m| m == v) => v.to_owned(),
                Some(v) => {
                    out.lossy.push(Lossy {
                        subject: format!("{entity}.{}", field.name),
                        detail: format!("default `{v}` is not a member of `{}`", e.name),
                    });
                    e.members.first().cloned().unwrap_or_default()
                }
                None => {
                    out.lossy.push(Lossy {
                        subject: format!("{entity}.{}", field.name),
                        detail: "a store-side default exists but the waist carries no expression"
                            .to_owned(),
                    });
                    e.members.first().cloned().unwrap_or_default()
                }
            };
            let first = chosen;
            let lit = format!("'{}'::{}", first.replace('\'', "''"), quote(&e.name));
            let _ = write!(
                s,
                " DEFAULT {}",
                if field.list {
                    format!("'{{}}'::{}[]", quote(&e.name))
                } else {
                    lit
                }
            );
        }
        return Some(s);
    }
    let Some(base) = sql_type(field.ty) else {
        out.lossy.push(Lossy {
            subject: format!("{entity}.{}", field.name),
            detail: "field type is unknown and has no store representation".to_owned(),
        });
        return None;
    };
    let mut ty = base.to_owned();
    if field.list {
        ty.push_str("[]");
    }
    let mut s = format!("  {} {}", quote(&field.name), ty);

    // A list column is nullable in a store even when the source authority could
    // not say so; forcing NOT NULL here would assert something not established.
    match field.nullable {
        Presence::Required if !field.list => s.push_str(" NOT NULL"),
        Presence::Required => {
            out.lossy.push(Lossy {
                subject: format!("{entity}.{}", field.name),
                detail: "list field declared required; stores model absence as NULL".to_owned(),
            });
        }
        Presence::Optional => {}
        Presence::Unknown => {
            out.lossy.push(Lossy {
                subject: format!("{entity}.{}", field.name),
                detail: "presence was not established by the source authority".to_owned(),
            });
        }
    }

    match field.default {
        DefaultOrigin::Database => match field.default_value.as_deref() {
            Some(v) => {
                let _ = write!(s, " DEFAULT {}", store_literal(v, field.ty, field.list));
            }
            None => {
                out.lossy.push(Lossy {
                    subject: format!("{entity}.{}", field.name),
                    detail: "a store-side default exists but the waist carries no expression"
                        .to_owned(),
                });
                let _ = write!(s, " DEFAULT {}", placeholder_default(field.ty, field.list));
            }
        },
        // An application-side default is not a store default. Emitting one would
        // move the fact to a layer that did not claim it.
        DefaultOrigin::Application | DefaultOrigin::None | DefaultOrigin::Unknown => {}
    }
    Some(s)
}

pub fn lower_to_postgres_ddl(model: &DataModel) -> Lowered {
    let mut out = Lowered::default();
    let mut s = String::new();

    writeln!(s, "-- generated by {LOWERING_ID}").expect("string write");

    let mut seen_enums: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for f in model.entities.iter().flat_map(|e| &e.fields) {
        if f.ty != FieldType::Scalar(ScalarType::Enumeration) {
            continue;
        }
        match &f.enumeration {
            Some(e) if !e.members.is_empty() => {
                seen_enums.insert(e.name.clone(), e.members.clone());
            }
            _ => {
                out.lossy.push(Lossy {
                    subject: "enumeration".to_owned(),
                    detail: "an enumeration arrived without members; a placeholder is emitted"
                        .to_owned(),
                });
                seen_enums
                    .entry(ENUM_FALLBACK.to_owned())
                    .or_insert_with(|| vec!["PLACEHOLDER".to_owned()]);
            }
        }
    }
    for (name, members) in &seen_enums {
        let labels: Vec<String> = members
            .iter()
            .map(|m| format!("'{}'", m.replace('\'', "''")))
            .collect();
        writeln!(
            s,
            "CREATE TYPE {} AS ENUM ({});",
            quote(name),
            labels.join(", ")
        )
        .expect("string write");
    }

    // Tables first, foreign keys afterwards, so declaration order and reference
    // cycles are both irrelevant.
    for e in &model.entities {
        writeln!(s, "\nCREATE TABLE {} (", quote(&e.name)).expect("string write");
        let mut parts: Vec<String> = Vec::new();
        for f in &e.fields {
            if let Some(c) = column(f, &mut out, &e.name) {
                parts.push(c);
            }
        }
        let identity: Vec<String> = e
            .fields
            .iter()
            .filter(|f| f.identity.is_yes())
            .map(|f| quote(&f.name))
            .collect();
        if !identity.is_empty() {
            parts.push(format!("  PRIMARY KEY ({})", identity.join(", ")));
        } else {
            out.lossy.push(Lossy {
                subject: e.name.clone(),
                detail: "no identity field; the table is emitted without a primary key".to_owned(),
            });
        }
        writeln!(s, "{}\n);", parts.join(",\n")).expect("string write");
    }

    // Uniqueness is emitted as an explicit index rather than an inline table
    // constraint. PostgreSQL folds a UNIQUE constraint that duplicates the
    // primary key, which silently loses a declared fact; it never folds an
    // explicit CREATE UNIQUE INDEX.
    for e in &model.entities {
        for f in e.fields.iter().filter(|f| f.unique.is_yes()) {
            writeln!(
                s,
                "\nCREATE UNIQUE INDEX {} ON {} ({});",
                quote(&format!("{}_{}_key", e.name, f.name)),
                quote(&e.name),
                quote(&f.name)
            )
            .expect("string write");
        }
        for (n, set) in e.unique_sets.iter().enumerate() {
            let cols: Vec<String> = set.iter().map(|c| quote(c)).collect();
            writeln!(
                s,
                "\nCREATE UNIQUE INDEX {} ON {} ({});",
                quote(&format!("{}_uniq_{n}", e.name)),
                quote(&e.name),
                cols.join(", ")
            )
            .expect("string write");
        }
    }

    for (i, rel) in model.relations.iter().enumerate() {
        let Some(from) = model.entity(&rel.from_entity) else {
            out.lossy.push(Lossy {
                subject: format!("{} -> {}", rel.from_entity, rel.to_entity),
                detail: "relation source entity is absent".to_owned(),
            });
            continue;
        };
        let missing: Vec<&String> = rel
            .from_fields
            .iter()
            .filter(|c| from.field(c).is_none())
            .collect();
        if !missing.is_empty() {
            out.lossy.push(Lossy {
                subject: format!("{} -> {}", rel.from_entity, rel.to_entity),
                detail: format!("relation names fields absent from its entity: {missing:?}"),
            });
            continue;
        }
        let to_cols: Vec<String> = if rel.to_fields.is_empty() {
            model
                .entity(&rel.to_entity)
                .map(|t| {
                    t.fields
                        .iter()
                        .filter(|f| f.identity.is_yes())
                        .map(|f| f.name.clone())
                        .collect()
                })
                .unwrap_or_default()
        } else {
            rel.to_fields.clone()
        };
        if to_cols.is_empty() {
            out.lossy.push(Lossy {
                subject: format!("{} -> {}", rel.from_entity, rel.to_entity),
                detail: "no referenced columns and no identity on the target".to_owned(),
            });
            continue;
        }
        let from_cols: Vec<String> = rel.from_fields.iter().map(|c| quote(c)).collect();
        let refs: Vec<String> = to_cols.iter().map(|c| quote(c)).collect();
        writeln!(
            s,
            "\nALTER TABLE {} ADD CONSTRAINT {} FOREIGN KEY ({}) REFERENCES {} ({});",
            quote(&rel.from_entity),
            quote(&format!("fk_{i}_{}", rel.from_entity)),
            from_cols.join(", "),
            quote(&rel.to_entity),
            refs.join(", ")
        )
        .expect("string write");
    }

    out.ddl = s;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use semantics_data_model_v1::{EntityShape, RelationEdge};

    fn f(name: &str, ty: ScalarType) -> FieldShape {
        FieldShape {
            name: name.to_owned(),
            ty: FieldType::Scalar(ty),
            nullable: Presence::Required,
            list: false,
            identity: semantics_data_model_v1::Tri::No,
            unique: semantics_data_model_v1::Tri::No,
            default: DefaultOrigin::None,
            default_value: None,
            enumeration: None,
        }
    }

    #[test]
    fn emits_a_table_with_quoted_identifiers_and_a_primary_key() {
        let mut id = f("id", ScalarType::Uuid);
        id.identity = semantics_data_model_v1::Tri::Yes;
        let m = DataModel {
            entities: vec![EntityShape {
                name: "EnvelopeItem".to_owned(),
                fields: vec![id, f("title", ScalarType::Text)],
                unique_sets: Vec::new(),
            }],
            relations: Vec::new(),
        };
        let out = lower_to_postgres_ddl(&m);
        assert!(out.ddl.contains("CREATE TABLE \"EnvelopeItem\" ("));
        assert!(out.ddl.contains("\"id\" uuid NOT NULL"));
        assert!(out.ddl.contains("PRIMARY KEY (\"id\")"));
    }

    #[test]
    fn foreign_keys_are_emitted_after_all_tables() {
        let mut id = f("id", ScalarType::Text);
        id.identity = semantics_data_model_v1::Tri::Yes;
        let m = DataModel {
            entities: vec![
                EntityShape {
                    name: "b".to_owned(),
                    fields: vec![id.clone(), f("a_id", ScalarType::Text)],
                    unique_sets: Vec::new(),
                },
                EntityShape {
                    name: "a".to_owned(),
                    fields: vec![id],
                    unique_sets: Vec::new(),
                },
            ],
            relations: vec![RelationEdge {
                from_entity: "b".to_owned(),
                from_fields: vec!["a_id".to_owned()],
                to_entity: "a".to_owned(),
                to_fields: vec!["id".to_owned()],
            }],
        };
        let out = lower_to_postgres_ddl(&m);
        let create_b = out.ddl.find("CREATE TABLE \"b\"").expect("table b");
        let alter = out.ddl.find("ALTER TABLE \"b\"").expect("fk");
        assert!(alter > create_b, "constraints must follow table creation");
    }

    #[test]
    fn an_application_default_is_not_moved_into_the_store() {
        let mut x = f("id", ScalarType::Text);
        x.identity = semantics_data_model_v1::Tri::Yes;
        x.default = DefaultOrigin::Application;
        let m = DataModel {
            entities: vec![EntityShape {
                name: "a".to_owned(),
                fields: vec![x],
                unique_sets: Vec::new(),
            }],
            relations: Vec::new(),
        };
        let out = lower_to_postgres_ddl(&m);
        assert!(!out.ddl.contains("DEFAULT"), "{}", out.ddl);
    }

    #[test]
    fn a_declared_unique_survives_even_on_the_identity_field() {
        let mut id = f("id", ScalarType::Text);
        id.identity = semantics_data_model_v1::Tri::Yes;
        id.unique = semantics_data_model_v1::Tri::Yes;
        let m = DataModel {
            entities: vec![EntityShape {
                name: "a".to_owned(),
                fields: vec![id],
                unique_sets: Vec::new(),
            }],
            relations: Vec::new(),
        };
        let out = lower_to_postgres_ddl(&m);
        assert!(out.ddl.contains("PRIMARY KEY (\"id\")"));
        // An explicit index survives alongside the primary key; an inline
        // UNIQUE constraint would be folded away by PostgreSQL.
        assert!(
            out.ddl.contains("CREATE UNIQUE INDEX"),
            "a declared constraint must not be dropped as redundant: {}",
            out.ddl
        );
        assert!(!out.ddl.contains("  UNIQUE ("), "{}", out.ddl);
    }

    #[test]
    fn a_list_default_uses_an_array_literal_not_a_scalar() {
        let mut x = f("scopes", ScalarType::Text);
        x.list = true;
        x.default = DefaultOrigin::Database;
        let m = DataModel {
            entities: vec![EntityShape {
                name: "a".to_owned(),
                fields: vec![x],
                unique_sets: Vec::new(),
            }],
            relations: Vec::new(),
        };
        let out = lower_to_postgres_ddl(&m);
        assert!(out.ddl.contains("'{}'::text[]"), "{}", out.ddl);
        assert!(!out.ddl.contains("''::text "), "{}", out.ddl);
    }

    #[test]
    fn a_required_list_is_reported_rather_than_forced() {
        let mut x = f("tags", ScalarType::Text);
        x.list = true;
        let m = DataModel {
            entities: vec![EntityShape {
                name: "a".to_owned(),
                fields: vec![x],
                unique_sets: Vec::new(),
            }],
            relations: Vec::new(),
        };
        let out = lower_to_postgres_ddl(&m);
        assert!(out.ddl.contains("\"tags\" text[]"));
        assert!(!out.ddl.contains("text[] NOT NULL"));
        assert!(
            out.lossy
                .iter()
                .any(|l| l.detail.contains("absence as NULL"))
        );
    }
}
