//! Lifts a Prisma schema into the neutral data-model waist.
//!
//! Prisma schema text is a declarative authority, so this lift is close to
//! total: there is no control flow to reason about and no intent to recover.
//! What it cannot establish it names as a defeat rather than guessing.
//!
//! The type mapping is derived from Prisma's own documented scalar set. It is
//! deliberately not tuned to agree with any other authority.

use lift_defeasible::{Defeasible, Defeat, DefeatKind};
use semantics_data_model_v1::{
    DataModel, DefaultOrigin, EntityShape, Enumeration, FieldShape, FieldType, Presence,
    RelationEdge, ScalarType, Tri,
};

pub const DEFEATER_SET: &str = "org.gooi.lifter.prisma_schema/defeaters@1";

/// Maps a Prisma scalar type name onto the neutral domain set.
/// Prisma has no dedicated UUID scalar; `String @db.Uuid` is a `String`.
fn scalar(name: &str) -> Option<ScalarType> {
    Some(match name {
        "String" => ScalarType::Text,
        "Boolean" => ScalarType::Boolean,
        "Int" => ScalarType::Integer,
        "BigInt" => ScalarType::BigInteger,
        "Float" => ScalarType::Float,
        "Decimal" => ScalarType::Decimal,
        "DateTime" => ScalarType::Timestamp,
        "Json" => ScalarType::Json,
        "Bytes" => ScalarType::Bytes,
        _ => return None,
    })
}

/// Prisma's scalar set is coarser than some stores'. A `@db.*` native-type
/// attribute carries the finer domain and is part of the authority, so it is
/// read rather than discarded.
fn refine_native(base: ScalarType, attrs: &str) -> ScalarType {
    if attrs.contains("@db.Uuid") {
        return ScalarType::Uuid;
    }
    base
}

/// Prisma defaults split by who generates the value. `cuid()`/`uuid()` and
/// friends are produced by the client; `now()`/`autoincrement()`/`dbgenerated()`
/// and literals are produced by the store.
fn default_origin(attrs: &str) -> DefaultOrigin {
    if !attrs.contains("@default") {
        return DefaultOrigin::None;
    }
    // `dbgenerated(...)` is explicitly store-side and can wrap a function whose
    // name looks client-side, e.g. dbgenerated("gen_random_uuid()"), so it is
    // decided before any name matching.
    if attrs.contains("dbgenerated(") {
        return DefaultOrigin::Database;
    }
    const APPLICATION: [&str; 5] = ["cuid(", "uuid(", "ulid(", "nanoid(", "auto("];
    if APPLICATION.iter().any(|f| attrs.contains(f)) {
        DefaultOrigin::Application
    } else {
        DefaultOrigin::Database
    }
}

#[derive(Debug)]
struct RawField {
    name: String,
    type_name: String,
    list: bool,
    optional: bool,
    attrs: String,
}

#[derive(Debug)]
struct RawModel {
    name: String,
    fields: Vec<RawField>,
    block_attrs: Vec<String>,
}

fn strip_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Extracts a bracketed identifier list, e.g. `fields: [a, b]` -> ["a","b"].
fn bracket_list(attrs: &str, key: &str) -> Vec<String> {
    let Some(start) = attrs.find(key) else {
        return Vec::new();
    };
    let rest = &attrs[start + key.len()..];
    let Some(open) = rest.find('[') else {
        return Vec::new();
    };
    let Some(close) = rest[open..].find(']') else {
        return Vec::new();
    };
    rest[open + 1..open + close]
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Every `@@unique([...])` list declared on a model, at any arity.
fn compound_uniques_all(block_attrs: &[String]) -> Vec<Vec<String>> {
    block_attrs
        .iter()
        .filter(|a| a.starts_with("@@unique"))
        .map(|a| bracket_list(a, "@@unique"))
        .filter(|v| !v.is_empty())
        .collect()
}

fn quoted_arg(attrs: &str, key: &str) -> Option<String> {
    let start = attrs.find(key)?;
    let rest = &attrs[start + key.len()..];
    let open = rest.find('"')?;
    let close = rest[open + 1..].find('"')?;
    Some(rest[open + 1..open + 1 + close].to_owned())
}

pub fn lift_prisma_schema(source: &str) -> Defeasible<DataModel> {
    let mut lifted = Defeasible::new(DataModel::default(), DEFEATER_SET);

    // (declared name, enumeration as the store sees it)
    let mut enums: Vec<(String, Enumeration)> = Vec::new();
    let mut models: Vec<RawModel> = Vec::new();
    let mut relation_mode: Option<String> = None;

    // --- block scan ---
    let mut cursor: Option<RawModel> = None;
    let mut block: Option<&'static str> = None;
    for raw_line in source.lines() {
        let line = strip_comment(raw_line);
        let t = line.trim();
        if t.is_empty() {
            continue;
        }

        if cursor.is_none() && block.is_none() {
            let mut w = t.split_whitespace();
            match (w.next(), w.next()) {
                (Some("model"), Some(name)) => {
                    cursor = Some(RawModel {
                        name: name.trim_end_matches('{').to_owned(),
                        fields: Vec::new(),
                        block_attrs: Vec::new(),
                    });
                }
                (Some("enum"), Some(name)) => {
                    let declared = name.trim_end_matches('{').to_owned();
                    enums.push((
                        declared.clone(),
                        Enumeration {
                            name: declared,
                            members: Vec::new(),
                        },
                    ));
                    block = Some("enum");
                }
                (Some("datasource"), _) => block = Some("datasource"),
                (Some("generator"), _) => block = Some("generator"),
                (Some("type"), Some(name)) => {
                    lifted.defeat(Defeat::new(
                        DefeatKind::LookedAndBlocked,
                        format!("type {}", name.trim_end_matches('{')),
                        "composite type blocks are not modeled by this lifter",
                    ));
                    block = Some("type");
                }
                (Some("view"), Some(name)) => {
                    lifted.defeat(Defeat::new(
                        DefeatKind::LookedAndBlocked,
                        format!("view {}", name.trim_end_matches('{')),
                        "view blocks are not modeled by this lifter",
                    ));
                    block = Some("view");
                }
                _ => {}
            }
            continue;
        }

        if t.starts_with('}') {
            if let Some(m) = cursor.take() {
                models.push(m);
            }
            block = None;
            continue;
        }

        if let Some(kind) = block {
            if kind == "enum" {
                // An enum is renamed by @@map exactly like a model is. Members
                // are bare identifiers; attribute lines are not.
                if t.starts_with("@@map") {
                    if let (Some(mapped), Some(e)) = (quoted_arg(t, "@@map"), enums.last_mut()) {
                        e.1.name = mapped;
                    }
                } else if let (Some(member), Some(e)) = (
                    t.split_whitespace().next().filter(|m| !m.starts_with('@')),
                    enums.last_mut(),
                ) {
                    e.1.members.push(member.to_owned());
                }
            }
            if kind == "datasource" && t.starts_with("relationMode") {
                relation_mode = t
                    .split('=')
                    .nth(1)
                    .map(|v| v.trim().trim_matches('"').to_owned());
            }
            continue;
        }

        let Some(model) = cursor.as_mut() else {
            continue;
        };

        if t.starts_with("@@") {
            model.block_attrs.push(t.to_owned());
            continue;
        }

        let mut parts = t.split_whitespace();
        let Some(name) = parts.next() else { continue };
        let Some(type_token) = parts.next() else {
            lifted.defeat(Defeat::new(
                DefeatKind::LookedAndBlocked,
                format!("{}.{name}", model.name),
                "field line has no type token",
            ));
            continue;
        };
        let attrs = parts.collect::<Vec<_>>().join(" ");
        let list = type_token.contains("[]");
        let base = type_token.trim_end_matches('?').trim_end_matches("[]");
        let optional =
            type_token.ends_with('?') || type_token.trim_end_matches("[]").ends_with('?');
        model.fields.push(RawField {
            name: name.to_owned(),
            type_name: base.trim_end_matches('?').to_owned(),
            list,
            optional,
            attrs,
        });
    }
    if let Some(m) = cursor.take() {
        models.push(m);
    }

    if relation_mode.as_deref() == Some("prisma") {
        lifted.defeat(Defeat::new(
            DefeatKind::OutOfScope,
            "datasource.relationMode",
            "relationMode=\"prisma\": relations are not enforced in the database, \
             so a catalog authority cannot corroborate them",
        ));
    }

    let model_names: Vec<String> = models.iter().map(|m| m.name.clone()).collect();
    let is_model = |n: &str| model_names.iter().any(|m| m == n);
    // A relation names a *model*; the waist names entities by their mapped name,
    // so the target must be resolved the same way the entity itself was.
    // Field names inside @relation(fields:/references:) name *model fields*; the
    // waist names fields by their mapped storage name, so they must be resolved
    // the same way. Leaving them raw makes a relation point at a field name the
    // entity does not have -- an inconsistency a symmetric round trip cannot see.
    let mapped_fields = |model: &str, names: &[String]| -> Vec<String> {
        let Some(m) = models.iter().find(|m| m.name == model) else {
            return names.to_vec();
        };
        names
            .iter()
            .map(|n| {
                m.fields
                    .iter()
                    .find(|f| &f.name == n)
                    .and_then(|f| quoted_arg(&f.attrs, "@map"))
                    .unwrap_or_else(|| n.clone())
            })
            .collect()
    };
    let mapped_name = |model: &str| -> String {
        models
            .iter()
            .find(|m| m.name == model)
            .and_then(|m| {
                m.block_attrs
                    .iter()
                    .find(|a| a.starts_with("@@map"))
                    .and_then(|a| quoted_arg(a, "@@map"))
            })
            .unwrap_or_else(|| model.to_owned())
    };
    let find_enum = |n: &str| {
        enums
            .iter()
            .find(|(declared, _)| declared == n)
            .map(|(_, e)| e.clone())
    };

    // --- project into the waist ---
    let mut out = DataModel::default();
    for m in &models {
        if m.block_attrs.iter().any(|a| a.starts_with("@@ignore")) {
            lifted.defeat(Defeat::new(
                DefeatKind::OutOfScope,
                m.name.clone(),
                "model is marked @@ignore",
            ));
            continue;
        }
        let entity_name = m
            .block_attrs
            .iter()
            .find_map(|a| a.strip_prefix("@@map").and_then(|_| quoted_arg(a, "@@map")))
            .unwrap_or_else(|| m.name.clone());

        let compound_id = m
            .block_attrs
            .iter()
            .find(|a| a.starts_with("@@id"))
            .map(|a| bracket_list(a, "@@id"))
            .unwrap_or_default();
        let compound_uniques: Vec<Vec<String>> = m
            .block_attrs
            .iter()
            .filter(|a| a.starts_with("@@unique"))
            .map(|a| bracket_list(a, "@@unique"))
            .collect();

        // A single-element @@unique([x]) constrains one field, so it is a field
        // property; only multi-element sets are set properties.
        let singleton_uniques: Vec<String> = compound_uniques_all(&m.block_attrs)
            .into_iter()
            .filter(|u| u.len() == 1)
            .flatten()
            .collect();

        let mut fields = Vec::new();
        for f in &m.fields {
            // A reference to another model is an edge, never a field.
            if is_model(&f.type_name) {
                let from_fields = bracket_list(&f.attrs, "fields:");
                let to_fields = bracket_list(&f.attrs, "references:");
                if !from_fields.is_empty() {
                    out.relations.push(RelationEdge {
                        from_entity: entity_name.clone(),
                        from_fields: mapped_fields(&m.name, &from_fields),
                        to_entity: mapped_name(&f.type_name),
                        to_fields: mapped_fields(&f.type_name, &to_fields),
                    });
                } else if f.list {
                    // Either the inverse of a 1-n, or an implicit m-n whose join
                    // table this authority never names.
                    let inverse_owns = models
                        .iter()
                        .find(|o| o.name == f.type_name)
                        .map(|o| {
                            o.fields.iter().any(|of| {
                                of.type_name == m.name
                                    && !bracket_list(&of.attrs, "fields:").is_empty()
                            })
                        })
                        .unwrap_or(false);
                    if !inverse_owns {
                        lifted.defeat(Defeat::new(
                            DefeatKind::AuthorityCannotExpress,
                            format!("{}.{}", m.name, f.name),
                            "implicit many-to-many relation: its join table is not named \
                             in the schema",
                        ));
                    }
                }
                continue;
            }

            let ty = if let Some(s) = scalar(&f.type_name) {
                FieldType::Scalar(refine_native(s, &f.attrs))
            } else if find_enum(&f.type_name).is_some() {
                FieldType::Scalar(ScalarType::Enumeration)
            } else if f.type_name.starts_with("Unsupported") {
                lifted.defeat(Defeat::new(
                    DefeatKind::AuthorityCannotExpress,
                    format!("{}.{}", m.name, f.name),
                    "Unsupported(...) native type has no neutral domain",
                ));
                FieldType::Scalar(ScalarType::Other)
            } else {
                lifted.defeat(Defeat::new(
                    DefeatKind::LookedAndBlocked,
                    format!("{}.{}", m.name, f.name),
                    format!("unrecognized type `{}`", f.type_name),
                ));
                FieldType::Unknown
            };

            let field_name = quoted_arg(&f.attrs, "@map").unwrap_or_else(|| f.name.clone());
            fields.push(FieldShape {
                name: field_name,
                ty,
                // Prisma list fields collapse null and empty, so presence is
                // not expressible for them.
                nullable: if f.list {
                    Presence::Unknown
                } else if f.optional {
                    Presence::Optional
                } else {
                    Presence::Required
                },
                list: f.list,
                identity: Tri::known(f.attrs.contains("@id") || compound_id.contains(&f.name)),
                unique: Tri::known(
                    f.attrs.contains("@unique") || singleton_uniques.contains(&f.name),
                ),
                default: default_origin(&f.attrs),
                enumeration: find_enum(&f.type_name),
            });
        }
        // Field names inside @@unique refer to model fields; map them the way the
        // fields themselves were mapped.
        let field_map = |fname: &str| -> String {
            m.fields
                .iter()
                .find(|f| f.name == fname)
                .and_then(|f| quoted_arg(&f.attrs, "@map"))
                .unwrap_or_else(|| fname.to_owned())
        };
        let unique_sets: Vec<Vec<String>> = compound_uniques
            .iter()
            .filter(|u| u.len() > 1)
            .map(|u| u.iter().map(|c| field_map(c)).collect())
            .collect();
        // Prisma's engine derives a unique index for the foreign key of a
        // one-to-one relation. That derivation belongs to Prisma, not here:
        // reproducing it produced false positives against the catalog (a
        // relation key that is also the primary key is identity, not a separate
        // unique constraint). The gap is named instead of guessed.
        for f in m.fields.iter().filter(|f| is_model(&f.type_name)) {
            if bracket_list(&f.attrs, "fields:").is_empty() {
                continue;
            }
            let inverse_singular = models
                .iter()
                .find(|o| o.name == f.type_name)
                .map(|o| {
                    o.fields.iter().any(|of| {
                        of.type_name == m.name
                            && !of.list
                            && bracket_list(&of.attrs, "fields:").is_empty()
                    })
                })
                .unwrap_or(false);
            if inverse_singular {
                lifted.defeat(Defeat::new(
                    DefeatKind::LookedAndBlocked,
                    format!("{}.{}", m.name, f.name),
                    "uniqueness implied by a one-to-one relation is derived by Prisma's \
                     engine and is not re-derived here",
                ));
            }
        }
        out.entities.push(EntityShape {
            name: entity_name,
            fields,
            unique_sets,
        });
    }

    if out.entities.is_empty() {
        lifted.defeat(Defeat::new(
            DefeatKind::SubjectUnresolvable,
            "schema",
            "no model blocks were found",
        ));
    }

    lifted.value = out;
    lifted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifts_entities_fields_and_owning_edges() {
        let src = r#"
model User {
  id    String @id @default(cuid())
  email String @unique
  posts Post[]
}
model Post {
  id       String @id
  title    String
  authorId String
  author   User   @relation(fields: [authorId], references: [id])
}
"#;
        let l = lift_prisma_schema(src);
        assert!(l.is_exhaustive(), "unexpected defeats: {:?}", l.defeats);
        assert_eq!(l.value.entity_names(), vec!["post", "user"]);
        // the relation field is not storage; the foreign key is
        let post = l.value.entity("Post").unwrap();
        assert!(post.field("author").is_none());
        assert!(post.field("authorId").is_some());
        // Post.id declares no default; User.id declares a client-generated one.
        assert_eq!(post.field("id").unwrap().default, DefaultOrigin::None);
        let user = l.value.entity("User").unwrap();
        assert_eq!(
            user.field("id").unwrap().default,
            DefaultOrigin::Application
        );
        assert_eq!(l.value.relations.len(), 1);
        assert_eq!(l.value.relations[0].to_entity, "User");
        // the relation must name fields that actually exist on the entities
        for c in &l.value.relations[0].from_fields {
            assert!(
                post.field(c).is_some(),
                "relation names a missing field {c}"
            );
        }
    }

    #[test]
    fn implicit_many_to_many_is_a_named_defeat_not_a_guess() {
        let src = r#"
model Post { id String @id
  tags Tag[] }
model Tag { id String @id
  posts Post[] }
"#;
        let l = lift_prisma_schema(src);
        assert!(!l.is_exhaustive());
        assert!(
            l.defeats_of(DefeatKind::AuthorityCannotExpress)
                .any(|d| d.reason.contains("join table"))
        );
    }

    #[test]
    fn relation_mode_prisma_is_recorded_as_scope_loss() {
        let src = r#"
datasource db {
  provider = "postgresql"
  relationMode = "prisma"
}
model A { id String @id }
"#;
        let l = lift_prisma_schema(src);
        assert!(
            l.defeats_of(DefeatKind::OutOfScope)
                .any(|d| d.subject.contains("relationMode"))
        );
    }

    #[test]
    fn relation_field_names_are_mapped_like_the_fields_they_name() {
        let src = r#"
model Post {
  id       String @id
  authorId String @map("author_id")
  author   User   @relation(fields: [authorId], references: [userId])
}
model User {
  userId String @id @map("user_id")
  posts  Post[]
}
"#;
        let l = lift_prisma_schema(src);
        let r = &l.value.relations[0];
        assert_eq!(r.from_fields, vec!["author_id".to_owned()]);
        assert_eq!(r.to_fields, vec!["user_id".to_owned()]);
        assert!(l.value.entity("Post").unwrap().field("author_id").is_some());
        assert!(l.value.entity("User").unwrap().field("user_id").is_some());
    }

    #[test]
    fn single_element_block_unique_is_a_field_property() {
        let src = "model Session {\n  id String @id\n  token String\n  @@unique([token])\n}\n";
        let l = lift_prisma_schema(src);
        assert!(
            l.value
                .entity("Session")
                .unwrap()
                .field("token")
                .unwrap()
                .unique
                .is_yes()
        );
        assert!(l.value.entity("Session").unwrap().unique_sets.is_empty());
    }

    #[test]
    fn one_to_one_uniqueness_is_named_as_a_gap_not_inferred() {
        let src = r#"
model Item {
  id     String @id
  dataId String
  data   Data   @relation(fields: [dataId], references: [id])
}
model Data {
  id   String @id
  item Item?
}
"#;
        let l = lift_prisma_schema(src);
        assert!(
            !l.value
                .entity("Item")
                .unwrap()
                .field("dataId")
                .unwrap()
                .unique
                .is_yes()
        );
        assert!(
            l.defeats_of(DefeatKind::LookedAndBlocked)
                .any(|d| d.subject == "Item.data")
        );
    }

    #[test]
    fn one_to_many_foreign_key_is_not_unique() {
        let src = r#"
model Post {
  id       String @id
  authorId String
  author   User   @relation(fields: [authorId], references: [id])
}
model User {
  id    String @id
  posts Post[]
}
"#;
        let l = lift_prisma_schema(src);
        assert!(
            !l.value
                .entity("Post")
                .unwrap()
                .field("authorId")
                .unwrap()
                .unique
                .is_yes()
        );
    }

    #[test]
    fn an_enum_is_renamed_by_its_own_map_attribute() {
        let src = r#"
enum PollStatus {
  open
  closed
  @@map("poll_status")
}
model Poll {
  id     String     @id
  status PollStatus
}
"#;
        let l = lift_prisma_schema(src);
        let e = l
            .value
            .entity("Poll")
            .unwrap()
            .field("status")
            .unwrap()
            .enumeration
            .clone()
            .expect("enumeration carried");
        assert_eq!(e.name, "poll_status", "the store-side name must be used");
        assert_eq!(e.members, vec!["open".to_owned(), "closed".to_owned()]);
    }

    #[test]
    fn map_attributes_rename_entities_and_fields() {
        let src = r#"
model User {
  emailAddress String @map("email_address")
  @@map("users")
}
"#;
        let l = lift_prisma_schema(src);
        assert!(l.value.entity("users").is_some());
        assert!(
            l.value
                .entity("users")
                .unwrap()
                .field("email_address")
                .is_some()
        );
    }

    #[test]
    fn unrecognized_type_degrades_to_unknown() {
        let src = "model A {\n  id String @id\n  weird Mystery\n}\n";
        let l = lift_prisma_schema(src);
        assert!(!l.is_exhaustive());
        let a = l.value.entity("A").unwrap();
        assert_eq!(a.field("weird").unwrap().ty, FieldType::Unknown);
    }
}
