//! A hand-writable surface for the neutral data-model waist.
//!
//! Every other way into the waist requires software that already exists. This
//! is the front door for someone who has none: a few lines of text, no
//! contracts, no vocabulary to learn beyond the field types themselves.
//!
//! ```text
//! entity User
//!   id        uuid       pk = uuid
//!   email     text       unique
//!   name      text?
//!   role      enum Role(admin, member) = admin
//!   createdAt timestamp  = now
//!
//! entity Post
//!   id       uuid  pk = uuid
//!   title    text
//!   authorId -> User
//!   unique(title, authorId)
//! ```
//!
//! The syntax is deliberately thin: it names exactly what the waist carries and
//! nothing more, so it cannot drift into a second vocabulary.

use lift_defeasible::{Defeasible, Defeat, DefeatKind};
use semantics_data_model_v1::{
    DataModel, DefaultOrigin, EntityShape, Enumeration, FieldShape, FieldType, Presence,
    RelationEdge, ScalarType, Tri,
};

pub const DEFEATER_SET: &str = "org.gooi.authoring.entity_spec/defeaters@1";

fn scalar(name: &str) -> Option<ScalarType> {
    Some(match name {
        "text" | "string" => ScalarType::Text,
        "integer" | "int" => ScalarType::Integer,
        "bigint" => ScalarType::BigInteger,
        "float" => ScalarType::Float,
        "decimal" => ScalarType::Decimal,
        "boolean" | "bool" => ScalarType::Boolean,
        "timestamp" => ScalarType::Timestamp,
        "date" => ScalarType::Date,
        "time" => ScalarType::Time,
        "json" => ScalarType::Json,
        "bytes" => ScalarType::Bytes,
        "uuid" => ScalarType::Uuid,
        _ => return None,
    })
}

fn scalar_name(t: ScalarType) -> &'static str {
    match t {
        ScalarType::Text => "text",
        ScalarType::Integer => "integer",
        ScalarType::BigInteger => "bigint",
        ScalarType::Float => "float",
        ScalarType::Decimal => "decimal",
        ScalarType::Boolean => "boolean",
        ScalarType::Timestamp => "timestamp",
        ScalarType::Date => "date",
        ScalarType::Time => "time",
        ScalarType::Json => "json",
        ScalarType::Bytes => "bytes",
        ScalarType::Uuid => "uuid",
        ScalarType::Enumeration => "enum",
        ScalarType::Other => "text",
    }
}

/// `now` and `autoincrement` are produced by the store; `uuid` and `cuid` by the
/// writing application. Anything else is treated as a store-side expression.
fn default_origin(token: &str) -> DefaultOrigin {
    match token {
        "uuid" | "cuid" | "ulid" | "nanoid" => DefaultOrigin::Application,
        _ => DefaultOrigin::Database,
    }
}

fn default_token(origin: DefaultOrigin) -> Option<&'static str> {
    match origin {
        DefaultOrigin::Application => Some("uuid"),
        DefaultOrigin::Database => Some("now"),
        DefaultOrigin::None | DefaultOrigin::Unknown => None,
    }
}

struct Pending {
    entity: String,
    field: String,
    target: String,
    explicit_type: Option<ScalarType>,
}

/// Splits `enum Name(a, b)` or `enum(a, b)` out of a token stream.
fn parse_enum(rest: &str, entity: &str, field: &str) -> Option<Enumeration> {
    let rest = rest.trim();
    let after = rest.strip_prefix("enum")?;
    let open = after.find('(')?;
    let close = after.find(')')?;
    let name = after[..open].trim();
    let name = if name.is_empty() {
        format!("{}_{}", entity.to_lowercase(), field.to_lowercase())
    } else {
        name.to_owned()
    };
    let members: Vec<String> = after[open + 1..close]
        .split(',')
        .map(|m| m.trim().to_owned())
        .filter(|m| !m.is_empty())
        .collect();
    Some(Enumeration { name, members })
}

pub fn parse_entity_spec(source: &str) -> Defeasible<DataModel> {
    let mut lifted = Defeasible::new(DataModel::default(), DEFEATER_SET);
    let mut model = DataModel::default();
    let mut pending: Vec<Pending> = Vec::new();
    let mut current: Option<usize> = None;

    for (lineno, raw) in source.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("");
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let at = |what: &str| format!("line {}: {what}", lineno + 1);

        if let Some(name) = t.strip_prefix("entity ") {
            let name = name.trim();
            if name.is_empty() {
                lifted.defeat(Defeat::new(
                    DefeatKind::LookedAndBlocked,
                    at("entity"),
                    "entity declaration has no name",
                ));
                continue;
            }
            model.entities.push(EntityShape {
                name: name.to_owned(),
                fields: Vec::new(),
                unique_sets: Vec::new(),
            });
            current = Some(model.entities.len() - 1);
            continue;
        }

        let Some(index) = current else {
            lifted.defeat(Defeat::new(
                DefeatKind::LookedAndBlocked,
                at(t),
                "field appears before any entity declaration",
            ));
            continue;
        };

        // entity-level: unique(a, b)
        if let Some(inner) = t.strip_prefix("unique(").and_then(|s| s.strip_suffix(')')) {
            let cols: Vec<String> = inner
                .split(',')
                .map(|c| c.trim().to_owned())
                .filter(|c| !c.is_empty())
                .collect();
            if cols.len() < 2 {
                lifted.defeat(Defeat::new(
                    DefeatKind::LookedAndBlocked,
                    at(t),
                    "unique(...) needs at least two fields; use `unique` on the field itself",
                ));
            } else {
                model.entities[index].unique_sets.push(cols);
            }
            continue;
        }

        let mut words = t.split_whitespace();
        let Some(fname) = words.next() else { continue };
        let remainder = t[fname.len()..].trim();

        // relation: `authorId -> User` or `authorId uuid -> User`
        if let Some(arrow) = remainder.find("->") {
            let before = remainder[..arrow].trim();
            let target = remainder[arrow + 2..].trim().to_owned();
            if target.is_empty() {
                lifted.defeat(Defeat::new(
                    DefeatKind::LookedAndBlocked,
                    at(t),
                    "relation names no target entity",
                ));
                continue;
            }
            pending.push(Pending {
                entity: model.entities[index].name.clone(),
                field: fname.to_owned(),
                target,
                explicit_type: before.split_whitespace().next().and_then(scalar),
            });
            continue;
        }

        let Some(type_token) = words.next() else {
            lifted.defeat(Defeat::new(
                DefeatKind::LookedAndBlocked,
                at(t),
                "field has no type",
            ));
            continue;
        };

        let optional =
            type_token.ends_with('?') || type_token.trim_end_matches("[]").ends_with('?');
        let list = type_token.contains("[]");
        let base = type_token
            .trim_end_matches('?')
            .trim_end_matches("[]")
            .trim_end_matches('?');

        let modifiers = remainder[remainder
            .find(type_token)
            .map(|i| i + type_token.len())
            .unwrap_or(0)..]
            .trim();
        let default_text = modifiers
            .split('=')
            .nth(1)
            .and_then(|d| d.split_whitespace().next())
            .map(str::to_owned);
        let default = default_text
            .as_deref()
            .map(default_origin)
            .unwrap_or(DefaultOrigin::None);
        let flags = modifiers.split('=').next().unwrap_or("");

        let enumeration = if base == "enum" {
            let e = parse_enum(remainder, &model.entities[index].name, fname);
            if e.is_none() {
                lifted.defeat(Defeat::new(
                    DefeatKind::LookedAndBlocked,
                    at(t),
                    "enum needs members, as enum(a, b)",
                ));
            }
            e
        } else {
            None
        };

        let ty = if enumeration.is_some() {
            FieldType::Scalar(ScalarType::Enumeration)
        } else {
            match scalar(base) {
                Some(s) => FieldType::Scalar(s),
                None => {
                    lifted.defeat(Defeat::new(
                        DefeatKind::LookedAndBlocked,
                        at(t),
                        format!("unknown type `{base}`"),
                    ));
                    FieldType::Unknown
                }
            }
        };

        model.entities[index].fields.push(FieldShape {
            name: fname.to_owned(),
            ty,
            nullable: if list {
                Presence::Unknown
            } else if optional {
                Presence::Optional
            } else {
                Presence::Required
            },
            list,
            identity: Tri::known(flags.split_whitespace().any(|w| w == "pk")),
            unique: Tri::known(flags.split_whitespace().any(|w| w == "unique")),
            default,
            default_value: default_text,
            enumeration,
        });
    }

    // Relations resolve once every entity is known.
    for p in pending {
        let target_identity = model
            .entity(&p.target)
            .map(|t| {
                t.fields
                    .iter()
                    .filter(|f| f.identity.is_yes())
                    .map(|f| (f.name.clone(), f.ty))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if target_identity.is_empty() {
            lifted.defeat(Defeat::new(
                DefeatKind::SubjectUnresolvable,
                format!("{}.{}", p.entity, p.field),
                format!("`{}` has no `pk` field to reference", p.target),
            ));
            continue;
        }
        if target_identity.len() > 1 {
            lifted.defeat(Defeat::new(
                DefeatKind::LookedAndBlocked,
                format!("{}.{}", p.entity, p.field),
                format!(
                    "`{}` has a composite key; name the columns explicitly",
                    p.target
                ),
            ));
            continue;
        }
        let (ref_field, ref_ty) = target_identity.into_iter().next().expect("one identity");
        let ty = p.explicit_type.map(FieldType::Scalar).unwrap_or(ref_ty);
        let Some(owner) = model.entities.iter_mut().find(|e| e.name == p.entity) else {
            continue;
        };
        owner.fields.push(FieldShape {
            name: p.field.clone(),
            ty,
            nullable: Presence::Required,
            list: false,
            identity: Tri::No,
            unique: Tri::No,
            default: DefaultOrigin::None,
            default_value: None,
            enumeration: None,
        });
        model.relations.push(RelationEdge {
            from_entity: p.entity,
            from_fields: vec![p.field],
            to_entity: p.target,
            to_fields: vec![ref_field],
        });
    }

    if model.entities.is_empty() {
        lifted.defeat(Defeat::new(
            DefeatKind::SubjectUnresolvable,
            "spec",
            "no entity declarations were found",
        ));
    }
    for e in &model.entities {
        if !e.fields.iter().any(|f| f.identity.is_yes()) {
            lifted.defeat(Defeat::new(
                DefeatKind::LookedAndBlocked,
                e.name.clone(),
                "entity has no `pk` field; it cannot be addressed individually",
            ));
        }
    }

    lifted.value = model;
    lifted
}

/// Renders a waist back into the authoring surface, so the format round-trips.
pub fn emit_entity_spec(model: &DataModel) -> String {
    let mut out = String::new();
    for e in &model.entities {
        out.push_str(&format!("entity {}\n", e.name));
        let relation_fields: Vec<&String> = model
            .relations
            .iter()
            .filter(|r| r.from_entity == e.name)
            .flat_map(|r| &r.from_fields)
            .collect();
        for f in &e.fields {
            if relation_fields.contains(&&f.name) {
                continue;
            }
            let mut ty = match &f.enumeration {
                Some(en) => format!("enum {}({})", en.name, en.members.join(", ")),
                None => scalar_name(match f.ty {
                    FieldType::Scalar(s) => s,
                    FieldType::Unknown => ScalarType::Text,
                })
                .to_owned(),
            };
            if f.list {
                ty.push_str("[]");
            } else if f.nullable == Presence::Optional {
                ty.push('?');
            }
            let mut mods = String::new();
            if f.identity.is_yes() {
                mods.push_str(" pk");
            }
            if f.unique.is_yes() {
                mods.push_str(" unique");
            }
            // Prefer the authored text; fall back to a token naming the origin.
            if let Some(d) = f
                .default_value
                .clone()
                .or_else(|| default_token(f.default).map(str::to_owned))
            {
                mods.push_str(&format!(" = {d}"));
            }
            out.push_str(&format!("  {} {}{}\n", f.name, ty, mods));
        }
        for r in model.relations.iter().filter(|r| r.from_entity == e.name) {
            for c in &r.from_fields {
                out.push_str(&format!("  {} -> {}\n", c, r.to_entity));
            }
        }
        for set in &e.unique_sets {
            out.push_str(&format!("  unique({})\n", set.join(", ")));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = r#"
# a small application
entity User
  id        uuid   pk = uuid
  email     text   unique
  name      text?
  role      enum Role(admin, member) = now
  createdAt timestamp = now

entity Post
  id       uuid  pk = uuid
  title    text
  views    integer
  authorId -> User
  unique(title, views)
"#;

    #[test]
    fn a_few_lines_of_text_become_a_model() {
        let s = parse_entity_spec(SPEC);
        assert!(s.is_exhaustive(), "unexpected defeats: {:?}", s.defeats);
        assert_eq!(s.value.entity_names(), vec!["post", "user"]);
        let u = s.value.entity("User").unwrap();
        assert!(u.field("id").unwrap().identity.is_yes());
        assert_eq!(u.field("id").unwrap().default, DefaultOrigin::Application);
        assert!(u.field("email").unwrap().unique.is_yes());
        assert_eq!(u.field("name").unwrap().nullable, Presence::Optional);
        let role = u.field("role").unwrap().enumeration.clone().unwrap();
        assert_eq!(role.name, "Role");
        assert_eq!(role.members, vec!["admin".to_owned(), "member".to_owned()]);
    }

    #[test]
    fn a_relation_takes_its_type_from_the_target_key() {
        let s = parse_entity_spec(SPEC);
        let p = s.value.entity("Post").unwrap();
        assert_eq!(
            p.field("authorId").unwrap().ty,
            FieldType::Scalar(ScalarType::Uuid),
            "the foreign key matches User.id"
        );
        assert_eq!(s.value.relations.len(), 1);
        assert_eq!(s.value.relations[0].to_fields, vec!["id".to_owned()]);
    }

    #[test]
    fn compound_uniqueness_is_read() {
        let s = parse_entity_spec(SPEC);
        assert_eq!(
            s.value.entity("Post").unwrap().unique_sets,
            vec![vec!["title".to_owned(), "views".to_owned()]]
        );
    }

    #[test]
    fn a_relation_to_a_keyless_entity_is_refused_not_guessed() {
        let s = parse_entity_spec("entity A\n  name text\nentity B\n  aId -> A\n");
        assert!(
            s.defeats_of(DefeatKind::SubjectUnresolvable)
                .any(|d| d.reason.contains("no `pk`"))
        );
        assert!(s.value.relations.is_empty());
    }

    #[test]
    fn an_unknown_type_is_named_not_silently_accepted() {
        let s = parse_entity_spec("entity A\n  id uuid pk\n  weird geography\n");
        assert!(
            s.defeats_of(DefeatKind::LookedAndBlocked)
                .any(|d| d.reason.contains("geography"))
        );
    }

    #[test]
    fn the_format_round_trips_through_itself() {
        let first = parse_entity_spec(SPEC).value;
        let text = emit_entity_spec(&first);
        let second = parse_entity_spec(&text).value;
        assert_eq!(first.entity_names(), second.entity_names());
        for e in &first.entities {
            let other = second.entity(&e.name).expect("entity survives");
            assert_eq!(e.fields.len(), other.fields.len(), "{}", e.name);
            for f in &e.fields {
                assert_eq!(Some(f), other.field(&f.name), "{}.{}", e.name, f.name);
            }
            assert_eq!(e.unique_sets, other.unique_sets, "{}", e.name);
        }
        assert_eq!(first.relations, second.relations);
    }
}
