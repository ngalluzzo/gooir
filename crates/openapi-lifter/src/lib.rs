//! Lifts an OpenAPI document's resource schemas into the neutral waist.
//!
//! An API document is an authority about shapes, not about storage. It has no
//! notion of a primary key, a unique constraint, a default, or a relation, so
//! this lifter reports those as defeats rather than as absences. That is the
//! whole point of running it: it establishes what a document-shaped authority
//! is and is not able to say.
//!
//! The resource set is derived from the document's own structure -- the item
//! type of each collection response -- rather than from a naming convention.

use lift_defeasible::{Defeasible, Defeat, DefeatKind};
use semantics_data_model_v1::{
    DataModel, DefaultOrigin, EntityShape, Enumeration, FieldShape, FieldType, Presence,
    ScalarType, Tri,
};
use serde_json::Value;

pub const DEFEATER_SET: &str = "org.gooi.lifter.openapi/defeaters@1";

fn ref_name(v: &Value) -> Option<String> {
    v.get("$ref")?
        .as_str()?
        .rsplit('/')
        .next()
        .map(str::to_owned)
}

/// Types present in a JSON Schema `type` keyword, and whether null is among them.
fn types(schema: &Value) -> (Vec<String>, bool) {
    match schema.get("type") {
        Some(Value::String(s)) => (vec![s.clone()], false),
        Some(Value::Array(a)) => {
            let mut out = Vec::new();
            let mut nullable = false;
            for t in a {
                match t.as_str() {
                    Some("null") => nullable = true,
                    Some(other) => out.push(other.to_owned()),
                    None => {}
                }
            }
            (out, nullable)
        }
        _ => (Vec::new(), false),
    }
}

fn scalar_of(schema: &Value) -> Option<ScalarType> {
    let (ts, _) = types(schema);
    let t = ts.first().map(String::as_str);
    let fmt = schema.get("format").and_then(Value::as_str);
    let enc = schema.get("contentEncoding").and_then(Value::as_str);
    Some(match (t, fmt, enc) {
        (Some("string"), Some("uuid"), _) => ScalarType::Uuid,
        (Some("string"), Some("date-time"), _) => ScalarType::Timestamp,
        (Some("string"), Some("date"), _) => ScalarType::Date,
        (Some("string"), Some("time"), _) => ScalarType::Time,
        (Some("string"), Some("decimal"), _) => ScalarType::Decimal,
        (Some("string"), _, Some("base64")) => ScalarType::Bytes,
        (Some("string"), _, _) => ScalarType::Text,
        (Some("integer"), Some("int64"), _) => ScalarType::BigInteger,
        (Some("integer"), _, _) => ScalarType::Integer,
        (Some("number"), _, _) => ScalarType::Float,
        (Some("boolean"), _, _) => ScalarType::Boolean,
        // An unconstrained schema is any JSON value.
        (None, _, _) => ScalarType::Json,
        _ => return None,
    })
}

/// Resource schema names, read from the item type of each collection response.
///
/// A collection may be represented either directly as an array response or as
/// a named response envelope whose `data` property is an array. Both forms are
/// common in generated OpenAPI documents; neither is more semantically
/// authoritative than the other.
fn resource_names(doc: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(paths) = doc.get("paths").and_then(Value::as_object) else {
        return out;
    };
    for (_, ops) in paths {
        let Some(list) = ops
            .get("get")
            .and_then(|g| g.get("responses"))
            .and_then(|r| r.get("200"))
            .and_then(|r| r.get("content"))
            .and_then(|c| c.get("application/json"))
            .and_then(|j| j.get("schema"))
        else {
            continue;
        };
        let items = if list.get("type").and_then(Value::as_str) == Some("array") {
            list.get("items")
        } else {
            ref_name(list).and_then(|list_name| {
                doc.get("components")
                    .and_then(|c| c.get("schemas"))
                    .and_then(|s| s.get(&list_name))
                    .and_then(|s| s.get("properties"))
                    .and_then(|p| p.get("data"))
                    .and_then(|d| d.get("items"))
            })
        };
        if let Some(name) = items.and_then(ref_name).filter(|n| !out.contains(n)) {
            out.push(name);
        }
    }
    out
}

pub fn lift_openapi(json: &str) -> Result<Defeasible<DataModel>, String> {
    let doc: Value =
        serde_json::from_str(json).map_err(|e| format!("document is not valid JSON: {e}"))?;
    Ok(lift_document(&doc))
}

/// Unwraps `{"anyOf":[X, {"type":"null"}]}` into `(X, nullable)`.
fn peel_nullable_union(schema: &Value) -> (&Value, bool) {
    let Some(arms) = schema.get("anyOf").and_then(Value::as_array) else {
        return (schema, false);
    };
    let mut body = None;
    let mut nullable = false;
    for arm in arms {
        if arm.get("type").and_then(Value::as_str) == Some("null") {
            nullable = true;
        } else {
            body = Some(arm);
        }
    }
    match body {
        Some(b) if nullable => (b, true),
        _ => (schema, false),
    }
}

/// A `$ref` to a component carrying `enum` is a named enumeration.
fn enumeration_at(doc: &Value, schema: &Value) -> Option<Enumeration> {
    let name = ref_name(schema)?;
    let target = doc
        .get("components")
        .and_then(|c| c.get("schemas"))
        .and_then(|s| s.get(&name))?;
    let members: Vec<String> = target
        .get("enum")?
        .as_array()?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    Some(Enumeration { name, members })
}

pub fn lift_document(doc: &Value) -> Defeasible<DataModel> {
    let mut lifted = Defeasible::new(DataModel::default(), DEFEATER_SET);
    let mut model = DataModel::default();

    let names = resource_names(doc);
    if names.is_empty() {
        lifted.defeat(Defeat::new(
            DefeatKind::SubjectUnresolvable,
            "resources",
            "no collection response named an item schema",
        ));
    }

    for name in names {
        let Some(schema) = doc
            .get("components")
            .and_then(|c| c.get("schemas"))
            .and_then(|s| s.get(&name))
        else {
            lifted.defeat(Defeat::new(
                DefeatKind::SubjectUnresolvable,
                name.clone(),
                "resource schema is referenced but not defined",
            ));
            continue;
        };
        let required: Vec<String> = schema
            .get("required")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();

        let mut fields = Vec::new();
        if let Some(props) = schema.get("properties").and_then(Value::as_object) {
            for (fname, raw) in props {
                let (fschema, union_null) = peel_nullable_union(raw);
                let (ts, mut nullable) = types(fschema);
                nullable = nullable || union_null;
                let is_array = ts.iter().any(|t| t == "array");
                let inner = if is_array {
                    fschema.get("items").unwrap_or(&Value::Null)
                } else {
                    fschema
                };
                if is_array {
                    let (_, item_null) = types(inner);
                    nullable = nullable || item_null;
                }
                let enumeration = enumeration_at(doc, inner);
                let ty = match enumeration
                    .as_ref()
                    .map(|_| ScalarType::Enumeration)
                    .or_else(|| scalar_of(inner))
                {
                    Some(s) => FieldType::Scalar(s),
                    None => {
                        lifted.defeat(Defeat::new(
                            DefeatKind::LookedAndBlocked,
                            format!("{name}.{fname}"),
                            "no neutral domain for this schema",
                        ));
                        FieldType::Unknown
                    }
                };
                let presence = if required.contains(fname) && !nullable {
                    Presence::Required
                } else {
                    Presence::Optional
                };
                fields.push(FieldShape {
                    name: fname.clone(),
                    ty,
                    nullable: presence,
                    list: is_array,
                    // A document schema cannot state either of these.
                    identity: Tri::Unknown,
                    unique: Tri::Unknown,
                    default: DefaultOrigin::Unknown,
                    default_value: None,
                    enumeration,
                });
            }
        }
        model.entities.push(EntityShape {
            name,
            fields,
            unique_sets: Vec::new(),
        });
    }

    if !model.entities.is_empty() {
        for subject in ["identity", "uniqueness", "defaults", "relations"] {
            lifted.defeat(Defeat::new(
                DefeatKind::AuthorityCannotExpress,
                subject,
                "an API document describes shapes, not storage; this cannot be \
                 established from it",
            ));
        }
    }

    lifted.value = model;
    lifted
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc() -> Value {
        json!({
          "openapi": "3.1.0",
          "paths": {"/User": {"get": {"responses": {"200": {"content":
            {"application/json": {"schema": {"$ref": "#/components/schemas/UserList"}}}}}}}},
          "components": {"schemas": {
            "UserList": {"type":"object","properties":{"data":{"type":"array",
              "items":{"$ref":"#/components/schemas/User"}}}},
            "User": {"type":"object","required":["id","email"],"properties":{
              "id": {"type":"string","format":"uuid"},
              "email": {"type":"string"},
              "bio": {"type":["string","null"]},
              "tags": {"type":"array","items":{"type":"string"}},
              "meta": {}
            }}
          }}
        })
    }

    #[test]
    fn resources_are_found_through_the_collection_response() {
        let l = lift_document(&doc());
        assert_eq!(l.value.entity_names(), vec!["user"]);
    }

    #[test]
    fn resources_are_found_in_direct_array_responses() {
        let doc = json!({
          "openapi": "3.1.0",
          "paths": {"/delivery-blocks": {"get": {"responses": {"200": {"content":
            {"application/json": {"schema": {"type": "array", "items":
              {"$ref": "#/components/schemas/BlockedDelivery"}}}}}}}}},
          "components": {"schemas": {
            "BlockedDelivery": {"type":"object","required":["block_id","reason"],
              "properties": {
                "block_id": {"type":"integer","format":"int64"},
                "reason": {"type":"string"}
              }}
          }}
        });

        let lifted = lift_document(&doc);

        assert_eq!(lifted.value.entity_names(), vec!["blockeddelivery"]);
        let blocked = lifted.value.entity("BlockedDelivery").unwrap();
        assert_eq!(
            blocked.field("block_id").unwrap().ty,
            FieldType::Scalar(ScalarType::BigInteger)
        );
        assert_eq!(
            blocked.field("reason").unwrap().nullable,
            Presence::Required
        );
    }

    #[test]
    fn domains_presence_and_lists_survive() {
        let l = lift_document(&doc());
        let u = l.value.entity("User").unwrap();
        assert_eq!(
            u.field("id").unwrap().ty,
            FieldType::Scalar(ScalarType::Uuid)
        );
        assert_eq!(u.field("id").unwrap().nullable, Presence::Required);
        assert_eq!(u.field("bio").unwrap().nullable, Presence::Optional);
        assert!(u.field("tags").unwrap().list);
        assert_eq!(
            u.field("meta").unwrap().ty,
            FieldType::Scalar(ScalarType::Json)
        );
    }

    #[test]
    fn storage_facts_are_defeats_not_absences() {
        let l = lift_document(&doc());
        let subjects: Vec<&str> = l
            .defeats_of(DefeatKind::AuthorityCannotExpress)
            .map(|d| d.subject.as_str())
            .collect();
        for s in ["identity", "uniqueness", "defaults", "relations"] {
            assert!(subjects.contains(&s), "missing defeat for {s}");
        }
        assert!(!l.is_exhaustive());
    }
}
