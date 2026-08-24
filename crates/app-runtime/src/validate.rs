//! Request validation derived entirely from the waist.
//!
//! Nothing here knows what a Task or a Team is. Every rule -- which fields
//! exist, which are required, which domain a value must belong to, which
//! members an enumeration admits -- is read off the model at request time.
//! This is the generic-over-the-entity layer the recurrence probe pointed at,
//! written once instead of per entity.

use semantics_data_model_v1::{
    DefaultOrigin, EntityShape, FieldShape, FieldType, Presence, ScalarType,
};
use serde_json::Value;

#[derive(Debug, PartialEq)]
pub enum Mode {
    Create,
    Update,
}

/// True when the store or the runtime supplies the value if the caller omits it.
pub fn server_supplied(f: &FieldShape) -> bool {
    matches!(
        f.default,
        DefaultOrigin::Database | DefaultOrigin::Application
    )
}

/// Checks one value against one field's domain. Used for path parameters,
/// which are as much a part of the request as the body is.
pub fn field_value(f: &FieldShape, v: &Value) -> Result<(), String> {
    domain_ok(f, v)
}

fn domain_ok(f: &FieldShape, v: &Value) -> Result<(), String> {
    if v.is_null() {
        return if f.nullable == Presence::Optional {
            Ok(())
        } else {
            Err("must not be null".to_owned())
        };
    }
    if f.list {
        let Some(items) = v.as_array() else {
            return Err("expected an array".to_owned());
        };
        for item in items {
            scalar_ok(f, item)?;
        }
        return Ok(());
    }
    scalar_ok(f, v)
}

fn scalar_ok(f: &FieldShape, v: &Value) -> Result<(), String> {
    if let Some(e) = &f.enumeration {
        let Some(s) = v.as_str() else {
            return Err("expected a string".to_owned());
        };
        return if e.members.iter().any(|m| m == s) {
            Ok(())
        } else {
            Err(format!("must be one of: {}", e.members.join(", ")))
        };
    }
    let FieldType::Scalar(t) = f.ty else {
        return Ok(());
    };
    let ok = match t {
        ScalarType::Text | ScalarType::Uuid | ScalarType::Bytes => v.is_string(),
        ScalarType::Timestamp | ScalarType::Date | ScalarType::Time => v.is_string(),
        ScalarType::Decimal => v.is_string() || v.is_number(),
        ScalarType::Integer | ScalarType::BigInteger => v.is_i64() || v.is_u64(),
        ScalarType::Float => v.is_number(),
        ScalarType::Boolean => v.is_boolean(),
        ScalarType::Json => true,
        ScalarType::Enumeration | ScalarType::Other => v.is_string(),
    };
    if ok {
        Ok(())
    } else {
        Err(format!("expected {t:?}"))
    }
}

/// Checks a request body against an entity, returning every problem at once.
pub fn check(entity: &EntityShape, body: &Value, mode: Mode) -> Vec<String> {
    let Some(obj) = body.as_object() else {
        return vec!["body must be a JSON object".to_owned()];
    };
    let mut problems = Vec::new();

    for (k, v) in obj {
        match entity.field(k) {
            None => problems.push(format!("`{k}` is not a field of {}", entity.name)),
            Some(f) => {
                if mode == Mode::Update && f.identity.is_yes() {
                    problems.push(format!("`{k}` is the identity and cannot be changed"));
                    continue;
                }
                if let Err(why) = domain_ok(f, v) {
                    problems.push(format!("`{k}`: {why}"));
                }
            }
        }
    }

    if mode == Mode::Create {
        for f in &entity.fields {
            let supplied = obj.contains_key(&f.name);
            if !supplied && f.nullable == Presence::Required && !server_supplied(f) {
                problems.push(format!("`{}` is required", f.name));
            }
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use semantics_data_model_v1::{Enumeration, Tri};
    use serde_json::json;

    fn entity() -> EntityShape {
        let f = |name: &str, ty: ScalarType, req: bool| FieldShape {
            name: name.to_owned(),
            ty: FieldType::Scalar(ty),
            nullable: if req {
                Presence::Required
            } else {
                Presence::Optional
            },
            list: false,
            identity: Tri::No,
            unique: Tri::No,
            default: DefaultOrigin::None,
            default_value: None,
            enumeration: None,
        };
        let mut id = f("id", ScalarType::Uuid, true);
        id.identity = Tri::Yes;
        id.default = DefaultOrigin::Application;
        let mut status = f("status", ScalarType::Enumeration, true);
        status.enumeration = Some(Enumeration {
            name: "S".to_owned(),
            members: vec!["todo".to_owned(), "done".to_owned()],
        });
        EntityShape {
            name: "Task".to_owned(),
            fields: vec![
                id,
                f("title", ScalarType::Text, true),
                f("priority", ScalarType::Integer, true),
                f("notes", ScalarType::Text, false),
                status,
            ],
            unique_sets: Vec::new(),
        }
    }

    #[test]
    fn a_valid_create_body_passes() {
        let p = check(
            &entity(),
            &json!({"title": "a", "priority": 1, "status": "todo"}),
            Mode::Create,
        );
        assert!(p.is_empty(), "{p:?}");
    }

    #[test]
    fn a_server_supplied_field_is_not_required_of_the_caller() {
        let p = check(
            &entity(),
            &json!({"title":"a","priority":1,"status":"todo"}),
            Mode::Create,
        );
        assert!(!p.iter().any(|x| x.contains("`id`")), "{p:?}");
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let p = check(
            &entity(),
            &json!({"title": 5, "status": "nope", "bogus": 1}),
            Mode::Create,
        );
        assert!(p.iter().any(|x| x.contains("`title`")), "{p:?}");
        assert!(p.iter().any(|x| x.contains("must be one of")), "{p:?}");
        assert!(p.iter().any(|x| x.contains("not a field")), "{p:?}");
        assert!(
            p.iter().any(|x| x.contains("`priority` is required")),
            "{p:?}"
        );
    }

    #[test]
    fn an_optional_field_accepts_null_and_a_required_one_does_not() {
        assert!(check(&entity(), &json!({"notes": null}), Mode::Update).is_empty());
        let p = check(&entity(), &json!({"title": null}), Mode::Update);
        assert!(p.iter().any(|x| x.contains("must not be null")), "{p:?}");
    }

    #[test]
    fn a_path_parameter_is_checked_against_its_domain() {
        let e = entity();
        let id = e.field("id").unwrap();
        assert!(
            field_value(id, &json!("not-a-uuid")).is_ok(),
            "shape only, not format"
        );
        assert!(
            field_value(id, &json!(42)).is_err(),
            "an integer is not a uuid"
        );
        let status = e.field("status").unwrap();
        assert!(field_value(status, &json!("nope")).is_err());
        assert!(field_value(status, &json!("todo")).is_ok());
    }

    #[test]
    fn the_identity_cannot_be_changed_by_an_update() {
        let p = check(&entity(), &json!({"id": "x"}), Mode::Update);
        assert!(p.iter().any(|x| x.contains("cannot be changed")), "{p:?}");
    }
}
