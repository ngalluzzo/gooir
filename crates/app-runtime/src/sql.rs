//! SQL rendering for the runtime, driven by the waist.

use semantics_data_model_v1::{DefaultOrigin, FieldShape, FieldType, ScalarType};
use serde_json::Value;

pub fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn literal(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// Renders a validated JSON value as a SQL literal for its field's domain.
/// Values reaching here have already been checked against the model.
pub fn value_to_sql(field: &FieldShape, v: &Value) -> String {
    if v.is_null() {
        return "NULL".to_owned();
    }
    if field.list {
        let items: Vec<String> = v
            .as_array()
            .map(|a| a.iter().map(|x| scalar_to_sql(field, x)).collect())
            .unwrap_or_default();
        return format!("ARRAY[{}]", items.join(", "));
    }
    scalar_to_sql(field, v)
}

fn scalar_to_sql(field: &FieldShape, v: &Value) -> String {
    if let Some(e) = &field.enumeration {
        let s = v.as_str().unwrap_or_default();
        return format!("{}::{}", literal(s), quote_ident(&e.name));
    }
    match field.ty {
        FieldType::Scalar(ScalarType::Boolean) => if v.as_bool().unwrap_or(false) {
            "true"
        } else {
            "false"
        }
        .to_owned(),
        FieldType::Scalar(ScalarType::Integer)
        | FieldType::Scalar(ScalarType::BigInteger)
        | FieldType::Scalar(ScalarType::Float) => v.to_string(),
        FieldType::Scalar(ScalarType::Decimal) => match v.as_str() {
            Some(s) => literal(s),
            None => literal(&v.to_string()),
        },
        FieldType::Scalar(ScalarType::Json) => format!("{}::jsonb", literal(&v.to_string())),
        FieldType::Scalar(ScalarType::Uuid) => {
            format!("{}::uuid", literal(v.as_str().unwrap_or_default()))
        }
        _ => literal(v.as_str().unwrap_or_default()),
    }
}

/// The runtime supplies application-origin defaults, because the store will not.
/// Generation is delegated to PostgreSQL rather than reimplemented here.
pub fn application_default(field: &FieldShape) -> Option<String> {
    if field.default != DefaultOrigin::Application {
        return None;
    }
    Some(match field.ty {
        FieldType::Scalar(ScalarType::Uuid) => "gen_random_uuid()".to_owned(),
        FieldType::Scalar(ScalarType::Text) => "gen_random_uuid()::text".to_owned(),
        _ => return None,
    })
}
