//! One authoritative JSON decoder that rejects duplicate object keys at every depth.

use std::error::Error;
use std::fmt;

use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// Decodes one complete UTF-8 JSON document after recursively rejecting
/// duplicate object keys.
///
/// # Errors
///
/// Returns a duplicate-key error before typed decoding, or an invalid-document
/// error for malformed JSON, trailing data, or a typed schema mismatch.
pub fn from_str<T: DeserializeOwned>(input: &str) -> Result<T, StrictJsonError> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let value = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|error| classify(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| StrictJsonError::Invalid(error.to_string()))?;
    decode(value.0)
}

/// Decodes one complete JSON byte document after recursively rejecting
/// duplicate object keys.
///
/// # Errors
///
/// Returns a duplicate-key error before typed decoding, or an invalid-document
/// error for invalid UTF-8 or JSON, trailing data, or a typed schema mismatch.
pub fn from_slice<T: DeserializeOwned>(input: &[u8]) -> Result<T, StrictJsonError> {
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|error| classify(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| StrictJsonError::Invalid(error.to_string()))?;
    decode(value.0)
}

fn decode<T: DeserializeOwned>(value: Value) -> Result<T, StrictJsonError> {
    serde_json::from_value(value).map_err(|error| StrictJsonError::Invalid(error.to_string()))
}

fn classify(error: String) -> StrictJsonError {
    const PREFIX: &str = "duplicate object key `";
    if let Some(rest) = error.strip_prefix(PREFIX)
        && let Some((key, _)) = rest.split_once('`')
    {
        return StrictJsonError::DuplicateObjectKey(key.to_owned());
    }
    StrictJsonError::Invalid(error)
}

/// Strict JSON syntax or typed-decoding failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StrictJsonError {
    DuplicateObjectKey(String),
    Invalid(String),
}

impl fmt::Display for StrictJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateObjectKey(key) => {
                write!(formatter, "duplicate JSON object key `{key}`")
            }
            Self::Invalid(detail) => formatter.write_str(detail),
        }
    }
}

impl Error for StrictJsonError {}

struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| E::custom("JSON number must be finite"))?;
        Ok(StrictJsonValue(Value::Number(number)))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some((key, value)) = map.next_entry::<String, StrictJsonValue>()? {
            if values.insert(key.clone(), value.0).is_some() {
                return Err(serde::de::Error::custom(format!(
                    "duplicate object key `{key}`"
                )));
            }
        }
        Ok(StrictJsonValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::Deserialize;
    use serde_json::{Value, json};

    use super::*;

    #[derive(Debug, Deserialize, PartialEq)]
    struct ExtensionEnvelope {
        extensions: BTreeMap<String, Value>,
    }

    #[test]
    fn recursively_rejects_duplicates_before_typed_decoding() {
        let error =
            from_str::<ExtensionEnvelope>(r#"{"extensions":{"nested":{"same":1,"same":2}}}"#)
                .unwrap_err();
        assert_eq!(
            error,
            StrictJsonError::DuplicateObjectKey("same".to_owned())
        );
    }

    #[test]
    fn preserves_unknown_extension_values() {
        let decoded =
            from_slice::<ExtensionEnvelope>(br#"{"extensions":{"unknown":{"ordered":[1,2,3]}}}"#)
                .unwrap();
        assert_eq!(decoded.extensions["unknown"], json!({"ordered": [1, 2, 3]}));
    }
}
