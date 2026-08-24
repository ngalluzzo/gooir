//! Lowers the neutral data-model waist into an OpenAPI 3.1 CRUD surface.
//!
//! This is the first target from a different modelling tradition: JSON
//! documents have no primary keys, no uniqueness, and no foreign keys. What the
//! target cannot carry is declared as [`Lossy`] rather than smuggled through a
//! vendor extension, because a target that quietly round-trips facts it cannot
//! actually express would make the waist look more portable than it is.
//!
//! The request/response variants are the point of the exercise: `Create` drops
//! fields the server supplies, `Update` makes everything optional, and `List`
//! wraps a page. That shaping is identical for every entity, which is precisely
//! the repetitive work worth generating.

use semantics_data_model_v1::{
    DataModel, DefaultOrigin, EntityShape, FieldShape, FieldType, Presence, ScalarType,
};
use serde_json::{Map, Value, json};

pub const LOWERING_ID: &str = "org.gooi.lowering.openapi@1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lossy {
    pub subject: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default)]
pub struct Lowered {
    pub document: Value,
    pub lossy: Vec<Lossy>,
}

/// JSON Schema for one neutral domain. OpenAPI 3.1 permits a type array, so
/// nullability is expressed without a vendor keyword.
fn json_type(ty: FieldType, out: &mut LossySink, subject: &str) -> Value {
    match ty {
        FieldType::Scalar(s) => match s {
            ScalarType::Text => json!({"type": "string"}),
            ScalarType::Integer => json!({"type": "integer", "format": "int32"}),
            ScalarType::BigInteger => json!({"type": "integer", "format": "int64"}),
            ScalarType::Float => json!({"type": "number", "format": "double"}),
            // A JSON number cannot carry arbitrary precision safely.
            ScalarType::Decimal => {
                out.push(
                    subject,
                    "decimal is carried as a string to preserve precision",
                );
                json!({"type": "string", "format": "decimal"})
            }
            ScalarType::Boolean => json!({"type": "boolean"}),
            ScalarType::Timestamp => json!({"type": "string", "format": "date-time"}),
            ScalarType::Date => json!({"type": "string", "format": "date"}),
            ScalarType::Time => json!({"type": "string", "format": "time"}),
            ScalarType::Json => json!({}),
            ScalarType::Bytes => json!({"type": "string", "contentEncoding": "base64"}),
            ScalarType::Uuid => json!({"type": "string", "format": "uuid"}),
            ScalarType::Enumeration => {
                out.push(subject, "enumeration members are not carried by the waist");
                json!({"type": "string"})
            }
            ScalarType::Other => {
                out.push(subject, "domain is outside the waist's neutral set");
                json!({"type": "string"})
            }
        },
        FieldType::Unknown => {
            out.push(
                subject,
                "field type is unknown; the schema is unconstrained",
            );
            json!({})
        }
    }
}

#[derive(Default)]
struct LossySink(Vec<Lossy>);

impl LossySink {
    fn push(&mut self, subject: &str, detail: &str) {
        self.0.push(Lossy {
            subject: subject.to_owned(),
            detail: detail.to_owned(),
        });
    }
}

fn nullable(schema: Value) -> Value {
    match schema.get("type").and_then(Value::as_str) {
        Some(t) => {
            let mut m = schema.as_object().cloned().unwrap_or_default();
            m.insert("type".to_owned(), json!([t, "null"]));
            Value::Object(m)
        }
        None => schema,
    }
}

fn property(field: &FieldShape, sink: &mut LossySink, entity: &str) -> Value {
    let subject = format!("{entity}.{}", field.name);
    // A named enumeration becomes a shared component, so both its name and its
    // members survive into the document and back out of it.
    let inner = match field.enumeration.as_ref().filter(|e| !e.members.is_empty()) {
        Some(e) => json!({"$ref": format!("#/components/schemas/{}", e.name)}),
        None => json_type(field.ty, sink, &subject),
    };
    let mut schema = if field.list {
        json!({"type": "array", "items": inner})
    } else {
        inner
    };
    if field.nullable == Presence::Optional {
        schema = nullable(schema);
    }
    if field.nullable == Presence::Unknown {
        sink.push(
            &subject,
            "presence was not established by the source authority",
        );
        schema = nullable(schema);
    }
    schema
}

/// The server supplies this value, so a create request must not require it.
fn server_supplied(field: &FieldShape) -> bool {
    matches!(
        field.default,
        DefaultOrigin::Database | DefaultOrigin::Application
    )
}

/// How `required` is computed for a variant.
///
/// "Required in a create request" and "always present in a response" are
/// different facts: a server-supplied value is absent from the former and
/// guaranteed in the latter. Conflating them makes every defaulted field look
/// optional to anyone reading the resource schema.
#[derive(Clone, Copy, PartialEq)]
enum Requiredness {
    /// Present whenever the resource is read.
    AsRead,
    /// The caller must supply it.
    AsWritten,
    /// Nothing is required.
    Nothing,
}

fn object_schema(
    entity: &EntityShape,
    sink: &mut LossySink,
    include: impl Fn(&FieldShape) -> bool,
    required_mode: Requiredness,
) -> Value {
    let mut props = Map::new();
    let mut required: Vec<Value> = Vec::new();
    for f in entity.fields.iter().filter(|f| include(f)) {
        props.insert(f.name.clone(), property(f, sink, &entity.name));
        let is_required = match required_mode {
            Requiredness::Nothing => false,
            Requiredness::AsRead => f.nullable == Presence::Required,
            Requiredness::AsWritten => f.nullable == Presence::Required && !server_supplied(f),
        };
        if is_required {
            required.push(Value::String(f.name.clone()));
        }
    }
    let mut obj = Map::new();
    obj.insert("type".to_owned(), json!("object"));
    obj.insert("properties".to_owned(), Value::Object(props));
    if !required.is_empty() {
        obj.insert("required".to_owned(), Value::Array(required));
    }
    obj.insert("additionalProperties".to_owned(), json!(false));
    Value::Object(obj)
}

fn collection_path(entity: &str) -> String {
    format!("/{}", entity)
}

pub fn lower_to_openapi(model: &DataModel) -> Lowered {
    let mut sink = LossySink::default();
    let mut schemas = Map::new();
    let mut paths = Map::new();

    // One component per distinct enumeration, referenced by every field using it.
    let mut enums: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for f in model.entities.iter().flat_map(|e| &e.fields) {
        if let Some(e) = f.enumeration.as_ref().filter(|e| !e.members.is_empty()) {
            enums.insert(e.name.clone(), e.members.clone());
        } else if f.ty == FieldType::Scalar(ScalarType::Enumeration) {
            sink.push(
                "enumeration",
                "an enumeration arrived without members; it degrades to a bare string",
            );
        }
    }
    for (name, members) in &enums {
        schemas.insert(name.clone(), json!({"type": "string", "enum": members}));
    }

    for e in &model.entities {
        let name = &e.name;

        // The resource as read.
        schemas.insert(
            name.clone(),
            object_schema(e, &mut sink, |_| true, Requiredness::AsRead),
        );

        // Create: drop anything the server supplies.
        schemas.insert(
            format!("{name}Create"),
            object_schema(
                e,
                &mut sink,
                |f| !server_supplied(f),
                Requiredness::AsWritten,
            ),
        );

        // Update: every field optional, identity excluded.
        let identity: Vec<String> = e
            .fields
            .iter()
            .filter(|f| f.identity.is_yes())
            .map(|f| f.name.clone())
            .collect();
        schemas.insert(
            format!("{name}Update"),
            object_schema(
                e,
                &mut sink,
                |f| !identity.contains(&f.name),
                Requiredness::Nothing,
            ),
        );

        // A page of resources.
        schemas.insert(
            format!("{name}List"),
            json!({
                "type": "object",
                "properties": {
                    "data": {"type": "array", "items": {"$ref": format!("#/components/schemas/{name}")}},
                    "nextCursor": {"type": ["string", "null"]}
                },
                "required": ["data"],
                "additionalProperties": false
            }),
        );

        if identity.is_empty() {
            sink.push(
                name,
                "no identity field; item routes cannot be addressed and are omitted",
            );
        }

        let r = |s: &str| json!({"$ref": format!("#/components/schemas/{s}")});
        let mut collection = Map::new();
        collection.insert(
            "get".to_owned(),
            json!({
                "operationId": format!("list{name}"),
                "responses": {"200": {"description": "a page of resources",
                    "content": {"application/json": {"schema": r(&format!("{name}List"))}}}}
            }),
        );
        collection.insert(
            "post".to_owned(),
            json!({
                "operationId": format!("create{name}"),
                "requestBody": {"required": true,
                    "content": {"application/json": {"schema": r(&format!("{name}Create"))}}},
                "responses": {"201": {"description": "created",
                    "content": {"application/json": {"schema": r(name)}}}}
            }),
        );
        paths.insert(collection_path(name), Value::Object(collection));

        // Item routes require an addressable identity.
        if identity.len() == 1 {
            let key = &identity[0];
            let param = json!([{
                "name": key, "in": "path", "required": true,
                "schema": {"type": "string"}
            }]);
            let mut item = Map::new();
            item.insert("parameters".to_owned(), param);
            item.insert(
                "get".to_owned(),
                json!({
                    "operationId": format!("get{name}"),
                    "responses": {
                        "200": {"description": "the resource",
                            "content": {"application/json": {"schema": r(name)}}},
                        "404": {"description": "not found"}}
                }),
            );
            item.insert(
                "patch".to_owned(),
                json!({
                    "operationId": format!("update{name}"),
                    "requestBody": {"required": true,
                        "content": {"application/json": {"schema": r(&format!("{name}Update"))}}},
                    "responses": {"200": {"description": "the updated resource",
                        "content": {"application/json": {"schema": r(name)}}},
                        "404": {"description": "not found"}}
                }),
            );
            item.insert(
                "delete".to_owned(),
                json!({
                    "operationId": format!("delete{name}"),
                    "responses": {"204": {"description": "deleted"},
                        "404": {"description": "not found"}}
                }),
            );
            paths.insert(
                format!("{}/{{{}}}", collection_path(name), key),
                Value::Object(item),
            );
        } else if identity.len() > 1 {
            sink.push(
                name,
                "composite identity is not addressable as a single path parameter",
            );
        }
    }

    // Facts this target has no place for.
    if model
        .entities
        .iter()
        .any(|e| e.fields.iter().any(|f| f.identity.is_yes()))
    {
        sink.push("identity", "JSON Schema has no notion of a primary key");
    }
    if model
        .entities
        .iter()
        .any(|e| e.fields.iter().any(|f| f.unique.is_yes()))
    {
        sink.push(
            "uniqueness",
            "JSON Schema has no notion of a unique constraint",
        );
    }
    if !model.relations.is_empty() {
        sink.push(
            "relations",
            "a relation is carried only as its foreign-key property; the edge itself \
             has no representation",
        );
    }
    if model
        .entities
        .iter()
        .any(|e| e.fields.iter().any(|f| f.default != DefaultOrigin::None))
    {
        sink.push("defaults", "the origin of a default has no representation");
    }

    let document = json!({
        "openapi": "3.1.0",
        "info": {"title": "generated CRUD surface", "version": "1.0.0",
                 "x-generated-by": LOWERING_ID},
        "paths": Value::Object(paths),
        "components": {"schemas": Value::Object(schemas)}
    });

    Lowered {
        document,
        lossy: sink.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use semantics_data_model_v1::EntityShape;
    use semantics_data_model_v1::Tri;

    fn f(name: &str, ty: ScalarType) -> FieldShape {
        FieldShape {
            name: name.to_owned(),
            ty: FieldType::Scalar(ty),
            nullable: Presence::Required,
            list: false,
            identity: Tri::No,
            unique: Tri::No,
            default: DefaultOrigin::None,
            enumeration: None,
        }
    }

    fn one_entity() -> DataModel {
        let mut id = f("id", ScalarType::Uuid);
        id.identity = Tri::Yes;
        id.default = DefaultOrigin::Application;
        let mut email = f("email", ScalarType::Text);
        email.unique = Tri::Yes;
        let mut bio = f("bio", ScalarType::Text);
        bio.nullable = Presence::Optional;
        DataModel {
            entities: vec![EntityShape {
                name: "User".to_owned(),
                fields: vec![id, email, bio],
                unique_sets: Vec::new(),
            }],
            relations: Vec::new(),
        }
    }

    #[test]
    fn emits_crud_paths_for_an_addressable_entity() {
        let out = lower_to_openapi(&one_entity());
        let paths = out.document["paths"].as_object().unwrap();
        assert!(paths.contains_key("/User"));
        assert!(paths.contains_key("/User/{id}"));
        assert_eq!(
            out.document["paths"]["/User"]["get"]["operationId"],
            "listUser"
        );
        assert_eq!(
            out.document["paths"]["/User/{id}"]["delete"]["operationId"],
            "deleteUser"
        );
    }

    #[test]
    fn create_drops_server_supplied_fields_and_update_requires_nothing() {
        let out = lower_to_openapi(&one_entity());
        let create = &out.document["components"]["schemas"]["UserCreate"];
        assert!(
            create["properties"].get("id").is_none(),
            "server supplies id"
        );
        assert!(create["properties"].get("email").is_some());
        assert_eq!(create["required"], json!(["email"]));

        let update = &out.document["components"]["schemas"]["UserUpdate"];
        assert!(
            update["properties"].get("id").is_none(),
            "identity not updatable"
        );
        assert!(update.get("required").is_none(), "update requires nothing");
    }

    #[test]
    fn an_optional_field_is_nullable_via_a_type_array() {
        let out = lower_to_openapi(&one_entity());
        let bio = &out.document["components"]["schemas"]["User"]["properties"]["bio"];
        assert_eq!(bio["type"], json!(["string", "null"]));
    }

    #[test]
    fn facts_the_target_cannot_carry_are_declared() {
        let out = lower_to_openapi(&one_entity());
        let subjects: Vec<&str> = out.lossy.iter().map(|l| l.subject.as_str()).collect();
        assert!(subjects.contains(&"identity"));
        assert!(subjects.contains(&"uniqueness"));
        assert!(subjects.contains(&"defaults"));
    }

    #[test]
    fn an_entity_without_identity_gets_no_item_routes() {
        let m = DataModel {
            entities: vec![EntityShape {
                name: "Log".to_owned(),
                fields: vec![f("message", ScalarType::Text)],
                unique_sets: Vec::new(),
            }],
            relations: Vec::new(),
        };
        let out = lower_to_openapi(&m);
        let paths = out.document["paths"].as_object().unwrap();
        assert!(paths.contains_key("/Log"));
        assert_eq!(paths.len(), 1, "no item route without an identity");
        assert!(
            out.lossy
                .iter()
                .any(|l| l.detail.contains("cannot be addressed"))
        );
    }
}
