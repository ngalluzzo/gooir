//! Native source lift for Fleetd's blocked-delivery review loop.
//!
//! The lift keeps public API observations separate from Rust implementation
//! observations. It does not manufacture a workflow from endpoint names:
//! authority comes from explicit handler guards and resolution effects come
//! from the SQL executed by the matching Rust enum arms.

use heck::ToSnakeCase;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt};
use syn::{
    Attribute, Block, Expr, ExprCall, ExprMatch, ExprMethodCall, ImplItem, Item, ItemEnum, LitStr,
    Pat, Stmt, visit::Visit,
};

pub const EXTRACTOR_PACKAGE: &str = "org.gooi.lifter.fleetd_control";
pub const EXTRACTOR_VERSION: &str = "0.1.0";
pub const OPENAPI_ARTIFACT: &str = "openapi/fleetd-v1.json";
pub const API_ARTIFACT: &str = "src/api.rs";
pub const MODEL_ARTIFACT: &str = "src/model.rs";
pub const DELIVERY_ARTIFACT: &str = "src/delivery.rs";

#[derive(Clone, Copy, Debug)]
pub struct FleetdControlSources<'a> {
    pub openapi: &'a str,
    pub api_rust: &'a str,
    pub model_rust: &'a str,
    pub delivery_rust: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceArtifact {
    pub authority: String,
    pub artifact: String,
    pub revision: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeApiOperation {
    pub operation_id: String,
    pub method: String,
    pub path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeResolution {
    pub wire_name: String,
    pub rust_symbol: Option<String>,
    /// Exact Fleetd delivery-state literal assigned by the implementation.
    pub resulting_state: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeCompleteness {
    Exhaustive,
    Partial,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeCoverage {
    pub extractor_package: String,
    pub extractor_version: String,
    pub mechanism: String,
    pub completeness: NativeCompleteness,
    pub included_artifacts: Vec<String>,
    pub unresolved: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FleetdControlLift {
    pub sources: Vec<SourceArtifact>,
    pub list_operation: Option<NativeApiOperation>,
    pub resolve_operation: Option<NativeApiOperation>,
    pub blocked_delivery_schema: Option<String>,
    pub resolution_selector: Option<String>,
    pub review_fields: Vec<String>,
    pub list_operator_guarded: bool,
    pub resolve_operator_guarded: bool,
    pub resolution_effects_committed: bool,
    pub resolutions: Vec<NativeResolution>,
    pub coverage: NativeCoverage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiftError {
    InvalidOpenApi(String),
    InvalidRust {
        artifact: &'static str,
        error: String,
    },
}

impl fmt::Display for LiftError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOpenApi(error) => write!(formatter, "OpenAPI is invalid JSON: {error}"),
            Self::InvalidRust { artifact, error } => {
                write!(formatter, "{artifact} is not valid Rust: {error}")
            }
        }
    }
}

impl std::error::Error for LiftError {}

pub fn lift_fleetd_control(
    sources: FleetdControlSources<'_>,
    authority: impl Into<String>,
    revision: impl Into<String>,
) -> Result<FleetdControlLift, LiftError> {
    let openapi: Value = serde_json::from_str(sources.openapi)
        .map_err(|error| LiftError::InvalidOpenApi(error.to_string()))?;
    let api = parse_rust(sources.api_rust, API_ARTIFACT)?;
    let model = parse_rust(sources.model_rust, MODEL_ARTIFACT)?;
    let delivery = parse_rust(sources.delivery_rust, DELIVERY_ARTIFACT)?;
    let authority = authority.into();
    let revision = revision.into();
    let mut unresolved = Vec::new();

    let list_operation = find_openapi_operation(&openapi, "listDeliveryBlocks");
    if list_operation.is_none() {
        unresolved.push("public operation listDeliveryBlocks was not found".to_owned());
    }
    let resolve_operation = find_openapi_operation(&openapi, "resolveDeliveryBlock");
    if resolve_operation.is_none() {
        unresolved.push("public operation resolveDeliveryBlock was not found".to_owned());
    }
    let resolution_selector = resolve_operation
        .as_ref()
        .and_then(|operation| operation_value(&openapi, operation))
        .and_then(single_required_path_parameter);
    if resolution_selector.is_none() {
        unresolved.push("resolveDeliveryBlock exact path selector was not established".to_owned());
    }

    let blocked_delivery_schema = list_operation
        .as_ref()
        .and_then(|operation| operation_value(&openapi, operation))
        .and_then(response_array_item_schema);
    if blocked_delivery_schema.is_none() {
        unresolved.push(
            "listDeliveryBlocks 200 response is not a direct array of a named schema".to_owned(),
        );
    }
    let review_fields = blocked_delivery_schema
        .as_deref()
        .and_then(|name| component_schema(&openapi, name))
        .and_then(|schema| schema.get("required"))
        .and_then(Value::as_array)
        .map(|fields| {
            fields
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if review_fields.is_empty() {
        unresolved.push("blocked-delivery review fields were not established".to_owned());
    }

    let openapi_resolutions = resolve_operation
        .as_ref()
        .and_then(|operation| operation_value(&openapi, operation))
        .and_then(request_schema_name)
        .and_then(|request| component_schema(&openapi, &request))
        .and_then(|schema| schema.get("properties"))
        .and_then(|properties| properties.get("resolution"))
        .and_then(ref_name)
        .and_then(|name| component_schema(&openapi, &name))
        .and_then(|schema| schema.get("enum"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if openapi_resolutions.is_empty() {
        unresolved.push("public resolution alternatives were not established".to_owned());
    }

    let rust_resolutions = rust_resolution_variants(&model, &mut unresolved);
    let openapi_set = openapi_resolutions.iter().cloned().collect::<BTreeSet<_>>();
    let rust_set = rust_resolutions
        .iter()
        .map(|(_, wire)| wire.clone())
        .collect::<BTreeSet<_>>();
    if openapi_set != rust_set {
        unresolved.push(format!(
            "public and Rust resolution alternatives diverge: public={openapi_set:?}, rust={rust_set:?}"
        ));
    }

    let list_operator_guarded =
        function_begins_with_propagated_call(&api, "list_delivery_blocks", "require_operator");
    if !list_operator_guarded {
        unresolved.push("list_delivery_blocks operator guard was not established".to_owned());
    }
    let resolve_operator_guarded =
        function_begins_with_propagated_call(&api, "resolve_delivery_block", "require_operator");
    if !resolve_operator_guarded {
        unresolved.push("resolve_delivery_block operator guard was not established".to_owned());
    }

    let transition_states = resolution_transition_states(&delivery, &mut unresolved);
    let resolution_effects_committed = resolution_effects_are_committed(&delivery);
    if !resolution_effects_committed {
        unresolved.push(
            "resolve_delivery_block did not establish an ordered resolution effect and transaction commit"
                .to_owned(),
        );
    }
    let resolutions = openapi_resolutions
        .into_iter()
        .map(|wire_name| {
            let rust_symbol = rust_resolutions
                .iter()
                .find(|(_, wire)| wire == &wire_name)
                .map(|(symbol, _)| symbol.clone());
            let resulting_state = rust_symbol.as_ref().and_then(|symbol| {
                transition_states
                    .iter()
                    .find(|(variant, _)| variant == symbol)
                    .and_then(|(_, state)| state.clone())
            });
            if resulting_state.is_none() {
                unresolved.push(format!(
                    "resolution {wire_name} has no statically established delivery-state effect"
                ));
            }
            NativeResolution {
                wire_name,
                rust_symbol,
                resulting_state,
            }
        })
        .collect();

    let completeness = if unresolved.is_empty() {
        NativeCompleteness::Exhaustive
    } else {
        NativeCompleteness::Partial
    };
    let source_documents = [
        (OPENAPI_ARTIFACT, sources.openapi),
        (API_ARTIFACT, sources.api_rust),
        (MODEL_ARTIFACT, sources.model_rust),
        (DELIVERY_ARTIFACT, sources.delivery_rust),
    ];

    Ok(FleetdControlLift {
        sources: source_documents
            .iter()
            .map(|(artifact, source)| SourceArtifact {
                authority: authority.clone(),
                artifact: (*artifact).to_owned(),
                revision: revision.clone(),
                sha256: sha256(source.as_bytes()),
            })
            .collect(),
        list_operation,
        resolve_operation,
        blocked_delivery_schema,
        resolution_selector,
        review_fields,
        list_operator_guarded,
        resolve_operator_guarded,
        resolution_effects_committed,
        resolutions,
        coverage: NativeCoverage {
            extractor_package: EXTRACTOR_PACKAGE.to_owned(),
            extractor_version: EXTRACTOR_VERSION.to_owned(),
            mechanism: "openapi_surface_plus_rust_guards_and_sql_effects".to_owned(),
            completeness,
            included_artifacts: source_documents
                .iter()
                .map(|(artifact, _)| (*artifact).to_owned())
                .collect(),
            unresolved,
        },
    })
}

fn parse_rust(source: &str, artifact: &'static str) -> Result<syn::File, LiftError> {
    syn::parse_file(source).map_err(|error| LiftError::InvalidRust {
        artifact,
        error: error.to_string(),
    })
}

fn find_openapi_operation(doc: &Value, operation_id: &str) -> Option<NativeApiOperation> {
    for (path, path_item) in doc.get("paths")?.as_object()? {
        for method in ["get", "post", "put", "patch", "delete"] {
            let Some(operation) = path_item.get(method) else {
                continue;
            };
            if operation.get("operationId").and_then(Value::as_str) == Some(operation_id) {
                return Some(NativeApiOperation {
                    operation_id: operation_id.to_owned(),
                    method: method.to_owned(),
                    path: path.clone(),
                });
            }
        }
    }
    None
}

fn operation_value<'a>(doc: &'a Value, operation: &NativeApiOperation) -> Option<&'a Value> {
    doc.get("paths")?
        .get(&operation.path)?
        .get(&operation.method)
}

fn response_array_item_schema(operation: &Value) -> Option<String> {
    let schema = operation
        .get("responses")?
        .get("200")?
        .get("content")?
        .get("application/json")?
        .get("schema")?;
    (schema.get("type").and_then(Value::as_str) == Some("array"))
        .then(|| schema.get("items").and_then(ref_name))
        .flatten()
}

fn request_schema_name(operation: &Value) -> Option<String> {
    operation
        .get("requestBody")?
        .get("content")?
        .get("application/json")?
        .get("schema")
        .and_then(ref_name)
}

fn single_required_path_parameter(operation: &Value) -> Option<String> {
    let names = operation
        .get("parameters")?
        .as_array()?
        .iter()
        .filter(|parameter| {
            parameter.get("in").and_then(Value::as_str) == Some("path")
                && parameter.get("required").and_then(Value::as_bool) == Some(true)
        })
        .filter_map(|parameter| parameter.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    (names.len() == 1).then(|| names[0].to_owned())
}

fn component_schema<'a>(doc: &'a Value, name: &str) -> Option<&'a Value> {
    doc.get("components")?.get("schemas")?.get(name)
}

fn ref_name(value: &Value) -> Option<String> {
    value
        .get("$ref")?
        .as_str()?
        .rsplit('/')
        .next()
        .map(str::to_owned)
}

fn rust_resolution_variants(
    file: &syn::File,
    unresolved: &mut Vec<String>,
) -> Vec<(String, String)> {
    let Some(item) = find_enum(file, "BlockResolution") else {
        unresolved.push("Rust enum BlockResolution was not found".to_owned());
        return Vec::new();
    };
    if !has_serde_snake_case(&item.attrs) {
        unresolved.push("BlockResolution wire naming is not direct serde snake_case".to_owned());
        return Vec::new();
    }
    item.variants
        .iter()
        .map(|variant| {
            (
                variant.ident.to_string(),
                variant.ident.to_string().to_snake_case(),
            )
        })
        .collect()
}

fn find_enum<'a>(file: &'a syn::File, name: &str) -> Option<&'a ItemEnum> {
    file.items.iter().find_map(|item| match item {
        Item::Enum(item) if item.ident == name => Some(item),
        _ => None,
    })
}

fn function_block<'a>(file: &'a syn::File, name: &str) -> Option<&'a Block> {
    for item in &file.items {
        match item {
            Item::Fn(function) if function.sig.ident == name => return Some(&function.block),
            Item::Impl(item_impl) => {
                if let Some(function) = item_impl.items.iter().find_map(|item| match item {
                    ImplItem::Fn(function) if function.sig.ident == name => Some(function),
                    _ => None,
                }) {
                    return Some(&function.block);
                }
            }
            _ => {}
        }
    }
    None
}

fn has_serde_snake_case(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        if !attribute.path().is_ident("serde") {
            return false;
        }
        let mut snake_case = false;
        let _ = attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename_all") {
                let value: LitStr = meta.value()?.parse()?;
                snake_case = value.value() == "snake_case";
            }
            Ok(())
        });
        snake_case
    })
}

fn function_begins_with_propagated_call(file: &syn::File, function: &str, called: &str) -> bool {
    let Some(block) = function_block(file, function) else {
        return false;
    };
    let Some(Stmt::Expr(Expr::Try(propagated), Some(_))) = block.stmts.first() else {
        return false;
    };
    let Expr::Call(call) = propagated.expr.as_ref() else {
        return false;
    };
    let Expr::Path(path) = call.func.as_ref() else {
        return false;
    };
    path.path.is_ident(called)
}

fn resolution_transition_states(
    file: &syn::File,
    unresolved: &mut Vec<String>,
) -> Vec<(String, Option<String>)> {
    let Some(block) = function_block(file, "resolve_delivery_row") else {
        unresolved.push("resolve_delivery_row was not found".to_owned());
        return Vec::new();
    };
    let mut visitor = ResolutionMatchVisitor {
        matches: Vec::new(),
    };
    visitor.visit_block(block);
    let Some(resolution_match) = visitor.matches.into_iter().next() else {
        unresolved.push("direct match on input.resolution was not found".to_owned());
        return Vec::new();
    };

    resolution_match
        .arms
        .iter()
        .filter_map(|arm| {
            let symbol = resolution_variant(&arm.pat)?;
            let mut queries = ExecutedQueryVisitor { values: Vec::new() };
            queries.visit_expr(&arm.body);
            let states = ["pending", "dead"]
                .into_iter()
                .filter(|state| {
                    let needle = format!("state = '{state}'");
                    queries.values.iter().any(|value| value.contains(&needle))
                })
                .collect::<Vec<_>>();
            let state = (states.len() == 1).then(|| states[0].to_owned());
            Some((symbol, state))
        })
        .collect()
}

struct ResolutionMatchVisitor<'a> {
    matches: Vec<&'a ExprMatch>,
}

impl<'ast> Visit<'ast> for ResolutionMatchVisitor<'ast> {
    fn visit_expr_match(&mut self, expression: &'ast ExprMatch) {
        if is_input_resolution(&expression.expr) {
            self.matches.push(expression);
        }
        syn::visit::visit_expr_match(self, expression);
    }
}

fn is_input_resolution(expression: &Expr) -> bool {
    let Expr::Field(field) = expression else {
        return false;
    };
    let syn::Member::Named(member) = &field.member else {
        return false;
    };
    let Expr::Path(base) = field.base.as_ref() else {
        return false;
    };
    member == "resolution" && base.path.is_ident("input")
}

fn resolution_variant(pattern: &Pat) -> Option<String> {
    let Pat::Path(path) = pattern else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

struct ExecutedQueryVisitor {
    values: Vec<String>,
}

impl<'ast> Visit<'ast> for ExecutedQueryVisitor {
    fn visit_expr_method_call(&mut self, expression: &'ast ExprMethodCall) {
        if expression.method == "execute"
            && let Some(query) = direct_sqlx_query(&expression.receiver)
        {
            self.values.push(query);
        }
        syn::visit::visit_expr_method_call(self, expression);
    }
}

fn direct_sqlx_query(expression: &Expr) -> Option<String> {
    match expression {
        Expr::MethodCall(method) => direct_sqlx_query(&method.receiver),
        Expr::Call(call) => {
            let Expr::Path(function) = call.func.as_ref() else {
                return None;
            };
            let segments = function
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>();
            if segments != ["sqlx", "query"] {
                return None;
            }
            let Expr::Lit(literal) = call.args.first()? else {
                return None;
            };
            let syn::Lit::Str(query) = &literal.lit else {
                return None;
            };
            Some(query.value())
        }
        _ => None,
    }
}

fn resolution_effects_are_committed(file: &syn::File) -> bool {
    let Some(block) = function_block(file, "resolve_delivery_block") else {
        return false;
    };
    let mut resolution_indices = Vec::new();
    let mut commit_indices = Vec::new();
    for (index, statement) in block.stmts.iter().enumerate() {
        let mut visitor = ResolutionCommitVisitor::default();
        visitor.visit_stmt(statement);
        if visitor.calls_resolution {
            resolution_indices.push(index);
        }
        if visitor.commits_transaction {
            commit_indices.push(index);
        }
    }
    resolution_indices
        .iter()
        .any(|effect| commit_indices.iter().any(|commit| effect < commit))
}

#[derive(Default)]
struct ResolutionCommitVisitor {
    calls_resolution: bool,
    commits_transaction: bool,
}

impl<'ast> Visit<'ast> for ResolutionCommitVisitor {
    fn visit_expr_call(&mut self, expression: &'ast ExprCall) {
        if let Expr::Path(function) = expression.func.as_ref()
            && function.path.is_ident("resolve_delivery_row")
        {
            self.calls_resolution = true;
        }
        syn::visit::visit_expr_call(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast ExprMethodCall) {
        if expression.method == "commit"
            && let Expr::Path(receiver) = expression.receiver.as_ref()
            && receiver.path.is_ident("transaction")
        {
            self.commits_transaction = true;
        }
        syn::visit::visit_expr_method_call(self, expression);
    }
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(7 + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPENAPI: &str = r##"{
      "openapi":"3.1.0",
      "paths":{
        "/v1/delivery-blocks":{"get":{"operationId":"listDeliveryBlocks","responses":{"200":{"content":{"application/json":{"schema":{"type":"array","items":{"$ref":"#/components/schemas/BlockedDelivery"}}}}}}}},
        "/v1/delivery-blocks/{block_id}/resolve":{"post":{"operationId":"resolveDeliveryBlock","parameters":[{"name":"block_id","in":"path","required":true}],"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/ResolveDeliveryBlock"}}}}}}
      },
      "components":{"schemas":{
        "BlockedDelivery":{"type":"object","required":["block_id","reason","message"]},
        "ResolveDeliveryBlock":{"type":"object","properties":{"resolution":{"$ref":"#/components/schemas/BlockResolution"}}},
        "BlockResolution":{"type":"string","enum":["requeue","abandon"]}
      }}
    }"##;

    const API: &str = r#"
      async fn list_delivery_blocks() { require_operator()?; }
      async fn resolve_delivery_block() { require_operator()?; }
    "#;

    const MODEL: &str = r#"
      #[serde(rename_all = "snake_case")]
      enum BlockResolution { Requeue, Abandon }
    "#;

    const DELIVERY: &str = r#"
      async fn resolve_delivery_row(input: Input) {
        match input.resolution {
          BlockResolution::Requeue => sqlx::query("UPDATE agent_deliveries SET state = 'pending'").execute(&mut transaction).await?,
          BlockResolution::Abandon => sqlx::query("UPDATE agent_deliveries SET state = 'dead'").execute(&mut transaction).await?,
        };
      }

      struct Store;
      impl Store {
        async fn resolve_delivery_block(&self) -> Result<(), Error> {
          let mut transaction = self.pool.begin().await?;
          resolve_delivery_row(&mut transaction, input).await?;
          transaction.commit().await?;
          Ok(())
        }
      }
    "#;

    fn lift(api: &str, delivery: &str) -> FleetdControlLift {
        lift_fleetd_control(
            FleetdControlSources {
                openapi: OPENAPI,
                api_rust: api,
                model_rust: MODEL,
                delivery_rust: delivery,
            },
            "fleetd-test",
            "fixture-revision",
        )
        .expect("fixture lifts")
    }

    #[test]
    fn unlike_authorities_converge_on_the_review_loop() {
        let lifted = lift(API, DELIVERY);

        assert_eq!(lifted.coverage.completeness, NativeCompleteness::Exhaustive);
        assert!(lifted.list_operator_guarded);
        assert!(lifted.resolve_operator_guarded);
        assert!(lifted.resolution_effects_committed);
        assert_eq!(
            lifted.blocked_delivery_schema.as_deref(),
            Some("BlockedDelivery")
        );
        assert_eq!(lifted.resolution_selector.as_deref(), Some("block_id"));
        assert_eq!(lifted.resolutions[0].wire_name, "requeue");
        assert_eq!(
            lifted.resolutions[0].resulting_state.as_deref(),
            Some("pending")
        );
        assert_eq!(
            lifted.resolutions[1].resulting_state.as_deref(),
            Some("dead")
        );
    }

    #[test]
    fn a_missing_authority_guard_is_partial_not_operator_safe() {
        let lifted = lift(
            "async fn list_delivery_blocks() {} async fn resolve_delivery_block() { require_operator()?; }",
            DELIVERY,
        );

        assert_eq!(lifted.coverage.completeness, NativeCompleteness::Partial);
        assert!(!lifted.list_operator_guarded);
        assert!(
            lifted
                .coverage
                .unresolved
                .iter()
                .any(|reason| reason.contains("list_delivery_blocks operator guard"))
        );
    }

    #[test]
    fn an_unresolved_effect_does_not_follow_the_choice_name() {
        let lifted = lift(
            API,
            r#"
              async fn resolve_delivery_row(input: Input) {
                match input.resolution {
                  BlockResolution::Requeue => do_something(),
                  BlockResolution::Abandon => do_something_else(),
                };
              }

              struct Store;
              impl Store {
                async fn resolve_delivery_block(&self) -> Result<(), Error> {
                  resolve_delivery_row(&mut transaction, input).await?;
                  transaction.commit().await?;
                  Ok(())
                }
              }
            "#,
        );

        assert_eq!(lifted.coverage.completeness, NativeCompleteness::Partial);
        assert!(
            lifted
                .resolutions
                .iter()
                .all(|resolution| resolution.resulting_state.is_none())
        );
    }

    #[test]
    fn ignored_or_late_operator_calls_are_not_authority_guards() {
        let lifted = lift(
            r#"
              async fn list_delivery_blocks() { do_work(); require_operator()?; }
              async fn resolve_delivery_block() { require_operator(); }
            "#,
            DELIVERY,
        );

        assert!(!lifted.list_operator_guarded);
        assert!(!lifted.resolve_operator_guarded);
        assert_eq!(lifted.coverage.completeness, NativeCompleteness::Partial);
    }

    #[test]
    fn state_text_not_executed_as_sql_is_not_an_effect() {
        let lifted = lift(
            API,
            r#"
              async fn resolve_delivery_row(input: Input) {
                match input.resolution {
                  BlockResolution::Requeue => log("state = 'pending'"),
                  BlockResolution::Abandon => log("state = 'dead'"),
                };
              }

              struct Store;
              impl Store {
                async fn resolve_delivery_block(&self) -> Result<(), Error> {
                  resolve_delivery_row(&mut transaction, input).await?;
                  transaction.commit().await?;
                  Ok(())
                }
              }
            "#,
        );

        assert!(
            lifted
                .resolutions
                .iter()
                .all(|resolution| resolution.resulting_state.is_none())
        );
    }

    #[test]
    fn an_uncommitted_resolution_path_is_partial() {
        let lifted = lift(
            API,
            r#"
              async fn resolve_delivery_row(input: Input) {
                match input.resolution {
                  BlockResolution::Requeue => sqlx::query("UPDATE agent_deliveries SET state = 'pending'").execute(&mut transaction).await?,
                  BlockResolution::Abandon => sqlx::query("UPDATE agent_deliveries SET state = 'dead'").execute(&mut transaction).await?,
                };
              }

              struct Store;
              impl Store {
                async fn resolve_delivery_block(&self) -> Result<(), Error> {
                  resolve_delivery_row(&mut transaction, input).await?;
                  Ok(())
                }
              }
            "#,
        );

        assert!(!lifted.resolution_effects_committed);
        assert_eq!(lifted.coverage.completeness, NativeCompleteness::Partial);
    }
}
