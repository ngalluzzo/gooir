//! Native lifting for Buzz relay ingest legality.
//!
//! The lifter evaluates the closed `required_scope_for_kind` match for the job
//! kinds supplied by `buzz-protocol-lifter`. It refuses an exhaustive result
//! when a guard, constant, fallback, or call site cannot be resolved.

use buzz_protocol_lifter::{ProtocolLift, SourceArtifact, SourceSpan};
use proc_macro2::Span;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};
use syn::{
    BinOp, Expr, ExprCall, ExprMacro, Item, ItemFn, Pat, Token,
    parse::{Parse, ParseStream},
    spanned::Spanned,
    visit::{self, Visit},
};

pub const EXTRACTOR_PACKAGE: &str = "org.gooi.lifter.buzz_relay";
pub const EXTRACTOR_VERSION: &str = "0.1.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestDecisionKind {
    Accepted,
    Rejected,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JobIngestDecision {
    pub symbol: String,
    pub value: u32,
    pub decision: IngestDecisionKind,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeCompleteness {
    Exhaustive,
    Partial,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayCoverage {
    pub extractor_package: String,
    pub extractor_version: String,
    pub mechanism: String,
    pub completeness: NativeCompleteness,
    pub included_artifacts: Vec<String>,
    pub unresolved: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayIngestLift {
    pub source: SourceArtifact,
    pub protocol_source: SourceArtifact,
    pub scope_function: SourceSpan,
    pub gate_call: SourceSpan,
    pub fallback: SourceSpan,
    pub fallback_error: String,
    pub job_decisions: Vec<JobIngestDecision>,
    pub coverage: RelayCoverage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiftError {
    InvalidIngestRust(String),
    InvalidKindRust(String),
    ProtocolSourceDigestMismatch { expected: String, actual: String },
    MissingScopeFunction,
    MissingScopeMatch,
    MissingGateCall,
    MissingFallback,
    MissingSourceSpan { construct: String },
}

impl fmt::Display for LiftError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIngestRust(error) => {
                write!(formatter, "ingest source is not valid Rust: {error}")
            }
            Self::InvalidKindRust(error) => {
                write!(formatter, "kind source is not valid Rust: {error}")
            }
            Self::ProtocolSourceDigestMismatch { expected, actual } => write!(
                formatter,
                "protocol source digest mismatch: lift records {expected}, input is {actual}"
            ),
            Self::MissingScopeFunction => {
                formatter.write_str("required_scope_for_kind was not found")
            }
            Self::MissingScopeMatch => {
                formatter.write_str("required_scope_for_kind has no direct match on kind")
            }
            Self::MissingGateCall => {
                formatter.write_str("production ingest gate call was not found")
            }
            Self::MissingFallback => formatter.write_str("closed rejecting fallback was not found"),
            Self::MissingSourceSpan { construct } => {
                write!(formatter, "could not resolve source span for {construct}")
            }
        }
    }
}

impl std::error::Error for LiftError {}

pub fn lift_relay_ingest(
    ingest_source: &str,
    kind_source: &str,
    protocol: &ProtocolLift,
    authority: impl Into<String>,
    artifact: impl Into<String>,
    revision: impl Into<String>,
) -> Result<RelayIngestLift, LiftError> {
    let actual_kind_digest = sha256(kind_source.as_bytes());
    if actual_kind_digest != protocol.source.sha256 {
        return Err(LiftError::ProtocolSourceDigestMismatch {
            expected: protocol.source.sha256.clone(),
            actual: actual_kind_digest,
        });
    }

    let ingest_file = syn::parse_file(ingest_source)
        .map_err(|error| LiftError::InvalidIngestRust(error.to_string()))?;
    let kind_file = syn::parse_file(kind_source)
        .map_err(|error| LiftError::InvalidKindRust(error.to_string()))?;
    let constants = direct_u32_constants(&kind_file);
    let predicates = named_predicates(&kind_file, &constants);
    let scope_function = find_function(&ingest_file, "required_scope_for_kind")
        .ok_or(LiftError::MissingScopeFunction)?;
    let scope_match = direct_scope_match(scope_function).ok_or(LiftError::MissingScopeMatch)?;

    let mut calls = ScopeCallVisitor::default();
    if let Some(ingest) = find_function(&ingest_file, "ingest_event_inner") {
        calls.visit_item_fn(ingest);
    }
    let gate_call_span = calls
        .gate_calls
        .first()
        .copied()
        .ok_or(LiftError::MissingGateCall)?;

    let fallback_arm = scope_match
        .arms
        .iter()
        .find(|arm| matches!(arm.pat, Pat::Wild(_)))
        .ok_or(LiftError::MissingFallback)?;
    let fallback_error = err_literal(&fallback_arm.body).ok_or(LiftError::MissingFallback)?;

    let mut unresolved = Vec::new();
    let job_decisions = protocol
        .job_kinds
        .iter()
        .map(|job| {
            let (decision, reason) =
                evaluate_match(scope_match, job.value, &constants, &predicates);
            if decision == IngestDecisionKind::Unknown {
                unresolved.push(format!("{} ({}) — {reason}", job.symbol, job.value));
            }
            JobIngestDecision {
                symbol: job.symbol.clone(),
                value: job.value,
                decision,
                reason,
            }
        })
        .collect::<Vec<_>>();

    let artifact = artifact.into();
    Ok(RelayIngestLift {
        source: SourceArtifact {
            authority: authority.into(),
            artifact: artifact.clone(),
            revision: revision.into(),
            sha256: sha256(ingest_source.as_bytes()),
        },
        protocol_source: protocol.source.clone(),
        scope_function: source_span(ingest_source, scope_function.span(), "scope function")?,
        gate_call: source_span(ingest_source, gate_call_span, "gate call")?,
        fallback: source_span(ingest_source, fallback_arm.span(), "fallback")?,
        fallback_error,
        job_decisions,
        coverage: RelayCoverage {
            extractor_package: EXTRACTOR_PACKAGE.to_owned(),
            extractor_version: EXTRACTOR_VERSION.to_owned(),
            mechanism: "rust_closed_required_scope_match_and_production_call".to_owned(),
            completeness: if unresolved.is_empty() {
                NativeCompleteness::Exhaustive
            } else {
                NativeCompleteness::Partial
            },
            included_artifacts: vec![artifact, protocol.source.artifact.clone()],
            unresolved,
        },
    })
}

fn find_function<'a>(file: &'a syn::File, name: &str) -> Option<&'a ItemFn> {
    file.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    })
}

fn direct_scope_match(function: &ItemFn) -> Option<&syn::ExprMatch> {
    function.block.stmts.iter().find_map(|statement| {
        let syn::Stmt::Expr(Expr::Match(expression), _) = statement else {
            return None;
        };
        matches!(&*expression.expr, Expr::Path(path) if path.path.is_ident("kind"))
            .then_some(expression)
    })
}

fn direct_u32_constants(file: &syn::File) -> BTreeMap<String, u32> {
    file.items
        .iter()
        .filter_map(|item| {
            let Item::Const(item) = item else { return None };
            let Expr::Lit(literal) = &*item.expr else {
                return None;
            };
            let syn::Lit::Int(value) = &literal.lit else {
                return None;
            };
            value
                .base10_parse::<u32>()
                .ok()
                .map(|value| (item.ident.to_string(), value))
        })
        .collect()
}

#[derive(Clone, Debug)]
struct PredicateValues {
    values: Vec<u32>,
    complete: bool,
}

fn named_predicates(
    file: &syn::File,
    constants: &BTreeMap<String, u32>,
) -> BTreeMap<String, PredicateValues> {
    file.items
        .iter()
        .filter_map(|item| {
            let Item::Fn(function) = item else {
                return None;
            };
            let expression = function
                .block
                .stmts
                .last()
                .and_then(|statement| match statement {
                    syn::Stmt::Expr(expression, _) => Some(expression),
                    _ => None,
                })?;
            let Expr::Macro(expression) = expression else {
                return None;
            };
            let matches = parse_matches_macro(expression)?;
            let parameter = function
                .sig
                .inputs
                .first()
                .and_then(|argument| match argument {
                    syn::FnArg::Typed(argument) => match &*argument.pat {
                        Pat::Ident(parameter) => Some(parameter.ident.to_string()),
                        _ => None,
                    },
                    syn::FnArg::Receiver(_) => None,
                })?;
            if !matches_expression_is_parameter(&matches.expression, &parameter) {
                return None;
            }
            let (values, complete) = pattern_values(&matches.pattern, constants);
            Some((
                function.sig.ident.to_string(),
                PredicateValues { values, complete },
            ))
        })
        .collect()
}

struct MatchesInput {
    expression: Expr,
    _comma: Token![,],
    pattern: Pat,
}

impl Parse for MatchesInput {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        Ok(Self {
            expression: input.parse()?,
            _comma: input.parse()?,
            pattern: Pat::parse_multi_with_leading_vert(input)?,
        })
    }
}

fn matches_expression_is_parameter(matches: &Expr, parameter: &str) -> bool {
    matches!(matches, Expr::Path(path) if path.path.is_ident(parameter))
}

fn parse_matches_macro(expression: &ExprMacro) -> Option<MatchesInput> {
    expression
        .mac
        .path
        .is_ident("matches")
        .then(|| syn::parse2(expression.mac.tokens.clone()).ok())
        .flatten()
}

fn pattern_values(pattern: &Pat, constants: &BTreeMap<String, u32>) -> (Vec<u32>, bool) {
    match pattern {
        Pat::Or(pattern) => {
            let mut values = Vec::new();
            let mut complete = true;
            for case in &pattern.cases {
                let (case_values, case_complete) = pattern_values(case, constants);
                values.extend(case_values);
                complete &= case_complete;
            }
            (values, complete)
        }
        Pat::Path(path) => {
            let symbol = path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string());
            match symbol.and_then(|symbol| constants.get(&symbol).copied()) {
                Some(value) => (vec![value], true),
                None => (Vec::new(), false),
            }
        }
        Pat::Ident(ident) => {
            let symbol = ident.ident.to_string();
            match constants.get(&symbol).copied() {
                Some(value) => (vec![value], true),
                None => (Vec::new(), false),
            }
        }
        Pat::Lit(literal) => match &literal.lit {
            syn::Lit::Int(value) => match value.base10_parse::<u32>() {
                Ok(value) => (vec![value], true),
                Err(_) => (Vec::new(), false),
            },
            _ => (Vec::new(), false),
        },
        Pat::Paren(pattern) => pattern_values(&pattern.pat, constants),
        _ => (Vec::new(), false),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Truth {
    True,
    False,
    Unknown,
}

fn evaluate_match(
    expression: &syn::ExprMatch,
    candidate: u32,
    constants: &BTreeMap<String, u32>,
    predicates: &BTreeMap<String, PredicateValues>,
) -> (IngestDecisionKind, String) {
    for arm in &expression.arms {
        let (pattern, guard) = match &arm.pat {
            Pat::Guard(guard) => (
                pattern_truth(&guard.pat, candidate, constants),
                guard_truth(&guard.guard, candidate, constants, predicates),
            ),
            pattern => (pattern_truth(pattern, candidate, constants), Truth::True),
        };
        match and(pattern, guard) {
            Truth::False => continue,
            Truth::Unknown => {
                return (
                    IngestDecisionKind::Unknown,
                    "an earlier match arm or guard could not be evaluated".to_owned(),
                );
            }
            Truth::True => {
                if let Some(error) = err_literal(&arm.body) {
                    return (IngestDecisionKind::Rejected, error);
                }
                return (
                    IngestDecisionKind::Accepted,
                    "required_scope_for_kind resolves to a non-error arm".to_owned(),
                );
            }
        }
    }
    (
        IngestDecisionKind::Unknown,
        "closed match did not select an arm".to_owned(),
    )
}

fn pattern_truth(pattern: &Pat, candidate: u32, constants: &BTreeMap<String, u32>) -> Truth {
    match pattern {
        Pat::Wild(_) => Truth::True,
        Pat::Ident(ident) => {
            let symbol = ident.ident.to_string();
            constants.get(&symbol).map_or_else(
                || {
                    if symbol.chars().all(|character| {
                        character.is_ascii_lowercase()
                            || character.is_ascii_digit()
                            || character == '_'
                    }) {
                        Truth::True
                    } else {
                        Truth::Unknown
                    }
                },
                |value| {
                    if *value == candidate {
                        Truth::True
                    } else {
                        Truth::False
                    }
                },
            )
        }
        Pat::Or(pattern) => pattern.cases.iter().fold(Truth::False, |result, case| {
            or(result, pattern_truth(case, candidate, constants))
        }),
        Pat::Path(path) => path
            .path
            .segments
            .last()
            .and_then(|segment| constants.get(&segment.ident.to_string()))
            .map_or(Truth::Unknown, |value| {
                if *value == candidate {
                    Truth::True
                } else {
                    Truth::False
                }
            }),
        Pat::Lit(literal) => match &literal.lit {
            syn::Lit::Int(value) => value.base10_parse::<u32>().map_or(Truth::Unknown, |value| {
                if value == candidate {
                    Truth::True
                } else {
                    Truth::False
                }
            }),
            _ => Truth::Unknown,
        },
        Pat::Paren(pattern) => pattern_truth(&pattern.pat, candidate, constants),
        _ => Truth::Unknown,
    }
}

fn guard_truth(
    expression: &Expr,
    candidate: u32,
    constants: &BTreeMap<String, u32>,
    predicates: &BTreeMap<String, PredicateValues>,
) -> Truth {
    match expression {
        Expr::Binary(binary) => match binary.op {
            BinOp::Or(_) => or(
                guard_truth(&binary.left, candidate, constants, predicates),
                guard_truth(&binary.right, candidate, constants, predicates),
            ),
            BinOp::And(_) => and(
                guard_truth(&binary.left, candidate, constants, predicates),
                guard_truth(&binary.right, candidate, constants, predicates),
            ),
            BinOp::Eq(_) => {
                comparison_truth(&binary.left, &binary.right, candidate, constants, false)
            }
            BinOp::Ne(_) => {
                comparison_truth(&binary.left, &binary.right, candidate, constants, true)
            }
            _ => Truth::Unknown,
        },
        Expr::Call(call) => predicate_truth(call, candidate, constants, predicates),
        Expr::Paren(expression) => guard_truth(&expression.expr, candidate, constants, predicates),
        Expr::Group(expression) => guard_truth(&expression.expr, candidate, constants, predicates),
        Expr::Lit(literal) => match &literal.lit {
            syn::Lit::Bool(value) => {
                if value.value {
                    Truth::True
                } else {
                    Truth::False
                }
            }
            _ => Truth::Unknown,
        },
        _ => Truth::Unknown,
    }
}

fn comparison_truth(
    left: &Expr,
    right: &Expr,
    candidate: u32,
    constants: &BTreeMap<String, u32>,
    negate: bool,
) -> Truth {
    let left = expression_value(left, candidate, constants);
    let right = expression_value(right, candidate, constants);
    match (left, right) {
        (Some(left), Some(right)) => {
            let equal = left == right;
            if equal ^ negate {
                Truth::True
            } else {
                Truth::False
            }
        }
        _ => Truth::Unknown,
    }
}

fn expression_value(
    expression: &Expr,
    candidate: u32,
    constants: &BTreeMap<String, u32>,
) -> Option<u32> {
    match expression {
        Expr::Path(path) => {
            let symbol = path.path.segments.last()?.ident.to_string();
            if symbol == "k" || symbol == "kind" {
                Some(candidate)
            } else {
                constants.get(&symbol).copied()
            }
        }
        Expr::Lit(literal) => match &literal.lit {
            syn::Lit::Int(value) => value.base10_parse().ok(),
            _ => None,
        },
        Expr::Paren(expression) => expression_value(&expression.expr, candidate, constants),
        Expr::Group(expression) => expression_value(&expression.expr, candidate, constants),
        _ => None,
    }
}

fn predicate_truth(
    call: &ExprCall,
    candidate: u32,
    constants: &BTreeMap<String, u32>,
    predicates: &BTreeMap<String, PredicateValues>,
) -> Truth {
    let Expr::Path(path) = &*call.func else {
        return Truth::Unknown;
    };
    let Some(name) = path
        .path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
    else {
        return Truth::Unknown;
    };
    let Some(predicate) = predicates.get(&name) else {
        return Truth::Unknown;
    };
    if call.args.len() != 1 {
        return Truth::Unknown;
    }
    let Some(argument) = call
        .args
        .first()
        .and_then(|argument| expression_value(argument, candidate, constants))
    else {
        return Truth::Unknown;
    };
    if predicate.values.contains(&argument) {
        Truth::True
    } else if predicate.complete {
        Truth::False
    } else {
        Truth::Unknown
    }
}

fn err_literal(expression: &Expr) -> Option<String> {
    let Expr::Call(call) = expression else {
        return None;
    };
    let Expr::Path(path) = &*call.func else {
        return None;
    };
    if !path.path.is_ident("Err") || call.args.len() != 1 {
        return None;
    }
    let Expr::Lit(literal) = call.args.first()? else {
        return None;
    };
    let syn::Lit::Str(message) = &literal.lit else {
        return None;
    };
    Some(message.value())
}

fn and(left: Truth, right: Truth) -> Truth {
    match (left, right) {
        (Truth::False, _) | (_, Truth::False) => Truth::False,
        (Truth::True, Truth::True) => Truth::True,
        _ => Truth::Unknown,
    }
}

fn or(left: Truth, right: Truth) -> Truth {
    match (left, right) {
        (Truth::True, _) | (_, Truth::True) => Truth::True,
        (Truth::False, Truth::False) => Truth::False,
        _ => Truth::Unknown,
    }
}

#[derive(Default)]
struct ScopeCallVisitor {
    gate_calls: Vec<Span>,
}

impl<'ast> Visit<'ast> for ScopeCallVisitor {
    fn visit_expr_call(&mut self, expression: &'ast ExprCall) {
        if matches!(&*expression.func, Expr::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == "required_scope_for_kind"))
        {
            self.gate_calls.push(expression.span());
        }
        visit::visit_expr_call(self, expression);
    }
}

fn source_span(source: &str, span: Span, construct: &str) -> Result<SourceSpan, LiftError> {
    let start = span.start();
    let end = span.end();
    let byte_start = byte_offset(source, start.line, start.column).ok_or_else(|| {
        LiftError::MissingSourceSpan {
            construct: construct.to_owned(),
        }
    })?;
    let byte_end =
        byte_offset(source, end.line, end.column).ok_or_else(|| LiftError::MissingSourceSpan {
            construct: construct.to_owned(),
        })?;
    Ok(SourceSpan {
        byte_start: byte_start as u64,
        byte_end: byte_end as u64,
        line_start: start.line as u32,
        line_end: end.line as u32,
    })
}

fn byte_offset(source: &str, line: usize, column: usize) -> Option<usize> {
    let line_start = if line == 1 {
        0
    } else {
        source.match_indices('\n').nth(line.checked_sub(2)?)?.0 + 1
    };
    let line_text = source
        .get(line_start..)?
        .split_once('\n')
        .map_or_else(|| source.get(line_start..), |(line, _)| Some(line))?;
    let column_offset = line_text
        .char_indices()
        .nth(column)
        .map_or(line_text.len(), |(offset, _)| offset);
    Some(line_start + column_offset)
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
    use buzz_protocol_lifter::lift_job_protocol;

    use super::{IngestDecisionKind, LiftError, NativeCompleteness, lift_relay_ingest};

    const KIND_SOURCE: &str = r#"
pub const KIND_MESSAGE: u32 = 1;
pub const KIND_SPECIAL: u32 = 2;
pub const KIND_MODERATION_BAN: u32 = 9040;
pub const KIND_JOB_REQUEST: u32 = 43001;
pub const KIND_JOB_RESULT: u32 = 43004;
pub const ALL_KINDS: &[u32] = &[KIND_MESSAGE, KIND_JOB_REQUEST, KIND_JOB_RESULT];
pub const fn is_moderation_command_kind(kind: u32) -> bool {
    matches!(kind, KIND_MODERATION_BAN)
}
"#;

    const INGEST_SOURCE: &str = r#"
fn required_scope_for_kind(kind: u32, event: &Event) -> Result<Scope, &'static str> {
    match kind {
        KIND_MESSAGE => Ok(Scope::MessagesWrite),
        k if is_moderation_command_kind(k) => Ok(Scope::MessagesWrite),
        KIND_SPECIAL if event.allowed => Ok(Scope::MessagesWrite),
        _ => Err("restricted: unknown event kind"),
    }
}

async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {
    let required = match required_scope_for_kind(kind_u32, &event) {
        Ok(scope) => scope,
        Err(error) => return Err(error.into()),
    };
    persist(required).await
}
"#;

    fn fixture_protocol() -> buzz_protocol_lifter::ProtocolLift {
        lift_job_protocol(KIND_SOURCE, "fixture", "kind.rs", "revision")
            .expect("protocol fixture lifts")
    }

    #[test]
    fn closed_fallback_rejects_job_kinds_after_resolving_named_guard() {
        let lift = lift_relay_ingest(
            INGEST_SOURCE,
            KIND_SOURCE,
            &fixture_protocol(),
            "fixture",
            "ingest.rs",
            "revision",
        )
        .expect("relay fixture lifts");

        assert!(
            lift.job_decisions.iter().all(|decision| {
                decision.decision == IngestDecisionKind::Rejected
                    && decision.reason == "restricted: unknown event kind"
            }),
            "{:?}",
            lift.job_decisions
        );
        assert_eq!(lift.coverage.completeness, NativeCompleteness::Exhaustive);
        assert_eq!(lift.gate_call.line_start, 12);
    }

    #[test]
    fn unresolved_guard_degrades_to_partial_unknown() {
        let source = INGEST_SOURCE.replace(
            "k if is_moderation_command_kind(k)",
            "k if third_party_guard(k)",
        );
        let lift = lift_relay_ingest(
            &source,
            KIND_SOURCE,
            &fixture_protocol(),
            "fixture",
            "ingest.rs",
            "revision",
        )
        .expect("unresolved relay fixture still lifts");

        assert!(
            lift.job_decisions
                .iter()
                .all(|decision| decision.decision == IngestDecisionKind::Unknown),
            "{:?}",
            lift.job_decisions
        );
        assert_eq!(lift.coverage.completeness, NativeCompleteness::Partial);
    }

    #[test]
    fn predicate_must_evaluate_its_declared_parameter() {
        let kind_source = KIND_SOURCE.replace(
            "matches!(kind, KIND_MODERATION_BAN)",
            "matches!(KIND_MODERATION_BAN, KIND_MODERATION_BAN)",
        );
        let protocol = lift_job_protocol(&kind_source, "fixture", "kind.rs", "revision")
            .expect("modified protocol fixture lifts");
        let lift = lift_relay_ingest(
            INGEST_SOURCE,
            &kind_source,
            &protocol,
            "fixture",
            "ingest.rs",
            "revision",
        )
        .expect("unresolved predicate fixture still lifts");

        assert!(
            lift.job_decisions
                .iter()
                .all(|decision| decision.decision == IngestDecisionKind::Unknown)
        );
        assert_eq!(lift.coverage.completeness, NativeCompleteness::Partial);
    }

    #[test]
    fn mismatched_protocol_source_is_rejected() {
        let error = lift_relay_ingest(
            INGEST_SOURCE,
            &KIND_SOURCE.replace("43001", "43002"),
            &fixture_protocol(),
            "fixture",
            "ingest.rs",
            "revision",
        )
        .expect_err("source mismatch must not be laundered");

        assert!(matches!(
            error,
            LiftError::ProtocolSourceDigestMismatch { .. }
        ));
    }

    #[test]
    fn pinned_native_output_records_six_exhaustive_rejections() {
        let lift: super::RelayIngestLift = serde_json::from_str(include_str!(
            "../../../fixtures/buzz/desktop-v0.5.18/job-relay.lift.json"
        ))
        .expect("pinned output matches the native schema");

        assert_eq!(
            lift.source.sha256,
            "sha256:6f5ecbac1056c64ce161e72bc9d4b0fabc2c8d8648fb41b3812a655121f194a5"
        );
        assert_eq!(lift.gate_call.line_start, 2157);
        assert_eq!(lift.fallback.line_start, 453);
        assert_eq!(lift.job_decisions.len(), 6);
        assert!(
            lift.job_decisions
                .iter()
                .all(|decision| decision.decision == IngestDecisionKind::Rejected)
        );
        assert_eq!(lift.coverage.completeness, NativeCompleteness::Exhaustive);
    }
}
