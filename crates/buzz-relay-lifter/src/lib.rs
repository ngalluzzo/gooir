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
    BinOp, Expr, ExprCall, ExprMacro, ExprMethodCall, Item, ItemFn, Pat, Stmt, Token,
    parse::{Parse, ParseStream, Parser},
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

    let ingest = find_function(&ingest_file, "ingest_event_inner");
    let gate = prove_production_gate(ingest)?;

    let fallback_arm = scope_match
        .arms
        .iter()
        .find(|arm| matches!(arm.pat, Pat::Wild(_)))
        .ok_or(LiftError::MissingFallback)?;
    let fallback_error = err_literal(&fallback_arm.body).ok_or(LiftError::MissingFallback)?;

    let mut unresolved = Vec::new();
    if let Some(reason) = &gate.unresolved {
        unresolved.push(reason.clone());
    }
    let job_decisions = protocol
        .job_kinds
        .iter()
        .map(|job| {
            let (decision, reason) = if let Some(reason) = &gate.unresolved {
                (
                    IngestDecisionKind::Unknown,
                    format!("production ingest gate could not be proven: {reason}"),
                )
            } else {
                evaluate_match(scope_match, job.value, &constants, &predicates)
            };
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
        gate_call: source_span(ingest_source, gate.span, "gate call")?,
        fallback: source_span(ingest_source, fallback_arm.span(), "fallback")?,
        fallback_error,
        job_decisions,
        coverage: RelayCoverage {
            extractor_package: EXTRACTOR_PACKAGE.to_owned(),
            extractor_version: EXTRACTOR_VERSION.to_owned(),
            mechanism: "rust_closed_required_scope_match_and_proven_ingest_gate".to_owned(),
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
    let [syn::Stmt::Expr(Expr::Match(expression), _)] = function.block.stmts.as_slice() else {
        return None;
    };
    matches!(&*expression.expr, Expr::Path(path) if path.path.is_ident("kind"))
        .then_some(expression)
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

struct GateProof {
    span: Span,
    unresolved: Option<String>,
}

fn prove_production_gate(ingest: Option<&ItemFn>) -> Result<GateProof, LiftError> {
    let ingest = ingest.ok_or(LiftError::MissingGateCall)?;
    let mut calls = ScopeCallVisitor::default();
    calls.visit_item_fn(ingest);
    let fallback_span = calls
        .gate_calls
        .first()
        .copied()
        .ok_or(LiftError::MissingGateCall)?;

    for (gate_index, statement) in ingest.block.stmts.iter().enumerate() {
        let Some((call, gate_match)) = direct_gate_statement(statement) else {
            continue;
        };
        let span = call.span();
        let prior_statements = &ingest.block.stmts[..gate_index];
        if prior_statements
            .iter()
            .any(|prior| matches!(prior, Stmt::Expr(Expr::Return(_), _)))
        {
            return Ok(GateProof {
                span,
                unresolved: Some(
                    "required_scope_for_kind is unreachable after an unconditional return"
                        .to_owned(),
                ),
            });
        }
        if let Err(reason) = gate_checks_incoming_kind(ingest, call, prior_statements) {
            return Ok(GateProof {
                span,
                unresolved: Some(reason),
            });
        }
        if !gate_rejection_returns(gate_match) {
            return Ok(GateProof {
                span,
                unresolved: Some(
                    "required_scope_for_kind rejection does not directly return from ingest_event_inner"
                        .to_owned(),
                ),
            });
        }

        let mut gate_arm_risks = PreGateRiskVisitor::default();
        for arm in &gate_match.arms {
            gate_arm_risks.visit_arm(arm);
        }
        if let Some(risk) = gate_arm_risks.risks.first() {
            return Ok(GateProof {
                span,
                unresolved: Some(format!(
                    "{risk} can run inside the required_scope_for_kind gate"
                )),
            });
        }

        let mut risks = PreGateRiskVisitor::default();
        for statement in prior_statements {
            risks.visit_stmt(statement);
        }
        if let Some(risk) = risks.risks.first() {
            return Ok(GateProof {
                span,
                unresolved: Some(format!("{risk} can run before required_scope_for_kind")),
            });
        }

        return Ok(GateProof {
            span,
            unresolved: None,
        });
    }

    Ok(GateProof {
        span: fallback_span,
        unresolved: Some(
            "required_scope_for_kind is not a direct top-level terminating match gate".to_owned(),
        ),
    })
}

fn direct_gate_statement(statement: &Stmt) -> Option<(&ExprCall, &syn::ExprMatch)> {
    let Stmt::Local(local) = statement else {
        return None;
    };
    let initializer = local.init.as_ref()?;
    let Expr::Match(gate_match) = strip_expression(&initializer.expr) else {
        return None;
    };
    let Expr::Call(call) = strip_expression(&gate_match.expr) else {
        return None;
    };
    is_required_scope_call(call).then_some((call, gate_match))
}

fn is_required_scope_call(call: &ExprCall) -> bool {
    matches!(
        strip_expression(&call.func),
        Expr::Path(path)
            if path.path.segments.last().is_some_and(|segment| {
                segment.ident == "required_scope_for_kind"
            })
    )
}

fn gate_checks_incoming_kind(
    ingest: &ItemFn,
    call: &ExprCall,
    prior_statements: &[Stmt],
) -> Result<(), String> {
    let Some(kind_argument) = call.args.first() else {
        return Err("required_scope_for_kind has no kind argument".to_owned());
    };
    let Expr::Path(kind_path) = strip_expression(kind_argument) else {
        return Err(
            "required_scope_for_kind does not receive a direct incoming-kind binding".to_owned(),
        );
    };
    let Some(kind_name) = kind_path.path.get_ident().map(ToString::to_string) else {
        return Err(
            "required_scope_for_kind does not receive a local incoming-kind binding".to_owned(),
        );
    };

    let event_parameters = ingest
        .sig
        .inputs
        .iter()
        .filter_map(|argument| match argument {
            syn::FnArg::Typed(argument) => match &*argument.pat {
                Pat::Ident(ident) if ident.ident.to_string().contains("event") => {
                    Some(ident.ident.to_string())
                }
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect::<Vec<_>>();
    if event_parameters.len() != 1 || event_parameters[0] != "event" {
        return Err(
            "ingest_event_inner does not have one canonical incoming event parameter".to_owned(),
        );
    }
    if call.args.len() != 2
        || call
            .args
            .get(1)
            .and_then(expression_binding_name)
            .is_none_or(|argument| argument != "event")
    {
        return Err(
            "required_scope_for_kind does not receive the canonical incoming event".to_owned(),
        );
    }

    if let Some(local) = prior_statements.iter().rev().find_map(|statement| {
        let Stmt::Local(local) = statement else {
            return None;
        };
        matches!(&local.pat, Pat::Ident(binding) if binding.ident == kind_name).then_some(local)
    }) {
        let Some(initializer) = &local.init else {
            return Err(
                "required_scope_for_kind kind binding has no incoming-event initializer".to_owned(),
            );
        };
        let Expr::Call(derived) = strip_expression(&initializer.expr) else {
            return Err(
                "required_scope_for_kind kind binding is not derived from the incoming event"
                    .to_owned(),
            );
        };
        let Expr::Path(function) = strip_expression(&derived.func) else {
            return Err(
                "required_scope_for_kind kind binding is not derived from the incoming event"
                    .to_owned(),
            );
        };
        if function
            .path
            .segments
            .last()
            .is_none_or(|segment| segment.ident != "event_kind_u32")
            || derived.args.len() != 1
        {
            return Err(
                "required_scope_for_kind kind binding is not derived from the incoming event"
                    .to_owned(),
            );
        }
        let Some(argument_name) = expression_binding_name(&derived.args[0]) else {
            return Err(
                "required_scope_for_kind kind binding is not derived from the incoming event"
                    .to_owned(),
            );
        };
        if argument_name == "event" {
            return Ok(());
        }
        return Err(
            "required_scope_for_kind kind binding is not derived from the incoming event"
                .to_owned(),
        );
    }

    let kind_parameters = ingest
        .sig
        .inputs
        .iter()
        .filter_map(|argument| match argument {
            syn::FnArg::Typed(argument) => match &*argument.pat {
                Pat::Ident(ident) if ident.ident.to_string().contains("kind") => {
                    Some(ident.ident.to_string())
                }
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect::<Vec<_>>();
    if kind_name == "kind_u32" && kind_parameters == [kind_name.clone()] {
        return Ok(());
    }

    if kind_parameters
        .iter()
        .any(|parameter| parameter == &kind_name)
    {
        return Err(
            "required_scope_for_kind direct kind parameter is ambiguous or not the canonical incoming kind"
                .to_owned(),
        );
    }

    Err("required_scope_for_kind kind argument is not derived from the incoming event".to_owned())
}

fn expression_binding_name(expression: &Expr) -> Option<String> {
    match strip_expression(expression) {
        Expr::Reference(reference) => expression_binding_name(&reference.expr),
        Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
        _ => None,
    }
}

fn gate_rejection_returns(gate_match: &syn::ExprMatch) -> bool {
    let mut saw_error_arm = false;
    let mut saw_catch_all_error_arm = false;
    for arm in &gate_match.arms {
        if !pattern_can_match_error(&arm.pat) {
            continue;
        }
        saw_error_arm = true;
        if !expression_returns_err(&arm.body) {
            return false;
        }
        saw_catch_all_error_arm |= pattern_is_catch_all_error(&arm.pat);
    }
    saw_error_arm && saw_catch_all_error_arm
}

fn pattern_can_match_error(pattern: &Pat) -> bool {
    match pattern {
        Pat::TupleStruct(pattern) => pattern
            .path
            .segments
            .last()
            .is_none_or(|segment| segment.ident != "Ok"),
        Pat::Or(pattern) => pattern.cases.iter().any(pattern_can_match_error),
        Pat::Guard(pattern) => pattern_can_match_error(&pattern.pat),
        Pat::Paren(pattern) => pattern_can_match_error(&pattern.pat),
        _ => true,
    }
}

fn pattern_is_catch_all_error(pattern: &Pat) -> bool {
    match pattern {
        Pat::TupleStruct(pattern)
            if pattern
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "Err")
                && pattern.elems.len() == 1 =>
        {
            matches!(pattern.elems.first(), Some(Pat::Wild(_)))
                || matches!(pattern.elems.first(), Some(Pat::Ident(ident)) if ident.subpat.is_none())
        }
        Pat::Or(pattern) => pattern.cases.iter().any(pattern_is_catch_all_error),
        Pat::Paren(pattern) => pattern_is_catch_all_error(&pattern.pat),
        Pat::Ident(pattern) => pattern.subpat.is_none(),
        Pat::Wild(_) => true,
        _ => false,
    }
}

fn expression_returns_err(expression: &Expr) -> bool {
    match strip_expression(expression) {
        Expr::Return(return_expression) => return_expression
            .expr
            .as_deref()
            .is_some_and(expression_is_err),
        Expr::Block(block) if block.block.stmts.len() == 1 => match &block.block.stmts[0] {
            Stmt::Expr(expression, _) => expression_returns_err(expression),
            _ => false,
        },
        _ => false,
    }
}

fn expression_is_err(expression: &Expr) -> bool {
    matches!(
        strip_expression(expression),
        Expr::Call(call)
            if matches!(strip_expression(&call.func), Expr::Path(path) if path.path.is_ident("Err"))
    )
}

fn strip_expression(expression: &Expr) -> &Expr {
    match expression {
        Expr::Group(group) => strip_expression(&group.expr),
        Expr::Paren(paren) => strip_expression(&paren.expr),
        _ => expression,
    }
}

#[derive(Default)]
struct PreGateRiskVisitor {
    risks: Vec<String>,
}

impl<'ast> Visit<'ast> for PreGateRiskVisitor {
    fn visit_expr(&mut self, expression: &'ast Expr) {
        match expression {
            Expr::Assign(_) => self
                .risks
                .push("an assignment with unproven effects".to_owned()),
            Expr::Binary(binary) if assignment_operator(&binary.op) => self
                .risks
                .push("an assignment with unproven effects".to_owned()),
            Expr::ForLoop(_) | Expr::Loop(_) | Expr::While(_) => {
                self.risks.push("a potentially diverging loop".to_owned())
            }
            Expr::Return(expression)
                if expression
                    .expr
                    .as_deref()
                    .is_none_or(|value| !expression_is_err(value)) =>
            {
                self.risks
                    .push("a non-error return that bypasses the gate".to_owned());
            }
            Expr::Unsafe(_) => self
                .risks
                .push("an unsafe block with unproven effects".to_owned()),
            _ => {}
        }
        visit::visit_expr(self, expression);
    }

    fn visit_expr_call(&mut self, expression: &'ast ExprCall) {
        match strip_expression(&expression.func) {
            Expr::Path(path) if allowed_pre_gate_function(&path.path) => {}
            Expr::Path(path) => self.risks.push(format!(
                "unrecognized call `{}` with unproven effects",
                path_name(&path.path)
            )),
            _ => self
                .risks
                .push("a dynamic call with unproven effects".to_owned()),
        }
        visit::visit_expr_call(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast ExprMethodCall) {
        let method = expression.method.to_string();
        if !allowed_pre_gate_method_call(expression) && !modeled_serving_state_read(expression) {
            self.risks.push(format!(
                "unrecognized method call `{method}` with unproven effects"
            ));
        }
        visit::visit_expr_method_call(self, expression);
    }

    fn visit_expr_await(&mut self, expression: &'ast syn::ExprAwait) {
        let modeled = allowed_awaited_expression(&expression.base);
        visit::visit_expr_await(self, expression);
        if !modeled {
            self.risks
                .push("an unmodeled awaited future with unproven effects".to_owned());
        }
    }

    fn visit_expr_macro(&mut self, expression: &'ast ExprMacro) {
        self.inspect_macro(&expression.mac);
        visit::visit_expr_macro(self, expression);
    }

    fn visit_stmt_macro(&mut self, statement: &'ast syn::StmtMacro) {
        self.inspect_macro(&statement.mac);
        visit::visit_stmt_macro(self, statement);
    }
}

impl PreGateRiskVisitor {
    fn inspect_macro(&mut self, expression: &syn::Macro) {
        let name = expression
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_else(|| "<unknown>".to_owned());
        let modeled = match name.as_str() {
            "debug" => {
                expression.tokens.to_string()
                    == "event_id = % event_id_hex , kind = kind_u32 , \"ingest_event\""
            }
            "error" => syn::parse2::<syn::LitStr>(expression.tokens.clone())
                .is_ok_and(|message| message.value() == "spawn_blocking panicked: {e}"),
            "format" => modeled_format_macro(expression.tokens.clone()),
            _ => false,
        };
        if !modeled {
            self.risks.push(format!(
                "unmodeled macro `{name}!` that may diverge or have effects"
            ));
        }
    }
}

fn modeled_format_macro(tokens: proc_macro2::TokenStream) -> bool {
    let parser = syn::punctuated::Punctuated::<Expr, Token![,]>::parse_terminated;
    let Ok(arguments) = parser.parse2(tokens) else {
        return false;
    };
    let mut arguments = arguments.iter();
    let Some(Expr::Lit(format)) = arguments.next() else {
        return false;
    };
    let syn::Lit::Str(format) = &format.lit else {
        return false;
    };
    match format.value().as_str() {
        "invalid: kind {kind_u32} is only accepted via WebSocket" | "invalid: {e}" => {
            arguments.next().is_none()
        }
        "invalid: content exceeds maximum size of {} bytes (got {})" => {
            matches!(arguments.next(), Some(Expr::Path(path)) if path.path.is_ident("MAX_EVENT_CONTENT_BYTES"))
                && matches!(arguments.next(), Some(Expr::MethodCall(call)) if allowed_pre_gate_method_call(call))
                && arguments.next().is_none()
        }
        _ => false,
    }
}

fn allowed_pre_gate_function(path: &syn::Path) -> bool {
    matches!(
        path_name(path).as_str(),
        "Err"
            | "IngestError::AuthFailed"
            | "IngestError::Internal"
            | "IngestError::Rejected"
            | "buzz_core::kind::is_relay_only_kind"
            | "buzz_deletion::store"
            | "chrono::Utc::now"
            | "event_kind_u32"
            | "map_serving_fence_state"
            | "std::sync::Arc::clone"
            | "std::sync::Arc::new"
            | "std::sync::Arc::try_unwrap"
            | "tokio::task::spawn_blocking"
            | "verify_event"
    )
}

fn allowed_awaited_expression(expression: &Expr) -> bool {
    match strip_expression(expression) {
        Expr::Call(call) => matches!(
            strip_expression(&call.func),
            Expr::Path(path) if path_name(&path.path) == "tokio::task::spawn_blocking"
        ),
        Expr::MethodCall(call) => modeled_serving_state_read(call),
        _ => false,
    }
}

fn modeled_serving_state_read(call: &ExprMethodCall) -> bool {
    if call.method != "is_serving_active" || call.args.len() != 1 {
        return false;
    }
    let Expr::Call(store) = strip_expression(&call.receiver) else {
        return false;
    };
    if !matches!(
        strip_expression(&store.func),
        Expr::Path(path) if path_name(&path.path) == "buzz_deletion::store"
    ) || store.args.len() != 1
    {
        return false;
    }
    let Some(store_argument) = store.args.first() else {
        return false;
    };
    let Expr::Reference(reference) = strip_expression(store_argument) else {
        return false;
    };
    let Expr::Field(field) = strip_expression(&reference.expr) else {
        return false;
    };
    if !matches!(&field.member, syn::Member::Named(member) if member == "db")
        || !matches!(strip_expression(&field.base), Expr::Path(path) if path.path.is_ident("state"))
    {
        return false;
    }

    let Some(community_argument) = call.args.first() else {
        return false;
    };
    matches!(
        strip_expression(community_argument),
        Expr::MethodCall(community)
            if community.method == "community"
                && community.args.is_empty()
                && matches!(strip_expression(&community.receiver), Expr::Path(path) if path.path.is_ident("tenant"))
    )
}

fn assignment_operator(operator: &BinOp) -> bool {
    matches!(
        operator,
        BinOp::AddAssign(_)
            | BinOp::SubAssign(_)
            | BinOp::MulAssign(_)
            | BinOp::DivAssign(_)
            | BinOp::RemAssign(_)
            | BinOp::BitXorAssign(_)
            | BinOp::BitAndAssign(_)
            | BinOp::BitOrAssign(_)
            | BinOp::ShlAssign(_)
            | BinOp::ShrAssign(_)
    )
}

fn allowed_pre_gate_method_call(call: &ExprMethodCall) -> bool {
    let method = call.method.to_string();
    let receiver = strip_expression(&call.receiver);
    match method.as_str() {
        "to_hex" => call.args.is_empty() && expression_is_field(receiver, "event", "id"),
        "community" => call.args.is_empty() && expression_is_path(receiver, "tenant"),
        "is_http" | "pubkey" => call.args.is_empty() && expression_is_path(receiver, "auth"),
        "into" => {
            call.args.is_empty()
                && (matches!(receiver, Expr::Lit(literal) if matches!(literal.lit, syn::Lit::Str(_)))
                    || matches!(receiver, Expr::Path(path) if path.path.is_ident("error") || path.path.is_ident("msg")))
        }
        "clone" => {
            call.args.is_empty()
                && matches!(receiver, Expr::Unary(unary)
                    if matches!(unary.op, syn::UnOp::Deref(_))
                        && expression_is_path(&unary.expr, "arc"))
        }
        "unwrap_or_else" => {
            call.args.len() == 1
                && matches!(receiver, Expr::Call(inner)
                    if matches!(strip_expression(&inner.func), Expr::Path(path)
                        if path_name(&path.path) == "std::sync::Arc::try_unwrap"))
        }
        "timestamp" => {
            call.args.is_empty()
                && matches!(receiver, Expr::Call(inner)
                    if matches!(strip_expression(&inner.func), Expr::Path(path)
                        if path_name(&path.path) == "chrono::Utc::now"))
        }
        "as_secs" => call.args.is_empty() && expression_is_field(receiver, "event", "created_at"),
        "abs" => call.args.is_empty() && matches!(receiver, Expr::Binary(_)),
        "len" => call.args.is_empty() && expression_is_field(receiver, "event", "content"),
        _ => false,
    }
}

fn expression_is_path(expression: &Expr, expected: &str) -> bool {
    matches!(strip_expression(expression), Expr::Path(path) if path.path.is_ident(expected))
}

fn expression_is_field(expression: &Expr, base: &str, member: &str) -> bool {
    matches!(
        strip_expression(expression),
        Expr::Field(field)
            if matches!(&field.member, syn::Member::Named(name) if name == member)
                && expression_is_path(&field.base, base)
    )
}

fn path_name(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
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

    fn assert_unproven_gate_is_partial(source: &str, expected_reason: &str) {
        let lift = lift_relay_ingest(
            source,
            KIND_SOURCE,
            &fixture_protocol(),
            "fixture",
            "ingest.rs",
            "revision",
        )
        .expect("unproven gate remains visible as a partial lift");

        assert_eq!(lift.coverage.completeness, NativeCompleteness::Partial);
        assert!(
            lift.job_decisions
                .iter()
                .all(|decision| decision.decision == IngestDecisionKind::Unknown)
        );
        assert!(
            lift.coverage
                .unresolved
                .iter()
                .any(|reason| reason.contains(expected_reason)),
            "{:?}",
            lift.coverage.unresolved
        );
    }

    #[test]
    fn gate_must_check_the_incoming_kind() {
        let source = INGEST_SOURCE.replace(
            "required_scope_for_kind(kind_u32, &event)",
            "required_scope_for_kind(KIND_MESSAGE, &event)",
        );

        assert_unproven_gate_is_partial(&source, "not derived from the incoming event");
    }

    #[test]
    fn ambiguous_kind_parameters_are_not_treated_as_the_incoming_kind() {
        let source = INGEST_SOURCE
            .replace(
                "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
                "async fn ingest_event_inner(kind_u32: u32, other_kind: u32, event: Event) -> Result<(), Error> {",
            )
            .replace(
                "required_scope_for_kind(kind_u32, &event)",
                "required_scope_for_kind(other_kind, &event)",
            );

        assert_unproven_gate_is_partial(&source, "ambiguous or not the canonical incoming kind");
    }

    #[test]
    fn ambiguous_event_parameters_cannot_supply_the_kind_binding() {
        let source = INGEST_SOURCE
            .replace(
                "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
                "async fn ingest_event_inner(event: Event, other_event: Event) -> Result<(), Error> {\n    let kind_u32 = event_kind_u32(&other_event);",
            );

        assert_unproven_gate_is_partial(&source, "one canonical incoming event parameter");
    }

    #[test]
    fn gate_must_receive_the_canonical_incoming_event() {
        let source = INGEST_SOURCE
            .replace(
                "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
                "async fn ingest_event_inner(kind_u32: u32, event: Event, other: Event) -> Result<(), Error> {",
            )
            .replace(
                "required_scope_for_kind(kind_u32, &event)",
                "required_scope_for_kind(kind_u32, &other)",
            );

        assert_unproven_gate_is_partial(&source, "does not receive the canonical incoming event");
    }

    #[test]
    fn ignored_gate_result_is_not_a_production_gate() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {\n        Ok(scope) => scope,\n        Err(error) => return Err(error.into()),\n    };",
            "let _ = required_scope_for_kind(kind_u32, &event);\n    let required = Scope::MessagesWrite;",
        );

        assert_unproven_gate_is_partial(&source, "direct top-level terminating match gate");
    }

    #[test]
    fn conditional_gate_is_not_a_production_gate() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {\n        Ok(scope) => scope,\n        Err(error) => return Err(error.into()),\n    };",
            "if event.allowed {\n        let required = match required_scope_for_kind(kind_u32, &event) {\n            Ok(scope) => scope,\n            Err(error) => return Err(error.into()),\n        };\n        persist(required).await?;\n    }\n    let required = Scope::MessagesWrite;",
        );

        assert_unproven_gate_is_partial(&source, "direct top-level terminating match gate");
    }

    #[test]
    fn dead_gate_after_unconditional_return_is_not_exhaustive() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "return Ok(());\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "unreachable after an unconditional return");
    }

    #[test]
    fn gate_after_a_panicking_path_is_not_exhaustive() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "panic!(\"gate is unreachable\");\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "macro `panic!`");
    }

    #[test]
    fn gate_must_use_the_latest_kind_binding() {
        let source = INGEST_SOURCE.replace(
            "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
            "async fn ingest_event_inner(event: Event) -> Result<(), Error> {\n    let kind_u32 = event_kind_u32(&event);\n    let kind_u32 = KIND_MESSAGE;",
        );

        assert_unproven_gate_is_partial(&source, "not derived from the incoming event");
    }

    #[test]
    fn reassigned_kind_bindings_make_dataflow_unproven() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "kind_u32 = KIND_MESSAGE;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "assignment with unproven effects");
    }

    #[test]
    fn gate_after_persistence_is_not_exhaustive() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "persist(Scope::MessagesWrite).await?;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "before required_scope_for_kind");
    }

    #[test]
    fn gate_rejection_must_terminate_ingest() {
        let source = INGEST_SOURCE.replace(
            "Err(error) => return Err(error.into()),",
            "Err(_) => Scope::MessagesWrite,",
        );

        assert_unproven_gate_is_partial(&source, "does not directly return");
    }

    #[test]
    fn every_error_path_through_the_gate_must_terminate_ingest() {
        let source = INGEST_SOURCE.replace(
            "Err(error) => return Err(error.into()),",
            "Err(\"different error\") => return Err(\"different error\".into()),\n        Err(_) => Scope::MessagesWrite,",
        );

        assert_unproven_gate_is_partial(&source, "does not directly return");
    }

    #[test]
    fn unrecognized_pre_gate_calls_make_ordering_unproven() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "store_event(&event).await?;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "unrecognized call `store_event`");
    }

    #[test]
    fn opaque_awaited_futures_make_ordering_unproven() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "write_before_gate.await?;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "unmodeled awaited future");
    }

    #[test]
    fn serving_read_method_name_alone_does_not_authorize_an_await() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "write_before_gate.is_serving_active(tenant.community()).await?;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "method call `is_serving_active`");
    }

    #[test]
    fn allowed_method_names_require_the_pinned_receiver_shape() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "write_before_gate.clone();\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "method call `clone`");
    }

    #[test]
    fn macros_with_unmodeled_arguments_make_ordering_unproven() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "format!(\"{}\", store_event(&event));\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "macro `format!`");
    }

    #[test]
    fn error_alternatives_in_or_patterns_must_terminate() {
        let source = INGEST_SOURCE.replace(
            "Ok(scope) => scope,\n        Err(error) => return Err(error.into()),",
            "Err(_) | Ok(Scope::Admin) if event.allowed => Scope::MessagesWrite,\n        Ok(scope) => scope,\n        Err(error) => return Err(error.into()),",
        );

        assert_unproven_gate_is_partial(&source, "does not directly return");
    }

    #[test]
    fn bound_subpatterns_do_not_count_as_error_catch_alls() {
        let source = INGEST_SOURCE.replace(
            "Err(error) => return Err(error.into()),",
            "Err(error @ \"different error\") => return Err(error.into()),",
        );

        assert_unproven_gate_is_partial(&source, "does not directly return");
    }

    #[test]
    fn guarded_error_patterns_do_not_count_as_catch_alls() {
        let source = INGEST_SOURCE.replace(
            "Err(error) => return Err(error.into()),",
            "Err(error) if event.allowed => return Err(error.into()),",
        );

        assert_unproven_gate_is_partial(&source, "does not directly return");
    }

    #[test]
    fn gate_arm_guards_cannot_hide_unmodeled_effects() {
        let source = INGEST_SOURCE.replace(
            "Err(error) => return Err(error.into()),",
            "Err(error) if store_event(&event) => return Err(error.into()),\n        Err(error) => return Err(error.into()),",
        );

        assert_unproven_gate_is_partial(&source, "inside the required_scope_for_kind gate");
    }

    #[test]
    fn scope_match_must_be_the_whole_scope_function_body() {
        let source = INGEST_SOURCE.replace(
            "fn required_scope_for_kind(kind: u32, event: &Event) -> Result<Scope, &'static str> {",
            "fn required_scope_for_kind(kind: u32, event: &Event) -> Result<Scope, &'static str> {\n    store_event(event);",
        );
        let error = lift_relay_ingest(
            &source,
            KIND_SOURCE,
            &fixture_protocol(),
            "fixture",
            "ingest.rs",
            "revision",
        )
        .expect_err("scope helper effects outside the match must fail closed");

        assert_eq!(error, LiftError::MissingScopeMatch);
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
