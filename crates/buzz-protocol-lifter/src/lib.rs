//! Lossless-enough native lifting for Buzz's direct Rust event-kind registry.
//!
//! This lifter deliberately understands Buzz source forms, not semantic
//! software-surface contracts. A separate projection package maps its native
//! output into shared contracts.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use syn::{Expr, Item};

pub const EXTRACTOR_PACKAGE: &str = "org.gooi.lifter.buzz_protocol";
pub const EXTRACTOR_VERSION: &str = "0.1.0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceArtifact {
    pub authority: String,
    pub artifact: String,
    pub revision: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceSpan {
    pub byte_start: u64,
    pub byte_end: u64,
    pub line_start: u32,
    pub line_end: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JobKindDeclaration {
    pub symbol: String,
    pub value: u32,
    pub registered: bool,
    pub declaration: SourceSpan,
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
    pub unresolved_macros: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtocolLift {
    pub source: SourceArtifact,
    pub registry_symbol: String,
    pub job_kinds: Vec<JobKindDeclaration>,
    pub coverage: NativeCoverage,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiftError {
    InvalidRust(String),
    MissingRegistry,
    UnsupportedRegistryShape,
    UnsupportedJobConstant { symbol: String },
    MissingSourceSpan { symbol: String },
    DuplicateJobValue { value: u32 },
}

impl fmt::Display for LiftError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRust(error) => write!(formatter, "source is not valid Rust: {error}"),
            Self::MissingRegistry => formatter.write_str("ALL_KINDS registry was not found"),
            Self::UnsupportedRegistryShape => {
                formatter.write_str("ALL_KINDS is not a direct referenced array of symbols")
            }
            Self::UnsupportedJobConstant { symbol } => {
                write!(formatter, "{symbol} is not a direct u32 integer constant")
            }
            Self::MissingSourceSpan { symbol } => {
                write!(formatter, "could not locate source bytes for {symbol}")
            }
            Self::DuplicateJobValue { value } => {
                write!(formatter, "multiple job constants use value {value}")
            }
        }
    }
}

impl std::error::Error for LiftError {}

pub fn lift_job_protocol(
    source: &str,
    authority: impl Into<String>,
    artifact: impl Into<String>,
    revision: impl Into<String>,
) -> Result<ProtocolLift, LiftError> {
    let parsed =
        syn::parse_file(source).map_err(|error| LiftError::InvalidRust(error.to_string()))?;
    let mut declarations = Vec::new();
    let mut registry = None;
    let mut unresolved_macros = Vec::new();

    for item in &parsed.items {
        match item {
            Item::Const(item) if item.ident == "ALL_KINDS" => {
                registry = Some(registry_symbols(&item.expr)?);
            }
            Item::Const(item) if item.ident.to_string().starts_with("KIND_JOB_") => {
                let symbol = item.ident.to_string();
                let value =
                    direct_u32(&item.expr).ok_or_else(|| LiftError::UnsupportedJobConstant {
                        symbol: symbol.clone(),
                    })?;
                let declaration = direct_const_span(source, &symbol).ok_or_else(|| {
                    LiftError::MissingSourceSpan {
                        symbol: symbol.clone(),
                    }
                })?;
                declarations.push((symbol, value, declaration));
            }
            Item::Macro(item) => unresolved_macros.push(item.mac.path.to_token_stream_string()),
            _ => {}
        }
    }

    let registry = registry.ok_or(LiftError::MissingRegistry)?;
    declarations.sort_by_key(|(_, value, _)| *value);

    for pair in declarations.windows(2) {
        if pair[0].1 == pair[1].1 {
            return Err(LiftError::DuplicateJobValue { value: pair[0].1 });
        }
    }

    let artifact = artifact.into();
    let completeness = if unresolved_macros.is_empty() {
        NativeCompleteness::Exhaustive
    } else {
        NativeCompleteness::Partial
    };
    let job_kinds = declarations
        .into_iter()
        .map(|(symbol, value, declaration)| JobKindDeclaration {
            registered: registry.iter().any(|registered| registered == &symbol),
            symbol,
            value,
            declaration,
        })
        .collect();

    Ok(ProtocolLift {
        source: SourceArtifact {
            authority: authority.into(),
            artifact: artifact.clone(),
            revision: revision.into(),
            sha256: sha256(source.as_bytes()),
        },
        registry_symbol: "ALL_KINDS".to_owned(),
        job_kinds,
        coverage: NativeCoverage {
            extractor_package: EXTRACTOR_PACKAGE.to_owned(),
            extractor_version: EXTRACTOR_VERSION.to_owned(),
            mechanism: "rust_direct_job_constants_and_registry".to_owned(),
            completeness,
            included_artifacts: vec![artifact],
            unresolved_macros,
        },
    })
}

fn direct_u32(expr: &Expr) -> Option<u32> {
    let Expr::Lit(literal) = expr else {
        return None;
    };
    let syn::Lit::Int(value) = &literal.lit else {
        return None;
    };
    value.base10_parse().ok()
}

fn registry_symbols(expr: &Expr) -> Result<Vec<String>, LiftError> {
    let Expr::Reference(reference) = expr else {
        return Err(LiftError::UnsupportedRegistryShape);
    };
    let Expr::Array(array) = reference.expr.as_ref() else {
        return Err(LiftError::UnsupportedRegistryShape);
    };
    array
        .elems
        .iter()
        .map(|element| {
            let Expr::Path(path) = element else {
                return Err(LiftError::UnsupportedRegistryShape);
            };
            path.path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .ok_or(LiftError::UnsupportedRegistryShape)
        })
        .collect()
}

fn direct_const_span(source: &str, symbol: &str) -> Option<SourceSpan> {
    let needle = format!("pub const {symbol}");
    let byte_start = source.find(&needle)?;
    let relative_end = source.get(byte_start..)?.find(';')? + 1;
    let byte_end = byte_start + relative_end;
    Some(SourceSpan {
        byte_start: byte_start.try_into().ok()?,
        byte_end: byte_end.try_into().ok()?,
        line_start: line_number(source, byte_start),
        line_end: line_number(source, byte_end.saturating_sub(1)),
    })
}

fn line_number(source: &str, byte_offset: usize) -> u32 {
    source.as_bytes()[..byte_offset]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        .saturating_add(1)
        .try_into()
        .unwrap_or(u32::MAX)
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

trait MacroPathDisplay {
    fn to_token_stream_string(&self) -> String;
}

impl MacroPathDisplay for syn::Path {
    fn to_token_stream_string(&self) -> String {
        self.segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::")
    }
}

#[cfg(test)]
mod tests {
    use super::{LiftError, NativeCompleteness, lift_job_protocol};

    const FIXTURE: &str = r#"
pub const KIND_MESSAGE: u32 = 1;
pub const KIND_JOB_REQUEST: u32 = 43001;
pub const KIND_JOB_RESULT: u32 = 43004;

pub const ALL_KINDS: &[u32] = &[
    KIND_MESSAGE,
    KIND_JOB_REQUEST,
    KIND_JOB_RESULT,
];
"#;

    #[test]
    fn lifts_direct_job_constants_and_registry_membership() {
        let lift = lift_job_protocol(FIXTURE, "fixture", "kind.rs", "revision")
            .expect("fixture can be lifted");

        assert_eq!(lift.job_kinds.len(), 2);
        assert_eq!(lift.job_kinds[0].value, 43001);
        assert!(lift.job_kinds.iter().all(|kind| kind.registered));
        assert_eq!(lift.coverage.completeness, NativeCompleteness::Exhaustive);
        assert_eq!(lift.job_kinds[0].declaration.line_start, 3);
    }

    #[test]
    fn macro_items_make_negative_coverage_partial() {
        let source = format!("emit_more_kinds!();\n{FIXTURE}");
        let lift = lift_job_protocol(&source, "fixture", "kind.rs", "revision")
            .expect("fixture can be lifted");

        assert_eq!(lift.coverage.completeness, NativeCompleteness::Partial);
        assert_eq!(lift.coverage.unresolved_macros, ["emit_more_kinds"]);
    }

    #[test]
    fn duplicate_job_values_are_rejected() {
        let source = FIXTURE.replace("43004", "43001");
        let error = lift_job_protocol(&source, "fixture", "kind.rs", "revision")
            .expect_err("duplicates are invalid");

        assert_eq!(error, LiftError::DuplicateJobValue { value: 43001 });
    }

    #[test]
    fn pinned_native_output_keeps_the_exact_source_digest_and_kinds() {
        let lift: super::ProtocolLift = serde_json::from_str(include_str!(
            "../../../fixtures/buzz/desktop-v0.5.18/job-protocol.lift.json"
        ))
        .expect("pinned output matches the native schema");

        assert_eq!(
            lift.source.sha256,
            "sha256:74533cfc1ac016dcb1a83279c2b06f93807f29489604cdccefc46b645acfce97"
        );
        assert_eq!(
            lift.job_kinds
                .iter()
                .map(|kind| kind.value)
                .collect::<Vec<_>>(),
            [43001, 43002, 43003, 43004, 43005, 43006]
        );
        assert!(lift.job_kinds.iter().all(|kind| kind.registered));
    }
}
