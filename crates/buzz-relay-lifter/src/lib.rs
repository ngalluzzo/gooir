//! Native lifting for Buzz relay ingest legality.
//!
//! The lifter evaluates the closed `required_scope_for_kind` match for the job
//! kinds supplied by `buzz-protocol-lifter`. It refuses an exhaustive result
//! when a guard, constant, fallback, or call site cannot be resolved.

use buzz_protocol_lifter::{ProtocolLift, SourceArtifact, SourceSpan};
use proc_macro2::Span;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use syn::{
    BinOp, Expr, ExprCall, ExprMacro, ExprMethodCall, Item, ItemFn, Pat, Stmt, Token,
    parse::{Parse, ParseStream, Parser},
    spanned::Spanned,
    visit::{self, Visit},
};

pub const EXTRACTOR_PACKAGE: &str = "org.gooi.lifter.buzz_relay";
pub const EXTRACTOR_VERSION: &str = "0.1.0";
pub const WORKSPACE_MANIFEST_ARTIFACT: &str = "Cargo.toml";
pub const WORKSPACE_LOCK_ARTIFACT: &str = "Cargo.lock";
pub const CARGO_CONFIG_ARTIFACT: &str = ".cargo/config.toml";
pub const RELAY_MANIFEST_ARTIFACT: &str = "crates/buzz-relay/Cargo.toml";
pub const RELAY_CRATE_ROOT_ARTIFACT: &str = "crates/buzz-relay/src/lib.rs";
pub const RELAY_HANDLERS_MODULE_ARTIFACT: &str = "crates/buzz-relay/src/handlers/mod.rs";
pub const RELAY_INGEST_ARTIFACT: &str = "crates/buzz-relay/src/handlers/ingest.rs";
pub const RELAY_PUSH_LEASE_ARTIFACT: &str = "crates/buzz-relay/src/handlers/push_lease.rs";
pub const CORE_MANIFEST_ARTIFACT: &str = "crates/buzz-core/Cargo.toml";
pub const CORE_CRATE_ROOT_ARTIFACT: &str = "crates/buzz-core/src/lib.rs";
pub const CORE_KIND_ARTIFACT: &str = "crates/buzz-core/src/kind.rs";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelaySemanticSources<'a> {
    pub ingest: &'a str,
    pub kind: &'a str,
    pub push_lease: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayCompilationSources<'a> {
    pub workspace_manifest: &'a str,
    pub workspace_lock: &'a str,
    pub cargo_config: &'a str,
    pub relay_manifest: &'a str,
    pub relay_crate_root: &'a str,
    pub relay_handlers_module: &'a str,
    pub core_manifest: &'a str,
    pub core_crate_root: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayInputs<'a> {
    pub semantic: RelaySemanticSources<'a>,
    pub compilation: RelayCompilationSources<'a>,
}

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
pub struct LockedDependency {
    pub crate_name: String,
    pub package: String,
    pub version: String,
    pub source: String,
    pub checksum: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolvedModuleEdge {
    pub module_path: String,
    pub parent_artifact: String,
    pub declaration: SourceSpan,
    pub child_artifact: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolvedPackageEdge {
    pub dependent_package: String,
    pub crate_name: String,
    pub dependency_package: String,
    pub source: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayCompilationEvidence {
    pub sources: Vec<SourceArtifact>,
    pub package_edges: Vec<ResolvedPackageEdge>,
    pub module_edges: Vec<ResolvedModuleEdge>,
    pub locked_dependencies: Vec<LockedDependency>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelayIngestLift {
    pub source: SourceArtifact,
    pub protocol_source: SourceArtifact,
    pub push_lease_source: SourceArtifact,
    pub push_lease_constant: Option<SourceSpan>,
    pub compilation: RelayCompilationEvidence,
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
    InvalidPushLeaseRust(String),
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
            Self::InvalidPushLeaseRust(error) => {
                write!(formatter, "push lease source is not valid Rust: {error}")
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
    inputs: RelayInputs<'_>,
    protocol: &ProtocolLift,
    authority: impl Into<String>,
    revision: impl Into<String>,
) -> Result<RelayIngestLift, LiftError> {
    let RelayInputs {
        semantic:
            RelaySemanticSources {
                ingest: ingest_source,
                kind: kind_source,
                push_lease: push_lease_source,
            },
        compilation,
    } = inputs;
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
    let push_lease_file = syn::parse_file(push_lease_source)
        .map_err(|error| LiftError::InvalidPushLeaseRust(error.to_string()))?;
    let kind_constants = direct_u32_constants(&kind_file);
    let push_lease_constant = exact_direct_u32_constant(&push_lease_file, "KIND_PUSH_LEASE");
    let constants = resolved_constant_values(&kind_constants, push_lease_constant);
    let kind_predicates = named_predicates(&kind_file, &kind_constants);
    let predicates = resolved_predicate_values(&kind_predicates);
    let authority = authority.into();
    let revision = revision.into();
    let (compilation, mut compilation_reason) = compilation_evidence(
        compilation,
        &authority,
        &revision,
        ingest_source,
        kind_source,
        push_lease_source,
    )?;
    if protocol.source.artifact != CORE_KIND_ARTIFACT
        || protocol.source.authority != authority
        || protocol.source.revision != revision
    {
        compilation_reason = Some(
            "protocol kind source is not the core module selected by this compilation".to_owned(),
        );
    }
    let scope_function = find_function(&ingest_file, "required_scope_for_kind")
        .ok_or(LiftError::MissingScopeFunction)?;
    let scope_match = direct_scope_match(scope_function).ok_or(LiftError::MissingScopeMatch)?;
    let scope_attribute_reason = scope_attribute_resolution_reason(scope_function);
    let scope_symbol_reason = scope_symbol_resolution_reason(
        &ingest_file,
        &kind_file,
        scope_function,
        scope_match,
        &kind_constants,
        &kind_predicates,
        push_lease_constant,
        RELAY_INGEST_ARTIFACT,
        RELAY_PUSH_LEASE_ARTIFACT,
    );

    let ingest = find_function(&ingest_file, "ingest_event_inner");
    let gate = prove_production_gate(&ingest_file, ingest)?;

    let fallback_arm = if scope_attribute_reason.is_some() {
        scope_match
            .arms
            .iter()
            .find(|arm| matches!(arm.pat, Pat::Wild(_)) && err_literal(&arm.body).is_some())
    } else {
        scope_match
            .arms
            .iter()
            .find(|arm| matches!(arm.pat, Pat::Wild(_)))
    }
    .ok_or(LiftError::MissingFallback)?;
    let fallback_error = err_literal(&fallback_arm.body).ok_or(LiftError::MissingFallback)?;

    let mut unresolved = Vec::new();
    if let Some(reason) = &gate.unresolved {
        unresolved.push(reason.clone());
    }
    if let Some(reason) = &scope_attribute_reason {
        unresolved.push(reason.clone());
    }
    if let Some(reason) = &scope_symbol_reason {
        unresolved.push(reason.clone());
    }
    if let Some(reason) = &compilation_reason {
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
            } else if let Some(reason) = &scope_attribute_reason {
                (
                    IngestDecisionKind::Unknown,
                    format!(
                        "required_scope_for_kind could not be evaluated exhaustively: {reason}"
                    ),
                )
            } else if let Some(reason) = &scope_symbol_reason {
                (
                    IngestDecisionKind::Unknown,
                    format!(
                        "required_scope_for_kind symbols could not be resolved exactly: {reason}"
                    ),
                )
            } else if let Some(reason) = &compilation_reason {
                (
                    IngestDecisionKind::Unknown,
                    format!("compiled source resolution could not be proven: {reason}"),
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

    let push_lease_constant = match push_lease_constant {
        Some((constant, _)) => Some(source_span(
            push_lease_source,
            constant.span(),
            "push lease constant",
        )?),
        None => None,
    };
    Ok(RelayIngestLift {
        source: SourceArtifact {
            authority: authority.clone(),
            artifact: RELAY_INGEST_ARTIFACT.to_owned(),
            revision: revision.clone(),
            sha256: sha256(ingest_source.as_bytes()),
        },
        protocol_source: protocol.source.clone(),
        push_lease_source: SourceArtifact {
            authority: authority.clone(),
            artifact: RELAY_PUSH_LEASE_ARTIFACT.to_owned(),
            revision: revision.clone(),
            sha256: sha256(push_lease_source.as_bytes()),
        },
        push_lease_constant,
        compilation,
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
            included_artifacts: vec![
                WORKSPACE_MANIFEST_ARTIFACT.to_owned(),
                WORKSPACE_LOCK_ARTIFACT.to_owned(),
                CARGO_CONFIG_ARTIFACT.to_owned(),
                RELAY_MANIFEST_ARTIFACT.to_owned(),
                RELAY_CRATE_ROOT_ARTIFACT.to_owned(),
                RELAY_HANDLERS_MODULE_ARTIFACT.to_owned(),
                RELAY_INGEST_ARTIFACT.to_owned(),
                RELAY_PUSH_LEASE_ARTIFACT.to_owned(),
                CORE_MANIFEST_ARTIFACT.to_owned(),
                CORE_CRATE_ROOT_ARTIFACT.to_owned(),
                protocol.source.artifact.clone(),
            ],
            unresolved,
        },
    })
}

fn compilation_evidence(
    sources: RelayCompilationSources<'_>,
    authority: &str,
    revision: &str,
    ingest_source: &str,
    kind_source: &str,
    push_lease_source: &str,
) -> Result<(RelayCompilationEvidence, Option<String>), LiftError> {
    let source_artifacts = vec![
        source_artifact(
            authority,
            WORKSPACE_MANIFEST_ARTIFACT,
            revision,
            sources.workspace_manifest,
        ),
        source_artifact(
            authority,
            WORKSPACE_LOCK_ARTIFACT,
            revision,
            sources.workspace_lock,
        ),
        source_artifact(
            authority,
            CARGO_CONFIG_ARTIFACT,
            revision,
            sources.cargo_config,
        ),
        source_artifact(
            authority,
            RELAY_MANIFEST_ARTIFACT,
            revision,
            sources.relay_manifest,
        ),
        source_artifact(
            authority,
            RELAY_CRATE_ROOT_ARTIFACT,
            revision,
            sources.relay_crate_root,
        ),
        source_artifact(
            authority,
            RELAY_HANDLERS_MODULE_ARTIFACT,
            revision,
            sources.relay_handlers_module,
        ),
        source_artifact(
            authority,
            CORE_MANIFEST_ARTIFACT,
            revision,
            sources.core_manifest,
        ),
        source_artifact(
            authority,
            CORE_CRATE_ROOT_ARTIFACT,
            revision,
            sources.core_crate_root,
        ),
    ];

    let resolution =
        prove_compilation_resolution(sources, ingest_source, kind_source, push_lease_source);
    let (package_edges, module_edges, locked_dependencies, unresolved) = match resolution {
        Ok((package_edges, module_edges, locked_dependency)) => {
            (package_edges, module_edges, vec![locked_dependency], None)
        }
        Err(reason) => (Vec::new(), Vec::new(), Vec::new(), Some(reason)),
    };

    Ok((
        RelayCompilationEvidence {
            sources: source_artifacts,
            package_edges,
            module_edges,
            locked_dependencies,
        },
        unresolved,
    ))
}

fn source_artifact(
    authority: &str,
    artifact: &str,
    revision: &str,
    source: &str,
) -> SourceArtifact {
    SourceArtifact {
        authority: authority.to_owned(),
        artifact: artifact.to_owned(),
        revision: revision.to_owned(),
        sha256: sha256(source.as_bytes()),
    }
}

fn prove_compilation_resolution(
    sources: RelayCompilationSources<'_>,
    ingest_source: &str,
    kind_source: &str,
    push_lease_source: &str,
) -> Result<
    (
        Vec<ResolvedPackageEdge>,
        Vec<ResolvedModuleEdge>,
        LockedDependency,
    ),
    String,
> {
    let workspace = toml::from_str::<toml::Table>(sources.workspace_manifest)
        .map(toml::Value::Table)
        .map_err(|error| format!("workspace manifest is not valid TOML: {error}"))?;
    let relay_manifest = toml::from_str::<toml::Table>(sources.relay_manifest)
        .map(toml::Value::Table)
        .map_err(|error| format!("relay manifest is not valid TOML: {error}"))?;
    let core_manifest = toml::from_str::<toml::Table>(sources.core_manifest)
        .map(toml::Value::Table)
        .map_err(|error| format!("core manifest is not valid TOML: {error}"))?;
    let lockfile = toml::from_str::<toml::Table>(sources.workspace_lock)
        .map(toml::Value::Table)
        .map_err(|error| format!("workspace lockfile is not valid TOML: {error}"))?;
    let cargo_config = toml::from_str::<toml::Table>(sources.cargo_config)
        .map(toml::Value::Table)
        .map_err(|error| format!("Cargo configuration is not valid TOML: {error}"))?;

    prove_workspace_manifest(&workspace)?;
    prove_cargo_config(&cargo_config)?;
    prove_package_manifest(
        &relay_manifest,
        "buzz-relay",
        &[("buzz-core", "buzz_core"), ("nostr", "nostr")],
    )?;
    prove_package_manifest(&core_manifest, "buzz-core", &[])?;
    let locked_nostr = locked_registry_dependency(&workspace, &lockfile, "nostr")?;

    let relay_root = syn::parse_file(sources.relay_crate_root)
        .map_err(|error| format!("relay crate root is not valid Rust: {error}"))?;
    let handlers_module = syn::parse_file(sources.relay_handlers_module)
        .map_err(|error| format!("relay handlers module is not valid Rust: {error}"))?;
    let core_root = syn::parse_file(sources.core_crate_root)
        .map_err(|error| format!("core crate root is not valid Rust: {error}"))?;

    prove_ancestor_scope(
        &relay_root,
        "relay crate root",
        &[
            "buzz_core",
            "buzz_deletion",
            "chrono",
            "nostr",
            "std",
            "tokio",
            "tracing",
        ],
    )?;
    prove_ancestor_scope(
        &handlers_module,
        "relay handlers module",
        &[
            "buzz_core",
            "buzz_deletion",
            "chrono",
            "nostr",
            "std",
            "tokio",
            "tracing",
        ],
    )?;
    prove_ancestor_scope(&core_root, "core crate root", &["nostr"])?;

    let handlers = exact_out_of_line_module(&relay_root, "handlers")
        .ok_or_else(|| "relay crate root does not select one exact `handlers` module".to_owned())?;
    let ingest = exact_out_of_line_module(&handlers_module, "ingest")
        .ok_or_else(|| "handlers module does not select one exact `ingest` module".to_owned())?;
    let push_lease = exact_out_of_line_module(&handlers_module, "push_lease").ok_or_else(|| {
        "handlers module does not select one exact `push_lease` module".to_owned()
    })?;
    let kind = exact_out_of_line_module(&core_root, "kind")
        .ok_or_else(|| "core crate root does not select one exact `kind` module".to_owned())?;

    if ingest_source.is_empty() || kind_source.is_empty() || push_lease_source.is_empty() {
        return Err("a selected semantic module source is empty".to_owned());
    }

    let edges = vec![
        resolved_module_edge(
            sources.relay_crate_root,
            handlers,
            "buzz_relay::handlers",
            RELAY_CRATE_ROOT_ARTIFACT,
            RELAY_HANDLERS_MODULE_ARTIFACT,
        )?,
        resolved_module_edge(
            sources.relay_handlers_module,
            ingest,
            "buzz_relay::handlers::ingest",
            RELAY_HANDLERS_MODULE_ARTIFACT,
            RELAY_INGEST_ARTIFACT,
        )?,
        resolved_module_edge(
            sources.relay_handlers_module,
            push_lease,
            "buzz_relay::handlers::push_lease",
            RELAY_HANDLERS_MODULE_ARTIFACT,
            RELAY_PUSH_LEASE_ARTIFACT,
        )?,
        resolved_module_edge(
            sources.core_crate_root,
            kind,
            "buzz_core::kind",
            CORE_CRATE_ROOT_ARTIFACT,
            CORE_KIND_ARTIFACT,
        )?,
    ];
    let package_edges = vec![
        ResolvedPackageEdge {
            dependent_package: "buzz-relay".to_owned(),
            crate_name: "buzz_core".to_owned(),
            dependency_package: "buzz-core".to_owned(),
            source: "path:crates/buzz-core".to_owned(),
        },
        ResolvedPackageEdge {
            dependent_package: "buzz-relay".to_owned(),
            crate_name: "nostr".to_owned(),
            dependency_package: "nostr".to_owned(),
            source: format!("{}#nostr@{}", locked_nostr.source, locked_nostr.version),
        },
    ];
    Ok((package_edges, edges, locked_nostr))
}

fn prove_workspace_manifest(workspace: &toml::Value) -> Result<(), String> {
    let workspace_table = toml_table(workspace, &["workspace"])
        .ok_or_else(|| "workspace table is missing".to_owned())?;
    if workspace_table
        .get("resolver")
        .and_then(toml::Value::as_str)
        != Some("2")
        || toml_table(workspace, &["workspace", "package"])
            .and_then(|package| package.get("edition"))
            .and_then(toml::Value::as_str)
            != Some("2021")
    {
        return Err("workspace does not pin the reviewed resolver and Rust edition".to_owned());
    }
    let members = workspace_table
        .get("members")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| "workspace member list is missing".to_owned())?;
    for package_path in ["crates/buzz-relay", "crates/buzz-core"] {
        if !members
            .iter()
            .any(|member| member.as_str() == Some(package_path))
        {
            return Err(format!(
                "workspace does not select `{package_path}` as an exact member"
            ));
        }
    }
    if workspace_table
        .get("exclude")
        .and_then(toml::Value::as_array)
        .is_some_and(|excluded| {
            excluded.iter().filter_map(toml::Value::as_str).any(|path| {
                path.contains('*')
                    || path.contains('?')
                    || matches!(path, "crates/buzz-relay" | "crates/buzz-core")
            })
        })
    {
        return Err("workspace exclusion can alter a selected package".to_owned());
    }

    let dependencies = toml_table(workspace, &["workspace", "dependencies"])
        .ok_or_else(|| "workspace dependencies are missing".to_owned())?;
    let core = dependencies
        .get("buzz-core")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "workspace `buzz-core` dependency is not a table".to_owned())?;
    if core.get("path").and_then(toml::Value::as_str) != Some("crates/buzz-core")
        || core.keys().any(|key| key != "path")
    {
        return Err(
            "workspace `buzz-core` does not resolve exactly to `crates/buzz-core`".to_owned(),
        );
    }

    let nostr = dependencies
        .get("nostr")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "workspace `nostr` dependency is not a table".to_owned())?;
    if nostr.get("version").and_then(toml::Value::as_str).is_none()
        || nostr
            .keys()
            .any(|key| !matches!(key.as_str(), "version" | "features" | "default-features"))
    {
        return Err("workspace `nostr` dependency has unmodeled source selection".to_owned());
    }

    if toml_table(workspace, &["replace"]).is_some_and(|replace| !replace.is_empty())
        || patch_targets_package(workspace, "nostr")
        || patch_targets_package(workspace, "buzz-core")
    {
        return Err("workspace patch or replacement can redirect a modeled dependency".to_owned());
    }
    Ok(())
}

fn prove_cargo_config(config: &toml::Value) -> Result<(), String> {
    let table = config
        .as_table()
        .ok_or_else(|| "Cargo configuration is not a table".to_owned())?;
    if table
        .keys()
        .any(|key| !matches!(key.as_str(), "profile" | "env"))
    {
        return Err(
            "Cargo configuration contains unmodeled resolution or compiler settings".to_owned(),
        );
    }
    if toml_table(config, &["env"]).is_some_and(|environment| {
        environment.keys().any(|name| {
            let upper = name.to_ascii_uppercase();
            upper.starts_with("CARGO") || upper.starts_with("RUST")
        })
    }) {
        return Err("Cargo configuration injects unmodeled Cargo or Rust settings".to_owned());
    }
    Ok(())
}

fn prove_package_manifest(
    manifest: &toml::Value,
    package: &str,
    required_dependencies: &[(&str, &str)],
) -> Result<(), String> {
    let package_table = toml_table(manifest, &["package"])
        .ok_or_else(|| format!("package `{package}` manifest has no package table"))?;
    if package_table.get("name").and_then(toml::Value::as_str) != Some(package)
        || package_table.get("autolib").and_then(toml::Value::as_bool) == Some(false)
        || package_table.contains_key("workspace")
        || package_table.contains_key("build")
        || package_table.contains_key("links")
        || manifest.get("workspace").is_some()
    {
        return Err(format!(
            "package manifest does not define the expected workspace `{package}` library"
        ));
    }
    let edition = package_table.get("edition").and_then(toml::Value::as_table);
    if edition.is_none_or(|edition| {
        edition.get("workspace").and_then(toml::Value::as_bool) != Some(true)
            || edition.keys().any(|key| key != "workspace")
    }) {
        return Err(format!(
            "package `{package}` does not inherit the reviewed Rust edition"
        ));
    }
    if toml_table(manifest, &["lib"]).is_some() {
        return Err(format!(
            "package `{package}` has an unmodeled library target override"
        ));
    }

    let dependencies = toml_table(manifest, &["dependencies"]);
    for (dependency, crate_name) in required_dependencies {
        let dependencies =
            dependencies.ok_or_else(|| format!("package `{package}` has no dependency table"))?;
        let matching = dependencies
            .iter()
            .filter(|(name, _)| normalize_crate_name(name) == *crate_name)
            .collect::<Vec<_>>();
        if matching.len() != 1 || matching[0].0.as_str() != *dependency {
            return Err(format!(
                "package `{package}` has ambiguous `{crate_name}` dependency naming"
            ));
        }
        let Some(specification) = matching[0].1.as_table() else {
            return Err(format!(
                "package `{package}` dependency `{dependency}` is not a table"
            ));
        };
        if specification
            .get("workspace")
            .and_then(toml::Value::as_bool)
            != Some(true)
            || specification.keys().any(|key| key != "workspace")
        {
            return Err(format!(
                "package `{package}` dependency `{dependency}` is not the exact workspace binding"
            ));
        }
    }
    if toml_table(manifest, &["target"]).is_some() {
        return Err(format!(
            "package `{package}` has unmodeled target-specific dependency selection"
        ));
    }
    if toml_table(manifest, &["build-dependencies"])
        .is_some_and(|dependencies| !dependencies.is_empty())
    {
        return Err(format!(
            "package `{package}` has an unmodeled build dependency boundary"
        ));
    }
    Ok(())
}

fn locked_registry_dependency(
    workspace: &toml::Value,
    lockfile: &toml::Value,
    package: &str,
) -> Result<LockedDependency, String> {
    let requirement = toml_table(workspace, &["workspace", "dependencies"])
        .and_then(|dependencies| dependencies.get(package))
        .and_then(toml::Value::as_table)
        .and_then(|specification| specification.get("version"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("workspace `{package}` version requirement is missing"))?;
    let packages = lockfile
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| "workspace lockfile has no package array".to_owned())?;
    let mut matching = packages.iter().filter_map(|entry| {
        let table = entry.as_table()?;
        let name = table.get("name")?.as_str()?;
        let version = table.get("version")?.as_str()?;
        (name == package && version_matches_requirement(version, requirement)).then_some(table)
    });
    let locked = matching
        .next()
        .ok_or_else(|| format!("no locked `{package}` package matches `{requirement}`"))?;
    if matching.next().is_some() {
        return Err(format!(
            "multiple locked `{package}` packages match `{requirement}`"
        ));
    }
    let version = locked
        .get("version")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("locked `{package}` version is missing"))?;
    let source = locked
        .get("source")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("locked `{package}` source is missing"))?;
    let checksum = locked
        .get("checksum")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| format!("locked `{package}` checksum is missing"))?;
    if source != "registry+https://github.com/rust-lang/crates.io-index"
        || checksum.len() != 64
        || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(format!(
            "locked `{package}` is not an exact checksummed crates.io package"
        ));
    }
    Ok(LockedDependency {
        crate_name: normalize_crate_name(package),
        package: package.to_owned(),
        version: version.to_owned(),
        source: source.to_owned(),
        checksum: checksum.to_owned(),
    })
}

fn version_matches_requirement(version: &str, requirement: &str) -> bool {
    version == requirement
        || version
            .strip_prefix(requirement)
            .is_some_and(|rest| rest.starts_with('.'))
}

fn patch_targets_package(workspace: &toml::Value, package: &str) -> bool {
    let Some(patches) = toml_table(workspace, &["patch"]) else {
        return false;
    };
    patches.values().any(|registry| {
        registry.as_table().is_some_and(|entries| {
            entries.iter().any(|(name, specification)| {
                name == package
                    || specification
                        .as_table()
                        .and_then(|table| table.get("package"))
                        .and_then(toml::Value::as_str)
                        == Some(package)
            })
        })
    })
}

fn toml_table<'a>(
    value: &'a toml::Value,
    path: &[&str],
) -> Option<&'a toml::map::Map<String, toml::Value>> {
    path.iter()
        .try_fold(value, |current, segment| current.get(*segment))?
        .as_table()
}

fn normalize_crate_name(name: &str) -> String {
    name.replace('-', "_")
}

fn exact_out_of_line_module<'a>(file: &'a syn::File, name: &str) -> Option<&'a syn::ItemMod> {
    if file
        .attrs
        .iter()
        .any(|attribute| !module_graph_attribute_is_inert(attribute))
        || file
            .items
            .iter()
            .any(|item| matches!(item, Item::Macro(_) | Item::Verbatim(_)))
    {
        return None;
    }
    let mut introducing = file
        .items
        .iter()
        .filter(|item| item_introduces_name(item, name));
    let Item::Mod(module) = introducing.next()? else {
        return None;
    };
    (introducing.next().is_none()
        && module.content.is_none()
        && module.attrs.iter().all(module_graph_attribute_is_inert))
    .then_some(module)
}

fn prove_ancestor_scope(file: &syn::File, label: &str, reserved: &[&str]) -> Result<(), String> {
    let mut visitor = AncestorScopeVisitor {
        reserved,
        reason: None,
    };
    visitor.visit_file(file);
    visitor.reason.map_or(Ok(()), Err).map_err(|reason| {
        format!("{label} does not preserve modeled crate-name resolution: {reason}")
    })
}

struct AncestorScopeVisitor<'a> {
    reserved: &'a [&'a str],
    reason: Option<String>,
}

impl Visit<'_> for AncestorScopeVisitor<'_> {
    fn visit_item(&mut self, item: &Item) {
        if self.reason.is_some() {
            return;
        }
        if matches!(item, Item::Macro(_) | Item::Verbatim(_)) {
            self.reason = Some("an item macro can alter the module namespace".to_owned());
            return;
        }
        if matches!(item, Item::ExternCrate(_)) {
            self.reason = Some("an extern-crate item can redirect a crate name".to_owned());
            return;
        }
        if let Some(name) = self
            .reserved
            .iter()
            .find(|name| item_introduces_name(item, name))
        {
            self.reason = Some(format!("an item introduces reserved name `{name}`"));
            return;
        }
        if item_attrs(item)
            .iter()
            .any(|attribute| attribute.path().is_ident("macro_use"))
        {
            self.reason = Some("a macro-use attribute can alter macro resolution".to_owned());
            return;
        }
        visit::visit_item(self, item);
    }
}

fn item_attrs(item: &Item) -> &[syn::Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        Item::Verbatim(_) => &[],
        _ => &[],
    }
}

fn module_graph_attribute_is_inert(attribute: &syn::Attribute) -> bool {
    matches!(
        path_name(attribute.path()).as_str(),
        "doc" | "allow" | "warn" | "deny" | "forbid"
    )
}

fn resolved_module_edge(
    source: &str,
    module: &syn::ItemMod,
    module_path: &str,
    parent_artifact: &str,
    child_artifact: &str,
) -> Result<ResolvedModuleEdge, String> {
    let declaration = source_span(source, module.span(), "module declaration")
        .map_err(|error| error.to_string())?;
    Ok(ResolvedModuleEdge {
        module_path: module_path.to_owned(),
        parent_artifact: parent_artifact.to_owned(),
        declaration,
        child_artifact: child_artifact.to_owned(),
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

fn scope_attribute_resolution_reason(function: &ItemFn) -> Option<String> {
    let mut visitor = ScopeAttributeVisitor::default();
    visitor.visit_item_fn(function);
    visitor.unmodeled.then(|| {
        "required_scope_for_kind contains an unmodeled attribute on decision-bearing syntax"
            .to_owned()
    })
}

#[derive(Default)]
struct ScopeAttributeVisitor {
    unmodeled: bool,
}

impl Visit<'_> for ScopeAttributeVisitor {
    fn visit_attribute(&mut self, attribute: &syn::Attribute) {
        if !attribute_is_modeled_inert(attribute) {
            self.unmodeled = true;
        }
    }
}

fn attribute_is_modeled_inert(attribute: &syn::Attribute) -> bool {
    attribute.path().is_ident("doc")
}

const PUSH_LEASE_CONSTANT_PATH: &str = "super::push_lease::KIND_PUSH_LEASE";

fn resolved_constant_values(
    kind_constants: &BTreeMap<String, u32>,
    push_lease_constant: Option<(&syn::ItemConst, u32)>,
) -> BTreeMap<String, u32> {
    let mut resolved = kind_constants.clone();
    for (name, value) in kind_constants {
        resolved.insert(format!("buzz_core::kind::{name}"), *value);
    }
    if let Some((_, value)) = push_lease_constant {
        resolved.insert(PUSH_LEASE_CONSTANT_PATH.to_owned(), value);
    }
    resolved
}

fn resolved_predicate_values(
    kind_predicates: &BTreeMap<String, PredicateValues>,
) -> BTreeMap<String, PredicateValues> {
    let mut resolved = kind_predicates.clone();
    for (name, values) in kind_predicates {
        resolved.insert(format!("buzz_core::kind::{name}"), values.clone());
    }
    resolved
}

fn exact_direct_u32_constant<'a>(
    file: &'a syn::File,
    name: &str,
) -> Option<(&'a syn::ItemConst, u32)> {
    if file.items.iter().any(|item| matches!(item, Item::Macro(_))) {
        return None;
    }
    let mut introducing = file
        .items
        .iter()
        .filter(|item| item_introduces_name(item, name));
    let Item::Const(constant) = introducing.next()? else {
        return None;
    };
    if introducing.next().is_some()
        || constant
            .attrs
            .iter()
            .any(|attribute| !attribute_is_modeled_inert(attribute))
        || !matches!(&*constant.ty, syn::Type::Path(path)
            if path.qself.is_none() && path.path.is_ident("u32"))
    {
        return None;
    }
    let Expr::Lit(literal) = &*constant.expr else {
        return None;
    };
    let syn::Lit::Int(value) = &literal.lit else {
        return None;
    };
    Some((constant, value.base10_parse().ok()?))
}

struct ScopeDecisionSymbolVisitor<'a> {
    kind_constants: &'a BTreeSet<String>,
    kind_predicates: &'a BTreeSet<String>,
    constant_paths: BTreeSet<String>,
    predicate_paths: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for ScopeDecisionSymbolVisitor<'_> {
    fn visit_pat(&mut self, pattern: &'ast Pat) {
        match pattern {
            Pat::Ident(pattern) => {
                let name = pattern.ident.to_string();
                if self.kind_constants.contains(&name) {
                    self.constant_paths.insert(name);
                }
            }
            Pat::Path(pattern) => {
                let path = path_name(&pattern.path);
                let known_kind = pattern.path.segments.last().is_some_and(|segment| {
                    self.kind_constants.contains(&segment.ident.to_string())
                });
                if known_kind || path == PUSH_LEASE_CONSTANT_PATH {
                    self.constant_paths.insert(path);
                }
            }
            _ => {}
        }
        visit::visit_pat(self, pattern);
    }

    fn visit_expr_call(&mut self, expression: &'ast ExprCall) {
        if let Expr::Path(function) = strip_expression(&expression.func)
            && function
                .path
                .segments
                .last()
                .is_some_and(|segment| self.kind_predicates.contains(&segment.ident.to_string()))
        {
            self.predicate_paths.insert(path_name(&function.path));
        }
        for argument in &expression.args {
            self.visit_expr(argument);
        }
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        let path = path_name(&expression.path);
        let known_kind = expression
            .path
            .segments
            .last()
            .is_some_and(|segment| self.kind_constants.contains(&segment.ident.to_string()));
        if known_kind || path == PUSH_LEASE_CONSTANT_PATH {
            self.constant_paths.insert(path);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn scope_symbol_resolution_reason(
    ingest_file: &syn::File,
    kind_file: &syn::File,
    scope_function: &ItemFn,
    scope_match: &syn::ExprMatch,
    kind_constants: &BTreeMap<String, u32>,
    kind_predicates: &BTreeMap<String, PredicateValues>,
    push_lease_constant: Option<(&syn::ItemConst, u32)>,
    ingest_artifact: &str,
    push_lease_artifact: &str,
) -> Option<String> {
    let constant_names = kind_constants.keys().cloned().collect::<BTreeSet<_>>();
    let predicate_names = kind_predicates.keys().cloned().collect::<BTreeSet<_>>();
    let mut visitor = ScopeDecisionSymbolVisitor {
        kind_constants: &constant_names,
        kind_predicates: &predicate_names,
        constant_paths: BTreeSet::new(),
        predicate_paths: BTreeSet::new(),
    };
    for arm in &scope_match.arms {
        visitor.visit_pat(&arm.pat);
        if matches!(arm.pat, Pat::Wild(_)) {
            break;
        }
    }

    for path in visitor.constant_paths {
        if !scope_constant_path_resolves(
            ingest_file,
            kind_file,
            scope_function,
            &path,
            kind_constants,
            push_lease_constant,
            ingest_artifact,
            push_lease_artifact,
        ) {
            return Some(format!(
                "decision constant `{path}` does not resolve to its consumed declaration"
            ));
        }
    }
    for path in visitor.predicate_paths {
        if !scope_predicate_path_resolves(
            ingest_file,
            kind_file,
            scope_function,
            &path,
            kind_constants,
            kind_predicates,
        ) {
            return Some(format!(
                "decision predicate `{path}` does not resolve to its consumed declaration"
            ));
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn scope_constant_path_resolves(
    ingest_file: &syn::File,
    kind_file: &syn::File,
    scope_function: &ItemFn,
    path: &str,
    kind_constants: &BTreeMap<String, u32>,
    push_lease_constant: Option<(&syn::ItemConst, u32)>,
    ingest_artifact: &str,
    push_lease_artifact: &str,
) -> bool {
    if path == PUSH_LEASE_CONSTANT_PATH {
        return push_lease_constant.is_some()
            && push_lease_artifact == sibling_artifact(ingest_artifact, "push_lease.rs");
    }
    let name = path.rsplit("::").next().unwrap_or(path);
    if !kind_constants.contains_key(name) || exact_direct_u32_constant(kind_file, name).is_none() {
        return false;
    }
    if path == name {
        return !function_generic_shadows(scope_function, name)
            && module_name_is_unshadowed(ingest_file, "buzz_core")
            && exact_unconditional_import(ingest_file, name, &format!("buzz_core::kind::{name}"));
    }
    path == format!("buzz_core::kind::{name}")
        && !function_generic_shadows(scope_function, "buzz_core")
        && module_name_is_unshadowed(ingest_file, "buzz_core")
}

fn scope_predicate_path_resolves(
    ingest_file: &syn::File,
    kind_file: &syn::File,
    scope_function: &ItemFn,
    path: &str,
    kind_constants: &BTreeMap<String, u32>,
    kind_predicates: &BTreeMap<String, PredicateValues>,
) -> bool {
    let name = path.rsplit("::").next().unwrap_or(path);
    if !kind_predicates.contains_key(name)
        || !exact_named_predicate(kind_file, name, kind_constants)
    {
        return false;
    }
    if path == name {
        return !function_generic_shadows(scope_function, name)
            && module_name_is_unshadowed(ingest_file, "buzz_core")
            && exact_unconditional_import(ingest_file, name, &format!("buzz_core::kind::{name}"));
    }
    path == format!("buzz_core::kind::{name}")
        && !function_generic_shadows(scope_function, "buzz_core")
        && module_name_is_unshadowed(ingest_file, "buzz_core")
}

fn exact_named_predicate(file: &syn::File, name: &str, constants: &BTreeMap<String, u32>) -> bool {
    if file.items.iter().any(|item| matches!(item, Item::Macro(_)))
        || file
            .items
            .iter()
            .any(|item| item_introduces_name(item, "matches"))
    {
        return false;
    }
    let mut introducing = file
        .items
        .iter()
        .filter(|item| item_introduces_name(item, name));
    let Some(Item::Fn(function)) = introducing.next() else {
        return false;
    };
    if introducing.next().is_some()
        || function
            .attrs
            .iter()
            .any(|attribute| !attribute_is_modeled_inert(attribute))
        || function.sig.constness.is_none()
        || function.sig.asyncness.is_some()
        || function.sig.abi.is_some()
        || !function.sig.generics.params.is_empty()
        || function.sig.generics.where_clause.is_some()
        || !matches!(&function.sig.output, syn::ReturnType::Type(_, ty)
            if matches!(&**ty, syn::Type::Path(path)
                if path.qself.is_none() && path.path.is_ident("bool")))
    {
        return false;
    }
    if function.sig.inputs.len() != 1 {
        return false;
    }
    let Some(syn::FnArg::Typed(argument)) = function.sig.inputs.first() else {
        return false;
    };
    let Pat::Ident(parameter) = &*argument.pat else {
        return false;
    };
    if !matches!(&*argument.ty, syn::Type::Path(path)
        if path.qself.is_none() && path.path.is_ident("u32"))
    {
        return false;
    }
    let [Stmt::Expr(Expr::Macro(expression), _)] = function.block.stmts.as_slice() else {
        return false;
    };
    let Some(matches) = parse_matches_macro(expression) else {
        return false;
    };
    if !matches_expression_is_parameter(&matches.expression, &parameter.ident.to_string()) {
        return false;
    }
    let constant_names = constants.keys().cloned().collect::<BTreeSet<_>>();
    let predicate_names = BTreeSet::new();
    let mut visitor = ScopeDecisionSymbolVisitor {
        kind_constants: &constant_names,
        kind_predicates: &predicate_names,
        constant_paths: BTreeSet::new(),
        predicate_paths: BTreeSet::new(),
    };
    visitor.visit_pat(&matches.pattern);
    visitor
        .constant_paths
        .into_iter()
        .all(|path| !path.contains("::") && exact_direct_u32_constant(file, &path).is_some())
}

fn sibling_artifact(artifact: &str, sibling: &str) -> String {
    artifact.rsplit_once('/').map_or_else(
        || sibling.to_owned(),
        |(directory, _)| format!("{directory}/{sibling}"),
    )
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
        Pat::Path(path) => match constants.get(&path_name(&path.path)).copied() {
            Some(value) => (vec![value], true),
            None => (Vec::new(), false),
        },
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
        Pat::Path(path) => constants
            .get(&path_name(&path.path))
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
            let symbol = path_name(&path.path);
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
    let name = path_name(&path.path);
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

fn prove_production_gate(
    ingest_file: &syn::File,
    ingest: Option<&ItemFn>,
) -> Result<GateProof, LiftError> {
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
        if let Some(helper) = shadowed_unqualified_helper(ingest, prior_statements) {
            return Ok(GateProof {
                span,
                unresolved: Some(format!(
                    "local binding, parameter, or import shadows modeled helper `{helper}`"
                )),
            });
        }
        if let Err(reason) = gate_checks_incoming_kind(ingest, call, prior_statements) {
            return Ok(GateProof {
                span,
                unresolved: Some(reason),
            });
        }
        if let Some(reason) = canonical_event_type_resolution_reason(ingest_file, ingest) {
            return Ok(GateProof {
                span,
                unresolved: Some(reason),
            });
        }
        if let Some(reason) =
            module_helper_resolution_reason(ingest_file, prior_statements, gate_match)
        {
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
        if let Some(reason) =
            callback_boundary_resolution_reason(ingest, prior_statements, gate_match)
        {
            return Ok(GateProof {
                span,
                unresolved: Some(reason),
            });
        }
        if let Some(reason) = macro_binding_resolution_reason(ingest, prior_statements, gate_match)
        {
            return Ok(GateProof {
                span,
                unresolved: Some(reason),
            });
        }
        if let Some(reason) =
            receiver_binding_resolution_reason(ingest, prior_statements, gate_match)
        {
            return Ok(GateProof {
                span,
                unresolved: Some(reason),
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
        Expr::Path(path) if path.path.is_ident("required_scope_for_kind")
    )
}

const MODELED_UNQUALIFIED_HELPERS: &[&str] = &[
    "Err",
    "event_kind_u32",
    "map_serving_fence_state",
    "required_scope_for_kind",
    "verify_event",
];
const MODELED_QUALIFIED_ROOTS: &[&str] = &[
    "IngestError",
    "buzz_core",
    "buzz_deletion",
    "chrono",
    "std",
    "tokio",
];
const MODELED_MACROS: &[&str] = &["debug", "error", "format"];

fn shadowed_unqualified_helper(ingest: &ItemFn, prior_statements: &[Stmt]) -> Option<&'static str> {
    MODELED_UNQUALIFIED_HELPERS
        .iter()
        .chain(MODELED_QUALIFIED_ROOTS)
        .chain(MODELED_MACROS)
        .copied()
        .find(|helper| {
            ingest.sig.inputs.iter().any(|argument| match argument {
                syn::FnArg::Typed(argument) => pattern_binds_name(&argument.pat, helper),
                syn::FnArg::Receiver(_) => false,
            }) || prior_statements
                .iter()
                .any(|statement| statement_introduces_name(statement, helper))
        })
}

fn statement_introduces_name(statement: &Stmt, expected: &str) -> bool {
    let mut bindings = BindingIntroductionVisitor {
        expected,
        found: false,
    };
    bindings.visit_stmt(statement);
    bindings.found
}

struct BindingIntroductionVisitor<'a> {
    expected: &'a str,
    found: bool,
}

impl<'ast> Visit<'ast> for BindingIntroductionVisitor<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        self.found |= item_introduces_name(item, self.expected);
        visit::visit_item(self, item);
    }

    fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
        self.found |= pattern.ident == self.expected;
        visit::visit_pat_ident(self, pattern);
    }
}

fn item_introduces_name(item: &Item, expected: &str) -> bool {
    match item {
        Item::Const(item) => item.ident == expected,
        Item::Enum(item) => item.ident == expected,
        Item::ExternCrate(item) => item
            .rename
            .as_ref()
            .map_or_else(|| item.ident == expected, |(_, rename)| rename == expected),
        Item::Fn(item) => item.sig.ident == expected,
        Item::Mod(item) => item.ident == expected,
        Item::Macro(item) => item.ident.as_ref().is_some_and(|ident| ident == expected),
        Item::Static(item) => item.ident == expected,
        Item::Struct(item) => item.ident == expected,
        Item::Trait(item) => item.ident == expected,
        Item::TraitAlias(item) => item.ident == expected,
        Item::Type(item) => item.ident == expected,
        Item::Union(item) => item.ident == expected,
        Item::Use(item) => use_tree_introduces_name(&item.tree, expected),
        Item::Verbatim(_) => true,
        _ => false,
    }
}

fn use_tree_introduces_name(tree: &syn::UseTree, expected: &str) -> bool {
    match tree {
        syn::UseTree::Glob(_) => true,
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|tree| use_tree_introduces_name(tree, expected)),
        syn::UseTree::Name(name) => name.ident == expected,
        syn::UseTree::Path(path) => use_tree_introduces_name(&path.tree, expected),
        syn::UseTree::Rename(rename) => rename.rename == expected,
    }
}

#[derive(Default)]
struct UnqualifiedCallVisitor {
    names: BTreeSet<String>,
    qualified_roots: BTreeSet<String>,
    macros: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for UnqualifiedCallVisitor {
    fn visit_expr_call(&mut self, expression: &'ast ExprCall) {
        if let Expr::Path(path) = strip_expression(&expression.func) {
            if let Some(name) = path.path.get_ident() {
                self.names.insert(name.to_string());
            } else if (allowed_pre_gate_function(&path.path)
                || path_name(&path.path) == "tokio::task::spawn_blocking")
                && let Some(root) = path.path.segments.first()
            {
                self.qualified_roots.insert(root.ident.to_string());
            }
        }
        visit::visit_expr_call(self, expression);
    }

    fn visit_expr_macro(&mut self, expression: &'ast ExprMacro) {
        if let Some(name) = expression.mac.path.get_ident() {
            self.macros.insert(name.to_string());
        }
        visit::visit_expr_macro(self, expression);
    }

    fn visit_stmt_macro(&mut self, statement: &'ast syn::StmtMacro) {
        if let Some(name) = statement.mac.path.get_ident() {
            self.macros.insert(name.to_string());
        }
        visit::visit_stmt_macro(self, statement);
    }
}

fn module_helper_resolution_reason(
    file: &syn::File,
    prior_statements: &[Stmt],
    gate_match: &syn::ExprMatch,
) -> Option<String> {
    let mut calls = UnqualifiedCallVisitor::default();
    for statement in prior_statements {
        calls.visit_stmt(statement);
    }
    calls.visit_expr_match(gate_match);

    for helper in MODELED_UNQUALIFIED_HELPERS {
        if !calls.names.contains(*helper) {
            continue;
        }
        let expected_import = match *helper {
            "event_kind_u32" => Some("buzz_core::kind::event_kind_u32"),
            "verify_event" => Some("buzz_core::verification::verify_event"),
            _ => None,
        };
        let imports = module_import_paths(file, helper);
        let item_count = file
            .items
            .iter()
            .filter(|item| !matches!(item, Item::Use(_)) && item_introduces_name(item, helper))
            .count();
        let resolved = match *helper {
            "required_scope_for_kind" | "map_serving_fence_state" => {
                item_count == 1 && imports.is_empty()
            }
            "event_kind_u32" | "verify_event" => {
                item_count == 0
                    && imports.len() == 1
                    && imports.first().map(String::as_str) == expected_import
            }
            "Err" => item_count == 0 && imports.is_empty(),
            _ => false,
        };
        if !resolved {
            return Some(format!(
                "modeled helper `{helper}` does not have the pinned module-level resolution"
            ));
        }
    }
    for root in &calls.qualified_roots {
        if !MODELED_QUALIFIED_ROOTS.contains(&root.as_str()) {
            continue;
        }
        let imports = module_import_paths(file, root);
        let item_count = file
            .items
            .iter()
            .filter(|item| !matches!(item, Item::Use(_)) && item_introduces_name(item, root))
            .count();
        let resolved = if root == "IngestError" {
            item_count == 1 && imports.is_empty()
        } else {
            item_count == 0 && imports.is_empty()
        };
        if !resolved {
            return Some(format!(
                "modeled path root `{root}` does not have the pinned module-level resolution"
            ));
        }
    }
    for name in &calls.macros {
        if !MODELED_MACROS.contains(&name.as_str()) {
            continue;
        }
        let expected_import = match name.as_str() {
            "debug" => Some("tracing::debug"),
            "error" => Some("tracing::error"),
            "format" => None,
            _ => unreachable!(),
        };
        let imports = module_import_paths(file, name);
        let macro_count = file
            .items
            .iter()
            .filter(|item| matches!(item, Item::Macro(item) if item.ident.as_ref().is_some_and(|ident| ident == name)))
            .count();
        let resolved = match expected_import {
            Some(expected) => {
                macro_count == 0
                    && imports.len() == 1
                    && imports.first().map(String::as_str) == Some(expected)
            }
            None => macro_count == 0 && imports.is_empty(),
        };
        if !resolved {
            return Some(format!(
                "modeled macro `{name}!` does not have the pinned module-level resolution"
            ));
        }
    }
    None
}

fn module_import_paths(file: &syn::File, introduced_name: &str) -> Vec<String> {
    let mut imports = Vec::new();
    for item in &file.items {
        let Item::Use(item) = item else { continue };
        collect_use_tree_paths(&item.tree, &[], introduced_name, &mut imports);
    }
    imports
}

fn canonical_event_type_resolution_reason(file: &syn::File, ingest: &ItemFn) -> Option<String> {
    let scope = find_function(file, "required_scope_for_kind")?;
    let Some(ingest_event_type) = direct_parameter_type(ingest, "event") else {
        return Some(
            "ingest_event_inner canonical event parameter does not resolve exactly to `nostr::Event`"
                .to_owned(),
        );
    };
    let Some(scope_event_type) = direct_parameter_type(scope, "event") else {
        return Some(
            "required_scope_for_kind event parameter does not resolve exactly to `&nostr::Event`"
                .to_owned(),
        );
    };
    let syn::Type::Reference(scope_event_reference) = scope_event_type else {
        return Some(
            "required_scope_for_kind event parameter does not resolve exactly to `&nostr::Event`"
                .to_owned(),
        );
    };
    if scope_event_reference.mutability.is_some()
        || scope_event_reference.lifetime.is_some()
        || !type_resolves_to_nostr_event(file, scope, &scope_event_reference.elem)
    {
        return Some(
            "required_scope_for_kind event parameter does not resolve exactly to `&nostr::Event`"
                .to_owned(),
        );
    }
    if !type_resolves_to_nostr_event(file, ingest, ingest_event_type) {
        return Some(
            "ingest_event_inner canonical event parameter does not resolve exactly to `nostr::Event`"
                .to_owned(),
        );
    }
    None
}

fn direct_parameter_type<'a>(function: &'a ItemFn, name: &str) -> Option<&'a syn::Type> {
    let mut matching = function.sig.inputs.iter().filter_map(|argument| {
        let syn::FnArg::Typed(argument) = argument else {
            return None;
        };
        direct_pattern_binding(&argument.pat, name).then_some(&*argument.ty)
    });
    let parameter_type = matching.next()?;
    matching.next().is_none().then_some(parameter_type)
}

fn type_resolves_to_nostr_event(file: &syn::File, function: &ItemFn, ty: &syn::Type) -> bool {
    let syn::Type::Path(event_type) = ty else {
        return false;
    };
    if event_type.qself.is_some()
        || event_type
            .path
            .segments
            .iter()
            .any(|segment| !matches!(segment.arguments, syn::PathArguments::None))
    {
        return false;
    }

    let name = path_name(&event_type.path);
    if name == "nostr::Event" {
        return !function_generic_shadows(function, "nostr")
            && module_name_is_unshadowed(file, "nostr");
    }
    name == "Event"
        && !function_generic_shadows(function, "Event")
        && module_name_is_unshadowed(file, "nostr")
        && exact_unconditional_import(file, "Event", "nostr::Event")
}

fn function_generic_shadows(function: &ItemFn, expected: &str) -> bool {
    function
        .sig
        .generics
        .params
        .iter()
        .any(|parameter| match parameter {
            syn::GenericParam::Type(parameter) => parameter.ident == expected,
            syn::GenericParam::Const(parameter) => parameter.ident == expected,
            syn::GenericParam::Lifetime(_) => false,
        })
}

fn module_name_is_unshadowed(file: &syn::File, expected: &str) -> bool {
    module_import_paths(file, expected).is_empty()
        && file.items.iter().all(|item| {
            !matches!(item, Item::Macro(_))
                && (matches!(item, Item::Use(_)) || !item_introduces_name(item, expected))
        })
}

fn exact_unconditional_import(file: &syn::File, introduced: &str, expected: &str) -> bool {
    let imports = module_import_paths(file, introduced);
    if imports.len() != 1 || imports.first().map(String::as_str) != Some(expected) {
        return false;
    }
    let introducing_uses = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Use(item) if use_tree_introduces_name(&item.tree, introduced) => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    introducing_uses.len() == 1
        && introducing_uses[0].attrs.is_empty()
        && file.items.iter().all(|item| {
            !matches!(item, Item::Macro(_))
                && (matches!(item, Item::Use(_)) || !item_introduces_name(item, introduced))
        })
}

fn collect_use_tree_paths(
    tree: &syn::UseTree,
    prefix: &[String],
    introduced_name: &str,
    imports: &mut Vec<String>,
) {
    match tree {
        syn::UseTree::Glob(_) => imports.push("*".to_owned()),
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                collect_use_tree_paths(tree, prefix, introduced_name, imports);
            }
        }
        syn::UseTree::Name(name) if name.ident == introduced_name => {
            let mut path = prefix.to_vec();
            path.push(name.ident.to_string());
            imports.push(path.join("::"));
        }
        syn::UseTree::Name(_) => {}
        syn::UseTree::Path(path) => {
            let mut prefix = prefix.to_vec();
            prefix.push(path.ident.to_string());
            collect_use_tree_paths(&path.tree, &prefix, introduced_name, imports);
        }
        syn::UseTree::Rename(rename) if rename.rename == introduced_name => {
            let mut path = prefix.to_vec();
            path.push(rename.ident.to_string());
            imports.push(path.join("::"));
        }
        syn::UseTree::Rename(_) => {}
    }
}

#[derive(Default)]
struct CallbackBoundaryVisitor {
    spawn_blocking_calls: usize,
    unwrap_or_else_calls: usize,
}

impl<'ast> Visit<'ast> for CallbackBoundaryVisitor {
    fn visit_expr_call(&mut self, expression: &'ast ExprCall) {
        if matches!(strip_expression(&expression.func), Expr::Path(path)
            if path_name(&path.path) == "tokio::task::spawn_blocking")
        {
            self.spawn_blocking_calls += 1;
        }
        visit::visit_expr_call(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast ExprMethodCall) {
        if expression.method == "unwrap_or_else" {
            self.unwrap_or_else_calls += 1;
        }
        visit::visit_expr_method_call(self, expression);
    }
}

fn callback_boundary_resolution_reason(
    ingest: &ItemFn,
    prior_statements: &[Stmt],
    gate_match: &syn::ExprMatch,
) -> Option<String> {
    let mut event_origin = ingest
        .sig
        .inputs
        .iter()
        .filter(|argument| match argument {
            syn::FnArg::Typed(argument) => direct_pattern_binding(&argument.pat, "event"),
            syn::FnArg::Receiver(_) => false,
        })
        .count()
        == 1;
    let mut verify_capture_bindings = ingest
        .sig
        .inputs
        .iter()
        .filter(|argument| match argument {
            syn::FnArg::Typed(argument) => pattern_binds_name(&argument.pat, "event_for_verify"),
            syn::FnArg::Receiver(_) => false,
        })
        .count();
    let mut verify_capture_origin = false;
    let mut saw_verification_spawn = false;
    let mut spawn_had_capture_origin = true;

    for statement in prior_statements {
        let capture_bindings = statement_binding_count(statement, "event_for_verify");
        if capture_bindings > 0 {
            verify_capture_bindings += capture_bindings;
            verify_capture_origin = verify_capture_bindings == 1
                && event_origin
                && statement_establishes_verification_capture_origin(statement);
        }

        let mut callbacks = CallbackBoundaryVisitor::default();
        callbacks.visit_stmt(statement);
        if callbacks.spawn_blocking_calls > 0
            && (callbacks.spawn_blocking_calls != 1
                || !statement_establishes_verification_result(statement))
        {
            return Some(
                "spawn_blocking callback is outside the pinned verification-result statement"
                    .to_owned(),
            );
        }
        if callbacks.spawn_blocking_calls == 1 {
            saw_verification_spawn = true;
            spawn_had_capture_origin &= verify_capture_bindings == 1 && verify_capture_origin;
        }
        if callbacks.unwrap_or_else_calls > 0
            && (callbacks.unwrap_or_else_calls != 1
                || !matches!(statement, Stmt::Local(local)
                    if direct_pattern_binding(&local.pat, "event")
                        && event_rebinding_has_arc_origin(local)))
        {
            return Some(
                "unwrap_or_else callback is outside the pinned event-rebinding statement"
                    .to_owned(),
            );
        }

        if statement_introduces_name(statement, "event") {
            event_origin = event_origin
                && matches!(statement, Stmt::Local(local)
                    if direct_pattern_binding(&local.pat, "event")
                        && event_rebinding_preserves_identity(local));
        }
    }

    if saw_verification_spawn
        && (!spawn_had_capture_origin || verify_capture_bindings != 1 || !verify_capture_origin)
    {
        return Some(
            "verification callback capture `event_for_verify` does not have one preceding pinned `Arc::clone(&event)` origin"
                .to_owned(),
        );
    }

    let mut gate_callbacks = CallbackBoundaryVisitor::default();
    gate_callbacks.visit_expr_match(gate_match);
    if gate_callbacks.spawn_blocking_calls > 0 || gate_callbacks.unwrap_or_else_calls > 0 {
        return Some("callback-taking API executes inside the scope gate".to_owned());
    }
    None
}

fn statement_binding_count(statement: &Stmt, expected: &str) -> usize {
    let mut bindings = BindingCountVisitor { expected, count: 0 };
    bindings.visit_stmt(statement);
    bindings.count
}

struct BindingCountVisitor<'a> {
    expected: &'a str,
    count: usize,
}

impl<'ast> Visit<'ast> for BindingCountVisitor<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        self.count += usize::from(item_introduces_name(item, self.expected));
        visit::visit_item(self, item);
    }

    fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
        self.count += usize::from(pattern.ident == self.expected);
        visit::visit_pat_ident(self, pattern);
    }
}

fn statement_establishes_verification_capture_origin(statement: &Stmt) -> bool {
    let Stmt::Local(local) = statement else {
        return false;
    };
    if !direct_pattern_binding(&local.pat, "event_for_verify") {
        return false;
    }
    let Some(initializer) = &local.init else {
        return false;
    };
    if initializer.diverge.is_some() {
        return false;
    }
    let Expr::Call(clone) = strip_expression(&initializer.expr) else {
        return false;
    };
    if !matches!(strip_expression(&clone.func), Expr::Path(path)
        if path_name(&path.path) == "std::sync::Arc::clone")
        || clone.args.len() != 1
    {
        return false;
    }
    clone
        .args
        .first()
        .is_some_and(|argument| expression_is_shared_reference_to_path(argument, "event"))
}

const MODELED_MACRO_BINDINGS: &[&str] = &[
    "MAX_EVENT_CONTENT_BYTES",
    "event",
    "event_id_hex",
    "kind_u32",
];

#[derive(Default)]
struct ModeledMacroUseVisitor {
    bindings: BTreeSet<String>,
    e_capture_count: usize,
}

impl ModeledMacroUseVisitor {
    fn inspect_macro(&mut self, expression: &syn::Macro) {
        let bindings = modeled_macro_bindings(expression);
        self.e_capture_count += usize::from(bindings.contains("e"));
        self.bindings.extend(bindings);
    }
}

impl<'ast> Visit<'ast> for ModeledMacroUseVisitor {
    fn visit_expr_macro(&mut self, expression: &'ast ExprMacro) {
        self.inspect_macro(&expression.mac);
        visit::visit_expr_macro(self, expression);
    }

    fn visit_stmt_macro(&mut self, statement: &'ast syn::StmtMacro) {
        self.inspect_macro(&statement.mac);
        visit::visit_stmt_macro(self, statement);
    }
}

fn modeled_macro_bindings(expression: &syn::Macro) -> BTreeSet<String> {
    let mut bindings = BTreeSet::new();
    if expression.path.is_ident("debug")
        && expression.tokens.to_string()
            == "event_id = % event_id_hex , kind = kind_u32 , \"ingest_event\""
    {
        bindings.insert("event_id_hex".to_owned());
        bindings.insert("kind_u32".to_owned());
        return bindings;
    }
    if expression.path.is_ident("error")
        && syn::parse2::<syn::LitStr>(expression.tokens.clone())
            .is_ok_and(|message| message.value() == "spawn_blocking panicked: {e}")
    {
        bindings.insert("e".to_owned());
        return bindings;
    }
    if !expression.path.is_ident("format") {
        return bindings;
    }
    let Some(arguments) = parse_format_arguments(expression.tokens.clone()) else {
        return bindings;
    };
    let mut arguments = arguments.iter();
    let Some(Expr::Lit(format)) = arguments.next() else {
        return bindings;
    };
    let syn::Lit::Str(format) = &format.lit else {
        return bindings;
    };
    match format.value().as_str() {
        "invalid: kind {kind_u32} is only accepted via WebSocket" => {
            bindings.insert("kind_u32".to_owned());
        }
        "invalid: {e}" => {
            bindings.insert("e".to_owned());
        }
        "invalid: content exceeds maximum size of {} bytes (got {})" => {
            bindings.insert("MAX_EVENT_CONTENT_BYTES".to_owned());
            bindings.insert("event".to_owned());
        }
        _ => {}
    }
    bindings
}

fn macro_binding_resolution_reason(
    ingest: &ItemFn,
    prior_statements: &[Stmt],
    gate_match: &syn::ExprMatch,
) -> Option<String> {
    let mut origins = BTreeMap::from([
        (
            "event",
            ingest
                .sig
                .inputs
                .iter()
                .filter(|argument| match argument {
                    syn::FnArg::Typed(argument) => direct_pattern_binding(&argument.pat, "event"),
                    syn::FnArg::Receiver(_) => false,
                })
                .count()
                == 1,
        ),
        (
            "kind_u32",
            ingest
                .sig
                .inputs
                .iter()
                .filter(|argument| match argument {
                    syn::FnArg::Typed(argument) => {
                        direct_pattern_binding(&argument.pat, "kind_u32")
                    }
                    syn::FnArg::Receiver(_) => false,
                })
                .count()
                == 1,
        ),
        ("event_id_hex", false),
        ("MAX_EVENT_CONTENT_BYTES", false),
    ]);
    let mut verification_result_origin = false;

    for statement in prior_statements {
        let mut uses = ModeledMacroUseVisitor::default();
        uses.visit_stmt(statement);
        if uses.e_capture_count > 0
            && let Some(reason) = verification_capture_resolution_reason(
                statement,
                verification_result_origin,
                uses.e_capture_count,
            )
        {
            return Some(reason);
        }
        for name in uses.bindings.iter().filter(|name| name.as_str() != "e") {
            if !origins.get(name.as_str()).copied().unwrap_or(false) {
                return Some(format!(
                    "modeled macro binding `{name}` has no pinned origin"
                ));
            }
            if statement_introduces_name(statement, name) {
                return Some(format!(
                    "modeled macro binding `{name}` is shadowed in its containing statement"
                ));
            }
        }

        for name in MODELED_MACRO_BINDINGS {
            if statement_introduces_name(statement, name) {
                origins.insert(name, statement_establishes_macro_origin(statement, name));
            }
        }
        if statement_introduces_name(statement, "verify_result") {
            verification_result_origin = statement_establishes_verification_result(statement);
        }
    }

    let mut gate_uses = ModeledMacroUseVisitor::default();
    gate_uses.visit_expr_match(gate_match);
    if !gate_uses.bindings.is_empty() {
        return Some(
            "modeled macro executes inside the scope gate without a pinned binding origin"
                .to_owned(),
        );
    }
    None
}

fn statement_establishes_macro_origin(statement: &Stmt, name: &str) -> bool {
    match name {
        "event" => matches!(statement, Stmt::Local(local)
            if direct_pattern_binding(&local.pat, "event")
                && event_rebinding_preserves_identity(local)),
        "kind_u32" => matches!(statement, Stmt::Local(local)
        if direct_pattern_binding(&local.pat, "kind_u32")
            && local.init.as_ref().is_some_and(|initializer| {
                matches!(strip_expression(&initializer.expr), Expr::Call(call)
                    if matches!(strip_expression(&call.func), Expr::Path(path)
                        if path.path.is_ident("event_kind_u32"))
                        && call.args.len() == 1
                        && call.args.first().is_some_and(|argument|
                            expression_binding_name(argument).as_deref() == Some("event"))
                )
            })),
        "event_id_hex" => matches!(statement, Stmt::Local(local)
        if direct_pattern_binding(&local.pat, "event_id_hex")
            && local.init.as_ref().is_some_and(|initializer| {
                matches!(strip_expression(&initializer.expr), Expr::MethodCall(call)
                    if call.method == "to_hex"
                        && call.args.is_empty()
                        && expression_is_field(&call.receiver, "event", "id"))
            })),
        "MAX_EVENT_CONTENT_BYTES" => matches!(statement, Stmt::Item(Item::Const(item))
            if item.ident == "MAX_EVENT_CONTENT_BYTES"
                && matches!(&*item.ty, syn::Type::Path(path) if path.path.is_ident("usize"))),
        _ => false,
    }
}

fn statement_establishes_verification_result(statement: &Stmt) -> bool {
    let Stmt::Local(local) = statement else {
        return false;
    };
    if !direct_pattern_binding(&local.pat, "verify_result") {
        return false;
    }
    let Some(initializer) = &local.init else {
        return false;
    };
    let Expr::Await(awaited) = strip_expression(&initializer.expr) else {
        return false;
    };
    let Expr::Call(spawn) = strip_expression(&awaited.base) else {
        return false;
    };
    modeled_spawn_blocking_verification(spawn)
}

fn modeled_spawn_blocking_verification(spawn: &ExprCall) -> bool {
    if !matches!(strip_expression(&spawn.func), Expr::Path(path)
        if path_name(&path.path) == "tokio::task::spawn_blocking")
        || spawn.args.len() != 1
    {
        return false;
    }
    let Some(Expr::Closure(closure)) = spawn.args.first() else {
        return false;
    };
    if !closure.attrs.is_empty()
        || closure.lifetimes.is_some()
        || closure.constness.is_some()
        || closure.asyncness.is_some()
        || closure.capture.is_none()
        || !closure.inputs.is_empty()
        || !matches!(closure.output, syn::ReturnType::Default)
    {
        return false;
    }
    let Expr::Call(verify) = strip_expression(&closure.body) else {
        return false;
    };
    matches!(strip_expression(&verify.func), Expr::Path(path)
        if path.path.is_ident("verify_event"))
        && verify.args.len() == 1
        && verify.args.first().is_some_and(|argument| {
            expression_is_shared_reference_to_path(argument, "event_for_verify")
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerificationCaptureKind {
    Format,
    Error,
}

struct VerificationCaptureVisitor {
    allowed: Option<VerificationCaptureKind>,
    seen: usize,
    unresolved: Option<String>,
}

impl VerificationCaptureVisitor {
    fn inspect_macro(&mut self, expression: &syn::Macro) {
        let bindings = modeled_macro_bindings(expression);
        if !bindings.contains("e") {
            return;
        }
        self.seen += 1;
        let actual = if expression.path.is_ident("format") {
            VerificationCaptureKind::Format
        } else {
            VerificationCaptureKind::Error
        };
        if self.allowed != Some(actual) {
            self.unresolved = Some(
                "modeled macro capture `e` does not originate in its pinned verification-result arm"
                    .to_owned(),
            );
        }
    }
}

impl<'ast> Visit<'ast> for VerificationCaptureVisitor {
    fn visit_expr_macro(&mut self, expression: &'ast ExprMacro) {
        self.inspect_macro(&expression.mac);
        visit::visit_expr_macro(self, expression);
    }

    fn visit_stmt_macro(&mut self, statement: &'ast syn::StmtMacro) {
        self.inspect_macro(&statement.mac);
        visit::visit_stmt_macro(self, statement);
    }

    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        let allowed = self.allowed.take();
        visit::visit_expr_match(self, expression);
        self.allowed = allowed;
    }
}

fn verification_capture_resolution_reason(
    statement: &Stmt,
    verification_result_origin: bool,
    expected_captures: usize,
) -> Option<String> {
    let Stmt::Expr(Expr::Match(match_expression), _) = statement else {
        return Some(
            "modeled macro capture `e` is outside the pinned verification-result match".to_owned(),
        );
    };
    if !verification_result_origin || !expression_is_path(&match_expression.expr, "verify_result") {
        return Some(
            "modeled macro capture `e` has no pinned verification-result origin".to_owned(),
        );
    }

    let mut visitor = VerificationCaptureVisitor {
        allowed: None,
        seen: 0,
        unresolved: None,
    };
    for arm in &match_expression.arms {
        visitor.allowed = if expression_introduces_name(&arm.body, "e") {
            None
        } else if pattern_is_nested_verification_error_binding(&arm.pat) {
            Some(VerificationCaptureKind::Format)
        } else if pattern_is_direct_error_binding(&arm.pat, "e") {
            Some(VerificationCaptureKind::Error)
        } else {
            None
        };
        visitor.visit_pat(&arm.pat);
        visitor.visit_expr(&arm.body);
    }
    if visitor.seen != expected_captures {
        return Some(
            "modeled macro capture `e` appears outside a direct verification-result arm".to_owned(),
        );
    }
    visitor.unresolved
}

fn pattern_is_nested_verification_error_binding(pattern: &Pat) -> bool {
    matches!(pattern, Pat::TupleStruct(ok)
        if ok.path.is_ident("Ok")
            && ok.elems.len() == 1
            && matches!(ok.elems.first(), Some(Pat::TupleStruct(error))
                if error.path.is_ident("Err")
                    && error.elems.len() == 1
                    && matches!(error.elems.first(), Some(Pat::Ident(binding))
                        if binding.ident == "e" && binding.subpat.is_none())))
}

#[derive(Default)]
struct ModeledReceiverVisitor {
    names: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for ModeledReceiverVisitor {
    fn visit_expr_method_call(&mut self, expression: &'ast ExprMethodCall) {
        self.names.extend(modeled_receiver_bindings(expression));
        visit::visit_expr_method_call(self, expression);
    }
}

fn modeled_receiver_bindings(call: &ExprMethodCall) -> Vec<String> {
    let receiver = strip_expression(&call.receiver);
    match call.method.to_string().as_str() {
        "to_hex" if expression_is_field(receiver, "event", "id") => vec!["event".to_owned()],
        "community" if expression_is_path(receiver, "tenant") => vec!["tenant".to_owned()],
        "is_http" | "pubkey" if expression_is_path(receiver, "auth") => {
            vec!["auth".to_owned()]
        }
        "into" => match receiver {
            Expr::Path(path) if path.path.is_ident("error") => vec!["error".to_owned()],
            Expr::Path(path) if path.path.is_ident("msg") => vec!["msg".to_owned()],
            _ => Vec::new(),
        },
        "clone"
            if matches!(receiver, Expr::Unary(unary)
                if matches!(unary.op, syn::UnOp::Deref(_))
                    && expression_is_path(&unary.expr, "arc")) =>
        {
            vec!["arc".to_owned()]
        }
        "as_secs" if expression_is_field(receiver, "event", "created_at") => {
            vec!["event".to_owned()]
        }
        "len" if expression_is_field(receiver, "event", "content") => vec!["event".to_owned()],
        "is_serving_active" if modeled_serving_state_read(call) => {
            vec!["state".to_owned(), "tenant".to_owned()]
        }
        _ => Vec::new(),
    }
}

fn receiver_binding_resolution_reason(
    ingest: &ItemFn,
    prior_statements: &[Stmt],
    gate_match: &syn::ExprMatch,
) -> Option<String> {
    let mut receivers = ModeledReceiverVisitor::default();
    for statement in prior_statements {
        receivers.visit_stmt(statement);
    }
    receivers.visit_expr_match(gate_match);
    if receivers.names.is_empty() {
        return None;
    }

    for name in ["event", "tenant", "auth", "state"] {
        if !receivers.names.contains(name) {
            continue;
        }
        let parameter_count = ingest
            .sig
            .inputs
            .iter()
            .filter(|argument| match argument {
                syn::FnArg::Typed(argument) => direct_pattern_binding(&argument.pat, name),
                syn::FnArg::Receiver(_) => false,
            })
            .count();
        if parameter_count != 1 {
            return Some(format!(
                "modeled method receiver `{name}` does not originate at its canonical parameter"
            ));
        }
    }
    for name in ["msg", "error", "arc"] {
        if receivers.names.contains(name)
            && ingest.sig.inputs.iter().any(|argument| match argument {
                syn::FnArg::Typed(argument) => pattern_binds_name(&argument.pat, name),
                syn::FnArg::Receiver(_) => false,
            })
        {
            return Some(format!(
                "modeled method receiver `{name}` is shadowed by an input parameter"
            ));
        }
    }

    for statement in prior_statements {
        let identity_event_rebinding = matches!(statement, Stmt::Local(local)
            if direct_pattern_binding(&local.pat, "event")
                && event_rebinding_preserves_identity(local));
        let arc_origin_rebinding = matches!(statement, Stmt::Local(local)
            if direct_pattern_binding(&local.pat, "event")
                && event_rebinding_has_arc_origin(local));
        for name in &receivers.names {
            if (name == "event" && identity_event_rebinding)
                || (name == "arc" && arc_origin_rebinding)
            {
                continue;
            }
            if statement_introduces_name(statement, name) {
                return Some(format!(
                    "modeled method receiver `{name}` is shadowed before the gate"
                ));
            }
        }
        let statement_receivers = receiver_names_in_statement(statement);
        for name in statement_receivers {
            match name.as_str() {
                "arc" if !arc_origin_rebinding => {
                    return Some(
                        "modeled method receiver `arc` has no pinned event-rebinding origin"
                            .to_owned(),
                    );
                }
                "msg" | "error" => {
                    return Some(format!(
                        "modeled method receiver `{name}` has no direct error-pattern origin"
                    ));
                }
                _ => {}
            }
        }
    }

    for arm in &gate_match.arms {
        let arm_receivers = receiver_names_in_arm(arm);
        for name in arm_receivers {
            if name == "arc" {
                return Some(
                    "modeled method receiver `arc` has no pinned event-rebinding origin".to_owned(),
                );
            }
            if pattern_binds_name(&arm.pat, &name) && !matches!(name.as_str(), "msg" | "error") {
                return Some(format!(
                    "modeled method receiver `{name}` is shadowed by a gate pattern"
                ));
            }
            if expression_introduces_name(&arm.body, &name) {
                return Some(format!(
                    "modeled method receiver `{name}` is rebound inside the gate"
                ));
            }
            if matches!(name.as_str(), "msg" | "error")
                && !pattern_is_direct_error_binding(&arm.pat, &name)
            {
                return Some(format!(
                    "modeled method receiver `{name}` has an unproven gate-pattern origin"
                ));
            }
        }
    }
    None
}

fn receiver_names_in_statement(statement: &Stmt) -> BTreeSet<String> {
    let mut receivers = ModeledReceiverVisitor::default();
    receivers.visit_stmt(statement);
    receivers.names
}

fn receiver_names_in_arm(arm: &syn::Arm) -> BTreeSet<String> {
    let mut receivers = ModeledReceiverVisitor::default();
    receivers.visit_arm(arm);
    receivers.names
}

fn expression_introduces_name(expression: &Expr, expected: &str) -> bool {
    let mut bindings = BindingIntroductionVisitor {
        expected,
        found: false,
    };
    bindings.visit_expr(expression);
    bindings.found
}

fn pattern_is_direct_error_binding(pattern: &Pat, expected: &str) -> bool {
    matches!(
        pattern,
        Pat::TupleStruct(pattern)
            if pattern.path.is_ident("Err")
                && pattern.elems.len() == 1
                && matches!(pattern.elems.first(), Some(Pat::Ident(binding))
                    if binding.ident == expected && binding.subpat.is_none())
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
    for local in prior_statements
        .iter()
        .filter_map(|statement| match statement {
            Stmt::Local(local) if pattern_binds_name(&local.pat, "event") => Some(local),
            _ => None,
        })
    {
        if !direct_pattern_binding(&local.pat, "event")
            || !event_rebinding_preserves_identity(local)
        {
            return Err(
                "required_scope_for_kind incoming event binding is shadowed by an unproven local"
                    .to_owned(),
            );
        }
    }

    if let Some(local) = prior_statements.iter().rev().find_map(|statement| {
        let Stmt::Local(local) = statement else {
            return None;
        };
        pattern_binds_name(&local.pat, &kind_name).then_some(local)
    }) {
        if !direct_pattern_binding(&local.pat, &kind_name) {
            return Err(
                "required_scope_for_kind kind binding is shadowed through an unproven pattern"
                    .to_owned(),
            );
        }
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

#[derive(Default)]
struct PatternBindingVisitor {
    names: Vec<String>,
}

impl<'ast> Visit<'ast> for PatternBindingVisitor {
    fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
        self.names.push(pattern.ident.to_string());
        visit::visit_pat_ident(self, pattern);
    }
}

fn pattern_binds_name(pattern: &Pat, expected: &str) -> bool {
    let mut bindings = PatternBindingVisitor::default();
    bindings.visit_pat(pattern);
    bindings.names.iter().any(|name| name == expected)
}

fn direct_pattern_binding(pattern: &Pat, expected: &str) -> bool {
    matches!(pattern, Pat::Ident(binding) if binding.ident == expected && binding.subpat.is_none())
}

fn event_rebinding_preserves_identity(local: &syn::Local) -> bool {
    let Some(initializer) = &local.init else {
        return false;
    };
    match strip_expression(&initializer.expr) {
        Expr::Call(call) => {
            matches!(strip_expression(&call.func), Expr::Path(path) if path_name(&path.path) == "std::sync::Arc::new")
                && call.args.len() == 1
                && call
                    .args
                    .first()
                    .is_some_and(|argument| expression_is_path(argument, "event"))
        }
        Expr::MethodCall(unwrap) => modeled_event_unwrap_fallback(unwrap),
        _ => false,
    }
}

fn modeled_event_unwrap_fallback(unwrap: &ExprMethodCall) -> bool {
    if unwrap.method != "unwrap_or_else" || unwrap.args.len() != 1 {
        return false;
    }
    let Expr::Call(try_unwrap) = strip_expression(&unwrap.receiver) else {
        return false;
    };
    if !matches!(strip_expression(&try_unwrap.func), Expr::Path(path)
        if path_name(&path.path) == "std::sync::Arc::try_unwrap")
        || try_unwrap.args.len() != 1
        || !try_unwrap
            .args
            .first()
            .is_some_and(|argument| expression_is_path(argument, "event"))
    {
        return false;
    }
    let Some(Expr::Closure(fallback)) = unwrap.args.first() else {
        return false;
    };
    fallback.attrs.is_empty()
        && fallback.lifetimes.is_none()
        && fallback.constness.is_none()
        && fallback.asyncness.is_none()
        && fallback.capture.is_none()
        && fallback.inputs.len() == 1
        && matches!(fallback.output, syn::ReturnType::Default)
        && matches!(fallback.inputs.first(), Some(Pat::Ident(binding))
            if binding.attrs.is_empty()
                && binding.by_ref.is_none()
                && binding.mutability.is_none()
                && binding.ident == "arc"
                && binding.subpat.is_none())
        && matches!(strip_expression(&fallback.body), Expr::MethodCall(clone)
            if allowed_pre_gate_method_call(clone))
}

fn event_rebinding_has_arc_origin(local: &syn::Local) -> bool {
    let Some(initializer) = &local.init else {
        return false;
    };
    event_rebinding_preserves_identity(local)
        && matches!(strip_expression(&initializer.expr), Expr::MethodCall(unwrap)
            if unwrap.method == "unwrap_or_else")
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
            Expr::Path(path)
                if path_name(&path.path) == "tokio::task::spawn_blocking"
                    && modeled_spawn_blocking_verification(expression) => {}
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
        let modeled = if expression.path.is_ident("debug") {
            expression.tokens.to_string()
                == "event_id = % event_id_hex , kind = kind_u32 , \"ingest_event\""
        } else if expression.path.is_ident("error") {
            syn::parse2::<syn::LitStr>(expression.tokens.clone())
                .is_ok_and(|message| message.value() == "spawn_blocking panicked: {e}")
        } else if expression.path.is_ident("format") {
            modeled_format_macro(expression.tokens.clone())
        } else {
            false
        };
        if !modeled {
            self.risks.push(format!(
                "unmodeled macro `{name}!` that may diverge or have effects"
            ));
        }
    }
}

fn modeled_format_macro(tokens: proc_macro2::TokenStream) -> bool {
    let Some(arguments) = parse_format_arguments(tokens) else {
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

fn parse_format_arguments(
    tokens: proc_macro2::TokenStream,
) -> Option<syn::punctuated::Punctuated<Expr, Token![,]>> {
    let parser = syn::punctuated::Punctuated::<Expr, Token![,]>::parse_terminated;
    parser.parse2(tokens).ok()
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
            | "verify_event"
    )
}

fn allowed_awaited_expression(expression: &Expr) -> bool {
    match strip_expression(expression) {
        Expr::Call(call) => modeled_spawn_blocking_verification(call),
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
        "unwrap_or_else" => modeled_event_unwrap_fallback(call),
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

fn expression_is_shared_reference_to_path(expression: &Expr, expected: &str) -> bool {
    matches!(strip_expression(expression), Expr::Reference(reference)
        if reference.mutability.is_none()
            && expression_is_path(&reference.expr, expected))
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

    use super::{
        CORE_KIND_ARTIFACT, IngestDecisionKind, LiftError, NativeCompleteness,
        PUSH_LEASE_CONSTANT_PATH, RelayCompilationSources, RelayInputs, RelaySemanticSources,
        lift_relay_ingest,
    };

    const WORKSPACE_MANIFEST: &str = r#"[workspace]
members = ["crates/buzz-core", "crates/buzz-relay"]
resolver = "2"

[workspace.package]
edition = "2021"

[workspace.dependencies]
buzz-core = { path = "crates/buzz-core" }
nostr = { version = "0.44", features = ["nip44"] }
"#;

    const WORKSPACE_LOCK: &str = r#"version = 4

[[package]]
name = "nostr"
version = "0.44.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c7d3d987ea7078dc36947cde532637c472a229426702e4331dd7667325378bd9"
"#;

    const CARGO_CONFIG: &str = r#"[profile.dev]
debug = "line-tables-only"

[env]
CMAKE_POLICY_VERSION_MINIMUM = "3.5"
"#;

    const RELAY_MANIFEST: &str = r#"[package]
name = "buzz-relay"
version = "0.1.0"
edition.workspace = true

[dependencies]
buzz-core = { workspace = true }
nostr = { workspace = true }
"#;

    const CORE_MANIFEST: &str = r#"[package]
name = "buzz-core"
version = "0.1.0"
edition.workspace = true
"#;

    const RELAY_CRATE_ROOT: &str = "pub mod handlers;\n";
    const RELAY_HANDLERS_MODULE: &str = "pub mod ingest;\npub mod push_lease;\n";
    const CORE_CRATE_ROOT: &str = "pub mod kind;\n";

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

    const PUSH_LEASE_SOURCE: &str = r#"
/// NIP-PL addressable push-lease event kind.
pub const KIND_PUSH_LEASE: u32 = 30_350;
"#;

    const INGEST_SOURCE: &str = r#"
use buzz_core::kind::{is_moderation_command_kind, KIND_MESSAGE, KIND_SPECIAL};
use nostr::Event;
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
        lift_job_protocol(KIND_SOURCE, "fixture", CORE_KIND_ARTIFACT, "revision")
            .expect("protocol fixture lifts")
    }

    fn fixture_inputs<'a>(ingest: &'a str, kind: &'a str, push_lease: &'a str) -> RelayInputs<'a> {
        fixture_inputs_with_handlers(ingest, kind, push_lease, RELAY_HANDLERS_MODULE)
    }

    fn fixture_inputs_with_handlers<'a>(
        ingest: &'a str,
        kind: &'a str,
        push_lease: &'a str,
        relay_handlers_module: &'a str,
    ) -> RelayInputs<'a> {
        RelayInputs {
            semantic: RelaySemanticSources {
                ingest,
                kind,
                push_lease,
            },
            compilation: RelayCompilationSources {
                workspace_manifest: WORKSPACE_MANIFEST,
                workspace_lock: WORKSPACE_LOCK,
                cargo_config: CARGO_CONFIG,
                relay_manifest: RELAY_MANIFEST,
                relay_crate_root: RELAY_CRATE_ROOT,
                relay_handlers_module,
                core_manifest: CORE_MANIFEST,
                core_crate_root: CORE_CRATE_ROOT,
            },
        }
    }

    #[test]
    fn closed_fallback_rejects_job_kinds_after_resolving_named_guard() {
        let lift = lift_relay_ingest(
            fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE),
            &fixture_protocol(),
            "fixture",
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
        assert_eq!(lift.gate_call.line_start, 14);
        assert_eq!(lift.compilation.package_edges.len(), 2);
        assert_eq!(lift.compilation.module_edges.len(), 4);
        assert_eq!(lift.compilation.locked_dependencies.len(), 1);
    }

    #[test]
    fn inline_or_macro_selected_modules_make_compilation_partial() {
        let mut inline = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        inline.compilation.relay_handlers_module =
            "pub mod ingest;\npub mod push_lease { pub const KIND_PUSH_LEASE: u32 = 43_001; }\n";
        assert_unproven_compilation_is_partial(inline, "exact `push_lease` module");

        let mut expanded = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        expanded.compilation.relay_handlers_module = "declare_ingest_and_push_lease!();\n";
        assert_unproven_compilation_is_partial(expanded, "item macro");
    }

    #[test]
    fn configured_module_paths_make_compilation_partial() {
        let mut inputs = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        inputs.compilation.relay_handlers_module =
            "pub mod ingest;\n#[path = \"alternate.rs\"]\npub mod push_lease;\n";
        assert_unproven_compilation_is_partial(inputs, "exact `push_lease` module");
    }

    #[test]
    fn alternate_workspace_core_paths_make_compilation_partial() {
        let alternate = WORKSPACE_MANIFEST.replace(
            "buzz-core = { path = \"crates/buzz-core\" }",
            "buzz-core = { path = \"crates/alternate-core\" }",
        );
        let mut inputs = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        inputs.compilation.workspace_manifest = &alternate;
        assert_unproven_compilation_is_partial(inputs, "does not resolve exactly");
    }

    #[test]
    fn selected_packages_must_be_exact_workspace_members() {
        let alternate = WORKSPACE_MANIFEST.replace(
            "members = [\"crates/buzz-core\", \"crates/buzz-relay\"]",
            "members = [\"crates/buzz-core\"]",
        );
        let mut inputs = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        inputs.compilation.workspace_manifest = &alternate;
        assert_unproven_compilation_is_partial(inputs, "exact member");

        let excluded = WORKSPACE_MANIFEST.replace(
            "resolver = \"2\"",
            "resolver = \"2\"\nexclude = [\"crates/buzz-relay\"]",
        );
        let mut inputs = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        inputs.compilation.workspace_manifest = &excluded;
        assert_unproven_compilation_is_partial(inputs, "exclusion");
    }

    #[test]
    fn nested_workspaces_and_library_overrides_make_compilation_partial() {
        let alternate = RELAY_MANIFEST.replace(
            "version = \"0.1.0\"",
            "version = \"0.1.0\"\nworkspace = \"../alternate\"",
        );
        let mut inputs = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        inputs.compilation.relay_manifest = &alternate;
        assert_unproven_compilation_is_partial(inputs, "expected workspace");

        let alternate = format!("{CORE_MANIFEST}\n[lib]\npath = \"src/alternate.rs\"\n");
        let mut inputs = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        inputs.compilation.core_manifest = &alternate;
        assert_unproven_compilation_is_partial(inputs, "library target override");
    }

    #[test]
    fn ancestor_modules_cannot_redirect_modeled_crate_names() {
        let mut inputs = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        inputs.compilation.relay_crate_root =
            "extern crate alternate as buzz_core;\npub mod handlers;\n";
        assert_unproven_compilation_is_partial(inputs, "extern-crate item");

        let mut inputs = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        inputs.compilation.relay_handlers_module =
            "pub use alternate as nostr;\npub mod ingest;\npub mod push_lease;\n";
        assert_unproven_compilation_is_partial(inputs, "reserved name `nostr`");

        let mut inputs = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        inputs.compilation.core_crate_root = "#[macro_use]\nmod alternate;\npub mod kind;\n";
        assert_unproven_compilation_is_partial(inputs, "macro-use attribute");
    }

    #[test]
    fn aliased_relay_dependencies_make_compilation_partial() {
        let alternate = RELAY_MANIFEST.replace(
            "buzz-core = { workspace = true }",
            "buzz_core = { package = \"alternate-core\", path = \"../alternate-core\" }",
        );
        let mut inputs = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        inputs.compilation.relay_manifest = &alternate;
        assert_unproven_compilation_is_partial(inputs, "ambiguous `buzz_core` dependency");
    }

    #[test]
    fn dependency_patches_make_compilation_partial() {
        let patched = format!(
            "{WORKSPACE_MANIFEST}\n[patch.crates-io]\nnostr = {{ path = \"crates/alternate-nostr\" }}\n"
        );
        let mut inputs = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        inputs.compilation.workspace_manifest = &patched;
        assert_unproven_compilation_is_partial(inputs, "patch or replacement");
    }

    #[test]
    fn cargo_source_or_compiler_overrides_make_compilation_partial() {
        let mut inputs = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        inputs.compilation.cargo_config = "[source.crates-io]\nreplace-with = \"alternate\"\n";
        assert_unproven_compilation_is_partial(inputs, "unmodeled resolution");

        let mut inputs = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        inputs.compilation.cargo_config = "[env]\nRUSTFLAGS = \"--cfg alternate\"\n";
        assert_unproven_compilation_is_partial(inputs, "unmodeled Cargo or Rust settings");
    }

    #[test]
    fn lockfile_must_bind_the_selected_registry_package() {
        let altered = WORKSPACE_LOCK.replace(
            "c7d3d987ea7078dc36947cde532637c472a229426702e4331dd7667325378bd9",
            "missing",
        );
        let mut inputs = fixture_inputs(INGEST_SOURCE, KIND_SOURCE, PUSH_LEASE_SOURCE);
        inputs.compilation.workspace_lock = &altered;
        assert_unproven_compilation_is_partial(inputs, "checksummed crates.io package");
    }

    #[test]
    fn unresolved_guard_degrades_to_partial_unknown() {
        let source = INGEST_SOURCE.replace(
            "k if is_moderation_command_kind(k)",
            "k if third_party_guard(k)",
        );
        let lift = lift_relay_ingest(
            fixture_inputs(&source, KIND_SOURCE, PUSH_LEASE_SOURCE),
            &fixture_protocol(),
            "fixture",
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
    fn conditional_scope_arms_degrade_to_partial_unknown() {
        let source = INGEST_SOURCE.replace(
            "        _ => Err(\"restricted: unknown event kind\"),",
            "        #[cfg(feature = \"reject_jobs\")]\n        _ => Err(\"restricted: unknown event kind\"),\n        #[cfg(not(feature = \"reject_jobs\"))]\n        _ => Ok(Scope::MessagesWrite),",
        );

        assert_unproven_gate_is_partial(&source, "unmodeled attribute");
    }

    #[test]
    fn conditional_accepting_arm_before_rejecting_fallback_remains_partial() {
        let source = INGEST_SOURCE.replace(
            "        _ => Err(\"restricted: unknown event kind\"),",
            "        #[cfg(not(feature = \"reject_jobs\"))]\n        _ => Ok(Scope::MessagesWrite),\n        #[cfg(feature = \"reject_jobs\")]\n        _ => Err(\"restricted: unknown event kind\"),",
        );

        assert_unproven_gate_is_partial(&source, "unmodeled attribute");
    }

    #[test]
    fn non_configuration_scope_arm_attributes_also_degrade_to_partial() {
        let source = INGEST_SOURCE.replace(
            "        KIND_MESSAGE => Ok(Scope::MessagesWrite),",
            "        #[allow(unreachable_patterns)]\n        KIND_MESSAGE => Ok(Scope::MessagesWrite),",
        );

        assert_unproven_gate_is_partial(&source, "unmodeled attribute");
    }

    #[test]
    fn scope_function_attributes_are_conservative_but_docs_are_inert() {
        let attributed = INGEST_SOURCE.replace(
            "fn required_scope_for_kind",
            "#[cfg(feature = \"scope_v2\")]\nfn required_scope_for_kind",
        );
        assert_unproven_gate_is_partial(&attributed, "unmodeled attribute");

        let documented = INGEST_SOURCE.replace(
            "fn required_scope_for_kind",
            "/// Select the required scope.\nfn required_scope_for_kind",
        );
        let lift = lift_relay_ingest(
            fixture_inputs(&documented, KIND_SOURCE, PUSH_LEASE_SOURCE),
            &fixture_protocol(),
            "fixture",
            "revision",
        )
        .expect("documented scope function lifts");
        assert_eq!(lift.coverage.completeness, NativeCompleteness::Exhaustive);
        assert!(lift.coverage.unresolved.is_empty());
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
            fixture_inputs(INGEST_SOURCE, &kind_source, PUSH_LEASE_SOURCE),
            &protocol,
            "fixture",
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
    fn scope_constants_require_exact_kind_imports() {
        let source = INGEST_SOURCE.replace(
            "use buzz_core::kind::{is_moderation_command_kind, KIND_MESSAGE, KIND_SPECIAL};",
            "use buzz_core::kind::{is_moderation_command_kind, KIND_SPECIAL};\nconst KIND_MESSAGE: u32 = 43_001;",
        );

        assert_unproven_gate_is_partial(&source, "decision constant `KIND_MESSAGE`");
    }

    #[test]
    fn qualified_scope_predicates_require_the_unshadowed_kind_root() {
        let source = INGEST_SOURCE
            .replace(
                "use buzz_core::kind::{is_moderation_command_kind, KIND_MESSAGE, KIND_SPECIAL};\n",
                "mod buzz_core { pub mod kind { pub fn is_moderation_command_kind(kind: u32) -> bool { kind == 43_001 } } }\n",
            )
            .replace("KIND_MESSAGE", "1")
            .replace("KIND_SPECIAL", "2")
            .replace(
                "is_moderation_command_kind(k)",
                "buzz_core::kind::is_moderation_command_kind(k)",
            );

        assert_unproven_gate_is_partial(
            &source,
            "decision predicate `buzz_core::kind::is_moderation_command_kind`",
        );
    }

    #[test]
    fn unqualified_scope_predicates_require_the_exact_kind_import() {
        let source = INGEST_SOURCE.replace(
            "use buzz_core::kind::{is_moderation_command_kind, KIND_MESSAGE, KIND_SPECIAL};",
            "use buzz_core::kind::{KIND_MESSAGE, KIND_SPECIAL};\nconst fn is_moderation_command_kind(kind: u32) -> bool { kind == 43_001 }",
        );

        assert_unproven_gate_is_partial(&source, "decision predicate `is_moderation_command_kind`");
    }

    #[test]
    fn exact_qualified_kind_predicates_remain_exhaustive() {
        let source = INGEST_SOURCE
            .replace(
                "use buzz_core::kind::{is_moderation_command_kind, KIND_MESSAGE, KIND_SPECIAL};",
                "use buzz_core::kind::{KIND_MESSAGE, KIND_SPECIAL};",
            )
            .replace(
                "is_moderation_command_kind(k)",
                "buzz_core::kind::is_moderation_command_kind(k)",
            );
        let lift = lift_relay_ingest(
            fixture_inputs(&source, KIND_SOURCE, PUSH_LEASE_SOURCE),
            &fixture_protocol(),
            "fixture",
            "revision",
        )
        .expect("qualified predicate fixture lifts");

        assert_eq!(lift.coverage.completeness, NativeCompleteness::Exhaustive);
        assert!(lift.coverage.unresolved.is_empty());
    }

    #[test]
    fn qualified_push_lease_constants_use_their_own_consumed_source() {
        let source = INGEST_SOURCE.replace(
            "        _ => Err(\"restricted: unknown event kind\"),",
            "        super::push_lease::KIND_PUSH_LEASE => Ok(Scope::MessagesWrite),\n        _ => Err(\"restricted: unknown event kind\"),",
        );
        let push_source = PUSH_LEASE_SOURCE.replace("30_350", "43_001");
        let lift = lift_relay_ingest(
            fixture_inputs(&source, KIND_SOURCE, &push_source),
            &fixture_protocol(),
            "fixture",
            "revision",
        )
        .expect("qualified push lease fixture lifts");

        assert_eq!(lift.coverage.completeness, NativeCompleteness::Exhaustive);
        assert_eq!(lift.job_decisions[0].decision, IngestDecisionKind::Accepted);
        assert_eq!(lift.job_decisions[1].decision, IngestDecisionKind::Rejected);
        assert!(lift.push_lease_constant.is_some());
    }

    #[test]
    fn missing_or_misidentified_push_lease_declarations_make_scope_partial() {
        let source = INGEST_SOURCE.replace(
            "        _ => Err(\"restricted: unknown event kind\"),",
            "        super::push_lease::KIND_PUSH_LEASE => Ok(Scope::MessagesWrite),\n        _ => Err(\"restricted: unknown event kind\"),",
        );
        let missing = lift_relay_ingest(
            fixture_inputs(&source, KIND_SOURCE, "pub const OTHER_KIND: u32 = 30_350;"),
            &fixture_protocol(),
            "fixture",
            "revision",
        )
        .expect("missing push declaration remains visible");
        assert_eq!(missing.coverage.completeness, NativeCompleteness::Partial);
        assert!(
            missing
                .coverage
                .unresolved
                .iter()
                .any(|reason| reason.contains(PUSH_LEASE_CONSTANT_PATH))
        );

        let misidentified = lift_relay_ingest(
            fixture_inputs_with_handlers(
                &source,
                KIND_SOURCE,
                PUSH_LEASE_SOURCE,
                "#[path = \"other.rs\"]\npub mod push_lease;\npub mod ingest;\n",
            ),
            &fixture_protocol(),
            "fixture",
            "revision",
        )
        .expect("misidentified push source remains visible");
        assert_eq!(
            misidentified.coverage.completeness,
            NativeCompleteness::Partial
        );
    }

    #[test]
    fn attributed_or_effectful_kind_predicates_make_scope_partial() {
        let attributed_kind = KIND_SOURCE.replace(
            "pub const fn is_moderation_command_kind",
            "#[cfg(feature = \"moderation\")]\npub const fn is_moderation_command_kind",
        );
        let attributed_protocol =
            lift_job_protocol(&attributed_kind, "fixture", "kind.rs", "revision")
                .expect("attributed protocol fixture lifts");
        let attributed = lift_relay_ingest(
            fixture_inputs(INGEST_SOURCE, &attributed_kind, PUSH_LEASE_SOURCE),
            &attributed_protocol,
            "fixture",
            "revision",
        )
        .expect("attributed predicate remains visible");
        assert_eq!(
            attributed.coverage.completeness,
            NativeCompleteness::Partial
        );

        let effectful_kind = KIND_SOURCE.replace(
            "    matches!(kind, KIND_MODERATION_BAN)",
            "    observe(kind);\n    matches!(kind, KIND_MODERATION_BAN)",
        );
        let effectful_protocol =
            lift_job_protocol(&effectful_kind, "fixture", "kind.rs", "revision")
                .expect("effectful protocol fixture lifts");
        let effectful = lift_relay_ingest(
            fixture_inputs(INGEST_SOURCE, &effectful_kind, PUSH_LEASE_SOURCE),
            &effectful_protocol,
            "fixture",
            "revision",
        )
        .expect("effectful predicate remains visible");
        assert_eq!(effectful.coverage.completeness, NativeCompleteness::Partial);
    }

    fn assert_unproven_gate_is_partial(source: &str, expected_reason: &str) {
        let lift = lift_relay_ingest(
            fixture_inputs(source, KIND_SOURCE, PUSH_LEASE_SOURCE),
            &fixture_protocol(),
            "fixture",
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

    fn assert_unproven_compilation_is_partial(inputs: RelayInputs<'_>, expected_reason: &str) {
        let lift = lift_relay_ingest(inputs, &fixture_protocol(), "fixture", "revision")
            .expect("unproven compilation remains visible as a partial lift");

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
    fn canonical_event_parameter_requires_the_pinned_foreign_type() {
        let source = INGEST_SOURCE.replace(
            "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
            "async fn ingest_event_inner(kind_u32: u32, event: AltEvent) -> Result<(), Error> {",
        );

        assert_unproven_gate_is_partial(&source, "does not resolve exactly to `nostr::Event`");
    }

    #[test]
    fn alternate_event_imports_make_type_resolution_unproven() {
        let source = INGEST_SOURCE.replace("use nostr::Event;", "use spoofed::Event;");

        assert_unproven_gate_is_partial(&source, "does not resolve exactly");
    }

    #[test]
    fn local_event_aliases_make_type_resolution_unproven() {
        let source = INGEST_SOURCE.replace("use nostr::Event;", "type Event = nostr::Event;");

        assert_unproven_gate_is_partial(&source, "does not resolve exactly");
    }

    #[test]
    fn same_name_generic_event_types_make_resolution_unproven() {
        let source = INGEST_SOURCE.replace(
            "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
            "async fn ingest_event_inner<Event>(kind_u32: u32, event: Event) -> Result<(), Error> {",
        );

        assert_unproven_gate_is_partial(&source, "does not resolve exactly to `nostr::Event`");
    }

    #[test]
    fn conditional_event_imports_make_type_resolution_unproven() {
        let source = INGEST_SOURCE.replace(
            "use nostr::Event;",
            "#[cfg(feature = \"alternate\")]\nuse nostr::Event;",
        );

        assert_unproven_gate_is_partial(&source, "does not resolve exactly");
    }

    #[test]
    fn local_nostr_modules_do_not_prove_the_foreign_event_type() {
        let source = INGEST_SOURCE
            .replace("use nostr::Event;", "mod nostr { pub struct Event; }")
            .replace("event: &Event", "event: &nostr::Event")
            .replace("event: Event", "event: nostr::Event");

        assert_unproven_gate_is_partial(&source, "does not resolve exactly");
    }

    #[test]
    fn unexpanded_item_macros_make_event_type_resolution_unproven() {
        let source = INGEST_SOURCE.replace(
            "use nostr::Event;",
            "make_nostr_module!();\nuse nostr::Event;",
        );

        assert_unproven_gate_is_partial(&source, "does not resolve exactly");
    }

    #[test]
    fn scope_event_parameter_requires_the_pinned_foreign_type() {
        let source = INGEST_SOURCE.replace("event: &Event", "event: &AltEvent");

        assert_unproven_gate_is_partial(&source, "does not resolve exactly to `&nostr::Event`");
    }

    #[test]
    fn qualified_foreign_event_types_remain_exhaustive() {
        let source = INGEST_SOURCE
            .replace("use nostr::Event;\n", "")
            .replace("event: &Event", "event: &nostr::Event")
            .replace("event: Event", "event: nostr::Event");
        let lift = lift_relay_ingest(
            fixture_inputs(&source, KIND_SOURCE, PUSH_LEASE_SOURCE),
            &fixture_protocol(),
            "fixture",
            "revision",
        )
        .expect("qualified nostr::Event fixture lifts");

        assert_eq!(lift.coverage.completeness, NativeCompleteness::Exhaustive);
        assert!(lift.coverage.unresolved.is_empty());
    }

    #[test]
    fn destructured_kind_shadows_are_not_treated_as_the_incoming_kind() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "let (kind_u32,) = (KIND_MESSAGE,);\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "shadowed through an unproven pattern");
    }

    #[test]
    fn destructured_event_shadows_cannot_supply_the_gate_event() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "let (event,) = (other_event,);\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "event binding is shadowed");
    }

    #[test]
    fn arbitrary_direct_event_rebindings_cannot_supply_the_gate_event() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "let event = other_event;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "event binding is shadowed");
    }

    #[test]
    fn local_scope_helper_aliases_make_resolution_unproven() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "let required_scope_for_kind = accepting;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "shadows modeled helper");
    }

    #[test]
    fn local_kind_helper_aliases_make_resolution_unproven() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "let event_kind_u32 = spoofed_kind;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "shadows modeled helper");
    }

    #[test]
    fn local_validation_helper_aliases_make_resolution_unproven() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "let verify_event = persist_before_gate;\n    verify_event(&event)?;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "shadows modeled helper");
    }

    #[test]
    fn local_helper_imports_make_resolution_unproven() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "use spoofed::verify_event;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "shadows modeled helper");
    }

    #[test]
    fn helper_named_parameters_make_resolution_unproven() {
        let source = INGEST_SOURCE.replace(
            "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
            "async fn ingest_event_inner(kind_u32: u32, event: Event, verify_event: VerifyFn) -> Result<(), Error> {",
        );

        assert_unproven_gate_is_partial(&source, "shadows modeled helper");
    }

    #[test]
    fn module_kind_aliases_make_resolution_unproven() {
        let source = INGEST_SOURCE
            .replace(
                "fn required_scope_for_kind",
                "use spoofed::event_kind_u32;\n\nfn required_scope_for_kind",
            )
            .replace(
                "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
                "async fn ingest_event_inner(event: Event) -> Result<(), Error> {\n    let kind_u32 = event_kind_u32(&event);",
            );

        assert_unproven_gate_is_partial(&source, "pinned module-level resolution");
    }

    #[test]
    fn module_validation_aliases_make_resolution_unproven() {
        let source = INGEST_SOURCE
            .replace(
                "fn required_scope_for_kind",
                "use spoofed::verify_event;\n\nfn required_scope_for_kind",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "verify_event(&event)?;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "pinned module-level resolution");
    }

    #[test]
    fn local_qualified_path_aliases_make_resolution_unproven() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "use spoofed as tokio;\n    tokio::task::spawn_blocking(|| persist_before_gate()).await?;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "shadows modeled helper");
    }

    #[test]
    fn module_qualified_path_aliases_make_resolution_unproven() {
        let source = INGEST_SOURCE
            .replace(
                "fn required_scope_for_kind",
                "use spoofed as tokio;\n\nfn required_scope_for_kind",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "tokio::task::spawn_blocking(|| persist_before_gate()).await?;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "pinned module-level resolution");
    }

    #[test]
    fn local_macro_aliases_make_resolution_unproven() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "use spoofed::debug;\n    debug!(event_id = % event_id_hex, kind = kind_u32, \"ingest_event\");\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "shadows modeled helper");
    }

    #[test]
    fn nested_local_helper_aliases_make_resolution_unproven() {
        let source = INGEST_SOURCE
            .replace(
                "fn required_scope_for_kind",
                "use buzz_core::verification::verify_event;\n\nfn required_scope_for_kind",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "{\n        let verify_event = persist_before_gate;\n        verify_event(&event)?;\n    }\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "shadows modeled helper");
    }

    #[test]
    fn qualified_modeled_macro_names_are_not_accepted() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "spoofed::format!(\"invalid: {e}\");\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "macro `format!`");
    }

    #[test]
    fn modeled_format_arguments_cannot_use_nested_shadowed_receivers() {
        let source = INGEST_SOURCE
            .replace(
                "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
                "async fn ingest_event_inner(kind_u32: u32, event: Event, attacker: EvilEvent) -> Result<(), Error> {",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "const MAX_EVENT_CONTENT_BYTES: usize = 256 * 1024;\n    {\n        let event = attacker;\n        format!(\"invalid: content exceeds maximum size of {} bytes (got {})\", MAX_EVENT_CONTENT_BYTES, event.content.len());\n    }\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "macro binding `event` is shadowed");
    }

    #[test]
    fn modeled_format_captures_require_verification_error_arms() {
        let source = INGEST_SOURCE
            .replace(
                "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
                "async fn ingest_event_inner(kind_u32: u32, event: Event, attacker: EvilDisplay) -> Result<(), Error> {",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "{\n        let e = attacker;\n        format!(\"invalid: {e}\");\n    }\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "outside the pinned verification-result match");
    }

    #[test]
    fn verification_pattern_spelling_does_not_prove_a_spoofed_result() {
        let source = INGEST_SOURCE
            .replace(
                "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
                "async fn ingest_event_inner(kind_u32: u32, event: Event, attacker: EvilResult) -> Result<(), Error> {",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "let verify_result = attacker;\n    match verify_result {\n        Ok(Err(e)) => { format!(\"invalid: {e}\"); },\n        _ => {},\n    }\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "no pinned verification-result origin");
    }

    #[test]
    fn modeled_kind_captures_cannot_use_nested_shadows() {
        let source = INGEST_SOURCE
            .replace(
                "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
                "async fn ingest_event_inner(kind_u32: u32, event: Event, attacker: EvilDisplay) -> Result<(), Error> {",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "{\n        let kind_u32 = attacker;\n        format!(\"invalid: kind {kind_u32} is only accepted via WebSocket\");\n    }\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "macro binding `kind_u32` is shadowed");
    }

    #[test]
    fn modeled_debug_fields_cannot_use_nested_shadows() {
        let source = INGEST_SOURCE
            .replace(
                "fn required_scope_for_kind",
                "use tracing::debug;\n\nfn required_scope_for_kind",
            )
            .replace(
                "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
                "async fn ingest_event_inner(kind_u32: u32, event: Event, attacker: EvilDisplay) -> Result<(), Error> {\n    let event_id_hex = event.id.to_hex();",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "{\n        let event_id_hex = attacker;\n        debug!(event_id = %event_id_hex, kind = kind_u32, \"ingest_event\");\n    }\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "macro binding `event_id_hex` is shadowed");
    }

    #[test]
    fn modeled_method_receivers_cannot_be_shadowed() {
        let source = INGEST_SOURCE
            .replace(
                "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
                "async fn ingest_event_inner(kind_u32: u32, event: Event, tenant: Tenant, attacker: EvilTenant) -> Result<(), Error> {",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "let tenant = attacker;\n    tenant.community();\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "receiver `tenant` is shadowed");
    }

    #[test]
    fn modeled_auth_receivers_cannot_be_shadowed() {
        let source = INGEST_SOURCE
            .replace(
                "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
                "async fn ingest_event_inner(kind_u32: u32, event: Event, auth: IngestAuth, attacker: IngestAuth) -> Result<(), Error> {",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "let auth = attacker;\n    auth.is_http();\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "receiver `auth` is shadowed");
    }

    #[test]
    fn modeled_arc_receiver_requires_the_pinned_rebinding_origin() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "(*arc).clone();\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "no pinned event-rebinding origin");
    }

    #[test]
    fn arc_new_does_not_prove_an_unrelated_arc_receiver() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "let event = std::sync::Arc::new(event);\n    (*arc).clone();\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "no pinned event-rebinding origin");
    }

    #[test]
    fn modeled_error_receiver_names_cannot_collide_with_parameters() {
        let source = INGEST_SOURCE
            .replace(
                "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
                "async fn ingest_event_inner(kind_u32: u32, event: Event, msg: Error) -> Result<(), Error> {",
            )
            .replace(
                "Err(error) => return Err(error.into()),",
                "Err(msg) => return Err(msg.into()),",
            );

        assert_unproven_gate_is_partial(&source, "receiver `msg` is shadowed by an input");
    }

    #[test]
    fn module_macro_aliases_make_resolution_unproven() {
        let source = INGEST_SOURCE
            .replace(
                "fn required_scope_for_kind",
                "use spoofed::debug;\n\nfn required_scope_for_kind",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "debug!(event_id = % event_id_hex, kind = kind_u32, \"ingest_event\");\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "pinned module-level resolution");
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
    fn qualified_scope_helpers_are_not_the_proven_top_level_gate() {
        let source = INGEST_SOURCE.replace(
            "required_scope_for_kind(kind_u32, &event)",
            "accepting::required_scope_for_kind(kind_u32, &event)",
        );

        assert_unproven_gate_is_partial(&source, "not a direct top-level terminating match gate");
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
    fn spawn_blocking_function_pointers_are_not_modeled_callbacks() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "tokio::task::spawn_blocking(persist_before_gate).await?;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "call `tokio::task::spawn_blocking`");
    }

    #[test]
    fn exact_spawn_closures_require_the_pinned_result_statement() {
        let source = INGEST_SOURCE
            .replace(
                "fn required_scope_for_kind",
                "use buzz_core::verification::verify_event;\n\nfn required_scope_for_kind",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "let event = std::sync::Arc::new(event);\n    let event_for_verify = std::sync::Arc::clone(&event);\n    let other = tokio::task::spawn_blocking(move || verify_event(&event_for_verify)).await;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(
            &source,
            "outside the pinned verification-result statement",
        );
    }

    #[test]
    fn verification_callbacks_require_the_pinned_capture_origin() {
        let source = INGEST_SOURCE
            .replace(
                "fn required_scope_for_kind",
                "use buzz_core::verification::verify_event;\n\nfn required_scope_for_kind",
            )
            .replace(
                "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
                "async fn ingest_event_inner(kind_u32: u32, event: Event, alternate: AlternateEvent) -> Result<(), Error> {",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "let event_for_verify = alternate;\n    let verify_result = tokio::task::spawn_blocking(move || verify_event(&event_for_verify)).await;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "does not have one preceding pinned");
    }

    #[test]
    fn verification_callbacks_require_a_preceding_capture_binding() {
        let source = INGEST_SOURCE
            .replace(
                "fn required_scope_for_kind",
                "use buzz_core::verification::verify_event;\n\nfn required_scope_for_kind",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "let verify_result = tokio::task::spawn_blocking(move || verify_event(&event_for_verify)).await;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "does not have one preceding pinned");
    }

    #[test]
    fn verification_capture_bindings_after_the_callback_do_not_count() {
        let source = INGEST_SOURCE
            .replace(
                "fn required_scope_for_kind",
                "use buzz_core::verification::verify_event;\n\nfn required_scope_for_kind",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "let verify_result = tokio::task::spawn_blocking(move || verify_event(&event_for_verify)).await;\n    let event_for_verify = std::sync::Arc::clone(&event);\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "does not have one preceding pinned");
    }

    #[test]
    fn verification_callbacks_require_the_exact_move_closure_header() {
        let source = INGEST_SOURCE
            .replace(
                "fn required_scope_for_kind",
                "use buzz_core::verification::verify_event;\n\nfn required_scope_for_kind",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "let event = std::sync::Arc::new(event);\n    let event_for_verify = std::sync::Arc::clone(&event);\n    let verify_result = tokio::task::spawn_blocking(|| verify_event(&event_for_verify)).await;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "call `tokio::task::spawn_blocking`");
    }

    #[test]
    fn verification_callbacks_reject_repeated_capture_bindings() {
        let source = INGEST_SOURCE
            .replace(
                "fn required_scope_for_kind",
                "use buzz_core::verification::verify_event;\n\nfn required_scope_for_kind",
            )
            .replace(
                "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
                "async fn ingest_event_inner(kind_u32: u32, event: Event, alternate: AlternateEvent) -> Result<(), Error> {",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "let event = std::sync::Arc::new(event);\n    let event_for_verify = std::sync::Arc::clone(&event);\n    let event_for_verify = alternate;\n    let verify_result = tokio::task::spawn_blocking(move || verify_event(&event_for_verify)).await;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "does not have one preceding pinned");
    }

    #[test]
    fn verification_callbacks_reject_nested_capture_shadows() {
        let source = INGEST_SOURCE
            .replace(
                "fn required_scope_for_kind",
                "use buzz_core::verification::verify_event;\n\nfn required_scope_for_kind",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "let event = std::sync::Arc::new(event);\n    let event_for_verify = std::sync::Arc::clone(&event);\n    { let event_for_verify = std::sync::Arc::clone(&event); }\n    let verify_result = tokio::task::spawn_blocking(move || verify_event(&event_for_verify)).await;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "does not have one preceding pinned");
    }

    #[test]
    fn verification_capture_clone_requires_the_canonical_event_binding() {
        let source = INGEST_SOURCE
            .replace(
                "fn required_scope_for_kind",
                "use buzz_core::verification::verify_event;\n\nfn required_scope_for_kind",
            )
            .replace(
                "async fn ingest_event_inner(kind_u32: u32, event: Event) -> Result<(), Error> {",
                "async fn ingest_event_inner(kind_u32: u32, event: Event, alternate: Event) -> Result<(), Error> {",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "let event = std::sync::Arc::new(event);\n    { let event = std::sync::Arc::new(alternate); }\n    let event_for_verify = std::sync::Arc::clone(&event);\n    let verify_result = tokio::task::spawn_blocking(move || verify_event(&event_for_verify)).await;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );

        assert_unproven_gate_is_partial(&source, "does not have one preceding pinned");
    }

    #[test]
    fn pinned_verification_callback_and_capture_origin_remain_exhaustive() {
        let source = INGEST_SOURCE
            .replace(
                "fn required_scope_for_kind",
                "use buzz_core::verification::verify_event;\n\nfn required_scope_for_kind",
            )
            .replace(
                "let required = match required_scope_for_kind(kind_u32, &event) {",
                "let event = std::sync::Arc::new(event);\n    let event_for_verify = std::sync::Arc::clone(&event);\n    let verify_result = tokio::task::spawn_blocking(move || verify_event(&event_for_verify)).await;\n    let required = match required_scope_for_kind(kind_u32, &event) {",
            );
        let lift = lift_relay_ingest(
            fixture_inputs(&source, KIND_SOURCE, PUSH_LEASE_SOURCE),
            &fixture_protocol(),
            "fixture",
            "revision",
        )
        .expect("pinned verification callback still lifts");

        assert_eq!(lift.coverage.completeness, NativeCompleteness::Exhaustive);
        assert!(lift.coverage.unresolved.is_empty());
    }

    #[test]
    fn unwrap_or_else_function_pointers_are_not_modeled_callbacks() {
        let source = INGEST_SOURCE.replace(
            "let required = match required_scope_for_kind(kind_u32, &event) {",
            "let _ = std::sync::Arc::try_unwrap(attacker_arc).unwrap_or_else(persist_before_gate);\n    let required = match required_scope_for_kind(kind_u32, &event) {",
        );

        assert_unproven_gate_is_partial(&source, "method call `unwrap_or_else`");
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
            fixture_inputs(&source, KIND_SOURCE, PUSH_LEASE_SOURCE),
            &fixture_protocol(),
            "fixture",
            "revision",
        )
        .expect_err("scope helper effects outside the match must fail closed");

        assert_eq!(error, LiftError::MissingScopeMatch);
    }

    #[test]
    fn mismatched_protocol_source_is_rejected() {
        let error = lift_relay_ingest(
            fixture_inputs(
                INGEST_SOURCE,
                &KIND_SOURCE.replace("43001", "43002"),
                PUSH_LEASE_SOURCE,
            ),
            &fixture_protocol(),
            "fixture",
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
        assert_eq!(
            lift.push_lease_source.sha256,
            "sha256:297f7f59a7e141cdd5acf3a2ba6395ed4a34035050fab4d17d698d043b389ce0"
        );
        assert_eq!(
            lift.push_lease_constant
                .as_ref()
                .expect("push lease declaration is pinned")
                .line_start,
            18
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
        assert_eq!(lift.coverage.included_artifacts.len(), 11);
        assert_eq!(lift.compilation.sources.len(), 8);
        assert_eq!(lift.compilation.package_edges.len(), 2);
        assert_eq!(lift.compilation.module_edges.len(), 4);
        assert_eq!(lift.compilation.locked_dependencies.len(), 1);
    }
}
