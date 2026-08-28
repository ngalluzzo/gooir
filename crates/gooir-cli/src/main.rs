//! `gooir` — one way in.
//!
//! The command inspects installed packages and emits provider-neutral plans.
//! Its temporary `derive` subcommand remains a visibly separate compatibility
//! bridge for legacy declaration packs and process plugins.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read as _,
    num::{NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
    process,
};

use gooir_artifact_sdk::{
    Admitted, ContentFile, ContentPath, ContentSet, LocalPublisher, ManagedOutput, ManagedOutputId,
    PublicationReceipt, content_set_contract,
};
use gooir_capability::authority::{AdmissionPolicy, ObservationAuthority, SourceObservation};
use gooir_capability::protocol::{EvidenceDigest, EvidenceKindId, EvidenceRef};
use gooir_capability::strict_json;
use gooir_capability::{
    Answer as LegacyAnswer, CapabilityId, CapabilityRegistry,
    DerivationRequest as LegacyDerivationRequest, Fact, FactInstance, FactType, PortName,
    RequestRefusal, register_pack,
};
use gooir_cli::{known_value_kinds, resolve_value_kind};
use gooir_derive::{
    Answer as CompileAnswer, CompilerDriver, DerivationLimits, LocalAttesterBinding,
    LocalStdioHost, LocalStdioLimits, Refusal,
};
use gooir_package::{LoadLimits, PackageRegistry, load_local_package};
use gooir_planning::{PlanLimits, RouteOutputRef, SemanticPlanner};
use gooir_toolchain::{InstalledToolchain, ToolchainLimits};
use rustix::fs::{Mode, OFlags, open};
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

const USAGE: &str = "\
gooir — compile and build over an explicitly installed capability graph

Compiler driver (GOOIR 0.1):
  gooir compile <target> --package DIR --policy JSON [--observation JSON]
      [--attester JSON] --stdin-bytes N --stdout-bytes N --stderr-bytes N
      --timeout-ms N [--json]

Managed admitted artifact build:
  gooir build <capability> <output-port> --toolchain DIR --source PATH
      [--source PATH] [--observation JSON] --source-authority JSON --policy JSON
      --output DIR --output-id NAME@VERSION --stdin-bytes N --stdout-bytes N
      --stderr-bytes N --timeout-ms N [--json]

The compile command admits explicit source observations, conservatively fixes
one complete route/offer/attester selection, invokes exact copied package
artifacts over bounded local stdio, independently assesses every candidate,
and admits each step before linking the next. Provider artifacts come only
from installed offers. Each attester binding names a complete authority plus
an exact installed package resource with the same copied digest. N must be
positive for every bound. Nothing is scanned, resolved through PATH, or
materialized to a target-specific file. JSON output is the existing derivation
Answer shape, not a new stable compile receipt protocol.
Policy, observation, and attester inputs must be regular files: no symlinks,
FIFOs, or directories. Each is bounded to 16 MiB and their aggregate to
64 MiB before JSON decoding.

The build command frames the explicitly named source files as one portable
ContentSet observation, derives one exact capability output from an installed
toolchain, resolves that output through the same admission ledger, and then
publishes it as one managed directory. Source PATH is both the local path and
the portable content path, so it must be relative and portable. Source bytes
use evidence kind org.gooi.cli.evidence/raw-file-sha256@1.0.0, whose digest is
SHA-256 over the exact file bytes. The explicit source authority must name that
evidence kind and the ContentSet value kind, and the policy must accept it.
The authority is still a caller-supplied untrusted claim; the CLI does not
claim it measured or executed the named observer. The named output must itself
be ContentSet. No backend, dialect parser, or executable is discovered.

Package inspection and planning (GOOIR 0.1):
  gooir facts --package DIR                 every value kind and its producers
  gooir capabilities --package DIR          every promise and exact offer
  gooir needs --package DIR                 promises with no implementation offer
  gooir doctor --package DIR                installed package-graph health
  gooir plan <target> --package DIR         complete provider-neutral graph slice

Repeat --package DIR to install explicit org.gooi.package/v1 directories in
dependency order. Nothing is discovered or installed implicitly. Planning
does not select a route, implementation, attester, or execution transport.

Legacy execution compatibility bridge (not the GOOIR 0.1 host boundary):
  gooir derive <target> --from FACT --pack MANIFEST [--plugin MANIFEST]

The compatibility bridge accepts repeatable legacy --pack and --plugin inputs.
It does not execute org.gooi.package/v1 offers. It is not a universal provider
transport. FACT is a serialized legacy FactInstance JSON document.

A target may be a full value-kind identity or an unambiguous bare name.";

/// Installation inputs are named by the caller, never discovered. Scanning a
/// directory for declarations or programs would make the active graph depend
/// on ambient filesystem state and turn provider loading into a supply-chain
/// hole.
fn value_paths(args: &[String], flag: &str) -> Vec<PathBuf> {
    args.iter()
        .enumerate()
        .filter(|(_, argument)| argument.as_str() == flag)
        .filter_map(|(i, _)| args.get(i + 1))
        .map(PathBuf::from)
        .collect()
}

fn planning_limits() -> PlanLimits {
    let graph = NonZeroUsize::new(4_096).expect("constant is nonzero");
    let aggregate = NonZeroUsize::new(16_384).expect("constant is nonzero");
    PlanLimits {
        max_capabilities: graph,
        max_value_kinds: graph,
        max_ports_per_capability: graph,
        max_total_ports: aggregate,
        max_offers_per_capability: graph,
        max_total_offers: aggregate,
    }
}

fn derivation_limits() -> DerivationLimits {
    let request = NonZeroUsize::new(4_096).expect("constant is nonzero");
    DerivationLimits {
        planning: planning_limits(),
        max_inputs: request,
        max_attesters: request,
    }
}

const MAX_COMPILE_PACKAGES: usize = 4_096;
const MAX_COMPILE_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_COMPILE_TOTAL_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;
const RAW_FILE_EVIDENCE_PACKAGE: &str = "org.gooi.cli.evidence";
const RAW_FILE_EVIDENCE_NAME: &str = "raw-file-sha256";
const RAW_FILE_EVIDENCE_VERSION: &str = "1.0.0";

#[derive(Clone, Copy, Debug)]
struct CompileInputLimits {
    max_packages: usize,
    max_observations: usize,
    max_attesters: usize,
    max_documents: usize,
    max_document_bytes: u64,
    max_total_document_bytes: u64,
}

fn compile_input_limits() -> CompileInputLimits {
    let derivation = derivation_limits();
    CompileInputLimits {
        max_packages: MAX_COMPILE_PACKAGES,
        max_observations: derivation.max_inputs.get(),
        max_attesters: derivation.max_attesters.get(),
        max_documents: derivation
            .max_inputs
            .get()
            .saturating_add(derivation.max_attesters.get())
            .saturating_add(1),
        max_document_bytes: MAX_COMPILE_DOCUMENT_BYTES,
        max_total_document_bytes: MAX_COMPILE_TOTAL_DOCUMENT_BYTES,
    }
}

#[derive(Debug)]
struct CompileArguments {
    target: String,
    packages: Vec<PathBuf>,
    policy: PathBuf,
    observations: Vec<PathBuf>,
    attesters: Vec<PathBuf>,
    stdio_limits: LocalStdioLimits,
    input_limits: CompileInputLimits,
    json: bool,
}

#[derive(Debug)]
struct BuildArguments {
    target: RouteOutputRef,
    toolchain: PathBuf,
    sources: Vec<PathBuf>,
    policy: PathBuf,
    source_authority: PathBuf,
    observations: Vec<PathBuf>,
    output: ManagedOutput,
    stdio_limits: LocalStdioLimits,
    input_limits: CompileInputLimits,
    json: bool,
}

impl BuildArguments {
    fn parse(args: &[String], input_limits: CompileInputLimits) -> Result<Self, String> {
        input_limits.validate_for("build")?;
        let capability = CapabilityId::parse(
            args.get(1)
                .filter(|value| !value.starts_with("--"))
                .ok_or_else(|| {
                    "usage: gooir build <capability> <output-port> --toolchain DIR --source PATH"
                        .to_owned()
                })?,
        )
        .map_err(|error| format!("invalid build capability: {error}"))?;
        let output_port = PortName::parse(
            args.get(2)
                .filter(|value| !value.starts_with("--"))
                .ok_or_else(|| {
                    "usage: gooir build <capability> <output-port> --toolchain DIR --source PATH"
                        .to_owned()
                })?
                .clone(),
        )
        .map_err(|error| format!("invalid build output port: {error}"))?;
        let mut toolchain = None;
        let mut sources = Vec::new();
        let mut policy = None;
        let mut source_authority = None;
        let mut observations = Vec::new();
        let mut output = None;
        let mut output_id = None;
        let mut stdin_bytes = None;
        let mut stdout_bytes = None;
        let mut stderr_bytes = None;
        let mut timeout_milliseconds = None;
        let mut json = false;
        let mut index = 3;

        while let Some(argument) = args.get(index) {
            match argument.as_str() {
                "--toolchain" => set_once_for(
                    &mut toolchain,
                    flag_path_for(args, &mut index, "build", "--toolchain")?,
                    "build",
                    "--toolchain",
                )?,
                "--source" => {
                    ensure_path_slot_for(
                        sources.len(),
                        input_limits.max_observations,
                        "build",
                        "source files",
                    )?;
                    sources.push(flag_path_for(args, &mut index, "build", "--source")?);
                }
                "--policy" => set_once_for(
                    &mut policy,
                    flag_path_for(args, &mut index, "build", "--policy")?,
                    "build",
                    "--policy",
                )?,
                "--source-authority" => set_once_for(
                    &mut source_authority,
                    flag_path_for(args, &mut index, "build", "--source-authority")?,
                    "build",
                    "--source-authority",
                )?,
                "--observation" => {
                    ensure_path_slot_for(
                        observations.len(),
                        input_limits.max_observations.saturating_sub(1),
                        "build",
                        "observation documents",
                    )?;
                    observations.push(flag_path_for(args, &mut index, "build", "--observation")?);
                }
                "--output" => set_once_for(
                    &mut output,
                    flag_path_for(args, &mut index, "build", "--output")?,
                    "build",
                    "--output",
                )?,
                "--output-id" => set_once_for(
                    &mut output_id,
                    ManagedOutputId::parse(flag_value_for(
                        args,
                        &mut index,
                        "build",
                        "--output-id",
                    )?)
                    .map_err(|error| error.to_string())?,
                    "build",
                    "--output-id",
                )?,
                "--stdin-bytes" => set_once_for(
                    &mut stdin_bytes,
                    positive_usize_value(
                        "--stdin-bytes",
                        flag_value_for(args, &mut index, "build", "--stdin-bytes")?,
                    )?,
                    "build",
                    "--stdin-bytes",
                )?,
                "--stdout-bytes" => set_once_for(
                    &mut stdout_bytes,
                    positive_usize_value(
                        "--stdout-bytes",
                        flag_value_for(args, &mut index, "build", "--stdout-bytes")?,
                    )?,
                    "build",
                    "--stdout-bytes",
                )?,
                "--stderr-bytes" => set_once_for(
                    &mut stderr_bytes,
                    positive_usize_value(
                        "--stderr-bytes",
                        flag_value_for(args, &mut index, "build", "--stderr-bytes")?,
                    )?,
                    "build",
                    "--stderr-bytes",
                )?,
                "--timeout-ms" => set_once_for(
                    &mut timeout_milliseconds,
                    positive_u64_value(
                        "--timeout-ms",
                        flag_value_for(args, &mut index, "build", "--timeout-ms")?,
                    )?,
                    "build",
                    "--timeout-ms",
                )?,
                "--json" if !json => {
                    json = true;
                    index += 1;
                }
                "--json" => return Err("gooir build accepts --json exactly once".to_owned()),
                unknown if unknown.starts_with("--") => {
                    return Err(format!("unknown gooir build flag `{unknown}`"));
                }
                positional => {
                    return Err(format!(
                        "unexpected extra gooir build argument `{positional}`"
                    ));
                }
            }
        }
        if sources.is_empty() {
            return Err("gooir build requires at least one --source".to_owned());
        }
        let output = ManagedOutput::new(
            required_for(output_id, "build", "--output-id")?,
            required_for(output, "build", "--output")?,
        )
        .map_err(|error| error.to_string())?;
        Ok(Self {
            target: RouteOutputRef {
                capability,
                output_port,
                extensions: Default::default(),
            },
            toolchain: required_for(toolchain, "build", "--toolchain")?,
            sources,
            policy: required_for(policy, "build", "--policy")?,
            source_authority: required_for(source_authority, "build", "--source-authority")?,
            observations,
            output,
            stdio_limits: LocalStdioLimits {
                max_stdin_bytes: required_for(stdin_bytes, "build", "--stdin-bytes")?,
                max_stdout_bytes: required_for(stdout_bytes, "build", "--stdout-bytes")?,
                max_stderr_bytes: required_for(stderr_bytes, "build", "--stderr-bytes")?,
                timeout_milliseconds: required_for(timeout_milliseconds, "build", "--timeout-ms")?,
            },
            input_limits,
            json,
        })
    }
}

impl CompileArguments {
    fn parse(args: &[String], input_limits: CompileInputLimits) -> Result<Self, String> {
        input_limits.validate()?;
        let target = args
            .get(1)
            .filter(|value| !value.starts_with("--"))
            .ok_or_else(|| "usage: gooir compile <target>".to_owned())?
            .clone();
        let mut packages = Vec::new();
        let mut policy = None;
        let mut observations = Vec::new();
        let mut attesters = Vec::new();
        let mut stdin_bytes = None;
        let mut stdout_bytes = None;
        let mut stderr_bytes = None;
        let mut timeout_milliseconds = None;
        let mut json = false;
        let mut index = 2;

        while let Some(argument) = args.get(index) {
            match argument.as_str() {
                "--package" => {
                    ensure_path_slot(packages.len(), input_limits.max_packages, "package paths")?;
                    packages.push(flag_path(args, &mut index, "--package")?);
                }
                "--policy" => set_once(
                    &mut policy,
                    flag_path(args, &mut index, "--policy")?,
                    "--policy",
                )?,
                "--observation" => {
                    ensure_document_slot(&observations, &attesters, input_limits)?;
                    ensure_path_slot(
                        observations.len(),
                        input_limits.max_observations,
                        "observation documents",
                    )?;
                    observations.push(flag_path(args, &mut index, "--observation")?);
                }
                "--attester" => {
                    ensure_document_slot(&observations, &attesters, input_limits)?;
                    ensure_path_slot(
                        attesters.len(),
                        input_limits.max_attesters,
                        "attester documents",
                    )?;
                    attesters.push(flag_path(args, &mut index, "--attester")?);
                }
                "--stdin-bytes" => set_once(
                    &mut stdin_bytes,
                    positive_usize_value(
                        "--stdin-bytes",
                        flag_value(args, &mut index, "--stdin-bytes")?,
                    )?,
                    "--stdin-bytes",
                )?,
                "--stdout-bytes" => set_once(
                    &mut stdout_bytes,
                    positive_usize_value(
                        "--stdout-bytes",
                        flag_value(args, &mut index, "--stdout-bytes")?,
                    )?,
                    "--stdout-bytes",
                )?,
                "--stderr-bytes" => set_once(
                    &mut stderr_bytes,
                    positive_usize_value(
                        "--stderr-bytes",
                        flag_value(args, &mut index, "--stderr-bytes")?,
                    )?,
                    "--stderr-bytes",
                )?,
                "--timeout-ms" => set_once(
                    &mut timeout_milliseconds,
                    positive_u64_value(
                        "--timeout-ms",
                        flag_value(args, &mut index, "--timeout-ms")?,
                    )?,
                    "--timeout-ms",
                )?,
                "--json" if !json => {
                    json = true;
                    index += 1;
                }
                "--json" => return Err("gooir compile accepts --json exactly once".to_owned()),
                unknown if unknown.starts_with("--") => {
                    return Err(format!("unknown gooir compile flag `{unknown}`"));
                }
                positional => {
                    return Err(format!(
                        "unexpected extra gooir compile argument `{positional}`"
                    ));
                }
            }
        }

        Ok(Self {
            target,
            packages,
            policy: required(policy, "--policy")?,
            observations,
            attesters,
            stdio_limits: LocalStdioLimits {
                max_stdin_bytes: required(stdin_bytes, "--stdin-bytes")?,
                max_stdout_bytes: required(stdout_bytes, "--stdout-bytes")?,
                max_stderr_bytes: required(stderr_bytes, "--stderr-bytes")?,
                timeout_milliseconds: required(timeout_milliseconds, "--timeout-ms")?,
            },
            input_limits,
            json,
        })
    }
}

impl CompileInputLimits {
    fn validate(self) -> Result<(), String> {
        self.validate_for("compile")
    }

    fn validate_for(self, command: &str) -> Result<(), String> {
        if self.max_packages == 0
            || self.max_observations == 0
            || self.max_attesters == 0
            || self.max_documents == 0
            || self.max_document_bytes == 0
            || self.max_total_document_bytes == 0
        {
            return Err(format!("gooir {command} resource limits must be positive"));
        }
        Ok(())
    }
}

fn flag_value<'args>(
    args: &'args [String],
    index: &mut usize,
    flag: &str,
) -> Result<&'args str, String> {
    flag_value_for(args, index, "compile", flag)
}

fn flag_value_for<'args>(
    args: &'args [String],
    index: &mut usize,
    command: &str,
    flag: &str,
) -> Result<&'args str, String> {
    let value = args
        .get(index.saturating_add(1))
        .filter(|value| !value.starts_with("--"))
        .ok_or_else(|| format!("gooir {command} flag {flag} requires a value"))?;
    *index += 2;
    Ok(value)
}

fn flag_path(args: &[String], index: &mut usize, flag: &str) -> Result<PathBuf, String> {
    flag_value(args, index, flag).map(PathBuf::from)
}

fn flag_path_for(
    args: &[String],
    index: &mut usize,
    command: &str,
    flag: &str,
) -> Result<PathBuf, String> {
    flag_value_for(args, index, command, flag).map(PathBuf::from)
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), String> {
    set_once_for(slot, value, "compile", flag)
}

fn set_once_for<T>(
    slot: &mut Option<T>,
    value: T,
    command: &str,
    flag: &str,
) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("gooir {command} accepts {flag} exactly once"));
    }
    Ok(())
}

fn required<T>(value: Option<T>, flag: &str) -> Result<T, String> {
    required_for(value, "compile", flag)
}

fn required_for<T>(value: Option<T>, command: &str, flag: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("gooir {command} requires {flag}"))
}

fn ensure_path_slot(current: usize, limit: usize, resource: &str) -> Result<(), String> {
    ensure_path_slot_for(current, limit, "compile", resource)
}

fn ensure_path_slot_for(
    current: usize,
    limit: usize,
    command: &str,
    resource: &str,
) -> Result<(), String> {
    if current >= limit {
        return Err(format!("gooir {command} {resource} exceed limit {limit}"));
    }
    Ok(())
}

fn ensure_document_slot(
    observations: &[PathBuf],
    attesters: &[PathBuf],
    limits: CompileInputLimits,
) -> Result<(), String> {
    let current = observations
        .len()
        .checked_add(attesters.len())
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| "gooir compile document count overflowed".to_owned())?;
    if current >= limits.max_documents {
        return Err(format!(
            "gooir compile documents exceed aggregate count limit {}",
            limits.max_documents
        ));
    }
    Ok(())
}

fn positive_usize_value(flag: &str, value: &str) -> Result<NonZeroUsize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("{flag} must be a positive integer"))?;
    NonZeroUsize::new(parsed).ok_or_else(|| format!("{flag} must be positive"))
}

fn positive_u64_value(flag: &str, value: &str) -> Result<NonZeroU64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{flag} must be a positive integer"))?;
    NonZeroU64::new(parsed).ok_or_else(|| format!("{flag} must be positive"))
}

fn installed_packages(package_directories: &[PathBuf]) -> Result<PackageRegistry, String> {
    let mut registry = PackageRegistry::default();
    for directory in package_directories {
        let package = load_local_package(directory, &registry, LoadLimits::default())
            .map_err(|error| format!("{}: {error}", directory.display()))?;
        registry
            .install(package)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
    }
    Ok(registry)
}

fn installed_legacy(packs: &[PathBuf], plugins: &[PathBuf]) -> Result<CapabilityRegistry, String> {
    let mut registry = CapabilityRegistry::default();
    for path in packs {
        let manifest =
            fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
        register_pack(&mut registry, &manifest)
            .map_err(|error| format!("{}: {error}", path.display()))?;
    }
    for path in plugins {
        let provider = gooir_plugin_process::ProcessProvider::load(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        eprintln!(
            "plugin {} -> {} (digest covers {} file(s))",
            provider.manifest().provider,
            provider.manifest().capability,
            provider.covered_files()
        );
        registry
            .register_provider(provider)
            .map_err(|error| format!("{}: {error}", path.display()))?;
    }
    Ok(registry)
}

fn reject_flags(args: &[String], flags: &[&str], context: &str) -> Result<(), String> {
    if let Some(flag) = flags
        .iter()
        .find(|flag| args.iter().any(|argument| argument == **flag))
    {
        return Err(format!("{context} does not accept {flag}\n\n{USAGE}"));
    }
    Ok(())
}

fn legacy_value_kinds(registry: &CapabilityRegistry) -> Vec<FactType> {
    registry
        .specs()
        .flat_map(|specification| {
            specification
                .input_ports
                .iter()
                .map(|port| port.value_kind.clone())
                .chain(
                    specification
                        .output_ports
                        .iter()
                        .map(|port| port.value_kind.clone()),
                )
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn resolve_legacy_value_kind(
    registry: &CapabilityRegistry,
    wanted: &str,
) -> Result<FactType, String> {
    let value_kinds = legacy_value_kinds(registry);
    if let Some(exact) = value_kinds
        .iter()
        .find(|value_kind| value_kind.to_string() == wanted)
    {
        return Ok(exact.clone());
    }
    let matches = value_kinds
        .iter()
        .filter(|value_kind| value_kind.name == wanted)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(format!("no legacy fact type named `{wanted}`")),
        many => Err(format!(
            "legacy fact type `{wanted}` is ambiguous; name one exactly:\n  {}",
            many.iter()
                .map(|value_kind| value_kind.to_string())
                .collect::<Vec<_>>()
                .join("\n  ")
        )),
    }
}

fn input_fact(path: &PathBuf) -> Result<FactInstance, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
}

/// Renders an answer that produced nothing, and says what to do about it.
///
/// Every branch ends in the answer's own remedy rather than a message written
/// here, so a new variant cannot be rendered as a bare failure.
fn print_answer(target: &FactType, given: &LegacyAnswer) {
    match given {
        LegacyAnswer::Produced(_) => unreachable!("rendered by the caller"),
        LegacyAnswer::Blocked(plan) => {
            println!("cannot derive {target} yet:");
            for need in &plan.needs {
                println!("  need {}", need.specification.id);
            }
        }
        LegacyAnswer::Unreachable(error) => println!("no route to {target}: {error}"),
        LegacyAnswer::Refused(RequestRefusal::AmbiguousInput(fact)) => {
            println!("refused: two inputs both declare {fact}");
        }
        LegacyAnswer::Refused(RequestRefusal::LegacyAdapterRepeatedInputKind {
            capability,
            value_kind,
        }) => println!(
            "refused: legacy adapter cannot bind repeated input kind {value_kind} for {capability}"
        ),
        LegacyAnswer::Refused(RequestRefusal::LegacyAdapterRepeatedOutputKind {
            capability,
            value_kind,
        }) => println!(
            "refused: legacy adapter cannot bind repeated output kind {value_kind} for {capability}"
        ),
        LegacyAnswer::Failed(error) => {
            println!("legacy execution failed deriving {target}: {error}");
        }
    }
    println!("\n-> {}", given.remedy());
}

struct DocumentBudget {
    limits: CompileInputLimits,
    command: &'static str,
    documents: usize,
    bytes: u64,
}

impl DocumentBudget {
    fn new(limits: CompileInputLimits) -> Result<Self, String> {
        Self::for_command(limits, "compile")
    }

    fn for_command(limits: CompileInputLimits, command: &'static str) -> Result<Self, String> {
        if limits.max_documents == 0
            || limits.max_document_bytes == 0
            || limits.max_total_document_bytes == 0
        {
            return Err(format!("gooir {command} document limits must be positive"));
        }
        Ok(Self {
            limits,
            command,
            documents: 0,
            bytes: 0,
        })
    }

    fn read(&mut self, path: &Path) -> Result<Vec<u8>, String> {
        if self.documents == self.limits.max_documents {
            return Err(format!(
                "{}: aggregate document count exceeds {}",
                path.display(),
                self.limits.max_documents
            ));
        }
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|error| format!("{}: document open failed: {error}", path.display()))?;
        let mut file = File::from(descriptor);
        let metadata = file
            .metadata()
            .map_err(|error| format!("{}: document metadata failed: {error}", path.display()))?;
        if !metadata.is_file() {
            return Err(format!(
                "{}: {} input must be a regular file",
                path.display(),
                self.command
            ));
        }
        let size = metadata.len();
        if size > self.limits.max_document_bytes {
            return Err(format!(
                "{}: document size {size} exceeds per-document limit {}",
                path.display(),
                self.limits.max_document_bytes
            ));
        }
        let aggregate_remaining = self
            .limits
            .max_total_document_bytes
            .checked_sub(self.bytes)
            .ok_or_else(|| format!("gooir {} aggregate document bytes overflowed", self.command))?;
        if size > aggregate_remaining {
            return Err(format!(
                "{}: document size {size} exceeds remaining aggregate limit {aggregate_remaining}",
                path.display()
            ));
        }

        let effective_limit = self.limits.max_document_bytes.min(aggregate_remaining);
        let capacity = usize::try_from(size.min(effective_limit))
            .map_err(|_| format!("{}: document is too large for this host", path.display()))?;
        let mut bytes = Vec::with_capacity(capacity);
        file.by_ref()
            .take(effective_limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| format!("{}: document read failed: {error}", path.display()))?;
        let actual = u64::try_from(bytes.len())
            .map_err(|_| format!("{}: document is too large for this host", path.display()))?;
        if actual > self.limits.max_document_bytes {
            return Err(format!(
                "{}: document exceeds per-document limit {}",
                path.display(),
                self.limits.max_document_bytes
            ));
        }
        if actual > aggregate_remaining {
            return Err(format!(
                "{}: document exceeds aggregate byte limit {}",
                path.display(),
                self.limits.max_total_document_bytes
            ));
        }
        self.documents += 1;
        self.bytes = self
            .bytes
            .checked_add(actual)
            .ok_or_else(|| format!("gooir {} aggregate document bytes overflowed", self.command))?;
        Ok(bytes)
    }
}

fn read_compile_document<T: DeserializeOwned>(
    path: &Path,
    budget: &mut DocumentBudget,
) -> Result<T, String> {
    let bytes = budget.read(path)?;
    strict_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))
}

fn raw_file_evidence_kind() -> EvidenceKindId {
    EvidenceKindId::new(
        RAW_FILE_EVIDENCE_PACKAGE,
        RAW_FILE_EVIDENCE_NAME,
        RAW_FILE_EVIDENCE_VERSION,
    )
}

fn raw_evidence_digest(bytes: &[u8]) -> EvidenceDigest {
    EvidenceDigest::parse(format!("sha256:{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 output is an exact evidence digest")
}

fn source_content_observation(
    source_root: &Path,
    paths: &[PathBuf],
    authority: ObservationAuthority,
    budget: &mut DocumentBudget,
) -> Result<SourceObservation, String> {
    authority
        .validate()
        .map_err(|error| format!("source authority is invalid: {error}"))?;
    if authority.value_kind != content_set_contract() {
        return Err(format!(
            "source authority value kind must be {}, found {}",
            content_set_contract(),
            authority.value_kind
        ));
    }
    let evidence_kind = raw_file_evidence_kind();
    if authority.evidence_kind != evidence_kind {
        return Err(format!(
            "source authority evidence kind must be {evidence_kind}, found {}",
            authority.evidence_kind
        ));
    }
    if !authority.extensions.is_empty() {
        return Err("source authority contains unsupported extensions".to_owned());
    }

    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let path_text = path
            .to_str()
            .ok_or_else(|| format!("{}: source path is not UTF-8", path.display()))?;
        ContentPath::parse(path_text).map_err(|error| format!("{}: {error}", path.display()))?;
        let content = budget.read(&source_root.join(path))?;
        files.push(
            ContentFile::new(path_text, content)
                .map_err(|error| format!("{}: {error}", path.display()))?,
        );
    }
    let content = ContentSet::new(files).map_err(|error| error.to_string())?;
    let mut evidence = content
        .files
        .iter()
        .map(|file| {
            EvidenceRef::new(
                evidence_kind.clone(),
                raw_evidence_digest(&file.content),
                file.path.as_str(),
                Default::default(),
            )
            .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter();
    let primary_evidence = evidence
        .next()
        .ok_or_else(|| "gooir build requires at least one source file".to_owned())?;
    let fact = Fact::new(
        content_set_contract(),
        serde_json::to_value(content).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    SourceObservation::new(
        fact,
        authority,
        primary_evidence,
        evidence.collect(),
        Default::default(),
    )
    .map_err(|error| error.to_string())
}

fn preflight_content_set_target(
    registry: &PackageRegistry,
    target: &RouteOutputRef,
) -> Result<(), String> {
    let specification = registry
        .capabilities()
        .find_map(|(_package, specification)| {
            (specification.id == target.capability).then_some(specification)
        })
        .ok_or_else(|| {
            format!(
                "build target capability {} is not installed",
                target.capability
            )
        })?;
    let output = specification
        .output_ports
        .iter()
        .find(|output| output.name == target.output_port)
        .ok_or_else(|| {
            format!(
                "build target capability {} has no output port {}",
                target.capability, target.output_port
            )
        })?;
    let expected = content_set_contract();
    if output.value_kind != expected {
        return Err(format!(
            "build target {}/{} produces {}, not {expected}",
            target.capability, target.output_port, output.value_kind
        ));
    }
    Ok(())
}

fn print_publication_receipt(receipt: &PublicationReceipt) {
    println!("published admitted ContentSet {}", receipt.source.fact_id);
    println!("  authority {}", receipt.source.authority_record_id);
    println!("  output {}", receipt.output_id);
    println!("  destination {}", receipt.destination);
    println!("  manifest {}", receipt.manifest_id);
    println!("  outcome {:?}", receipt.outcome);
    println!("  synchronization {:?}", receipt.sync);
    println!("  cleanup {:?}", receipt.cleanup);
    println!("\n-> use the managed files and retain the publication receipt");
}

fn render_committed_receipt(receipt: &PublicationReceipt, json: bool) {
    if !json {
        print_publication_receipt(receipt);
        return;
    }
    match receipt.to_canonical_json() {
        Ok(bytes) => println!("{}", String::from_utf8_lossy(&bytes)),
        Err(error) => {
            // Publication has already committed. A receipt-rendering invariant
            // cannot safely be presented as a retryable build failure.
            eprintln!(
                "warning: publication committed, but canonical receipt rendering failed: {error}"
            );
            print_publication_receipt(receipt);
        }
    }
}

fn run_build(build: BuildArguments) -> Result<(), String> {
    let installed = InstalledToolchain::load(&build.toolchain, ToolchainLimits::default())
        .map_err(|error| format!("{}: {error}", build.toolchain.display()))?;
    preflight_content_set_target(installed.registry(), &build.target)?;

    let mut budget = DocumentBudget::for_command(build.input_limits, "build")?;
    let policy = read_compile_document::<AdmissionPolicy>(&build.policy, &mut budget)?;
    let source_authority =
        read_compile_document::<ObservationAuthority>(&build.source_authority, &mut budget)?;
    let source = source_content_observation(
        Path::new("."),
        &build.sources,
        source_authority,
        &mut budget,
    )?;
    let mut observations = Vec::with_capacity(build.observations.len().saturating_add(1));
    observations.push(source);
    for path in &build.observations {
        observations.push(read_compile_document::<SourceObservation>(
            path,
            &mut budget,
        )?);
    }

    let host = LocalStdioHost::new(
        installed.registry(),
        installed.local_attester_bindings().iter().cloned(),
        build.stdio_limits,
    )
    .map_err(|error| error.to_string())?;
    let authorities = host.authorities().cloned().collect::<Vec<_>>();
    let mut driver = CompilerDriver::new(
        installed.registry(),
        policy,
        authorities,
        host,
        derivation_limits(),
    )
    .map_err(|error| error.to_string())?;
    let answer = driver.compile_output(build.target, observations);
    let produced = match answer {
        CompileAnswer::Produced(produced) => produced,
        other => {
            if build.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&other).map_err(|error| error.to_string())?
                );
            } else {
                print_compile_answer(&other);
            }
            process::exit(match other {
                CompileAnswer::Blocked(_) => 3,
                CompileAnswer::Produced(_) => unreachable!("handled above"),
                CompileAnswer::Unreachable(_)
                | CompileAnswer::Refused(_)
                | CompileAnswer::Failed(_) => 1,
            });
        }
    };
    let admitted = Admitted::<ContentSet>::resolve(driver.ledger(), &produced.target).map_err(
        |error| {
            format!(
                "admitted build target {} under authority {} is not a publishable ContentSet: {error}",
                produced.target.fact_id, produced.target.authority_record_id
            )
        },
    )?;
    let receipt = LocalPublisher::default()
        .publish(&admitted, &build.output)
        .map_err(|error| {
            format!(
                "admitted ContentSet {} under authority {} was not published: {error}",
                produced.target.fact_id, produced.target.authority_record_id
            )
        })?;
    render_committed_receipt(&receipt, build.json);
    Ok(())
}

fn print_compile_answer(answer: &CompileAnswer) {
    match answer {
        CompileAnswer::Produced(produced) => {
            println!("produced admitted target {}", produced.target.fact_id);
            println!("  authority {}", produced.target.authority_record_id);
            println!("  admitted {} route output(s)", produced.admitted.len());
        }
        CompileAnswer::Blocked(blocked) => {
            println!("blocked plan {}", blocked.plan.plan_id);
            for node in &blocked.blockage.nodes {
                if node.missing_offer {
                    println!("  missing implementation for {}", node.capability);
                }
                for need in &node.missing_attesters {
                    println!(
                        "  missing independent attester for {} / {}",
                        need.capability, need.suite
                    );
                }
            }
        }
        CompileAnswer::Unreachable(unreachable) => {
            if let Some(target) = &unreachable.target_output {
                println!(
                    "unreachable target {}/{}",
                    target.capability, target.output_port
                );
            } else {
                println!("unreachable target {}", unreachable.target);
            }
        }
        CompileAnswer::Refused(refusal) => match refusal.as_ref() {
            Refusal::InvalidRequest { detail }
            | Refusal::InvalidSelection { detail }
            | Refusal::AmbiguousSelection { detail, .. }
            | Refusal::AdmissionPolicy { detail, .. } => println!("refused: {detail}"),
        },
        CompileAnswer::Failed(failed) => {
            println!("failed at {:?}: {}", failed.stage, failed.detail);
        }
    }
    println!("\n-> {}", answer.remedy());
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str);

    match command {
        None | Some("-h") | Some("--help") | Some("help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some("facts") => {
            reject_flags(
                &args,
                &["--pack", "--plugin"],
                "GOOIR 0.1 package inspection",
            )?;
            let registry = installed_packages(&value_paths(&args, "--package"))?;
            let value_kinds = known_value_kinds(&registry);
            println!("{} value kind(s)\n", value_kinds.len());
            for value_kind in &value_kinds {
                let producers: Vec<String> = registry
                    .capabilities()
                    .filter(|(_package, specification)| {
                        specification
                            .output_ports
                            .iter()
                            .any(|port| &port.value_kind == value_kind)
                    })
                    .map(|(_package, specification)| specification.id.to_string())
                    .collect();
                let how = if producers.is_empty() {
                    "supplied by you".to_owned()
                } else {
                    format!("via {}", producers.join(" | "))
                };
                println!("  {value_kind}\n      {how}");
            }
            Ok(())
        }
        Some("compile") => {
            let compile = CompileArguments::parse(&args, compile_input_limits())?;
            let registry = installed_packages(&compile.packages)?;
            let target = resolve_value_kind(&registry, &compile.target)?;
            let mut budget = DocumentBudget::new(compile.input_limits)?;
            let policy = read_compile_document::<AdmissionPolicy>(&compile.policy, &mut budget)?;
            let mut observations = Vec::with_capacity(compile.observations.len());
            for path in &compile.observations {
                observations.push(read_compile_document::<SourceObservation>(
                    path,
                    &mut budget,
                )?);
            }
            let mut bindings = Vec::with_capacity(compile.attesters.len());
            for path in &compile.attesters {
                bindings.push(read_compile_document::<LocalAttesterBinding>(
                    path,
                    &mut budget,
                )?);
            }
            let host = LocalStdioHost::new(&registry, bindings, compile.stdio_limits)
                .map_err(|error| error.to_string())?;
            let authorities = host.authorities().cloned().collect::<Vec<_>>();
            let mut driver =
                CompilerDriver::new(&registry, policy, authorities, host, derivation_limits())
                    .map_err(|error| error.to_string())?;
            let answer = driver.compile(target, observations);
            if compile.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&answer).map_err(|error| error.to_string())?
                );
            } else {
                print_compile_answer(&answer);
            }
            match answer {
                CompileAnswer::Produced(_) => Ok(()),
                CompileAnswer::Blocked(_) => process::exit(3),
                CompileAnswer::Unreachable(_)
                | CompileAnswer::Refused(_)
                | CompileAnswer::Failed(_) => process::exit(1),
            }
        }
        Some("build") => run_build(BuildArguments::parse(&args, compile_input_limits())?),
        Some("capabilities") => {
            reject_flags(
                &args,
                &["--pack", "--plugin"],
                "GOOIR 0.1 package inspection",
            )?;
            let registry = installed_packages(&value_paths(&args, "--package"))?;
            println!(
                "{} capability(ies), {} exact offer(s)\n",
                registry.capabilities().count(),
                registry.offers().count()
            );
            for (package, specification) in registry.capabilities() {
                let offers = registry
                    .offers()
                    .filter(|offer| offer.capability == specification.id)
                    .collect::<Vec<_>>();
                let mark = if offers.is_empty() { "NEED" } else { "have" };
                println!("  {mark}  {}", specification.id);
                println!("          package {package}");
                for port in &specification.input_ports {
                    println!(
                        "          <- {}: {} ({:?})",
                        port.name, port.value_kind, port.acceptance
                    );
                }
                for port in &specification.output_ports {
                    println!("          -> {}: {}", port.name, port.value_kind);
                }
                for offer in offers {
                    println!(
                        "          offer {} ({})",
                        offer.offer_id, offer.implementation
                    );
                }
            }
            Ok(())
        }
        Some("needs") => {
            reject_flags(
                &args,
                &["--pack", "--plugin"],
                "GOOIR 0.1 package diagnostics",
            )?;
            let registry = installed_packages(&value_paths(&args, "--package"))?;
            let report = gooir_doctor::diagnose(&registry, planning_limits())
                .map_err(|error| error.to_string())?;
            if report.unimplemented.is_empty() {
                println!("no open needs: every capability has an implementation offer");
                return Ok(());
            }
            println!("{} open need(s)\n", report.unimplemented.len());
            for need in &report.unimplemented {
                println!("  {}", need.capability);
                println!("    package  {}", need.package);
                for p in &need.produces {
                    println!("    produces {p}");
                }
                println!("    suite    {}", need.conformance_suite);
            }
            println!("\nEach is assignable: an exact promise a provider can be given.");
            Ok(())
        }
        Some("doctor") => {
            reject_flags(
                &args,
                &["--pack", "--plugin"],
                "GOOIR 0.1 package diagnostics",
            )?;
            let registry = installed_packages(&value_paths(&args, "--package"))?;
            let report = gooir_doctor::diagnose(&registry, planning_limits())
                .map_err(|error| error.to_string())?;
            println!("{report}");
            if report.blocking() > 0 {
                process::exit(2);
            }
            Ok(())
        }
        Some("plan") => {
            reject_flags(
                &args,
                &["--pack", "--plugin"],
                "GOOIR 0.1 semantic planning",
            )?;
            let registry = installed_packages(&value_paths(&args, "--package"))?;
            let wanted = args.get(1).ok_or("usage: gooir plan <target>")?;
            let target = resolve_value_kind(&registry, wanted)?;
            let limits = planning_limits();
            let roots = gooir_doctor::diagnose(&registry, limits)
                .map_err(|error| error.to_string())?
                .roots
                .into_iter()
                .map(|root| root.value_kind)
                .collect::<Vec<_>>();
            let planner = SemanticPlanner::from_registry(&registry, limits)
                .map_err(|error| error.to_string())?;
            let plan = planner
                .plan(roots, target.clone())
                .map_err(|error| error.to_string())?;
            println!("provider-neutral plan {}", plan.plan_id);
            println!("target {target}");
            for planned in &plan.capabilities {
                if planned.offers.is_empty() {
                    println!("  NEED  {}", planned.specification.id);
                } else {
                    println!("  have  {}", planned.specification.id);
                    for offer in &planned.offers {
                        println!(
                            "        offer {} ({})",
                            offer.offer_id, offer.implementation
                        );
                    }
                }
            }
            println!("\nNo route or implementation was selected.");
            Ok(())
        }
        Some("derive") => {
            reject_flags(
                &args,
                &["--package"],
                "the legacy derive compatibility bridge",
            )?;
            eprintln!(
                "warning: `gooir derive` is the legacy compatibility bridge; it does not execute GOOIR 0.1 package offers"
            );
            let registry = installed_legacy(
                &value_paths(&args, "--pack"),
                &value_paths(&args, "--plugin"),
            )?;
            let wanted = args
                .get(1)
                .ok_or("usage: gooir derive <target> --from FACT")?;
            let sources = value_paths(&args, "--from");
            if sources.is_empty() {
                return Err("usage: gooir derive <target> --from FACT".to_owned());
            }
            let target = resolve_legacy_value_kind(&registry, wanted)?;
            let request = LegacyDerivationRequest {
                target: target.clone(),
                inputs: sources
                    .iter()
                    .map(input_fact)
                    .collect::<Result<Vec<_>, _>>()?,
            };
            // One call, and every outcome comes back as an answer. The CLI
            // renders; it no longer decides what counts as a failure.
            let given = gooir_capability::answer(&registry, &request);
            let json = args.iter().any(|a| a == "--json");
            match &given {
                LegacyAnswer::Produced(report) => {
                    println!("{target}");
                    println!("  id       {}", report.target.id);
                    println!("  coverage {:?}", report.target.coverage);
                    println!("  chain    {} fact(s)", report.facts.len());
                    println!();
                    // Payload meaning belongs to its ecosystem. The neutral
                    // CLI renders the exact JSON and never guesses presentation
                    // semantics from coincidental field names.
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report.target.payload).unwrap_or_default()
                    );
                    Ok(())
                }
                other => {
                    if json {
                        // There is no payload to show, so the answer itself is
                        // the document — the same one that rides a request.
                        println!(
                            "{}",
                            serde_json::to_string_pretty(other).unwrap_or_default()
                        );
                    } else {
                        print_answer(&target, other);
                    }
                    process::exit(match other {
                        LegacyAnswer::Blocked(_) => 3,
                        _ => 1,
                    });
                }
            }
        }
        Some(other) => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gooir_capability::authority::ObservationSourceId;
    use gooir_capability::protocol::{ArtifactDigest, ImplementationId};
    use gooir_capability::{FactCoverage, FactType};
    use nix::sys::stat::Mode as NixMode;
    use nix::unistd::mkfifo;
    use std::os::unix::fs::symlink;

    const PACK: &str = r#"{
      "protocol": "org.gooi.pack/v2",
      "capabilities": [{
        "id": "test.capability/copy@1.0.0",
        "input_ports": [{
          "name": "source",
          "value_kind": "test.value/source@1.0.0",
          "acceptance": "complete_only"
        }],
        "output_ports": [{
          "name": "result",
          "value_kind": "test.value/result@1.0.0"
        }],
        "default_conformance_suite": "test.conformance/copy@1.0.0"
      }]
    }"#;

    #[test]
    fn legacy_installation_is_empty_until_a_pack_is_named() {
        let empty = installed_legacy(&[], &[]).unwrap();
        assert_eq!(empty.specs().count(), 0);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pack.json");
        fs::write(&path, PACK).unwrap();
        let explicit = installed_legacy(&[path], &[]).unwrap();
        assert_eq!(explicit.specs().count(), 1);
    }

    #[test]
    fn help_separates_package_planning_from_legacy_execution() {
        assert!(USAGE.contains("Compiler driver (GOOIR 0.1)"));
        assert!(USAGE.contains("Managed admitted artifact build"));
        assert!(USAGE.contains("gooir build <capability> <output-port>"));
        assert!(USAGE.contains("org.gooi.cli.evidence/raw-file-sha256@1.0.0"));
        assert!(USAGE.contains("caller-supplied untrusted claim"));
        assert!(USAGE.contains("exact copied package"));
        assert!(USAGE.contains("N must be\npositive"));
        assert!(USAGE.contains("not a new stable compile receipt protocol"));
        assert!(USAGE.contains("Package inspection and planning (GOOIR 0.1)"));
        assert!(USAGE.contains("--package DIR"));
        assert!(USAGE.contains("Legacy execution compatibility bridge"));
        assert!(USAGE.contains("not a universal provider"));
    }

    #[test]
    fn modern_and_legacy_installation_flags_cannot_be_mixed() {
        let modern = vec!["facts".to_owned(), "--pack".to_owned()];
        assert!(
            reject_flags(&modern, &["--pack", "--plugin"], "modern")
                .unwrap_err()
                .contains("does not accept --pack")
        );

        let legacy = vec!["derive".to_owned(), "--package".to_owned()];
        assert!(
            reject_flags(&legacy, &["--package"], "legacy")
                .unwrap_err()
                .contains("does not accept --package")
        );
    }

    #[test]
    fn repeated_installation_and_input_flags_keep_caller_order() {
        let args = vec![
            "derive".to_owned(),
            "result".to_owned(),
            "--pack".to_owned(),
            "one.json".to_owned(),
            "--from".to_owned(),
            "first.json".to_owned(),
            "--pack".to_owned(),
            "two.json".to_owned(),
            "--from".to_owned(),
            "second.json".to_owned(),
        ];
        assert_eq!(
            value_paths(&args, "--pack"),
            [PathBuf::from("one.json"), PathBuf::from("two.json")]
        );
        assert_eq!(
            value_paths(&args, "--from"),
            [PathBuf::from("first.json"), PathBuf::from("second.json")]
        );
    }

    fn compile_args() -> Vec<String> {
        [
            "compile",
            "test.value/target@1.0.0",
            "--package",
            "package",
            "--policy",
            "policy.json",
            "--observation",
            "observation.json",
            "--attester",
            "attester.json",
            "--stdin-bytes",
            "1024",
            "--stdout-bytes",
            "2048",
            "--stderr-bytes",
            "512",
            "--timeout-ms",
            "1000",
        ]
        .map(str::to_owned)
        .to_vec()
    }

    fn build_args() -> Vec<String> {
        [
            "build",
            "test.generator/rust@1.0.0",
            "files",
            "--toolchain",
            "toolchain",
            "--source",
            "specs/api.bin",
            "--source-authority",
            "source-authority.json",
            "--policy",
            "policy.json",
            "--observation",
            "context.json",
            "--output",
            "generated",
            "--output-id",
            "test.generated@1.0.0",
            "--stdin-bytes",
            "1024",
            "--stdout-bytes",
            "2048",
            "--stderr-bytes",
            "512",
            "--timeout-ms",
            "1000",
        ]
        .map(str::to_owned)
        .to_vec()
    }

    fn observation_authority() -> ObservationAuthority {
        ObservationAuthority::new(
            ObservationSourceId::new("test.source", "files", "1.0.0"),
            ImplementationId::new("test.observer", "files", "1.0.0"),
            ArtifactDigest::parse(format!("sha256:{}", "a".repeat(64))).unwrap(),
            content_set_contract(),
            raw_file_evidence_kind(),
            Default::default(),
        )
        .unwrap()
    }

    fn test_input_limits(
        max_document_bytes: u64,
        max_total_document_bytes: u64,
    ) -> CompileInputLimits {
        CompileInputLimits {
            max_packages: 4,
            max_observations: 4,
            max_attesters: 4,
            max_documents: 9,
            max_document_bytes,
            max_total_document_bytes,
        }
    }

    #[test]
    fn compile_grammar_is_closed_and_limits_are_positive_singletons() {
        let parsed = CompileArguments::parse(&compile_args(), compile_input_limits()).unwrap();
        assert_eq!(parsed.packages, [PathBuf::from("package")]);
        assert_eq!(parsed.observations, [PathBuf::from("observation.json")]);
        assert_eq!(parsed.attesters, [PathBuf::from("attester.json")]);
        assert_eq!(parsed.stdio_limits.max_stdin_bytes.get(), 1024);
        assert_eq!(parsed.stdio_limits.max_stdout_bytes.get(), 2048);
        assert_eq!(parsed.stdio_limits.max_stderr_bytes.get(), 512);
        assert_eq!(parsed.stdio_limits.timeout_milliseconds.get(), 1000);

        let mut trailing_attester = compile_args();
        trailing_attester.push("--attester".to_owned());
        assert!(
            CompileArguments::parse(&trailing_attester, compile_input_limits())
                .unwrap_err()
                .contains("--attester requires a value")
        );

        let mut unknown = compile_args();
        unknown.push("--unknown".to_owned());
        assert!(
            CompileArguments::parse(&unknown, compile_input_limits())
                .unwrap_err()
                .contains("unknown gooir compile flag")
        );

        let mut positional = compile_args();
        positional.push("extra".to_owned());
        assert!(
            CompileArguments::parse(&positional, compile_input_limits())
                .unwrap_err()
                .contains("unexpected extra gooir compile argument")
        );

        let mut duplicate = compile_args();
        duplicate.extend(["--timeout-ms".to_owned(), "2".to_owned()]);
        assert!(
            CompileArguments::parse(&duplicate, compile_input_limits())
                .unwrap_err()
                .contains("--timeout-ms exactly once")
        );

        let mut zero = compile_args();
        let timeout = zero
            .iter()
            .position(|value| value == "--timeout-ms")
            .unwrap();
        zero[timeout + 1] = "0".to_owned();
        assert!(
            CompileArguments::parse(&zero, compile_input_limits())
                .unwrap_err()
                .contains("--timeout-ms must be positive")
        );
    }

    #[test]
    fn build_grammar_names_one_exact_output_and_closes_every_host_input() {
        let parsed = BuildArguments::parse(&build_args(), compile_input_limits()).unwrap();
        assert_eq!(
            parsed.target.capability,
            CapabilityId::new("test.generator", "rust", "1.0.0")
        );
        assert_eq!(parsed.target.output_port, PortName::parse("files").unwrap());
        assert_eq!(parsed.toolchain, PathBuf::from("toolchain"));
        assert_eq!(parsed.sources, [PathBuf::from("specs/api.bin")]);
        assert_eq!(parsed.observations, [PathBuf::from("context.json")]);
        assert_eq!(parsed.output.id().as_str(), "test.generated@1.0.0");
        assert_eq!(parsed.output.destination(), Path::new("generated"));
        assert_eq!(parsed.stdio_limits.max_stdin_bytes.get(), 1024);
        assert_eq!(parsed.stdio_limits.max_stdout_bytes.get(), 2048);
        assert_eq!(parsed.stdio_limits.max_stderr_bytes.get(), 512);
        assert_eq!(parsed.stdio_limits.timeout_milliseconds.get(), 1000);

        let mut slash_port = build_args();
        slash_port[2] = "generated/files".to_owned();
        assert_eq!(
            BuildArguments::parse(&slash_port, compile_input_limits())
                .unwrap()
                .target
                .output_port,
            PortName::parse("generated/files").unwrap()
        );

        for removed in [
            "--toolchain",
            "--source",
            "--source-authority",
            "--policy",
            "--output",
            "--output-id",
            "--stdin-bytes",
            "--stdout-bytes",
            "--stderr-bytes",
            "--timeout-ms",
        ] {
            let mut missing = build_args();
            let position = missing.iter().position(|value| value == removed).unwrap();
            missing.drain(position..=position + 1);
            let error = BuildArguments::parse(&missing, compile_input_limits()).unwrap_err();
            assert!(
                error.contains(if removed == "--source" {
                    "at least one --source"
                } else {
                    removed
                }),
                "{removed}: {error}"
            );
        }

        let mut duplicate = build_args();
        duplicate.extend(["--output".to_owned(), "elsewhere".to_owned()]);
        assert!(
            BuildArguments::parse(&duplicate, compile_input_limits())
                .unwrap_err()
                .contains("accepts --output exactly once")
        );
        let mut unknown = build_args();
        unknown.push("--package".to_owned());
        assert!(
            BuildArguments::parse(&unknown, compile_input_limits())
                .unwrap_err()
                .contains("unknown gooir build flag `--package`")
        );
        let mut positional = build_args();
        positional.push("extra".to_owned());
        assert!(
            BuildArguments::parse(&positional, compile_input_limits())
                .unwrap_err()
                .contains("unexpected extra gooir build argument")
        );
    }

    #[test]
    fn build_source_framing_is_binary_safe_canonical_and_authority_exact() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("specs")).unwrap();
        fs::write(directory.path().join("specs/z.bin"), [0, 255, 4]).unwrap();
        fs::write(directory.path().join("specs/a.bin"), b"alpha").unwrap();
        let paths = [PathBuf::from("specs/z.bin"), PathBuf::from("specs/a.bin")];
        let mut budget =
            DocumentBudget::for_command(test_input_limits(1024, 4096), "build").unwrap();

        let observation = source_content_observation(
            directory.path(),
            &paths,
            observation_authority(),
            &mut budget,
        )
        .unwrap();

        assert_eq!(observation.fact.value_kind, content_set_contract());
        let content: ContentSet = serde_json::from_value(observation.fact.payload.clone()).unwrap();
        assert_eq!(
            content
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            ["specs/a.bin", "specs/z.bin"]
        );
        assert_eq!(content.files[0].content, b"alpha");
        assert_eq!(content.files[1].content, [0, 255, 4]);
        assert_eq!(observation.primary_evidence.locator, "specs/a.bin");
        assert_eq!(
            observation.primary_evidence.digest,
            raw_evidence_digest(b"alpha")
        );
        assert_eq!(observation.additional_evidence.len(), 1);
        assert_eq!(observation.additional_evidence[0].locator, "specs/z.bin");

        let mut wrong_kind = observation_authority();
        wrong_kind.value_kind = FactType::new("test.wrong", "kind", "1.0.0");
        let error = source_content_observation(
            directory.path(),
            &paths,
            wrong_kind,
            &mut DocumentBudget::for_command(test_input_limits(1024, 4096), "build").unwrap(),
        )
        .unwrap_err();
        assert!(error.contains("value kind must be"), "{error}");

        let mut wrong_evidence = observation_authority();
        wrong_evidence.evidence_kind = EvidenceKindId::new("test.evidence", "other", "1.0.0");
        let error = source_content_observation(
            directory.path(),
            &paths,
            wrong_evidence,
            &mut DocumentBudget::for_command(test_input_limits(1024, 4096), "build").unwrap(),
        )
        .unwrap_err();
        assert!(error.contains("evidence kind must be"), "{error}");

        let mut extended = observation_authority();
        extended
            .extensions
            .insert("test.future/meaning".to_owned(), serde_json::json!(true));
        assert!(
            source_content_observation(
                directory.path(),
                &paths,
                extended,
                &mut DocumentBudget::for_command(test_input_limits(1024, 4096), "build").unwrap(),
            )
            .unwrap_err()
            .contains("unsupported extensions")
        );
    }

    #[test]
    fn build_source_reads_refuse_nonportable_and_nonregular_inputs_before_observation() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("regular"), b"value").unwrap();
        symlink("regular", directory.path().join("link")).unwrap();
        fs::create_dir(directory.path().join("nested")).unwrap();
        let fifo = directory.path().join("fifo");
        mkfifo(&fifo, NixMode::S_IRUSR | NixMode::S_IWUSR).unwrap();

        for (path, expected) in [
            ("../regular", "not a portable relative content path"),
            ("link", "document open failed"),
            ("nested", "build input must be a regular file"),
            ("fifo", "build input must be a regular file"),
        ] {
            let error = source_content_observation(
                directory.path(),
                &[PathBuf::from(path)],
                observation_authority(),
                &mut DocumentBudget::for_command(test_input_limits(1024, 4096), "build").unwrap(),
            )
            .unwrap_err();
            assert!(error.contains(expected), "{path}: {error}");
        }
    }

    #[test]
    fn compile_grammar_rejects_path_counts_before_accepting_excess_values() {
        let mut package_limited = compile_input_limits();
        package_limited.max_packages = 1;
        let mut packages = compile_args();
        packages.extend(["--package".to_owned(), "second-package".to_owned()]);
        assert!(
            CompileArguments::parse(&packages, package_limited)
                .unwrap_err()
                .contains("package paths exceed limit 1")
        );

        let mut observation_limited = compile_input_limits();
        observation_limited.max_observations = 1;
        let mut observations = compile_args();
        observations.extend(["--observation".to_owned(), "second.json".to_owned()]);
        assert!(
            CompileArguments::parse(&observations, observation_limited)
                .unwrap_err()
                .contains("observation documents exceed limit 1")
        );

        let mut aggregate_limited = compile_input_limits();
        aggregate_limited.max_documents = 3;
        let mut documents = compile_args();
        documents.extend(["--attester".to_owned(), "second.json".to_owned()]);
        assert!(
            CompileArguments::parse(&documents, aggregate_limited)
                .unwrap_err()
                .contains("aggregate count limit 3")
        );
    }

    #[test]
    fn compile_documents_reject_nested_duplicate_keys_at_each_typed_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let policy = directory.path().join("policy.json");
        let observation = directory.path().join("observation.json");
        let attester = directory.path().join("attester.json");
        fs::write(
            &policy,
            br#"{"accepted_conformance":[{"extensions":{"same":1,"same":2}}]}"#,
        )
        .unwrap();
        fs::write(&observation, br#"{"fact":{"payload":{"same":1,"same":2}}}"#).unwrap();
        fs::write(
            &attester,
            br#"{"authority":{"extensions":{"same":1,"same":2}}}"#,
        )
        .unwrap();

        for error in [
            read_compile_document::<AdmissionPolicy>(
                &policy,
                &mut DocumentBudget::new(test_input_limits(1024, 4096)).unwrap(),
            )
            .unwrap_err(),
            read_compile_document::<SourceObservation>(
                &observation,
                &mut DocumentBudget::new(test_input_limits(1024, 4096)).unwrap(),
            )
            .unwrap_err(),
            read_compile_document::<LocalAttesterBinding>(
                &attester,
                &mut DocumentBudget::new(test_input_limits(1024, 4096)).unwrap(),
            )
            .unwrap_err(),
        ] {
            assert!(
                error.contains("duplicate JSON object key `same`"),
                "{error}"
            );
        }
    }

    #[test]
    fn compile_document_reads_are_bounded_and_regular_file_only() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.json");
        let second = directory.path().join("second.json");
        fs::write(&first, b"1234").unwrap();
        fs::write(&second, b"5678").unwrap();

        let mut per_document = DocumentBudget::new(test_input_limits(3, 16)).unwrap();
        assert!(
            per_document
                .read(&first)
                .unwrap_err()
                .contains("per-document limit 3")
        );

        let mut aggregate = DocumentBudget::new(test_input_limits(8, 6)).unwrap();
        assert_eq!(aggregate.read(&first).unwrap(), b"1234");
        assert!(
            aggregate
                .read(&second)
                .unwrap_err()
                .contains("remaining aggregate limit 2")
        );

        let mut count_limits = test_input_limits(8, 16);
        count_limits.max_documents = 1;
        let mut count = DocumentBudget::new(count_limits).unwrap();
        assert_eq!(count.read(&first).unwrap(), b"1234");
        assert!(
            count
                .read(&directory.path().join("does-not-exist"))
                .unwrap_err()
                .contains("aggregate document count exceeds 1")
        );

        let target = directory.path().join("target.json");
        let link = directory.path().join("link.json");
        fs::write(&target, b"{}").unwrap();
        symlink(&target, &link).unwrap();
        assert!(
            DocumentBudget::new(test_input_limits(8, 16))
                .unwrap()
                .read(&link)
                .unwrap_err()
                .contains("document open failed")
        );

        assert!(
            DocumentBudget::new(test_input_limits(8, 16))
                .unwrap()
                .read(directory.path())
                .unwrap_err()
                .contains("compile input must be a regular file")
        );

        let fifo = directory.path().join("input.fifo");
        mkfifo(&fifo, NixMode::S_IRUSR | NixMode::S_IWUSR).unwrap();
        assert!(
            DocumentBudget::new(test_input_limits(8, 16))
                .unwrap()
                .read(&fifo)
                .unwrap_err()
                .contains("compile input must be a regular file")
        );
    }

    #[test]
    fn input_is_a_domain_neutral_fact_document() {
        let fact = FactInstance::initial(
            FactType::new("test.value", "source", "1.0.0"),
            FactCoverage::Complete,
            serde_json::json!({"any": "payload"}),
            "test fixture",
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fact.json");
        fs::write(&path, serde_json::to_vec(&fact).unwrap()).unwrap();
        assert_eq!(input_fact(&path).unwrap(), fact);
    }
}
