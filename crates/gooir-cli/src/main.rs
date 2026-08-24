//! `gooir` — one way in.
//!
//! Everything this system does is a derivation over a capability graph. This
//! command shows the graph, plans a route through it, runs one, and names what
//! is missing. It replaces having to know which of a dozen crates holds the
//! entry point for a given question.

use std::{fs, path::PathBuf, process};

use gooir_capability::{CapabilityRegistry, FactInstance, FactType};
use gooir_cli::{known_facts, resolve};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

const USAGE: &str = "\
gooir — derive facts over a capability graph

  gooir facts                        every fact type, and how it is reached
  gooir capabilities                 every promise, and whether it has a provider
  gooir needs                        promises with no provider, as work contracts
  gooir doctor                        graph health
  gooir plan <target>                 the route to a target
  gooir derive <target> --from FILE   run it, and print the derivation chain

Add --plugin MANIFEST (repeatable) to install an out-of-process provider.

A target may be a full identity (org.gooi.artifact.sql/postgres_ddl@0.1.0) or a
bare name (postgres_ddl) when it is unambiguous.

FILE is a hand-written .entities specification. Sources lifted from existing
software are supplied by their own packs; see `gooir capabilities`.";

/// Plugin manifests are named by the caller, never discovered. Scanning a
/// directory for programs to execute would be a supply-chain hole.
fn plugin_paths(args: &[String]) -> Vec<PathBuf> {
    args.iter()
        .enumerate()
        .filter(|(_, a)| a.as_str() == "--plugin")
        .filter_map(|(i, _)| args.get(i + 1))
        .map(PathBuf::from)
        .collect()
}

fn installed(plugins: &[PathBuf]) -> Result<CapabilityRegistry, String> {
    let mut registry = CapabilityRegistry::default();
    gooir_datamodel_pack::register(&mut registry).map_err(|e| e.to_string())?;
    fleetd_capability_pack::register_specs(&mut registry).map_err(|e| e.to_string())?;
    fleetd_capability_pack::register_providers(&mut registry).map_err(|e| e.to_string())?;
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

fn authored_source(path: &PathBuf) -> Result<FactInstance, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let parsed = gooir_datamodel_pack::authored_fact(path.display().to_string(), &text)
        .map_err(|e| e.to_string())?;
    Ok(parsed)
}

/// Prints an artifact the way a person reads it.
///
/// A generated schema is text; showing it as a JSON string with escaped
/// newlines would defeat the purpose of having one entry point. `--json` still
/// gives the exact payload.
fn print_payload(payload: &serde_json::Value) {
    const TEXT_FIELDS: [&str; 4] = ["ddl", "text", "source", "content"];

    // A generated schema is text. Unwrapping an envelope must not hand it back
    // as a JSON string with escaped newlines.
    if let Some(text) = payload.as_str() {
        println!("{text}");
        return;
    }

    // Every fact payload is a defeasible envelope: a value plus what could not
    // be established. Show the value, then say what was lost, rather than
    // making a reader dig the artifact out of its own provenance.
    if let Some(object) = payload
        .as_object()
        .filter(|o| o.contains_key("value") && o.contains_key("defeater_set"))
    {
        {
            print_payload(&object["value"]);
            let defeats = object.get("defeats").and_then(|d| d.as_array());
            match defeats.map(|d| d.len()).unwrap_or(0) {
                0 => println!("\nnothing was lost"),
                n => {
                    println!("\n{n} thing(s) the target could not carry:");
                    for defeat in defeats.into_iter().flatten() {
                        println!(
                            "  [{}] {}: {}",
                            defeat["kind"].as_str().unwrap_or("?"),
                            defeat["subject"].as_str().unwrap_or("?"),
                            defeat["reason"].as_str().unwrap_or("?")
                        );
                    }
                }
            }
            return;
        }
    }

    if let Some(object) = payload.as_object() {
        for field in TEXT_FIELDS {
            if let Some(text) = object.get(field).and_then(|v| v.as_str()) {
                println!("{text}");
                let extra: Vec<&String> = object.keys().filter(|k| k.as_str() != field).collect();
                if !extra.is_empty() {
                    let names: Vec<&str> = extra.iter().map(|k| k.as_str()).collect();
                    println!("(also carries: {}; --json for all of it)", names.join(", "));
                }
                return;
            }
        }
        // A structured artifact: show its shape rather than its bytes.
        let mut keys: Vec<&String> = object.keys().collect();
        keys.sort();
        for key in keys {
            let value = &object[key];
            let shape = match value {
                serde_json::Value::Object(m) => format!("{} field(s)", m.len()),
                serde_json::Value::Array(a) => format!("{} item(s)", a.len()),
                serde_json::Value::String(s) => format!("{} character(s)", s.len()),
                other => other.to_string(),
            };
            println!("  {key:<12} {shape}");
        }
        println!("\n--json for the exact payload");
        return;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(payload).unwrap_or_default()
    );
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str);
    let registry = installed(&plugin_paths(&args))?;

    match command {
        None | Some("-h") | Some("--help") | Some("help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some("facts") => {
            let facts = known_facts(&registry);
            println!("{} fact type(s)\n", facts.len());
            for fact in &facts {
                let producers: Vec<String> = registry
                    .specs()
                    .filter(|s| s.produces.contains(fact))
                    .map(|s| s.id.name.clone())
                    .collect();
                let how = if producers.is_empty() {
                    "supplied by you".to_owned()
                } else {
                    format!("via {}", producers.join(" | "))
                };
                println!("  {fact}\n      {how}");
            }
            Ok(())
        }
        Some("capabilities") => {
            let provided: Vec<_> = registry
                .provider_descriptors()
                .into_iter()
                .map(|d| d.capability)
                .collect();
            println!("{} capability(ies)\n", registry.specs().count());
            for spec in registry.specs() {
                let mark = if provided.contains(&spec.id) {
                    "have"
                } else {
                    "NEED"
                };
                println!("  {mark}  {}", spec.id);
                for r in &spec.requires {
                    println!("          <- {} ({:?})", r.fact, r.acceptance);
                }
                for p in &spec.produces {
                    println!("          -> {p}");
                }
            }
            Ok(())
        }
        Some("needs") => {
            let report = gooir_doctor::diagnose(&registry);
            if report.unimplemented.is_empty() {
                println!("no open needs: every capability has a provider");
                return Ok(());
            }
            println!("{} open need(s)\n", report.unimplemented.len());
            for need in &report.unimplemented {
                println!("  {}", need.capability);
                for p in &need.produces {
                    println!("    produces {p}");
                }
                println!("    suite    {}", need.conformance_suite);
            }
            println!("\nEach is assignable: an exact promise a provider can be given.");
            Ok(())
        }
        Some("doctor") => {
            let report = gooir_doctor::diagnose(&registry);
            println!(
                "{} capabilities, {} providers, {} fact types",
                report.capabilities, report.providers, report.fact_types
            );
            println!(
                "{} blocking, {} open need(s), {} attester(s) admitted",
                report.blocking(),
                report.open_needs(),
                report.admitted_attesters
            );
            for u in &report.unreachable {
                println!("  UNREACHABLE {} ({})", u.fact, u.reason);
            }
            if report.blocking() > 0 {
                process::exit(2);
            }
            Ok(())
        }
        Some("plan") => {
            let wanted = args.get(1).ok_or("usage: gooir plan <target>")?;
            let target = resolve(&registry, wanted)?;
            let roots: Vec<FactType> = gooir_doctor::diagnose(&registry)
                .roots
                .into_iter()
                .map(|r| r.fact)
                .collect();
            let plan = registry.plan(roots, &target).map_err(|e| e.to_string())?;
            println!("target {target}");
            for step in &plan.steps {
                println!(
                    "  {} {}",
                    if step.provider.is_some() {
                        "run "
                    } else {
                        "NEED"
                    },
                    step.capability
                );
            }
            println!(
                "\n{}",
                if plan.is_executable() {
                    "executable"
                } else {
                    "not executable: see `gooir needs`"
                }
            );
            Ok(())
        }
        Some("derive") => {
            let wanted = args
                .get(1)
                .ok_or("usage: gooir derive <target> --from FILE")?;
            let from = args
                .iter()
                .position(|a| a == "--from")
                .and_then(|i| args.get(i + 1))
                .map(PathBuf::from)
                .ok_or("usage: gooir derive <target> --from FILE")?;
            let target = resolve(&registry, wanted)?;
            let source = authored_source(&from)?;
            let plan = registry
                .plan([source.fact_type.clone()], &target)
                .map_err(|e| e.to_string())?;
            if !plan.is_executable() {
                println!("cannot derive {target} yet:");
                for need in &plan.needs {
                    println!("  need {}", need.capability);
                }
                println!("\n`gooir needs` shows these as assignable work.");
                process::exit(3);
            }
            let report = registry
                .execute(&plan, vec![source])
                .map_err(|e| e.to_string())?;
            println!("{target}");
            println!("  id       {}", report.target.id);
            println!("  coverage {:?}", report.target.coverage);
            println!("  chain    {} fact(s)", report.facts.len());
            println!();
            if args.iter().any(|a| a == "--json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report.target.payload).unwrap_or_default()
                );
            } else {
                print_payload(&report.target.payload);
            }
            Ok(())
        }
        Some(other) => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    }
}
