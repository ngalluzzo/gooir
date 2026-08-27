//! `gooir` — one way in.
//!
//! Everything this system does is a derivation over a capability graph. This
//! command shows the graph, plans a route through it, runs one, and names what
//! is missing. It replaces having to know which of a dozen crates holds the
//! entry point for a given question.

use std::{fs, path::PathBuf, process};

use gooir_capability::{
    Answer, CapabilityRegistry, DerivationRequest, FactInstance, FactType, RequestRefusal,
    register_pack,
};
use gooir_cli::{known_facts, resolve};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

const USAGE: &str = "\
gooir — inspect and exercise an explicitly installed capability graph

  gooir facts                         every fact type, and how it is reached
  gooir capabilities                  every promise, and whether it has a provider
  gooir needs                         promises with no provider, as work contracts
  gooir doctor                        graph health
  gooir plan <target>                 the route to a target
  gooir derive <target> --from FACT   run the legacy in-process adapter

Add --pack MANIFEST (repeatable) to declare capabilities.
Add --plugin MANIFEST (repeatable) to install an out-of-process provider.
Nothing is installed implicitly.

A target may be a full value-kind identity or an unambiguous bare name.

FACT is a serialized FactInstance JSON document. Repeat --from for each input.
Domain authoring formats and their conversion to facts belong to ecosystem
packages, not this command.";

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

fn installed(packs: &[PathBuf], plugins: &[PathBuf]) -> Result<CapabilityRegistry, String> {
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

fn input_fact(path: &PathBuf) -> Result<FactInstance, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
}

/// Renders an answer that produced nothing, and says what to do about it.
///
/// Every branch ends in the answer's own remedy rather than a message written
/// here, so a new variant cannot be rendered as a bare failure.
fn print_answer(target: &FactType, given: &Answer) {
    match given {
        Answer::Produced(_) => unreachable!("rendered by the caller"),
        Answer::Blocked(plan) => {
            println!("cannot derive {target} yet:");
            for need in &plan.needs {
                println!("  need {}", need.specification.id);
            }
        }
        Answer::Unreachable(error) => println!("no route to {target}: {error}"),
        Answer::Refused(RequestRefusal::AmbiguousInput(fact)) => {
            println!("refused: two inputs both declare {fact}");
        }
        Answer::Refused(RequestRefusal::LegacyAdapterRepeatedInputKind {
            capability,
            value_kind,
        }) => println!(
            "refused: legacy adapter cannot bind repeated input kind {value_kind} for {capability}"
        ),
        Answer::Refused(RequestRefusal::LegacyAdapterRepeatedOutputKind {
            capability,
            value_kind,
        }) => println!(
            "refused: legacy adapter cannot bind repeated output kind {value_kind} for {capability}"
        ),
        Answer::Failed(error) => println!("legacy execution failed deriving {target}: {error}"),
    }
    println!("\n-> {}", given.remedy());
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
            let registry = installed(
                &value_paths(&args, "--pack"),
                &value_paths(&args, "--plugin"),
            )?;
            let facts = known_facts(&registry);
            println!("{} fact type(s)\n", facts.len());
            for fact in &facts {
                let producers: Vec<String> = registry
                    .specs()
                    .filter(|spec| {
                        spec.output_ports
                            .iter()
                            .any(|port| &port.value_kind == fact)
                    })
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
            let registry = installed(
                &value_paths(&args, "--pack"),
                &value_paths(&args, "--plugin"),
            )?;
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
                for port in &spec.input_ports {
                    println!(
                        "          <- {}: {} ({:?})",
                        port.name, port.value_kind, port.acceptance
                    );
                }
                for port in &spec.output_ports {
                    println!("          -> {}: {}", port.name, port.value_kind);
                }
            }
            Ok(())
        }
        Some("needs") => {
            let registry = installed(
                &value_paths(&args, "--pack"),
                &value_paths(&args, "--plugin"),
            )?;
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
            let registry = installed(
                &value_paths(&args, "--pack"),
                &value_paths(&args, "--plugin"),
            )?;
            let report = gooir_doctor::diagnose(&registry);
            println!("{report}");
            if report.blocking() > 0 {
                process::exit(2);
            }
            Ok(())
        }
        Some("plan") => {
            let registry = installed(
                &value_paths(&args, "--pack"),
                &value_paths(&args, "--plugin"),
            )?;
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
                if plan.has_provider_for_every_step() {
                    "legacy provider binding present for every plan step"
                } else {
                    "legacy provider binding missing: see `gooir needs`"
                }
            );
            Ok(())
        }
        Some("derive") => {
            let registry = installed(
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
            let target = resolve(&registry, wanted)?;
            let request = DerivationRequest {
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
                Answer::Produced(report) => {
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
                        Answer::Blocked(_) => 3,
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
    use gooir_capability::{FactCoverage, FactType};

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
    fn installation_is_empty_until_a_pack_is_named() {
        let empty = installed(&[], &[]).unwrap();
        assert_eq!(empty.specs().count(), 0);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pack.json");
        fs::write(&path, PACK).unwrap();
        let explicit = installed(&[path], &[]).unwrap();
        assert_eq!(explicit.specs().count(), 1);
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
