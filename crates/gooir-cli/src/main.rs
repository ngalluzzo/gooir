//! `gooir` — one way in.
//!
//! The command inspects installed packages and emits provider-neutral plans.
//! Its temporary `derive` subcommand remains a visibly separate compatibility
//! bridge for legacy declaration packs and process plugins.

use std::{collections::BTreeSet, fs, num::NonZeroUsize, path::PathBuf, process};

use gooir_capability::{
    Answer, CapabilityRegistry, DerivationRequest, FactInstance, FactType, RequestRefusal,
    register_pack,
};
use gooir_cli::{known_value_kinds, resolve_value_kind};
use gooir_package::{LoadLimits, PackageRegistry, load_local_package};
use gooir_planning::{PlanLimits, SemanticPlanner};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

const USAGE: &str = "\
gooir — inspect and exercise an explicitly installed capability graph

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
