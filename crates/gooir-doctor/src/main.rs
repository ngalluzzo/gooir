//! `gooir doctor` — what the installed capability graph can and cannot deliver.

use std::{collections::BTreeMap, fs, path::PathBuf};

use gooir_capability::CapabilityRegistry;
use gooir_doctor::{Report, diagnose};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn installed() -> Result<CapabilityRegistry, String> {
    let mut registry = CapabilityRegistry::default();
    gooir_datamodel_pack::register(&mut registry).map_err(|e| e.to_string())?;
    fleetd_capability_pack::register_specs(&mut registry).map_err(|e| e.to_string())?;
    fleetd_capability_pack::register_providers(&mut registry).map_err(|e| e.to_string())?;
    Ok(registry)
}

fn run() -> Result<(), String> {
    let report = diagnose(&installed()?);
    print_graph(&report);
    print_declarations()?;
    println!();
    println!(
        "summary  {} blocking, {} open need(s), {} unadmitted provider(s)",
        report.blocking(),
        report.open_needs(),
        report.unadmitted.len()
    );
    if report.blocking() > 0 {
        std::process::exit(2);
    }
    Ok(())
}

fn print_graph(r: &Report) {
    println!("capability graph");
    println!(
        "  {} capabilities, {} providers, {} fact types",
        r.capabilities, r.providers, r.fact_types
    );

    println!("\nyou must supply ({})", r.roots.len());
    for root in &r.roots {
        println!("  {}", root.fact);
        println!("    needed by {}", root.required_by.len());
    }

    println!("\nyou can obtain ({})", r.terminals.len());
    for t in &r.terminals {
        println!(
            "  {:<7} {}",
            if t.obtainable { "yes" } else { "needs" },
            t.fact
        );
        for c in &t.blocked_by {
            println!("          waiting on {c}");
        }
    }

    if !r.unimplemented.is_empty() {
        println!("\nopen needs — assignable work ({})", r.unimplemented.len());
        for u in &r.unimplemented {
            println!("  {}", u.capability);
            for p in &u.produces {
                println!("    produces {p}");
            }
            println!("    suite    {}", u.conformance_suite);
        }
    }

    if !r.unreachable.is_empty() {
        println!("\nUNREACHABLE ({})", r.unreachable.len());
        for u in &r.unreachable {
            println!("  {}  ({})", u.fact, u.reason);
        }
    }

    if !r.ambiguous.is_empty() {
        println!(
            "\nmultiple routes ({}) — the planner picks by score",
            r.ambiguous.len()
        );
        for a in &r.ambiguous {
            println!("  {}", a.fact);
            for c in &a.produced_by {
                println!("    via {c}");
            }
        }
    }

    println!("\nadmission");
    println!(
        "  {} attester(s) admitted by this host",
        r.admitted_attesters
    );
    println!(
        "  {} provider(s) whose outputs are not admissible yet",
        r.unadmitted.len()
    );
    if r.admitted_attesters == 0 && !r.unadmitted.is_empty() {
        println!("  -> no produced fact can become admitted, whatever a verifier reports");
    }
    for u in &r.unadmitted {
        println!("    {} needs {}", u.provider.name, u.conformance_suite);
    }
}

/// A source-level check, not a registry one: the same exact identity declared in
/// more than one crate is the drift this project exists to remove.
fn print_declarations() -> Result<(), String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .ok_or("workspace root")?
        .join("crates");

    let mut fact_sites: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut identity_kinds: BTreeMap<&str, usize> = BTreeMap::new();
    let mut implementations: Vec<String> = Vec::new();

    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                continue;
            };
            let crate_name = path
                .components()
                .rev()
                .find_map(|c| {
                    let s = c.as_os_str().to_string_lossy().into_owned();
                    (s != "src" && s != "tests" && !s.ends_with(".rs")).then_some(s)
                })
                .unwrap_or_default();
            for kind in ["FactType::new(", "CapabilityId::new(", "ContractId::new("] {
                let n = text.matches(kind).count();
                if n > 0 {
                    *identity_kinds
                        .entry(kind.trim_end_matches("::new("))
                        .or_default() += n;
                }
            }
            // An *implementation* of the identity rule: a macro that declares
            // one, or a hand-written struct carrying all three exact parts.
            //
            // The needles are assembled from fragments so that this file's own
            // source does not match them. A tool that scans source must not
            // count itself.
            let macro_needle = concat!("macro_rules!", " exact_identity");
            let legacy_needle = concat!("macro_rules!", " exact_id ");
            let declares_macro = text.contains(macro_needle) || text.contains(legacy_needle);
            let declares_struct = text.contains(concat!("pub ", "package: String"))
                && text.contains(concat!("pub ", "name: String"))
                && text.contains(concat!("pub ", "version: String"))
                && !declares_macro;
            if declares_macro || declares_struct {
                implementations.push(format!(
                    "{crate_name} ({})",
                    if declares_macro { "macro" } else { "struct" }
                ));
            }
            for (index, _) in text.match_indices("FactType::new(") {
                let tail = &text[index + "FactType::new(".len()..];
                let Some(end) = tail.find(')') else { continue };
                let args: Vec<String> = tail[..end]
                    .split(',')
                    .map(|a| a.trim().trim_matches('"').to_owned())
                    .collect();
                if args.len() == 3 && args.iter().all(|a| !a.is_empty() && !a.contains(' ')) {
                    let id = format!("{}/{}@{}", args[0], args[1], args[2]);
                    let sites = fact_sites.entry(id).or_default();
                    if !sites.contains(&crate_name) {
                        sites.push(crate_name.clone());
                    }
                }
            }
        }
    }

    implementations.sort();
    implementations.dedup();
    println!("\nexact identity");
    println!(
        "  {} implementation(s) of the rule: {}",
        implementations.len(),
        implementations.join(", ")
    );
    for (kind, count) in &identity_kinds {
        println!("    {kind:<12} {count} use site(s)");
    }
    if implementations.len() > 1 {
        println!(
            "  -> {} parallel implementations of one idea",
            implementations.len()
        );
    }

    let shared: Vec<(&String, &Vec<String>)> =
        fact_sites.iter().filter(|(_, v)| v.len() > 1).collect();
    println!(
        "\nfact identities declared in more than one crate ({})",
        shared.len()
    );
    for (id, crates) in shared {
        println!("  {id}");
        println!("    {}", crates.join(", "));
    }
    Ok(())
}
