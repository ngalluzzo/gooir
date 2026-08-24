use std::{collections::BTreeMap, fs, path::PathBuf};

use data_model_convergence::{Divergence, Side, compare};
use lift_defeasible::DefeatKind;

const APPS: [&str; 4] = [
    "umami-software_umami",
    "lukevella_rallly",
    "ghostfolio_ghostfolio",
    "documenso_documenso",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn main() -> Result<(), String> {
    let base = root().join("fixtures/datamodel");
    let verbose = std::env::args().any(|a| a == "--details");
    let mut totals = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);

    println!("Cross-authority convergence on the neutral data-model waist");
    println!("  left  = Prisma schema source     (declared intent)");
    println!("  right = PostgreSQL catalog       (enforced reality)\n");

    for app in APPS {
        let prisma_src = fs::read_to_string(base.join(format!("prisma/{app}.prisma")))
            .map_err(|e| format!("{app}: {e}"))?;
        let catalog_src = fs::read_to_string(base.join(format!("catalog/{app}.catalog.json")))
            .map_err(|e| format!("{app}: {e}"))?;

        let left = prisma_schema_lifter::lift_prisma_schema(&prisma_src);
        let right = postgres_catalog_lifter::lift_catalog(&catalog_src)?;
        let r = compare(&left.value, &right.value);

        println!("== {app}");
        println!(
            "   entities   prisma={:<4} catalog={:<4} shared={}",
            left.value.entities.len(),
            right.value.entities.len(),
            r.shared_entities
        );
        println!(
            "   relations  prisma={:<4} catalog={:<4}",
            left.value.relations.len(),
            right.value.relations.len()
        );
        println!(
            "   divergence entity={} field={} attribute={}/{} ({:.1}% agreement) relation={}",
            r.entity_divergences(),
            r.field_divergences(),
            r.attribute_divergences(),
            r.compared_attributes,
            r.attribute_agreement() * 100.0,
            r.relation_divergences()
        );
        println!("   unique-set divergence: {}", r.unique_set_divergences());
        println!(
            "   authority-limited comparisons (one side Unknown): {}",
            r.authority_limited
        );

        let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
        for d in left.defeats.iter() {
            *by_kind.entry(format!("prisma/{:?}", d.kind)).or_default() += 1;
        }
        for d in right.defeats.iter() {
            *by_kind.entry(format!("catalog/{:?}", d.kind)).or_default() += 1;
        }
        if by_kind.is_empty() {
            println!("   defeats    none");
        } else {
            let s: Vec<String> = by_kind.iter().map(|(k, v)| format!("{k}={v}")).collect();
            println!("   defeats    {}", s.join(" "));
        }

        // Which attributes disagree, aggregated -- this is the vocabulary signal.
        let mut attr_hist: BTreeMap<(&str, String, String), usize> = BTreeMap::new();
        for d in &r.divergences {
            if let Divergence::Attribute {
                attribute,
                left,
                right,
                ..
            } = d
            {
                *attr_hist
                    .entry((attribute, left.clone(), right.clone()))
                    .or_default() += 1;
            }
        }
        let mut top: Vec<_> = attr_hist.into_iter().collect();
        top.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        for ((attr, l, rr), n) in top.iter().take(if verbose { 30 } else { 6 }) {
            println!("     {n:>4}x {attr}: prisma={l} catalog={rr}");
        }

        if verbose {
            for d in &r.divergences {
                match d {
                    Divergence::Entity { side, entity } => println!(
                        "     entity only in {}: {entity}",
                        if *side == Side::OnlyLeft {
                            "prisma"
                        } else {
                            "catalog"
                        }
                    ),
                    Divergence::Field {
                        side,
                        entity,
                        field,
                    } => println!(
                        "     field only in {}: {entity}.{field}",
                        if *side == Side::OnlyLeft {
                            "prisma"
                        } else {
                            "catalog"
                        }
                    ),
                    Divergence::Relation { side, from, to } => println!(
                        "     relation only in {}: {from} -> {to}",
                        if *side == Side::OnlyLeft {
                            "prisma"
                        } else {
                            "catalog"
                        }
                    ),
                    Divergence::UniqueSet {
                        side,
                        entity,
                        fields,
                    } => println!(
                        "     unique set only in {}: {entity}({})",
                        if *side == Side::OnlyLeft {
                            "prisma"
                        } else {
                            "catalog"
                        },
                        fields.join(", ")
                    ),
                    Divergence::Attribute {
                        entity,
                        field,
                        attribute,
                        left,
                        right,
                    } => println!(
                        "     attr {entity}.{field} [{attribute}] prisma={left} catalog={right}"
                    ),
                }
            }
            for d in left.defeats.iter().chain(right.defeats.iter()) {
                println!("     defeat [{:?}] {}: {}", d.kind, d.subject, d.reason);
            }
        }
        println!();

        totals.0 += r.shared_entities;
        totals.1 += r.entity_divergences();
        totals.2 += r.field_divergences();
        totals.3 += r.attribute_divergences();
        totals.4 += r.compared_attributes;
        totals.5 += r.relation_divergences();
    }

    let agreement = if totals.4 == 0 {
        100.0
    } else {
        (1.0 - totals.3 as f64 / totals.4 as f64) * 100.0
    };
    println!(
        "TOTALS  shared_entities={} entity_div={} field_div={} attr_div={}/{} ({agreement:.1}% agreement) relation_div={}",
        totals.0, totals.1, totals.2, totals.3, totals.4, totals.5
    );
    let _ = DefeatKind::NotLooked;
    Ok(())
}
