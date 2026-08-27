//! Pure helpers behind the `gooir` command, kept importable so the ergonomics
//! can be tested rather than only demonstrated.

use gooir_capability::ValueKindId;
use gooir_package::PackageRegistry;

/// Every value kind mentioned by the installed package graph.
pub fn known_value_kinds(registry: &PackageRegistry) -> Vec<ValueKindId> {
    let mut value_kinds: Vec<ValueKindId> = registry
        .capabilities()
        .flat_map(|(_package, specification)| {
            specification
                .output_ports
                .iter()
                .map(|port| port.value_kind.clone())
                .chain(
                    specification
                        .input_ports
                        .iter()
                        .map(|port| port.value_kind.clone()),
                )
        })
        .collect();
    value_kinds.sort();
    value_kinds.dedup();
    value_kinds
}

/// Accepts a full identity or an unambiguous bare name. Ambiguity is reported
/// rather than resolved by preference.
pub fn resolve_value_kind(registry: &PackageRegistry, wanted: &str) -> Result<ValueKindId, String> {
    let value_kinds = known_value_kinds(registry);
    if let Some(exact) = value_kinds.iter().find(|kind| kind.to_string() == wanted) {
        return Ok(exact.clone());
    }
    let matches: Vec<&ValueKindId> = value_kinds
        .iter()
        .filter(|kind| kind.name == wanted)
        .collect();
    match matches.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(format!(
            "no value kind named `{wanted}`. `gooir facts` lists them."
        )),
        many => {
            let names: Vec<String> = many.iter().map(|kind| kind.to_string()).collect();
            Err(format!(
                "`{wanted}` is ambiguous; name one exactly:\n  {}",
                names.join("\n  ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use gooir_capability::protocol::ConformanceSuiteId;
    use gooir_capability::{CapabilitySpec, InputPort, OutputPort, PortName};
    use gooir_package::{
        ConformanceSuiteDeclaration, DialectDeclaration, LoadLimits, PackageId, PackageManifest,
        ValueKindDeclaration, load_local_package, write_manifest,
    };

    fn value_kind(package: &str, name: &str) -> ValueKindId {
        ValueKindId::new(package, name, "1.0.0")
    }

    fn port(name: &str) -> PortName {
        PortName::parse(name).unwrap()
    }

    fn registry() -> PackageRegistry {
        let specifications = vec![
            CapabilitySpec {
                id: gooir_capability::CapabilityId::new("t", "one", "1.0.0"),
                input_ports: vec![InputPort::complete(
                    port("source"),
                    value_kind("t.source", "input"),
                )],
                output_ports: vec![OutputPort::new(
                    port("result"),
                    value_kind("t.artifact", "unique_name"),
                )],
                default_conformance_suite: "t.suite/exact@1.0.0".to_owned(),
                extensions: Default::default(),
            },
            CapabilitySpec {
                id: gooir_capability::CapabilityId::new("t", "two", "1.0.0"),
                input_ports: vec![InputPort::complete(
                    port("source"),
                    value_kind("t.source", "input"),
                )],
                output_ports: vec![
                    OutputPort::new(port("first"), value_kind("t.a", "shared")),
                    OutputPort::new(port("second"), value_kind("t.b", "shared")),
                ],
                default_conformance_suite: "t.suite/exact@1.0.0".to_owned(),
                extensions: Default::default(),
            },
        ];
        let declarations = specifications
            .iter()
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
            .map(|id| ValueKindDeclaration {
                id,
                schema: None,
                extensions: BTreeMap::new(),
            })
            .collect::<Vec<_>>();
        let mut declarations_by_dialect = BTreeMap::new();
        for declaration in declarations {
            declarations_by_dialect
                .entry(declaration.id.dialect())
                .or_insert_with(Vec::new)
                .push(declaration);
        }
        let dialects = declarations_by_dialect
            .into_iter()
            .map(|(id, value_kinds)| DialectDeclaration {
                id,
                value_kinds,
                extensions: BTreeMap::new(),
            })
            .collect();
        let manifest = PackageManifest::new(
            PackageId::parse("t.package@1.0.0").unwrap(),
            Vec::new(),
            Vec::new(),
            dialects,
            vec![ConformanceSuiteDeclaration {
                id: ConformanceSuiteId::parse("t.suite/exact@1.0.0").unwrap(),
                extensions: BTreeMap::new(),
            }],
            specifications,
            Vec::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("gooir-package.json"),
            write_manifest(&manifest).unwrap(),
        )
        .unwrap();
        let mut registry = PackageRegistry::default();
        let package =
            load_local_package(directory.path(), &registry, LoadLimits::default()).unwrap();
        registry.install(package).unwrap();
        registry
    }

    #[test]
    fn known_facts_covers_inputs_and_outputs_without_duplicates() {
        let value_kinds = known_value_kinds(&registry());
        assert_eq!(value_kinds.len(), 4, "{value_kinds:?}");
        assert!(value_kinds.contains(&value_kind("t.source", "input")));
        assert!(value_kinds.contains(&value_kind("t.artifact", "unique_name")));
    }

    #[test]
    fn a_full_identity_resolves_exactly() {
        let r = registry();
        let wanted = "t.artifact/unique_name@1.0.0";
        assert_eq!(
            resolve_value_kind(&r, wanted).unwrap(),
            value_kind("t.artifact", "unique_name")
        );
    }

    #[test]
    fn an_unambiguous_bare_name_resolves() {
        let r = registry();
        assert_eq!(
            resolve_value_kind(&r, "unique_name").unwrap(),
            value_kind("t.artifact", "unique_name")
        );
    }

    #[test]
    fn an_ambiguous_bare_name_lists_the_candidates_instead_of_choosing() {
        let r = registry();
        let error = resolve_value_kind(&r, "shared").expect_err("must not choose");
        assert!(error.contains("ambiguous"), "{error}");
        assert!(error.contains("t.a/shared@1.0.0"), "{error}");
        assert!(error.contains("t.b/shared@1.0.0"), "{error}");
    }

    #[test]
    fn an_unknown_name_points_at_the_listing_command() {
        let error = resolve_value_kind(&registry(), "nope").expect_err("unknown");
        assert!(error.contains("gooir facts"), "{error}");
    }
}
