//! Pure helpers behind the `gooir` command, kept importable so the ergonomics
//! can be tested rather than only demonstrated.

use gooir_capability::{CapabilityRegistry, FactType};

/// Every fact type mentioned by the installed graph.
pub fn known_facts(registry: &CapabilityRegistry) -> Vec<FactType> {
    let mut facts: Vec<FactType> = registry
        .specs()
        .flat_map(|spec| {
            spec.output_ports
                .iter()
                .map(|port| port.value_kind.clone())
                .chain(spec.input_ports.iter().map(|port| port.value_kind.clone()))
        })
        .collect();
    facts.sort();
    facts.dedup();
    facts
}

/// Accepts a full identity or an unambiguous bare name. Ambiguity is reported
/// rather than resolved by preference.
pub fn resolve(registry: &CapabilityRegistry, wanted: &str) -> Result<FactType, String> {
    let facts = known_facts(registry);
    if let Some(exact) = facts.iter().find(|f| f.to_string() == wanted) {
        return Ok(exact.clone());
    }
    let matches: Vec<&FactType> = facts.iter().filter(|f| f.name == wanted).collect();
    match matches.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(format!(
            "no fact type named `{wanted}`. `gooir facts` lists them."
        )),
        many => {
            let names: Vec<String> = many.iter().map(|f| f.to_string()).collect();
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
    use gooir_capability::{CapabilitySpec, InputPort, OutputPort, PortName};

    fn fact(package: &str, name: &str) -> FactType {
        FactType::new(package, name, "1.0.0")
    }

    fn port(name: &str) -> PortName {
        PortName::parse(name).unwrap()
    }

    fn registry() -> CapabilityRegistry {
        let mut r = CapabilityRegistry::default();
        r.register_spec(CapabilitySpec {
            id: gooir_capability::CapabilityId::new("t", "one", "1.0.0"),
            input_ports: vec![InputPort::complete(
                port("source"),
                fact("t.source", "input"),
            )],
            output_ports: vec![OutputPort::new(
                port("result"),
                fact("t.artifact", "unique_name"),
            )],
            default_conformance_suite: "t/suite@1".to_owned(),
            extensions: Default::default(),
        })
        .unwrap();
        r.register_spec(CapabilitySpec {
            id: gooir_capability::CapabilityId::new("t", "two", "1.0.0"),
            input_ports: vec![InputPort::complete(
                port("source"),
                fact("t.source", "input"),
            )],
            output_ports: vec![
                OutputPort::new(port("first"), fact("t.a", "shared")),
                OutputPort::new(port("second"), fact("t.b", "shared")),
            ],
            default_conformance_suite: "t/suite@1".to_owned(),
            extensions: Default::default(),
        })
        .unwrap();
        r
    }

    #[test]
    fn known_facts_covers_inputs_and_outputs_without_duplicates() {
        let facts = known_facts(&registry());
        assert_eq!(facts.len(), 4, "{facts:?}");
        assert!(facts.contains(&fact("t.source", "input")));
        assert!(facts.contains(&fact("t.artifact", "unique_name")));
    }

    #[test]
    fn a_full_identity_resolves_exactly() {
        let r = registry();
        let wanted = "t.artifact/unique_name@1.0.0";
        assert_eq!(
            resolve(&r, wanted).unwrap(),
            fact("t.artifact", "unique_name")
        );
    }

    #[test]
    fn an_unambiguous_bare_name_resolves() {
        let r = registry();
        assert_eq!(
            resolve(&r, "unique_name").unwrap(),
            fact("t.artifact", "unique_name")
        );
    }

    #[test]
    fn an_ambiguous_bare_name_lists_the_candidates_instead_of_choosing() {
        let r = registry();
        let error = resolve(&r, "shared").expect_err("must not choose");
        assert!(error.contains("ambiguous"), "{error}");
        assert!(error.contains("t.a/shared@1.0.0"), "{error}");
        assert!(error.contains("t.b/shared@1.0.0"), "{error}");
    }

    #[test]
    fn an_unknown_name_points_at_the_listing_command() {
        let error = resolve(&registry(), "nope").expect_err("unknown");
        assert!(error.contains("gooir facts"), "{error}");
    }
}
