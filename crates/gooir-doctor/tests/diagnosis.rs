//! The diagnostic is generic: these graphs contain no domain meanings.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::num::NonZeroUsize;

use gooir_capability::protocol::{ConformanceSuiteId, ImplementationId};
use gooir_capability::{
    CapabilityId, CapabilitySpec, DialectId, InputPort, OutputPort, PortName, ValueKindId,
};
use gooir_doctor::diagnose;
use gooir_package::{
    ConformanceSuiteDeclaration, DialectDeclaration, ImplementationOfferDeclaration, LoadLimits,
    PackageId, PackageManifest, PackageRegistry, PackageResource, ResourceDigest, ResourceName,
    ValueKindDeclaration, load_local_package, write_manifest,
};
use gooir_planning::PlanLimits;

const VERSION: &str = "1.0.0";
const EMPTY_SHA256: &str =
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn value_kind(name: &str) -> ValueKindId {
    ValueKindId::new("test.fact", name, VERSION)
}

fn capability(name: &str) -> CapabilityId {
    CapabilityId::new("test.capability", name, VERSION)
}

fn port(name: &str) -> PortName {
    PortName::parse(name).unwrap()
}

fn specification(id: CapabilityId, from: &str, to: &str) -> CapabilitySpec {
    CapabilitySpec {
        id,
        input_ports: vec![InputPort::complete(port("source"), value_kind(from))],
        output_ports: vec![OutputPort::new(port("result"), value_kind(to))],
        default_conformance_suite: suite().to_string(),
        extensions: BTreeMap::new(),
    }
}

fn suite() -> ConformanceSuiteId {
    ConformanceSuiteId::parse("test.suite/default@1.0.0").unwrap()
}

fn limits() -> PlanLimits {
    let bound = NonZeroUsize::new(128).unwrap();
    PlanLimits {
        max_capabilities: bound,
        max_value_kinds: bound,
        max_ports_per_capability: bound,
        max_total_ports: bound,
        max_offers_per_capability: bound,
        max_total_offers: bound,
    }
}

fn install_graph(
    mut specifications: Vec<CapabilitySpec>,
    offered: impl IntoIterator<Item = CapabilityId>,
) -> PackageRegistry {
    specifications.sort_by(|left, right| left.id.cmp(&right.id));

    let dialect = DialectId::new("test.fact", VERSION);
    let value_kinds = specifications
        .iter()
        .flat_map(|specification| {
            specification
                .input_ports
                .iter()
                .map(|input| input.value_kind.clone())
                .chain(
                    specification
                        .output_ports
                        .iter()
                        .map(|output| output.value_kind.clone()),
                )
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|id| ValueKindDeclaration {
            id,
            schema: None,
            extensions: BTreeMap::new(),
        })
        .collect();

    let artifact_name = ResourceName::parse("provider").unwrap();
    let mut implementation_offers = offered
        .into_iter()
        .map(|capability| ImplementationOfferDeclaration {
            implementation: ImplementationId::new("test.implementation", &capability.name, VERSION),
            capability,
            artifact: artifact_name.clone(),
            extensions: BTreeMap::new(),
        })
        .collect::<Vec<_>>();
    implementation_offers.sort_by(|left, right| {
        (&left.capability, &left.implementation, &left.artifact).cmp(&(
            &right.capability,
            &right.implementation,
            &right.artifact,
        ))
    });

    let resources = (!implementation_offers.is_empty())
        .then(|| PackageResource {
            name: artifact_name,
            path: "bin/provider".to_owned(),
            media_type: "application/octet-stream".to_owned(),
            size: 0,
            digest: ResourceDigest::parse(EMPTY_SHA256).unwrap(),
            extensions: BTreeMap::new(),
        })
        .into_iter()
        .collect();
    let manifest = PackageManifest::new(
        PackageId::parse("test.package@1.0.0").unwrap(),
        Vec::new(),
        resources,
        vec![DialectDeclaration {
            id: dialect,
            value_kinds,
            extensions: BTreeMap::new(),
        }],
        vec![ConformanceSuiteDeclaration {
            id: suite(),
            extensions: BTreeMap::new(),
        }],
        specifications,
        implementation_offers,
        BTreeMap::new(),
    )
    .unwrap();

    let directory = tempfile::tempdir().unwrap();
    if !manifest.resources.is_empty() {
        fs::create_dir_all(directory.path().join("bin")).unwrap();
        fs::write(directory.path().join("bin/provider"), []).unwrap();
    }
    fs::write(
        directory.path().join("gooir-package.json"),
        write_manifest(&manifest).unwrap(),
    )
    .unwrap();

    let mut registry = PackageRegistry::default();
    let package = load_local_package(directory.path(), &registry, LoadLimits::default()).unwrap();
    registry.install(package).unwrap();
    registry
}

#[test]
fn a_fully_offered_chain_reports_nothing_blocking() {
    let graph = install_graph(
        vec![specification(capability("a_to_b"), "a", "b")],
        [capability("a_to_b")],
    );

    let report = diagnose(&graph, limits()).unwrap();
    assert_eq!(report.capabilities, 1);
    assert_eq!(report.offers, 1);
    assert_eq!(report.conformance_suites, 1);
    assert_eq!(report.blocking(), 0);
    assert_eq!(report.open_needs(), 0);
    assert_eq!(report.roots.len(), 1, "`a` must be supplied");
    assert_eq!(report.roots[0].value_kind, value_kind("a"));
    assert_eq!(report.terminals.len(), 1, "`b` is the answer");
    assert!(report.terminals[0].offered_route_exists);
}

#[test]
fn repeated_kind_ports_do_not_duplicate_root_requirements() {
    let repeated = CapabilitySpec {
        id: capability("compare_to_b"),
        input_ports: vec![
            InputPort::complete(port("left"), value_kind("a")),
            InputPort::complete(port("right"), value_kind("a")),
        ],
        output_ports: vec![OutputPort::new(port("result"), value_kind("b"))],
        default_conformance_suite: suite().to_string(),
        extensions: BTreeMap::new(),
    };
    let graph = install_graph(vec![repeated], [capability("compare_to_b")]);

    let report = diagnose(&graph, limits()).unwrap();
    assert_eq!(
        report.roots[0].required_by,
        vec![capability("compare_to_b")]
    );
    assert!(report.terminals[0].offered_route_exists);
}

#[test]
fn a_capability_without_an_offer_is_an_open_need() {
    let graph = install_graph(
        vec![
            specification(capability("a_to_b"), "a", "b"),
            specification(capability("b_to_c"), "b", "c"),
        ],
        [capability("a_to_b")],
    );

    let report = diagnose(&graph, limits()).unwrap();
    assert_eq!(report.open_needs(), 1);
    assert_eq!(
        report.unimplemented[0].package.to_string(),
        "test.package@1.0.0"
    );
    assert_eq!(report.unimplemented[0].capability, capability("b_to_c"));
    let terminal = report
        .terminals
        .iter()
        .find(|terminal| terminal.value_kind == value_kind("c"))
        .unwrap();
    assert!(!terminal.offered_route_exists);
    assert_eq!(terminal.unoffered_alternatives, vec![capability("b_to_c")]);
    assert_eq!(report.blocking(), 0, "a declared need is not unreachable");
}

#[test]
fn an_unoffered_alternative_does_not_block_an_offered_route() {
    let graph = install_graph(
        vec![
            specification(capability("a_to_m"), "a", "m"),
            specification(capability("k_to_m"), "k", "m"),
        ],
        [capability("a_to_m")],
    );

    let report = diagnose(&graph, limits()).unwrap();
    let terminal = report
        .terminals
        .iter()
        .find(|terminal| terminal.value_kind == value_kind("m"))
        .unwrap();
    assert!(terminal.offered_route_exists);
    assert_eq!(terminal.unoffered_alternatives, vec![capability("k_to_m")]);
}

#[test]
fn an_unseeded_cycle_is_unreachable() {
    let graph = install_graph(
        vec![CapabilitySpec {
            id: capability("cycle"),
            input_ports: vec![InputPort::complete(port("source"), value_kind("z"))],
            output_ports: vec![OutputPort::new(port("result"), value_kind("z"))],
            default_conformance_suite: suite().to_string(),
            extensions: BTreeMap::new(),
        }],
        [capability("cycle")],
    );

    let report = diagnose(&graph, limits()).unwrap();
    assert_eq!(report.unreachable.len(), 1);
    assert_eq!(report.unreachable[0].value_kind, value_kind("z"));
    assert_eq!(report.blocking(), 1);
}

#[test]
fn multiple_producers_are_visible_without_implicit_selection() {
    let graph = install_graph(
        vec![
            specification(capability("a_to_m"), "a", "m"),
            specification(capability("k_to_m"), "k", "m"),
        ],
        [capability("a_to_m"), capability("k_to_m")],
    );

    let report = diagnose(&graph, limits()).unwrap();
    assert_eq!(report.multiple_producers.len(), 1);
    assert_eq!(report.multiple_producers[0].value_kind, value_kind("m"));
    assert_eq!(
        report.multiple_producers[0].produced_by,
        vec![capability("a_to_m"), capability("k_to_m")]
    );
    assert!(
        report
            .to_string()
            .contains("multiple producers (1) — selection remains explicit")
    );
}

#[test]
fn rendering_is_deterministic_and_names_installed_availability() {
    let graph = install_graph(
        vec![
            specification(capability("a_to_b"), "a", "b"),
            specification(capability("b_to_c"), "b", "c"),
        ],
        [capability("a_to_b")],
    );

    let rendered = diagnose(&graph, limits()).unwrap().to_string();
    assert_eq!(
        rendered,
        concat!(
            "installed capability graph\n",
            "  2 capabilities, 1 implementation offers, 3 value kinds\n",
            "  1 referenced conformance suites\n",
            "\n",
            "you must supply (1)\n",
            "  test.fact/a@1.0.0\n",
            "    needed by 1\n",
            "\n",
            "terminal offer availability (1)\n",
            "  needs offer test.fact/c@1.0.0\n",
            "\n",
            "open needs — assignable implementation work (1)\n",
            "  test.capability/b_to_c@1.0.0\n",
            "    package  test.package@1.0.0\n",
            "    produces test.fact/c@1.0.0\n",
            "    suite    test.suite/default@1.0.0\n",
            "\n",
            "summary  0 unreachable, 1 open need(s)",
        )
    );
}
