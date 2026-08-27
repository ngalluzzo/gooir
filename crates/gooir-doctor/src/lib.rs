//! Provider-neutral diagnostics over an installed GOOIR package graph.
//!
//! The doctor inspects exact capability declarations and implementation offers
//! already admitted to a [`gooir_package::PackageRegistry`]. It uses the same
//! bounded [`gooir_planning::SemanticPlanner`] as callers, but it never selects
//! a route or offer, executes an implementation, establishes conformance, or
//! admits a fact.

pub mod declarations;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use gooir_capability::protocol::ConformanceSuiteId;
use gooir_capability::{CapabilityId, ValueKindId};
use gooir_package::{PackageId, PackageRegistry};
use gooir_planning::{PlanLimits, PlanningError, SemanticPlan, SemanticPlanner};

/// A value kind nothing in the installed graph produces. A caller must supply
/// an admitted fact of this kind before a route requiring it can be linked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootValueKind {
    pub value_kind: ValueKindId,
    pub required_by: Vec<CapabilityId>,
}

/// A produced value kind nothing in the installed graph consumes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalValueKind {
    pub value_kind: ValueKindId,
    pub produced_by: Vec<CapabilityId>,
    /// Whether at least one complete semantic route has an implementation
    /// offer for every capability it needs.
    pub offered_route_exists: bool,
    /// Providerless alternatives retained in the target's complete semantic
    /// plan. Their presence does not imply that every route is blocked.
    pub unoffered_alternatives: Vec<CapabilityId>,
}

/// A declared capability with no installed implementation offer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnimplementedCapability {
    pub package: PackageId,
    pub capability: CapabilityId,
    pub produces: Vec<ValueKindId>,
    pub conformance_suite: ConformanceSuiteId,
}

/// A value kind that no declared route from the installed root set reaches.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnreachableValueKind {
    pub value_kind: ValueKindId,
    pub reason: String,
}

/// More than one capability can produce this value kind. This is availability
/// information, not an instruction to rank or select one of them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultipleProducers {
    pub value_kind: ValueKindId,
    pub produced_by: Vec<CapabilityId>,
}

/// Deterministic diagnostics for one exact installed planning inventory.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Report {
    pub capabilities: usize,
    pub offers: usize,
    /// Value kinds referenced by installed capability ports.
    pub value_kinds: usize,
    /// Exact conformance suites referenced by installed capabilities.
    pub conformance_suites: usize,
    pub roots: Vec<RootValueKind>,
    pub terminals: Vec<TerminalValueKind>,
    pub unimplemented: Vec<UnimplementedCapability>,
    pub unreachable: Vec<UnreachableValueKind>,
    pub multiple_producers: Vec<MultipleProducers>,
}

impl Report {
    /// Semantic declarations that cannot be reached from the graph's roots.
    #[must_use]
    pub fn blocking(&self) -> usize {
        self.unreachable.len()
    }

    /// Declared capabilities awaiting at least one implementation offer.
    #[must_use]
    pub fn open_needs(&self) -> usize {
        self.unimplemented.len()
    }
}

impl fmt::Display for Report {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "installed capability graph")?;
        writeln!(
            formatter,
            "  {} capabilities, {} implementation offers, {} value kinds",
            self.capabilities, self.offers, self.value_kinds
        )?;
        writeln!(
            formatter,
            "  {} referenced conformance suites",
            self.conformance_suites
        )?;

        writeln!(formatter, "\nyou must supply ({})", self.roots.len())?;
        for root in &self.roots {
            writeln!(formatter, "  {}", root.value_kind)?;
            writeln!(formatter, "    needed by {}", root.required_by.len())?;
        }

        writeln!(
            formatter,
            "\nterminal offer availability ({})",
            self.terminals.len()
        )?;
        for terminal in &self.terminals {
            writeln!(
                formatter,
                "  {:<11} {}",
                if terminal.offered_route_exists {
                    "available"
                } else {
                    "needs offer"
                },
                terminal.value_kind
            )?;
        }

        if !self.unimplemented.is_empty() {
            writeln!(
                formatter,
                "\nopen needs — assignable implementation work ({})",
                self.unimplemented.len()
            )?;
            for need in &self.unimplemented {
                writeln!(formatter, "  {}", need.capability)?;
                writeln!(formatter, "    package  {}", need.package)?;
                for produced in &need.produces {
                    writeln!(formatter, "    produces {produced}")?;
                }
                writeln!(formatter, "    suite    {}", need.conformance_suite)?;
            }
        }

        if !self.unreachable.is_empty() {
            writeln!(formatter, "\nUNREACHABLE ({})", self.unreachable.len())?;
            for value_kind in &self.unreachable {
                writeln!(
                    formatter,
                    "  {}  ({})",
                    value_kind.value_kind, value_kind.reason
                )?;
            }
        }

        if !self.multiple_producers.is_empty() {
            writeln!(
                formatter,
                "\nmultiple producers ({}) — selection remains explicit",
                self.multiple_producers.len()
            )?;
            for value_kind in &self.multiple_producers {
                writeln!(formatter, "  {}", value_kind.value_kind)?;
                for capability in &value_kind.produced_by {
                    writeln!(formatter, "    via {capability}")?;
                }
            }
        }

        write!(
            formatter,
            "\nsummary  {} unreachable, {} open need(s)",
            self.blocking(),
            self.open_needs()
        )
    }
}

/// Why an installed package graph could not be diagnosed conservatively.
#[derive(Debug)]
pub enum DiagnosisError {
    Planning(PlanningError),
    InvalidConformanceSuite {
        capability: CapabilityId,
        suite: String,
        detail: String,
    },
}

impl fmt::Display for DiagnosisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Planning(error) => error.fmt(formatter),
            Self::InvalidConformanceSuite {
                capability,
                suite,
                detail,
            } => write!(
                formatter,
                "capability {capability} references invalid conformance suite `{suite}`: {detail}"
            ),
        }
    }
}

impl std::error::Error for DiagnosisError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Planning(error) => Some(error),
            Self::InvalidConformanceSuite { .. } => None,
        }
    }
}

impl From<PlanningError> for DiagnosisError {
    fn from(error: PlanningError) -> Self {
        Self::Planning(error)
    }
}

/// Diagnoses one exact installed package inventory under caller-selected
/// planning bounds.
///
/// The bounds are mandatory because constructing the complete provider-neutral
/// planning inventory is itself bounded host work. No route or implementation
/// is selected while producing this report.
pub fn diagnose(registry: &PackageRegistry, limits: PlanLimits) -> Result<Report, DiagnosisError> {
    let planner = SemanticPlanner::from_registry(registry, limits)?;
    let installed = registry.capabilities().collect::<Vec<_>>();

    let mut produced_by: BTreeMap<ValueKindId, Vec<CapabilityId>> = BTreeMap::new();
    let mut required_by: BTreeMap<ValueKindId, Vec<CapabilityId>> = BTreeMap::new();
    let mut all = BTreeSet::new();
    let mut conformance_suites = BTreeSet::new();

    for (_package, specification) in &installed {
        let suite = ConformanceSuiteId::parse(&specification.default_conformance_suite).map_err(
            |error| DiagnosisError::InvalidConformanceSuite {
                capability: specification.id.clone(),
                suite: specification.default_conformance_suite.clone(),
                detail: error.to_string(),
            },
        )?;
        conformance_suites.insert(suite);
        for port in &specification.output_ports {
            produced_by
                .entry(port.value_kind.clone())
                .or_default()
                .push(specification.id.clone());
            all.insert(port.value_kind.clone());
        }
        for port in &specification.input_ports {
            required_by
                .entry(port.value_kind.clone())
                .or_default()
                .push(specification.id.clone());
            all.insert(port.value_kind.clone());
        }
    }
    canonicalize_capability_lists(&mut produced_by);
    canonicalize_capability_lists(&mut required_by);

    let mut offer_counts: BTreeMap<CapabilityId, usize> = BTreeMap::new();
    let mut offers = 0_usize;
    for offer in registry.offers() {
        offers += 1;
        *offer_counts.entry(offer.capability.clone()).or_default() += 1;
    }

    let roots = required_by
        .iter()
        .filter(|(value_kind, _)| !produced_by.contains_key(*value_kind))
        .map(|(value_kind, required_by)| RootValueKind {
            value_kind: value_kind.clone(),
            required_by: required_by.clone(),
        })
        .collect::<Vec<_>>();
    let initial_value_kinds = roots
        .iter()
        .map(|root| root.value_kind.clone())
        .collect::<Vec<_>>();

    let mut unreachable = Vec::new();
    let mut terminals = Vec::new();
    for value_kind in &all {
        let is_root = !produced_by.contains_key(value_kind);
        match planner.plan(initial_value_kinds.clone(), value_kind.clone()) {
            Ok(plan) => {
                if !required_by.contains_key(value_kind) && !is_root {
                    terminals.push(TerminalValueKind {
                        value_kind: value_kind.clone(),
                        produced_by: produced_by.get(value_kind).cloned().unwrap_or_default(),
                        offered_route_exists: offered_route_exists(&plan),
                        unoffered_alternatives: plan
                            .needs()
                            .map(|specification| specification.id.clone())
                            .collect(),
                    });
                }
            }
            Err(PlanningError::Unreachable(_)) if !is_root => {
                unreachable.push(UnreachableValueKind {
                    value_kind: value_kind.clone(),
                    reason: "no declared route from the installed root set".to_owned(),
                });
            }
            Err(PlanningError::Unreachable(_)) => {}
            Err(error) => return Err(error.into()),
        }
    }

    let unimplemented = installed
        .iter()
        .filter(|(_package, specification)| !offer_counts.contains_key(&specification.id))
        .map(|(package, specification)| {
            let conformance_suite = ConformanceSuiteId::parse(
                &specification.default_conformance_suite,
            )
            .map_err(|error| DiagnosisError::InvalidConformanceSuite {
                capability: specification.id.clone(),
                suite: specification.default_conformance_suite.clone(),
                detail: error.to_string(),
            })?;
            let mut produces = specification
                .output_ports
                .iter()
                .map(|port| port.value_kind.clone())
                .collect::<Vec<_>>();
            produces.sort();
            produces.dedup();
            Ok(UnimplementedCapability {
                package: (*package).clone(),
                capability: specification.id.clone(),
                produces,
                conformance_suite,
            })
        })
        .collect::<Result<Vec<_>, DiagnosisError>>()?;

    let multiple_producers = produced_by
        .iter()
        .filter(|(_value_kind, capabilities)| capabilities.len() > 1)
        .map(|(value_kind, capabilities)| MultipleProducers {
            value_kind: value_kind.clone(),
            produced_by: capabilities.clone(),
        })
        .collect();

    Ok(Report {
        capabilities: installed.len(),
        offers,
        value_kinds: all.len(),
        conformance_suites: conformance_suites.len(),
        roots,
        terminals,
        unimplemented,
        unreachable,
        multiple_producers,
    })
}

fn canonicalize_capability_lists(index: &mut BTreeMap<ValueKindId, Vec<CapabilityId>>) {
    for capabilities in index.values_mut() {
        capabilities.sort();
        capabilities.dedup();
    }
}

/// Computes existential offer availability over the plan's AND/OR hypergraph.
/// Providerless alternatives cannot make an already complete route unavailable.
fn offered_route_exists(plan: &SemanticPlan) -> bool {
    let mut available = plan
        .initial_value_kinds
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut changed = true;
    while changed {
        changed = false;
        for planned in &plan.capabilities {
            if planned.offers.is_empty()
                || !planned
                    .specification
                    .input_ports
                    .iter()
                    .all(|port| available.contains(&port.value_kind))
            {
                continue;
            }
            for output in &planned.specification.output_ports {
                changed |= available.insert(output.value_kind.clone());
            }
        }
    }
    available.contains(&plan.target_value_kind)
}
