//! Reports the health of a capability graph.
//!
//! GOOIR exists to find cross-layer gaps — a thing declared but not
//! producible, produced but never consumed, privileged without a gate. Its own
//! capability graph has exactly those pathologies, and until now the only way
//! to see them was to read Rust.
//!
//! This analyzer consumes a registry and nothing else. It knows no fact
//! meanings, no product, and no domain verbs.

pub mod declarations;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use gooir_capability::{AdmissionPolicy, CapabilityId, CapabilityRegistry, FactType, ProviderId};

/// A fact type nothing produces. Whoever runs a derivation must supply it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootFact {
    pub fact: FactType,
    /// Capabilities that require it.
    pub required_by: Vec<CapabilityId>,
}

/// A fact type nothing consumes. These are the graph's answers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalFact {
    pub fact: FactType,
    pub produced_by: Vec<CapabilityId>,
    /// True when at least one route from the roots is fully provided.
    pub obtainable: bool,
    /// Capabilities on the route that have no provider. A terminal blocked
    /// solely by these is *accounted for*, not broken: that is what an open
    /// need means.
    pub blocked_by: Vec<CapabilityId>,
}

/// A capability nobody implements. This is a work contract, not a defect --
/// but an unbounded number of them is.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnimplementedCapability {
    pub capability: CapabilityId,
    pub produces: Vec<FactType>,
    pub conformance_suite: String,
}

/// A fact type that no route from the root set can reach at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnreachableFact {
    pub fact: FactType,
    pub reason: String,
}

/// More than one capability produces this fact. Not a fault: it is how an
/// authored specification and a lifted document reach one waist. Worth seeing,
/// because the planner silently picks one by score.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AmbiguousFact {
    pub fact: FactType,
    pub produced_by: Vec<CapabilityId>,
}

/// A registered provider whose outputs are not yet admissible, because
/// registration is not conformance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnadmittedProvider {
    pub provider: ProviderId,
    pub capability: CapabilityId,
    pub conformance_suite: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Report {
    pub capabilities: usize,
    pub providers: usize,
    pub fact_types: usize,
    pub roots: Vec<RootFact>,
    pub terminals: Vec<TerminalFact>,
    pub unimplemented: Vec<UnimplementedCapability>,
    pub unreachable: Vec<UnreachableFact>,
    pub ambiguous: Vec<AmbiguousFact>,
    pub unadmitted: Vec<UnadmittedProvider>,
    /// Attesters this host admits results from. Zero means no produced fact can
    /// become an admitted one, whatever a verifier reports.
    pub admitted_attesters: usize,
}

impl Report {
    /// Findings the graph cannot explain: a fact it describes but cannot route
    /// to, or a terminal blocked for a reason other than a declared need.
    ///
    /// A terminal blocked only by provider-less capabilities is deliberately
    /// *not* counted. Those are the assignable work items, and a tool that
    /// fails because work remains would be useless.
    pub fn blocking(&self) -> usize {
        let declared: BTreeSet<&CapabilityId> =
            self.unimplemented.iter().map(|u| &u.capability).collect();
        self.unreachable.len()
            + self
                .terminals
                .iter()
                .filter(|t| !t.obtainable)
                .filter(|t| t.blocked_by.iter().any(|c| !declared.contains(c)))
                .count()
    }

    /// Findings that are honest gaps rather than faults.
    pub fn open_needs(&self) -> usize {
        self.unimplemented.len()
    }
}

/// The report renders itself, so there is one rendering rather than one per
/// caller. Two of them drifted once already: a standalone binary printed the
/// whole graph while `gooir doctor` printed two lines, and the difference was
/// invisible until someone ran both.
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "capability graph")?;
        writeln!(
            f,
            "  {} capabilities, {} providers, {} fact types",
            self.capabilities, self.providers, self.fact_types
        )?;

        writeln!(f, "\nyou must supply ({})", self.roots.len())?;
        for root in &self.roots {
            writeln!(f, "  {}", root.fact)?;
            writeln!(f, "    needed by {}", root.required_by.len())?;
        }

        writeln!(f, "\nyou can obtain ({})", self.terminals.len())?;
        for terminal in &self.terminals {
            writeln!(
                f,
                "  {:<7} {}",
                if terminal.obtainable { "yes" } else { "needs" },
                terminal.fact
            )?;
            for capability in &terminal.blocked_by {
                writeln!(f, "          waiting on {capability}")?;
            }
        }

        if !self.unimplemented.is_empty() {
            writeln!(
                f,
                "\nopen needs — assignable work ({})",
                self.unimplemented.len()
            )?;
            for need in &self.unimplemented {
                writeln!(f, "  {}", need.capability)?;
                for produced in &need.produces {
                    writeln!(f, "    produces {produced}")?;
                }
                writeln!(f, "    suite    {}", need.conformance_suite)?;
            }
        }

        if !self.unreachable.is_empty() {
            writeln!(f, "\nUNREACHABLE ({})", self.unreachable.len())?;
            for fact in &self.unreachable {
                writeln!(f, "  {}  ({})", fact.fact, fact.reason)?;
            }
        }

        if !self.ambiguous.is_empty() {
            writeln!(
                f,
                "\nmultiple routes ({}) — the planner picks by score",
                self.ambiguous.len()
            )?;
            for fact in &self.ambiguous {
                writeln!(f, "  {}", fact.fact)?;
                for capability in &fact.produced_by {
                    writeln!(f, "    via {capability}")?;
                }
            }
        }

        writeln!(f, "\nadmission")?;
        writeln!(
            f,
            "  {} attester(s) admitted by this host",
            self.admitted_attesters
        )?;
        writeln!(
            f,
            "  {} provider(s) whose outputs are not admissible yet",
            self.unadmitted.len()
        )?;
        if self.admitted_attesters == 0 && !self.unadmitted.is_empty() {
            writeln!(
                f,
                "  -> no produced fact can become admitted, whatever a verifier reports"
            )?;
        }
        for provider in &self.unadmitted {
            writeln!(
                f,
                "    {} needs {}",
                provider.provider.name, provider.conformance_suite
            )?;
        }

        write!(
            f,
            "\nsummary  {} blocking, {} open need(s), {} unadmitted provider(s)",
            self.blocking(),
            self.open_needs(),
            self.unadmitted.len()
        )
    }
}

/// Diagnoses against an empty admission policy: the honest default for a host
/// that has not stated one.
pub fn diagnose(registry: &CapabilityRegistry) -> Report {
    diagnose_with_policy(registry, &AdmissionPolicy::default())
}

pub fn diagnose_with_policy(registry: &CapabilityRegistry, policy: &AdmissionPolicy) -> Report {
    let mut produced_by: BTreeMap<FactType, Vec<CapabilityId>> = BTreeMap::new();
    let mut required_by: BTreeMap<FactType, Vec<CapabilityId>> = BTreeMap::new();
    let mut all: BTreeSet<FactType> = BTreeSet::new();
    let mut capabilities = 0usize;

    for spec in registry.specs() {
        capabilities += 1;
        for out in &spec.produces {
            produced_by
                .entry(out.clone())
                .or_default()
                .push(spec.id.clone());
            all.insert(out.clone());
        }
        for req in &spec.requires {
            required_by
                .entry(req.fact.clone())
                .or_default()
                .push(spec.id.clone());
            all.insert(req.fact.clone());
        }
    }

    let descriptors = registry.provider_descriptors();
    let implemented: BTreeSet<CapabilityId> =
        descriptors.iter().map(|d| d.capability.clone()).collect();

    let roots: Vec<RootFact> = required_by
        .iter()
        .filter(|(fact, _)| !produced_by.contains_key(*fact))
        .map(|(fact, required_by)| RootFact {
            fact: fact.clone(),
            required_by: required_by.clone(),
        })
        .collect();
    let root_types: Vec<FactType> = roots.iter().map(|r| r.fact.clone()).collect();

    let mut unreachable = Vec::new();
    let mut terminals = Vec::new();
    for fact in &all {
        let is_root = !produced_by.contains_key(fact);
        match registry.plan(root_types.clone(), fact) {
            Ok(plan) => {
                if !required_by.contains_key(fact) && !is_root {
                    terminals.push(TerminalFact {
                        fact: fact.clone(),
                        produced_by: produced_by.get(fact).cloned().unwrap_or_default(),
                        obtainable: plan.is_executable(),
                        blocked_by: plan
                            .steps
                            .iter()
                            .filter(|s| s.provider.is_none())
                            .map(|s| s.capability.clone())
                            .collect(),
                    });
                }
            }
            Err(error) => {
                if !is_root {
                    unreachable.push(UnreachableFact {
                        fact: fact.clone(),
                        reason: error.to_string(),
                    });
                }
            }
        }
    }

    let unimplemented: Vec<UnimplementedCapability> = registry
        .specs()
        .filter(|spec| !implemented.contains(&spec.id))
        .map(|spec| UnimplementedCapability {
            capability: spec.id.clone(),
            produces: spec.produces.clone(),
            conformance_suite: spec.default_conformance_suite.clone(),
        })
        .collect();

    let ambiguous: Vec<AmbiguousFact> = produced_by
        .iter()
        .filter(|(_, by)| by.len() > 1)
        .map(|(fact, by)| AmbiguousFact {
            fact: fact.clone(),
            produced_by: by.clone(),
        })
        .collect();

    // The registry records the suite a provider would have to pass; it holds no
    // admission. Every registered provider is therefore unadmitted until an
    // external conformance result is verified against it.
    let suites: BTreeMap<CapabilityId, String> = registry
        .specs()
        .map(|s| (s.id.clone(), s.default_conformance_suite.clone()))
        .collect();
    let unadmitted: Vec<UnadmittedProvider> = descriptors
        .iter()
        .map(|d| UnadmittedProvider {
            provider: d.id.clone(),
            capability: d.capability.clone(),
            conformance_suite: suites.get(&d.capability).cloned().unwrap_or_default(),
        })
        .collect();

    Report {
        capabilities,
        providers: descriptors.len(),
        fact_types: all.len(),
        roots,
        terminals,
        unimplemented,
        unreachable,
        ambiguous,
        unadmitted,
        admitted_attesters: policy.admitted().len(),
    }
}
