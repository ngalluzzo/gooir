use gooir_core::{Claim, ContractId, Operation, Program};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FindingLevel {
    Error,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub code: String,
    pub level: FindingLevel,
    pub operation_id: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AnalysisReport {
    pub analyzer: String,
    pub findings: Vec<Finding>,
}

impl AnalysisReport {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

pub trait ClaimBridge: Send + Sync {
    fn from(&self) -> ContractId;
    fn to(&self) -> ContractId;
    fn convert(&self, claim: &Claim) -> Result<Claim, String>;
}

/// Late-bound projection from a native operation into one semantic contract.
/// An analyzer consumes only the resulting claim; it never sees projection
/// implementation details.
pub trait ContractProjection: Send + Sync {
    fn target(&self) -> ContractId;
    fn project(&self, operation: &Operation) -> Result<Option<Claim>, String>;
}

#[derive(Default)]
pub struct BridgeRegistry {
    bridges: Vec<Box<dyn ClaimBridge>>,
}

impl BridgeRegistry {
    pub fn register(&mut self, bridge: impl ClaimBridge + 'static) {
        self.bridges.push(Box::new(bridge));
    }
}

#[derive(Default)]
pub struct ProjectionRegistry {
    projections: Vec<Box<dyn ContractProjection>>,
}

impl ProjectionRegistry {
    pub fn register(&mut self, projection: impl ContractProjection + 'static) {
        self.projections.push(Box::new(projection));
    }
}

#[derive(Default)]
pub struct SemanticResolver {
    bridges: BridgeRegistry,
    projections: ProjectionRegistry,
}

impl SemanticResolver {
    pub fn with_bridges(bridges: BridgeRegistry) -> Self {
        Self {
            bridges,
            projections: ProjectionRegistry::default(),
        }
    }

    pub fn register_bridge(&mut self, bridge: impl ClaimBridge + 'static) {
        self.bridges.register(bridge);
    }

    pub fn register_projection(&mut self, projection: impl ContractProjection + 'static) {
        self.projections.register(projection);
    }

    pub fn resolve(&self, operation: &Operation, expected: &ContractId) -> ClaimResolution {
        let mut claims = operation.claims.clone();

        for projection in &self.projections.projections {
            let target = projection.target();
            if target == *expected || target.is_other_version_of(expected) {
                match projection.project(operation) {
                    Ok(Some(claim)) if claim.contract == target => claims.push(claim),
                    Ok(Some(claim)) => {
                        return ClaimResolution::InvalidProjection(format!(
                            "projection produced {}@{} instead of its declared target {}@{}",
                            claim.contract.name,
                            claim.contract.version,
                            target.name,
                            target.version
                        ));
                    }
                    Ok(None) => {}
                    Err(error) => return ClaimResolution::InvalidProjection(error),
                }
            }
        }

        let exact = claims
            .iter()
            .filter(|claim| claim.contract == *expected)
            .cloned()
            .collect::<Vec<_>>();

        match exact.as_slice() {
            [claim] => return classify(claim.clone()),
            claims if claims.len() > 1 => {
                return ClaimResolution::Ambiguous(
                    claims.iter().map(|claim| claim.contract.clone()).collect(),
                );
            }
            _ => {}
        }

        let related = claims
            .iter()
            .filter(|claim| claim.contract.is_other_version_of(expected))
            .collect::<Vec<_>>();

        let mut converted = Vec::new();
        for claim in &related {
            for bridge in &self.bridges.bridges {
                if bridge.from() == claim.contract && bridge.to() == *expected {
                    match bridge.convert(claim) {
                        Ok(converted_claim) if converted_claim.contract == *expected => {
                            converted.push(converted_claim);
                        }
                        Ok(converted_claim) => {
                            return ClaimResolution::InvalidBridge(format!(
                                "bridge produced {}@{} instead of {}@{}",
                                converted_claim.contract.name,
                                converted_claim.contract.version,
                                expected.name,
                                expected.version
                            ));
                        }
                        Err(error) => return ClaimResolution::InvalidBridge(error),
                    }
                }
            }
        }

        match converted.as_slice() {
            [claim] => classify(claim.clone()),
            claims if claims.len() > 1 => ClaimResolution::Ambiguous(
                claims.iter().map(|claim| claim.contract.clone()).collect(),
            ),
            _ if !related.is_empty() => ClaimResolution::VersionMismatch(
                related.iter().map(|claim| claim.contract.clone()).collect(),
            ),
            _ => ClaimResolution::Absent,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ClaimResolution {
    Trusted(Claim),
    Untrusted(Claim),
    VersionMismatch(Vec<ContractId>),
    Ambiguous(Vec<ContractId>),
    InvalidBridge(String),
    InvalidProjection(String),
    Absent,
}

fn classify(claim: Claim) -> ClaimResolution {
    if claim.evidence.is_verified() {
        ClaimResolution::Trusted(claim)
    } else {
        ClaimResolution::Untrusted(claim)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Legality {
    Legal,
    Pinned { reason: String },
    Unknown { reason: String },
}

/// Target packs provide this semantic decision. The generic traversal only
/// records the exact frontier; it does not know why an operation is legal.
pub trait LegalityOracle {
    fn classify(&self, operation: &Operation) -> Legality;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrontierEntry {
    pub operation_id: String,
    pub path: String,
    pub legality: Legality,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PortabilityFrontier {
    pub entries: Vec<FrontierEntry>,
}

pub fn portability_frontier(
    program: &Program,
    oracle: &impl LegalityOracle,
) -> PortabilityFrontier {
    let mut frontier = PortabilityFrontier::default();

    for (operation_index, operation) in program.operations.iter().enumerate() {
        visit_legality(
            operation,
            format!("operations[{operation_index}]"),
            oracle,
            &mut frontier,
        );
    }

    frontier
}

fn visit_legality(
    operation: &Operation,
    path: String,
    oracle: &impl LegalityOracle,
    frontier: &mut PortabilityFrontier,
) {
    let legality = oracle.classify(operation);
    if legality != Legality::Legal {
        frontier.entries.push(FrontierEntry {
            operation_id: operation.id.clone(),
            path: path.clone(),
            legality,
        });
        return;
    }

    for (region_index, region) in operation.regions.iter().enumerate() {
        for (operation_index, child) in region.iter().enumerate() {
            visit_legality(
                child,
                format!("{path}.regions[{region_index}][{operation_index}]"),
                oracle,
                frontier,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Legality, LegalityOracle, portability_frontier};
    use gooir_core::{Operation, Program};

    struct FixtureTarget;

    impl LegalityOracle for FixtureTarget {
        fn classify(&self, operation: &Operation) -> Legality {
            match operation.name.as_str() {
                "portable" => Legality::Legal,
                "target_specific" => Legality::Pinned {
                    reason: "requires target.alpha capability".to_owned(),
                },
                _ => Legality::Unknown {
                    reason: "no installed legality rule".to_owned(),
                },
            }
        }
    }

    #[test]
    fn partial_legality_reports_the_exact_portability_frontier() {
        let program = Program::new(vec![
            Operation::new("root", "fixture", "portable").with_region(vec![
                Operation::new("portable-child", "fixture", "portable"),
                Operation::new("pinned-child", "fixture", "target_specific"),
                Operation::new("opaque-child", "unknown", "opaque"),
            ]),
        ]);

        let frontier = portability_frontier(&program, &FixtureTarget);

        assert_eq!(frontier.entries.len(), 2);
        assert_eq!(frontier.entries[0].operation_id, "pinned-child");
        assert_eq!(frontier.entries[0].path, "operations[0].regions[0][1]");
        assert_eq!(frontier.entries[1].operation_id, "opaque-child");
        assert_eq!(frontier.entries[1].path, "operations[0].regions[0][2]");
        assert!(matches!(
            frontier.entries[1].legality,
            Legality::Unknown { .. }
        ));
    }
}
