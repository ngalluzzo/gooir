use gooir_analysis::{
    AnalysisReport, BridgeRegistry, ClaimResolution, Finding, FindingLevel, SemanticResolver,
};
use gooir_core::{Operation, Program};
use semantics_effects_v1::{
    Delivery, Repeatability, external_effect_contract, parse_delivery, parse_repeatability,
    retry_boundary_contract,
};

pub struct RetrySafetyAnalyzer {
    resolver: SemanticResolver,
}

impl RetrySafetyAnalyzer {
    pub fn new() -> Self {
        Self {
            resolver: SemanticResolver::default(),
        }
    }

    pub fn with_bridges(bridges: BridgeRegistry) -> Self {
        Self {
            resolver: SemanticResolver::with_bridges(bridges),
        }
    }

    pub fn with_resolver(resolver: SemanticResolver) -> Self {
        Self { resolver }
    }

    pub fn analyze(&self, program: &Program) -> AnalysisReport {
        let mut report = AnalysisReport {
            analyzer: "org.gooi.analysis.retry_safety@1.0.0".to_owned(),
            findings: Vec::new(),
        };

        for operation in &program.operations {
            self.visit(operation, None, &mut report);
        }

        report
    }

    fn visit(
        &self,
        operation: &Operation,
        inherited_retry: Option<RetryContext>,
        report: &mut AnalysisReport,
    ) {
        let retry = self.retry_context(operation).or(inherited_retry);

        if let Some(retry) = &retry {
            self.check_effect(operation, retry, report);
        }

        for region in &operation.regions {
            for child in region {
                self.visit(child, retry.clone(), report);
            }
        }
    }

    fn retry_context(&self, operation: &Operation) -> Option<RetryContext> {
        match self.resolver.resolve(operation, &retry_boundary_contract()) {
            ClaimResolution::Trusted(claim) => parse_delivery(&claim.payload)
                .map(RetryContext::Known)
                .or_else(|| Some(RetryContext::Unknown("invalid retry payload".to_owned()))),
            ClaimResolution::Untrusted { .. } => Some(RetryContext::Unknown(
                "retry semantics are declared but unverified".to_owned(),
            )),
            ClaimResolution::VersionMismatch(_) => Some(RetryContext::Unknown(
                "retry contract version has no explicit bridge".to_owned(),
            )),
            ClaimResolution::Ambiguous(_) => Some(RetryContext::Unknown(
                "multiple retry claims are ambiguous".to_owned(),
            )),
            ClaimResolution::InvalidBridge(error) => Some(RetryContext::Unknown(format!(
                "retry contract bridge is invalid: {error}"
            ))),
            ClaimResolution::InvalidProjection(error) => Some(RetryContext::Unknown(format!(
                "retry contract projection is invalid: {error}"
            ))),
            ClaimResolution::Absent if !operation.regions.is_empty() => Some(
                RetryContext::Unknown("retry semantics are unresolved".to_owned()),
            ),
            ClaimResolution::Absent => None,
        }
    }

    fn check_effect(
        &self,
        operation: &Operation,
        retry: &RetryContext,
        report: &mut AnalysisReport,
    ) {
        match self
            .resolver
            .resolve(operation, &external_effect_contract())
        {
            ClaimResolution::Trusted(claim) => match parse_repeatability(&claim.payload) {
                Some(repeatability) => {
                    self.check_known_effect(operation, retry, repeatability, report)
                }
                None => report_unknown(operation, "external-effect payload is invalid", report),
            },
            ClaimResolution::Untrusted { .. } => report_unknown(
                operation,
                "external-effect semantics are declared but unverified",
                report,
            ),
            ClaimResolution::VersionMismatch(_) => report_unknown(
                operation,
                "external-effect contract version has no explicit bridge",
                report,
            ),
            ClaimResolution::Ambiguous(_) => report_unknown(
                operation,
                "multiple external-effect claims are ambiguous",
                report,
            ),
            ClaimResolution::InvalidBridge(error) => report_unknown(
                operation,
                &format!("external-effect contract bridge is invalid: {error}"),
                report,
            ),
            ClaimResolution::InvalidProjection(error) => report_unknown(
                operation,
                &format!("external-effect contract projection is invalid: {error}"),
                report,
            ),
            ClaimResolution::Absent => report_unknown(
                operation,
                "external-effect semantics are unresolved",
                report,
            ),
        }
    }

    fn check_known_effect(
        &self,
        operation: &Operation,
        retry: &RetryContext,
        repeatability: Repeatability,
        report: &mut AnalysisReport,
    ) {
        match (retry, repeatability) {
            (RetryContext::Known(Delivery::AtLeastOnce), Repeatability::NonIdempotent) => {
                report.findings.push(Finding {
                    code: "retry.non_idempotent_effect".to_owned(),
                    level: FindingLevel::Error,
                    operation_id: operation.id.clone(),
                    message:
                        "verified non-idempotent effect executes inside verified at-least-once retry"
                            .to_owned(),
                });
            }
            (RetryContext::Unknown(reason), Repeatability::NonIdempotent) => {
                report_unknown(operation, reason, report)
            }
            _ => {}
        }
    }
}

impl Default for RetrySafetyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
enum RetryContext {
    Known(Delivery),
    Unknown(String),
}

fn report_unknown(operation: &Operation, message: &str, report: &mut AnalysisReport) {
    report.findings.push(Finding {
        code: "retry.effect_safety_unknown".to_owned(),
        level: FindingLevel::Unknown,
        operation_id: operation.id.clone(),
        message: message.to_owned(),
    });
}
