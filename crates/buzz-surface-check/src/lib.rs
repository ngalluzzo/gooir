use std::fmt::Write;

use buzz_surface_profile::{BUZZ_REVISION, BUZZ_SOURCE_TAG, SOURCE_SCOPE_ID, job_surface_profile};
use buzz_surface_projection::{admit_pinned_surface, project_pinned_job_surface};
use gooir_analysis::SemanticResolver;
use semantics_software_surface_v1::RelationKind;
use surface_completeness_analysis::{
    SurfaceAnalysisReport, SurfaceCompletenessAnalyzer, SurfaceFinding, SurfaceFindingLevel,
};

pub const PROTOCOL_LIFT_NAME: &str = "job-protocol.lift.json";
pub const RELAY_LIFT_NAME: &str = "job-relay.lift.json";
pub const CLI_LIFT_NAME: &str = "job-cli.lift.json";

pub fn embedded_documents() -> (&'static [u8], &'static [u8], &'static [u8]) {
    (
        include_bytes!("../../../fixtures/buzz/desktop-v0.5.18/job-protocol.lift.json"),
        include_bytes!("../../../fixtures/buzz/desktop-v0.5.18/job-relay.lift.json"),
        include_bytes!("../../../fixtures/buzz/desktop-v0.5.18/job-cli.lift.json"),
    )
}

pub fn analyze_documents(
    protocol: &[u8],
    relay: &[u8],
    cli: &[u8],
) -> Result<SurfaceAnalysisReport, String> {
    let surface = project_pinned_job_surface(protocol, relay, cli)
        .map_err(|error| format!("Input changed after review; result is not admitted ({error})"))?;
    let policy = admit_pinned_surface(&surface)
        .map_err(|error| format!("Reviewed input could not be admitted ({error})"))?;
    Ok(
        SurfaceCompletenessAnalyzer::new(SemanticResolver::with_trust_policy(policy))
            .analyze(&surface.program, &job_surface_profile()),
    )
}

pub fn render_human(report: &SurfaceAnalysisReport) -> Result<String, String> {
    let relay = finding(report, "relay-accepts-43001")?;
    let declaration = relay
        .relation_basis
        .iter()
        .find(|basis| basis.relation.relation == RelationKind::Declares)
        .ok_or_else(|| "relay finding has no protocol declaration evidence".to_owned())?;
    let rejection = relay
        .relation_basis
        .iter()
        .find(|basis| basis.relation.relation == RelationKind::Rejects)
        .ok_or_else(|| "relay finding has no rejection evidence".to_owned())?;
    let unknown = report
        .findings
        .iter()
        .filter(|finding| finding.level == SurfaceFindingLevel::Unknown)
        .count();

    let mut output = String::new();
    writeln!(output, "Agent job request (kind 43001) | BROKEN")
        .expect("writing to a String cannot fail");
    writeln!(output).expect("writing to a String cannot fail");
    writeln!(
        output,
        "Declared  yes      {}",
        source_location(&declaration.source, "declaration:")
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "Produced  unknown  SDK builder coverage is not installed"
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "Accepted  no       {}",
        source_location(&rejection.source, "fallback=lines:")
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "Consumed  unknown  runtime dispatch coverage is not installed"
    )
    .expect("writing to a String cannot fail");
    writeln!(output).expect("writing to a String cannot fail");
    writeln!(output, "Impact").expect("writing to a String cannot fail");
    writeln!(
        output,
        "The protocol defines agent job requests, but the production relay rejects"
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "them before persistence. A client cannot complete this path through this relay."
    )
    .expect("writing to a String cannot fail");
    writeln!(output).expect("writing to a String cannot fail");
    writeln!(output, "Next action").expect("writing to a String cannot fail");
    writeln!(
        output,
        "Add or intentionally deny relay admission for job kinds 43001-43006, then"
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "re-run this check. Do not infer SDK/runtime safety from current coverage."
    )
    .expect("writing to a String cannot fail");
    writeln!(output).expect("writing to a String cannot fail");
    writeln!(output, "Scope").expect("writing to a String cannot fail");
    writeln!(
        output,
        "Buzz {BUZZ_SOURCE_TAG} @ {BUZZ_REVISION}; source only; {unknown} unknown requirements."
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "Run with --details for evidence or --json for the full report."
    )
    .expect("writing to a String cannot fail");
    Ok(output)
}

pub fn render_details(report: &SurfaceAnalysisReport) -> Result<String, String> {
    let relay = finding(report, "relay-accepts-43001")?;
    let sdk = finding(report, "sdk-constructs-43001")?;
    let runtime = finding(report, "runtime-dispatches-job-request")?;
    let cli = finding(report, "cli-exposes-job-protocol")?;
    let declaration = relay
        .relation_basis
        .iter()
        .find(|basis| basis.relation.relation == RelationKind::Declares)
        .ok_or_else(|| "relay finding has no protocol declaration evidence".to_owned())?;
    let rejection = relay
        .relation_basis
        .iter()
        .find(|basis| basis.relation.relation == RelationKind::Rejects)
        .ok_or_else(|| "relay finding has no rejection evidence".to_owned())?;
    let cli_coverage = cli
        .coverage_basis
        .first()
        .ok_or_else(|| "CLI finding has no exhaustive coverage evidence".to_owned())?;

    let actionable = report
        .findings
        .iter()
        .filter(|finding| finding.level == SurfaceFindingLevel::Error)
        .count();
    let unknown = report
        .findings
        .iter()
        .filter(|finding| finding.level == SurfaceFindingLevel::Unknown)
        .count();
    let other_relay_kinds = report
        .findings
        .iter()
        .filter(|finding| {
            finding.level == SurfaceFindingLevel::Error
                && finding.requirement_id.starts_with("relay-accepts-")
                && finding.requirement_id != "relay-accepts-43001"
        })
        .filter_map(|finding| finding.requirement_id.strip_prefix("relay-accepts-"))
        .collect::<Vec<_>>();
    let sdk_unknowns = report
        .findings
        .iter()
        .filter(|finding| {
            finding.level == SurfaceFindingLevel::Unknown
                && finding.requirement_id.starts_with("sdk-constructs-")
        })
        .count();
    let runtime_unknowns = report
        .findings
        .iter()
        .filter(|finding| {
            finding.level == SurfaceFindingLevel::Unknown
                && finding.requirement_id.starts_with("runtime-dispatches-")
        })
        .count();

    let mut output = String::new();
    writeln!(output, "GOOIR | Buzz agent job surface").expect("writing to a String cannot fail");
    writeln!(output).expect("writing to a String cannot fail");
    writeln!(output, "Target    Buzz {BUZZ_SOURCE_TAG}").expect("writing to a String cannot fail");
    writeln!(output, "Revision  {BUZZ_REVISION}").expect("writing to a String cannot fail");
    writeln!(output, "Scope     {SOURCE_SCOPE_ID}").expect("writing to a String cannot fail");
    writeln!(
        output,
        "Trust     exact reviewed protocol, relay, and CLI lift bytes admitted"
    )
    .expect("writing to a String cannot fail");
    writeln!(output).expect("writing to a String cannot fail");
    writeln!(output, "Path | agent job request (Nostr kind 43001)")
        .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  1 DECLARED  yes | the protocol declares this event kind"
    )
    .expect("writing to a String cannot fail");
    writeln!(output, "      {}", source_line(&declaration.source))
        .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  2 PRODUCED  unknown | SDK builder coverage has not been lifted"
    )
    .expect("writing to a String cannot fail");
    writeln!(output, "      {}", concise_reason(sdk)).expect("writing to a String cannot fail");
    writeln!(
        output,
        "  3 ACCEPTED  no | the production relay rejects this event kind"
    )
    .expect("writing to a String cannot fail");
    writeln!(output, "      {}", source_line(&rejection.source))
        .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  4 CONSUMED  unknown | runtime dispatch coverage has not been lifted"
    )
    .expect("writing to a String cannot fail");
    writeln!(output, "      {}", concise_reason(runtime)).expect("writing to a String cannot fail");
    writeln!(output).expect("writing to a String cannot fail");
    writeln!(output, "Other actionable gaps").expect("writing to a String cannot fail");
    writeln!(
        output,
        "  - relay also rejects job event kinds {}",
        other_relay_kinds.join(", ")
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  - CLI exposes no job command across its exhaustive command tree"
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "      searched roots: {}",
        cli_coverage.witness.source_roots.join(", ")
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "      included: {}",
        cli_coverage.witness.included_artifacts.join(", ")
    )
    .expect("writing to a String cannot fail");
    writeln!(output, "      {}", source_line(&cli_coverage.source))
        .expect("writing to a String cannot fail");
    writeln!(output).expect("writing to a String cannot fail");
    writeln!(output, "Unknowns kept honest").expect("writing to a String cannot fail");
    writeln!(
        output,
        "  - {sdk_unknowns} SDK construction requirements remain unknown"
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "  - {runtime_unknowns} runtime dispatch requirement remains unknown"
    )
    .expect("writing to a String cannot fail");
    writeln!(output).expect("writing to a String cannot fail");
    writeln!(
        output,
        "Summary | {actionable} actionable gaps, {unknown} unknowns"
    )
    .expect("writing to a String cannot fail");
    writeln!(
        output,
        "Next    | fix the relay acceptance edge, then re-lift and compare"
    )
    .expect("writing to a String cannot fail");
    Ok(output)
}

fn finding<'a>(
    report: &'a SurfaceAnalysisReport,
    requirement_id: &str,
) -> Result<&'a SurfaceFinding, String> {
    report
        .findings
        .iter()
        .find(|finding| finding.requirement_id == requirement_id)
        .ok_or_else(|| format!("expected finding {requirement_id} was not present"))
}

fn source_line(source: &gooir_core::SourceRef) -> String {
    format!(
        "source: {} @ {} | {}",
        source.artifact,
        source.revision,
        source.span.as_deref().unwrap_or("span unavailable")
    )
}

fn source_location(source: &gooir_core::SourceRef, marker: &str) -> String {
    let location = source
        .span
        .as_deref()
        .and_then(|span| span.split("; ").find(|part| part.starts_with(marker)))
        .and_then(|part| part.strip_prefix(marker))
        .and_then(|location| location.split_whitespace().next())
        .map(collapse_same_line_range)
        .unwrap_or("span unavailable");
    format!("{}:{location}", source.artifact)
}

fn collapse_same_line_range(location: &str) -> &str {
    match location.split_once('-') {
        Some((start, end)) if start == end => start,
        _ => location,
    }
}

fn concise_reason(finding: &SurfaceFinding) -> String {
    finding
        .message
        .split(": missing exhaustive mechanisms")
        .next()
        .unwrap_or(&finding.message)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::{analyze_documents, embedded_documents, render_details, render_human};

    #[test]
    fn embedded_demo_reports_the_product_path_and_honest_boundary() {
        let (protocol, relay, cli) = embedded_documents();
        let report = analyze_documents(protocol, relay, cli).expect("embedded inputs are admitted");
        let output = render_human(&report).expect("pinned report has the demo evidence");

        assert!(output.contains("Agent job request (kind 43001) | BROKEN"));
        assert!(output.contains("Declared  yes"));
        assert!(output.contains("Produced  unknown"));
        assert!(output.contains("Accepted  no"));
        assert!(output.contains("Consumed  unknown"));
        assert!(output.contains("A client cannot complete this path through this relay."));
        assert!(output.contains("Add or intentionally deny relay admission"));
        assert!(output.contains("7 unknown requirements"));
        assert!(output.contains("crates/buzz-relay/src/handlers/ingest.rs"));
        assert!(output.contains("crates/buzz-core/src/kind.rs:518"));
        assert!(output.contains("crates/buzz-relay/src/handlers/ingest.rs:453"));
        assert!(!output.contains("bytes"));
        assert!(
            output.lines().count() <= 24,
            "default output must fit on one screen"
        );

        let details = render_details(&report).expect("pinned report has full evidence");
        assert!(details.contains("Path | agent job request (Nostr kind 43001)"));
        assert!(details.contains("Summary | 7 actionable gaps, 7 unknowns"));
        assert!(details.contains("crates/buzz-cli/src"));
    }

    #[test]
    fn changing_a_reviewed_document_revokes_admission() {
        let (protocol, relay, cli) = embedded_documents();
        let mut changed_protocol = protocol.to_vec();
        changed_protocol.push(b'\n');

        let error = analyze_documents(&changed_protocol, relay, cli)
            .expect_err("altered reviewed bytes must not be admitted");

        assert!(error.contains("Input changed after review; result is not admitted"));
        assert!(error.contains("protocol native lift document mismatch"));
    }
}
