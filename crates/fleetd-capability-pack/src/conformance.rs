//! Independent conformance for Fleetd's first runnable web artifact.
//!
//! The producer only proposes an exact Git revision and content-addressed
//! served assets. This verifier checks out that revision from a trusted local
//! repository, verifies the manifest, then injects and runs a verifier-owned
//! black-box test. Candidate-authored tests are not evidence for admission.

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use gooir_capability::{
    CapabilityCandidate, CapabilityConformanceProvider, CapabilityRequest, ConformanceCheck,
    ConformanceOutcome, ConformanceProviderDescriptor, ProviderId,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const RUNNABLE_WEB_ARTIFACT_SCHEMA: &str = "dev.fleetd.artifact.runnable_web_surface/v1";
const SUITE: &str = "dev.fleetd.conformance/runnable_web_surface@0.2.0";
const ENTRYPOINT: &str = "/operator/";
const CHECK_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_PROCESS_EVIDENCE_BYTES: usize = 16 * 1024;

const EXPECTED_ASSETS: [(&str, &str); 4] = [
    ("web/operator/contract.json", "application/json"),
    ("web/operator/index.html", "text/html; charset=utf-8"),
    ("web/operator/operator.css", "text/css; charset=utf-8"),
    ("web/operator/operator.js", "text/javascript; charset=utf-8"),
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitArtifactSource {
    pub authority: String,
    pub revision: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFile {
    pub path: String,
    pub media_type: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnableWebArtifact {
    pub schema: String,
    pub source: GitArtifactSource,
    pub target_input_id: String,
    pub entrypoint: String,
    pub assets: Vec<ArtifactFile>,
}

/// Verifies candidates only against the repository root supplied by the
/// operator. A candidate cannot redirect conformance to another checkout.
pub struct RunnableWebConformanceProvider {
    repository_root: PathBuf,
}

impl RunnableWebConformanceProvider {
    #[must_use]
    pub fn new(repository_root: impl Into<PathBuf>) -> Self {
        Self {
            repository_root: repository_root.into(),
        }
    }
}

impl CapabilityConformanceProvider for RunnableWebConformanceProvider {
    fn descriptor(&self) -> ConformanceProviderDescriptor {
        ConformanceProviderDescriptor {
            id: ProviderId::new(
                "dev.fleetd.conformance_provider",
                "runnable_web_surface_git",
                "0.2.0",
            ),
            suite: SUITE.to_owned(),
            implementation_digest: implementation_digest(),
        }
    }

    fn verify(
        &self,
        request: &CapabilityRequest,
        candidate: &CapabilityCandidate,
    ) -> Result<Vec<ConformanceCheck>, String> {
        let target = request
            .body
            .inputs
            .first()
            .ok_or_else(|| "runnable web request has no bound target input".to_owned())?;
        let output = candidate
            .body
            .outputs
            .first()
            .ok_or_else(|| "runnable web candidate has no output".to_owned())?;
        let artifact: RunnableWebArtifact = match serde_json::from_value(output.payload.clone()) {
            Ok(artifact) => artifact,
            Err(error) => {
                return Ok(vec![failed(
                    "artifact_contract",
                    json!({"reason": error.to_string()}),
                )]);
            }
        };
        let trusted_root = match fs::canonicalize(&self.repository_root) {
            Ok(root) => root,
            Err(error) => {
                return Ok(vec![failed(
                    "trusted_repository",
                    json!({"reason": error.to_string()}),
                )]);
            }
        };
        let expected_authority = format!("git:{}", trusted_root.display());
        let contract_errors = validate_artifact(&artifact, &expected_authority, &target.id);
        let mut checks = vec![check(
            "artifact_contract",
            contract_errors.is_empty(),
            json!({
                "schema": artifact.schema,
                "entrypoint": artifact.entrypoint,
                "target_input_id": artifact.target_input_id,
                "errors": contract_errors,
            }),
        )];
        if checks[0].outcome == ConformanceOutcome::Failed {
            return Ok(checks);
        }

        let checkout = tempfile::tempdir().map_err(|error| error.to_string())?;
        let checkout_root = checkout.path().join("fleetd");
        let clone = run_bounded(
            Command::new("git")
                .args(["clone", "--quiet", "--no-checkout", "--"])
                .arg(&trusted_root)
                .arg(&checkout_root),
            checkout.path(),
            Duration::from_secs(60),
        )?;
        if !clone.success {
            checks.push(failed("git_revision", clone.evidence()));
            return Ok(checks);
        }
        let checkout_result = run_bounded(
            Command::new("git")
                .arg("-C")
                .arg(&checkout_root)
                .args([
                    "-c",
                    "advice.detachedHead=false",
                    "checkout",
                    "--quiet",
                    "--detach",
                ])
                .arg(&artifact.source.revision),
            checkout.path(),
            Duration::from_secs(60),
        )?;
        if !checkout_result.success {
            checks.push(failed("git_revision", checkout_result.evidence()));
            return Ok(checks);
        }
        let observed_revision = git_text(&checkout_root, &["rev-parse", "HEAD"])?;
        let pristine = git_text(&checkout_root, &["status", "--porcelain"])?;
        let revision_matches = observed_revision == artifact.source.revision && pristine.is_empty();
        checks.push(check(
            "git_revision",
            revision_matches,
            json!({
                "expected": artifact.source.revision,
                "observed": observed_revision,
                "pristine": pristine.is_empty(),
            }),
        ));
        if !revision_matches {
            return Ok(checks);
        }

        let manifest_errors = verify_manifest(&checkout_root, &artifact.assets);
        checks.push(check(
            "asset_manifest",
            manifest_errors.is_empty(),
            json!({"files": artifact.assets, "errors": manifest_errors}),
        ));
        if !manifest_errors.is_empty() {
            return Ok(checks);
        }

        let generated_test = generated_conformance_test(&target.payload, ENTRYPOINT);
        let test_path = checkout_root
            .join("tests")
            .join("gooir_generated_runnable_web.rs");
        fs::write(&test_path, generated_test).map_err(|error| error.to_string())?;
        let runtime = run_bounded(
            Command::new("cargo")
                .args([
                    "test",
                    "--locked",
                    "--test",
                    "gooir_generated_runnable_web",
                    "--",
                    "--nocapture",
                ])
                .current_dir(&checkout_root),
            &checkout_root,
            CHECK_TIMEOUT,
        )?;
        checks.push(check(
            "independent_runtime_behavior",
            runtime.success,
            runtime.evidence(),
        ));
        Ok(checks)
    }
}

fn validate_artifact(
    artifact: &RunnableWebArtifact,
    expected_authority: &str,
    target_input_id: &str,
) -> Vec<String> {
    let mut errors = Vec::new();
    if artifact.schema != RUNNABLE_WEB_ARTIFACT_SCHEMA {
        errors.push("unsupported artifact schema".to_owned());
    }
    if artifact.source.authority != expected_authority {
        errors.push("artifact authority does not equal the trusted repository".to_owned());
    }
    if !valid_git_revision(&artifact.source.revision) {
        errors.push("artifact revision is not a lowercase full Git object identity".to_owned());
    }
    if artifact.target_input_id != target_input_id {
        errors.push("artifact does not bind the exact target input fact".to_owned());
    }
    if artifact.entrypoint != ENTRYPOINT {
        errors.push(format!("entrypoint must be {ENTRYPOINT}"));
    }
    let expected = EXPECTED_ASSETS
        .iter()
        .map(|(path, media_type)| ((*path).to_owned(), (*media_type).to_owned()))
        .collect::<BTreeMap<_, _>>();
    let mut observed = BTreeMap::new();
    for file in &artifact.assets {
        if observed
            .insert(file.path.clone(), file.media_type.clone())
            .is_some()
        {
            errors.push(format!("duplicate asset {}", file.path));
        }
        if !valid_sha256(&file.sha256) {
            errors.push(format!("asset {} has an invalid SHA-256 digest", file.path));
        }
    }
    if observed != expected {
        errors.push("served asset set or media types do not match suite v0.1.0".to_owned());
    }
    errors
}

fn verify_manifest(root: &Path, assets: &[ArtifactFile]) -> Vec<String> {
    let mut errors = Vec::new();
    for asset in assets {
        let path = root.join(&asset.path);
        match fs::read(&path) {
            Ok(bytes) => {
                let observed = sha256(&bytes);
                if observed != asset.sha256 {
                    errors.push(format!(
                        "{} digest mismatch: expected {}, observed {observed}",
                        asset.path, asset.sha256
                    ));
                }
            }
            Err(error) => errors.push(format!("{} could not be read: {error}", asset.path)),
        }
    }
    errors
}

fn generated_conformance_test(target: &Value, entrypoint: &str) -> String {
    let target_json = serde_json::to_string(target).expect("target value serializes");
    let target_literal = format!("{target_json:?}");
    format!(
        r#"
use fleetd::{{
    AppState, AuthService, BlockDelivery, ClaimDeliveries, CreateAgent, CreateChannel,
    CreateMessage, ResolveDeliveryBlock, Store, router,
}};
use reqwest::header::CONTENT_TYPE;
use serde_json::{{Value, json}};

#[tokio::test]
async fn verifier_owned_runnable_web_contract() {{
    let directory = tempfile::tempdir().expect("temporary directory");
    let store = Store::open(directory.path().join("fleetd.db"))
        .await
        .expect("open store");
    let token_path = directory.path().join("operator.token");
    AuthService::new(store.clone())
        .ensure_operator_credential(&token_path)
        .await
        .expect("bootstrap operator credential");
    let token = std::fs::read_to_string(token_path)
        .expect("read operator token")
        .trim()
        .to_owned();

    let sender = store.create_agent(CreateAgent {{
        name: "gooir-sender".to_owned(), metadata: json!({{}}),
    }}).await.expect("create sender");
    let receiver = store.create_agent(CreateAgent {{
        name: "gooir-worker".to_owned(), metadata: json!({{}}),
    }}).await.expect("create receiver");
    let channel = store.create_channel(CreateChannel {{
        name: "gooir-conformance".to_owned(),
        metadata: json!({{}}),
        member_ids: vec![sender.id.clone(), receiver.id.clone()],
    }}).await.expect("create channel");
    let first = create_block(&store, &channel.id, &sender.id, &receiver.id, "requeue fixture").await;
    let second = create_block(&store, &channel.id, &sender.id, &receiver.id, "abandon fixture").await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind server");
    let address = listener.local_addr().expect("server address");
    let server_store = store.clone();
    let process = tokio::spawn(async move {{
        axum::serve(listener, router(AppState::new(server_store)))
            .await
            .expect("serve fleetd");
    }});
    let client = reqwest::Client::new();
    let base = format!("http://{{address}}");

    let page = client.get(format!("{{base}}{entrypoint}"))
        .send().await.expect("operator page response");
    assert_eq!(page.status(), reqwest::StatusCode::OK);
    assert_eq!(page.headers().get(CONTENT_TYPE).and_then(|value| value.to_str().ok()), Some("text/html; charset=utf-8"));
    let policy = page.headers().get("content-security-policy")
        .and_then(|value| value.to_str().ok()).expect("content security policy");
    assert!(policy.contains("default-src 'none'"));
    assert!(policy.contains("script-src 'self'"));
    assert!(policy.contains("connect-src 'self'"));
    let html = page.text().await.expect("operator page body");
    for marker in ["id=\"operator-auth\"", "id=\"operator-token\"", "id=\"surface-status\"", "id=\"delivery-blocks\""] {{
        assert!(html.contains(marker), "missing accessible surface marker {{marker}}");
    }}
    assert!(!html.contains("<script>"), "inline scripts violate the surface policy");

    let expected: Value = serde_json::from_str({target_literal}).expect("embedded target IR");
    let contract_response = client.get(format!("{{base}}/operator/contract.json"))
        .send().await.expect("contract response");
    assert_eq!(contract_response.status(), reqwest::StatusCode::OK);
    let observed: Value = contract_response.json().await.expect("contract JSON");
    assert_eq!(observed, expected, "served contract must equal the exact target IR");

    let binding = expected.get("binding").expect("binding");
    assert_eq!(binding.get("list_method").and_then(Value::as_str), Some("GET"));
    assert_eq!(binding.get("resolve_method").and_then(Value::as_str), Some("POST"));
    let list_path = binding.get("list_path").and_then(Value::as_str).expect("list path");
    let unauthorized = client.get(format!("{{base}}{{list_path}}"))
        .send().await.expect("unauthorized list response");
    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);
    let listed: Vec<Value> = client.get(format!("{{base}}{{list_path}}"))
        .bearer_auth(&token).send().await.expect("list response")
        .error_for_status().expect("list status").json().await.expect("list JSON");
    assert_eq!(listed.len(), 2);

    let template = binding.get("resolve_path_template").and_then(Value::as_str).expect("resolve path");
    for (block_id, resolution) in [(first.block_id, "requeue"), (second.block_id, "abandon")] {{
        assert!(expected.get("actions").and_then(Value::as_array).expect("actions").iter().any(|action| {{
            action.pointer("/semantic/name").and_then(Value::as_str) == Some(resolution)
        }}), "target IR is missing action {{resolution}}");
        let path = template.replace("{{block_id}}", &block_id.to_string());
        let response = client.post(format!("{{base}}{{path}}"))
            .bearer_auth(&token)
            .json(&ResolveDeliveryBlock {{
                resolution: serde_json::from_value(json!(resolution)).expect("known resolution"),
                retry_after_ms: 0,
                note: Some("GOOIR independent conformance".to_owned()),
            }})
            .send().await.expect("resolve response");
        assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
    }}
    let remaining: Vec<Value> = client.get(format!("{{base}}{{list_path}}"))
        .bearer_auth(&token).send().await.expect("final list response")
        .error_for_status().expect("final list status").json().await.expect("final list JSON");
    assert!(remaining.is_empty());
    let reclaimed = store.claim_deliveries(&receiver.id, ClaimDeliveries {{ limit: 10, lease_duration_ms: 10_000 }})
        .await.expect("claim requeued delivery");
    assert_eq!(reclaimed.deliveries.len(), 1);
    assert_eq!(reclaimed.deliveries[0].attempt, 2);
    process.abort();
}}

async fn create_block(store: &Store, channel: &str, sender: &str, receiver: &str, reason: &str) -> fleetd::BlockedDelivery {{
    let message = store.append_message(channel, CreateMessage {{
        sender_id: sender.to_owned(),
        idempotency_key: None,
        recipient_id: Some(receiver.to_owned()),
        kind: "gooir.conformance/v1".to_owned(),
        payload: json!({{"reason": reason}}),
        correlation_id: None,
        causation_id: None,
    }}).await.expect("append fixture message");
    let claim = store.claim_deliveries(receiver, ClaimDeliveries {{ limit: 1, lease_duration_ms: 10_000 }})
        .await.expect("claim fixture delivery");
    assert_eq!(claim.deliveries.len(), 1);
    let (blocked, created) = store.block_delivery(receiver, &message.id, BlockDelivery {{
        lease_token: claim.lease_token,
        reason: reason.to_owned(),
    }}).await.expect("block fixture delivery");
    assert!(created);
    blocked
}}
"#
    )
}

struct ProcessResult {
    success: bool,
    timed_out: bool,
    stdout: String,
    stderr: String,
}

impl ProcessResult {
    fn evidence(&self) -> Value {
        json!({
            "success": self.success,
            "timed_out": self.timed_out,
            "stdout": self.stdout,
            "stderr": self.stderr,
        })
    }
}

fn run_bounded(
    command: &mut Command,
    evidence_directory: &Path,
    timeout: Duration,
) -> Result<ProcessResult, String> {
    let stdout_path = evidence_directory.join("command.stdout");
    let stderr_path = evidence_directory.join("command.stderr");
    let stdout = fs::File::create(&stdout_path).map_err(|error| error.to_string())?;
    let stderr = fs::File::create(&stderr_path).map_err(|error| error.to_string())?;
    let mut child = command
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| error.to_string())?;
    let start = Instant::now();
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break (status, false);
        }
        if start.elapsed() >= timeout {
            child.kill().map_err(|error| error.to_string())?;
            let status = child.wait().map_err(|error| error.to_string())?;
            break (status, true);
        }
        thread::sleep(Duration::from_millis(100));
    };
    Ok(ProcessResult {
        success: status.success() && !timed_out,
        timed_out,
        stdout: read_bounded(&stdout_path)?,
        stderr: read_bounded(&stderr_path)?,
    })
}

fn read_bounded(path: &Path) -> Result<String, String> {
    let file = fs::File::open(path).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_PROCESS_EVIDENCE_BYTES as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn git_text(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn implementation_digest() -> String {
    let mut hasher = Sha256::new();
    hasher.update(include_bytes!("conformance.rs"));
    hasher.update(include_bytes!("../Cargo.toml"));
    hasher.update(include_bytes!("../../../Cargo.lock"));
    sha256_digest(hasher.finalize())
}

fn sha256(bytes: &[u8]) -> String {
    sha256_digest(Sha256::digest(bytes))
}

fn sha256_digest(digest: impl AsRef<[u8]>) -> String {
    let mut output = String::from("sha256:");
    for byte in digest.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn valid_git_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| valid_hex(hex, 64))
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn check(name: &str, passed: bool, evidence: Value) -> ConformanceCheck {
    ConformanceCheck {
        name: name.to_owned(),
        outcome: if passed {
            ConformanceOutcome::Passed
        } else {
            ConformanceOutcome::Failed
        },
        evidence,
    }
}

fn failed(name: &str, evidence: Value) -> ConformanceCheck {
    check(name, false, evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> RunnableWebArtifact {
        RunnableWebArtifact {
            schema: RUNNABLE_WEB_ARTIFACT_SCHEMA.to_owned(),
            source: GitArtifactSource {
                authority: "git:/tmp/fleetd".to_owned(),
                revision: "a".repeat(40),
            },
            target_input_id: format!("sha256:{}", "b".repeat(64)),
            entrypoint: ENTRYPOINT.to_owned(),
            assets: EXPECTED_ASSETS
                .iter()
                .map(|(path, media_type)| ArtifactFile {
                    path: (*path).to_owned(),
                    media_type: (*media_type).to_owned(),
                    sha256: format!("sha256:{}", "c".repeat(64)),
                })
                .collect(),
        }
    }

    #[test]
    fn artifact_contract_is_exact_and_closed() {
        let artifact = artifact();
        assert!(
            validate_artifact(
                &artifact,
                "git:/tmp/fleetd",
                &format!("sha256:{}", "b".repeat(64))
            )
            .is_empty()
        );

        let mut changed = artifact;
        changed.assets.pop();
        assert!(
            !validate_artifact(
                &changed,
                "git:/tmp/fleetd",
                &format!("sha256:{}", "b".repeat(64))
            )
            .is_empty()
        );
    }

    #[test]
    fn unknown_artifact_fields_fail_closed() {
        let mut encoded = serde_json::to_value(artifact()).unwrap();
        encoded["generator_claimed_conformance"] = json!(true);
        assert!(serde_json::from_value::<RunnableWebArtifact>(encoded).is_err());
    }
}
