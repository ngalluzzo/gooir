//! Deterministically projects an existing Fleetd Git revision into the exact
//! runnable-web provider response. This is the brownfield entry path: it does
//! not generate or verify the surface.

use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use fleetd_capability_pack::{
    ArtifactFile, GitArtifactSource, RUNNABLE_WEB_ARTIFACT_SCHEMA, RunnableWebArtifact,
};
use gooir_capability::{
    CapabilityRequest, FactCoverage, ProducedFact, ProviderDescriptor, ProviderId,
};
use serde::Serialize;
use serde_json::to_value;
use sha2::{Digest, Sha256};

const SUITE: &str = "dev.fleetd.conformance.runnable_web_surface@0.1.0";
const ASSETS: [(&str, &str); 4] = [
    ("web/operator/contract.json", "application/json"),
    ("web/operator/index.html", "text/html; charset=utf-8"),
    ("web/operator/operator.css", "text/css; charset=utf-8"),
    ("web/operator/operator.js", "text/javascript; charset=utf-8"),
];

#[derive(Serialize)]
struct ProjectionReport {
    provider: ProviderDescriptor,
    response: ProviderResponse,
}

#[derive(Serialize)]
struct ProviderResponse {
    request_id: String,
    status: &'static str,
    outputs: Vec<ProducedFact>,
    conformance_suite: String,
    conformance_status: &'static str,
    diagnostics: Vec<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let repository = PathBuf::from(
        arguments
            .next()
            .ok_or("usage: fleetd-runnable-web-project <fleetd-repository> <request.json>")?,
    );
    let request_path = PathBuf::from(arguments.next().ok_or("missing request path")?);
    if arguments.next().is_some() {
        return Err("unexpected extra arguments".into());
    }
    let request: CapabilityRequest = serde_json::from_slice(&fs::read(request_path)?)?;
    request.validate()?;
    if request.body.conformance_suite != SUITE {
        return Err("request does not name the runnable-web suite v0.1.0".into());
    }
    let [input] = request.body.inputs.as_slice() else {
        return Err("runnable-web projection requires exactly one target input".into());
    };
    let [output_type] = request.body.produces.as_slice() else {
        return Err("runnable-web projection requires exactly one output type".into());
    };
    let root = fs::canonicalize(repository)?;
    require_clean(&root)?;
    let revision = git(&root, &["rev-parse", "HEAD"])?;
    let artifact = RunnableWebArtifact {
        schema: RUNNABLE_WEB_ARTIFACT_SCHEMA.to_owned(),
        source: GitArtifactSource {
            authority: format!("git:{}", root.display()),
            revision,
        },
        target_input_id: input.id.clone(),
        entrypoint: "/operator/".to_owned(),
        assets: ASSETS
            .iter()
            .map(|(path, media_type)| {
                let bytes = fs::read(root.join(path))?;
                Ok(ArtifactFile {
                    path: (*path).to_owned(),
                    media_type: (*media_type).to_owned(),
                    sha256: digest(&bytes),
                })
            })
            .collect::<Result<Vec<_>, std::io::Error>>()?,
    };
    let provider = ProviderDescriptor {
        id: ProviderId::new("dev.fleetd.provider.git", "runnable_web_manifest", "0.1.0"),
        capability: request.body.capability.clone(),
        implementation_digest: implementation_digest(),
    };
    let report = ProjectionReport {
        provider,
        response: ProviderResponse {
            request_id: request.request_id,
            status: "candidate",
            outputs: vec![ProducedFact {
                fact_type: output_type.clone(),
                coverage: FactCoverage::Complete,
                payload: to_value(artifact)?,
            }],
            conformance_suite: SUITE.to_owned(),
            conformance_status: "unverified",
            diagnostics: Vec::new(),
        },
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn require_clean(root: &Path) -> Result<(), Box<dyn Error>> {
    let status = git(root, &["status", "--porcelain"])?;
    if !status.is_empty() {
        return Err("Fleetd repository must be clean before artifact projection".into());
    }
    Ok(())
}

fn git(root: &Path, arguments: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_owned()
            .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn implementation_digest() -> String {
    let mut hasher = Sha256::new();
    hasher.update(include_bytes!("candidate_main.rs"));
    hasher.update(include_bytes!("../Cargo.toml"));
    hasher.update(include_bytes!("../../../Cargo.lock"));
    prefixed(hasher.finalize())
}

fn digest(bytes: &[u8]) -> String {
    prefixed(Sha256::digest(bytes))
}

fn prefixed(bytes: impl AsRef<[u8]>) -> String {
    let mut output = String::from("sha256:");
    for byte in bytes.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
