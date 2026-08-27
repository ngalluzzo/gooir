#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::io::Write;
use std::process::{Command, Stdio};

use fleetd_direct_conversation_external_host_proof::journal::NativeRuntimeLock;
use serde_json::Value;

#[test]
#[ignore = "current-host exact native runtime proof; run optimized with --release --ignored --exact"]
fn single_thread_probe_qualifies_launches_both_roles_and_recovers_exactly() {
    let probe = env!("CARGO_BIN_EXE_native-runtime-probe");
    let fixture = env!("CARGO_BIN_EXE_native-supervisor-fixture");
    let qualified = Command::new(probe)
        .arg("qualify")
        .arg(fixture)
        .output()
        .expect("run single-thread qualification probe");
    assert!(
        qualified.status.success(),
        "qualification probe failed: {}",
        String::from_utf8_lossy(&qualified.stderr)
    );
    let document: Value = serde_json::from_slice(&qualified.stdout).expect("probe result JSON");
    let runtime_lock: NativeRuntimeLock =
        serde_json::from_value(document["runtime_lock"].clone()).expect("runtime lock");
    assert_eq!(
        document["runtime_qualification_id"],
        runtime_lock.runtime_digest()
    );
    assert_ne!(
        document["provider_artifact_lock_id"],
        document["attester_artifact_lock_id"]
    );
    let serialized_qualification =
        serde_json::to_vec(&document["runtime_qualification"]).expect("serialized qualification");
    for forbidden in [
        probe.as_bytes(),
        fixture.as_bytes(),
        b"http://127.0.0.1:43123/",
        b"native-runtime-probe-secret-never-retained",
        b"operator-credential/revision-native-runtime-probe",
    ] {
        assert!(
            !contains(&serialized_qualification, forbidden),
            "runtime qualification exposed a forbidden live value"
        );
    }
    assert_ne!(
        document["provider_receipt_id"],
        document["attester_receipt_id"]
    );

    assert_recovery_launch(probe, fixture, &runtime_lock);
    assert_supervisor_regressions(probe, fixture, &runtime_lock);
}

fn assert_recovery_launch(probe: &str, fixture: &str, runtime_lock: &NativeRuntimeLock) {
    let mut recovered = Command::new(probe)
        .arg("recover")
        .arg(fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start single-thread recovery probe");
    serde_json::to_writer(
        recovered.stdin.as_mut().expect("recovery stdin"),
        &runtime_lock,
    )
    .expect("write exact runtime lock");
    let mut recovery_stdin = recovered.stdin.take().expect("close recovery stdin");
    recovery_stdin.flush().expect("flush recovery lock");
    drop(recovery_stdin);
    let recovered = recovered.wait_with_output().expect("wait recovery probe");
    assert!(
        recovered.status.success(),
        "recovery probe failed: {}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let recovered: Value =
        serde_json::from_slice(&recovered.stdout).expect("recovered runtime result");
    let recovered_lock: NativeRuntimeLock =
        serde_json::from_value(recovered["runtime_lock"].clone()).expect("recovered runtime lock");
    assert_eq!(&recovered_lock, runtime_lock);
    assert_eq!(
        recovered["runtime_qualification_id"],
        runtime_lock.runtime_digest()
    );
    assert_eq!(
        recovered["receipt_runtime_qualification_id"],
        runtime_lock.runtime_digest()
    );
    assert_eq!(
        recovered["receipt_artifact_lock_id"],
        recovered["artifact_lock_id"]
    );
    assert!(
        recovered["receipt_id"]
            .as_str()
            .is_some_and(|value| value.starts_with("sha256:") && value.len() == 71),
        "recovered runtime launch did not return an exact receipt identity"
    );
}

fn assert_supervisor_regressions(probe: &str, fixture: &str, runtime_lock: &NativeRuntimeLock) {
    for mode in [
        "isolation",
        "overflow",
        "nonzero",
        "timeout-group",
        "descendant-cleanup",
        "secret-output",
        "sensitive-stdin",
    ] {
        let result = Command::new(probe)
            .arg(mode)
            .arg(fixture)
            .output()
            .unwrap_or_else(|error| panic!("run isolated {mode} probe: {error}"));
        assert!(
            result.status.success(),
            "isolated {mode} probe failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let result: Value = serde_json::from_slice(&result.stdout)
            .unwrap_or_else(|error| panic!("decode isolated {mode} result: {error}"));
        assert_eq!(result["mode"], mode);
        assert_eq!(
            result["runtime_qualification_id"],
            runtime_lock.runtime_digest(),
            "isolated {mode} used a different runtime qualification"
        );
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
