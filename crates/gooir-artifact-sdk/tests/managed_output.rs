use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;

use gooir_artifact_sdk::{
    Admitted, ContentFile, ContentSet, LocalPublisher, ManagedOutput, ManagedOutputId, OutputState,
    OwnershipManifest, PathChangeKind, PublicationLimits, PublicationOutcome, PublicationReceipt,
    PublishError, content_set_contract,
};
use gooir_capability::authority::{
    AdmissionAuthorityId, AdmissionLedger, AdmissionOutcome, AdmissionPolicy, ObservationAuthority,
    ObservationSourceId, SourceObservation,
};
use gooir_capability::protocol::{
    AdmittedFactRef, ArtifactDigest, AuthorityRecordId, EvidenceDigest, EvidenceKindId,
    EvidenceRef, ImplementationId,
};
use gooir_capability::{Fact, FactId, ValueKindId};
use serde_json::json;

fn sha(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn admit_fact(fact: Fact) -> (AdmissionLedger, AdmittedFactRef) {
    let evidence_kind = EvidenceKindId::new("test.evidence", "artifact", "1.0.0");
    let authority = ObservationAuthority::new(
        ObservationSourceId::new("test.source", "generator", "1.0.0"),
        ImplementationId::new("test.observer", "generator", "1.0.0"),
        ArtifactDigest::parse(sha('a')).unwrap(),
        fact.value_kind.clone(),
        evidence_kind.clone(),
        BTreeMap::new(),
    )
    .unwrap();
    let evidence = EvidenceRef::new(
        evidence_kind,
        EvidenceDigest::parse(sha('b')).unwrap(),
        "opaque://artifact",
        BTreeMap::new(),
    )
    .unwrap();
    let observation = SourceObservation::new(
        fact,
        authority.clone(),
        evidence,
        Vec::new(),
        BTreeMap::new(),
    )
    .unwrap();
    let policy = AdmissionPolicy::new(
        AdmissionAuthorityId::new("test.admission", "artifacts", "1.0.0"),
        Vec::new(),
        vec![authority],
        BTreeMap::new(),
    )
    .unwrap();
    let mut ledger = AdmissionLedger::new();
    let AdmissionOutcome::Admitted { links, .. } =
        ledger.admit_observation(&policy, &observation).unwrap()
    else {
        panic!("fixture policy must admit")
    };
    (ledger, links[0].reference.clone())
}

fn admitted(files: &[(&str, &[u8])]) -> (AdmissionLedger, Admitted<ContentSet>) {
    let set = ContentSet::new(
        files
            .iter()
            .map(|(path, bytes)| ContentFile::new(*path, bytes.to_vec()).unwrap())
            .collect(),
    )
    .unwrap();
    let fact = Fact::new(content_set_contract(), serde_json::to_value(set).unwrap()).unwrap();
    let (ledger, reference) = admit_fact(fact);
    let artifact = Admitted::resolve(&ledger, &reference).unwrap();
    (ledger, artifact)
}

fn output(path: impl Into<std::path::PathBuf>, id: &str) -> ManagedOutput {
    ManagedOutput::new(ManagedOutputId::parse(id).unwrap(), path).unwrap()
}

#[test]
fn admitted_requires_exact_ledger_reference_kind_and_valid_payload() {
    let (_, artifact) = admitted(&[("a.txt", b"a")]);
    assert_eq!(artifact.value().files[0].path.as_str(), "a.txt");

    let forged = AdmittedFactRef::new(
        FactId::parse(sha('c')).unwrap(),
        AuthorityRecordId::parse(sha('d')).unwrap(),
        BTreeMap::new(),
    )
    .unwrap();
    assert!(Admitted::<ContentSet>::resolve(&AdmissionLedger::new(), &forged).is_err());

    let wrong = Fact::new(ValueKindId::new("test", "wrong", "1.0.0"), json!({})).unwrap();
    let (wrong_ledger, wrong_ref) = admit_fact(wrong);
    assert!(Admitted::<ContentSet>::resolve(&wrong_ledger, &wrong_ref).is_err());

    let malformed = Fact::new(
        content_set_contract(),
        json!({"files": [{"path": "../escape", "content": "YQ=="}]}),
    )
    .unwrap();
    let (malformed_ledger, malformed_ref) = admit_fact(malformed);
    assert!(Admitted::<ContentSet>::resolve(&malformed_ledger, &malformed_ref).is_err());
}

#[test]
fn content_paths_are_portable_and_empty_sets_are_valid() {
    assert!(ContentSet::new(Vec::new()).is_ok());
    for path in [
        "",
        "/absolute",
        "../escape",
        "a/./b",
        "a\\b",
        "CON.txt",
        ".gooir-managed-output.json",
        ".GOOIR-MANAGED-OUTPUT.JSON",
    ] {
        assert!(ContentFile::new(path, Vec::new()).is_err(), "{path}");
    }
    assert!(
        ContentSet::new(vec![
            ContentFile::new("A", Vec::new()).unwrap(),
            ContentFile::new("a", Vec::new()).unwrap(),
        ])
        .is_err()
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn unsupported_extensions_and_resource_excess_are_refused_before_writes() {
    let extended = ContentSet::with_extensions(
        vec![ContentFile::new("a.txt", b"a".to_vec()).unwrap()],
        BTreeMap::from([("future.example/meaning".to_owned(), json!(true))]),
    )
    .unwrap();
    let fact = Fact::new(
        content_set_contract(),
        serde_json::to_value(extended).unwrap(),
    )
    .unwrap();
    let (ledger, reference) = admit_fact(fact);
    let artifact = Admitted::resolve(&ledger, &reference).unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("extended");
    assert!(matches!(
        LocalPublisher::default().publish(&artifact, &output(&destination, "test.extended@1")),
        Err(PublishError::ArtifactExtensions)
    ));
    assert!(!destination.exists());

    let ordinary_set =
        ContentSet::new(vec![ContentFile::new("a.txt", b"a".to_vec()).unwrap()]).unwrap();
    let fact_with_extension = Fact::with_extensions(
        content_set_contract(),
        serde_json::to_value(&ordinary_set).unwrap(),
        BTreeMap::from([("future.example/fact".to_owned(), json!(true))]),
    )
    .unwrap();
    let (fact_ledger, fact_reference) = admit_fact(fact_with_extension);
    let fact_extended = Admitted::resolve(&fact_ledger, &fact_reference).unwrap();
    let fact_destination = temporary.path().join("fact-extended");
    assert!(matches!(
        LocalPublisher::default().publish(
            &fact_extended,
            &output(&fact_destination, "test.fact-extended@1")
        ),
        Err(PublishError::ArtifactExtensions)
    ));
    assert!(!fact_destination.exists());

    let ordinary_fact = Fact::new(
        content_set_contract(),
        serde_json::to_value(ordinary_set).unwrap(),
    )
    .unwrap();
    let (reference_ledger, mut extended_reference) = admit_fact(ordinary_fact);
    extended_reference
        .extensions
        .insert("future.example/reference".to_owned(), json!(true));
    let reference_extended = Admitted::resolve(&reference_ledger, &extended_reference).unwrap();
    let reference_destination = temporary.path().join("reference-extended");
    assert!(matches!(
        LocalPublisher::default().publish(
            &reference_extended,
            &output(&reference_destination, "test.reference-extended@1")
        ),
        Err(PublishError::ArtifactExtensions)
    ));
    assert!(!reference_destination.exists());

    let (_, ordinary) = admitted(&[("a.txt", b"a")]);
    let bounded = LocalPublisher::new(PublicationLimits {
        max_files: 1,
        max_directories: 1,
        max_file_bytes: 1,
        max_total_bytes: 1,
        max_manifest_bytes: 1,
    })
    .unwrap();
    let limited = temporary.path().join("limited");
    assert!(matches!(
        bounded.publish(&ordinary, &output(&limited, "test.limited@1")),
        Err(PublishError::LimitExceeded("max_manifest_bytes"))
    ));
    assert!(!limited.exists());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn create_unchanged_replace_and_empty_are_complete_tree_operations() {
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("generated");
    let target = output(&destination, "test.output@1");
    let publisher = LocalPublisher::default();

    let (_, first) = admitted(&[("a.txt", b"a"), ("nested/b.txt", b"b")]);
    let created = publisher.publish(&first, &target).unwrap();
    assert!(matches!(created.outcome, PublicationOutcome::Created));
    assert_eq!(fs::read(destination.join("nested/b.txt")).unwrap(), b"b");

    let unchanged = publisher.publish(&first, &target).unwrap();
    assert!(matches!(
        unchanged.outcome,
        PublicationOutcome::Unchanged { .. }
    ));

    let (_, second) = admitted(&[("a.txt", b"changed"), ("c.txt", b"c")]);
    let replaced = publisher.publish(&second, &target).unwrap();
    assert!(matches!(
        replaced.outcome,
        PublicationOutcome::Replaced { .. }
    ));
    assert!(!destination.join("nested/b.txt").exists());
    assert_eq!(fs::read(destination.join("a.txt")).unwrap(), b"changed");

    let (_, empty) = admitted(&[]);
    publisher.publish(&empty, &target).unwrap();
    let names: Vec<_> = fs::read_dir(&destination)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, [".gooir-managed-output.json"]);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn check_and_diff_are_read_only_and_describe_changes() {
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("generated");
    let target = output(&destination, "test.output@1");
    let publisher = LocalPublisher::default();
    let (_, first) = admitted(&[("a.txt", b"a")]);
    publisher.publish(&first, &target).unwrap();
    let marker = destination.join(".gooir-managed-output.json");
    let before = fs::read(&marker).unwrap();

    let (_, second) = admitted(&[("a.txt", b"changed"), ("b.txt", b"b")]);
    let check = publisher.check(&second, &target).unwrap();
    assert_eq!(check.state, OutputState::ManagedClean);
    let diff = publisher.diff(&second, &target).unwrap();
    assert_eq!(diff.state, OutputState::ManagedClean);
    assert_eq!(
        diff.changes
            .iter()
            .map(|change| (&change.kind, change.path.as_str()))
            .collect::<Vec<_>>(),
        [
            (&PathChangeKind::Changed, "a.txt"),
            (&PathChangeKind::Added, "b.txt"),
        ]
    );
    assert_eq!(fs::read(&marker).unwrap(), before);
    assert_eq!(fs::read(destination.join("a.txt")).unwrap(), b"a");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn unmanaged_wrong_owner_and_drift_conflict_before_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let unmanaged_path = temporary.path().join("unmanaged");
    fs::create_dir(&unmanaged_path).unwrap();
    fs::write(unmanaged_path.join("mine"), b"mine").unwrap();
    let publisher = LocalPublisher::default();
    let (_, artifact) = admitted(&[("a.txt", b"a")]);
    assert!(matches!(
        publisher.publish(&artifact, &output(&unmanaged_path, "test.output@1")),
        Err(PublishError::Unmanaged(_))
    ));
    assert_eq!(fs::read(unmanaged_path.join("mine")).unwrap(), b"mine");

    let managed_path = temporary.path().join("managed");
    let owner = output(&managed_path, "owner.one@1");
    publisher.publish(&artifact, &owner).unwrap();
    assert!(matches!(
        publisher.publish(&artifact, &output(&managed_path, "owner.two@1")),
        Err(PublishError::WrongOwner { .. })
    ));

    fs::write(managed_path.join("a.txt"), b"user edit").unwrap();
    assert_eq!(
        publisher.check(&artifact, &owner).unwrap().state,
        OutputState::ManagedDrifted
    );
    assert!(matches!(
        publisher.publish(&artifact, &owner),
        Err(PublishError::Drift(_))
    ));
    assert_eq!(fs::read(managed_path.join("a.txt")).unwrap(), b"user edit");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn wide_directory_drift_is_bounded_when_entries_are_discovered() {
    let temporary = tempfile::tempdir().unwrap();
    let destination = temporary.path().join("managed");
    let target = output(&destination, "test.wide-directory-limit@1");
    let publisher = LocalPublisher::new(PublicationLimits {
        max_directories: 1,
        ..PublicationLimits::default()
    })
    .unwrap();
    let (_, artifact) = admitted(&[("a.txt", b"a")]);
    publisher.publish(&artifact, &target).unwrap();

    fs::create_dir(destination.join("first-unmanaged-directory")).unwrap();
    fs::create_dir(destination.join("second-unmanaged-directory")).unwrap();

    assert_eq!(
        publisher.check(&artifact, &target).unwrap().state,
        OutputState::ManagedDrifted
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn destination_and_tree_symlinks_are_never_followed() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let outside = temporary.path().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("keep"), b"keep").unwrap();
    let linked = temporary.path().join("linked");
    symlink(&outside, &linked).unwrap();
    let publisher = LocalPublisher::default();
    let (_, artifact) = admitted(&[("a.txt", b"a")]);
    assert!(matches!(
        publisher.publish(&artifact, &output(&linked, "test.output@1")),
        Err(PublishError::Unmanaged(_))
    ));
    assert_eq!(fs::read(outside.join("keep")).unwrap(), b"keep");

    let managed = temporary.path().join("managed");
    let target = output(&managed, "test.output@1");
    publisher.publish(&artifact, &target).unwrap();
    fs::remove_file(managed.join("a.txt")).unwrap();
    symlink(outside.join("keep"), managed.join("a.txt")).unwrap();
    assert_eq!(
        publisher.check(&artifact, &target).unwrap().state,
        OutputState::ManagedDrifted
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn concurrent_cooperative_publishers_expose_only_complete_trees() {
    let temporary = tempfile::tempdir().unwrap();
    let target = Arc::new(output(temporary.path().join("generated"), "test.output@1"));
    let (_, artifact) = admitted(&[("a.txt", b"a"), ("b.txt", b"b")]);
    let artifact = Arc::new(artifact);
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let target = Arc::clone(&target);
            let artifact = Arc::clone(&artifact);
            std::thread::spawn(move || {
                LocalPublisher::default()
                    .publish(&artifact, &target)
                    .unwrap()
            })
        })
        .collect();
    let receipts: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| matches!(receipt.outcome, PublicationOutcome::Created))
            .count(),
        1
    );
    assert_eq!(fs::read(target.destination().join("a.txt")).unwrap(), b"a");
    assert_eq!(fs::read(target.destination().join("b.txt")).unwrap(), b"b");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn manifest_and_receipt_have_canonical_roundtrips() {
    let temporary = tempfile::tempdir().unwrap();
    let target = output(temporary.path().join("generated"), "test.output@1");
    let (_, artifact) = admitted(&[("a.txt", b"a")]);
    let receipt = LocalPublisher::default()
        .publish(&artifact, &target)
        .unwrap();
    let marker = fs::read(target.destination().join(".gooir-managed-output.json")).unwrap();
    let manifest: OwnershipManifest = serde_json::from_slice(&marker).unwrap();
    assert_eq!(manifest.to_canonical_json().unwrap(), marker);

    let canonical = receipt.to_canonical_json().unwrap();
    let parsed: PublicationReceipt = serde_json::from_slice(&canonical).unwrap();
    parsed.validate().unwrap();
    assert_eq!(parsed.to_canonical_json().unwrap(), canonical);
}
