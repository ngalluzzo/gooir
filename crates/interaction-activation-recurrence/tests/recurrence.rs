use interaction_activation_recurrence::{
    CorpusError, DefeatImpact, DivergenceDimension, Ecosystem, LineageParticipation,
    ObservationRole, RuntimeLineage, ScopedDefeat, compare, default_corpus_root, load_corpus,
    observed_core_authorities, source_summary,
};
use lift_defeasible::{Completeness, Defeat, DefeatKind};
use semantics_interaction_activation_v0::ActivationOutcome;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

fn observations() -> Vec<interaction_activation_recurrence::NativeObservation> {
    let corpus = load_corpus(default_corpus_root()).expect("checked-in authority corpus verifies");
    observed_core_authorities(&corpus).expect("generated core observations are admitted")
}

#[test]
fn authority_lock_is_identity_and_provenance_only() {
    let root = default_corpus_root();
    let lock: Value = serde_json::from_slice(
        &fs::read(root.join("authorities.lock.json")).expect("authority lock"),
    )
    .expect("valid authority lock JSON");
    for authority in lock["authorities"].as_array().expect("authorities") {
        assert!(authority.get("establishes").is_none());
        assert!(authority.get("defeats").is_none());
    }

    let corpus = load_corpus(root).expect("checked-in authority corpus verifies");
    assert_eq!(corpus.manifest().authorities.len(), 17);
    assert_eq!(corpus.manifest().licenses.len(), 5);
    assert_eq!(
        corpus.manifest().recurrence.independent_authority_groups,
        ["react_dom", "vue_runtime_dom"]
    );
    assert_eq!(
        corpus.manifest().recurrence.same_system_participants,
        ["ink_terminal", "shadcn_react_dom", "mantine_react_dom"]
    );
}

#[test]
fn every_source_document_matches_its_pinned_revision_and_digest() {
    let corpus = load_corpus(default_corpus_root()).expect("checked-in authority corpus verifies");
    for authority in &corpus.manifest().authorities {
        assert!(authority.repository.url.starts_with("https://github.com/"));
        assert_eq!(authority.repository.commit.len(), 40, "{}", authority.id);
        assert_eq!(authority.sha256.len(), 64, "{}", authority.id);
        assert!(!authority.source_path.is_empty(), "{}", authority.id);
        assert!(!authority.snapshot_path.is_empty(), "{}", authority.id);
    }
}

#[test]
fn unknown_or_misspelled_lock_fields_fail_closed() {
    let root = copied_corpus();
    mutate_json(&root.path().join("authorities.lock.json"), |lock| {
        lock.as_object_mut()
            .unwrap()
            .insert("autorities".to_owned(), json!([]));
    });
    assert!(matches!(
        load_corpus(root.path()),
        Err(CorpusError::Parse(_))
    ));

    let root = copied_corpus();
    mutate_json(&root.path().join("authorities.lock.json"), |lock| {
        lock["authorities"][0]["repository"]
            .as_object_mut()
            .unwrap()
            .insert("revison".to_owned(), json!("misspelled"));
    });
    assert!(matches!(
        load_corpus(root.path()),
        Err(CorpusError::Parse(_))
    ));
}

#[test]
fn authored_semantic_verdicts_are_rejected_from_the_identity_lock() {
    let root = copied_corpus();
    mutate_json(&root.path().join("authorities.lock.json"), |lock| {
        lock["authorities"][0]
            .as_object_mut()
            .unwrap()
            .insert("establishes".to_owned(), json!(["dispatches"]));
    });
    assert!(matches!(
        load_corpus(root.path()),
        Err(CorpusError::Parse(_))
    ));
}

#[test]
fn declared_authority_groups_must_equal_entry_derived_groups() {
    let root = copied_corpus();
    mutate_json(&root.path().join("authorities.lock.json"), |lock| {
        lock["recurrence"]["independent_authority_groups"] = json!(["react_dom"]);
    });
    assert!(matches!(
        load_corpus(root.path()),
        Err(CorpusError::AuthorityGroupsMismatch { .. })
    ));
}

#[test]
fn lineage_classification_cannot_be_manufactured_by_changing_labels() {
    let root = copied_corpus();
    mutate_json(&root.path().join("authorities.lock.json"), |lock| {
        for authority in lock["authorities"].as_array_mut().unwrap() {
            if authority["authority_group"] == "ink_terminal" {
                authority["authority_class"] = json!("independent_runtime");
            }
        }
        lock["recurrence"]["independent_authority_groups"] =
            json!(["react_dom", "vue_runtime_dom", "ink_terminal"]);
        lock["recurrence"]["same_system_participants"] =
            json!(["shadcn_react_dom", "mantine_react_dom"]);
    });
    assert!(matches!(
        load_corpus(root.path()),
        Err(CorpusError::InvalidAuthorityClassification { .. })
    ));
}

#[test]
fn one_authority_group_cannot_span_repository_revisions() {
    let root = copied_corpus();
    mutate_json(&root.path().join("authorities.lock.json"), |lock| {
        lock["authorities"][0]["repository"]["url"] =
            json!("https://github.com/example/not-react.git");
    });
    assert!(matches!(
        load_corpus(root.path()),
        Err(CorpusError::GroupRepositoryMismatch(_))
    ));
}

#[test]
fn generated_lift_fields_are_strict_and_source_bound() {
    let root = copied_corpus();
    mutate_json(&root.path().join("observations.lift.json"), |lift| {
        lift.as_object_mut()
            .unwrap()
            .insert("observatons".to_owned(), json!([]));
    });
    let corpus = load_corpus(root.path()).expect("corpus");
    assert!(matches!(
        observed_core_authorities(&corpus),
        Err(CorpusError::InvalidLift(_))
    ));

    let root = copied_corpus();
    mutate_json(&root.path().join("observations.lift.json"), |lift| {
        let ink = lift["observations"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|observation| observation["ecosystem"] == "ink")
            .unwrap();
        ink["lineage"]["runtime"] = json!("vue");
    });
    let corpus = load_corpus(root.path()).expect("corpus");
    assert!(matches!(
        observed_core_authorities(&corpus),
        Err(CorpusError::InvalidLift(_))
    ));

    let root = copied_corpus();
    mutate_json(&root.path().join("observations.lift.json"), |lift| {
        let ink = lift["observations"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|observation| observation["ecosystem"] == "ink")
            .unwrap();
        let import = ink["lineage"]["evidence"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|evidence| evidence["relation"] == "imports_react_reconciler")
            .unwrap();
        import["module"] = json!("not-react-reconciler");
    });
    let corpus = load_corpus(root.path()).expect("corpus");
    assert!(matches!(
        observed_core_authorities(&corpus),
        Err(CorpusError::InvalidLift(_))
    ));

    let root = copied_corpus();
    mutate_json(&root.path().join("observations.lift.json"), |lift| {
        lift["observations"][0]["chain"]
            .as_object_mut()
            .unwrap()
            .remove("runtime_handler_invocation");
    });
    let corpus = load_corpus(root.path()).expect("corpus");
    assert!(matches!(
        observed_core_authorities(&corpus),
        Err(CorpusError::InvalidLift(_))
    ));

    let root = copied_corpus();
    mutate_json(&root.path().join("observations.lift.json"), |lift| {
        lift["observations"][0]["chain"]["binding"]["source"] =
            json!("vue_runtime_dom.events.runtime");
    });
    let corpus = load_corpus(root.path()).expect("corpus");
    assert!(matches!(
        observed_core_authorities(&corpus),
        Err(CorpusError::InvalidLift(_))
    ));

    let root = copied_corpus();
    mutate_json(&root.path().join("observations.lift.json"), |lift| {
        let original = lift["observations"][0]["chain"]["binding"]["span"]["utf8_bytes"]["start"]
            .as_u64()
            .unwrap();
        lift["observations"][0]["chain"]["binding"]["span"]["utf8_bytes"]["start"] =
            json!(original + 1);
    });
    let corpus = load_corpus(root.path()).expect("corpus");
    assert!(matches!(
        observed_core_authorities(&corpus),
        Err(CorpusError::InvalidLift(_))
    ));

    let root = copied_corpus();
    mutate_json(&root.path().join("observations.lift.json"), |lift| {
        lift["observations"][0]["defeats"][0]["defeat"]
            .as_object_mut()
            .unwrap()
            .insert("reasn".to_owned(), json!("typo must fail closed"));
    });
    let corpus = load_corpus(root.path()).expect("corpus");
    assert!(matches!(
        observed_core_authorities(&corpus),
        Err(CorpusError::InvalidLift(_))
    ));

    let root = copied_corpus();
    mutate_json(&root.path().join("observations.lift.json"), |lift| {
        lift["observations"][0]["sources"][0]["sha256"] = json!("0".repeat(64));
    });
    let corpus = load_corpus(root.path()).expect("corpus");
    assert!(matches!(
        observed_core_authorities(&corpus),
        Err(CorpusError::InvalidLift(_))
    ));

    let root = copied_corpus();
    mutate_json(&root.path().join("observations.lift.json"), |lift| {
        lift["generator"]["parser"]["config"]["variants"]["flow_jsx"]["plugins"][0] =
            json!("typescript");
    });
    let corpus = load_corpus(root.path()).expect("corpus");
    assert!(matches!(
        observed_core_authorities(&corpus),
        Err(CorpusError::InvalidLift(_))
    ));
}

#[test]
fn semantically_rearranged_but_coordinate_valid_projection_is_not_canonical() {
    let root = copied_corpus();
    mutate_json(&root.path().join("observations.lift.json"), |lift| {
        let chain = lift["observations"][0]["chain"].as_object_mut().unwrap();
        let binding = chain["binding"].clone();
        let assertion = chain["assertion"].clone();
        chain.insert("binding".to_owned(), assertion);
        chain.insert("assertion".to_owned(), binding);
    });
    let corpus = load_corpus(root.path()).expect("identity corpus remains valid");
    assert!(matches!(
        observed_core_authorities(&corpus),
        Err(CorpusError::InvalidLift(_))
    ));
}

#[test]
fn generator_and_parser_pins_are_byte_verified() {
    let root = copied_corpus();
    mutate_json(&root.path().join("observations.lift.json"), |lift| {
        lift["generator"]["implementation_sha256"] = json!("0".repeat(64));
    });
    let corpus = load_corpus(root.path()).expect("corpus");
    assert!(matches!(
        observed_core_authorities(&corpus),
        Err(CorpusError::InvalidLift(_))
    ));

    let root = copied_corpus();
    mutate_json(&root.path().join("observations.lift.json"), |lift| {
        lift["generator"]["parser"]["config"] = json!({});
    });
    let corpus = load_corpus(root.path()).expect("corpus");
    assert!(matches!(
        observed_core_authorities(&corpus),
        Err(CorpusError::InvalidLift(_))
    ));
}

#[test]
fn generated_semantic_facts_must_verify() {
    let root = copied_corpus();
    mutate_json(&root.path().join("observations.lift.json"), |lift| {
        lift["observations"][0]["semantic"]["action_id"] = json!("  ");
    });
    let corpus = load_corpus(root.path()).expect("corpus");
    assert!(matches!(
        observed_core_authorities(&corpus),
        Err(CorpusError::InvalidLift(_))
    ));
}

#[test]
fn react_and_vue_vote_while_ink_only_extends_the_same_system_route() {
    let observations = observations();
    let report = compare(&observations);

    assert_eq!(report.independent_authorities, 2);
    assert_eq!(report.same_system_participants, 1);
    assert_eq!(report.established_observations, 3);
    assert_eq!(
        report.recurring_outcome,
        Some(ActivationOutcome::InvokesRegisteredHandler)
    );
    assert!(report.blocking_defeats.is_empty());
    assert!(!report.disjoint_defeats.is_empty());
    assert_eq!(report.coverage, Completeness::Partial);

    let roles = observations
        .iter()
        .map(|observation| (observation.ecosystem, observation.role))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        roles[&Ecosystem::ReactDom],
        ObservationRole::IndependentVote
    );
    assert_eq!(
        roles[&Ecosystem::VueRuntimeDom],
        ObservationRole::IndependentVote
    );
    assert_eq!(
        roles[&Ecosystem::Ink],
        ObservationRole::SameSystemParticipant
    );
    let react = observations
        .iter()
        .find(|observation| observation.ecosystem == Ecosystem::ReactDom)
        .unwrap();
    let vue = observations
        .iter()
        .find(|observation| observation.ecosystem == Ecosystem::VueRuntimeDom)
        .unwrap();
    let ink = observations
        .iter()
        .find(|observation| observation.ecosystem == Ecosystem::Ink)
        .unwrap();
    assert_eq!(react.lineage.runtime, RuntimeLineage::React);
    assert_eq!(react.lineage.participation, LineageParticipation::Authority);
    assert_eq!(vue.lineage.runtime, RuntimeLineage::Vue);
    assert_eq!(vue.lineage.participation, LineageParticipation::Authority);
    assert_eq!(ink.lineage.runtime, react.lineage.runtime);
    assert_eq!(ink.lineage.participation, LineageParticipation::Renderer);
}

#[test]
fn participant_presence_or_defeat_cannot_veto_independent_recurrence() {
    let all = observations();
    assert_eq!(
        compare(&all).recurring_outcome,
        Some(ActivationOutcome::InvokesRegisteredHandler)
    );

    let react_and_vue = all
        .iter()
        .filter(|observation| observation.ecosystem != Ecosystem::Ink)
        .cloned()
        .collect::<Vec<_>>();
    let without_ink = compare(&react_and_vue);
    assert_eq!(
        without_ink.recurring_outcome,
        Some(ActivationOutcome::InvokesRegisteredHandler)
    );
    assert!(without_ink.recurrence_blocking_defeats.is_empty());
    assert!(without_ink.participant_blocking_defeats.is_empty());
    assert!(without_ink.evidence_gaps.is_empty());

    let react_and_ink = all
        .iter()
        .filter(|observation| observation.ecosystem != Ecosystem::VueRuntimeDom)
        .cloned()
        .collect::<Vec<_>>();
    let without_vue = compare(&react_and_ink);
    assert_eq!(without_vue.recurring_outcome, None);
    assert!(!without_vue.recurrence_blocking_defeats.is_empty());

    let mut defeated_ink = all;
    let ink = defeated_ink
        .iter_mut()
        .find(|observation| observation.ecosystem == Ecosystem::Ink)
        .unwrap();
    let claim_defeat = ScopedDefeat {
        impact: DefeatImpact::Blocking,
        defeat: Defeat::new(
            DefeatKind::LookedAndBlocked,
            "ink_terminal.activation_claim",
            "participant activation claim is unresolved",
        ),
    };
    ink.activation.defeat(claim_defeat.defeat.clone());
    ink.scoped_defeats.push(claim_defeat);
    let with_defeated_ink = compare(&defeated_ink);
    assert_eq!(
        with_defeated_ink.recurring_outcome,
        Some(ActivationOutcome::InvokesRegisteredHandler)
    );
    assert!(with_defeated_ink.recurrence_blocking_defeats.is_empty());
    assert!(
        with_defeated_ink
            .participant_blocking_defeats
            .iter()
            .any(|defeat| defeat.subject == "ink_terminal.activation_claim")
    );
}

#[test]
fn every_required_native_dimension_is_accounted_for() {
    let report = compare(&observations());
    assert_eq!(report.compared_native_dimensions.len(), 5);
    assert_eq!(
        report.native_divergences.len() + report.equal_native_dimensions.len(),
        5
    );
    for divergence in &report.native_divergences {
        assert_eq!(divergence.values.len(), 3, "{:?}", divergence.dimension);
        assert_eq!(
            divergence.preserved_extension_keys.len(),
            3,
            "{:?}",
            divergence.dimension
        );
    }
}

#[test]
fn missing_native_dimension_is_an_explicit_blocking_gap() {
    let mut observations = observations();
    let react = observations
        .iter_mut()
        .find(|observation| observation.ecosystem == Ecosystem::ReactDom)
        .unwrap();
    let subject = react.audit_subject_id.clone();
    react
        .activation
        .value
        .extensions
        .get_mut(Ecosystem::ReactDom.extension_key())
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("host");

    let report = compare(&observations);
    assert_eq!(report.recurring_outcome, None);
    assert!(!report.blocking_defeats.is_empty());
    assert!(report.evidence_gaps.iter().any(|gap| {
        gap.audit_subject_id == subject && gap.dimension == Some(DivergenceDimension::Host)
    }));
    assert!(
        !report
            .compared_native_dimensions
            .contains(&DivergenceDimension::Host)
    );
}

#[test]
fn blocking_and_disjoint_defeats_are_typed_not_string_classified() {
    let mut observations = observations();
    let blocking = ScopedDefeat {
        impact: DefeatImpact::Blocking,
        defeat: Defeat::new(
            DefeatKind::OutOfScope,
            "looks.like.a.scope.limit",
            "free-form text cannot make this non-blocking",
        ),
    };
    observations[0].activation.defeat(blocking.defeat.clone());
    observations[0].scoped_defeats.push(blocking);
    let report = compare(&observations);

    assert_eq!(report.recurring_outcome, None);
    assert!(
        report
            .blocking_defeats
            .iter()
            .any(|defeat| defeat.subject == "looks.like.a.scope.limit")
    );
}

#[test]
fn untyped_defeats_block_recurrence() {
    let mut observations = observations();
    observations[0].activation.defeat(Defeat::new(
        DefeatKind::LookedAndBlocked,
        "react_dom.dispatch",
        "generated chain is unresolved",
    ));
    let report = compare(&observations);

    assert_eq!(report.recurring_outcome, None);
    assert!(
        report
            .blocking_defeats
            .iter()
            .any(|defeat| defeat.subject.ends_with(".defeat_admission"))
    );
}

#[test]
fn invalid_action_activation_blocks_recurrence_even_if_outcomes_match() {
    let mut observations = observations();
    observations[0].activation.value.action_id = " ".to_owned();
    let report = compare(&observations);

    assert_eq!(report.recurring_outcome, None);
    assert!(
        report
            .blocking_defeats
            .iter()
            .any(|defeat| defeat.subject.ends_with(".semantic_activation"))
    );
}

#[test]
fn a_role_label_cannot_override_inks_source_derived_react_lineage() {
    let mut observations = observations();
    observations
        .iter_mut()
        .find(|observation| observation.ecosystem == Ecosystem::Ink)
        .unwrap()
        .role = ObservationRole::IndependentVote;
    let report = compare(&observations);

    assert_eq!(
        report.recurring_outcome,
        Some(ActivationOutcome::InvokesRegisteredHandler)
    );
    assert!(
        report
            .blocking_defeats
            .iter()
            .any(|defeat| defeat.subject.ends_with(".observation_identity"))
    );
    assert!(report.recurrence_blocking_defeats.is_empty());
    assert!(!report.participant_blocking_defeats.is_empty());
    assert_eq!(report.independent_authorities, 2);
}

#[test]
fn summaries_use_audit_local_subject_identity_and_exact_sources() {
    for observation in observations() {
        let summary = source_summary(&observation);
        assert_eq!(summary["audit_subject_id"], observation.audit_subject_id);
        assert!(summary.get("action_id").is_none());
        assert_eq!(
            summary["sources"].as_array().unwrap().len(),
            observation.native.sources.len()
        );
    }
}

#[test]
#[ignore = "effectful: fetches five pinned upstream Git revisions"]
fn refreshing_authorities_from_clean_upstream_checkouts_is_byte_identical() {
    let corpus = load_corpus(default_corpus_root()).expect("checked-in authority corpus verifies");
    let mut repositories: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
    for authority in &corpus.manifest().authorities {
        repositories
            .entry((
                authority.repository.url.clone(),
                authority.repository.commit.clone(),
            ))
            .or_default()
            .push((
                authority.source_path.clone(),
                authority.snapshot_path.clone(),
            ));
    }
    for license in &corpus.manifest().licenses {
        repositories
            .entry((
                license.repository.url.clone(),
                license.repository.commit.clone(),
            ))
            .or_default()
            .push((license.source_path.clone(), license.snapshot_path.clone()));
    }

    let temporary = tempfile::tempdir().expect("temporary upstream audit directory");
    for (index, ((url, revision), sources)) in repositories.into_iter().enumerate() {
        let checkout = temporary.path().join(format!("authority-{index}"));
        git(&["init", "--quiet"], &checkout);
        git(&["remote", "add", "origin", &url], &checkout);
        git(
            &["fetch", "--quiet", "--depth", "1", "origin", &revision],
            &checkout,
        );
        for (source_path, snapshot_path) in sources {
            let object = format!("{revision}:{source_path}");
            let upstream = git(&["show", &object], &checkout);
            let checked_in = fs::read(corpus.root().join(&snapshot_path))
                .unwrap_or_else(|error| panic!("could not read {snapshot_path}: {error}"));
            assert_eq!(upstream, checked_in, "{url}@{revision}:{source_path}");
        }
    }
}

fn copied_corpus() -> tempfile::TempDir {
    let temporary = tempfile::tempdir().expect("temporary corpus");
    copy_tree(&default_corpus_root(), temporary.path());
    temporary
}

fn mutate_json(path: &Path, mutate: impl FnOnce(&mut Value)) {
    let mut value: Value =
        serde_json::from_slice(&fs::read(path).expect("read JSON")).expect("valid JSON");
    mutate(&mut value);
    fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).expect("write JSON");
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create corpus directory");
    for entry in fs::read_dir(source).expect("read corpus directory") {
        let entry = entry.expect("read corpus entry");
        let target = destination.join(entry.file_name());
        if entry.file_type().expect("read corpus entry type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).expect("copy corpus entry");
        }
    }
}

fn git(arguments: &[&str], repository: &Path) -> Vec<u8> {
    let mut command = Command::new("git");
    if !repository.exists() {
        fs::create_dir_all(repository).expect("create audit repository directory");
    }
    command.arg("-C").arg(repository);
    let output = command
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("could not run git {arguments:?}: {error}"));
    assert!(
        output.status.success(),
        "git {arguments:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
