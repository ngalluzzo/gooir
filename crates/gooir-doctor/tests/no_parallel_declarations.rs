//! The drift guard this project exists to have, pointed at this project.
//!
//! GOOIR's premise is that one idea implemented twice in two layers is a defect
//! you find far too late. That is as true of GOOIR as of anything it inspects.
//! These fail rather than warn, because a warning nobody reads guards nothing.

use gooir_doctor::declarations::{scan, workspace_crates};

#[test]
fn exactly_one_crate_implements_the_exact_identity_rule() {
    let found = scan(&workspace_crates());
    assert_eq!(
        found.identity_implementations,
        vec!["gooir-identity (macro)".to_owned()],
        "a second spelling of exact identity is the drift 0016 removed; \
         if this is deliberate, the decision record has to say so"
    );
}

#[test]
fn no_fact_identity_is_declared_in_two_crates() {
    let found = scan(&workspace_crates());
    assert!(
        found.facts_declared_twice.is_empty(),
        "a fact identity written down twice is two authorities on one meaning: {:#?}",
        found.facts_declared_twice
    );
}

#[test]
fn the_scan_does_not_count_itself() {
    // An earlier version of this scan reported its own search strings as
    // matches. The needles are split so the scanner's source cannot match them;
    // this asserts the property rather than trusting the trick.
    let found = scan(&workspace_crates());
    assert!(
        !found
            .identity_implementations
            .iter()
            .any(|i| i.starts_with("gooir-doctor")),
        "the instrument counted itself: {:?}",
        found.identity_implementations
    );
}
