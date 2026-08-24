//! The defeasible core: a lifted value plus the reasons it may not be trusted.
//!
//! Every lift is a claim with an open set of defeaters. If no defeater fires the
//! result is exhaustive with respect to the named defeater set; if any fires the
//! result degrades to unknown and carries the reason. `Exhaustive` is never
//! absolute -- it is always relative to `defeater_set`.

use serde::{Deserialize, Serialize};

/// Why a lift could not establish something. These are not interchangeable:
/// each implies a different action for whoever reads the result.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefeatKind {
    /// No extractor is installed for the mechanism. Install one.
    NotLooked,
    /// An extractor looked and could not establish the fact. May be unknowable.
    LookedAndBlocked,
    /// The named subject could not be located in the source at all.
    SubjectUnresolvable,
    /// The fact lies outside the admitted scope. Widen the scope.
    OutOfScope,
    /// The authority is structurally incapable of expressing the fact.
    AuthorityCannotExpress,
}

impl DefeatKind {
    /// The action this defeat implies for a reader.
    pub fn remedy(self) -> &'static str {
        match self {
            Self::NotLooked => "install an extractor for this mechanism",
            Self::LookedAndBlocked => "may be unknowable; decide whether it matters",
            Self::SubjectUnresolvable => {
                "the subject does not exist here, or the question is malformed"
            }
            Self::OutOfScope => "widen the admitted scope",
            Self::AuthorityCannotExpress => "consult an authority that can express this fact",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Defeat {
    pub kind: DefeatKind,
    /// What the defeat is about, in the source's own terms.
    pub subject: String,
    pub reason: String,
}

impl Defeat {
    pub fn new(kind: DefeatKind, subject: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            kind,
            subject: subject.into(),
            reason: reason.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    /// No defeater fired, relative to the named defeater set.
    Exhaustive,
    /// At least one defeater fired.
    Partial,
}

/// A lifted value carrying every reason it may be incomplete.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Defeasible<T> {
    pub value: T,
    /// Exact identity of the defeater set applied. `Exhaustive` means nothing
    /// without it.
    pub defeater_set: String,
    pub defeats: Vec<Defeat>,
}

impl<T> Defeasible<T> {
    pub fn new(value: T, defeater_set: impl Into<String>) -> Self {
        Self {
            value,
            defeater_set: defeater_set.into(),
            defeats: Vec::new(),
        }
    }

    pub fn defeat(&mut self, defeat: Defeat) {
        self.defeats.push(defeat);
    }

    pub fn completeness(&self) -> Completeness {
        if self.defeats.is_empty() {
            Completeness::Exhaustive
        } else {
            Completeness::Partial
        }
    }

    pub fn is_exhaustive(&self) -> bool {
        self.defeats.is_empty()
    }

    pub fn defeats_of(&self, kind: DefeatKind) -> impl Iterator<Item = &Defeat> {
        self.defeats.iter().filter(move |d| d.kind == kind)
    }
}

/// Three-valued logic. Absence of proof is never falsity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Truth {
    True,
    False,
    Unknown,
}

impl Truth {
    pub fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::True, Self::True) => Self::True,
            _ => Self::Unknown,
        }
    }

    pub fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::False, Self::False) => Self::False,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_defeater_is_exhaustive_relative_to_its_set() {
        let d = Defeasible::new(1u32, "test@1");
        assert_eq!(d.completeness(), Completeness::Exhaustive);
        assert_eq!(d.defeater_set, "test@1");
    }

    #[test]
    fn any_defeater_degrades_the_whole_result() {
        let mut d = Defeasible::new(1u32, "test@1");
        d.defeat(Defeat::new(DefeatKind::NotLooked, "x", "no extractor"));
        assert_eq!(d.completeness(), Completeness::Partial);
        assert!(!d.is_exhaustive());
    }

    #[test]
    fn defeat_kinds_carry_distinct_remedies() {
        let kinds = [
            DefeatKind::NotLooked,
            DefeatKind::LookedAndBlocked,
            DefeatKind::SubjectUnresolvable,
            DefeatKind::OutOfScope,
            DefeatKind::AuthorityCannotExpress,
        ];
        let remedies: std::collections::BTreeSet<_> = kinds.iter().map(|k| k.remedy()).collect();
        assert_eq!(
            remedies.len(),
            kinds.len(),
            "each kind needs its own action"
        );
    }

    #[test]
    fn unknown_never_becomes_false() {
        assert_eq!(Truth::Unknown.and(Truth::True), Truth::Unknown);
        assert_eq!(Truth::Unknown.or(Truth::False), Truth::Unknown);
        assert_eq!(Truth::Unknown.and(Truth::False), Truth::False);
        assert_eq!(Truth::Unknown.or(Truth::True), Truth::True);
    }
}
