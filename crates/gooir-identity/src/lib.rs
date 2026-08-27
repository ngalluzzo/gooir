//! Exact semantic identity primitives.
//!
//! Package, name, and version, matched exactly and never by range. This shape
//! existed twice: as `gooir_core::ContractId`, and as a private macro in
//! `gooir-capability` generating `FactType`, `CapabilityId`, and `ProviderId`.
//!
//! Distinct *types* are worth keeping — a fact is not a capability, and the
//! compiler should say so. Two *implementations* of the same rule were not:
//! they drifted in derives, gained different `Display` forms, and made the
//! repository read as two projects that happened to share a directory.
//!
//! A dialect and a value kind are deliberately different levels. A dialect is
//! one governed, versioned vocabulary. A value kind is one exact named type in
//! that vocabulary. Other exact identities are generated with
//! [`exact_identity!`].

use serde::{Deserialize, Serialize};

/// One independently governed, exactly versioned vocabulary family.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct DialectId {
    pub package: String,
    pub version: String,
}

impl DialectId {
    pub fn new(package: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            package: package.into(),
            version: version.into(),
        }
    }

    /// True when this names the same vocabulary at a different version.
    ///
    /// No compatibility is inferred. A version-changing relationship still
    /// requires an explicit capability.
    pub fn is_other_version_of(&self, other: &Self) -> bool {
        self.package == other.package && self.version != other.version
    }

    /// Reads the display form, `package@version`, without filling defaults.
    pub fn parse(text: &str) -> Result<Self, IdentityParseError> {
        let (package, version) = text
            .split_once('@')
            .ok_or_else(|| IdentityParseError::new(text, "expected package@version"))?;
        let id = Self::new(package, version);
        if !id.is_well_formed() || version.contains('@') {
            return Err(IdentityParseError::new(
                text,
                "a part is blank or ambiguous",
            ));
        }
        Ok(id)
    }

    pub fn is_well_formed(&self) -> bool {
        !self.package.trim().is_empty()
            && !self.version.trim().is_empty()
            && !self.package.contains('@')
            && !self.package.contains('/')
            && !self.version.contains('@')
            && !self.version.contains('/')
    }
}

impl std::fmt::Display for DialectId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}@{}", self.package, self.version)
    }
}

/// One exact named type within a [`DialectId`].
///
/// The serialized fields and display form intentionally match the historical
/// `FactType`/`ContractId` representation during migration.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ValueKindId {
    pub package: String,
    pub name: String,
    pub version: String,
}

impl ValueKindId {
    /// Compatibility constructor for the historical exact-identity shape.
    pub fn new(
        package: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            package: package.into(),
            name: name.into(),
            version: version.into(),
        }
    }

    /// Names one value kind under an explicit vocabulary family.
    pub fn in_dialect(dialect: DialectId, name: impl Into<String>) -> Self {
        Self::new(dialect.package, name, dialect.version)
    }

    /// Returns the vocabulary family governing this value kind.
    pub fn dialect(&self) -> DialectId {
        DialectId::new(self.package.clone(), self.version.clone())
    }

    /// True when this names the same value kind at a different version.
    ///
    /// The two identities remain incompatible until an explicit capability
    /// relates them.
    pub fn is_other_version_of(&self, other: &Self) -> bool {
        self.package == other.package && self.name == other.name && self.version != other.version
    }

    /// Reads the compatibility display form, `package/name@version`.
    pub fn parse(text: &str) -> Result<Self, IdentityParseError> {
        let (package, rest) = text
            .split_once('/')
            .ok_or_else(|| IdentityParseError::new(text, "expected package/name@version"))?;
        let (name, version) = rest
            .split_once('@')
            .ok_or_else(|| IdentityParseError::new(text, "expected a @version"))?;
        let id = Self::new(package, name, version);
        if !id.is_well_formed() || rest.contains('/') || version.contains('@') {
            return Err(IdentityParseError::new(
                text,
                "a part is blank or ambiguous",
            ));
        }
        Ok(id)
    }

    pub fn is_well_formed(&self) -> bool {
        self.dialect().is_well_formed()
            && !self.name.trim().is_empty()
            && !self.name.contains('@')
            && !self.name.contains('/')
    }
}

impl std::fmt::Display for ValueKindId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}@{}", self.package, self.name, self.version)
    }
}

/// Why an identity could not be read from its display form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityParseError {
    pub text: String,
    pub reason: &'static str,
}

impl IdentityParseError {
    pub fn new(text: impl Into<String>, reason: &'static str) -> Self {
        Self {
            text: text.into(),
            reason,
        }
    }
}

impl std::fmt::Display for IdentityParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "`{}` is not an exact identity: {}",
            self.text, self.reason
        )
    }
}

impl std::error::Error for IdentityParseError {}

/// Declares an exact identity type.
///
/// ```
/// gooir_identity::exact_identity! {
///     /// What this identity names.
///     MyId
/// }
/// let id = MyId::new("org.example", "thing", "1.0.0");
/// assert_eq!(id.to_string(), "org.example/thing@1.0.0");
/// ```
#[macro_export]
macro_rules! exact_identity {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd,
            ::serde::Serialize, ::serde::Deserialize,
        )]
        pub struct $name {
            pub package: String,
            pub name: String,
            pub version: String,
        }

        impl $name {
            pub fn new(
                package: impl Into<String>,
                name: impl Into<String>,
                version: impl Into<String>,
            ) -> Self {
                Self {
                    package: package.into(),
                    name: name.into(),
                    version: version.into(),
                }
            }

            /// True when this names the same thing at a different version.
            ///
            /// Two versions of one identity are *not* compatible. This only
            /// reports that a version-changing relationship exists, which a
            /// caller must bridge explicitly.
            pub fn is_other_version_of(&self, other: &Self) -> bool {
                self.package == other.package
                    && self.name == other.name
                    && self.version != other.version
            }

            /// Reads the display form, `package/name@version`.
            ///
            /// Exactness is the whole point, so this refuses anything it
            /// cannot read rather than filling in a default part.
            pub fn parse(text: &str) -> Result<Self, $crate::IdentityParseError> {
                let (package, rest) = text.split_once('/').ok_or_else(|| {
                    $crate::IdentityParseError::new(text, "expected package/name@version")
                })?;
                let (name, version) = rest.split_once('@').ok_or_else(|| {
                    $crate::IdentityParseError::new(text, "expected a @version")
                })?;
                let id = Self::new(package, name, version);
                if !id.is_well_formed() {
                    return Err($crate::IdentityParseError::new(text, "a part is blank"));
                }
                Ok(id)
            }

            /// False when any part is blank. An identity with an empty part
            /// cannot be matched exactly, so it cannot mean anything.
            pub fn is_well_formed(&self) -> bool {
                !self.package.trim().is_empty()
                    && !self.name.trim().is_empty()
                    && !self.version.trim().is_empty()
                    && !self.package.contains('/')
                    && !self.package.contains('@')
                    && !self.name.contains('/')
                    && !self.name.contains('@')
                    && !self.version.contains('/')
                    && !self.version.contains('@')
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(formatter, "{}/{}@{}", self.package, self.name, self.version)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::{DialectId, ValueKindId};

    exact_identity! {
        /// A test identity.
        TestId
    }

    #[test]
    fn identities_render_as_package_name_at_version() {
        let id = TestId::new("org.example", "thing", "1.0.0");
        assert_eq!(id.to_string(), "org.example/thing@1.0.0");
    }

    #[test]
    fn a_version_change_is_reported_not_resolved() {
        let a = TestId::new("p", "n", "1.0.0");
        let b = TestId::new("p", "n", "2.0.0");
        assert!(a.is_other_version_of(&b));
        assert_ne!(a, b, "different versions are different identities");
        assert!(!a.is_other_version_of(&a));
    }

    #[test]
    fn an_identity_round_trips_through_its_display_form() {
        let id = TestId::new("org.example", "thing", "1.0.0");
        assert_eq!(TestId::parse(&id.to_string()).unwrap(), id);
    }

    #[test]
    fn a_malformed_identity_is_refused_rather_than_completed() {
        for bad in [
            "no-slash@1.0.0",
            "pkg/no-version",
            "pkg/nested/name@1.0.0",
            "pkg/name@1.0.0@other",
            "/name@1.0.0",
            "pkg/@1.0.0",
            "pkg/name@",
            "",
        ] {
            assert!(TestId::parse(bad).is_err(), "`{bad}` must not parse");
        }
    }

    #[test]
    fn a_blank_part_is_not_well_formed() {
        assert!(TestId::new("p", "n", "1").is_well_formed());
        assert!(!TestId::new("", "n", "1").is_well_formed());
        assert!(!TestId::new("p", "  ", "1").is_well_formed());
        assert!(!TestId::new("p", "n", "").is_well_formed());
    }

    #[test]
    fn identities_order_and_hash_so_they_can_key_a_graph() {
        use std::collections::BTreeSet;
        let set: BTreeSet<TestId> = [
            TestId::new("b", "n", "1"),
            TestId::new("a", "n", "1"),
            TestId::new("a", "n", "1"),
        ]
        .into_iter()
        .collect();
        assert_eq!(set.len(), 2);
        assert_eq!(set.iter().next().unwrap().package, "a");
    }

    #[test]
    fn dialect_and_value_kind_are_distinct_exact_levels() {
        let dialect = DialectId::new("org.gooi.conversation", "1.0.0");
        let message = ValueKindId::in_dialect(dialect.clone(), "message");

        assert_eq!(dialect.to_string(), "org.gooi.conversation@1.0.0");
        assert_eq!(message.to_string(), "org.gooi.conversation/message@1.0.0");
        assert_eq!(message.dialect(), dialect);
        assert_eq!(DialectId::parse(&dialect.to_string()).unwrap(), dialect);
        assert_eq!(ValueKindId::parse(&message.to_string()).unwrap(), message);
    }

    #[test]
    fn value_kind_keeps_the_historical_wire_shape() {
        let kind = ValueKindId::new("org.gooi.conversation", "message", "1.0.0");
        assert_eq!(kind.package, "org.gooi.conversation");
        assert_eq!(kind.name, "message");
        assert_eq!(kind.version, "1.0.0");
    }

    #[test]
    fn hierarchy_delimiters_cannot_make_an_identity_ambiguous() {
        for bad in ["org.example@@1", "org.example/sub@1", "@1", "org.example@"] {
            assert!(DialectId::parse(bad).is_err(), "`{bad}` must not parse");
        }
        for bad in [
            "org.example/a/b@1",
            "org.example/name@1@2",
            "org.example/@1",
        ] {
            assert!(ValueKindId::parse(bad).is_err(), "`{bad}` must not parse");
        }
    }
}
