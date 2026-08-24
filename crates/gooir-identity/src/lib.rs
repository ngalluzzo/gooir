//! The one exact-identity primitive.
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
//! Every identity type in GOOIR is now generated from here.

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

            /// False when any part is blank. An identity with an empty part
            /// cannot be matched exactly, so it cannot mean anything.
            pub fn is_well_formed(&self) -> bool {
                !self.package.trim().is_empty()
                    && !self.name.trim().is_empty()
                    && !self.version.trim().is_empty()
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
}
