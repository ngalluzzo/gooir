//! Product-host composition from semantic `FileTree` derivation to physical
//! materialization.
//!
//! This crate adds no dialect, capability, effect model, or serialized build
//! protocol. It fixes the semantic target to the `FileTree` value kind, delegates
//! derivation and admission to [`CompilerDriver`], resolves the exact produced
//! authority through that driver's ledger, and only then invokes a caller-owned
//! [`FileTreeMaterializer`].

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;

use gooir_capability::authority::SourceObservation;
use gooir_derive::{
    Answer, BlockedAnswer, COMPLETE_SELECTION_EXTENSION, CompilerDriver, CompleteSelectionId,
    DerivationHost, FailedAnswer, ProducedAnswer, Refusal, UnreachableAnswer,
};
use gooir_file_tree_materializer::{
    AdmittedFileTree, AdmittedFileTreeError, AuthorityExtension, AuthorityExtensionError,
    AuthorityExtensionScope, AuthorityExtensionValidator, FileTreeMaterializer,
};
use gooir_file_tree_v1::file_tree_value_kind;

/// A successful physical build bound to the exact admitted semantic product.
#[derive(Debug, PartialEq)]
pub struct MaterializedFileTreeBuild<R> {
    pub produced: Box<ProducedAnswer>,
    pub receipt: R,
}

/// Product-level build answers.
///
/// `Materialized` is the physical-success refinement of the compiler's
/// semantic `Produced` answer. The other four variants preserve their exact
/// compiler documents and remedies without invoking the materializer.
#[derive(Debug, PartialEq)]
pub enum FileTreeBuildAnswer<R> {
    Materialized(Box<MaterializedFileTreeBuild<R>>),
    Blocked(Box<BlockedAnswer>),
    Unreachable(Box<UnreachableAnswer>),
    Refused(Box<Refusal>),
    Failed(Box<FailedAnswer>),
}

impl<R> FileTreeBuildAnswer<R> {
    /// The caller action appropriate to this exact terminal category.
    #[must_use]
    pub const fn remedy(&self) -> &'static str {
        match self {
            Self::Materialized(_) => "use the physical files and retained effect receipt",
            Self::Blocked(_) => "supply the missing implementation or attester",
            Self::Unreachable(_) => "declare a semantic capability route",
            Self::Refused(_) => "fix the request, selection, or admission policy",
            Self::Failed(_) => "inspect the fixed attempt and repair its failing stage",
        }
    }
}

/// Host-local failure after the compiler produced an admitted `FileTree` target.
///
/// Both variants retain that exact semantic product. These errors are not a
/// serialized semantic answer, and callers must follow the selected
/// materializer's documented effect semantics before retrying.
#[derive(Debug)]
pub enum FileTreeBuildError<E> {
    /// The materializer's conservative authority/value gate refused the
    /// compiler product before calling the effect implementation.
    ArtifactAdmission {
        produced: Box<ProducedAnswer>,
        source: AdmittedFileTreeError,
    },
    /// The selected materializer refused or failed its host operation.
    Materialization {
        produced: Box<ProducedAnswer>,
        source: E,
    },
}

impl<E> FileTreeBuildError<E> {
    /// The admitted semantic product retained despite host-side failure.
    #[must_use]
    pub const fn produced(&self) -> &ProducedAnswer {
        match self {
            Self::ArtifactAdmission { produced, .. } | Self::Materialization { produced, .. } => {
                produced
            }
        }
    }
}

impl<E: fmt::Display> fmt::Display for FileTreeBuildError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactAdmission { source, .. } => {
                write!(
                    formatter,
                    "admitted FileTree was refused before materialization effects: {source}"
                )
            }
            Self::Materialization { source, .. } => {
                write!(formatter, "FileTree materialization failed: {source}")
            }
        }
    }
}

impl<E> Error for FileTreeBuildError<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ArtifactAdmission { source, .. } => Some(source),
            Self::Materialization { source, .. } => Some(source),
        }
    }
}

/// In-process product host that composes semantic compilation with one
/// explicit `FileTree` materializer.
///
/// The driver owns both components so the exact ledger mutated by compilation
/// is necessarily the ledger used by the materializer's authority gate.
#[derive(Debug)]
pub struct FileTreeBuildDriver<H, M> {
    compiler: CompilerDriver<H>,
    materializer: M,
}

struct CompilerSelectionExtensionValidator<'selection> {
    selection_id: &'selection CompleteSelectionId,
}

impl AuthorityExtensionValidator for CompilerSelectionExtensionValidator<'_> {
    fn validate(
        &mut self,
        extension: AuthorityExtension<'_>,
    ) -> Result<(), AuthorityExtensionError> {
        if extension.scope != AuthorityExtensionScope::ImplementationSelection
            || extension.key != COMPLETE_SELECTION_EXTENSION
        {
            return Err(AuthorityExtensionError::Unhandled);
        }
        if extension.value.as_str() == Some(self.selection_id.as_str()) {
            Ok(())
        } else {
            Err(AuthorityExtensionError::Invalid(
                "value does not match the compiler's complete selection identity".to_owned(),
            ))
        }
    }
}

impl<H, M> FileTreeBuildDriver<H, M>
where
    H: DerivationHost,
    M: FileTreeMaterializer,
{
    /// Composes an already configured compiler driver with one explicit
    /// materializer. Construction itself performs no effects.
    #[must_use]
    pub const fn new(compiler: CompilerDriver<H>, materializer: M) -> Self {
        Self {
            compiler,
            materializer,
        }
    }

    /// Derives, admits, authority-gates, and materializes one `FileTree`.
    ///
    /// The semantic target is fixed by this type and cannot be caller-swapped.
    /// The materializer is called only after an exact `Produced` target resolves
    /// through the compiler driver's current ledger.
    ///
    /// # Errors
    ///
    /// Returns a host-local error when the produced artifact fails the
    /// conservative `FileTree` gate or the selected materializer refuses/fails.
    /// Both errors retain the exact admitted semantic product.
    pub fn build(
        &mut self,
        observations: impl IntoIterator<Item = SourceObservation>,
        destination: &M::Destination,
        policy: &M::Policy,
    ) -> Result<FileTreeBuildAnswer<M::Receipt>, FileTreeBuildError<M::Error>> {
        match self.compiler.compile(file_tree_value_kind(), observations) {
            Answer::Produced(produced) => {
                let resolution = {
                    let mut validator = CompilerSelectionExtensionValidator {
                        selection_id: &produced.selection_id,
                    };
                    AdmittedFileTree::resolve_with_authority_extensions(
                        self.compiler.ledger(),
                        &produced.target,
                        &mut validator,
                    )
                };
                let artifact = match resolution {
                    Ok(artifact) => artifact,
                    Err(source) => {
                        return Err(FileTreeBuildError::ArtifactAdmission { produced, source });
                    }
                };
                let receipt = match self
                    .materializer
                    .materialize(&artifact, destination, policy)
                {
                    Ok(receipt) => receipt,
                    Err(source) => {
                        return Err(FileTreeBuildError::Materialization { produced, source });
                    }
                };
                Ok(FileTreeBuildAnswer::Materialized(Box::new(
                    MaterializedFileTreeBuild { produced, receipt },
                )))
            }
            Answer::Blocked(answer) => Ok(FileTreeBuildAnswer::Blocked(answer)),
            Answer::Unreachable(answer) => Ok(FileTreeBuildAnswer::Unreachable(answer)),
            Answer::Refused(answer) => Ok(FileTreeBuildAnswer::Refused(answer)),
            Answer::Failed(answer) => Ok(FileTreeBuildAnswer::Failed(answer)),
        }
    }

    /// The semantic compiler component and its current admission ledger.
    #[must_use]
    pub const fn compiler(&self) -> &CompilerDriver<H> {
        &self.compiler
    }

    /// Mutable access for host-specific inspection or configuration.
    #[must_use]
    pub const fn compiler_mut(&mut self) -> &mut CompilerDriver<H> {
        &mut self.compiler
    }

    /// The selected physical materializer.
    #[must_use]
    pub const fn materializer(&self) -> &M {
        &self.materializer
    }

    /// Mutable access to the selected physical materializer.
    #[must_use]
    pub const fn materializer_mut(&mut self) -> &mut M {
        &mut self.materializer
    }

    /// Recovers both configured host components.
    #[must_use]
    pub fn into_parts(self) -> (CompilerDriver<H>, M) {
        (self.compiler, self.materializer)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn selection_id() -> CompleteSelectionId {
        serde_json::from_value(json!(format!("sha256:{}", "a".repeat(64)))).unwrap()
    }

    #[test]
    fn compiler_extension_validator_binds_scope_key_and_value() {
        let selection_id = selection_id();
        let exact = json!(selection_id.as_str());
        let mut validator = CompilerSelectionExtensionValidator {
            selection_id: &selection_id,
        };
        assert_eq!(
            validator.validate(AuthorityExtension {
                scope: AuthorityExtensionScope::ImplementationSelection,
                key: COMPLETE_SELECTION_EXTENSION,
                value: &exact,
            }),
            Ok(())
        );

        let wrong_value = json!(format!("sha256:{}", "b".repeat(64)));
        assert!(matches!(
            validator.validate(AuthorityExtension {
                scope: AuthorityExtensionScope::ImplementationSelection,
                key: COMPLETE_SELECTION_EXTENSION,
                value: &wrong_value,
            }),
            Err(AuthorityExtensionError::Invalid(_))
        ));
        assert_eq!(
            validator.validate(AuthorityExtension {
                scope: AuthorityExtensionScope::CapabilityInvocation,
                key: COMPLETE_SELECTION_EXTENSION,
                value: &exact,
            }),
            Err(AuthorityExtensionError::Unhandled)
        );
        assert_eq!(
            validator.validate(AuthorityExtension {
                scope: AuthorityExtensionScope::ImplementationSelection,
                key: "org.example/unknown",
                value: &exact,
            }),
            Err(AuthorityExtensionError::Unhandled)
        );
    }
}
