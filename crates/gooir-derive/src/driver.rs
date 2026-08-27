//! Ergonomic compiler driver over the complete v1 derivation façade.
//!
//! The driver accepts source observations rather than caller-authored
//! authority records, stages their contextual admission, and delegates route,
//! offer, input, attester, linking, execution, conformance, and derived
//! admission decisions to [`DerivationFacade`]. It adds no serialized compile
//! protocol and no execution transport.

use std::fmt;

use gooir_capability::ValueKindId;
use gooir_capability::authority::{
    AdmissionLedger, AdmissionOutcome, AdmissionPolicy, AuthorityError, ConformanceAuthority,
    SourceObservation,
};
use gooir_package::PackageRegistry;

use crate::{
    Answer, AttesterInventory, DerivationFacade, DerivationHost, DerivationLimits,
    DerivationRequest, FacadeError, Refusal,
};

/// One reusable compiler driver bound to an immutable package inventory and
/// fixed host policy.
///
/// A caller supplies semantic source observations and a target. The driver
/// creates no offers, selections, invocations, or authority records directly;
/// those remain products of the installed registry, façade linker, external
/// host, independent assessment, and admission ledger respectively.
#[derive(Debug)]
pub struct CompilerDriver<H> {
    facade: DerivationFacade,
    ledger: AdmissionLedger,
    policy: AdmissionPolicy,
    attesters: AttesterInventory,
    host: H,
}

impl<H> CompilerDriver<H>
where
    H: DerivationHost,
{
    /// Binds one driver to exact installed packages, policy, attester
    /// inventory, host, and finite limits.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy, attester inventory, or package-backed
    /// planning inventory is invalid or exceeds the supplied limits.
    pub fn new(
        registry: &PackageRegistry,
        policy: AdmissionPolicy,
        attesters: impl IntoIterator<Item = ConformanceAuthority>,
        host: H,
        limits: DerivationLimits,
    ) -> Result<Self, CompilerDriverError> {
        policy
            .validate()
            .map_err(CompilerDriverError::InvalidPolicy)?;
        let attesters = AttesterInventory::new(attesters, limits.max_attesters)
            .map_err(CompilerDriverError::Facade)?;
        let facade =
            DerivationFacade::new(registry, limits).map_err(CompilerDriverError::Facade)?;
        Ok(Self {
            facade,
            ledger: AdmissionLedger::new(),
            policy,
            attesters,
            host,
        })
    }

    /// Admits the exact source observations and answers one derivation request.
    ///
    /// Source admission is staged: an invalid or withheld observation leaves
    /// the driver's ledger unchanged. Once every source is admitted, the
    /// existing façade performs conservative complete selection, explicit
    /// linking, host invocation, independent assessment, and admission.
    pub fn compile(
        &mut self,
        target: ValueKindId,
        observations: impl IntoIterator<Item = SourceObservation>,
    ) -> Answer {
        let mut staged = self.ledger.clone();
        let mut inputs = Vec::new();
        for observation in observations {
            let outcome = match staged.admit_observation(&self.policy, &observation) {
                Ok(outcome) => outcome,
                Err(error) => {
                    return Answer::Refused(Box::new(Refusal::InvalidRequest {
                        detail: format!("source observation is invalid: {error}"),
                    }));
                }
            };
            match outcome {
                AdmissionOutcome::Admitted { links, .. } => {
                    let [link] = links.as_slice() else {
                        return Answer::Refused(Box::new(Refusal::InvalidRequest {
                            detail: "source admission did not return one exact fact reference"
                                .to_owned(),
                        }));
                    };
                    if link.port.is_some() {
                        return Answer::Refused(Box::new(Refusal::InvalidRequest {
                            detail: "source admission unexpectedly returned an output port"
                                .to_owned(),
                        }));
                    }
                    inputs.push(link.reference.clone());
                }
                AdmissionOutcome::Withheld { decision } => {
                    return Answer::Refused(Box::new(Refusal::AdmissionPolicy {
                        decision: Some(Box::new(decision)),
                        detail: "a source observation was withheld by the admission policy"
                            .to_owned(),
                    }));
                }
            }
        }

        let request = DerivationRequest::unique_only(target, inputs);
        let answer = self.facade.answer(
            &mut staged,
            &self.policy,
            &self.attesters,
            &mut self.host,
            &request,
        );
        self.ledger = staged;
        answer
    }

    /// Current contextual admission state, including admitted sources and
    /// every derived output retained from prior compile calls.
    #[must_use]
    pub const fn ledger(&self) -> &AdmissionLedger {
        &self.ledger
    }

    /// The exact fixed admission policy used by this driver.
    #[must_use]
    pub const fn policy(&self) -> &AdmissionPolicy {
        &self.policy
    }

    /// Shared access to the caller-supplied external host.
    #[must_use]
    pub const fn host(&self) -> &H {
        &self.host
    }

    /// Mutable access to the caller-supplied external host.
    #[must_use]
    pub const fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }
}

/// Failure to construct one fixed compiler-driver context.
#[derive(Debug)]
pub enum CompilerDriverError {
    InvalidPolicy(AuthorityError),
    Facade(FacadeError),
}

impl fmt::Display for CompilerDriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(error) => write!(formatter, "invalid admission policy: {error}"),
            Self::Facade(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CompilerDriverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPolicy(error) => Some(error),
            Self::Facade(error) => Some(error),
        }
    }
}
