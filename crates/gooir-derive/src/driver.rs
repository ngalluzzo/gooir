//! Ergonomic compiler driver over the complete v1 derivation façade.
//!
//! The driver accepts source observations rather than caller-authored
//! authority records, stages their contextual admission, and delegates route,
//! offer, input, authority-basis, linking, execution, and derived admission
//! decisions to [`DerivationFacade`]. It adds no serialized compile protocol
//! and no execution transport.

use std::fmt;
use std::num::NonZeroUsize;

use gooir_capability::ValueKindId;
use gooir_capability::authority::{
    AdmissionLedger, AdmissionOutcome, AdmissionPolicy, AuthorityError, ConformanceAuthority,
    SourceObservation,
};
use gooir_capability::protocol::AdmittedFactRef;
use gooir_package::PackageRegistry;
use gooir_planning::RouteOutputRef;

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
/// host, exact policy, optional independent assessment, and admission ledger.
#[derive(Debug)]
pub struct CompilerDriver<H> {
    facade: DerivationFacade,
    ledger: AdmissionLedger,
    policy: AdmissionPolicy,
    attesters: AttesterInventory,
    host: H,
    max_inputs: NonZeroUsize,
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
            max_inputs: limits.max_inputs,
        })
    }

    /// Admits the exact source observations and answers one derivation request.
    ///
    /// Source admission is staged: an invalid or withheld observation leaves
    /// the driver's ledger unchanged. Once every source is admitted, the
    /// existing façade performs conservative complete selection, explicit
    /// linking, host invocation, direct-provider authorization or independent
    /// assessment, and admission.
    pub fn compile(
        &mut self,
        target: ValueKindId,
        observations: impl IntoIterator<Item = SourceObservation>,
    ) -> Answer {
        let inputs = match self.admit_sources(observations) {
            Ok(inputs) => inputs,
            Err(refusal) => return Answer::Refused(refusal),
        };
        self.derive_request(&DerivationRequest::unique_only(target, inputs))
    }

    /// Admits the exact source observations and derives one named capability
    /// output using conservative unique-only selection beneath that terminal.
    ///
    /// This is the product path for independently installed generators that
    /// share a portable output kind such as `ContentSet`.
    pub fn compile_output(
        &mut self,
        target: RouteOutputRef,
        observations: impl IntoIterator<Item = SourceObservation>,
    ) -> Answer {
        let inputs = match self.admit_sources(observations) {
            Ok(inputs) => inputs,
            Err(refusal) => return Answer::Refused(refusal),
        };
        self.derive_output(target, &inputs)
    }

    /// Atomically admits source observations into this reusable driver and
    /// returns their exact contextual references.
    ///
    /// No derivation is selected or executed. Invalid, withheld, or excessive
    /// observations leave the ledger unchanged, so callers may admit one
    /// source bundle once and use its references for several later requests.
    ///
    /// # Errors
    ///
    /// Returns a product-facing refusal when an observation is invalid,
    /// withheld by policy, or exceeds the configured input bound.
    pub fn admit_sources(
        &mut self,
        observations: impl IntoIterator<Item = SourceObservation>,
    ) -> Result<Vec<AdmittedFactRef>, Box<Refusal>> {
        let mut observations = observations.into_iter();
        let mut staged = self.ledger.clone();
        let mut inputs = Vec::new();
        for index in 0.. {
            let Some(observation) = observations.next() else {
                break;
            };
            if index == self.max_inputs.get() {
                return Err(Box::new(Refusal::InvalidRequest {
                    detail: format!(
                        "source observation count exceeds configured input limit {}",
                        self.max_inputs
                    ),
                }));
            }
            let outcome = match staged.admit_observation(&self.policy, &observation) {
                Ok(outcome) => outcome,
                Err(error) => {
                    return Err(Box::new(Refusal::InvalidRequest {
                        detail: format!("source observation is invalid: {error}"),
                    }));
                }
            };
            match outcome {
                AdmissionOutcome::Admitted { links, .. } => {
                    let [link] = links.as_slice() else {
                        return Err(Box::new(Refusal::InvalidRequest {
                            detail: "source admission did not return one exact fact reference"
                                .to_owned(),
                        }));
                    };
                    if link.port.is_some() {
                        return Err(Box::new(Refusal::InvalidRequest {
                            detail: "source admission unexpectedly returned an output port"
                                .to_owned(),
                        }));
                    }
                    inputs.push(link.reference.clone());
                }
                AdmissionOutcome::Withheld { decision } => {
                    return Err(Box::new(Refusal::AdmissionPolicy {
                        decision: Some(Box::new(decision)),
                        detail: "a source observation was withheld by the admission policy"
                            .to_owned(),
                    }));
                }
            }
        }
        self.ledger = staged;
        Ok(inputs)
    }

    /// Answers one request using already-admitted references and retains every
    /// newly admitted derived output for later requests.
    pub fn derive_request(&mut self, request: &DerivationRequest) -> Answer {
        self.facade.answer(
            &mut self.ledger,
            &self.policy,
            &self.attesters,
            &mut self.host,
            request,
        )
    }

    /// Derives one exact named output from already-admitted references.
    pub fn derive_output(&mut self, target: RouteOutputRef, inputs: &[AdmittedFactRef]) -> Answer {
        self.derive_request(&DerivationRequest::unique_output(
            target,
            inputs.iter().cloned(),
        ))
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
