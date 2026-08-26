//! Semantically agnostic capability planning and in-process execution.
//!
//! A capability is a typed promise over exact fact identities. A provider is
//! one implementation of that promise. The planner understands neither the
//! meanings of facts nor domain verbs such as lift, analyze, or lower; it only
//! constructs derivations over multi-input capability edges.

mod manifest;

pub use manifest::{
    ManifestCapability, ManifestRequirement, PACK_PROTOCOL, PackManifest, PackManifestError,
    read_pack, register_pack, write_pack,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::{error::Error, fmt};

pub use gooir_identity::{DialectId, ValueKindId};

/// Compatibility name for the exact kind of a fact.
///
/// New code should say [`ValueKindId`]. The alias preserves the existing
/// display form, serialized fields, constructors, and downstream source while
/// the graph migrates to the explicit dialect/value-kind vocabulary.
pub type FactType = ValueKindId;

gooir_identity::exact_identity! {
    /// The exact identity of a typed promise from facts to facts.
    CapabilityId
}

gooir_identity::exact_identity! {
    /// The exact identity of one implementation of a capability.
    ProviderId
}

/// Content-derived identity of one semantic fact value.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FactId(String);

impl FactId {
    pub fn parse(value: impl Into<String>) -> Result<Self, FactIdentityError> {
        let value = value.into();
        if is_sha256_identity(&value) {
            Ok(Self(value))
        } else {
            Err(FactIdentityError::Malformed(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FactId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One content-identified semantic value.
///
/// Identity covers exactly the value kind, payload, and every preserved
/// semantic extension. It deliberately excludes provenance, coverage,
/// conformance, admission, and execution-host state; those are authority
/// records about this value rather than parts of the value itself.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Fact {
    pub id: FactId,
    pub value_kind: ValueKindId,
    pub payload: Value,
    /// Namespaced semantic data unknown to this version survives unchanged.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl Fact {
    pub fn new(value_kind: ValueKindId, payload: Value) -> Result<Self, FactIdentityError> {
        Self::with_extensions(value_kind, payload, BTreeMap::new())
    }

    pub fn with_extensions(
        value_kind: ValueKindId,
        payload: Value,
        extensions: BTreeMap<String, Value>,
    ) -> Result<Self, FactIdentityError> {
        validate_fact_parts(&value_kind, &extensions)?;
        let id = semantic_fact_digest(&value_kind, &payload, &extensions)?;
        Ok(Self {
            id,
            value_kind,
            payload,
            extensions,
        })
    }

    /// Revalidates both the envelope and its content-derived identity.
    pub fn validate(&self) -> Result<(), FactIdentityError> {
        FactId::parse(self.id.to_string())?;
        validate_fact_parts(&self.value_kind, &self.extensions)?;
        let expected = semantic_fact_digest(&self.value_kind, &self.payload, &self.extensions)?;
        if self.id != expected {
            return Err(FactIdentityError::IdentityMismatch {
                expected,
                actual: self.id.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FactIdentityError {
    Malformed(String),
    InvalidValueKind(ValueKindId),
    ReservedExtension(String),
    Serialization(String),
    IdentityMismatch { expected: FactId, actual: FactId },
}

impl fmt::Display for FactIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(value) => write!(formatter, "`{value}` is not a SHA-256 fact identity"),
            Self::InvalidValueKind(kind) => write!(formatter, "`{kind}` is not a valid value kind"),
            Self::ReservedExtension(key) => {
                write!(formatter, "semantic extension `{key}` shadows a fact field")
            }
            Self::Serialization(error) => write!(formatter, "fact serialization failed: {error}"),
            Self::IdentityMismatch { expected, actual } => write!(
                formatter,
                "fact identity mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}

impl Error for FactIdentityError {}

/// Whether an input may carry unresolved defeats.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactAcceptance {
    CompleteOnly,
    PartialAllowed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Requirement {
    pub fact: FactType,
    pub acceptance: FactAcceptance,
}

impl Requirement {
    pub fn complete(fact: FactType) -> Self {
        Self {
            fact,
            acceptance: FactAcceptance::CompleteOnly,
        }
    }

    pub fn partial_allowed(fact: FactType) -> Self {
        Self {
            fact,
            acceptance: FactAcceptance::PartialAllowed,
        }
    }
}

/// One versioned transformation contract. `requires` is a conjunction, making
/// each capability a hyperedge rather than a simple graph edge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilitySpec {
    pub id: CapabilityId,
    pub requires: Vec<Requirement>,
    pub produces: Vec<FactType>,
    /// The suite this capability declares by default.
    ///
    /// It is an obligation, not a fixed requirement. A neutral capability may
    /// be verified by a concrete, installation-specific suite, so a request may
    /// bind a different one — see [`CapabilityRequest::bind_with_suite`].
    /// Nothing compares a request's suite to this value; what gates admission
    /// is whether the host admits an attester *for the suite the request
    /// names*, which is [`AdmissionPolicy`]'s job.
    pub default_conformance_suite: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderDescriptor {
    pub id: ProviderId,
    pub capability: CapabilityId,
    /// Digest of the installed implementation artifact or source closure.
    pub implementation_digest: String,
}

/// Coverage is not trust. `Complete` means only that no defeater fired under
/// the producing capability's named mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactCoverage {
    Complete,
    Partial,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FactDerivation {
    Initial {
        origin: String,
    },
    Produced {
        capability: CapabilityId,
        provider: ProviderId,
        inputs: Vec<String>,
    },
    /// An out-of-process candidate admitted only after an independent exact
    /// conformance suite passed. The referenced request, candidate, and result
    /// documents carry the rest of the immutable evidence chain.
    Admitted {
        capability: CapabilityId,
        provider: ProviderId,
        provider_implementation: String,
        inputs: Vec<String>,
        request: String,
        candidate: String,
        conformance_result: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FactInstance {
    pub id: String,
    pub fact_type: FactType,
    pub coverage: FactCoverage,
    pub payload: Value,
    pub derivation: FactDerivation,
}

impl FactInstance {
    pub fn initial(
        fact_type: FactType,
        coverage: FactCoverage,
        payload: Value,
        origin: impl Into<String>,
    ) -> Result<Self, RegistryError> {
        let derivation = FactDerivation::Initial {
            origin: origin.into(),
        };
        let id = fact_digest(&fact_type, coverage, &payload, &derivation)?;
        Ok(Self {
            id,
            fact_type,
            coverage,
            payload,
            derivation,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProducedFact {
    pub fact_type: FactType,
    pub coverage: FactCoverage,
    pub payload: Value,
}

pub trait CapabilityProvider: Send + Sync {
    fn descriptor(&self) -> ProviderDescriptor;

    fn invoke(
        &self,
        capability: &CapabilitySpec,
        inputs: &[FactInstance],
    ) -> Result<Vec<ProducedFact>, String>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlanStep {
    pub capability: CapabilityId,
    pub provider: Option<ProviderId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityNeed {
    pub capability: CapabilityId,
    pub requires: Vec<Requirement>,
    pub produces: Vec<FactType>,
    pub conformance_suite: String,
    pub reason: String,
}

/// The digest-bearing provider-neutral portion of one exact capability
/// invocation. Authority, ownership, deadlines, and settlement belong to the
/// orchestrator that durably consumes this request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityRequestBody {
    pub capability: CapabilityId,
    pub requires: Vec<Requirement>,
    pub inputs: Vec<FactInstance>,
    pub produces: Vec<FactType>,
    pub conformance_suite: String,
}

/// A missing capability bound to exact input fact instances. This is the
/// provider-neutral handoff from derivation planning to an orchestrator; it is
/// not itself a lease, authority grant, provider selection, or accepted result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityRequest {
    pub request_id: String,
    #[serde(flatten)]
    pub body: CapabilityRequestBody,
}

impl CapabilityRequest {
    /// Binds a need to exact inputs, keeping the suite the need published.
    pub fn bind(
        need: &CapabilityNeed,
        inputs: Vec<FactInstance>,
    ) -> Result<Self, CapabilityRequestError> {
        let suite = need.conformance_suite.clone();
        Self::bind_with_suite(need, inputs, suite)
    }

    /// Binds a need while naming the suite that will actually be run.
    ///
    /// A capability can be neutral while its verification is not: only a suite
    /// that knows a particular system can check that a generated surface really
    /// serves it. Without this, that specificity would have to live in the
    /// capability's identity, dragging every fact identity along with it.
    ///
    /// This is not a hole. A request naming a weaker suite still yields no
    /// admitted facts unless the host has admitted an attester *for that
    /// suite*, which is a deliberate act — see [`AdmissionPolicy`].
    pub fn bind_with_suite(
        need: &CapabilityNeed,
        inputs: Vec<FactInstance>,
        conformance_suite: impl Into<String>,
    ) -> Result<Self, CapabilityRequestError> {
        let mut required = need
            .requires
            .iter()
            .map(|requirement| (requirement.fact.clone(), requirement))
            .collect::<BTreeMap<_, _>>();
        if required.len() != need.requires.len() {
            return Err(CapabilityRequestError::InvalidNeed(
                "duplicate required fact identity".to_owned(),
            ));
        }
        let mut seen = BTreeSet::new();
        for input in &inputs {
            if !seen.insert(input.fact_type.clone()) {
                return Err(CapabilityRequestError::DuplicateInput(
                    input.fact_type.clone(),
                ));
            }
            let requirement = required
                .remove(&input.fact_type)
                .ok_or_else(|| CapabilityRequestError::UnexpectedInput(input.fact_type.clone()))?;
            if requirement.acceptance == FactAcceptance::CompleteOnly
                && input.coverage == FactCoverage::Partial
            {
                return Err(CapabilityRequestError::PartialInputRejected(
                    input.fact_type.clone(),
                ));
            }
        }
        if let Some(missing) = required.into_keys().next() {
            return Err(CapabilityRequestError::MissingInput(missing));
        }
        if need.produces.is_empty() {
            return Err(CapabilityRequestError::InvalidNeed(
                "produced fact set is empty".to_owned(),
            ));
        }
        let body = CapabilityRequestBody {
            capability: need.capability.clone(),
            requires: need.requires.clone(),
            inputs,
            produces: need.produces.clone(),
            conformance_suite: conformance_suite.into(),
        };
        validate_request_body(&body)?;
        let request_id = request_digest(&body)?;
        Ok(Self { request_id, body })
    }

    /// Revalidates a deserialized request and its content-derived identity.
    pub fn validate(&self) -> Result<(), CapabilityRequestError> {
        validate_request_body(&self.body)?;
        let expected = request_digest(&self.body)?;
        if self.request_id != expected {
            return Err(CapabilityRequestError::IdentityMismatch {
                expected,
                actual: self.request_id.clone(),
            });
        }
        Ok(())
    }
}

/// Opaque, content-bound reference to the durable provider attempt from which
/// a candidate was extracted. GOOIR need not understand the orchestrator's
/// invocation, lease, session, or fencing model.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AttemptEvidence {
    pub authority: String,
    pub attempt_id: String,
    pub invocation_id: String,
    pub evidence_digest: String,
}

/// Digest-bearing portion of one unverified provider candidate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityCandidateBody {
    pub request_id: String,
    pub provider: ProviderDescriptor,
    pub outputs: Vec<ProducedFact>,
    pub attempt: AttemptEvidence,
}

/// Exact proposed outputs extracted from a provider attempt. A candidate is
/// syntactically bound to the request but remains untrusted and unadmitted.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityCandidate {
    pub candidate_id: String,
    #[serde(flatten)]
    pub body: CapabilityCandidateBody,
}

impl CapabilityCandidate {
    pub fn bind(
        request: &CapabilityRequest,
        provider: ProviderDescriptor,
        outputs: Vec<ProducedFact>,
        attempt: AttemptEvidence,
    ) -> Result<Self, CapabilityCandidateError> {
        request
            .validate()
            .map_err(CapabilityCandidateError::Request)?;
        let body = CapabilityCandidateBody {
            request_id: request.request_id.clone(),
            provider,
            outputs,
            attempt,
        };
        validate_candidate_body(request, &body)?;
        let candidate_id = canonical_digest(&body)
            .map_err(|error| CapabilityCandidateError::Serialization(error.to_string()))?;
        Ok(Self { candidate_id, body })
    }

    pub fn validate(&self, request: &CapabilityRequest) -> Result<(), CapabilityCandidateError> {
        request
            .validate()
            .map_err(CapabilityCandidateError::Request)?;
        validate_candidate_body(request, &self.body)?;
        let expected = canonical_digest(&self.body)
            .map_err(|error| CapabilityCandidateError::Serialization(error.to_string()))?;
        if self.candidate_id != expected {
            return Err(CapabilityCandidateError::IdentityMismatch {
                expected,
                actual: self.candidate_id.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceOutcome {
    Passed,
    Failed,
}

/// One named observation made by an exact conformance provider.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConformanceCheck {
    pub name: String,
    pub outcome: ConformanceOutcome,
    pub evidence: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConformanceProviderDescriptor {
    pub id: ProviderId,
    pub suite: String,
    pub implementation_digest: String,
}

/// Product- or dialect-specific verifier behind the generic admission waist.
/// It receives exact immutable inputs and returns named observations; it does
/// not construct trusted facts itself.
pub trait CapabilityConformanceProvider: Send + Sync {
    fn descriptor(&self) -> ConformanceProviderDescriptor;

    fn verify(
        &self,
        request: &CapabilityRequest,
        candidate: &CapabilityCandidate,
    ) -> Result<Vec<ConformanceCheck>, String>;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityConformanceBody {
    pub request_id: String,
    pub candidate_id: String,
    pub suite: String,
    pub attester: ProviderId,
    pub attester_implementation: String,
    pub outcome: ConformanceOutcome,
    pub checks: Vec<ConformanceCheck>,
}

/// Immutable result of independently evaluating one exact candidate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityConformanceResult {
    pub result_id: String,
    #[serde(flatten)]
    pub body: CapabilityConformanceBody,
}

/// Why an admission produced no facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactsWithheld {
    /// The attester reported at least one failing check.
    ConformanceFailed,
    /// The attester reported success, but this host does not admit it.
    AttesterNotAdmitted,
}

/// A conformance result plus any facts it made eligible for graph admission.
/// A failed or unadmitted result is a valid report with an empty fact set.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityAdmission {
    pub conformance: CapabilityConformanceResult,
    pub facts: Vec<FactInstance>,
    /// Set when `facts` is empty. A conformance result is evidence either way;
    /// whether it counts is a separate decision.
    pub withheld: Option<FactsWithheld>,
}

/// Which attesters this host accepts conformance results from.
///
/// Default-deny, and deliberately separate from the conformance run itself.
/// Structural independence from the provider is necessary but not sufficient:
/// without this, any caller could supply an independent-looking verifier and
/// mint admitted facts, which is the laundering hole
/// [decision 0002](../../../docs/DECISIONS/0002_EVIDENCE_TRUST_POLICY.md)
/// closed for transported attestations. An attestation produced in-process is
/// no more self-certifying than one that arrived over a wire.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdmissionPolicy {
    admitted: Vec<ConformanceProviderDescriptor>,
}

impl AdmissionPolicy {
    /// Records one exact attester binding: identity, suite, and implementation
    /// digest together.
    ///
    /// The host is responsible for establishing that verifier's authority
    /// before calling this. Admitting an identity alone would let a different
    /// implementation inherit the decision, so all three parts bind.
    pub fn admit_attester(&mut self, descriptor: ConformanceProviderDescriptor) {
        if !self.admitted.contains(&descriptor) {
            self.admitted.push(descriptor);
        }
    }

    pub fn admits(&self, descriptor: &ConformanceProviderDescriptor) -> bool {
        self.admitted.contains(descriptor)
    }

    pub fn admitted(&self) -> &[ConformanceProviderDescriptor] {
        &self.admitted
    }
}

pub fn verify_and_admit(
    request: &CapabilityRequest,
    candidate: &CapabilityCandidate,
    verifier: &dyn CapabilityConformanceProvider,
    policy: &AdmissionPolicy,
) -> Result<CapabilityAdmission, CapabilityAdmissionError> {
    candidate
        .validate(request)
        .map_err(CapabilityAdmissionError::Candidate)?;
    let descriptor = verifier.descriptor();
    validate_conformance_provider(&descriptor)?;
    if descriptor.suite != request.body.conformance_suite {
        return Err(CapabilityAdmissionError::SuiteMismatch {
            expected: request.body.conformance_suite.clone(),
            actual: descriptor.suite,
        });
    }
    if descriptor.id == candidate.body.provider.id
        || descriptor.implementation_digest == candidate.body.provider.implementation_digest
    {
        return Err(CapabilityAdmissionError::VerifierNotIndependent);
    }
    let checks = verifier
        .verify(request, candidate)
        .map_err(CapabilityAdmissionError::VerifierFailed)?;
    if checks.is_empty() {
        return Err(CapabilityAdmissionError::NoChecks);
    }
    for check in &checks {
        if check.name.trim().is_empty() {
            return Err(CapabilityAdmissionError::InvalidCheck(
                "check name is empty".to_owned(),
            ));
        }
    }
    let outcome = if checks
        .iter()
        .all(|check| check.outcome == ConformanceOutcome::Passed)
    {
        ConformanceOutcome::Passed
    } else {
        ConformanceOutcome::Failed
    };
    let admitted_descriptor = descriptor.clone();
    let body = CapabilityConformanceBody {
        request_id: request.request_id.clone(),
        candidate_id: candidate.candidate_id.clone(),
        suite: request.body.conformance_suite.clone(),
        attester: descriptor.id,
        attester_implementation: descriptor.implementation_digest,
        outcome,
        checks,
    };
    let result_id = canonical_digest(&body)
        .map_err(|error| CapabilityAdmissionError::Serialization(error.to_string()))?;
    let conformance = CapabilityConformanceResult { result_id, body };
    // Two independent conditions. The attester must have passed, and this host
    // must accept the attester. Either alone is insufficient.
    let withheld = if outcome != ConformanceOutcome::Passed {
        Some(FactsWithheld::ConformanceFailed)
    } else if !policy.admits(&admitted_descriptor) {
        Some(FactsWithheld::AttesterNotAdmitted)
    } else {
        None
    };
    let facts = if withheld.is_none() {
        admitted_facts(request, candidate, &conformance)?
    } else {
        Vec::new()
    };
    Ok(CapabilityAdmission {
        conformance,
        facts,
        withheld,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DerivationPlan {
    pub target: FactType,
    pub steps: Vec<PlanStep>,
    pub needs: Vec<CapabilityNeed>,
}

impl DerivationPlan {
    pub fn is_executable(&self) -> bool {
        self.needs.is_empty() && self.steps.iter().all(|step| step.provider.is_some())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExecutionReport {
    pub target: FactInstance,
    pub facts: Vec<FactInstance>,
    pub steps: Vec<PlanStep>,
}

/// One question at the door: the facts a caller holds, and the fact it wants.
///
/// These are exactly the arguments [`CapabilityRegistry::plan`] and
/// [`CapabilityRegistry::execute`] already take. Naming them is the point —
/// a request that can be written down can be sent, queued, and answered by
/// something other than a terminal.
///
/// The request names a `FactType` and nothing else. There is no target kind,
/// no host, no frontend selector: GOOIR does not need to know what end the
/// caller is targeting.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DerivationRequest {
    pub target: FactType,
    pub inputs: Vec<FactInstance>,
}

/// Why a request could not be accepted as asked.
///
/// One cause today. It is a separate answer from [`Answer::Failed`] because
/// the remedy belongs to the caller rather than to a provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestRefusal {
    /// Two inputs declare the same fact type. Which one governs is the
    /// caller's decision, and guessing would silently pick an authority.
    AmbiguousInput(FactType),
}

/// Everything GOOIR has to say about one derivation request.
///
/// **There is no `Result` at the door.** A `Result` would sort outcomes into
/// answers and errors, when the premise is that "I cannot" is an answer that
/// names a remedy. Five variants exist because they imply five different next
/// actions — the same reason `DefeatKind` is five-valued. Two variants that
/// shared a remedy would mean one of them is not earning its place.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "answer", content = "detail")]
pub enum Answer {
    /// The fact exists. Its coverage says whether it is complete.
    ///
    /// Boxed because a report is far larger than the other four answers, and
    /// every caller pays for the biggest variant.
    Produced(Box<ExecutionReport>),
    /// A route exists, but a capability on it has no provider. The plan's
    /// `needs` are assignable work, not a failure — this is the one answer
    /// that leaves the building.
    Blocked(DerivationPlan),
    /// No route at all. The remedy is a declared capability, not a provider.
    Unreachable(PlanError),
    /// The request could not be accepted as asked.
    Refused(RequestRefusal),
    /// A provider on an executable route failed while running.
    Failed(ExecutionError),
}

impl Answer {
    /// What the caller should do next.
    ///
    /// This is the justification for the variant set: if two of these strings
    /// were ever equal, one of the variants would be redundant. A test holds
    /// them distinct.
    pub fn remedy(&self) -> &'static str {
        match self {
            Answer::Produced(_) => "use the fact; read its coverage before assuming it is complete",
            Answer::Blocked(_) => "assign the open needs to a provider, an agent, or a person",
            Answer::Unreachable(_) => "declare a capability that produces this fact",
            Answer::Refused(_) => "fix the request",
            Answer::Failed(_) => "fix or replace the provider that failed",
        }
    }

    /// The assignable work this answer names, if any.
    ///
    /// Read from the plan rather than copied beside it: two lists of the same
    /// needs would be two authorities on one meaning.
    pub fn needs(&self) -> &[CapabilityNeed] {
        match self {
            Answer::Blocked(plan) => &plan.needs,
            _ => &[],
        }
    }
}

/// Answers one derivation request. Never fails; every outcome is an [`Answer`].
pub fn answer(registry: &CapabilityRegistry, request: &DerivationRequest) -> Answer {
    let mut seen: BTreeSet<&FactType> = BTreeSet::new();
    for input in &request.inputs {
        if !seen.insert(&input.fact_type) {
            return Answer::Refused(RequestRefusal::AmbiguousInput(input.fact_type.clone()));
        }
    }

    let initial: Vec<FactType> = request
        .inputs
        .iter()
        .map(|input| input.fact_type.clone())
        .collect();
    let plan = match registry.plan(initial, &request.target) {
        Ok(plan) => plan,
        Err(error) => return Answer::Unreachable(error),
    };
    if !plan.is_executable() {
        return Answer::Blocked(plan);
    }

    match registry.execute(&plan, request.inputs.clone()) {
        Ok(report) => Answer::Produced(Box::new(report)),
        // `is_executable` already passed, so a disagreement here is the
        // registry moving underneath the plan, not assignable work.
        Err(error) => Answer::Failed(error),
    }
}

#[derive(Default)]
pub struct CapabilityRegistry {
    specs: BTreeMap<CapabilityId, CapabilitySpec>,
    providers: BTreeMap<ProviderId, Box<dyn CapabilityProvider>>,
    providers_by_capability: BTreeMap<CapabilityId, BTreeSet<ProviderId>>,
}

impl CapabilityRegistry {
    pub fn register_spec(&mut self, spec: CapabilitySpec) -> Result<(), RegistryError> {
        validate_spec(&spec)?;
        if self.specs.contains_key(&spec.id) {
            return Err(RegistryError::DuplicateCapability(spec.id));
        }
        self.specs.insert(spec.id.clone(), spec);
        Ok(())
    }

    pub fn register_provider(
        &mut self,
        provider: impl CapabilityProvider + 'static,
    ) -> Result<(), RegistryError> {
        let descriptor = provider.descriptor();
        validate_provider(&descriptor)?;
        if !self.specs.contains_key(&descriptor.capability) {
            return Err(RegistryError::UnknownCapability(
                descriptor.capability.clone(),
            ));
        }
        if self.providers.contains_key(&descriptor.id) {
            return Err(RegistryError::DuplicateProvider(descriptor.id));
        }
        self.providers_by_capability
            .entry(descriptor.capability.clone())
            .or_default()
            .insert(descriptor.id.clone());
        self.providers.insert(descriptor.id, Box::new(provider));
        Ok(())
    }

    pub fn specs(&self) -> impl Iterator<Item = &CapabilitySpec> {
        self.specs.values()
    }

    pub fn provider_descriptors(&self) -> Vec<ProviderDescriptor> {
        self.providers
            .values()
            .map(|provider| provider.descriptor())
            .collect()
    }

    pub fn plan(
        &self,
        initial: impl IntoIterator<Item = FactType>,
        target: &FactType,
    ) -> Result<DerivationPlan, PlanError> {
        let mut candidates = initial
            .into_iter()
            .map(|fact| (fact, Candidate::default()))
            .collect::<BTreeMap<_, _>>();

        let mut changed = true;
        while changed {
            changed = false;
            for spec in self.specs.values() {
                let Some(candidate) = candidate_for(spec, &candidates, self) else {
                    continue;
                };
                for output in &spec.produces {
                    let replace = candidates
                        .get(output)
                        .is_none_or(|existing| candidate.score() < existing.score());
                    if replace {
                        candidates.insert(output.clone(), candidate.clone());
                        changed = true;
                    }
                }
            }
        }

        let candidate = candidates
            .get(target)
            .ok_or_else(|| PlanError::Unreachable(target.clone()))?;
        let steps = candidate.steps.clone();
        let needs = steps
            .iter()
            .filter(|step| step.provider.is_none())
            .map(|step| {
                let spec = self
                    .specs
                    .get(&step.capability)
                    .expect("planned capability remains registered");
                CapabilityNeed {
                    capability: spec.id.clone(),
                    requires: spec.requires.clone(),
                    produces: spec.produces.clone(),
                    conformance_suite: spec.default_conformance_suite.clone(),
                    reason: "no installed provider implements this exact capability".to_owned(),
                }
            })
            .collect();
        Ok(DerivationPlan {
            target: target.clone(),
            steps,
            needs,
        })
    }

    pub fn execute(
        &self,
        plan: &DerivationPlan,
        initial: Vec<FactInstance>,
    ) -> Result<ExecutionReport, ExecutionError> {
        if !plan.is_executable() {
            return Err(ExecutionError::PlanNotExecutable(plan.needs.clone()));
        }
        let mut facts = BTreeMap::new();
        for fact in initial {
            if facts.insert(fact.fact_type.clone(), fact).is_some() {
                return Err(ExecutionError::AmbiguousInput);
            }
        }

        for step in &plan.steps {
            let spec = self
                .specs
                .get(&step.capability)
                .ok_or_else(|| ExecutionError::RegistryChanged(step.capability.clone()))?;
            let provider_id = step
                .provider
                .as_ref()
                .ok_or_else(|| ExecutionError::PlanNotExecutable(plan.needs.clone()))?;
            let provider = self
                .providers
                .get(provider_id)
                .ok_or_else(|| ExecutionError::ProviderUnavailable(provider_id.clone()))?;
            let mut inputs = Vec::with_capacity(spec.requires.len());
            for requirement in &spec.requires {
                let fact = facts
                    .get(&requirement.fact)
                    .ok_or_else(|| ExecutionError::MissingInput(requirement.fact.clone()))?;
                if requirement.acceptance == FactAcceptance::CompleteOnly
                    && fact.coverage == FactCoverage::Partial
                {
                    return Err(ExecutionError::PartialInputRejected {
                        capability: Box::new(spec.id.clone()),
                        fact: Box::new(requirement.fact.clone()),
                    });
                }
                inputs.push(fact.clone());
            }

            let produced =
                provider
                    .invoke(spec, &inputs)
                    .map_err(|error| ExecutionError::ProviderFailed {
                        provider: provider_id.clone(),
                        error,
                    })?;
            validate_outputs(spec, &produced)?;
            let input_ids = inputs
                .iter()
                .map(|fact| fact.id.clone())
                .collect::<Vec<_>>();
            for output in produced {
                let derivation = FactDerivation::Produced {
                    capability: spec.id.clone(),
                    provider: provider_id.clone(),
                    inputs: input_ids.clone(),
                };
                let id = fact_digest(
                    &output.fact_type,
                    output.coverage,
                    &output.payload,
                    &derivation,
                )
                .map_err(ExecutionError::Registry)?;
                facts.insert(
                    output.fact_type.clone(),
                    FactInstance {
                        id,
                        fact_type: output.fact_type,
                        coverage: output.coverage,
                        payload: output.payload,
                        derivation,
                    },
                );
            }
        }

        let target = facts
            .get(&plan.target)
            .cloned()
            .ok_or_else(|| ExecutionError::MissingTarget(plan.target.clone()))?;
        Ok(ExecutionReport {
            target,
            facts: facts.into_values().collect(),
            steps: plan.steps.clone(),
        })
    }
}

#[derive(Clone, Default)]
struct Candidate {
    steps: Vec<PlanStep>,
}

impl Candidate {
    fn score(&self) -> (usize, usize, String) {
        let missing = self
            .steps
            .iter()
            .filter(|step| step.provider.is_none())
            .count();
        let identity = self
            .steps
            .iter()
            .map(|step| step.capability.to_string())
            .collect::<Vec<_>>()
            .join("|");
        (missing, self.steps.len(), identity)
    }
}

fn candidate_for(
    spec: &CapabilitySpec,
    candidates: &BTreeMap<FactType, Candidate>,
    registry: &CapabilityRegistry,
) -> Option<Candidate> {
    let mut steps = Vec::new();
    for requirement in &spec.requires {
        let requirement_candidate = candidates.get(&requirement.fact)?;
        for step in &requirement_candidate.steps {
            if !steps
                .iter()
                .any(|existing: &PlanStep| existing.capability == step.capability)
            {
                steps.push(step.clone());
            }
        }
    }
    let provider = registry
        .providers_by_capability
        .get(&spec.id)
        .and_then(|providers| providers.first())
        .cloned();
    steps.push(PlanStep {
        capability: spec.id.clone(),
        provider,
    });
    Some(Candidate { steps })
}

fn validate_spec(spec: &CapabilitySpec) -> Result<(), RegistryError> {
    if !spec.id.is_well_formed() {
        return Err(RegistryError::InvalidCapability {
            capability: spec.id.clone(),
            reason: "capability identity is malformed".to_owned(),
        });
    }
    if spec.produces.is_empty() {
        return Err(RegistryError::InvalidCapability {
            capability: spec.id.clone(),
            reason: "a capability must produce at least one fact".to_owned(),
        });
    }
    if spec.default_conformance_suite.trim().is_empty() {
        return Err(RegistryError::InvalidCapability {
            capability: spec.id.clone(),
            reason: "a capability must name an exact conformance suite".to_owned(),
        });
    }
    if let Some(requirement) = spec
        .requires
        .iter()
        .find(|requirement| !requirement.fact.is_well_formed())
    {
        return Err(RegistryError::InvalidCapability {
            capability: spec.id.clone(),
            reason: format!("required value kind `{}` is malformed", requirement.fact),
        });
    }
    if let Some(produced) = spec
        .produces
        .iter()
        .find(|produced| !produced.is_well_formed())
    {
        return Err(RegistryError::InvalidCapability {
            capability: spec.id.clone(),
            reason: format!("produced value kind `{produced}` is malformed"),
        });
    }
    let required = spec
        .requires
        .iter()
        .map(|requirement| &requirement.fact)
        .collect::<BTreeSet<_>>();
    if required.len() != spec.requires.len() {
        return Err(RegistryError::InvalidCapability {
            capability: spec.id.clone(),
            reason: "duplicate input fact identity".to_owned(),
        });
    }
    let produced = spec.produces.iter().collect::<BTreeSet<_>>();
    if produced.len() != spec.produces.len() {
        return Err(RegistryError::InvalidCapability {
            capability: spec.id.clone(),
            reason: "duplicate output fact identity".to_owned(),
        });
    }
    Ok(())
}

fn validate_provider(descriptor: &ProviderDescriptor) -> Result<(), RegistryError> {
    if !descriptor.id.is_well_formed() {
        return Err(RegistryError::InvalidProvider {
            provider: descriptor.id.clone(),
            reason: "provider identity is malformed".to_owned(),
        });
    }
    if !is_sha256_identity(&descriptor.implementation_digest) {
        return Err(RegistryError::InvalidProvider {
            provider: descriptor.id.clone(),
            reason: "implementation digest must be a sha256 identity".to_owned(),
        });
    }
    Ok(())
}

fn validate_request_body(body: &CapabilityRequestBody) -> Result<(), CapabilityRequestError> {
    validate_exact_identity(
        "capability",
        &body.capability.package,
        &body.capability.name,
        &body.capability.version,
    )?;
    if body.conformance_suite.trim().is_empty() {
        return Err(CapabilityRequestError::InvalidNeed(
            "conformance suite is empty".to_owned(),
        ));
    }
    if body.produces.is_empty() {
        return Err(CapabilityRequestError::InvalidNeed(
            "produced fact set is empty".to_owned(),
        ));
    }
    let required = body
        .requires
        .iter()
        .map(|requirement| {
            validate_value_kind("required value kind", &requirement.fact)?;
            Ok(requirement.fact.clone())
        })
        .collect::<Result<BTreeSet<_>, CapabilityRequestError>>()?;
    if required.len() != body.requires.len() {
        return Err(CapabilityRequestError::InvalidNeed(
            "duplicate required fact identity".to_owned(),
        ));
    }
    let produced = body
        .produces
        .iter()
        .map(|fact| {
            validate_value_kind("produced value kind", fact)?;
            Ok(fact.clone())
        })
        .collect::<Result<BTreeSet<_>, CapabilityRequestError>>()?;
    if produced.len() != body.produces.len() {
        return Err(CapabilityRequestError::InvalidNeed(
            "duplicate produced fact identity".to_owned(),
        ));
    }
    let mut inputs = BTreeMap::new();
    for input in &body.inputs {
        validate_value_kind("input value kind", &input.fact_type)?;
        if inputs.insert(input.fact_type.clone(), input).is_some() {
            return Err(CapabilityRequestError::DuplicateInput(
                input.fact_type.clone(),
            ));
        }
        if !is_sha256_identity(&input.id) {
            return Err(CapabilityRequestError::InvalidFactIdentity(
                input.id.clone(),
            ));
        }
        let expected = fact_digest(
            &input.fact_type,
            input.coverage,
            &input.payload,
            &input.derivation,
        )
        .map_err(|error| CapabilityRequestError::Serialization(error.to_string()))?;
        if input.id != expected {
            return Err(CapabilityRequestError::InvalidFactIdentity(
                input.id.clone(),
            ));
        }
    }
    for requirement in &body.requires {
        let input = inputs
            .remove(&requirement.fact)
            .ok_or_else(|| CapabilityRequestError::MissingInput(requirement.fact.clone()))?;
        if requirement.acceptance == FactAcceptance::CompleteOnly
            && input.coverage == FactCoverage::Partial
        {
            return Err(CapabilityRequestError::PartialInputRejected(
                requirement.fact.clone(),
            ));
        }
    }
    if let Some(unexpected) = inputs.into_keys().next() {
        return Err(CapabilityRequestError::UnexpectedInput(unexpected));
    }
    Ok(())
}

fn validate_candidate_body(
    request: &CapabilityRequest,
    body: &CapabilityCandidateBody,
) -> Result<(), CapabilityCandidateError> {
    if body.request_id != request.request_id {
        return Err(CapabilityCandidateError::RequestMismatch {
            expected: request.request_id.clone(),
            actual: body.request_id.clone(),
        });
    }
    validate_exact_identity(
        "provider",
        &body.provider.id.package,
        &body.provider.id.name,
        &body.provider.id.version,
    )
    .map_err(|error| {
        CapabilityCandidateError::Provider(RegistryError::InvalidProvider {
            provider: body.provider.id.clone(),
            reason: error.to_string(),
        })
    })?;
    validate_provider(&body.provider).map_err(CapabilityCandidateError::Provider)?;
    if body.provider.capability != request.body.capability {
        return Err(CapabilityCandidateError::ProviderCapabilityMismatch);
    }
    let actual = body
        .outputs
        .iter()
        .map(|output| output.fact_type.clone())
        .collect::<Vec<_>>();
    let actual_set = actual.iter().collect::<BTreeSet<_>>();
    let expected_set = request.body.produces.iter().collect::<BTreeSet<_>>();
    if actual.len() != actual_set.len() || actual_set != expected_set {
        return Err(CapabilityCandidateError::OutputContractViolation {
            expected: request.body.produces.clone(),
            actual,
        });
    }
    if body.attempt.authority.trim().is_empty()
        || body.attempt.attempt_id.trim().is_empty()
        || body.attempt.invocation_id.trim().is_empty()
    {
        return Err(CapabilityCandidateError::InvalidAttempt(
            "attempt authority and identities must not be empty".to_owned(),
        ));
    }
    if !is_sha256_identity(&body.attempt.evidence_digest) {
        return Err(CapabilityCandidateError::InvalidAttempt(
            "attempt evidence digest must be a sha256 identity".to_owned(),
        ));
    }
    Ok(())
}

fn validate_conformance_provider(
    descriptor: &ConformanceProviderDescriptor,
) -> Result<(), CapabilityAdmissionError> {
    validate_exact_identity(
        "conformance provider",
        &descriptor.id.package,
        &descriptor.id.name,
        &descriptor.id.version,
    )
    .map_err(|error| CapabilityAdmissionError::InvalidVerifier(error.to_string()))?;
    if descriptor.suite.trim().is_empty() {
        return Err(CapabilityAdmissionError::InvalidVerifier(
            "conformance suite is empty".to_owned(),
        ));
    }
    if !is_sha256_identity(&descriptor.implementation_digest) {
        return Err(CapabilityAdmissionError::InvalidVerifier(
            "implementation digest must be a sha256 identity".to_owned(),
        ));
    }
    Ok(())
}

fn admitted_facts(
    request: &CapabilityRequest,
    candidate: &CapabilityCandidate,
    conformance: &CapabilityConformanceResult,
) -> Result<Vec<FactInstance>, CapabilityAdmissionError> {
    let input_ids = request
        .body
        .inputs
        .iter()
        .map(|input| input.id.clone())
        .collect::<Vec<_>>();
    candidate
        .body
        .outputs
        .iter()
        .map(|output| {
            let derivation = FactDerivation::Admitted {
                capability: request.body.capability.clone(),
                provider: candidate.body.provider.id.clone(),
                provider_implementation: candidate.body.provider.implementation_digest.clone(),
                inputs: input_ids.clone(),
                request: request.request_id.clone(),
                candidate: candidate.candidate_id.clone(),
                conformance_result: conformance.result_id.clone(),
            };
            let id = fact_digest(
                &output.fact_type,
                output.coverage,
                &output.payload,
                &derivation,
            )
            .map_err(CapabilityAdmissionError::Registry)?;
            Ok(FactInstance {
                id,
                fact_type: output.fact_type.clone(),
                coverage: output.coverage,
                payload: output.payload.clone(),
                derivation,
            })
        })
        .collect()
}

fn validate_exact_identity(
    label: &str,
    package: &str,
    name: &str,
    version: &str,
) -> Result<(), CapabilityRequestError> {
    if package.trim().is_empty()
        || name.trim().is_empty()
        || version.trim().is_empty()
        || package.contains('/')
        || package.contains('@')
        || name.contains('/')
        || name.contains('@')
        || version.contains('/')
        || version.contains('@')
    {
        return Err(CapabilityRequestError::InvalidNeed(format!(
            "{label} identity is malformed"
        )));
    }
    Ok(())
}

fn validate_value_kind(
    label: &str,
    value_kind: &ValueKindId,
) -> Result<(), CapabilityRequestError> {
    if !value_kind.is_well_formed() {
        return Err(CapabilityRequestError::InvalidNeed(format!(
            "{label} `{value_kind}` is malformed"
        )));
    }
    Ok(())
}

fn is_sha256_identity(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn canonical_digest(value: &impl Serialize) -> Result<String, String> {
    serde_json_canonicalizer::to_vec(value)
        .map(|bytes| sha256_identity(&bytes))
        .map_err(|error| error.to_string())
}

fn validate_fact_parts(
    value_kind: &ValueKindId,
    extensions: &BTreeMap<String, Value>,
) -> Result<(), FactIdentityError> {
    if !value_kind.is_well_formed() {
        return Err(FactIdentityError::InvalidValueKind(value_kind.clone()));
    }
    for reserved in ["id", "value_kind", "payload"] {
        if extensions.contains_key(reserved) {
            return Err(FactIdentityError::ReservedExtension(reserved.to_owned()));
        }
    }
    Ok(())
}

fn semantic_fact_digest(
    value_kind: &ValueKindId,
    payload: &Value,
    extensions: &BTreeMap<String, Value>,
) -> Result<FactId, FactIdentityError> {
    validate_fact_parts(value_kind, extensions)?;
    let mut envelope = serde_json::Map::new();
    envelope.insert(
        "value_kind".to_owned(),
        serde_json::to_value(value_kind)
            .map_err(|error| FactIdentityError::Serialization(error.to_string()))?,
    );
    envelope.insert("payload".to_owned(), payload.clone());
    envelope.extend(extensions.clone());
    canonical_digest(&Value::Object(envelope))
        .map(FactId)
        .map_err(FactIdentityError::Serialization)
}

fn validate_outputs(spec: &CapabilitySpec, outputs: &[ProducedFact]) -> Result<(), ExecutionError> {
    let actual = outputs
        .iter()
        .map(|output| output.fact_type.clone())
        .collect::<Vec<_>>();
    let actual_set = actual.iter().collect::<BTreeSet<_>>();
    let expected_set = spec.produces.iter().collect::<BTreeSet<_>>();
    if actual.len() != actual_set.len() || actual_set != expected_set {
        return Err(ExecutionError::OutputContractViolation {
            capability: spec.id.clone(),
            expected: spec.produces.clone(),
            actual,
        });
    }
    Ok(())
}

fn fact_digest(
    fact_type: &FactType,
    coverage: FactCoverage,
    payload: &Value,
    derivation: &FactDerivation,
) -> Result<String, RegistryError> {
    let bytes = serde_json::to_vec(&(fact_type, coverage, payload, derivation))
        .map_err(|error| RegistryError::Serialization(error.to_string()))?;
    Ok(sha256_identity(&bytes))
}

fn request_digest(body: &CapabilityRequestBody) -> Result<String, CapabilityRequestError> {
    let bytes = serde_json_canonicalizer::to_vec(body)
        .map_err(|error| CapabilityRequestError::Serialization(error.to_string()))?;
    Ok(sha256_identity(&bytes))
}

fn sha256_identity(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(7 + digest.len() * 2);
    output.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RegistryError {
    DuplicateCapability(CapabilityId),
    DuplicateProvider(ProviderId),
    UnknownCapability(CapabilityId),
    InvalidCapability {
        capability: CapabilityId,
        reason: String,
    },
    InvalidProvider {
        provider: ProviderId,
        reason: String,
    },
    Serialization(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityRequestError {
    InvalidNeed(String),
    DuplicateInput(FactType),
    UnexpectedInput(FactType),
    MissingInput(FactType),
    PartialInputRejected(FactType),
    InvalidFactIdentity(String),
    IdentityMismatch { expected: String, actual: String },
    Serialization(String),
}

impl fmt::Display for CapabilityRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for CapabilityRequestError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityCandidateError {
    Request(CapabilityRequestError),
    RequestMismatch {
        expected: String,
        actual: String,
    },
    Provider(RegistryError),
    ProviderCapabilityMismatch,
    OutputContractViolation {
        expected: Vec<FactType>,
        actual: Vec<FactType>,
    },
    InvalidAttempt(String),
    IdentityMismatch {
        expected: String,
        actual: String,
    },
    Serialization(String),
}

impl fmt::Display for CapabilityCandidateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for CapabilityCandidateError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapabilityAdmissionError {
    Candidate(CapabilityCandidateError),
    InvalidVerifier(String),
    SuiteMismatch { expected: String, actual: String },
    VerifierNotIndependent,
    VerifierFailed(String),
    NoChecks,
    InvalidCheck(String),
    Serialization(String),
    Registry(RegistryError),
}

impl fmt::Display for CapabilityAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for CapabilityAdmissionError {}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RegistryError {}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PlanError {
    Unreachable(FactType),
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PlanError {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionError {
    PlanNotExecutable(Vec<CapabilityNeed>),
    AmbiguousInput,
    RegistryChanged(CapabilityId),
    ProviderUnavailable(ProviderId),
    MissingInput(FactType),
    PartialInputRejected {
        capability: Box<CapabilityId>,
        fact: Box<FactType>,
    },
    ProviderFailed {
        provider: ProviderId,
        error: String,
    },
    OutputContractViolation {
        capability: CapabilityId,
        expected: Vec<FactType>,
        actual: Vec<FactType>,
    },
    MissingTarget(FactType),
    Registry(RegistryError),
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for ExecutionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fact(name: &str) -> FactType {
        FactType::new("test", name, "1")
    }

    #[test]
    fn fact_type_is_a_wire_compatible_value_kind() {
        let dialect = DialectId::new("org.gooi.conversation", "1.0.0");
        let value_kind = ValueKindId::in_dialect(dialect.clone(), "message");
        let compatibility_name: FactType = value_kind.clone();

        assert_eq!(compatibility_name.dialect(), dialect);
        assert_eq!(
            compatibility_name.to_string(),
            "org.gooi.conversation/message@1.0.0"
        );
        assert_eq!(
            serde_json::to_value(&compatibility_name).unwrap(),
            json!({
                "package": "org.gooi.conversation",
                "name": "message",
                "version": "1.0.0"
            })
        );
    }

    #[test]
    fn semantic_fact_identity_is_exact_and_content_sensitive() {
        let kind = ValueKindId::new("org.gooi.conversation", "message", "1.0.0");
        let first = Fact::new(kind.clone(), json!({"body": "hello"})).unwrap();
        let replay = Fact::new(kind.clone(), json!({"body": "hello"})).unwrap();
        let changed_payload = Fact::new(kind, json!({"body": "goodbye"})).unwrap();
        let changed_kind = Fact::new(
            ValueKindId::new("org.gooi.conversation", "notice", "1.0.0"),
            json!({"body": "hello"}),
        )
        .unwrap();

        assert_eq!(first.id, replay.id);
        assert_ne!(first.id, changed_payload.id);
        assert_ne!(first.id, changed_kind.id);
        assert!(first.id.as_str().starts_with("sha256:"));
        first.validate().unwrap();
    }

    #[test]
    fn unknown_semantic_extensions_round_trip_and_change_fact_identity() {
        let kind = ValueKindId::new("org.gooi.conversation", "message", "1.0.0");
        let plain = Fact::new(kind.clone(), json!({"body": "hello"})).unwrap();
        let extended = Fact::with_extensions(
            kind,
            json!({"body": "hello"}),
            BTreeMap::from([
                (
                    "org.example.future/retention".to_owned(),
                    json!({"days": 30}),
                ),
                ("org.example.future/labels".to_owned(), json!(["reviewed"])),
            ]),
        )
        .unwrap();

        assert_ne!(plain.id, extended.id);
        let encoded = serde_json::to_value(&extended).unwrap();
        assert_eq!(encoded["org.example.future/retention"], json!({"days": 30}));
        let decoded: Fact = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap(), encoded);
        assert_eq!(decoded, extended);
        decoded.validate().unwrap();

        let mut tampered = decoded;
        tampered
            .extensions
            .insert("org.example.future/labels".to_owned(), json!(["changed"]));
        assert!(matches!(
            tampered.validate(),
            Err(FactIdentityError::IdentityMismatch { .. })
        ));
    }

    fn capability(
        name: &str,
        requires: Vec<Requirement>,
        produces: Vec<FactType>,
    ) -> CapabilitySpec {
        CapabilitySpec {
            id: CapabilityId::new("test", name, "1"),
            requires,
            produces,
            default_conformance_suite: format!("test/{name}@1"),
        }
    }

    #[test]
    fn malformed_value_kinds_cannot_enter_the_registry() {
        let malformed = FactType::new("test/nested", "output", "1");
        let spec = capability("bad_output", Vec::new(), vec![malformed]);

        assert!(matches!(
            CapabilityRegistry::default().register_spec(spec),
            Err(RegistryError::InvalidCapability { .. })
        ));
    }

    #[test]
    fn malformed_value_kinds_cannot_enter_through_a_request_document() {
        let body = CapabilityRequestBody {
            capability: CapabilityId::new("test", "generate", "1"),
            requires: Vec::new(),
            inputs: Vec::new(),
            produces: vec![FactType::new("test/nested", "output", "1")],
            conformance_suite: "test/generate@1".to_owned(),
        };
        let request = CapabilityRequest {
            request_id: format!("sha256:{}", "0".repeat(64)),
            body,
        };

        assert!(matches!(
            request.validate(),
            Err(CapabilityRequestError::InvalidNeed(_))
        ));
    }

    struct CopyProvider {
        descriptor: ProviderDescriptor,
        output: FactType,
        coverage: FactCoverage,
    }

    impl CapabilityProvider for CopyProvider {
        fn descriptor(&self) -> ProviderDescriptor {
            self.descriptor.clone()
        }

        fn invoke(
            &self,
            _: &CapabilitySpec,
            inputs: &[FactInstance],
        ) -> Result<Vec<ProducedFact>, String> {
            Ok(vec![ProducedFact {
                fact_type: self.output.clone(),
                coverage: self.coverage,
                payload: json!({"inputs": inputs.iter().map(|input| &input.id).collect::<Vec<_>>() }),
            }])
        }
    }

    fn register_copy(registry: &mut CapabilityRegistry, spec: &CapabilitySpec, output: FactType) {
        registry
            .register_provider(CopyProvider {
                descriptor: ProviderDescriptor {
                    id: ProviderId::new("test.provider", &spec.id.name, "1"),
                    capability: spec.id.clone(),
                    implementation_digest: format!("sha256:{:064}", spec.id.name.len()),
                },
                output,
                coverage: FactCoverage::Complete,
            })
            .unwrap();
    }

    #[test]
    fn multi_input_capabilities_are_planned_as_hyperedges() {
        let a = fact("a");
        let b = fact("b");
        let c = fact("c");
        let spec = capability(
            "compose",
            vec![
                Requirement::complete(a.clone()),
                Requirement::complete(b.clone()),
            ],
            vec![c.clone()],
        );
        let mut registry = CapabilityRegistry::default();
        registry.register_spec(spec.clone()).unwrap();
        register_copy(&mut registry, &spec, c.clone());

        assert!(registry.plan([a.clone()], &c).is_err());
        let plan = registry.plan([a, b], &c).unwrap();
        assert!(plan.is_executable());
        assert_eq!(plan.steps.len(), 1);
    }

    #[test]
    fn absent_provider_becomes_a_machine_readable_capability_need() {
        let source = fact("source");
        let target = fact("target");
        let spec = capability(
            "missing",
            vec![Requirement::complete(source.clone())],
            vec![target.clone()],
        );
        let mut registry = CapabilityRegistry::default();
        registry.register_spec(spec.clone()).unwrap();

        let plan = registry.plan([source], &target).unwrap();

        assert!(!plan.is_executable());
        assert_eq!(plan.needs.len(), 1);
        assert_eq!(plan.needs[0].capability, spec.id);
    }

    #[test]
    fn exact_versions_do_not_match_implicitly() {
        let source_v1 = FactType::new("test", "source", "1");
        let source_v2 = FactType::new("test", "source", "2");
        let target = fact("target");
        let spec = capability(
            "exact",
            vec![Requirement::complete(source_v1)],
            vec![target.clone()],
        );
        let mut registry = CapabilityRegistry::default();
        registry.register_spec(spec).unwrap();

        assert_eq!(
            registry.plan([source_v2], &target),
            Err(PlanError::Unreachable(target))
        );
    }

    #[test]
    fn execution_binds_provenance_to_capability_provider_and_inputs() {
        let source = fact("source");
        let target = fact("target");
        let spec = capability(
            "copy",
            vec![Requirement::complete(source.clone())],
            vec![target.clone()],
        );
        let mut registry = CapabilityRegistry::default();
        registry.register_spec(spec.clone()).unwrap();
        register_copy(&mut registry, &spec, target.clone());
        let plan = registry.plan([source.clone()], &target).unwrap();
        let input = FactInstance::initial(
            source,
            FactCoverage::Complete,
            json!({"value": 1}),
            "fixture",
        )
        .unwrap();

        let report = registry.execute(&plan, vec![input.clone()]).unwrap();

        let FactDerivation::Produced {
            capability,
            provider: _,
            inputs,
        } = &report.target.derivation
        else {
            panic!("target is produced");
        };
        assert_eq!(capability, &spec.id);
        assert_eq!(inputs, &vec![input.id]);
    }

    #[test]
    fn complete_only_requirement_rejects_partial_input() {
        let source = fact("source");
        let target = fact("target");
        let spec = capability(
            "copy",
            vec![Requirement::complete(source.clone())],
            vec![target.clone()],
        );
        let mut registry = CapabilityRegistry::default();
        registry.register_spec(spec.clone()).unwrap();
        register_copy(&mut registry, &spec, target.clone());
        let plan = registry.plan([source.clone()], &target).unwrap();
        let input = FactInstance::initial(
            source.clone(),
            FactCoverage::Partial,
            json!(null),
            "fixture",
        )
        .unwrap();

        assert_eq!(
            registry.execute(&plan, vec![input]),
            Err(ExecutionError::PartialInputRejected {
                capability: Box::new(spec.id),
                fact: Box::new(source),
            })
        );
    }

    #[test]
    fn capability_request_binds_need_to_exact_input_fact() {
        let source = fact("source");
        let target = fact("target");
        let need = CapabilityNeed {
            capability: CapabilityId::new("test", "generate", "1"),
            requires: vec![Requirement::complete(source.clone())],
            produces: vec![target],
            conformance_suite: "test/generate@1".to_owned(),
            reason: "no provider".to_owned(),
        };
        let first = FactInstance::initial(
            source.clone(),
            FactCoverage::Complete,
            json!({"value": 1}),
            "fixture@1",
        )
        .unwrap();
        let second = FactInstance::initial(
            source,
            FactCoverage::Complete,
            json!({"value": 2}),
            "fixture@1",
        )
        .unwrap();

        let first_request = CapabilityRequest::bind(&need, vec![first.clone()]).unwrap();
        let replay = CapabilityRequest::bind(&need, vec![first]).unwrap();
        let changed = CapabilityRequest::bind(&need, vec![second]).unwrap();

        assert_eq!(first_request.request_id, replay.request_id);
        assert_ne!(first_request.request_id, changed.request_id);
        assert_eq!(first_request.body.capability, need.capability);
        assert_eq!(first_request.body.inputs.len(), 1);
    }

    #[test]
    fn source_capability_request_may_have_no_inputs() {
        let need = CapabilityNeed {
            capability: CapabilityId::new("test", "discover", "1"),
            requires: Vec::new(),
            produces: vec![fact("discovered")],
            conformance_suite: "test/discover@1".to_owned(),
            reason: "no provider".to_owned(),
        };

        let request = CapabilityRequest::bind(&need, Vec::new()).unwrap();
        request.validate().unwrap();
        assert!(request.body.inputs.is_empty());
    }

    struct FixedVerifier {
        descriptor: ConformanceProviderDescriptor,
        outcome: ConformanceOutcome,
    }

    impl CapabilityConformanceProvider for FixedVerifier {
        fn descriptor(&self) -> ConformanceProviderDescriptor {
            self.descriptor.clone()
        }

        fn verify(
            &self,
            _: &CapabilityRequest,
            _: &CapabilityCandidate,
        ) -> Result<Vec<ConformanceCheck>, String> {
            Ok(vec![ConformanceCheck {
                name: "exact-output-semantics".to_owned(),
                outcome: self.outcome,
                evidence: json!({"fixture": true}),
            }])
        }
    }

    fn external_candidate() -> (CapabilityRequest, CapabilityCandidate) {
        let source = fact("external_source");
        let target = fact("external_target");
        let need = CapabilityNeed {
            capability: CapabilityId::new("test.capability", "external_generate", "1.0.0"),
            requires: vec![Requirement::complete(source.clone())],
            produces: vec![target.clone()],
            conformance_suite: "test.conformance/external_generate@1.0.0".to_owned(),
            reason: "no installed provider".to_owned(),
        };
        let input = FactInstance::initial(
            source,
            FactCoverage::Complete,
            json!({"intent": "exact"}),
            "fixture@1",
        )
        .unwrap();
        let request = CapabilityRequest::bind(&need, vec![input]).unwrap();
        let candidate = CapabilityCandidate::bind(
            &request,
            ProviderDescriptor {
                id: ProviderId::new("test.provider", "external_agent", "1.0.0"),
                capability: need.capability,
                implementation_digest: format!("sha256:{}", "a".repeat(64)),
            },
            vec![ProducedFact {
                fact_type: target,
                coverage: FactCoverage::Complete,
                payload: json!({"artifact": "candidate"}),
            }],
            AttemptEvidence {
                authority: "test.orchestrator/fleet@1".to_owned(),
                attempt_id: "attempt-1".to_owned(),
                invocation_id: "invocation-1".to_owned(),
                evidence_digest: format!("sha256:{}", "b".repeat(64)),
            },
        )
        .unwrap();
        (request, candidate)
    }

    fn verifier(outcome: ConformanceOutcome) -> FixedVerifier {
        FixedVerifier {
            descriptor: ConformanceProviderDescriptor {
                id: ProviderId::new("test.conformance", "external_suite", "1.0.0"),
                suite: "test.conformance/external_generate@1.0.0".to_owned(),
                implementation_digest: format!("sha256:{}", "c".repeat(64)),
            },
            outcome,
        }
    }

    #[test]
    fn candidate_identity_binds_request_provider_outputs_and_attempt() {
        let (request, candidate) = external_candidate();
        candidate.validate(&request).unwrap();
        let replay = CapabilityCandidate::bind(
            &request,
            candidate.body.provider.clone(),
            candidate.body.outputs.clone(),
            candidate.body.attempt.clone(),
        )
        .unwrap();
        assert_eq!(candidate.candidate_id, replay.candidate_id);

        let mut changed = candidate.clone();
        changed.body.outputs[0].payload = json!({"artifact": "different"});
        assert!(matches!(
            changed.validate(&request),
            Err(CapabilityCandidateError::IdentityMismatch { .. })
        ));
    }

    /// A policy admitting exactly the attester supplied. Real hosts establish
    /// authority out of band; tests state it directly.
    fn admitting(verifier: &dyn CapabilityConformanceProvider) -> AdmissionPolicy {
        let mut policy = AdmissionPolicy::default();
        policy.admit_attester(verifier.descriptor());
        policy
    }

    /// A need, its inputs, and a candidate bound under a caller-chosen suite.
    fn candidate_under_suite(suite: &str) -> (CapabilityRequest, CapabilityCandidate) {
        let source = fact("external_source");
        let target = fact("external_target");
        let need = CapabilityNeed {
            capability: CapabilityId::new("test.capability", "external_generate", "1.0.0"),
            requires: vec![Requirement::complete(source.clone())],
            produces: vec![target.clone()],
            conformance_suite: "test.conformance/external_generate@1.0.0".to_owned(),
            reason: "no installed provider".to_owned(),
        };
        let input = FactInstance::initial(
            source,
            FactCoverage::Complete,
            json!({"intent": "exact"}),
            "fixture@1",
        )
        .unwrap();
        let request = CapabilityRequest::bind_with_suite(&need, vec![input], suite).unwrap();
        let candidate = CapabilityCandidate::bind(
            &request,
            ProviderDescriptor {
                id: ProviderId::new("test.provider", "external_agent", "1.0.0"),
                capability: need.capability,
                implementation_digest: format!("sha256:{}", "a".repeat(64)),
            },
            vec![ProducedFact {
                fact_type: target,
                coverage: FactCoverage::Complete,
                payload: json!({"artifact": "candidate"}),
            }],
            AttemptEvidence {
                authority: "test.orchestrator/fleet@1".to_owned(),
                attempt_id: "attempt-1".to_owned(),
                invocation_id: "invocation-1".to_owned(),
                evidence_digest: format!("sha256:{}", "b".repeat(64)),
            },
        )
        .unwrap();
        (request, candidate)
    }

    fn verifier_for(suite: &str) -> FixedVerifier {
        FixedVerifier {
            descriptor: ConformanceProviderDescriptor {
                id: ProviderId::new("test.conformance", "concrete_suite", "1.0.0"),
                suite: suite.to_owned(),
                implementation_digest: format!("sha256:{}", "f".repeat(64)),
            },
            outcome: ConformanceOutcome::Passed,
        }
    }

    /// A capability may be neutral while its verification is not. Without this,
    /// the suite's specificity would have to live in the capability's identity.
    #[test]
    fn a_request_may_name_a_more_concrete_suite_than_the_capability_declares() {
        const CONCRETE: &str = "dev.product.conformance/runs_the_real_system@1.0.0";
        let (request, candidate) = candidate_under_suite(CONCRETE);
        assert_eq!(request.body.conformance_suite, CONCRETE);
        assert_ne!(
            request.body.conformance_suite, "test.conformance/external_generate@1.0.0",
            "the need's default was overridden"
        );

        let attester = verifier_for(CONCRETE);
        let admission =
            verify_and_admit(&request, &candidate, &attester, &admitting(&attester)).unwrap();
        assert!(admission.withheld.is_none());
        assert_eq!(admission.facts.len(), 1);
    }

    /// Overriding the suite is not a hole: an attester admitted for one suite
    /// cannot verify a request that names another.
    #[test]
    fn an_attester_admitted_for_a_different_suite_cannot_verify_the_request() {
        let (request, candidate) = candidate_under_suite("dev.product.conformance/real@1.0.0");
        // Admitted, independent, and passing -- but for the default suite.
        let attester = verifier_for("test.conformance/external_generate@1.0.0");
        assert_eq!(
            verify_and_admit(&request, &candidate, &attester, &admitting(&attester)),
            Err(CapabilityAdmissionError::SuiteMismatch {
                expected: "dev.product.conformance/real@1.0.0".to_owned(),
                actual: "test.conformance/external_generate@1.0.0".to_owned(),
            })
        );
    }

    #[test]
    fn binding_without_an_override_keeps_the_declared_default() {
        let (request, _) = external_candidate();
        assert_eq!(
            request.body.conformance_suite,
            "test.conformance/external_generate@1.0.0"
        );
    }

    #[test]
    fn independent_passing_conformance_admits_exact_candidate_facts() {
        let (request, candidate) = external_candidate();
        let attester = verifier(ConformanceOutcome::Passed);
        let admission =
            verify_and_admit(&request, &candidate, &attester, &admitting(&attester)).unwrap();
        assert!(admission.withheld.is_none());

        assert_eq!(
            admission.conformance.body.outcome,
            ConformanceOutcome::Passed
        );
        assert_eq!(admission.facts.len(), 1);
        let FactDerivation::Admitted {
            request: bound_request,
            candidate: bound_candidate,
            conformance_result,
            ..
        } = &admission.facts[0].derivation
        else {
            panic!("candidate fact must carry admitted derivation")
        };
        assert_eq!(bound_request, &request.request_id);
        assert_eq!(bound_candidate, &candidate.candidate_id);
        assert_eq!(conformance_result, &admission.conformance.result_id);

        let mut registry = CapabilityRegistry::default();
        registry
            .register_spec(CapabilitySpec {
                id: request.body.capability.clone(),
                requires: request.body.requires.clone(),
                produces: request.body.produces.clone(),
                default_conformance_suite: request.body.conformance_suite.clone(),
            })
            .unwrap();
        let admitted = admission.facts[0].clone();
        let resumed = registry
            .plan([admitted.fact_type.clone()], &admitted.fact_type)
            .unwrap();
        assert!(resumed.is_executable());
        assert!(resumed.needs.is_empty());
        assert_eq!(
            registry
                .execute(&resumed, vec![admitted.clone()])
                .unwrap()
                .target,
            admitted
        );
    }

    #[test]
    fn failed_conformance_is_preserved_without_admitting_facts() {
        let (request, candidate) = external_candidate();
        let attester = verifier(ConformanceOutcome::Failed);
        let admission =
            verify_and_admit(&request, &candidate, &attester, &admitting(&attester)).unwrap();

        assert_eq!(
            admission.conformance.body.outcome,
            ConformanceOutcome::Failed
        );
        assert!(admission.facts.is_empty());
        assert_eq!(admission.withheld, Some(FactsWithheld::ConformanceFailed));
    }

    /// A host that admits nothing gets nothing, even from a passing attester.
    /// Structural independence is necessary and not sufficient.
    #[test]
    fn a_passing_attester_this_host_does_not_admit_yields_no_facts() {
        let (request, candidate) = external_candidate();
        let attester = verifier(ConformanceOutcome::Passed);
        let admission =
            verify_and_admit(&request, &candidate, &attester, &AdmissionPolicy::default()).unwrap();

        assert_eq!(
            admission.conformance.body.outcome,
            ConformanceOutcome::Passed,
            "the result is still evidence"
        );
        assert!(admission.facts.is_empty());
        assert_eq!(admission.withheld, Some(FactsWithheld::AttesterNotAdmitted));
    }

    #[test]
    fn admission_binds_the_implementation_not_just_the_identity() {
        let (request, candidate) = external_candidate();
        let attester = verifier(ConformanceOutcome::Passed);

        // Same identity and suite, different build.
        let mut other = attester.descriptor();
        other.implementation_digest = format!("sha256:{}", "e".repeat(64));
        let mut policy = AdmissionPolicy::default();
        policy.admit_attester(other);

        let admission = verify_and_admit(&request, &candidate, &attester, &policy).unwrap();
        assert_eq!(
            admission.withheld,
            Some(FactsWithheld::AttesterNotAdmitted),
            "a different implementation must not inherit the decision"
        );
    }

    #[test]
    fn generating_provider_cannot_attest_its_own_candidate() {
        let (request, candidate) = external_candidate();
        let self_verifier = FixedVerifier {
            descriptor: ConformanceProviderDescriptor {
                id: candidate.body.provider.id.clone(),
                suite: request.body.conformance_suite.clone(),
                implementation_digest: format!("sha256:{}", "d".repeat(64)),
            },
            outcome: ConformanceOutcome::Passed,
        };

        assert_eq!(
            verify_and_admit(
                &request,
                &candidate,
                &self_verifier,
                &admitting(&self_verifier)
            ),
            Err(CapabilityAdmissionError::VerifierNotIndependent),
            "independence is checked before this host's policy is consulted"
        );
    }

    // ---- the door -------------------------------------------------------

    struct FailingProvider(ProviderDescriptor);

    impl CapabilityProvider for FailingProvider {
        fn descriptor(&self) -> ProviderDescriptor {
            self.0.clone()
        }
        fn invoke(
            &self,
            _: &CapabilitySpec,
            _: &[FactInstance],
        ) -> Result<Vec<ProducedFact>, String> {
            Err("the upstream service was unreachable".to_owned())
        }
    }

    /// `a -> make -> b`, with a provider unless `with_provider` is false.
    fn one_hop(with_provider: bool) -> (CapabilityRegistry, FactType, FactType) {
        let (a, b) = (fact("a"), fact("b"));
        let spec = capability(
            "make",
            vec![Requirement::complete(a.clone())],
            vec![b.clone()],
        );
        let mut registry = CapabilityRegistry::default();
        registry.register_spec(spec.clone()).unwrap();
        if with_provider {
            register_copy(&mut registry, &spec, b.clone());
        }
        (registry, a, b)
    }

    fn held(fact_type: &FactType) -> FactInstance {
        FactInstance::initial(
            fact_type.clone(),
            FactCoverage::Complete,
            json!({"value": 1}),
            "fixture",
        )
        .unwrap()
    }

    #[test]
    fn every_answer_variant_is_reachable() {
        let (registry, a, b) = one_hop(true);
        let produced = answer(
            &registry,
            &DerivationRequest {
                target: b.clone(),
                inputs: vec![held(&a)],
            },
        );
        assert!(matches!(produced, Answer::Produced(_)), "{produced:?}");

        let (registry, a, b) = one_hop(false);
        let blocked = answer(
            &registry,
            &DerivationRequest {
                target: b.clone(),
                inputs: vec![held(&a)],
            },
        );
        assert!(matches!(blocked, Answer::Blocked(_)), "{blocked:?}");
        assert_eq!(
            blocked.needs().len(),
            1,
            "a blocked answer names its assignable work"
        );

        let unreachable = answer(
            &CapabilityRegistry::default(),
            &DerivationRequest {
                target: b.clone(),
                inputs: vec![held(&a)],
            },
        );
        assert!(
            matches!(unreachable, Answer::Unreachable(_)),
            "{unreachable:?}"
        );

        let (registry, a, b) = one_hop(true);
        let refused = answer(
            &registry,
            &DerivationRequest {
                target: b,
                inputs: vec![held(&a), held(&a)],
            },
        );
        assert!(
            matches!(refused, Answer::Refused(RequestRefusal::AmbiguousInput(_))),
            "{refused:?}"
        );

        let (a, b) = (fact("a"), fact("b"));
        let spec = capability(
            "make",
            vec![Requirement::complete(a.clone())],
            vec![b.clone()],
        );
        let mut registry = CapabilityRegistry::default();
        registry.register_spec(spec.clone()).unwrap();
        registry
            .register_provider(FailingProvider(ProviderDescriptor {
                id: ProviderId::new("test.provider", "make", "1"),
                capability: spec.id.clone(),
                implementation_digest: format!("sha256:{:064}", 1),
            }))
            .unwrap();
        let failed = answer(
            &registry,
            &DerivationRequest {
                target: b,
                inputs: vec![held(&a)],
            },
        );
        assert!(matches!(failed, Answer::Failed(_)), "{failed:?}");
    }

    #[test]
    fn a_fact_is_never_reported_produced_when_the_route_had_open_needs() {
        let (registry, a, b) = one_hop(false);
        let given = answer(
            &registry,
            &DerivationRequest {
                target: b,
                inputs: vec![held(&a)],
            },
        );
        // Asserting the variant, not merely "not Produced": `Failed` would also
        // be wrong here, because it sends the caller to fix a provider that was
        // never installed instead of to assign the work.
        assert!(
            matches!(given, Answer::Blocked(_)),
            "a route with no provider is assignable work, not a produced fact \
             and not a provider fault: {given:?}"
        );
    }

    #[test]
    fn work_is_never_reported_assignable_when_the_fact_was_actually_derivable() {
        let (registry, a, b) = one_hop(true);
        let given = answer(
            &registry,
            &DerivationRequest {
                target: b,
                inputs: vec![held(&a)],
            },
        );
        // `needs().is_empty()` alone would be vacuous: an executable plan has no
        // needs by construction, so it holds whatever variant comes back. The
        // variant is the property worth guarding.
        assert!(
            matches!(given, Answer::Produced(_)),
            "publishing a need a local provider could already serve would send \
             someone else to redo finished work: {given:?}"
        );
        assert!(given.needs().is_empty());
    }

    #[test]
    fn the_five_remedies_are_distinct() {
        let (registry, a, b) = one_hop(true);
        let produced = answer(
            &registry,
            &DerivationRequest {
                target: b.clone(),
                inputs: vec![held(&a)],
            },
        );
        let (blocked_registry, _, _) = one_hop(false);
        let blocked = answer(
            &blocked_registry,
            &DerivationRequest {
                target: b.clone(),
                inputs: vec![held(&a)],
            },
        );
        let unreachable = answer(
            &CapabilityRegistry::default(),
            &DerivationRequest {
                target: b.clone(),
                inputs: vec![held(&a)],
            },
        );
        let refused = answer(
            &registry,
            &DerivationRequest {
                target: b,
                inputs: vec![held(&a), held(&a)],
            },
        );
        let failed = Answer::Failed(ExecutionError::AmbiguousInput);

        let remedies: BTreeSet<&str> = [&produced, &blocked, &unreachable, &refused, &failed]
            .iter()
            .map(|a| a.remedy())
            .collect();
        assert_eq!(
            remedies.len(),
            5,
            "two variants sharing a remedy means one of them is not earning its place"
        );
    }

    /// The orchestrator owns ownership, deadlines, and settlement; Fleetd's
    /// `work.capability.attempt/v2` envelope already carries them. An answer
    /// that repeated any of them would create two authorities on one meaning.
    #[test]
    fn an_answer_carries_no_field_the_orchestrator_owns() {
        const ORCHESTRATOR_OWNED: [&str; 9] = [
            "status",
            "correlation_id",
            "causation_id",
            "usage",
            "deadline",
            "owner",
            "session_persistence",
            "invocation_id",
            "stop_reason",
        ];

        fn walk(node: &Value, found: &mut Vec<String>) {
            match node {
                Value::Object(map) => {
                    for (key, value) in map {
                        if ORCHESTRATOR_OWNED.contains(&key.as_str()) {
                            found.push(key.clone());
                        }
                        // A provider's payload is opaque to this rule: what a
                        // fact says is the provider's business, not the door's.
                        if key != "payload" {
                            walk(value, found);
                        }
                    }
                }
                Value::Array(items) => items.iter().for_each(|item| walk(item, found)),
                _ => {}
            }
        }

        let (registry, a, b) = one_hop(true);
        let produced = answer(
            &registry,
            &DerivationRequest {
                target: b.clone(),
                inputs: vec![held(&a)],
            },
        );
        let (blocked_registry, _, _) = one_hop(false);
        let blocked = answer(
            &blocked_registry,
            &DerivationRequest {
                target: b,
                inputs: vec![held(&a)],
            },
        );

        let mut found = Vec::new();
        for given in [&produced, &blocked] {
            walk(&serde_json::to_value(given).unwrap(), &mut found);
        }
        assert!(
            found.is_empty(),
            "the door restated orchestration state: {found:?}"
        );
    }

    #[test]
    fn an_answer_survives_the_wire() {
        let (registry, a, b) = one_hop(true);
        for given in [
            answer(
                &registry,
                &DerivationRequest {
                    target: b.clone(),
                    inputs: vec![held(&a)],
                },
            ),
            answer(
                &CapabilityRegistry::default(),
                &DerivationRequest {
                    target: b,
                    inputs: vec![held(&a)],
                },
            ),
        ] {
            let text = serde_json::to_string(&given).unwrap();
            let back: Answer = serde_json::from_str(&text).unwrap();
            assert_eq!(back, given, "an answer rides in structured_result.value");
        }
    }
}
