//! Closed neutral input document for one independent conformance assessment.

use std::error::Error;
use std::fmt;

use crate::authority::ConformanceAuthority;
use crate::protocol::{
    CapabilityCandidate, CapabilityInvocation, CapabilityResult, ConformanceSuiteId, ProtocolError,
};
use serde::{Deserialize, Serialize};

/// Exact request protocol for one independently assessed candidate chain.
pub const ASSESSMENT_REQUEST_PROTOCOL: &str = "org.gooi.authority.assessment-request/v1";

/// One closed request containing the complete neutral candidate chain and the
/// exact host-selected conformance authority.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssessmentRequest {
    protocol: String,
    invocation: CapabilityInvocation,
    result: CapabilityResult,
    candidate: CapabilityCandidate,
    authority: ConformanceAuthority,
}

impl AssessmentRequest {
    /// Constructs a request only from a valid, exactly correlated chain.
    ///
    /// # Errors
    ///
    /// Refuses an invalid or uncorrelated invocation/result/candidate chain,
    /// invalid authority, suite mismatch, or non-independent attester.
    pub fn new(
        invocation: CapabilityInvocation,
        result: CapabilityResult,
        candidate: CapabilityCandidate,
        authority: ConformanceAuthority,
    ) -> Result<Self, AssessmentRequestError> {
        let request = Self {
            protocol: ASSESSMENT_REQUEST_PROTOCOL.to_owned(),
            invocation,
            result,
            candidate,
            authority,
        };
        request.validate()?;
        Ok(request)
    }

    /// Revalidates request identity, correlation, suite, and independence.
    ///
    /// # Errors
    ///
    /// Refuses a changed protocol, invalid or uncorrelated candidate chain,
    /// invalid authority, suite mismatch, or non-independent attester.
    pub fn validate(&self) -> Result<(), AssessmentRequestError> {
        if self.protocol != ASSESSMENT_REQUEST_PROTOCOL {
            return Err(AssessmentRequestError::ProtocolMismatch {
                actual: self.protocol.clone(),
            });
        }
        self.invocation
            .validate()
            .map_err(|error| AssessmentRequestError::Protocol(Box::new(error)))?;
        self.result
            .validate_against(&self.invocation)
            .map_err(|error| AssessmentRequestError::Protocol(Box::new(error)))?;
        self.candidate
            .validate_against(&self.invocation)
            .map_err(|error| AssessmentRequestError::Protocol(Box::new(error)))?;
        if self.candidate.result != self.result {
            return Err(AssessmentRequestError::ResultCandidateMismatch);
        }
        self.authority
            .validate()
            .map_err(|error| AssessmentRequestError::InvalidAuthority(error.to_string()))?;
        if self.authority.suite != self.invocation.conformance_suite {
            return Err(AssessmentRequestError::SuiteMismatch {
                expected: Box::new(self.invocation.conformance_suite.clone()),
                actual: Box::new(self.authority.suite.clone()),
            });
        }
        let selected = &self.invocation.selection.offer;
        if self.authority.attester.implementation == selected.implementation
            || self.authority.attester.artifact_digest == selected.artifact_digest
        {
            return Err(AssessmentRequestError::NotIndependent);
        }
        Ok(())
    }

    /// Exact invocation embedded in this request.
    #[must_use]
    pub const fn invocation(&self) -> &CapabilityInvocation {
        &self.invocation
    }

    /// Exact provider result embedded in this request.
    #[must_use]
    pub const fn result(&self) -> &CapabilityResult {
        &self.result
    }

    /// Exact candidate embedding the provider result.
    #[must_use]
    pub const fn candidate(&self) -> &CapabilityCandidate {
        &self.candidate
    }

    /// Exact host-selected authority this artifact must author as.
    #[must_use]
    pub const fn authority(&self) -> &ConformanceAuthority {
        &self.authority
    }
}

/// Invalid closed assessment input.
#[derive(Debug)]
pub enum AssessmentRequestError {
    ProtocolMismatch {
        actual: String,
    },
    Protocol(Box<ProtocolError>),
    ResultCandidateMismatch,
    InvalidAuthority(String),
    SuiteMismatch {
        expected: Box<ConformanceSuiteId>,
        actual: Box<ConformanceSuiteId>,
    },
    NotIndependent,
}

impl fmt::Display for AssessmentRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolMismatch { actual } => write!(
                formatter,
                "assessment request protocol `{actual}` does not match `{ASSESSMENT_REQUEST_PROTOCOL}`"
            ),
            Self::Protocol(error) => write!(formatter, "invalid neutral protocol: {error}"),
            Self::ResultCandidateMismatch => {
                formatter.write_str("assessment request result and candidate disagree")
            }
            Self::InvalidAuthority(detail) => {
                write!(formatter, "invalid conformance authority: {detail}")
            }
            Self::SuiteMismatch { expected, actual } => write!(
                formatter,
                "assessment suite `{actual}` does not match invocation suite `{expected}`"
            ),
            Self::NotIndependent => {
                formatter.write_str("selected attester is not independent of the provider")
            }
        }
    }
}

impl Error for AssessmentRequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}
