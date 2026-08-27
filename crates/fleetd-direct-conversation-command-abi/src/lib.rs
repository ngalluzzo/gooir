//! Proof-local authority ABI for Fleetd direct-conversation native commands.
//!
//! The document is operational authority, not semantic meaning. It travels
//! only through inherited file descriptor 3, is consumed exactly once, and
//! contains no Fleetd request or response types. The bearer credential has an
//! explicit exposure method, a redacted debug surface, and no serialization or
//! display implementation.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{IntoRawFd, RawFd};

use serde::{Deserialize, Deserializer, Serialize};
use url::{Host, Url};

/// Exact proof-local wire protocol for inherited command authority.
pub const AUTHORITY_PROTOCOL: &str =
    "org.gooi.proof.fleetd-direct-conversation-command-authority/v1";

/// Maximum encoded authority document accepted from inherited descriptor 3.
pub const MAX_AUTHORITY_DOCUMENT_BYTES: usize = 64 * 1024;

/// Maximum HTTP deadline granted to one native command.
pub const MAX_HTTP_TIMEOUT_MS: u64 = 5 * 60 * 1_000;

/// Maximum Fleetd response body that one native command may retain.
pub const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

const AUTHORITY_FD_PATH: &str = "/dev/fd/3";
const MAX_TARGET_CHARS: usize = 256;
const MAX_OPAQUE_REVISION_CHARS: usize = 256;
const MAX_ENDPOINT_BYTES: usize = 2 * 1024;
const MAX_BEARER_TOKEN_BYTES: usize = 16 * 1024;

/// One bearer credential with an explicit, auditable exposure point.
///
/// It deliberately implements neither [`fmt::Display`] nor
/// [`serde::Serialize`]. Its debug representation is always redacted.
#[derive(Clone, Eq, PartialEq)]
pub struct BearerToken(String);

impl BearerToken {
    /// Returns the exact credential for the single authorized HTTP boundary.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    fn parse(value: String) -> Result<Self, AuthorityError> {
        validate_bearer_token(&value)?;
        Ok(Self(value))
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerToken([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for BearerToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Closed authority granted to one Fleetd native command.
///
/// This value intentionally has no serialization implementation. The proof
/// host owns transport construction; the native child only consumes and
/// validates the inherited document.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorityDocument {
    protocol: String,
    target: String,
    endpoint_mapping_digest: String,
    credential_revision: String,
    endpoint: String,
    bearer_token: BearerToken,
    http_timeout_ms: u64,
    max_response_bytes: u64,
}

impl fmt::Debug for AuthorityDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorityDocument")
            .field("protocol", &self.protocol)
            .field("target", &self.target)
            .field("endpoint_mapping_digest", &self.endpoint_mapping_digest)
            .field("credential_revision", &self.credential_revision)
            .field("endpoint", &"[REDACTED]")
            .field("bearer_token", &self.bearer_token)
            .field("http_timeout_ms", &self.http_timeout_ms)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl AuthorityDocument {
    /// Constructs one fully validated host-side authority document.
    ///
    /// The exact protocol is supplied by this ABI rather than by the caller.
    /// This is operational authority only; construction grants no semantic
    /// claim or replay permission.
    ///
    /// # Errors
    ///
    /// Refuses invalid coordinates, digests, endpoint, secret, or limits.
    pub fn new(
        target: impl Into<String>,
        endpoint_mapping_digest: impl Into<String>,
        credential_revision: impl Into<String>,
        endpoint: impl Into<String>,
        bearer_token: impl Into<String>,
        http_timeout_ms: u64,
        max_response_bytes: u64,
    ) -> Result<Self, AuthorityError> {
        let document = Self {
            protocol: AUTHORITY_PROTOCOL.to_owned(),
            target: target.into(),
            endpoint_mapping_digest: endpoint_mapping_digest.into(),
            credential_revision: credential_revision.into(),
            endpoint: endpoint.into(),
            bearer_token: BearerToken::parse(bearer_token.into())?,
            http_timeout_ms,
            max_response_bytes,
        };
        document.validate()?;
        Ok(document)
    }

    /// Exact authority protocol.
    #[must_use]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Exact non-secret target coordinate repeated from the locked attempt.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Exact digest of the host-qualified target-to-endpoint mapping.
    #[must_use]
    pub fn endpoint_mapping_digest(&self) -> &str {
        &self.endpoint_mapping_digest
    }

    /// Exact non-secret credential revision selected by the proof host.
    #[must_use]
    pub fn credential_revision(&self) -> &str {
        &self.credential_revision
    }

    /// Exact canonical loopback HTTP origin granted to this command.
    ///
    /// Its spelling equals `Url::as_str()`, including the root-path trailing
    /// slash, so callers can append fixed relative paths without normalization.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Bearer credential with explicit secret exposure.
    #[must_use]
    pub const fn bearer_token(&self) -> &BearerToken {
        &self.bearer_token
    }

    /// HTTP deadline in milliseconds.
    #[must_use]
    pub const fn http_timeout_ms(&self) -> u64 {
        self.http_timeout_ms
    }

    /// Maximum accepted Fleetd response bytes.
    #[must_use]
    pub const fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }

    /// Materializes the exact bounded authority JSON written to the inherited
    /// pipe by the proof host.
    ///
    /// This is the ABI's sole intentional bearer-secret serialization seam.
    /// The type itself implements no general-purpose [`Serialize`], and errors
    /// never contain the encoded document or credential.
    ///
    /// # Errors
    ///
    /// Refuses an invalid in-memory document, an encoding failure, or output
    /// beyond the fixed authority-document bound.
    pub fn encode_for_pipe(&self) -> Result<Vec<u8>, AuthorityError> {
        self.validate()?;
        let wire = EncodedAuthorityDocument {
            protocol: &self.protocol,
            target: &self.target,
            endpoint_mapping_digest: &self.endpoint_mapping_digest,
            credential_revision: &self.credential_revision,
            endpoint: &self.endpoint,
            bearer_token: self.bearer_token.expose_secret(),
            http_timeout_ms: self.http_timeout_ms,
            max_response_bytes: self.max_response_bytes,
        };
        let bytes = serde_json::to_vec(&wire).map_err(|_| AuthorityError::EncodeDocument)?;
        if bytes.len() > MAX_AUTHORITY_DOCUMENT_BYTES {
            return Err(AuthorityError::DocumentTooLarge);
        }
        Ok(bytes)
    }

    fn from_wire(wire: WireAuthorityDocument) -> Result<Self, AuthorityError> {
        let document = Self {
            protocol: wire.protocol,
            target: wire.target,
            endpoint_mapping_digest: wire.endpoint_mapping_digest,
            credential_revision: wire.credential_revision,
            endpoint: wire.endpoint,
            bearer_token: wire.bearer_token,
            http_timeout_ms: wire.http_timeout_ms,
            max_response_bytes: wire.max_response_bytes,
        };
        document.validate()?;
        Ok(document)
    }

    fn validate(&self) -> Result<(), AuthorityError> {
        if self.protocol != AUTHORITY_PROTOCOL {
            return Err(AuthorityError::ProtocolMismatch);
        }
        validate_opaque(
            &self.target,
            MAX_TARGET_CHARS,
            AuthorityError::InvalidTarget,
        )?;
        if !is_sha256_identity(&self.endpoint_mapping_digest) {
            return Err(AuthorityError::InvalidEndpointMappingDigest);
        }
        validate_opaque(
            &self.credential_revision,
            MAX_OPAQUE_REVISION_CHARS,
            AuthorityError::InvalidCredentialRevision,
        )?;
        validate_endpoint(&self.endpoint)?;
        validate_bearer_token(self.bearer_token.expose_secret())?;
        if self.http_timeout_ms == 0 || self.http_timeout_ms > MAX_HTTP_TIMEOUT_MS {
            return Err(AuthorityError::InvalidHttpTimeout);
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(AuthorityError::InvalidMaxResponseBytes);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for AuthorityDocument {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = WireAuthorityDocument::deserialize(deserializer)?;
        Self::from_wire(wire).map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAuthorityDocument {
    protocol: String,
    target: String,
    endpoint_mapping_digest: String,
    credential_revision: String,
    endpoint: String,
    bearer_token: BearerToken,
    http_timeout_ms: u64,
    max_response_bytes: u64,
}

#[derive(Serialize)]
struct EncodedAuthorityDocument<'a> {
    protocol: &'a str,
    target: &'a str,
    endpoint_mapping_digest: &'a str,
    credential_revision: &'a str,
    endpoint: &'a str,
    bearer_token: &'a str,
    http_timeout_ms: u64,
    max_response_bytes: u64,
}

/// Parses one bounded, closed authority document.
///
/// # Errors
///
/// Refuses empty or oversized input, malformed or ambiguous JSON, unknown or
/// duplicate fields, and every invalid authority constraint.
pub fn parse_authority_document(bytes: &[u8]) -> Result<AuthorityDocument, AuthorityError> {
    if bytes.is_empty() {
        return Err(AuthorityError::EmptyDocument);
    }
    if bytes.len() > MAX_AUTHORITY_DOCUMENT_BYTES {
        return Err(AuthorityError::DocumentTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| AuthorityError::MalformedDocument)
}

/// Consumes the authority pipe inherited as descriptor 3.
///
/// The helper first opens `/dev/fd/3`, producing a close-on-exec duplicate,
/// then closes the original inherited descriptor. It reads the duplicate to a
/// bounded EOF, explicitly drops it, and only then parses and returns the
/// authority. Therefore no caller can begin HTTP while either authority
/// descriptor remains owned by this function.
///
/// # Errors
///
/// Refuses a missing/unreadable descriptor, close or read failure, a document
/// beyond the fixed byte bound, or an invalid authority document.
pub fn read_authority_from_fd3() -> Result<AuthorityDocument, AuthorityError> {
    let duplicate_result = File::open(AUTHORITY_FD_PATH);
    let close_result = nix::unistd::close(InheritedAuthorityFd);

    let mut duplicate = duplicate_result.map_err(AuthorityError::OpenAuthorityFd)?;
    close_result.map_err(AuthorityError::CloseAuthorityFd)?;

    let bytes = read_bounded_to_eof(&mut duplicate);
    drop(duplicate);
    let bytes = bytes?;
    parse_authority_document(&bytes)
}

struct InheritedAuthorityFd;

impl IntoRawFd for InheritedAuthorityFd {
    fn into_raw_fd(self) -> RawFd {
        3
    }
}

fn read_bounded_to_eof(reader: &mut File) -> Result<Vec<u8>, AuthorityError> {
    let limit = u64::try_from(MAX_AUTHORITY_DOCUMENT_BYTES)
        .expect("the authority byte bound is representable")
        + 1;
    let mut bytes = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(AuthorityError::ReadAuthorityFd)?;
    if bytes.len() > MAX_AUTHORITY_DOCUMENT_BYTES {
        return Err(AuthorityError::DocumentTooLarge);
    }
    Ok(bytes)
}

fn validate_opaque(
    value: &str,
    max_chars: usize,
    error: AuthorityError,
) -> Result<(), AuthorityError> {
    if value.is_empty()
        || value.trim() != value
        || value.chars().count() > max_chars
        || value.chars().any(char::is_control)
    {
        Err(error)
    } else {
        Ok(())
    }
}

fn is_sha256_identity(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn validate_endpoint(endpoint: &str) -> Result<(), AuthorityError> {
    if endpoint.is_empty()
        || endpoint.len() > MAX_ENDPOINT_BYTES
        || endpoint.trim() != endpoint
        || !endpoint.starts_with("http://")
    {
        return Err(AuthorityError::InvalidEndpoint);
    }
    let url = Url::parse(endpoint).map_err(|_| AuthorityError::InvalidEndpoint)?;
    if url.scheme() != "http"
        || url.as_str() != endpoint
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(AuthorityError::InvalidEndpoint);
    }
    match url.host() {
        Some(Host::Ipv4(address)) if address.is_loopback() => {}
        Some(Host::Ipv6(address)) if address.is_loopback() => {}
        _ => return Err(AuthorityError::InvalidEndpoint),
    }
    let explicit_port = parse_explicit_port(endpoint).ok_or(AuthorityError::InvalidEndpoint)?;
    if url.port_or_known_default() != Some(explicit_port) {
        return Err(AuthorityError::InvalidEndpoint);
    }
    Ok(())
}

fn validate_bearer_token(value: &str) -> Result<(), AuthorityError> {
    if value.is_empty()
        || value.len() > MAX_BEARER_TOKEN_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        Err(AuthorityError::InvalidBearerToken)
    } else {
        Ok(())
    }
}

fn parse_explicit_port(endpoint: &str) -> Option<u16> {
    let remainder = endpoint.strip_prefix("http://")?;
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let port = if authority.starts_with('[') {
        let bracket = authority.find(']')?;
        authority.get(bracket + 1..)?.strip_prefix(':')?
    } else {
        let (host, port) = authority.rsplit_once(':')?;
        if host.is_empty() || host.contains(':') {
            return None;
        }
        port
    };
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

/// Closed, secret-free failure class for the authority ABI.
#[derive(Debug)]
pub enum AuthorityError {
    OpenAuthorityFd(io::Error),
    CloseAuthorityFd(nix::Error),
    ReadAuthorityFd(io::Error),
    EncodeDocument,
    EmptyDocument,
    DocumentTooLarge,
    MalformedDocument,
    ProtocolMismatch,
    InvalidTarget,
    InvalidEndpointMappingDigest,
    InvalidCredentialRevision,
    InvalidEndpoint,
    InvalidBearerToken,
    InvalidHttpTimeout,
    InvalidMaxResponseBytes,
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OpenAuthorityFd(_) => "could not duplicate inherited authority descriptor 3",
            Self::CloseAuthorityFd(_) => "could not close inherited authority descriptor 3",
            Self::ReadAuthorityFd(_) => "could not read inherited authority to bounded EOF",
            Self::EncodeDocument => "could not encode the authority document",
            Self::EmptyDocument => "authority document is empty",
            Self::DocumentTooLarge => "authority document exceeds its byte bound",
            Self::MalformedDocument => "authority document is malformed or not closed",
            Self::ProtocolMismatch => "authority protocol does not match",
            Self::InvalidTarget => "authority target is invalid",
            Self::InvalidEndpointMappingDigest => "endpoint mapping digest is invalid",
            Self::InvalidCredentialRevision => "credential revision is invalid",
            Self::InvalidEndpoint => "endpoint is not an explicit-port loopback HTTP origin",
            Self::InvalidBearerToken => "bearer credential is invalid",
            Self::InvalidHttpTimeout => "HTTP timeout is outside the proof bound",
            Self::InvalidMaxResponseBytes => "response byte limit is outside the proof bound",
        })
    }
}

impl Error for AuthorityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OpenAuthorityFd(error) | Self::ReadAuthorityFd(error) => Some(error),
            Self::CloseAuthorityFd(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::io::Write;
    use std::process::{Command, Stdio};

    use serde_json::{Value, json};

    use super::*;

    const SECRET: &str = "fleetd-proof-secret.token+123";

    fn valid_value() -> Value {
        json!({
            "protocol": AUTHORITY_PROTOCOL,
            "target": "fleetd:target-a",
            "endpoint_mapping_digest": format!("sha256:{}", "a".repeat(64)),
            "credential_revision": "operator-credential/revision-7",
            "endpoint": "http://127.0.0.1:63967/",
            "bearer_token": SECRET,
            "http_timeout_ms": 30_000,
            "max_response_bytes": 262_144
        })
    }

    fn encode(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("authority JSON")
    }

    #[test]
    fn exact_document_parses_and_debug_redacts_the_secret() {
        let document = parse_authority_document(&encode(&valid_value())).expect("authority");
        assert_eq!(document.protocol(), AUTHORITY_PROTOCOL);
        assert_eq!(document.target(), "fleetd:target-a");
        assert_eq!(
            document.endpoint_mapping_digest(),
            format!("sha256:{}", "a".repeat(64))
        );
        assert_eq!(
            document.credential_revision(),
            "operator-credential/revision-7"
        );
        assert!(
            document.endpoint() == "http://127.0.0.1:63967/",
            "canonical endpoint changed"
        );
        assert!(
            document.bearer_token().expose_secret() == SECRET,
            "bearer credential changed"
        );
        assert_eq!(document.http_timeout_ms(), 30_000);
        assert_eq!(document.max_response_bytes(), 262_144);

        let debug = format!("{document:?} {:?}", document.bearer_token());
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(SECRET));
        assert!(!debug.contains(document.endpoint()));
    }

    #[test]
    fn host_constructor_and_pipe_encoder_define_the_same_exact_wire() {
        let document = AuthorityDocument::new(
            "fleetd:target-a",
            format!("sha256:{}", "a".repeat(64)),
            "operator-credential/revision-7",
            "http://127.0.0.1:63967/",
            SECRET,
            30_000,
            262_144,
        )
        .expect("host authority");
        let encoded = document.encode_for_pipe().expect("pipe encoding");
        assert!(encoded.len() <= MAX_AUTHORITY_DOCUMENT_BYTES);
        assert!(String::from_utf8_lossy(&encoded).contains(SECRET));
        assert_eq!(
            parse_authority_document(&encoded).expect("decoded host authority"),
            document
        );

        let debug = format!("{document:?}");
        assert!(!debug.contains(SECRET));
        assert!(!debug.contains(document.endpoint()));
    }

    #[test]
    fn closed_document_and_all_bounds_fail_closed() {
        let mut cases = Vec::new();

        let mut wrong_protocol = valid_value();
        wrong_protocol["protocol"] = json!("wrong/v1");
        cases.push(wrong_protocol);

        let mut empty_target = valid_value();
        empty_target["target"] = json!("");
        cases.push(empty_target);

        let mut padded_target = valid_value();
        padded_target["target"] = json!(" fleetd:target-a");
        cases.push(padded_target);

        let mut long_target = valid_value();
        long_target["target"] = json!("x".repeat(MAX_TARGET_CHARS + 1));
        cases.push(long_target);

        let mut bad_digest = valid_value();
        bad_digest["endpoint_mapping_digest"] = json!(format!("sha256:{}", "A".repeat(64)));
        cases.push(bad_digest);

        let mut bad_revision = valid_value();
        bad_revision["credential_revision"] = json!("revision\n8");
        cases.push(bad_revision);

        let mut empty_token = valid_value();
        empty_token["bearer_token"] = json!("");
        cases.push(empty_token);

        let mut spaced_token = valid_value();
        spaced_token["bearer_token"] = json!("secret token");
        cases.push(spaced_token);

        let mut long_token = valid_value();
        long_token["bearer_token"] = json!("x".repeat(MAX_BEARER_TOKEN_BYTES + 1));
        cases.push(long_token);

        let mut zero_timeout = valid_value();
        zero_timeout["http_timeout_ms"] = json!(0);
        cases.push(zero_timeout);

        let mut long_timeout = valid_value();
        long_timeout["http_timeout_ms"] = json!(MAX_HTTP_TIMEOUT_MS + 1);
        cases.push(long_timeout);

        let mut zero_response = valid_value();
        zero_response["max_response_bytes"] = json!(0);
        cases.push(zero_response);

        let mut long_response = valid_value();
        long_response["max_response_bytes"] = json!(MAX_RESPONSE_BYTES + 1);
        cases.push(long_response);

        let mut unknown = valid_value();
        unknown["base_url"] = json!("http://example.invalid/");
        cases.push(unknown);

        for (index, invalid) in cases.into_iter().enumerate() {
            assert!(
                parse_authority_document(&encode(&invalid)).is_err(),
                "accepted invalid authority case {index}"
            );
        }

        let duplicate = format!(
            concat!(
                "{{\"protocol\":\"{0}\",\"protocol\":\"{0}\",",
                "\"target\":\"fleetd:target-a\",",
                "\"endpoint_mapping_digest\":\"sha256:{1}\",",
                "\"credential_revision\":\"revision-1\",",
                "\"endpoint\":\"http://127.0.0.1:63967/\",",
                "\"bearer_token\":\"{2}\",",
                "\"http_timeout_ms\":1000,\"max_response_bytes\":1024}}"
            ),
            AUTHORITY_PROTOCOL,
            "a".repeat(64),
            SECRET
        );
        assert!(parse_authority_document(duplicate.as_bytes()).is_err());
        assert!(matches!(
            parse_authority_document(&[]),
            Err(AuthorityError::EmptyDocument)
        ));
        assert!(matches!(
            parse_authority_document(&vec![b'x'; MAX_AUTHORITY_DOCUMENT_BYTES + 1]),
            Err(AuthorityError::DocumentTooLarge)
        ));
    }

    #[test]
    fn only_explicit_port_numeric_loopback_http_origins_are_accepted() {
        for (index, endpoint) in [
            "http://127.0.0.1:8080/",
            "http://127.255.12.9:63967/",
            "http://[::1]:63967/",
        ]
        .into_iter()
        .enumerate()
        {
            let mut value = valid_value();
            value["endpoint"] = json!(endpoint);
            assert!(
                parse_authority_document(&encode(&value)).is_ok(),
                "rejected valid endpoint case {index}"
            );
        }

        for (index, endpoint) in [
            "https://127.0.0.1:63967/",
            "http://127.0.0.1/",
            "http://127.0.0.1:80/",
            "http://127.0.0.1:63967",
            "http://localhost:63967/",
            "http://0.0.0.0:63967/",
            "http://192.0.2.1:63967/",
            "http://user@127.0.0.1:63967/",
            "http://127.0.0.1:63967/path",
            "http://127.0.0.1:63967/?query=yes",
            "http://127.0.0.1:63967/#fragment",
            "http://127.0.0.1:0/",
        ]
        .into_iter()
        .enumerate()
        {
            let mut value = valid_value();
            value["endpoint"] = json!(endpoint);
            assert!(
                parse_authority_document(&encode(&value)).is_err(),
                "accepted invalid endpoint case {index}"
            );
        }
    }

    #[test]
    fn rejection_and_error_surfaces_never_echo_the_bearer_secret() {
        let malformed = format!("{{\"bearer_token\":\"{SECRET}\",\"unexpected\":true}}");
        let error = parse_authority_document(malformed.as_bytes()).expect_err("invalid authority");
        let surface = format!("{error} {error:?}");
        assert!(!surface.contains(SECRET));

        let private_endpoint = "http://127.0.0.1:63967/?must-not-escape";
        let mut invalid_endpoint = valid_value();
        invalid_endpoint["endpoint"] = json!(private_endpoint);
        let error = parse_authority_document(&encode(&invalid_endpoint))
            .expect_err("invalid endpoint authority");
        let surface = format!("{error} {error:?}");
        assert!(!surface.contains(private_endpoint));
    }

    #[test]
    fn fd3_is_consumed_in_a_real_subprocess_and_the_original_is_closed() {
        const CHILD_ENV: &str = "GOOIR_AUTHORITY_FD3_TEST_CHILD";
        if env::var_os(CHILD_ENV).is_some() {
            let document = read_authority_from_fd3().expect("authority from fd 3");
            assert_eq!(document.target(), "fleetd:target-a");
            assert!(
                document.bearer_token().expose_secret() == SECRET,
                "bearer credential changed"
            );
            assert!(File::open(AUTHORITY_FD_PATH).is_err());
            return;
        }

        let executable = env::current_exe().expect("current test executable");
        let mut child = Command::new("/bin/sh")
            .args([
                "-c",
                concat!(
                    "exec 3<&0; exec \"$1\" --exact ",
                    "tests::fd3_is_consumed_in_a_real_subprocess_and_the_original_is_closed ",
                    "--nocapture"
                ),
                "authority-fd3-test",
            ])
            .arg(executable)
            .env(CHILD_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn child test");
        child
            .stdin
            .take()
            .expect("child stdin")
            .write_all(
                &AuthorityDocument::new(
                    "fleetd:target-a",
                    format!("sha256:{}", "a".repeat(64)),
                    "operator-credential/revision-7",
                    "http://127.0.0.1:63967/",
                    SECRET,
                    30_000,
                    262_144,
                )
                .expect("host authority")
                .encode_for_pipe()
                .expect("pipe authority"),
            )
            .expect("write authority and close pipe");
        let output = child.wait_with_output().expect("child output");
        assert!(
            output.status.success(),
            "child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
    }
}
