//! Shared bounded HTTP/1.1 framing for the real Fleetd proof proxies.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use sha2::{Digest, Sha256};

pub(super) const HTTP_IO_DEADLINE: Duration = Duration::from_secs(15);

const MAX_HTTP_HEADER_BYTES: usize = 32 * 1024;
const MAX_HTTP_MESSAGE_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy)]
pub(super) enum HttpSide {
    Request,
    Response,
}

/// One bounded complete HTTP/1.1 request and its still-owned client stream.
pub(super) struct HttpRequest {
    client: TcpStream,
    bytes: Vec<u8>,
    method: String,
    target: String,
    body_offset: usize,
}

impl HttpRequest {
    pub(super) fn method(&self) -> &str {
        &self.method
    }

    pub(super) fn target(&self) -> &str {
        &self.target
    }

    pub(super) fn body_bytes(&self) -> u64 {
        u64::try_from(self.bytes.len() - self.body_offset).expect("HTTP body length fits u64")
    }

    pub(super) fn body_digest(&self) -> String {
        sha256_identity(&self.bytes[self.body_offset..])
    }

    pub(super) fn write_response(&mut self, response: &HttpResponse) {
        self.client
            .write_all(response.bytes())
            .unwrap_or_else(|_| panic!("proof proxy client response write failed"));
    }

    pub(super) fn shutdown_write(&self) {
        self.client
            .shutdown(Shutdown::Write)
            .unwrap_or_else(|_| panic!("proof proxy client write shutdown failed"));
    }

    pub(super) fn shutdown_both(&self) {
        self.client
            .shutdown(Shutdown::Both)
            .unwrap_or_else(|_| panic!("proof proxy client shutdown failed"));
    }
}

/// One bounded complete HTTP/1.1 response.
pub(super) struct HttpResponse {
    bytes: Vec<u8>,
    status: u16,
    body_offset: usize,
}

impl HttpResponse {
    pub(super) fn from_bytes(bytes: Vec<u8>) -> Self {
        let (status, body_offset) = parse_response_head(&bytes);
        Self {
            bytes,
            status,
            body_offset,
        }
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) const fn status(&self) -> u16 {
        self.status
    }

    pub(super) fn body(&self) -> &[u8] {
        &self.bytes[self.body_offset..]
    }

    pub(super) fn body_bytes(&self) -> u64 {
        u64::try_from(self.body().len()).expect("HTTP body length fits u64")
    }

    pub(super) fn body_digest(&self) -> String {
        sha256_identity(self.body())
    }
}

/// Accept up to `empty_capacity` loopback connections until one complete
/// bounded request is read. Headerless closes consume capacity.
pub(super) fn accept_request(listener: &TcpListener, empty_capacity: usize) -> HttpRequest {
    (0..empty_capacity)
        .find_map(|_| {
            let (client, peer) = listener
                .accept()
                .unwrap_or_else(|_| panic!("proof proxy accept failed"));
            assert!(peer.ip().is_loopback());
            read_request(client)
        })
        .unwrap_or_else(|| panic!("proof proxy empty-connection capacity was exhausted"))
}

/// Read one bounded request from an already accepted loopback stream.
pub(super) fn read_request(mut client: TcpStream) -> Option<HttpRequest> {
    configure_proxy_stream(&client);
    let bytes = read_framed_http(&mut client, HttpSide::Request)?;
    let (method, target, body_offset) = parse_request_head(&bytes);
    Some(HttpRequest {
        client,
        bytes,
        method,
        target,
        body_offset,
    })
}

/// Forward one exact request to the loopback backend and read its one bounded
/// Content-Length-framed response.
pub(super) fn forward_request(request: &HttpRequest, backend: SocketAddr) -> HttpResponse {
    assert!(backend.ip().is_loopback());
    let mut upstream = TcpStream::connect_timeout(&backend, HTTP_IO_DEADLINE)
        .unwrap_or_else(|_| panic!("proof proxy backend connect failed"));
    configure_proxy_stream(&upstream);
    upstream
        .write_all(&request.bytes)
        .unwrap_or_else(|_| panic!("proof proxy backend request write failed"));
    let response = read_framed_http(&mut upstream, HttpSide::Response)
        .unwrap_or_else(|| panic!("proof proxy backend closed before its response"));
    HttpResponse::from_bytes(response)
}

pub(super) fn read_framed_http(stream: &mut TcpStream, side: HttpSide) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let header_end = loop {
        let count = stream
            .read(&mut buffer)
            .unwrap_or_else(|_| panic!("proof proxy HTTP header read failed"));
        if count == 0 && bytes.is_empty() {
            return None;
        }
        assert_ne!(count, 0, "proof proxy HTTP message ended within its header");
        bytes.extend_from_slice(&buffer[..count]);
        assert!(
            bytes.len() <= MAX_HTTP_MESSAGE_BYTES,
            "proof proxy HTTP message exceeded its bound"
        );
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let end = end + 4;
            assert!(end <= MAX_HTTP_HEADER_BYTES);
            break end;
        }
        assert!(bytes.len() <= MAX_HTTP_HEADER_BYTES);
    };
    let content_length = match side {
        HttpSide::Request => parse_request_content_length(&bytes[..header_end]),
        HttpSide::Response => parse_response_content_length(&bytes[..header_end]),
    };
    let expected = header_end
        .checked_add(content_length)
        .unwrap_or_else(|| panic!("proof proxy HTTP length overflowed"));
    assert!(expected <= MAX_HTTP_MESSAGE_BYTES);
    assert!(
        bytes.len() <= expected,
        "proof proxy rejected HTTP pipelining"
    );
    while bytes.len() < expected {
        let available = buffer.len().min(expected - bytes.len());
        let count = stream
            .read(&mut buffer[..available])
            .unwrap_or_else(|_| panic!("proof proxy HTTP body read failed"));
        assert_ne!(count, 0, "proof proxy HTTP message ended before its body");
        bytes.extend_from_slice(&buffer[..count]);
    }
    Some(bytes)
}

pub(super) fn parse_request_head(bytes: &[u8]) -> (String, String, usize) {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    let httparse::Status::Complete(body_offset) = request
        .parse(bytes)
        .unwrap_or_else(|_| panic!("proof proxy request header was malformed"))
    else {
        panic!("proof proxy request header was incomplete");
    };
    assert_eq!(request.version, Some(1));
    (
        request
            .method
            .unwrap_or_else(|| panic!("proof proxy request method was absent"))
            .to_owned(),
        request
            .path
            .unwrap_or_else(|| panic!("proof proxy request target was absent"))
            .to_owned(),
        body_offset,
    )
}

pub(super) fn parse_response_head(bytes: &[u8]) -> (u16, usize) {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    let httparse::Status::Complete(body_offset) = response
        .parse(bytes)
        .unwrap_or_else(|_| panic!("proof proxy response header was malformed"))
    else {
        panic!("proof proxy response header was incomplete");
    };
    assert_eq!(response.version, Some(1));
    (
        response
            .code
            .unwrap_or_else(|| panic!("proof proxy response status was absent")),
        body_offset,
    )
}

fn parse_request_content_length(bytes: &[u8]) -> usize {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    assert!(matches!(
        request
            .parse(bytes)
            .unwrap_or_else(|_| panic!("proof proxy request framing was malformed")),
        httparse::Status::Complete(_)
    ));
    content_length(request.headers)
}

fn parse_response_content_length(bytes: &[u8]) -> usize {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    assert!(matches!(
        response
            .parse(bytes)
            .unwrap_or_else(|_| panic!("proof proxy response framing was malformed")),
        httparse::Status::Complete(_)
    ));
    content_length(response.headers)
}

fn content_length(headers: &[httparse::Header<'_>]) -> usize {
    assert!(
        headers
            .iter()
            .all(|header| !header.name.eq_ignore_ascii_case("transfer-encoding")),
        "proof proxy rejects transfer encoding"
    );
    let lengths = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
        .map(|header| {
            std::str::from_utf8(header.value)
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or_else(|| panic!("proof proxy content length was invalid"))
        })
        .collect::<Vec<_>>();
    match lengths.as_slice() {
        [] => 0,
        [length] => *length,
        _ => panic!("proof proxy rejected ambiguous content length"),
    }
}

pub(super) fn configure_proxy_stream(stream: &TcpStream) {
    stream
        .set_read_timeout(Some(HTTP_IO_DEADLINE))
        .unwrap_or_else(|_| panic!("proof proxy read deadline failed"));
    stream
        .set_write_timeout(Some(HTTP_IO_DEADLINE))
        .unwrap_or_else(|_| panic!("proof proxy write deadline failed"));
}

fn sha256_identity(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
