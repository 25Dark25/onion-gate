//! The reverse proxy: once a visitor holds a valid pass, their request is
//! forwarded to a local backend and the backend's response is relayed back.
//!
//! Design (deliberately strict, std only):
//!  - One upstream connection per request, `Connection: close` both ways. No
//!    keep-alive, no pooling, no pipelining.
//!  - The request is forwarded verbatim (method, target, headers, body) EXCEPT:
//!    hop-by-hop headers are dropped, the gate's own pass cookie is stripped
//!    from the `Cookie` header, `Content-Length` is recomputed, and
//!    `Connection: close` is forced. Nothing about the visitor is added — no
//!    `X-Forwarded-For`, no client address — so the backend learns nothing the
//!    gate did not already strip.
//!  - The upstream must be a loopback address (checked at startup): the gate is
//!    meant to sit in front of a backend on the same host.
//!  - The whole request and response bodies are buffered in memory, each capped
//!    (`max_body` and `MAX_RESPONSE`). This rules out streaming and very large
//!    transfers by design; see the README.
//!  - A chunked upstream response is de-chunked; otherwise `Content-Length` or
//!    read-to-EOF frames the body.

use crate::http::{self, Request};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Largest upstream response the gate will buffer and relay.
const MAX_RESPONSE: usize = 8 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Header names that belong to a single hop and must never be forwarded in
/// either direction (RFC 9110 §7.6.1, plus the chunked framing header).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

#[derive(Debug)]
pub enum ProxyError {
    /// The upstream address could not be reached.
    Connect,
    /// Timed out talking to the upstream.
    Timeout,
    /// The upstream sent something that is not a usable HTTP/1 response.
    BadResponse,
    /// The upstream response exceeded `MAX_RESPONSE`.
    TooLarge,
}

impl ProxyError {
    /// The status the gate returns to the visitor when forwarding fails.
    pub fn status(&self) -> u16 {
        match self {
            ProxyError::Connect | ProxyError::BadResponse => 502,
            ProxyError::Timeout => 504,
            ProxyError::TooLarge => 502,
        }
    }
}

pub struct Upstream {
    /// Every address `--upstream` resolved to (all loopback), tried in order.
    addrs: Vec<SocketAddr>,
    /// The pass cookie name to strip from forwarded requests.
    pass_cookie: &'static str,
}

impl Upstream {
    /// Resolves `spec` (host:port) and requires every resolved address to be
    /// loopback. Returns an error string for the operator at startup.
    pub fn new(spec: &str, pass_cookie: &'static str) -> Result<Upstream, String> {
        let addrs: Vec<SocketAddr> = spec.to_socket_addrs().map_err(|e| format!("{}: {}", spec, e))?.collect();
        if addrs.is_empty() {
            return Err(format!("{}: resolved to no address", spec));
        }
        if let Some(a) = addrs.iter().find(|a| !a.ip().is_loopback()) {
            return Err(format!(
                "{}: upstream must be loopback (got {}); onion-gate only proxies a backend on the same host",
                spec, a
            ));
        }
        Ok(Upstream { addrs, pass_cookie })
    }

    /// Forwards one request and returns the response, already framed as bytes
    /// ready to write to the visitor's connection.
    pub fn forward(&self, req: &Request) -> Result<Vec<u8>, ProxyError> {
        let wire = build_request(req, self.pass_cookie);
        // `localhost` may resolve to ::1 and 127.0.0.1; use the first that answers.
        let mut stream = self
            .addrs
            .iter()
            .find_map(|a| TcpStream::connect_timeout(a, CONNECT_TIMEOUT).ok())
            .ok_or(ProxyError::Connect)?;
        stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| ProxyError::Connect)?;
        stream.write_all(&wire).map_err(|_| ProxyError::Connect)?;
        stream.flush().map_err(|_| ProxyError::Connect)?;
        // No half-close: some servers read an early FIN as "client gave up".
        // `Connection: close` and an exact Content-Length frame the request.

        let head_only = req.method == "HEAD";
        let raw = read_response(&mut stream, head_only)?;
        frame_response(&raw, head_only)
    }
}

/// How the body of a parsed response is delimited.
#[derive(Clone, Copy)]
enum Body {
    /// No body at all (a HEAD request, 204, 304).
    None,
    Length(usize),
    Chunked,
    /// No length given: the body runs until the upstream closes.
    ToEof,
}

/// A parsed response head (any interim 1xx heads already skipped).
struct Head<'a> {
    code: u16,
    reason: &'a str,
    /// Headers to relay: hop-by-hop, framing and Connection-named ones removed.
    headers: Vec<(&'a str, &'a str)>,
    content_length: Option<usize>,
    body_kind: Body,
    /// Everything after the head (may be incomplete while still reading).
    body: &'a [u8],
}

/// Parses the response head. Ok(None) = the head is not complete yet.
fn parse_head(raw: &[u8], head_only: bool) -> Result<Option<Head<'_>>, ProxyError> {
    let mut rest = raw;
    loop {
        let end = match rest.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(e) => e,
            None => return Ok(None),
        };
        let head = std::str::from_utf8(&rest[..end]).map_err(|_| ProxyError::BadResponse)?;
        let body = &rest[end + 4..];
        let mut lines = head.split("\r\n");
        let status_line = lines.next().ok_or(ProxyError::BadResponse)?;
        let code = parse_status(status_line).ok_or(ProxyError::BadResponse)?;
        if code == 101 {
            return Err(ProxyError::BadResponse); // no protocol switching (WebSockets)
        }
        if (100..200).contains(&code) {
            rest = body; // interim response (e.g. 100 Continue): skip it
            continue;
        }
        let reason = status_line.splitn(3, ' ').nth(2).unwrap_or("");

        let lines: Vec<&str> = lines.collect();
        // Headers named in `Connection` are hop-by-hop too (RFC 9110 §7.6.1).
        let mut named: Vec<String> = Vec::new();
        let mut parsed: Vec<(&str, &str)> = Vec::with_capacity(lines.len());
        for line in lines {
            if line.contains('\r') || line.contains('\n') || line.starts_with(' ') || line.starts_with('\t') {
                return Err(ProxyError::BadResponse); // response splitting / obs-fold
            }
            let (name, value) = line.split_once(':').ok_or(ProxyError::BadResponse)?;
            if name.is_empty() || name.bytes().any(|b| b == b' ' || b == b'\t') {
                return Err(ProxyError::BadResponse);
            }
            let value = value.trim_matches(|c: char| c == ' ' || c == '\t');
            if name.eq_ignore_ascii_case("connection") {
                named.extend(value.split(',').map(|t| t.trim().to_ascii_lowercase()));
            }
            parsed.push((name, value));
        }

        let mut chunked = false;
        let mut content_length: Option<usize> = None;
        let mut headers = Vec::with_capacity(parsed.len());
        for (name, value) in parsed {
            let lname = name.to_ascii_lowercase();
            if lname == "transfer-encoding" {
                // Only plain chunked is understood; anything else cannot be
                // re-framed correctly, so refuse it rather than corrupt the body.
                if !value.eq_ignore_ascii_case("chunked") {
                    return Err(ProxyError::BadResponse);
                }
                chunked = true;
                continue;
            }
            if lname == "content-length" {
                if value.is_empty() || value.len() > 15 || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(ProxyError::BadResponse);
                }
                let n = value.parse::<usize>().map_err(|_| ProxyError::BadResponse)?;
                if content_length.is_some_and(|prev| prev != n) {
                    return Err(ProxyError::BadResponse); // conflicting lengths
                }
                content_length = Some(n);
                continue;
            }
            if HOP_BY_HOP.contains(&lname.as_str()) || named.contains(&lname) {
                continue;
            }
            headers.push((name, value));
        }

        let body_kind = if head_only || code == 204 || code == 304 {
            Body::None
        } else if chunked {
            Body::Chunked
        } else if let Some(cl) = content_length {
            Body::Length(cl)
        } else {
            Body::ToEof
        };
        return Ok(Some(Head {
            code,
            reason,
            headers,
            content_length,
            body_kind,
            body,
        }));
    }
}

/// Reads the upstream response into memory, bounded by MAX_RESPONSE and a total
/// deadline. Stops as soon as the response is complete by its own framing, so a
/// backend that keeps the connection open is not waited on until the timeout.
fn read_response(stream: &mut TcpStream, head_only: bool) -> Result<Vec<u8>, ProxyError> {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    // (where the body starts in `buf`, how it is delimited), once the head is in
    let mut framing: Option<(usize, Body)> = None;
    loop {
        let left = match deadline.checked_duration_since(Instant::now()) {
            Some(d) if !d.is_zero() => d,
            _ => return Err(ProxyError::Timeout),
        };
        stream.set_read_timeout(Some(left)).map_err(|_| ProxyError::Connect)?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() + n > MAX_RESPONSE {
                    return Err(ProxyError::TooLarge);
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) => match e.kind() {
                ErrorKind::Interrupted => continue,
                ErrorKind::WouldBlock | ErrorKind::TimedOut => return Err(ProxyError::Timeout),
                _ => return Err(ProxyError::Connect),
            },
        }
        if framing.is_none() {
            framing = match parse_head(&buf, head_only) {
                Ok(Some(h)) => Some((buf.len() - h.body.len(), h.body_kind)),
                Ok(None) => None,
                Err(_) => break, // frame_response reports it
            };
        }
        let done = match framing {
            Some((_, Body::None)) => true,
            Some((start, Body::Length(cl))) => buf.len() - start >= cl,
            // The usual last chunk with no trailers; anything else ends at EOF.
            Some((start, Body::Chunked)) => buf.len() - start >= 5 && buf.ends_with(b"0\r\n\r\n"),
            Some((_, Body::ToEof)) | None => false,
        };
        if done {
            break;
        }
    }
    if buf.is_empty() {
        return Err(ProxyError::BadResponse);
    }
    Ok(buf)
}

/// Request headers never forwarded besides the hop-by-hop ones: the length is
/// recomputed, and the gate already holds the whole body, so `Expect:
/// 100-continue` must not reach the backend (its interim 100 would be wasted).
const DROP_REQUEST: &[&str] = &["content-length", "expect"];

/// Builds the request line + headers + body to send to the upstream.
fn build_request(req: &Request, pass_cookie: &str) -> Vec<u8> {
    // Headers named in the client's `Connection` header are hop-by-hop too.
    let named: Vec<String> = req
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(',').map(|t| t.trim().to_ascii_lowercase()))
        .collect();
    let mut head = format!("{} {} HTTP/1.1\r\n", req.method, req.target);
    let mut has_host = false;
    for (name, value) in &req.headers {
        let lname = name.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lname.as_str()) || DROP_REQUEST.contains(&lname.as_str()) || named.contains(&lname) {
            continue;
        }
        if lname == "host" {
            has_host = true;
        }
        if lname == "cookie" {
            // Only the pass cookie present -> drop the header entirely.
            if let Some(v) = http::cookie_without(value, pass_cookie) {
                head.push_str("Cookie: ");
                head.push_str(&v);
                head.push_str("\r\n");
            }
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    // HTTP/1.1 requires a Host header; Tor Browser always sends one, but be safe.
    if !has_host {
        head.push_str("Host: localhost\r\n");
    }
    // Recompute framing: our own Content-Length (only when there is a body) and
    // a forced close.
    if !req.body.is_empty() {
        head.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
    }
    head.push_str("Connection: close\r\n\r\n");

    let mut out = head.into_bytes();
    out.extend_from_slice(&req.body);
    out
}

/// Parses the upstream response and re-frames it for the visitor: hop-by-hop
/// headers dropped, body de-chunked if needed, `Content-Length` and
/// `Connection: close` set by us. `head_only` (a HEAD request) keeps the
/// upstream's Content-Length and sends no body.
fn frame_response(raw: &[u8], head_only: bool) -> Result<Vec<u8>, ProxyError> {
    let h = parse_head(raw, head_only)?.ok_or(ProxyError::BadResponse)?;
    let body: Vec<u8> = match h.body_kind {
        Body::None => Vec::new(),
        Body::Chunked => dechunk(h.body)?,
        Body::Length(cl) => {
            if cl > h.body.len() {
                return Err(ProxyError::BadResponse); // promised more than it sent
            }
            h.body[..cl].to_vec()
        }
        Body::ToEof => h.body.to_vec(),
    };

    let reason = if h.reason.is_empty() { http::reason(h.code) } else { h.reason };
    let mut out = format!("HTTP/1.1 {} {}\r\n", h.code, reason);
    for (name, value) in &h.headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    match h.body_kind {
        // HEAD: the length of the entity a GET would return, as the upstream said.
        Body::None if head_only => {
            if let Some(cl) = h.content_length {
                out.push_str(&format!("Content-Length: {}\r\n", cl));
            }
        }
        Body::None => {} // 204 / 304: no body and no length
        _ => out.push_str(&format!("Content-Length: {}\r\n", body.len())),
    }
    out.push_str("Connection: close\r\n\r\n");

    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

/// `HTTP/1.1 200 OK` -> 200.
fn parse_status(line: &str) -> Option<u16> {
    let mut it = line.split(' ');
    let v = it.next()?;
    if v != "HTTP/1.1" && v != "HTTP/1.0" {
        return None;
    }
    let code = it.next()?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    code.parse::<u16>().ok()
}

/// Decodes a chunked body. Bounded by MAX_RESPONSE. Ignores trailers.
fn dechunk(data: &[u8]) -> Result<Vec<u8>, ProxyError> {
    let mut out = Vec::new();
    let mut i = 0usize;
    loop {
        // chunk-size line
        let nl = data
            .get(i..)
            .and_then(|d| d.windows(2).position(|w| w == b"\r\n"))
            .ok_or(ProxyError::BadResponse)?;
        let size_line = std::str::from_utf8(&data[i..i + nl]).map_err(|_| ProxyError::BadResponse)?;
        // a chunk extension (";...") may follow the size; ignore it
        let hex = size_line.split(';').next().unwrap_or("").trim();
        if hex.is_empty() || hex.len() > 15 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ProxyError::BadResponse);
        }
        let size = usize::from_str_radix(hex, 16).map_err(|_| ProxyError::BadResponse)?;
        i += nl + 2;
        if size == 0 {
            break; // last chunk; trailers (if any) are ignored
        }
        if size > MAX_RESPONSE || out.len() + size > MAX_RESPONSE {
            return Err(ProxyError::TooLarge);
        }
        let end = i.checked_add(size).ok_or(ProxyError::BadResponse)?;
        if end > data.len() {
            return Err(ProxyError::BadResponse);
        }
        out.extend_from_slice(&data[i..end]);
        i = end;
        // each chunk's data is followed by CRLF
        if data.get(i..i + 2) != Some(b"\r\n") {
            return Err(ProxyError::BadResponse);
        }
        i += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, headers: Vec<(&str, &str)>, body: &[u8]) -> Request {
        Request {
            method: method.to_string(),
            target: "/p?q=1".to_string(),
            path: "/p".to_string(),
            headers: headers.into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(),
            cookie: None,
            body: body.to_vec(),
        }
    }

    #[test]
    fn non_loopback_upstream_is_refused() {
        assert!(Upstream::new("127.0.0.1:8080", "pass").is_ok());
        assert!(Upstream::new("localhost:8080", "pass").is_ok());
        assert!(Upstream::new("8.8.8.8:80", "pass").is_err());
        assert!(Upstream::new("not a host:port", "pass").is_err());
    }

    #[test]
    fn request_drops_hop_by_hop_and_pass_cookie() {
        let r = req(
            "GET",
            vec![
                ("Host", "site.onion"),
                ("Connection", "keep-alive"),
                ("Cookie", "onion_gate_pass=secret; sid=keep"),
                ("Accept", "text/html"),
            ],
            b"",
        );
        let wire = String::from_utf8(build_request(&r, "onion_gate_pass")).unwrap();
        assert!(wire.starts_with("GET /p?q=1 HTTP/1.1\r\n"));
        assert!(wire.contains("Host: site.onion\r\n"));
        assert!(wire.contains("Accept: text/html\r\n"));
        assert!(wire.contains("Cookie: sid=keep\r\n"), "pass cookie must be stripped, others kept");
        assert!(!wire.to_lowercase().contains("keep-alive"));
        assert!(!wire.to_lowercase().contains("onion_gate_pass"));
        assert!(wire.contains("Connection: close\r\n"));
        // no client identity leaked to the backend
        assert!(!wire.to_lowercase().contains("x-forwarded"));
    }

    #[test]
    fn request_drops_cookie_header_when_only_pass() {
        let r = req("GET", vec![("Cookie", "onion_gate_pass=secret")], b"");
        let wire = String::from_utf8(build_request(&r, "onion_gate_pass")).unwrap();
        assert!(!wire.to_lowercase().contains("cookie:"), "no cookie header should remain");
    }

    #[test]
    fn request_sets_content_length_for_a_body() {
        let r = req("POST", vec![("Host", "x")], b"hello");
        let wire = String::from_utf8(build_request(&r, "p")).unwrap();
        assert!(wire.contains("Content-Length: 5\r\n"));
        assert!(wire.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn request_without_host_gets_one() {
        let r = req("GET", vec![("Accept", "*/*")], b"");
        let wire = String::from_utf8(build_request(&r, "p")).unwrap();
        assert!(wire.contains("Host: localhost\r\n"));
    }

    #[test]
    fn response_with_content_length_is_reframed() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello";
        let out = String::from_utf8(frame_response(raw, false).unwrap()).unwrap();
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(out.contains("Content-Type: text/plain\r\n"));
        assert!(out.contains("Content-Length: 5\r\n"));
        assert!(out.contains("Connection: close\r\n"));
        assert!(!out.to_lowercase().contains("keep-alive"));
        assert!(out.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn response_chunked_is_dechunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let out = String::from_utf8(frame_response(raw, false).unwrap()).unwrap();
        assert!(out.contains("Content-Length: 11\r\n"));
        assert!(!out.to_lowercase().contains("transfer-encoding"));
        assert!(out.ends_with("\r\n\r\nhello world"));
    }

    #[test]
    fn response_read_to_eof_when_no_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody bytes to eof";
        let out = String::from_utf8(frame_response(raw, false).unwrap()).unwrap();
        assert!(out.contains("Content-Length: 17\r\n"));
        assert!(out.ends_with("\r\n\r\nbody bytes to eof"));
    }

    #[test]
    fn head_response_keeps_length_and_has_no_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n";
        let out = String::from_utf8(frame_response(raw, true).unwrap()).unwrap();
        assert!(out.contains("Content-Length: 1234\r\n"), "HEAD keeps the upstream length");
        assert!(out.ends_with("\r\n\r\n"));
    }

    #[test]
    fn dechunk_rejects_garbage() {
        assert!(dechunk(b"zzzz\r\n").is_err());
        assert!(dechunk(b"5\r\nhi\r\n").is_err()); // size says 5, only 2 present
    }

    #[test]
    fn malformed_response_is_bad_gateway() {
        assert!(matches!(frame_response(b"not http at all\r\n\r\n", false), Err(ProxyError::BadResponse)));
        assert!(matches!(frame_response(b"", false), Err(ProxyError::BadResponse)));
    }

    #[test]
    fn interim_100_continue_is_skipped() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok";
        let out = String::from_utf8(frame_response(raw, false).unwrap()).unwrap();
        assert!(out.starts_with("HTTP/1.1 201 Created\r\n"), "{}", out);
        assert!(out.ends_with("\r\n\r\nok"));
    }

    #[test]
    fn switching_protocols_is_refused() {
        assert!(matches!(frame_response(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n", false), Err(ProxyError::BadResponse)));
    }

    #[test]
    fn no_content_and_not_modified_carry_no_length() {
        for code in ["204 No Content", "304 Not Modified"] {
            let raw = format!("HTTP/1.1 {}\r\nETag: \"x\"\r\n\r\n", code);
            let out = String::from_utf8(frame_response(raw.as_bytes(), false).unwrap()).unwrap();
            assert!(!out.to_lowercase().contains("content-length"), "{}", out);
            assert!(out.contains("ETag: \"x\"\r\n") && out.ends_with("\r\n\r\n"));
        }
    }

    #[test]
    fn response_header_smuggling_and_bad_framing_are_refused() {
        let bad: &[&[u8]] = &[
            b"HTTP/1.1 200 OK\r\nX: a\nSet-Cookie: evil=1\r\nContent-Length: 0\r\n\r\n", // lone LF
            b"HTTP/1.1 200 OK\r\n folded: x\r\n\r\n",                                     // obs-fold
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nabc",      // conflict
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",                              // not digits
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",       // not plain chunked
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",                         // truncated
            b"HTTP/1.1 2000 OK\r\n\r\n",                                                    // bad status
        ];
        for raw in bad {
            assert!(frame_response(raw, false).is_err(), "accepted {:?}", String::from_utf8_lossy(raw));
        }
    }

    #[test]
    fn headers_named_in_connection_are_dropped_both_ways() {
        let raw = b"HTTP/1.1 200 OK\r\nConnection: close, X-Hop\r\nX-Hop: 1\r\nX-Keep: 2\r\nContent-Length: 0\r\n\r\n";
        let out = String::from_utf8(frame_response(raw, false).unwrap()).unwrap();
        assert!(!out.contains("X-Hop") && out.contains("X-Keep: 2\r\n"));
        let r = req("GET", vec![("Connection", "X-Secret"), ("X-Secret", "1"), ("Host", "h")], b"");
        let wire = String::from_utf8(build_request(&r, "p")).unwrap();
        assert!(!wire.contains("X-Secret"));
    }

    #[test]
    fn expect_is_not_forwarded() {
        let r = req("POST", vec![("Host", "h"), ("Expect", "100-continue")], b"abc");
        let wire = String::from_utf8(build_request(&r, "p")).unwrap();
        assert!(!wire.to_lowercase().contains("expect"));
    }

    #[test]
    fn dechunk_huge_size_is_an_error_not_a_panic() {
        assert!(dechunk(b"ffffffffffffffff\r\nx\r\n0\r\n\r\n").is_err());
        assert!(dechunk(b"fffffffffffffff\r\nx\r\n0\r\n\r\n").is_err());
        assert!(dechunk(b"+5\r\nhello\r\n0\r\n\r\n").is_err(), "no sign allowed");
    }
}
