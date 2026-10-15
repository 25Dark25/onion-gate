//! The reverse proxy: once a visitor holds a valid pass, their request is
//! forwarded to a local backend and the backend's response is relayed back.
//!
//! Design (deliberately strict, std only):
//!  - One upstream connection per request, `Connection: close` both ways. No
//!    keep-alive, no pooling, no pipelining.
//!  - The request is forwarded verbatim (method, target, headers, body) EXCEPT:
//!    hop-by-hop headers are dropped, the gate's own pass cookie is stripped
//!    from the `Cookie` header, client-supplied forwarding headers
//!    (`X-Forwarded-*`, `Forwarded`, `X-Real-IP`, …) and `Proxy` are dropped,
//!    `Content-Length` is recomputed, and `Connection: close` is forced.
//!    Nothing about the visitor is added — no `X-Forwarded-For`, no client
//!    address — so the backend learns nothing the gate did not already strip.
//!  - The upstream must be a loopback address (checked at startup): the gate is
//!    meant to sit in front of a backend on the same host.
//!  - The whole request and response bodies are buffered in memory, each capped
//!    (`max_body` and `MAX_RESPONSE`). This rules out streaming and very large
//!    transfers by design; see the README.
//!  - A chunked upstream response is de-chunked; otherwise `Content-Length` or
//!    read-to-EOF frames the body.

use crate::http::{self, Request};
use crate::limit::{Memory, Reservation};
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
    /// The global buffer budget (`limit::MAX_BUFFERED`) is spent.
    Busy,
}

impl ProxyError {
    /// The status the gate returns to the visitor when forwarding fails.
    pub fn status(&self) -> u16 {
        match self {
            ProxyError::Connect | ProxyError::BadResponse => 502,
            ProxyError::Timeout => 504,
            ProxyError::TooLarge => 502,
            ProxyError::Busy => 503,
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

    /// Every address `--upstream` resolved to.
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// Forwards one request and returns the response, already framed as bytes
    /// ready to write to the visitor's connection, together with its share of
    /// the memory budget (hold it until the bytes are sent).
    pub fn forward<'m>(&self, req: &Request, mem: &'m Memory) -> Result<(Vec<u8>, Reservation<'m>), ProxyError> {
        let mut held = mem.reserve(0).ok_or(ProxyError::Busy)?;
        let wire = build_request(req, self.pass_cookie);
        // `localhost` may resolve to ::1 and 127.0.0.1; use the first that answers.
        let mut stream = self
            .addrs
            .iter()
            .find_map(|a| TcpStream::connect_timeout(a, CONNECT_TIMEOUT).ok())
            .ok_or(ProxyError::Connect)?;
        stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(|_| ProxyError::Connect)?;
        // No half-close: some servers read an early FIN as "client gave up".
        // `Connection: close` and an exact Content-Length frame the request.
        let sent = stream.write_all(&wire).and_then(|_| stream.flush()).is_ok();
        drop(wire);

        // Even if the write failed, the backend may have answered before closing
        // (e.g. a 413 for a body it did not want): relay that if it is there.
        let head_only = req.method == "HEAD";
        let raw = match read_response(&mut stream, head_only, &mut held) {
            Ok(raw) => raw,
            Err(_) if !sent => return Err(ProxyError::Connect),
            Err(e) => return Err(e),
        };
        let framed = frame_response(&raw, head_only)?;
        drop(raw);
        // The re-framed reply of a tiny response can exceed the 2x reserved
        // (our own Content-Length and Connection headers): charge the rest.
        if framed.len() > held.bytes() && !held.grow(framed.len() - held.bytes()) {
            return Err(ProxyError::Busy);
        }
        held.shrink_to(framed.len());
        Ok((framed, held))
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
        // The reason phrase is relayed to the visitor: a lone CR/LF in it would
        // split the response (inject headers), so the whole line must be clean.
        if !http::is_field_text(status_line) {
            return Err(ProxyError::BadResponse);
        }
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
            // A lone CR/LF or a control byte (response splitting), or obs-fold.
            if !http::is_field_text(line) || line.starts_with(' ') || line.starts_with('\t') {
                return Err(ProxyError::BadResponse);
            }
            let (name, value) = line.split_once(':').ok_or(ProxyError::BadResponse)?;
            if !http::is_token(name) {
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
                // Chunked twice (or in two headers) is invalid too.
                if !value.eq_ignore_ascii_case("chunked") || chunked {
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

/// Reads the upstream response into memory, bounded by MAX_RESPONSE, the
/// global memory budget and a total deadline. Stops as soon as the response is
/// complete by its own framing, so a backend that keeps the connection open is
/// not waited on until the timeout.
fn read_response(stream: &mut TcpStream, head_only: bool, held: &mut Reservation<'_>) -> Result<Vec<u8>, ProxyError> {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    // (where the body starts in `buf`, how it is delimited), once the head is in
    let mut framing: Option<(usize, Body)> = None;
    // Chunked bodies: offset (within the body) of the next chunk not yet seen
    // whole, so each read resumes the walk instead of starting over.
    let mut chunk_pos = 0usize;
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
                // Twice: these bytes, and their copy in the re-framed response.
                if !held.grow(2 * n) {
                    return Err(ProxyError::Busy);
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
            // Walk the chunk structure: chunk data that merely ends in
            // "0\r\n\r\n" must not be taken for the last chunk. Malformed
            // framing stops reading; frame_response reports it.
            Some((start, Body::Chunked)) => match walk_chunks(&buf[start..], &mut chunk_pos, |_| {}) {
                Walk::More => false,
                Walk::Done | Walk::Bad => true,
            },
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
///
/// The rest claim to describe the client or an earlier proxy. The gate is the
/// first hop and connects from loopback, so a backend that trusts them from a
/// local proxy would believe whatever the visitor wrote in them (an address
/// allowlist or a per-IP limit fooled). `proxy` is httpoxy: CGI turns it into
/// the HTTP_PROXY variable. Any header starting with `x-forwarded-` goes too.
const DROP_REQUEST: &[&str] = &[
    "content-length",
    "expect",
    "forwarded",
    "x-real-ip",
    "x-client-ip",
    "true-client-ip",
    "x-cluster-client-ip",
    "x-originating-ip",
    "client-ip",
    "cf-connecting-ip",
    "fastly-client-ip",
    "proxy",
];

/// Lowercase, with `_` read as `-`: CGI, PHP and others map both to the same
/// variable, so `X_Forwarded_For` must be dropped like `X-Forwarded-For`.
fn normalized(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

fn dropped_request_header(lname: &str) -> bool {
    HOP_BY_HOP.contains(&lname) || DROP_REQUEST.contains(&lname) || lname.starts_with("x-forwarded-")
}

/// Builds the request line + headers + body to send to the upstream.
fn build_request(req: &Request, pass_cookie: &str) -> Vec<u8> {
    // Headers named in the client's `Connection` header are hop-by-hop too.
    let named: Vec<String> = req
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(',').map(|t| normalized(t.trim())))
        .collect();
    let mut head = format!("{} {} HTTP/1.1\r\n", req.method, req.target);
    let mut has_host = false;
    for (name, value) in &req.headers {
        let lname = normalized(name);
        if dropped_request_header(&lname) || named.contains(&lname) {
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
    // Only an HTTP/1.0 request can arrive without Host (http.rs refuses it for
    // 1.1); it is forwarded as HTTP/1.1, which needs one.
    if !has_host {
        head.push_str("Host: localhost\r\n");
    }
    // Recompute framing: our own Content-Length (when there is a body, and
    // always for the methods that normally carry one: some servers answer a
    // POST without it with 411) and a forced close.
    if !req.body.is_empty() || matches!(req.method.as_str(), "POST" | "PUT" | "PATCH") {
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
    // The body's length, found without copying it (the copy is made once,
    // straight into the output).
    let body_len = match h.body_kind {
        Body::None => 0,
        Body::Chunked => {
            let mut len = 0usize;
            match walk_chunks(h.body, &mut 0, |c| len += c.len()) {
                Walk::Done => len,
                Walk::More | Walk::Bad => return Err(ProxyError::BadResponse), // truncated or malformed
            }
        }
        Body::Length(cl) => {
            if cl > h.body.len() {
                return Err(ProxyError::BadResponse); // promised more than it sent
            }
            cl
        }
        Body::ToEof => h.body.len(),
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
        _ => out.push_str(&format!("Content-Length: {}\r\n", body_len)),
    }
    out.push_str("Connection: close\r\n\r\n");

    let mut bytes = Vec::with_capacity(out.len() + body_len);
    bytes.extend_from_slice(out.as_bytes());
    match h.body_kind {
        Body::None => {}
        Body::Chunked => {
            walk_chunks(h.body, &mut 0, |c| bytes.extend_from_slice(c));
        }
        Body::Length(_) | Body::ToEof => bytes.extend_from_slice(&h.body[..body_len]),
    }
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

/// Longest chunk-size line (size plus any extension) and longest trailer
/// section accepted. Both are tiny in practice; the caps keep a re-scan cheap.
const MAX_CHUNK_LINE: usize = 4096;
const MAX_TRAILERS: usize = 16 * 1024;

/// Outcome of walking a chunked body.
#[derive(Debug, PartialEq, Eq)]
enum Walk {
    /// The last chunk and the trailer section (if any) are complete.
    Done,
    /// The data stops before the body is complete.
    More,
    /// Not valid chunked framing.
    Bad,
}

/// Offset of the first CRLF in `data` at or after `from`, relative to `from`.
fn find_crlf(data: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?.windows(2).position(|w| w == b"\r\n")
}

/// The size in a chunk-size line (`1a`, `1a;ext=1`). Strict hex, no sign.
fn chunk_size(line: &[u8]) -> Option<usize> {
    let line = std::str::from_utf8(line).ok()?;
    let hex = line.split(';').next().unwrap_or("").trim_matches(|c| c == ' ' || c == '\t');
    if hex.is_empty() || hex.len() > 15 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    usize::from_str_radix(hex, 16).ok()
}

/// Walks a chunked body, calling `each` with the data of every complete chunk.
/// `pos` is where the next chunk-size line starts; it advances past each
/// complete chunk, so a caller that gets `More` can call again with more data
/// and the same `pos` (linear overall). Trailers are checked for their end and
/// otherwise ignored.
fn walk_chunks(data: &[u8], pos: &mut usize, mut each: impl FnMut(&[u8])) -> Walk {
    loop {
        let nl = match find_crlf(data, *pos) {
            Some(nl) if nl <= MAX_CHUNK_LINE => nl,
            Some(_) => return Walk::Bad,
            // A line of MAX_CHUNK_LINE bytes may still be waiting for its CRLF.
            None if data.len() - (*pos).min(data.len()) > MAX_CHUNK_LINE + 1 => return Walk::Bad,
            None => return Walk::More,
        };
        let size = match chunk_size(&data[*pos..*pos + nl]) {
            Some(n) => n,
            None => return Walk::Bad,
        };
        let start = *pos + nl + 2;
        if size == 0 {
            // Trailer section: header lines up to an empty line.
            let mut t = start;
            loop {
                if t - start > MAX_TRAILERS {
                    return Walk::Bad;
                }
                match find_crlf(data, t) {
                    // One endless trailer line must hit the cap too.
                    None if data.len() - t > MAX_TRAILERS => return Walk::Bad,
                    None => return Walk::More,
                    Some(0) => return Walk::Done,
                    Some(n) => t += n + 2,
                }
            }
        }
        let after = match start.checked_add(size).and_then(|end| end.checked_add(2)) {
            Some(a) => a,
            None => return Walk::Bad,
        };
        if after > data.len() {
            return Walk::More;
        }
        if &data[after - 2..after] != b"\r\n" {
            return Walk::Bad; // each chunk's data is followed by CRLF
        }
        each(&data[start..after - 2]);
        *pos = after;
    }
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

    fn walk(data: &[u8]) -> (Walk, Vec<u8>) {
        let mut out = Vec::new();
        let w = walk_chunks(data, &mut 0, |c| out.extend_from_slice(c));
        (w, out)
    }

    #[test]
    fn walk_chunks_decodes_and_detects_the_end() {
        assert_eq!(walk(b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n"), (Walk::Done, b"hello world".to_vec()));
        assert_eq!(walk(b"2\r\nok\r\n0\r\nA: 1\r\nB: 2\r\n\r\n").0, Walk::Done, "trailers");
        // incomplete at every possible cut: never Done, never Bad
        let full = b"3\r\nabc\r\n0\r\nT: 1\r\n\r\n";
        for cut in 0..full.len() {
            assert_eq!(walk(&full[..cut]).0, Walk::More, "cut at {}", cut);
        }
        // resuming from `pos` gives the same result as one pass
        let mut pos = 0;
        let mut out = Vec::new();
        assert_eq!(walk_chunks(&full[..9], &mut pos, |c| out.extend_from_slice(c)), Walk::More);
        assert_eq!(walk_chunks(full, &mut pos, |c| out.extend_from_slice(c)), Walk::Done);
        assert_eq!(out, b"abc");
    }

    #[test]
    fn walk_chunks_rejects_garbage() {
        assert_eq!(walk(b"zzzz\r\n").0, Walk::Bad);
        assert_eq!(walk(b"2\r\nhiX\r\n0\r\n\r\n").0, Walk::Bad, "data not followed by CRLF");
        assert_eq!(walk(&[b'1'; MAX_CHUNK_LINE + 10]).0, Walk::Bad, "endless size line");
        // a size line of exactly MAX_CHUNK_LINE bytes is fine whether or not its
        // CRLF has fully arrived yet
        let mut line = vec![b'0'; MAX_CHUNK_LINE - 1];
        line.push(b'1');
        assert_eq!(walk(&line).0, Walk::More);
        line.push(b'\r');
        assert_eq!(walk(&line).0, Walk::More);
        // an endless trailer line is refused, not rescanned forever
        let mut t = b"0\r\n".to_vec();
        t.extend(vec![b'a'; MAX_TRAILERS + 10]);
        assert_eq!(walk(&t).0, Walk::Bad);
        // a truncated response is refused when framed
        assert!(frame_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhi", false).is_err());
        assert!(frame_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", false).is_err(), "chunked twice");
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
            b"HTTP/1.1 200 OK\nSet-Cookie: evil=1\r\nContent-Length: 0\r\n\r\n",     // lone LF in the status line
            b"HTTP/1.1 200 OK\rSet-Cookie: evil=1\r\nContent-Length: 0\r\n\r\n",     // lone CR in the status line
            b"HTTP/1.1 200 O\x00K\r\nContent-Length: 0\r\n\r\n",                    // control byte in the reason
            b"HTTP/1.1 200 OK\r\nX: a\x00b\r\nContent-Length: 0\r\n\r\n",          // control byte in a value
            b"HTTP/1.1 200 OK\r\nX(y): 1\r\nContent-Length: 0\r\n\r\n",            // not a token name
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
    fn client_supplied_forwarding_headers_are_not_forwarded() {
        // The gate connects from loopback, so a backend that trusts these from a
        // local proxy would believe whatever the visitor wrote in them.
        let r = req(
            "GET",
            vec![
                ("Host", "h"),
                ("X-Forwarded-For", "10.0.0.1"),
                ("x_forwarded_for", "10.0.0.2"), // CGI/PHP read _ as -
                ("X-Forwarded-Proto", "https"),
                ("Forwarded", "for=10.0.0.3"),
                ("X-Real-IP", "10.0.0.4"),
                ("True-Client-IP", "10.0.0.5"),
                ("Proxy", "http://evil:1"), // httpoxy: becomes HTTP_PROXY in CGI
                ("X-Other", "kept"),
            ],
            b"",
        );
        let wire = String::from_utf8(build_request(&r, "p")).unwrap();
        assert!(!wire.contains("10.0.0.") && !wire.contains("evil") && !wire.contains("https"), "{}", wire);
        assert!(wire.contains("X-Other: kept\r\n"));
    }

    #[test]
    fn an_empty_post_still_says_content_length_0() {
        let wire = String::from_utf8(build_request(&req("POST", vec![("Host", "h")], b""), "p")).unwrap();
        assert!(wire.contains("Content-Length: 0\r\n"), "{}", wire);
        let wire = String::from_utf8(build_request(&req("GET", vec![("Host", "h")], b""), "p")).unwrap();
        assert!(!wire.contains("Content-Length"), "{}", wire);
    }

    #[test]
    fn expect_is_not_forwarded() {
        let r = req("POST", vec![("Host", "h"), ("Expect", "100-continue")], b"abc");
        let wire = String::from_utf8(build_request(&r, "p")).unwrap();
        assert!(!wire.to_lowercase().contains("expect"));
    }

    /// A one-shot backend on loopback: writes `parts` with a pause between
    /// them, then keeps the connection open (it ignores `Connection: close`).
    fn scripted_backend(parts: Vec<Vec<u8>>) -> Upstream {
        use std::net::{Ipv4Addr, TcpListener};
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let mut sink = [0u8; 4096];
                let _ = s.read(&mut sink);
                for p in parts {
                    let _ = s.write_all(&p);
                    std::thread::sleep(Duration::from_millis(150));
                }
                std::thread::sleep(Duration::from_secs(20));
            }
        });
        Upstream::new(&addr, "p").unwrap()
    }

    fn get() -> Request {
        req("GET", vec![("Host", "h")], b"")
    }

    fn fwd(up: &Upstream) -> Result<Vec<u8>, ProxyError> {
        let mem = Memory::default();
        let out = up.forward(&get(), &mem).map(|(bytes, _held)| bytes);
        assert_eq!(mem.used(), 0, "the budget must be given back");
        out
    }

    #[test]
    fn a_response_over_the_memory_budget_is_busy_not_buffered() {
        let up = scripted_backend(vec![b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n".to_vec(), vec![b'x'; 1000]]);
        let mem = Memory::new(500);
        assert!(matches!(up.forward(&get(), &mem), Err(ProxyError::Busy)));
        assert_eq!(mem.used(), 0);
        // within budget, the reservation is the framed size, held by the caller
        let up = scripted_backend(vec![b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()]);
        let mem = Memory::new(10_000);
        let (bytes, held) = up.forward(&get(), &mem).unwrap();
        assert_eq!(mem.used(), bytes.len());
        drop(held);
        assert_eq!(mem.used(), 0);
    }

    /// The backend answers 413, half-closes and drains the rest: its answer
    /// arrives before the gate has finished sending the body.
    #[test]
    fn an_answer_sent_before_the_body_was_read_is_relayed() {
        use std::net::{Ipv4Addr, TcpListener};
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let mut buf = [0u8; 64 * 1024];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n");
                let _ = s.shutdown(std::net::Shutdown::Write);
                while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
            }
        });
        let up = Upstream::new(&addr, "p").unwrap();
        let big = req("POST", vec![("Host", "h")], &vec![b'x'; 1024 * 1024]);
        let mem = Memory::default();
        let (bytes, _held) = up.forward(&big, &mem).expect("the 413 is relayed");
        assert!(String::from_utf8_lossy(&bytes).starts_with("HTTP/1.1 413"));
    }

    /// Same, but the backend closes without reading the body, so the gate's
    /// write fails with a reset. Linux keeps the bytes received before the
    /// reset readable; other systems may discard them, hence Linux only.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_early_answer_is_relayed_even_if_the_backend_stopped_reading() {
        // The backend answers 413 and closes without reading a large body.
        use std::net::{Ipv4Addr, TcpListener};
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let mut head = [0u8; 256];
                let _ = s.read(&mut head);
                let _ = s.write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n");
            }
        });
        let up = Upstream::new(&addr, "p").unwrap();
        let big = req("POST", vec![("Host", "h")], &vec![b'x'; 8 * 1024 * 1024]);
        let mem = Memory::default();
        let (bytes, _held) = up.forward(&big, &mem).expect("the 413 is relayed, not a 502");
        assert!(String::from_utf8_lossy(&bytes).starts_with("HTTP/1.1 413"));
    }

    #[test]
    fn chunk_data_that_looks_like_the_last_chunk_does_not_end_the_read() {
        // The first chunk's data ends in "0\r\n" and is followed by its CRLF, so
        // the bytes read so far end in "0\r\n\r\n" although the body is not over.
        let up = scripted_backend(vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\nabc,0\r\n\r\n".to_vec(),
            b"3\r\nxyz\r\n0\r\n\r\n".to_vec(),
        ]);
        let t0 = Instant::now();
        let out = String::from_utf8(fwd(&up).expect("complete response")).unwrap();
        assert!(out.ends_with("\r\n\r\nabc,0\r\nxyz"), "{:?}", out);
        assert!(t0.elapsed() < Duration::from_secs(5), "took {:?}", t0.elapsed());
    }

    #[test]
    fn chunked_body_with_trailers_ends_without_waiting_for_eof() {
        let up = scripted_backend(vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-Trailer: 1\r\n\r\n".to_vec(),
        ]);
        let t0 = Instant::now();
        let out = String::from_utf8(fwd(&up).expect("complete response")).unwrap();
        assert!(out.ends_with("Content-Length: 2\r\nConnection: close\r\n\r\nok"), "{:?}", out);
        assert!(t0.elapsed() < Duration::from_secs(5), "took {:?}", t0.elapsed());
    }

    #[test]
    fn huge_chunk_size_is_an_error_not_a_panic() {
        assert_eq!(walk(b"ffffffffffffffff\r\nx\r\n0\r\n\r\n").0, Walk::Bad);
        assert_eq!(walk(b"fffffffffffffff\r\nx\r\n0\r\n\r\n").0, Walk::More, "needs more data, no overflow");
        assert_eq!(walk(b"+5\r\nhello\r\n0\r\n\r\n").0, Walk::Bad, "no sign allowed");
    }
}
