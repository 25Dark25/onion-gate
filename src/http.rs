//! Minimal, strict HTTP/1.1 using only std.
//!
//! Security decisions:
//!  - ONE request per connection and always `Connection: close`: no keep-alive
//!    and no pipelining, so request smuggling is impossible.
//!  - `Transfer-Encoding` (chunked) in a request is rejected; a duplicate or
//!    non-numeric `Content-Length` is rejected.
//!  - Hard limits: 16 KiB head, a configurable body cap, an 8 s deadline for
//!    the head (anti-slowloris) and 60 s more for a body, a 2 KiB target.
//!  - Control bytes, non-ASCII, stray CR/LF, "obs-fold", a header name that
//!    is not a token, a tab in the target, and a missing (HTTP/1.1) or
//!    repeated `Host` => 400.
//!  - Nothing about requests is logged (no access logs).
//!
//! The request is parsed once. The gate reads `method`/`path` to decide what to
//! do; when it forwards, `upstream.rs` reuses `method`, `target`, `headers` and
//! `body` verbatim (minus hop-by-hop headers and the gate's own pass cookie).

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, TcpStream};
use std::time::{Duration, Instant};

const MAX_HEAD: usize = 16 * 1024;
/// Default body cap. The binary overrides it from `--max-body`.
pub const DEFAULT_MAX_BODY: usize = 1024 * 1024;
const MAX_TARGET: usize = 2048;
/// Deadline for the request line and headers (anti-slowloris).
const READ_DEADLINE: Duration = Duration::from_secs(8);
/// Extra time to receive a body once the head is in: a 1 MiB upload over Tor
/// can take tens of seconds. Slow senders still hold at most
/// `MAX_CONN_PER_CIRCUIT` connections per circuit.
const BODY_DEADLINE: Duration = Duration::from_secs(60);
/// Tor writes the PROXY line as soon as it opens the connection: no need to wait.
const PROXY_DEADLINE: Duration = Duration::from_secs(2);
/// Maximum length of a PROXY v1 line per its specification (CRLF included).
const MAX_PROXY_LINE: usize = 107;
/// Longest any write may block before the connection is dropped...
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// ...and the total time allowed to deliver one response. A visitor reading
/// very slowly would otherwise keep its buffered response (and its share of
/// the memory budget) indefinitely, as long as each write made some progress.
/// 8 MiB at a slow 30 KB/s over Tor takes under 300 s.
pub const SEND_DEADLINE: Duration = Duration::from_secs(300);

/// Request methods the gate accepts and will forward. Anything else is 405.
pub const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];

pub struct Request {
    /// Validated request method, uppercase (one of `METHODS`).
    pub method: String,
    /// Raw request target as received: path plus any query string. Starts with
    /// `/`. Forwarded verbatim to the upstream.
    pub target: String,
    /// `target` without the query string, for routing (matching the gate's own
    /// namespace). A route match is always exact.
    pub path: String,
    /// Every request header, in order, as `(name, value)`. Forwarded to the
    /// upstream after hop-by-hop headers and the pass cookie are removed.
    pub headers: Vec<(String, String)>,
    /// Convenience copy of the first `Cookie` header value (if any).
    pub cookie: Option<String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn is_get(&self) -> bool {
        self.method == "GET"
    }
    pub fn is_post(&self) -> bool {
        self.method == "POST"
    }
}

#[derive(Debug)]
pub enum HttpError {
    Bad,
    BadMethod,
    Timeout,
    LengthRequired,
    TooLarge,
    HeadTooLarge,
    /// The memory budget for buffered bodies is spent.
    Busy,
    /// The client closed / I/O error: nothing is sent back.
    Closed,
}

impl HttpError {
    pub fn status(&self) -> Option<u16> {
        match self {
            HttpError::Bad => Some(400),
            HttpError::BadMethod => Some(405),
            HttpError::Timeout => Some(408),
            HttpError::LengthRequired => Some(411),
            HttpError::TooLarge => Some(413),
            HttpError::HeadTooLarge => Some(431),
            HttpError::Busy => Some(503),
            HttpError::Closed => None,
        }
    }
}

/// A response the gate generates itself (the challenge page, errors, redirects).
/// Proxied upstream responses do not go through this type; see `upstream.rs`.
pub struct Reply {
    pub status: u16,
    pub ctype: &'static str,
    /// Extra headers (server-generated values only).
    pub extra: Vec<(&'static str, String)>,
    pub body: String,
}

impl Reply {
    pub fn page(status: u16, body: String) -> Reply {
        Reply {
            status,
            ctype: "text/html; charset=utf-8",
            extra: Vec::new(),
            body,
        }
    }

    /// 303 See Other: after a POST, the browser requests `location` with GET.
    /// `location` must be a sanitized same-origin path (see `safe_return_path` in lib.rs).
    pub fn redirect(location: String) -> Reply {
        Reply {
            status: 303,
            ctype: "text/plain; charset=utf-8",
            extra: vec![("Location", location)],
            body: String::new(),
        }
    }
}

// ------------------------------------------------------------- reading

fn read_some(stream: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> Result<usize, HttpError> {
    let left = match deadline.checked_duration_since(Instant::now()) {
        Some(d) if !d.is_zero() => d,
        _ => return Err(HttpError::Timeout),
    };
    // set_read_timeout(Some(0)) is an error; above we already ensured > 0.
    stream
        .set_read_timeout(Some(left))
        .map_err(|_| HttpError::Closed)?;
    loop {
        match stream.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) => match e.kind() {
                ErrorKind::Interrupted => continue,
                ErrorKind::WouldBlock | ErrorKind::TimedOut => return Err(HttpError::Timeout),
                _ => return Err(HttpError::Closed),
            },
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == &b"\r\n\r\n"[..])
}

fn safe_head(b: &[u8]) -> bool {
    b.iter()
        .all(|&c| c == b'\r' || c == b'\n' || c == b'\t' || (0x20..=0x7E).contains(&c))
}

/// Reads the PROXY v1 line that tor prepends with `HiddenServiceExportCircuitID
/// haproxy` and returns (circuit identifier, bytes already read after it).
pub fn read_proxy(stream: &mut TcpStream) -> Result<(u32, Vec<u8>), HttpError> {
    let deadline = Instant::now() + PROXY_DEADLINE;
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    loop {
        if let Some(i) = buf.windows(2).position(|w| w == &b"\r\n"[..]) {
            if i + 2 > MAX_PROXY_LINE {
                return Err(HttpError::Bad);
            }
            let line = std::str::from_utf8(&buf[..i]).map_err(|_| HttpError::Bad)?;
            let circuit = parse_proxy(line).ok_or(HttpError::Bad)?;
            return Ok((circuit, buf[i + 2..].to_vec()));
        }
        if buf.len() >= MAX_PROXY_LINE {
            return Err(HttpError::Bad);
        }
        let n = read_some(stream, &mut chunk, deadline)?;
        if n == 0 {
            return Err(HttpError::Closed);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// `PROXY TCP6 <source> <destination> <port> <port>` (or TCP4).
/// Tor encodes the circuit in the low 32 bits of the source IPv6
/// (fc00:dead:beef:4dad::XXXX:XXXX). With TCP4 (e.g. `curl --haproxy-protocol`
/// in local tests) the source IPv4 is used.
pub fn parse_proxy(line: &str) -> Option<u32> {
    let mut it = line.split(' ');
    if it.next()? != "PROXY" {
        return None;
    }
    let proto = it.next()?;
    let src = it.next()?;
    let _dst = it.next()?;
    it.next()?.parse::<u16>().ok()?;
    it.next()?.parse::<u16>().ok()?;
    if it.next().is_some() {
        return None;
    }
    match proto {
        "TCP6" => Some((u128::from(src.parse::<Ipv6Addr>().ok()?) & 0xFFFF_FFFF) as u32),
        "TCP4" => Some(u32::from(src.parse::<Ipv4Addr>().ok()?)),
        _ => None,
    }
}

/// A request whose head has been read and validated, and whose body (if any)
/// has not been read yet. The caller decides how much body it is willing to
/// buffer once it knows who is asking (see `lib.rs`).
pub struct PendingBody {
    /// The request, with an empty `body`.
    pub req: Request,
    /// The declared body length, if any.
    pub content_length: Option<usize>,
    /// Body bytes already read together with the head.
    rest: Vec<u8>,
}

impl PendingBody {
    /// Reads the body. More than `max_body` declared => TooLarge, nothing read.
    pub fn read_body(self, stream: &mut TcpStream, max_body: usize) -> Result<Request, HttpError> {
        let PendingBody { mut req, content_length, rest } = self;
        let cl = match content_length {
            Some(cl) => cl,
            None => return Ok(req),
        };
        if cl > max_body {
            return Err(HttpError::TooLarge);
        }
        let mut body = rest;
        let mut chunk = [0u8; 1024];
        let body_deadline = Instant::now() + BODY_DEADLINE;
        while body.len() < cl {
            let n = read_some(stream, &mut chunk, body_deadline)?;
            if n == 0 {
                return Err(HttpError::Closed);
            }
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(cl); // anything extra (pipelining) is discarded
        req.body = body;
        Ok(req)
    }

    /// Gives up on the body: the request is handled as if it had none, and the
    /// unread bytes are left on the socket (the connection is closed after the
    /// reply anyway).
    pub fn skip_body(self) -> Request {
        self.req
    }
}

/// Reads one HTTP request. `initial` holds bytes already read (whatever followed
/// the PROXY line, or nothing). `max_body` caps the request body.
pub fn read_request(stream: &mut TcpStream, initial: Vec<u8>, max_body: usize) -> Result<Request, HttpError> {
    read_head(stream, initial)?.read_body(stream, max_body)
}

/// Reads and validates the request line and headers, but not the body.
pub fn read_head(stream: &mut TcpStream, initial: Vec<u8>) -> Result<PendingBody, HttpError> {
    let deadline = Instant::now() + READ_DEADLINE;
    let mut buf: Vec<u8> = initial;
    buf.reserve(1024);
    let mut chunk = [0u8; 1024];

    // 1) full head (up to CRLF CRLF)
    let head_end = loop {
        if let Some(i) = find_head_end(&buf) {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return Err(HttpError::HeadTooLarge);
        }
        let n = read_some(stream, &mut chunk, deadline)?;
        if n == 0 {
            return Err(HttpError::Closed);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    if head_end > MAX_HEAD {
        return Err(HttpError::HeadTooLarge);
    }
    if !safe_head(&buf[..head_end]) {
        return Err(HttpError::Bad);
    }
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| HttpError::Bad)?;

    // 2) request line
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(HttpError::Bad)?;
    // A lone CR or LF inside a line (we split on CRLF pairs only) would let a
    // crafted request smuggle extra header lines into the forwarded request.
    if request_line.contains('\r') || request_line.contains('\n') {
        return Err(HttpError::Bad);
    }
    let mut parts = request_line.split(' ');
    let m = parts.next().ok_or(HttpError::Bad)?;
    let target = parts.next().ok_or(HttpError::Bad)?;
    let version = parts.next().ok_or(HttpError::Bad)?;
    if parts.next().is_some() {
        return Err(HttpError::Bad);
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HttpError::Bad);
    }
    // Visible ASCII only: a tab (allowed by safe_head) would be forwarded inside
    // the request line, where some backends split on any whitespace.
    if !target.starts_with('/') || target.len() > MAX_TARGET || !target.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return Err(HttpError::Bad);
    }
    if !METHODS.contains(&m) {
        return Err(HttpError::BadMethod);
    }
    let method = m.to_string();
    let path = target.split('?').next().unwrap_or("").to_string();

    // 3) headers
    let mut content_length: Option<usize> = None;
    let mut cookie: Option<String> = None;
    let mut hosts = 0usize;
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.contains('\r') || line.contains('\n') {
            return Err(HttpError::Bad); // a lone CR/LF would smuggle a header
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(HttpError::Bad); // obs-fold
        }
        let (name, value) = line.split_once(':').ok_or(HttpError::Bad)?;
        if !is_token(name) {
            return Err(HttpError::Bad);
        }
        let value = value.trim_matches(|c: char| c == ' ' || c == '\t');
        if name.eq_ignore_ascii_case("host") {
            hosts += 1;
        }

        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(HttpError::Bad);
            }
            if value.is_empty() || value.len() > 9 || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(HttpError::Bad);
            }
            content_length = Some(value.parse::<usize>().map_err(|_| HttpError::Bad)?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(HttpError::Bad);
        } else if name.eq_ignore_ascii_case("cookie") && cookie.is_none() {
            cookie = Some(value.to_string());
        }
        headers.push((name.to_string(), value.to_string()));
    }

    // RFC 9112 §3.2: an HTTP/1.1 request needs exactly one Host, and two would
    // let the gate and the backend disagree about which site is meant.
    if hosts > 1 || (hosts == 0 && version == "HTTP/1.1") {
        return Err(HttpError::Bad);
    }

    // 4) the body is read later (PendingBody::read_body), once the caller knows
    //    how much it will accept. POST/PUT/PATCH without a length cannot be
    //    framed safely.
    if content_length.is_none() && matches!(m, "POST" | "PUT" | "PATCH") {
        return Err(HttpError::LengthRequired);
    }

    let rest = buf[head_end + 4..].to_vec();
    Ok(PendingBody {
        req: Request {
            method,
            target: target.to_string(),
            path,
            headers,
            cookie,
            body: Vec::new(),
        },
        content_length,
        rest,
    })
}

// ------------------------------------------------------------ parsing helpers

/// A header field name: a non-empty RFC 9110 token (letters, digits and
/// ``!#$%&'*+-.^_`|~``). Anything else (spaces, separators, controls) is refused
/// rather than forwarded for a backend to interpret its own way.
pub fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Text allowed in a header value or a reason phrase: no control bytes except
/// tab (so no CR or LF that could start a new line), no DEL. Bytes >= 0x80
/// (obs-text) are allowed.
pub fn is_field_text(s: &str) -> bool {
    s.bytes().all(|b| b == b'\t' || (b >= 0x20 && b != 0x7F))
}

/// Value of `key` in an application/x-www-form-urlencoded body.
/// None if missing or present more than once (no ambiguity).
/// Does not decode %XX: the expected fields (hex and digits) never need it.
pub fn form_get<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let mut found: Option<&'a str> = None;
    for pair in body.split('&') {
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        if k == key {
            if found.is_some() {
                return None;
            }
            found = Some(v);
        }
    }
    found
}

/// Value of cookie `name` in a Cookie header.
pub fn cookie_get<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    for part in header.split(';') {
        if let Some((k, v)) = part.trim().split_once('=') {
            if k == name {
                return Some(v);
            }
        }
    }
    None
}

/// Rebuilds a `Cookie` header value with the cookie named `drop` removed, so the
/// gate's own pass cookie never reaches the upstream. Returns None when nothing
/// is left (the header should then be dropped entirely).
pub fn cookie_without<'a>(header: &'a str, drop: &str) -> Option<String> {
    let kept: Vec<&'a str> = header
        .split(';')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .filter(|p| match p.split_once('=') {
            Some((k, _)) => k != drop,
            None => true,
        })
        .collect();
    if kept.is_empty() {
        None
    } else {
        Some(kept.join("; "))
    }
}

// ------------------------------------------------------------ writing

pub fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

/// Strict CSP for the gate's OWN pages (the challenge and error pages): no
/// scripts, no connections, images from `data:` only. Proxied upstream
/// responses are relayed with the upstream's own headers and never get these.
const SECURITY_HEADERS: &str = "Cache-Control: no-store\r\n\
X-Content-Type-Options: nosniff\r\n\
Referrer-Policy: no-referrer\r\n\
X-Frame-Options: DENY\r\n\
Cross-Origin-Opener-Policy: same-origin\r\n\
Content-Security-Policy: default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'\r\n";

pub fn send(stream: &mut TcpStream, r: &Reply) {
    write_reply(stream, r, true);
}

/// The reply to a HEAD request: the same headers (Content-Length included, as
/// for GET), no body.
pub fn send_head(stream: &mut TcpStream, r: &Reply) {
    write_reply(stream, r, false);
}

fn write_reply(stream: &mut TcpStream, r: &Reply, with_body: bool) {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}",
        r.status,
        reason(r.status),
        r.ctype,
        r.body.len(),
        SECURITY_HEADERS
    );
    for (k, v) in r.extra.iter() {
        head.push_str(k);
        head.push_str(": ");
        head.push_str(v);
        head.push_str("\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");

    let mut out = head.into_bytes();
    if with_body {
        out.extend_from_slice(r.body.as_bytes());
    }
    send_raw(stream, &out);
}

/// Writes already-framed response bytes (used for a relayed upstream response).
/// Gives up silently after SEND_DEADLINE, or a write blocked for WRITE_TIMEOUT.
pub fn send_raw(stream: &mut TcpStream, bytes: &[u8]) {
    let deadline = Instant::now() + SEND_DEADLINE;
    let mut off = 0;
    while off < bytes.len() {
        let left = match deadline.checked_duration_since(Instant::now()) {
            Some(d) if !d.is_zero() => d.min(WRITE_TIMEOUT),
            _ => return,
        };
        if stream.set_write_timeout(Some(left)).is_err() {
            return;
        }
        match stream.write(&bytes[off..]) {
            Ok(0) => return,
            Ok(n) => off += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return,
        }
    }
    let _ = stream.flush();
}

/// Graceful close: send FIN, then drain (a little of) whatever the client still
/// sends, so no RST makes it lose the response.
pub fn close(stream: &mut TcpStream) {
    let _ = stream.shutdown(Shutdown::Write);
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut sink = [0u8; 2048];
    for _ in 0..16 {
        match read_some(stream, &mut sink, deadline) {
            Ok(n) if n > 0 => continue,
            _ => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_proxy_line() {
        // literal example from tor's own tests
        assert_eq!(parse_proxy("PROXY TCP6 fc00:dead:beef:4dad::ffff:ffff ::1 65535 42"), Some(u32::MAX));
        assert_eq!(parse_proxy("PROXY TCP6 fc00:dead:beef:4dad::12:3456 ::1 13398 80"), Some(0x0012_3456));
        assert_eq!(parse_proxy("PROXY TCP4 127.0.0.1 127.0.0.1 51000 8080"), Some(0x7F00_0001));
    }

    #[test]
    fn malformed_proxy_line() {
        assert_eq!(parse_proxy(""), None);
        assert_eq!(parse_proxy("PROXY UNKNOWN"), None);
        assert_eq!(parse_proxy("PROXY TCP6 nothing ::1 1 80"), None);
        assert_eq!(parse_proxy("PROXY TCP6 fc00::1 ::1 1 80 extra"), None);
        assert_eq!(parse_proxy("PROXY TCP6 fc00::1 ::1 99999 80"), None);
        assert_eq!(parse_proxy("GET / HTTP/1.1"), None);
    }

    #[test]
    fn form_get_basic() {
        let b = "t=abc&c.x=12&c.y=34";
        assert_eq!(form_get(b, "t"), Some("abc"));
        assert_eq!(form_get(b, "c.x"), Some("12"));
        assert_eq!(form_get(b, "c.y"), Some("34"));
        assert_eq!(form_get(b, "z"), None);
    }

    #[test]
    fn form_get_rejects_duplicates() {
        assert_eq!(form_get("t=a&t=b", "t"), None);
        assert_eq!(form_get("t=a&x=1&t=a", "t"), None);
    }

    #[test]
    fn form_get_tolerates_junk() {
        assert_eq!(form_get("&&=&noequals&t=ok", "t"), Some("ok"));
        assert_eq!(form_get("", "t"), None);
    }

    #[test]
    fn cookie_get_basic() {
        assert_eq!(cookie_get("a=1; onion_gate_pass=xyz; b=2", "onion_gate_pass"), Some("xyz"));
        assert_eq!(cookie_get("onion_gate_pass=xyz", "onion_gate_pass"), Some("xyz"));
        assert_eq!(cookie_get("a=1", "onion_gate_pass"), None);
        assert_eq!(cookie_get("xonion_gate_pass=1", "onion_gate_pass"), None);
    }

    #[test]
    fn cookie_without_strips_only_the_named_one() {
        assert_eq!(cookie_without("a=1; pass=xyz; b=2", "pass").as_deref(), Some("a=1; b=2"));
        assert_eq!(cookie_without("pass=xyz", "pass"), None);
        assert_eq!(cookie_without("pass=xyz; pass=abc", "pass"), None);
        assert_eq!(cookie_without("a=1", "pass").as_deref(), Some("a=1"));
        assert_eq!(cookie_without("", "pass"), None);
    }

    #[test]
    fn token_and_field_text() {
        assert!(is_token("Content-Type") && is_token("X_Custom") && is_token("a!#$%&'*+-.^_`|~9"));
        for bad in ["", "X Y", "X(y)", "X:y", "X\"y", "X/y", "X\u{e9}", "X\ty"] {
            assert!(!is_token(bad), "{:?}", bad);
        }
        assert!(is_field_text("text/html; charset=utf-8") && is_field_text("a\tb") && is_field_text("caf\u{e9}"));
        for bad in ["a\rb", "a\nb", "a\x00b", "a\x7fb", "a\x1bb"] {
            assert!(!is_field_text(bad), "{:?}", bad);
        }
    }

    #[test]
    fn find_head_end_works() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\n"), Some(14));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(find_head_end(b""), None);
    }

    #[test]
    fn safe_head_rejects_control_and_non_ascii() {
        assert!(safe_head(b"GET / HTTP/1.1\r\nHost: a\r\n"));
        assert!(!safe_head(b"GET /\x00 HTTP/1.1"));
        assert!(!safe_head("GET /\u{e9} HTTP/1.1".as_bytes()));
        assert!(!safe_head(b"GET /\x7f HTTP/1.1"));
    }
}
