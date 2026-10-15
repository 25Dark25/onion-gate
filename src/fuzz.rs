//! Fuzz targets for the parsers: properties that must hold for ANY input, not
//! just "does not panic". Each target panics when a property is broken.
//!
//! Two drivers use them:
//!  - `cargo test` runs a small, deterministic, std-only mutation fuzzer over
//!    them (the tests at the bottom; `FUZZ_ITERS` and `FUZZ_SEED` to run longer
//!    or elsewhere);
//!  - an external coverage-guided fuzzer (libFuzzer via cargo-fuzz, kept out of
//!    this repository so it adds no dependency) calls them through the
//!    `fuzzing` feature. See docs/TESTING.md.
//!
//! The properties:
//!  - `request`: whatever the request parser accepts is well-formed, and the
//!    request the gate would forward is accepted by the same strict parser,
//!    framed exactly (no byte left over for a second request), without the
//!    pass cookie, client-identity headers or the client's hop-by-hop headers.
//!  - `response`: a re-framed backend response has clean lines (no response
//!    splitting), one framing (our Content-Length, no Transfer-Encoding), a
//!    body of exactly that length, and re-framing it again changes nothing.
//!  - `chunks`: walking a chunked body as it arrives, in pieces, gives the same
//!    result and the same bytes as walking it whole.
//!  - `proxy_line`, `cookies`, `return_path`: no panic, and their outputs keep
//!    the promises the rest of the gate relies on.

use crate::http::{self, METHODS};
use crate::upstream::{self, Body, Walk};
use crate::COOKIE;

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A request head as the client could send it.
pub fn request(data: &[u8]) {
    let head_end = match http::find_head_end(data) {
        Some(e) => e,
        None => return,
    };
    let p = match http::parse_head(data.to_vec(), head_end) {
        Ok(p) => p,
        Err(_) => return,
    };
    let req = &p.req;

    // What the parser accepted is well-formed.
    assert!(METHODS.contains(&req.method.as_str()), "method {:?}", req.method);
    assert!(req.target.starts_with('/') && req.target.len() <= 2048, "target {:?}", req.target);
    assert!(req.target.bytes().all(|b| (0x21..=0x7E).contains(&b)), "target {:?}", req.target);
    assert_eq!(req.path, req.target.split('?').next().unwrap());
    let mut hosts = 0;
    let mut lengths = 0;
    for (name, value) in &req.headers {
        assert!(http::is_token(name), "header name {:?}", name);
        assert!(value.bytes().all(|b| b == b'\t' || (0x20..=0x7E).contains(&b)), "header value {:?}", value);
        assert!(!value.starts_with([' ', '\t']) && !value.ends_with([' ', '\t']), "untrimmed {:?}", value);
        assert!(!name.eq_ignore_ascii_case("transfer-encoding"), "Transfer-Encoding accepted");
        hosts += name.eq_ignore_ascii_case("host") as usize;
        if name.eq_ignore_ascii_case("content-length") {
            lengths += 1;
            assert_eq!(value.parse::<usize>().ok(), p.content_length);
        }
    }
    assert!(hosts <= 1, "{} Host headers accepted", hosts);
    assert!(lengths <= 1 && (lengths == 1) == p.content_length.is_some());
    let first_cookie = req.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("cookie")).map(|(_, v)| v.clone());
    assert_eq!(req.cookie, first_cookie);

    // The request the gate forwards, with whatever body bytes came along.
    let mut fwd = http::Request {
        method: req.method.clone(),
        target: req.target.clone(),
        path: req.path.clone(),
        headers: req.headers.clone(),
        cookie: req.cookie.clone(),
        body: p.rest.clone(),
    };
    fwd.body.truncate(p.content_length.unwrap_or(0));
    let wire = upstream::build_request(&fwd, COOKIE);
    let he = http::find_head_end(&wire).expect("forwarded request has no head end");
    let p2 = match http::parse_head(wire.clone(), he) {
        Ok(p2) => p2,
        // The few lines the gate adds can push a head that was just under the
        // cap over it: the backend's own limit, not a framing problem.
        Err(http::HttpError::HeadTooLarge) if he > 16 * 1024 => return,
        Err(e) => panic!("the gate's own parser rejects what it forwards ({:?}):\n{}", e, lossy(&wire)),
    };
    assert_eq!(p2.req.method, fwd.method);
    assert_eq!(p2.req.target, fwd.target);
    let body_len = fwd.body.len();
    let want_len = if body_len > 0 || matches!(fwd.method.as_str(), "POST" | "PUT" | "PATCH") {
        Some(body_len)
    } else {
        None
    };
    assert_eq!(p2.content_length, want_len, "forwarded Content-Length:\n{}", lossy(&wire));
    assert_eq!(wire.len(), he + 4 + body_len, "bytes after the forwarded body (smuggling):\n{}", lossy(&wire));

    // Headers the client named in its Connection header are hop-by-hop too.
    let named: Vec<String> = req
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(',').map(|t| norm(t.trim())))
        .collect();
    let (mut hosts, mut conns) = (0, 0);
    for (name, value) in &p2.req.headers {
        let n = norm(name);
        match n.as_str() {
            "host" => hosts += 1,
            "connection" => {
                conns += 1;
                assert_eq!(value, "close");
            }
            "content-length" => {}
            _ => {
                assert!(!never_forwarded(&n), "{:?} forwarded:\n{}", name, lossy(&wire));
                assert!(!named.contains(&n), "{:?} named in Connection, forwarded:\n{}", name, lossy(&wire));
                if n == "cookie" {
                    assert_eq!(http::cookie_get(value, COOKIE), None, "pass cookie forwarded:\n{}", lossy(&wire));
                } else {
                    assert!(
                        req.headers.iter().any(|(a, b)| a == name && b == value),
                        "forwarded header {:?} was not in the request",
                        name
                    );
                }
            }
        }
    }
    assert_eq!(hosts, 1, "forwarded Host headers:\n{}", lossy(&wire));
    assert_eq!(conns, 1, "forwarded Connection headers:\n{}", lossy(&wire));
}

/// Lowercase, `_` read as `-` (as CGI and PHP do).
fn norm(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

/// Request headers that must never reach the backend, written out here rather
/// than taken from `upstream.rs`, so the check does not trust the code it checks.
/// `name` is lowercase with `_` read as `-`. (Content-Length, Host and
/// Connection are checked separately: the gate sets its own.)
fn never_forwarded(name: &str) -> bool {
    const NAMES: &[&str] = &[
        // hop-by-hop
        "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade",
        "proxy-authorization", "proxy-authenticate",
        // the gate holds the whole body
        "expect",
        // claims about the client or an earlier proxy; httpoxy
        "forwarded", "x-real-ip", "x-client-ip", "true-client-ip", "x-cluster-client-ip",
        "x-originating-ip", "client-ip", "cf-connecting-ip", "fastly-client-ip", "proxy",
    ];
    NAMES.contains(&name) || name.starts_with("x-forwarded-")
}

/// A backend response. The first byte picks a HEAD request (odd) or not.
pub fn response(data: &[u8]) {
    let (head_only, raw) = match data.split_first() {
        Some((f, r)) => (f & 1 == 1, r),
        None => return,
    };
    let out = match upstream::frame_response(raw, head_only) {
        Ok(o) => o,
        Err(_) => return,
    };
    let he = http::find_head_end(&out).expect("re-framed response has no head end");
    let head = std::str::from_utf8(&out[..he]).expect("re-framed head is not UTF-8");
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap();
    let code = status.strip_prefix("HTTP/1.1 ").and_then(|s| s.get(..3)).unwrap_or("");
    assert!(
        code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()) && status.as_bytes().get(12) == Some(&b' '),
        "status line {:?}",
        status
    );
    let (mut lengths, mut conns) = (0, 0);
    for line in std::iter::once(status).chain(lines) {
        assert!(http::is_field_text(line), "control byte in a relayed line {:?}", line);
        let lname = line.split(':').next().unwrap().to_ascii_lowercase();
        assert_ne!(lname, "transfer-encoding", "Transfer-Encoding relayed");
        lengths += (lname == "content-length") as usize;
        conns += (lname == "connection") as usize;
    }
    assert!(lengths <= 1 && conns == 1, "framing headers:\n{}", head);

    let h = match upstream::parse_head(&out, head_only) {
        Ok(Some(h)) => h,
        other => panic!("re-framed response does not parse ({:?}):\n{}", other.map(|_| ()), lossy(&out)),
    };
    assert!((200..600).contains(&h.code), "relayed status {}", h.code);
    match h.body_kind {
        Body::None => assert_eq!(out.len(), he + 4, "body after a body-less response"),
        Body::Length(cl) => assert_eq!(out.len(), he + 4 + cl, "body length differs from Content-Length"),
        Body::Chunked | Body::ToEof => panic!("re-framed response is not length-delimited:\n{}", head),
    }
    // Re-framing again changes nothing, with one exception: a header literally
    // named `close` is relayed, and on a second pass the gate's own
    // `Connection: close` names it as hop-by-hop, so it goes. (Harmless, and
    // what RFC 9110 §7.6.1 asks of the next proxy anyway.)
    let again = upstream::frame_response(&out, head_only).expect("re-framing a re-framed response fails");
    let expected = without_header(&out, he, "close");
    assert!(again == expected, "re-framing is not stable:\n{}\n----\n{}", lossy(&out), lossy(&again));
}

/// `msg` (head ending at `he`) without the header lines named `name`.
fn without_header(msg: &[u8], he: usize, name: &str) -> Vec<u8> {
    let head = std::str::from_utf8(&msg[..he]).unwrap();
    let kept: Vec<&str> = head
        .split("\r\n")
        .enumerate()
        .filter(|(i, l)| *i == 0 || !l.split(':').next().unwrap().eq_ignore_ascii_case(name))
        .map(|(_, l)| l)
        .collect();
    let mut out = kept.join("\r\n").into_bytes();
    out.extend_from_slice(&msg[he..]);
    out
}

/// A chunked body. The first byte sets the size of the pieces it arrives in.
pub fn chunks(data: &[u8]) {
    let (step, body) = match data.split_first() {
        Some((f, r)) => (1 + *f as usize, r),
        None => return,
    };
    let mut whole = Vec::new();
    let r1 = upstream::walk_chunks(body, &mut 0, |c| whole.extend_from_slice(c));
    let mut pieces = Vec::new();
    let (mut pos, mut end) = (0usize, 0usize);
    let r2 = loop {
        end = (end + step).min(body.len());
        let r = upstream::walk_chunks(&body[..end], &mut pos, |c| pieces.extend_from_slice(c));
        if r != Walk::More || end == body.len() {
            break r;
        }
    };
    assert_eq!(r1, r2, "walking in pieces of {} differs", step);
    if r1 == Walk::Done {
        assert!(whole == pieces, "chunk data differs when walked in pieces of {}", step);
    }
}

/// A PROXY v1 line (without its CRLF).
pub fn proxy_line(data: &[u8]) {
    if let Ok(line) = std::str::from_utf8(data) {
        if http::parse_proxy(line).is_some() {
            assert!(line.starts_with("PROXY TCP4 ") || line.starts_with("PROXY TCP6 "), "{:?}", line);
        }
    }
}

/// A Cookie header value: the pass cookie never survives `cookie_without`.
pub fn cookies(data: &[u8]) {
    let header = match std::str::from_utf8(data) {
        Ok(h) => h,
        Err(_) => return,
    };
    let _ = http::form_get(header, "t");
    match http::cookie_without(header, COOKIE) {
        Some(v) => {
            assert_eq!(http::cookie_get(&v, COOKIE), None, "pass cookie kept in {:?}", v);
            assert!(v.split(';').all(|p| !p.trim().is_empty()), "empty pair in {:?}", v);
            assert_eq!(http::cookie_without(&v, COOKIE).as_deref(), Some(v.as_str()), "not stable");
        }
        None => assert!(header
            .split(';')
            .map(str::trim)
            .all(|p| p.is_empty() || p.split_once('=').is_some_and(|(k, _)| k == COOKIE))),
    }
}

/// A request target: the return path after the CAPTCHA is never an open redirect.
pub fn return_path(data: &[u8]) {
    if let Ok(t) = std::str::from_utf8(data) {
        let r = crate::safe_return_path(t);
        assert!(r == "/" || r == t, "{:?} -> {:?}", t, r);
        assert!(r.starts_with('/') && !r.starts_with("//") && !r.starts_with("/\\"), "{:?}", r);
        assert!(r.len() <= 1024 && r.bytes().all(|b| (0x21..=0x7E).contains(&b)), "{:?}", r);
    }
}

#[cfg(test)]
mod tests {
    //! A deterministic, std-only mutation fuzzer: no coverage feedback, so it
    //! is no substitute for libFuzzer, but it runs on every `cargo test`.
    //! Inputs the parsers accept join the corpus, so mutations reach deeper.

    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            // splitmix64
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    const BYTES: &[u8] = b"\0\t\n\r :;=,0129afAF/?#%_-\x7f\x80\xc3\xff";
    const DICT: &[&str] = &[
        "\r\n", "\r\n\r\n", "\n", "\r", ": ", ":", " ", "\t", ";", "=", ",", "0", "1", "ff", "-1", "99999999999999999",
        "HTTP/1.1", "HTTP/1.0", "HTTP/1.1 ", "GET ", "POST ", "HEAD ", "Host: a\r\n", "Content-Length: ",
        "Content-Length: 5\r\n", "Transfer-Encoding: chunked\r\n", "Transfer-Encoding", "chunked", "Connection: ",
        "Connection: close\r\n", "keep-alive", "Cookie: ", "onion_gate_pass", "onion_gate_pass=", "X-Forwarded-For",
        "X_Forwarded_For", "x-forwarded-", "Forwarded", "Proxy", "Expect: 100-continue\r\n", "Upgrade", "cookie",
        "content-length", "host", "connection", "HTTP/1.1 100 Continue\r\n\r\n", "HTTP/1.1 204 No Content\r\n",
        "HTTP/1.1 304 x\r\n", "HTTP/1.1 101 x\r\n", "HTTP/1.1 000 x\r\n", "HTTP/1.1 999 x\r\n", "0\r\n\r\n",
        "5\r\nhello\r\n", "1;ext=\"x\"\r\n", "PROXY TCP4 ", "PROXY TCP6 ", "fc00:dead:beef:4dad::1:2", "127.0.0.1",
        "65535", "/__gate/", "//", "/\\", "?", "%0d%0a",
    ];

    fn mutate(rng: &mut Rng, corpus: &[Vec<u8>]) -> Vec<u8> {
        let mut v = corpus[rng.below(corpus.len())].clone();
        for _ in 0..1 + rng.below(4) {
            let at = if v.is_empty() { 0 } else { rng.below(v.len() + 1) };
            match rng.below(8) {
                0 if !v.is_empty() => {
                    let i = rng.below(v.len());
                    v[i] ^= 1 << rng.below(8);
                }
                1 if !v.is_empty() => {
                    let i = rng.below(v.len());
                    v[i] = BYTES[rng.below(BYTES.len())];
                }
                2 | 3 => {
                    let t = DICT[rng.below(DICT.len())].as_bytes();
                    v.splice(at..at, t.iter().copied());
                }
                4 if !v.is_empty() => {
                    let i = rng.below(v.len());
                    let n = 1 + rng.below(8.min(v.len() - i));
                    v.drain(i..i + n);
                }
                5 if !v.is_empty() => {
                    let i = rng.below(v.len());
                    let n = 1 + rng.below(16.min(v.len() - i));
                    let dup: Vec<u8> = v[i..i + n].to_vec();
                    v.splice(at..at, dup);
                }
                6 => {
                    let other = &corpus[rng.below(corpus.len())];
                    let j = rng.below(other.len() + 1);
                    v.truncate(at);
                    v.extend_from_slice(&other[j..]);
                }
                _ => {
                    let t = DICT[rng.below(DICT.len())].as_bytes();
                    let end = (at + 1 + rng.below(8)).min(v.len());
                    v.splice(at..end.max(at), t.iter().copied());
                }
            }
        }
        v.truncate(20_000);
        v
    }

    fn env(name: &str, default: u64) -> u64 {
        std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
    }

    /// Runs `target` on `seeds` and on mutations of them. `keep` says whether an
    /// input reached deep enough to be worth mutating further.
    fn run(name: &str, seeds: &[&[u8]], target: fn(&[u8]), keep: fn(&[u8]) -> bool) {
        let iters = env("FUZZ_ITERS", 20_000);
        let seed = env("FUZZ_SEED", 0x5EED) ^ name.bytes().fold(0u64, |h, b| h.wrapping_mul(31).wrapping_add(b as u64));
        let mut rng = Rng(seed);
        let mut corpus: Vec<Vec<u8>> = seeds.iter().map(|s| s.to_vec()).collect();
        for s in seeds {
            target(s);
        }
        for i in 0..iters {
            let input = mutate(&mut rng, &corpus);
            let r = std::panic::catch_unwind(|| target(&input));
            if r.is_err() {
                panic!(
                    "fuzz target {} failed at iteration {} (FUZZ_SEED={}) on input {:?}",
                    name,
                    i,
                    env("FUZZ_SEED", 0x5EED),
                    lossy(&input)
                );
            }
            if corpus.len() < 512 && keep(&input) {
                corpus.push(input);
            }
        }
    }

    const REQUESTS: &[&[u8]] = &[
        b"GET / HTTP/1.1\r\nHost: a.onion\r\n\r\n",
        b"GET /p?q=1 HTTP/1.0\r\n\r\n",
        b"POST /__gate/verify HTTP/1.1\r\nHost: a\r\nContent-Length: 11\r\n\r\nt=00&c.x=1",
        b"POST /form HTTP/1.1\r\nHost: a\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\nhello",
        b"GET /x HTTP/1.1\r\nHost: a\r\nCookie: a=1; onion_gate_pass=0123456789abcdef0123456789abcdef; b=2\r\nCookie: onion_gate_pass=x\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, X-Secret, Host\r\nX-Secret: 1\r\nX-Forwarded-For: 1.2.3.4\r\nX_Forwarded_Host: e\r\nProxy: x\r\nUpgrade: websocket\r\n\r\n",
        b"DELETE /a HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nAccept: */*\r\n\r\n",
        b"OPTIONS /a HTTP/1.1\r\nHost: a\r\nTE: trailers\r\nTrailer: x\r\nKeep-Alive: 5\r\n\r\n",
    ];

    fn parses(d: &[u8]) -> bool {
        http::find_head_end(d).is_some_and(|e| http::parse_head(d.to_vec(), e).is_ok())
    }

    #[test]
    fn fuzz_request() {
        run("request", REQUESTS, request, parses);
    }

    const RESPONSES: &[&[u8]] = &[
        b"\0HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello",
        b"\0HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close, X-Drop\r\nX-Drop: 1\r\n\r\n5;e=1\r\nhello\r\n0\r\nT: 1\r\n\r\n",
        b"\0HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nLocation: /a\r\nContent-Length: 2\r\n\r\nok",
        b"\0HTTP/1.0 200\r\nSet-Cookie: a=1\r\n\r\nto the end",
        b"\0HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
        b"\0HTTP/1.1 304 Not Modified\r\nETag: \"x\"\r\n\r\n",
        b"\x01HTTP/1.1 200 OK\r\nContent-Length: 1234\r\nKeep-Alive: timeout=5\r\n\r\n",
        b"\0HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        // Found by libFuzzer: a header named `close`.
        b"\0HTTP/1.1 200 ed\r\nclose:d \r\nC%ion:2 \r\nn:2 \r\n\r\n",
    ];

    fn frames(d: &[u8]) -> bool {
        d.split_first().is_some_and(|(f, r)| upstream::frame_response(r, f & 1 == 1).is_ok())
    }

    #[test]
    fn fuzz_response() {
        run("response", RESPONSES, response, frames);
    }

    /// First byte: the size of the pieces; the rest: the chunked body.
    const CHUNKED: &[&[u8]] = &[
        b"\x02a\r\n0123456789\r\n0\r\n\r\n",
        b"\x0b1;ext=\"q\"\r\nx\r\n0\r\nTrailer: v\r\nOther: w\r\n\r\n",
        b"\x0010\r\n0\r\n\r\n0\r\n\r\nxxxxxx\r\n0\r\n\r\n",
        b"\x05" as &[u8],
    ];

    #[test]
    fn fuzz_chunks() {
        // Boundary seed: a chunk-size line of exactly MAX_CHUNK_LINE (4096)
        // bytes, arriving in pieces of 241 so that one piece ends between its
        // CR and its LF (17 * 241 = 4097). Blind mutation does not find this.
        let mut edge = vec![240u8];
        edge.extend_from_slice(b"1;");
        edge.extend_from_slice(&[b'x'; 4094]);
        edge.extend_from_slice(b"\r\nA\r\n0\r\n\r\n");
        let mut seeds: Vec<&[u8]> = CHUNKED.to_vec();
        seeds.push(&edge);
        run("chunks", &seeds, chunks, |d| d.len() > 1 && d.len() < 1024);
    }

    #[test]
    fn fuzz_small_parsers() {
        let proxy: &[&[u8]] = &[
            b"PROXY TCP6 fc00:dead:beef:4dad::1:2 ::1 80 80",
            b"PROXY TCP4 10.0.0.1 127.0.0.1 40000 8088",
        ];
        run("proxy_line", proxy, proxy_line, |_| false);
        let cookie: &[&[u8]] = &[
            b"a=1; onion_gate_pass=0123; b=2",
            b"onion_gate_pass=x;onion_gate_pass=y;;  ; c",
            b"t=00&c.x=1&c.y=2",
        ];
        run("cookies", cookie, cookies, |_| false);
        let paths: &[&[u8]] = &[b"/a/b?c=d", b"//evil", b"/\\evil", b"/%2F%2Fx"];
        run("return_path", paths, return_path, |_| false);
    }
}
