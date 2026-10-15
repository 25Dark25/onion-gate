//! End-to-end tests over real loopback sockets. They drive the exact
//! `serve_connection` the binary uses, with a tiny mock backend standing in for
//! the real upstream, so the whole chain is exercised: PROXY line, gate,
//! two-round CAPTCHA, pass cookie, forwarding, and the per-circuit limits.

use onion_gate::store::{from_hex, to_hex, Store, Token};
use onion_gate::upstream::Upstream;
use onion_gate::{captcha, limit::Limiter, serve_connection, App, COOKIE, ROUNDS};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// A tiny backend. Every request gets a 200 that echoes the request target, the
/// body it received and whether the pass cookie reached it, so a test can see
/// exactly what the gate forwarded. With `linger`, it keeps the connection open
/// after answering (like a keep-alive server ignoring `Connection: close`).
fn backend(linger: bool) -> String {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            thread::spawn(move || {
                s.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                let (head, body) = loop {
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                    if let Some(he) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..he]).into_owned();
                        let len: usize = head
                            .lines()
                            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                            .unwrap_or(0);
                        if buf.len() >= he + 4 + len {
                            break (head, String::from_utf8_lossy(&buf[he + 4..he + 4 + len]).into_owned());
                        }
                    }
                };
                let target = head.lines().next().and_then(|l| l.split(' ').nth(1)).unwrap_or("?").to_string();
                let saw_pass = head.to_lowercase().contains("onion_gate_pass");
                let saw_expect = head.to_lowercase().contains("expect:");
                let out = format!(
                    "BACKEND saw target={} pass_cookie_present={} expect_present={} body={}",
                    target, saw_pass, saw_expect, body
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    out.len(),
                    out
                );
                let _ = s.write_all(resp.as_bytes());
                if linger {
                    thread::sleep(Duration::from_secs(20));
                }
            });
        }
    });
    addr
}

fn start() -> (u16, Arc<App>) {
    start_with(false)
}

fn start_with(linger: bool) -> (u16, Arc<App>) {
    let backend = backend(linger);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Arc::new(App {
        store: Store::new(),
        limiter: Limiter::new(),
        upstream: Upstream::new(&backend, COOKIE).unwrap(),
        proxy: true,
        max_body: 64 * 1024,
    });
    let a = Arc::clone(&app);
    thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let a2 = Arc::clone(&a);
            thread::spawn(move || {
                let mut s = s;
                serve_connection(&mut s, &a2);
            });
        }
    });
    (port, app)
}

/// Tor's PROXY v1 line encoding the circuit in a TCP4 source address.
fn proxy_line(circuit: u32) -> String {
    let ip = Ipv4Addr::from(circuit);
    format!("PROXY TCP4 {} 127.0.0.1 40000 8088\r\n", ip)
}

/// Sends one raw request (with a PROXY line) on a fresh connection and returns
/// the whole response as a string.
fn send(port: u16, circuit: u32, method: &str, target: &str, cookie: Option<&str>, body: Option<&str>) -> String {
    send_with(port, circuit, method, target, cookie, body, "")
}

/// Like `send`, with extra raw header lines (each ending in CRLF).
fn send_with(port: u16, circuit: u32, method: &str, target: &str, cookie: Option<&str>, body: Option<&str>, extra: &str) -> String {
    let mut raw = proxy_line(circuit);
    raw.push_str(&format!("{} {} HTTP/1.1\r\nHost: test.onion\r\n{}", method, target, extra));
    if let Some(c) = cookie {
        raw.push_str(&format!("Cookie: {}={}\r\n", COOKIE, c));
    }
    match body {
        Some(b) => raw.push_str(&format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{}",
            b.len(),
            b
        )),
        None => raw.push_str("\r\n"),
    }
    let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

fn is_challenge(resp: &str) -> bool {
    resp.starts_with("HTTP/1.1 200") && resp.contains("action=\"/__gate/verify\"")
}

fn token_of(resp: &str) -> Token {
    let key = "name=\"t\" value=\"";
    let i = resp.find(key).expect("no token in page") + key.len();
    from_hex(&resp[i..i + 32]).expect("bad token")
}

fn pass_of(resp: &str) -> String {
    let key = format!("Set-Cookie: {}=", COOKIE);
    let i = resp.find(&key).expect("no pass cookie") + key.len();
    resp[i..i + 32].to_string()
}

/// The undistorted click point for a registered challenge token.
fn click_body(app: &App, tok: &Token) -> String {
    let s = app.store.peek(tok).expect("token not registered");
    let (x, y) = s.warp.invert(s.cx, s.cy);
    format!("t={}&c.x={}&c.y={}", to_hex(tok), x.round() as i32, y.round() as i32)
}

/// Solves every round starting from a challenge page, returns the final reply.
fn solve(port: u16, app: &App, circuit: u32, first: &str) -> String {
    let mut resp = first.to_string();
    for i in 0..ROUNDS {
        assert!(is_challenge(&resp), "round {}: expected a challenge, got:\n{}", i + 1, &resp[..resp.len().min(200)]);
        let body = click_body(app, &token_of(&resp));
        resp = send(port, circuit, "POST", "/__gate/verify", None, Some(&body));
    }
    resp
}

#[test]
fn full_flow_gate_then_forward_to_backend() {
    let (port, app) = start();
    let c = 0x0A0A_0A0A;

    // 1) asking for a backend path without a pass yields a challenge, in place.
    let first = send(port, c, "GET", "/dashboard?tab=1", None, None);
    assert!(is_challenge(&first), "a passless request must get a challenge");
    assert!(!first.contains("BACKEND"), "the backend must not be reached without a pass");

    // 2) solving both rounds issues a pass and 303s back to where we were.
    let done = solve(port, app.as_ref(), c, &first);
    assert!(done.starts_with("HTTP/1.1 303"), "expected a redirect, got:\n{}", &done[..done.len().min(120)]);
    assert!(done.contains("Location: /dashboard?tab=1\r\n"), "must return to the original path+query");
    let pass = pass_of(&done);

    // 3) with the pass, the same request is forwarded to the backend.
    let page = send(port, c, "GET", "/dashboard?tab=1", Some(&pass), None);
    assert!(page.starts_with("HTTP/1.1 200"));
    assert!(page.contains("BACKEND saw target=/dashboard?tab=1"), "gate must forward target verbatim");
    assert!(page.contains("pass_cookie_present=false"), "the pass cookie must be stripped before the backend");
}

#[test]
fn no_pass_hides_the_backend_on_every_path() {
    let (port, _app) = start();
    let c = 0x0B0B_0B0B;
    for path in ["/", "/secret", "/admin", "/does-not-exist"] {
        let r = send(port, c, "GET", path, None, None);
        assert!(is_challenge(&r), "{} should be gated", path);
        assert!(!r.contains("BACKEND"));
    }
}

#[test]
fn a_forged_pass_cookie_is_refused_and_cleared() {
    let (port, _app) = start();
    let c = 0x0C0C_0C0C;
    let r = send(port, c, "GET", "/", Some("ffffffffffffffffffffffffffffffff"), None);
    assert!(is_challenge(&r), "an unknown pass must fall back to a challenge");
    assert!(r.contains(&format!("Set-Cookie: {}=; Path=/; Max-Age=0", COOKIE)), "a dead cookie is deleted");
    assert!(!r.contains("BACKEND"));
}

#[test]
fn no_open_redirect_through_the_return_path() {
    let (port, app) = start();
    let c = 0x0D0D_0D0D;
    // A protocol-relative target must not become the Location after solving.
    let first = send(port, c, "GET", "//evil.onion/", None, None);
    let done = solve(port, app.as_ref(), c, &first);
    assert!(done.starts_with("HTTP/1.1 303"));
    assert!(done.contains("Location: /\r\n"), "must collapse to '/', got:\n{}", &done[..done.len().min(160)]);
    assert!(!done.contains("evil.onion"));
}

#[test]
fn header_smuggling_is_rejected() {
    let (port, _app) = start();
    // A bare LF inside the headers must not split into an extra header line.
    let raw = format!(
        "{}GET / HTTP/1.1\r\nHost: t.onion\r\nX: a\nSmuggled: 1\r\n\r\n",
        proxy_line(0x3333_3333)
    );
    let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 400"), "a lone LF in headers must be a 400, got:\n{}", &out[..out.len().min(80)]);
    assert!(!out.contains("BACKEND"));
}

#[test]
fn gate_namespace_is_reachable_without_a_pass() {
    let (port, _app) = start();
    let c = 0x0E0E_0E0E;
    let r = send(port, c, "GET", "/__gate/", None, None);
    assert!(is_challenge(&r));
    // wrong method on the verify endpoint is a clean 405
    let r = send(port, c, "GET", "/__gate/verify", None, None);
    assert!(r.starts_with("HTTP/1.1 405") && r.contains("Allow: POST"));
}

#[test]
fn a_single_wrong_round_restarts_without_a_pass() {
    let (port, app) = start();
    let c = 0x0F0F_0F0F;
    let first = send(port, c, "GET", "/x", None, None);
    // click far from the target: a fresh challenge, no pass issued.
    let tok = token_of(&first);
    let _ = app.store.peek(&tok);
    let wrong = format!("t={}&c.x=0&c.y=0", to_hex(&tok));
    let resp = send(port, c, "POST", "/__gate/verify", None, Some(&wrong));
    assert!(is_challenge(&resp), "a wrong click restarts the challenge");
    assert!(!resp.contains(&format!("Set-Cookie: {}=", COOKIE)) || resp.contains("Max-Age=0"));
}

#[test]
fn challenge_permits_run_out_per_circuit() {
    let (port, _app) = start();
    let c = 0x1111_1111;
    // CHALLENGE_BURST is 10; after that a challenge-generating request is 429.
    let mut got_429 = false;
    for _ in 0..40 {
        let r = send(port, c, "GET", "/", None, None);
        if r.starts_with("HTTP/1.1 429") {
            got_429 = true;
            break;
        }
    }
    assert!(got_429, "a circuit hammering challenges must eventually get 429");
    // a different circuit is unaffected
    let other = send(port, 0x2222_2222, "GET", "/", None, None);
    assert!(is_challenge(&other));
}

#[test]
fn solver_click_math_is_a_hit() {
    // guards the click math the other tests rely on: clicking invert(center)
    // on the distorted image lands inside the hit radius.
    let mut rng = onion_gate::rng::Rng::new();
    let ch = captcha::generate(&mut rng);
    let (x, y) = ch.secret.warp.invert(ch.secret.cx, ch.secret.cy);
    assert!(captcha::is_hit(&ch.secret, x, y));
}

/// Solves the CAPTCHA from circuit `c` and returns a valid pass.
fn pass_for(port: u16, app: &App, c: u32) -> String {
    let first = send(port, c, "GET", "/", None, None);
    pass_of(&solve(port, app, c, &first))
}

#[test]
fn post_body_reaches_the_backend_intact() {
    let (port, app) = start();
    let c = 0x4444_4444;
    let pass = pass_for(port, app.as_ref(), c);
    let r = send_with(port, c, "POST", "/form", Some(&pass), Some("name=a&x=1"), "Expect: 100-continue\r\n");
    assert!(r.starts_with("HTTP/1.1 200"), "{}", &r[..r.len().min(120)]);
    assert!(r.contains("target=/form") && r.contains("body=name=a&x=1"), "{}", r);
    assert!(r.contains("expect_present=false"), "Expect must not reach the backend");
    assert!(r.contains("pass_cookie_present=false"));
}

#[test]
fn a_backend_that_keeps_the_connection_open_is_not_waited_on() {
    let (port, app) = start_with(true);
    let c = 0x5555_5555;
    let pass = pass_for(port, app.as_ref(), c);
    let t0 = std::time::Instant::now();
    let r = send(port, c, "GET", "/slow-close", Some(&pass), None);
    assert!(r.starts_with("HTTP/1.1 200") && r.contains("target=/slow-close"), "{}", &r[..r.len().min(120)]);
    // The backend lingers 20 s; the gate must stop at Content-Length.
    assert!(t0.elapsed() < Duration::from_secs(4), "took {:?}", t0.elapsed());
}

#[test]
fn an_unreachable_backend_is_a_502_not_a_hang() {
    // Bind and drop a listener to get a loopback port nobody listens on.
    let dead = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().to_string();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Arc::new(App {
        store: Store::new(),
        limiter: Limiter::new(),
        upstream: Upstream::new(&dead, COOKIE).unwrap(),
        proxy: true,
        max_body: 64 * 1024,
    });
    let a = Arc::clone(&app);
    thread::spawn(move || {
        for s in listener.incoming().flatten() {
            let a2 = Arc::clone(&a);
            thread::spawn(move || {
                let mut s = s;
                serve_connection(&mut s, &a2);
            });
        }
    });
    let c = 0x6666_6666;
    let pass = pass_for(port, app.as_ref(), c);
    let r = send(port, c, "GET", "/", Some(&pass), None);
    assert!(r.starts_with("HTTP/1.1 502"), "{}", &r[..r.len().min(120)]);
}

#[test]
fn a_page_with_many_assets_does_not_revoke_the_pass() {
    // One page view = the HTML plus ~25 assets, all on one circuit and pass.
    let (port, app) = start();
    let c = 0x7777_7777;
    let pass = pass_for(port, app.as_ref(), c);
    for i in 0..26 {
        let r = send(port, c, "GET", &format!("/asset/{}", i), Some(&pass), None);
        assert!(r.starts_with("HTTP/1.1 200") && r.contains("BACKEND"), "request {} was gated", i);
    }
}

