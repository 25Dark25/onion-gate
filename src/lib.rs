//! onion-gate: a no-JavaScript CAPTCHA gate and reverse proxy for a .onion (or
//! any loopback) backend.
//!
//! A visitor cannot reach the backend until they pass a "click the broken
//! circle" CAPTCHA. Once they do, the gate holds a short-lived session pass and
//! forwards their requests to the backend; per-Tor-circuit limits throttle
//! abuse. Everything here is std-only, listens on loopback, and never runs
//! JavaScript in the browser.
//!
//! This crate is a library (the pieces) plus a thin binary (`main.rs`). The
//! integration tests drive the same `serve_connection` the binary uses.

// Randomness comes from /dev/urandom (std has no portable CSPRNG), so the gate
// needs a Unix system. Fail the build elsewhere rather than panic at run time.
#[cfg(not(unix))]
compile_error!("onion-gate needs a Unix-like system (Linux, macOS, BSD): it reads randomness from /dev/urandom");

pub mod captcha;
pub mod html;
pub mod http;
pub mod limit;
pub mod png;
pub mod rng;
pub mod store;
pub mod upstream;

use http::{HttpError, Reply, Request};
use limit::Limiter;
use rng::Rng;
use std::net::TcpStream;
use store::{PassUse, Store, Token};
use upstream::Upstream;

/// Consecutive CAPTCHA rounds required. A failure restarts the chain.
pub const ROUNDS: u8 = 2;
/// Name of the session pass cookie.
pub const COOKIE: &str = "onion_gate_pass";
/// The gate's own reserved namespace. Requests here are the gate itself and are
/// never forwarded, so the backend must not use this prefix.
pub const GATE_PREFIX: &str = "/__gate/";
/// Where the challenge form posts (inside GATE_PREFIX).
pub const VERIFY_PATH: &str = "/__gate/verify";

const MSG_FAIL: &str = "Wrong or expired. Try this new image.";
const MSG_NEXT: &str = "Correct. One more.";
const MSG_BUSY: &str = "Service busy. Try again in a few seconds.";
const MSG_SLOW: &str = "Too many requests from your connection. Wait a minute.";
const MSG_RATE: &str = "Too many requests in a short time. Please verify again.";
const MSG_GATEWAY: &str = "The site behind the gate did not respond. Try again shortly.";

/// Shared state for all connections.
pub struct App {
    pub store: Store,
    pub limiter: Limiter,
    /// The backend requests are forwarded to once a pass is held.
    pub upstream: Upstream,
    /// true = every connection starts with tor's PROXY line (mandatory then).
    pub proxy: bool,
    /// Largest request body accepted (and thus forwarded).
    pub max_body: usize,
}

/// What `route` produces: either a page the gate generated, or already-framed
/// bytes from the upstream to relay verbatim.
pub enum Out {
    Reply(Reply),
    Raw(Vec<u8>),
}

// --------------------------------------------------------------- return path

/// Sanitizes the path to return to after the CAPTCHA. The result is always a
/// same-origin absolute path, so it can never become an open redirect. Anything
/// suspicious collapses to "/". Stored server-side, bound to the token; the
/// client never gets to pick the final `Location` freely.
pub fn safe_return_path(target: &str) -> String {
    let ok = target.starts_with('/')
        && !target.starts_with("//")
        && !target.starts_with("/\\")
        && target.len() <= 1024
        && target.bytes().all(|b| (0x21..=0x7E).contains(&b)); // visible ASCII, no spaces/controls
    if ok {
        target.to_string()
    } else {
        "/".to_string()
    }
}

// --------------------------------------------------------------- cookies

fn pass_cookie(pass: &Token) -> String {
    format!("{}={}; Path=/; HttpOnly; SameSite=Lax", COOKIE, store::to_hex(pass))
}

fn clear_cookie() -> String {
    format!("{}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax", COOKIE)
}

// --------------------------------------------------------------- replies

fn too_many() -> Reply {
    let mut r = Reply::page(429, html::message(MSG_SLOW));
    r.extra.push(("Retry-After", "60".to_string()));
    r
}

fn method_not_allowed(allow: &'static str) -> Reply {
    let mut r = Reply::page(405, html::message("Error 405"));
    r.extra.push(("Allow", allow.to_string()));
    r
}

/// Every image costs CPU: generating one consumes a circuit challenge permit.
fn challenge_allowed(app: &App, circuit: Option<u32>) -> bool {
    circuit.is_none_or(|c| app.limiter.take(c))
}

// --------------------------------------------------------------- serving

/// Handles one connection end to end: the PROXY line (proxy mode), the
/// per-circuit connection slot, one request, and the reply.
pub fn serve_connection(stream: &mut TcpStream, app: &App) {
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(30)));

    let (circuit, initial) = if app.proxy {
        match http::read_proxy(stream) {
            Ok((c, rest)) => (Some(c), rest),
            Err(_) => {
                http::close(stream);
                return;
            }
        }
    } else {
        (None, Vec::new())
    };

    let _slot = match circuit {
        Some(c) => match app.limiter.enter(c) {
            Some(slot) => Some(slot),
            None => {
                http::send(stream, &too_many());
                http::close(stream);
                return;
            }
        },
        None => None,
    };

    match http::read_request(stream, initial, app.max_body) {
        Ok(req) => match route(&req, circuit, app) {
            Out::Reply(r) => http::send(stream, &r),
            Out::Raw(bytes) => http::send_raw(stream, &bytes),
        },
        Err(e) => {
            if let Some(reply) = error_reply(&e) {
                http::send(stream, &reply);
            }
        }
    }
    http::close(stream);
}

fn error_reply(e: &HttpError) -> Option<Reply> {
    let status = e.status()?;
    let mut r = Reply::page(status, html::message(&format!("Error {}", status)));
    if status == 405 {
        r.extra.push(("Allow", "GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS".to_string()));
    }
    Some(r)
}

/// Routes one parsed request.
pub fn route(req: &Request, circuit: Option<u32>, app: &App) -> Out {
    let path = req.path.as_str();
    if path == GATE_PREFIX.trim_end_matches('/') || path.starts_with(GATE_PREFIX) {
        Out::Reply(gate_route(req, circuit, app))
    } else {
        gated(req, circuit, app)
    }
}

/// The gate's own namespace: the challenge and its verification. Reachable
/// without a pass (it IS the gate); never forwarded.
fn gate_route(req: &Request, circuit: Option<u32>, app: &App) -> Reply {
    match (req.is_get(), req.is_post(), req.path.as_str()) {
        (true, _, p) if p == GATE_PREFIX => {
            if !challenge_allowed(app, circuit) {
                return too_many();
            }
            new_challenge(&app.store, ROUNDS, "", "/".to_string())
        }
        (_, true, VERIFY_PATH) => {
            if !challenge_allowed(app, circuit) {
                return too_many();
            }
            verify(req, &app.store)
        }
        (_, _, VERIFY_PATH) => method_not_allowed("POST"),
        (_, _, p) if p == GATE_PREFIX => method_not_allowed("GET"),
        _ => Reply::page(404, html::message("Error 404")),
    }
}

/// Everything that is not the gate's namespace: the backend, behind the gate.
/// Without a valid pass the answer is always a challenge (the backend is never
/// reached, and nothing about it is revealed).
fn gated(req: &Request, circuit: Option<u32>, app: &App) -> Out {
    // Where to send the visitor after they pass. A non-GET cannot be replayed,
    // so it returns to "/".
    let ret = if req.is_get() {
        safe_return_path(&req.target)
    } else {
        "/".to_string()
    };

    let presented = req.cookie.as_deref().and_then(|c| http::cookie_get(c, COOKIE));
    let pass = match presented {
        None => return Out::Reply(gate(app, circuit, "", ret, false)),
        Some(v) => match store::from_hex(v) {
            Some(t) => t,
            None => return Out::Reply(gate(app, circuit, "", ret, true)),
        },
    };
    match app.store.use_pass(&pass) {
        PassUse::Ok => {}
        PassUse::Invalid => return Out::Reply(gate(app, circuit, "", ret, true)),
        PassUse::Exhausted => return Out::Reply(gate(app, circuit, MSG_RATE, ret, true)),
    }
    // The circuit's own page budget (catches several passes on one circuit).
    if let Some(c) = circuit {
        if !app.limiter.take_page(c) {
            app.store.revoke_pass(&pass);
            return Out::Reply(gate(app, circuit, MSG_RATE, ret, true));
        }
    }

    // Valid pass: forward to the backend.
    match app.upstream.forward(req) {
        Ok(bytes) => Out::Raw(bytes),
        Err(e) => Out::Reply(Reply::page(e.status(), html::message(MSG_GATEWAY))),
    }
}

/// Serves a challenge in place (200). `clear` deletes a dead pass cookie.
fn gate(app: &App, circuit: Option<u32>, notice: &str, ret: String, clear: bool) -> Reply {
    let mut r = if challenge_allowed(app, circuit) {
        new_challenge(&app.store, ROUNDS, notice, ret)
    } else {
        too_many()
    };
    if clear {
        r.extra.push(("Set-Cookie", clear_cookie()));
    }
    r
}

/// Generates a challenge, registers it and returns the page.
fn new_challenge(store: &Store, rounds_left: u8, notice: &str, ret: String) -> Reply {
    let rounds_left = rounds_left.clamp(1, ROUNDS);
    let mut rng = Rng::new();
    let ch = captcha::generate(&mut rng);
    let token = rng.token();
    if !store.add_challenge(token, ch.secret, rounds_left, ret) {
        return Reply::page(503, html::message(MSG_BUSY));
    }
    let page = html::challenge(
        &html::base64(&ch.png),
        &store::to_hex(&token),
        ROUNDS - rounds_left + 1,
        ROUNDS,
        notice,
    );
    Reply::page(200, page)
}

fn verify(req: &Request, store: &Store) -> Reply {
    let body = std::str::from_utf8(&req.body).unwrap_or("");

    // 1) The token is CONSUMED before anything else: one attempt per token.
    let pending = http::form_get(body, "t")
        .and_then(store::from_hex)
        .and_then(|t| store.take_challenge(&t));
    let pending = match pending {
        Some(p) => p,
        None => return new_challenge(store, ROUNDS, MSG_FAIL, "/".to_string()),
    };

    // 2) Strict coordinates; anything odd = generic failure.
    let x = parse_coord(http::form_get(body, "c.x"));
    let y = parse_coord(http::form_get(body, "c.y"));
    let ok = match (x, y) {
        (Some(x), Some(y)) => captcha::is_hit(&pending.secret, x, y),
        _ => false,
    };

    // 3) Same message for every failure: the reason is never revealed. A
    //    failure restarts from round 1 with a new image, keeping the return path.
    if !ok {
        return new_challenge(store, ROUNDS, MSG_FAIL, pending.ret);
    }
    if pending.rounds_left > 1 {
        return new_challenge(store, pending.rounds_left - 1, MSG_NEXT, pending.ret);
    }

    // 4) Passed: issue a session pass and 303 (POST -> GET) to the stored path.
    let mut rng = Rng::new();
    let pass = rng.token();
    if !store.add_pass(pass) {
        return Reply::page(503, html::message(MSG_BUSY));
    }
    let mut r = Reply::redirect(pending.ret);
    r.extra.push(("Set-Cookie", pass_cookie(&pass)));
    r
}

/// Digits and a dot only (accepts "123" and "123.5"; rejects "inf", "nan",
/// "1e9", "-3").
fn parse_coord(v: Option<&str>) -> Option<f32> {
    let s = v?;
    if s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    s.parse::<f32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_path_allows_same_origin_paths() {
        assert_eq!(safe_return_path("/"), "/");
        assert_eq!(safe_return_path("/products"), "/products");
        assert_eq!(safe_return_path("/a/b/c?x=1&y=2"), "/a/b/c?x=1&y=2");
    }

    #[test]
    fn return_path_rejects_open_redirects_and_junk() {
        for bad in [
            "//evil.onion",      // protocol-relative
            "/\\evil.onion",     // backslash trick
            "https://evil",      // absolute URL (no leading slash anyway)
            "evil",              // no leading slash
            "",                  // empty
        ] {
            assert_eq!(safe_return_path(bad), "/", "{:?} must collapse to /", bad);
        }
        // overly long collapses to /
        let long = format!("/{}", "a".repeat(2000));
        assert_eq!(safe_return_path(&long), "/");
    }

    #[test]
    fn parse_coord_is_strict() {
        assert_eq!(parse_coord(Some("150")), Some(150.0));
        assert_eq!(parse_coord(Some("12.5")), Some(12.5));
        for bad in ["", "-3", "1e9", "inf", "NaN", "0x10", "12 ", "1234567890123"] {
            assert_eq!(parse_coord(Some(bad)), None, "{:?}", bad);
        }
    }
}
