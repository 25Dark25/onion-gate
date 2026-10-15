//! In-memory state: pending challenges and session "passes".
//!
//! Properties:
//!  - A challenge token is consumed (DELETED) on the first verification
//!    attempt, whether it succeeds or fails. No retries on the same token.
//!  - Strict expiry (CHALLENGE_TTL + GRACE), checked on every use.
//!  - Each challenge carries the path to return to once the CAPTCHA is passed.
//!    It is the sanitized request path (see `safe_return_path` in lib.rs): always a
//!    same-origin absolute path, so it can never become an open redirect. It is
//!    stored here, bound to the token, never echoed through the client.
//!  - A pass dies after PASS_IDLE without use or PASS_MAX after it was issued,
//!    whichever comes first. Each pass has a request budget (token bucket);
//!    spending it all REVOKES the pass.
//!  - Bounded memory: once the maximum is reached, new entries are refused
//!    instead of growing without limit.
//!  - Nothing is written to disk; restarting the process invalidates everything.

use crate::captcha::Secret;
use crate::config::Limits;
use crate::limit::Bucket;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub type Token = [u8; 16];

// Defaults of the configurable settings (config.rs takes its defaults from
// here; the binary can override them).

/// VISIBLE lifetime of a challenge: how long the page's progress bar lasts.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(30);
/// Extra server-side margin for Tor latency (the bar starts when the browser
/// finishes receiving the page, and the click takes time to arrive).
const GRACE: Duration = Duration::from_secs(5);
/// A pass not used for this long expires (sliding: every page view renews it).
pub const PASS_IDLE: Duration = Duration::from_secs(30 * 60);
/// Hard lifetime of a pass, however active it is. Bounds how long a shared or
/// stolen pass stays useful.
pub const PASS_MAX: Duration = Duration::from_secs(2 * 60 * 60);
/// Requests a pass may make in one burst. Every request counts, assets
/// included: a page with ~20 assets, a few tabs at once...
pub const PASS_BURST: f32 = 60.0;
/// ...and the sustained rate: 1 per second (60 per minute), about three pages
/// of ~20 requests each per minute. A scraper going faster is cut.
pub const PASS_REFILL_PER_SEC: f32 = 1.0;

const MAX_CHALLENGES: usize = 20_000;
const MAX_PASSES: usize = 20_000;
const PURGE_EVERY: Duration = Duration::from_secs(1);

pub struct Pending {
    /// Center, hit radius and distortion parameters (secret).
    pub secret: Secret,
    /// Rounds still to pass, including this challenge's (>= 1).
    pub rounds_left: u8,
    /// Where to send the visitor after the last round: a sanitized, same-origin
    /// absolute path (see `safe_return_path` in lib.rs).
    pub ret: String,
    expires: Instant,
}

struct Pass {
    issued: Instant,
    last_used: Instant,
    budget: Bucket,
}

impl Pass {
    fn alive(&self, now: Instant, l: &PassLimits) -> bool {
        let age = now.checked_duration_since(self.issued).unwrap_or(Duration::ZERO);
        let idle = now.checked_duration_since(self.last_used).unwrap_or(Duration::ZERO);
        age < l.max && idle < l.idle
    }
}

/// The pass settings in force (from the configuration).
#[derive(Clone, Copy)]
struct PassLimits {
    idle: Duration,
    max: Duration,
    burst: f32,
    per_sec: f32,
}

/// Result of presenting a pass with a page request.
#[derive(Debug, PartialEq, Eq)]
pub enum PassUse {
    /// Valid; one request charged to its budget.
    Ok,
    /// Unknown, expired or already revoked.
    Invalid,
    /// It was valid but its request budget ran out: it has just been revoked.
    Exhausted,
}

struct Inner {
    challenges: HashMap<Token, Pending>,
    passes: HashMap<Token, Pass>,
    last_purge: Instant,
}

impl Inner {
    /// Removes expired entries, at most once per second
    /// (stops an attacker from turning every request into an O(n) sweep).
    fn purge(&mut self, now: Instant, l: &PassLimits) {
        match now.checked_duration_since(self.last_purge) {
            Some(d) if d >= PURGE_EVERY => {}
            _ => return,
        }
        self.last_purge = now;
        self.challenges.retain(|_, p| p.expires > now);
        self.passes.retain(|_, p| p.alive(now, l));
    }
}

pub struct Store {
    inner: Mutex<Inner>,
    /// Visible lifetime of a challenge (GRACE is added on top).
    ttl: Duration,
    pass: PassLimits,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    /// A store with the default settings.
    pub fn new() -> Store {
        Self::with_limits(&Limits::default())
    }

    /// A store with the configured challenge lifetime and pass budget.
    pub fn with_limits(l: &Limits) -> Store {
        Store {
            inner: Mutex::new(Inner {
                challenges: HashMap::new(),
                passes: HashMap::new(),
                last_purge: Instant::now(),
            }),
            ttl: l.challenge_ttl,
            pass: PassLimits {
                idle: l.pass_idle,
                max: l.pass_max,
                burst: l.pass_burst as f32,
                per_sec: l.pass_per_sec(),
            },
        }
    }

    /// If a thread panicked while holding the lock, keep using the data
    /// (it is consistent: every operation is atomic on the HashMap).
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Registers a challenge. Returns false if the store is full.
    pub fn add_challenge(&self, token: Token, secret: Secret, rounds_left: u8, ret: String) -> bool {
        self.add_challenge_at(Instant::now(), token, secret, rounds_left, ret)
    }

    fn add_challenge_at(
        &self,
        now: Instant,
        token: Token,
        secret: Secret,
        rounds_left: u8,
        ret: String,
    ) -> bool {
        let mut g = self.lock();
        if g.challenges.len() >= MAX_CHALLENGES {
            g.purge(now, &self.pass);
            if g.challenges.len() >= MAX_CHALLENGES {
                return false;
            }
        }
        g.challenges.insert(
            token,
            Pending {
                secret,
                rounds_left,
                ret,
                expires: now + self.ttl + GRACE,
            },
        );
        true
    }

    /// Consumes the challenge: it is ALWAYS deleted. Returns None if it does
    /// not exist or has expired.
    pub fn take_challenge(&self, token: &Token) -> Option<Pending> {
        self.take_challenge_at(Instant::now(), token)
    }

    fn take_challenge_at(&self, now: Instant, token: &Token) -> Option<Pending> {
        let p = self.lock().challenges.remove(token)?;
        if p.expires > now {
            Some(p)
        } else {
            None
        }
    }

    /// Registers a session pass. Returns false if the store is full.
    pub fn add_pass(&self, token: Token) -> bool {
        self.add_pass_at(Instant::now(), token)
    }

    fn add_pass_at(&self, now: Instant, token: Token) -> bool {
        let mut g = self.lock();
        if g.passes.len() >= MAX_PASSES {
            g.purge(now, &self.pass);
            if g.passes.len() >= MAX_PASSES {
                return false;
            }
        }
        g.passes.insert(
            token,
            Pass {
                issued: now,
                last_used: now,
                budget: Bucket::full(self.pass.burst, now),
            },
        );
        true
    }

    /// Presents the pass with a page request: checks it, renews its idle
    /// timer and charges one request to its budget. A dead pass is deleted;
    /// an exhausted one is revoked (also deleted).
    pub fn use_pass(&self, token: &Token) -> PassUse {
        self.use_pass_at(Instant::now(), token)
    }

    fn use_pass_at(&self, now: Instant, token: &Token) -> PassUse {
        let mut g = self.lock();
        let p = match g.passes.get_mut(token) {
            Some(p) => p,
            None => return PassUse::Invalid,
        };
        if !p.alive(now, &self.pass) {
            g.passes.remove(token);
            return PassUse::Invalid;
        }
        if !p.budget.take(now, self.pass.burst, self.pass.per_sec) {
            g.passes.remove(token);
            return PassUse::Exhausted;
        }
        if now > p.last_used {
            p.last_used = now;
        }
        PassUse::Ok
    }

    /// Is the pass registered and alive? Charges nothing and renews nothing.
    pub fn pass_alive(&self, token: &Token) -> bool {
        let now = Instant::now();
        self.lock().passes.get(token).is_some_and(|p| p.alive(now, &self.pass))
    }

    /// Revokes a pass (e.g. its circuit went over the page limit).
    pub fn revoke_pass(&self, token: &Token) {
        self.lock().passes.remove(token);
    }

    /// (pending challenges, passes held): for the metrics.
    pub fn sizes(&self) -> (usize, usize) {
        let g = self.lock();
        (g.challenges.len(), g.passes.len())
    }

    /// The secret of a registered challenge (its undistorted click target).
    /// Exposed so an integration test (or a harness) can solve a challenge.
    pub fn peek(&self, token: &Token) -> Option<Secret> {
        self.lock().challenges.get(token).map(|p| p.secret)
    }

    #[cfg(test)]
    pub fn has_pass(&self, token: &Token) -> bool {
        self.lock().passes.contains_key(token)
    }
}

// ------------------------------------------------------------------ hex

pub fn to_hex(t: &Token) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(32);
    for &b in t.iter() {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

/// Strict: exactly 32 lowercase hex digits.
pub fn from_hex(s: &str) -> Option<Token> {
    let b = s.as_bytes();
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = nibble(b[2 * i])?;
        let lo = nibble(b[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::captcha::Warp;

    fn sec(cx: f32) -> Secret {
        Secret {
            cx,
            cy: 20.0,
            hit_r: 30.0,
            warp: Warp::identity(),
        }
    }

    const T1: Token = [1u8; 16];
    const T2: Token = [2u8; 16];

    #[test]
    fn single_use() {
        let s = Store::new();
        assert!(s.add_challenge(T1, sec(10.0), 2, "/about".to_string()));
        let p = s.take_challenge(&T1).expect("should exist");
        assert_eq!((p.secret.cx, p.secret.cy, p.secret.hit_r, p.rounds_left), (10.0, 20.0, 30.0, 2));
        assert_eq!(p.ret, "/about");
        assert!(s.take_challenge(&T1).is_none(), "token was reused");
    }

    #[test]
    fn unknown_token() {
        let s = Store::new();
        assert!(s.take_challenge(&T2).is_none());
    }

    #[test]
    fn expires_and_is_deleted_anyway() {
        let s = Store::new();
        s.add_challenge(T1, sec(1.0), 1, "/".to_string());
        let late = Instant::now() + CHALLENGE_TTL + GRACE + Duration::from_secs(1);
        assert!(s.take_challenge_at(late, &T1).is_none());
        // and it can no longer be used even if we "go back" to a valid instant
        assert!(s.take_challenge(&T1).is_none());
    }

    #[test]
    fn valid_within_ttl() {
        let s = Store::new();
        s.add_challenge(T1, sec(1.0), 1, "/".to_string());
        let almost = Instant::now() + CHALLENGE_TTL + GRACE - Duration::from_secs(2);
        assert!(s.take_challenge_at(almost, &T1).is_some());
    }

    #[test]
    fn grace_is_short_and_bounded() {
        let s = Store::new();
        s.add_challenge(T1, sec(1.0), 1, "/".to_string());
        // at the visual limit (30 s) it is still valid, thanks to the margin
        let at_30 = Instant::now() + CHALLENGE_TTL;
        assert!(s.take_challenge_at(at_30, &T1).is_some());
        s.add_challenge(T2, sec(1.0), 1, "/".to_string());
        // past the grace period it is not
        let past = Instant::now() + CHALLENGE_TTL + GRACE + Duration::from_millis(500);
        assert!(s.take_challenge_at(past, &T2).is_none());
    }

    #[test]
    fn memory_limit() {
        let s = Store::new();
        let now = Instant::now();
        for i in 0..MAX_CHALLENGES {
            let mut t = [0u8; 16];
            t[..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(s.add_challenge_at(now, t, sec(0.0), 1, "/".to_string()));
        }
        // full and nothing has expired yet -> refused
        assert!(!s.add_challenge_at(now, T1, sec(0.0), 1, "/".to_string()));
        // once everything expired (and the purge interval passed) it accepts again
        let late = now + CHALLENGE_TTL + GRACE + Duration::from_secs(5);
        assert!(s.add_challenge_at(late, T1, sec(0.0), 1, "/".to_string()));
    }

    #[test]
    fn passes() {
        let s = Store::new();
        assert_eq!(s.use_pass(&T1), PassUse::Invalid);
        assert!(s.add_pass(T1));
        assert_eq!(s.use_pass(&T1), PassUse::Ok);
        assert_eq!(s.use_pass(&T2), PassUse::Invalid);
    }

    #[test]
    fn pass_idle_timeout_is_sliding() {
        let s = Store::new();
        let t0 = Instant::now();
        assert!(s.add_pass_at(t0, T1));
        // used every 20 min: it never reaches PASS_IDLE (30 min) of inactivity
        let mut t = t0;
        for _ in 0..4 {
            t += Duration::from_secs(20 * 60);
            assert_eq!(s.use_pass_at(t, &T1), PassUse::Ok);
        }
        // now 31 min without use: expired and deleted
        t += PASS_IDLE + Duration::from_secs(60);
        assert_eq!(s.use_pass_at(t, &T1), PassUse::Invalid);
        assert!(!s.has_pass(&T1));
    }

    #[test]
    fn pass_has_a_hard_lifetime() {
        let s = Store::new();
        let t0 = Instant::now();
        assert!(s.add_pass_at(t0, T1));
        // kept active every 10 min, it still dies at PASS_MAX
        let mut t = t0;
        while t + Duration::from_secs(10 * 60) < t0 + PASS_MAX {
            t += Duration::from_secs(10 * 60);
            assert_eq!(s.use_pass_at(t, &T1), PassUse::Ok);
        }
        assert_eq!(s.use_pass_at(t0 + PASS_MAX, &T1), PassUse::Invalid);
        assert!(!s.has_pass(&T1));
    }

    #[test]
    fn pass_budget_exhaustion_revokes_it() {
        let s = Store::new();
        let t0 = Instant::now();
        assert!(s.add_pass_at(t0, T1));
        for _ in 0..PASS_BURST as usize {
            assert_eq!(s.use_pass_at(t0, &T1), PassUse::Ok);
        }
        assert_eq!(s.use_pass_at(t0, &T1), PassUse::Exhausted);
        assert!(!s.has_pass(&T1), "an exhausted pass must be revoked");
        // revoked for good: waiting does not bring it back
        let later = t0 + Duration::from_secs(600);
        assert_eq!(s.use_pass_at(later, &T1), PassUse::Invalid);
    }

    #[test]
    fn pass_budget_refills_at_reading_pace() {
        let s = Store::new();
        let t0 = Instant::now();
        assert!(s.add_pass_at(t0, T1));
        // one request per second forever never runs out (sustained rate)
        let mut t = t0;
        for _ in 0..200 {
            t += Duration::from_secs(1);
            assert_eq!(s.use_pass_at(t, &T1), PassUse::Ok);
        }
        // three requests per second run out after roughly burst / (3 - 1) s
        let t1 = t;
        let mut served = 0;
        'outer: for k in 1..=100u64 {
            for _ in 0..3 {
                match s.use_pass_at(t1 + Duration::from_secs(k), &T1) {
                    PassUse::Ok => served += 1,
                    PassUse::Exhausted => break 'outer,
                    PassUse::Invalid => panic!("unexpected"),
                }
            }
        }
        // burst 60, refilled 1 per second, spent 3 per second: ~90 requests
        assert!((85..=95).contains(&served), "served {}", served);
    }

    #[test]
    fn revoke_pass_works() {
        let s = Store::new();
        assert!(s.add_pass(T1));
        assert!(s.add_pass(T2));
        assert!(s.pass_alive(&T1));
        s.revoke_pass(&T1);
        assert!(!s.pass_alive(&T1));
        assert_eq!(s.use_pass(&T1), PassUse::Invalid);
        assert_eq!(s.use_pass(&T2), PassUse::Ok);
    }

    #[test]
    fn pass_memory_limit() {
        let s = Store::new();
        let now = Instant::now();
        for i in 0..MAX_PASSES {
            let mut t = [0u8; 16];
            t[..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(s.add_pass_at(now, t));
        }
        assert!(!s.add_pass_at(now, T1), "full store must refuse");
        let late = now + PASS_IDLE + Duration::from_secs(5);
        assert!(s.add_pass_at(late, T1), "expired passes must make room");
    }

    #[test]
    fn hex_round_trip() {
        let t: Token = [0x00, 0x01, 0xAB, 0xFF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0];
        let h = to_hex(&t);
        assert_eq!(h, "0001abff102030405060708090a0b0c0");
        assert_eq!(from_hex(&h), Some(t));
    }

    #[test]
    fn hex_is_strict() {
        assert!(from_hex("").is_none());
        assert!(from_hex("zz01abff102030405060708090a0b0c0").is_none());
        assert!(from_hex("0001ABFF102030405060708090A0B0C0").is_none()); // no uppercase
        assert!(from_hex("0001abff102030405060708090a0b0c").is_none()); // 31
        assert!(from_hex("0001abff102030405060708090a0b0c0f").is_none()); // 33
        // 30 ASCII + 'e with accent' (2 UTF-8 bytes) = 32 bytes, but not hex
        assert!(from_hex("0001abff102030405060708090a0b0\u{e9}").is_none());
    }
}
