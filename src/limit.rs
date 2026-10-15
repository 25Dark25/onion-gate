//! Per-Tor-circuit limits.
//!
//! Every connection arrives from 127.0.0.1, so the IP cannot tell clients
//! apart. With `HiddenServiceExportCircuitID haproxy`, tor prefixes each
//! connection with a PROXY line carrying the visitor's circuit identifier.
//! This module limits by that identifier:
//!
//!  - simultaneous connections per circuit (stops single-client slowloris),
//!  - challenges generated per circuit (token bucket: stops CPU abuse and
//!    filling the challenge store),
//!  - site pages served per circuit (token bucket: stops one circuit from
//!    hammering the site with several passes; see `gated` in lib.rs for what happens
//!    when it runs out).
//!
//! To take the service down, an attacker needs many circuits, and every new
//! circuit goes through tor's defenses (PoW included).
//! Policy: when in doubt, deny (fail-closed).
//!
//! The constants below are the defaults; the configuration (config.rs) can
//! change them, and checks the rules between them at start-up.

use crate::config::Limits;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Connections open at the same time from one circuit. There is no keep-alive,
/// so every request of a page (HTML, CSS, scripts, images) is its own
/// connection; browsers open about 6 in parallel per host. 8 leaves margin while
/// still bounding how many slow connections one circuit can hold (slowloris).
pub const MAX_CONN_PER_CIRCUIT: u16 = 8;
/// Challenges a circuit may request in one burst...
pub const CHALLENGE_BURST: f32 = 10.0;
/// ...and the sustained rate: 1 every 6 s (10 per minute).
pub const CHALLENGE_REFILL_PER_SEC: f32 = 1.0 / 6.0;
/// Forwarded requests a circuit may make in one burst (a page and its assets,
/// several tabs at once)...
pub const CIRCUIT_PAGE_BURST: f32 = 90.0;
/// ...and the sustained rate: 1.5 per second (90 per minute). Deliberately
/// looser than the per-pass limit (store.rs), so an honest visitor never hits
/// this one first.
pub const CIRCUIT_PAGE_REFILL_PER_SEC: f32 = 1.5;
/// Maximum number of circuits remembered (bounded memory).
const MAX_ENTRIES: usize = 50_000;
/// A circuit idle for this long is forgotten. Must be at least the time any
/// bucket needs to refill completely, or forgetting would hand back a full
/// bucket early (with the defaults: challenges 60 s, pages 60 s). The limiter
/// raises it when the configured buckets take longer.
const IDLE_FORGET: Duration = Duration::from_secs(600);
const PURGE_EVERY: Duration = Duration::from_secs(1);

/// Token bucket: starts full with `burst` tokens and refills continuously at
/// `per_sec`, never above `burst`. Shared with store.rs (per-pass limit).
#[derive(Clone, Copy)]
pub struct Bucket {
    tokens: f32,
    last: Instant,
}

impl Bucket {
    pub fn full(burst: f32, now: Instant) -> Bucket {
        Bucket { tokens: burst, last: now }
    }

    /// Takes one token. false = empty (nothing is taken).
    pub fn take(&mut self, now: Instant, burst: f32, per_sec: f32) -> bool {
        // A clock that goes "backwards" (now < last) refills nothing.
        let dt = now
            .checked_duration_since(self.last)
            .map_or(0.0, |d| d.as_secs_f32());
        self.tokens = (self.tokens + dt * per_sec).min(burst);
        if now > self.last {
            self.last = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct Entry {
    active: u16,
    challenges: Bucket,
    pages: Bucket,
    /// Last activity (for IDLE_FORGET).
    last: Instant,
}

struct Inner {
    map: HashMap<u32, Entry>,
    last_purge: Instant,
}

/// The per-circuit settings in force (from the configuration).
#[derive(Clone, Copy)]
struct CircuitLimits {
    conns: u16,
    challenge_burst: f32,
    challenge_per_sec: f32,
    page_burst: f32,
    page_per_sec: f32,
    forget: Duration,
}

impl Inner {
    fn purge(&mut self, now: Instant, forget: Duration) {
        match now.checked_duration_since(self.last_purge) {
            Some(d) if d >= PURGE_EVERY => {}
            _ => return,
        }
        self.last_purge = now;
        self.map.retain(|_, e| {
            e.active > 0 || now.checked_duration_since(e.last).is_none_or(|d| d < forget)
        });
    }

    /// The circuit's entry, created if there is room. None if the map is full.
    fn entry(&mut self, c: u32, now: Instant, l: &CircuitLimits) -> Option<&mut Entry> {
        if !self.map.contains_key(&c) {
            if self.map.len() >= MAX_ENTRIES {
                self.purge(now, l.forget);
                if self.map.len() >= MAX_ENTRIES {
                    return None;
                }
            }
            self.map.insert(
                c,
                Entry {
                    active: 0,
                    challenges: Bucket::full(l.challenge_burst, now),
                    pages: Bucket::full(l.page_burst, now),
                    last: now,
                },
            );
        }
        let e = self.map.get_mut(&c)?;
        if now > e.last {
            e.last = now;
        }
        Some(e)
    }
}

pub struct Limiter {
    inner: Mutex<Inner>,
    limits: CircuitLimits,
}

impl Default for Limiter {
    fn default() -> Self {
        Self::new()
    }
}

/// While it exists, it counts as one open connection of the circuit.
pub struct ConnSlot<'a> {
    lim: &'a Limiter,
    circuit: u32,
}

impl Drop for ConnSlot<'_> {
    fn drop(&mut self) {
        let mut g = self.lim.lock();
        if let Some(e) = g.map.get_mut(&self.circuit) {
            e.active = e.active.saturating_sub(1);
        }
    }
}

impl Limiter {
    /// A limiter with the default settings.
    pub fn new() -> Limiter {
        Self::with_limits(&Limits::default())
    }

    /// A limiter with the configured per-circuit settings.
    pub fn with_limits(l: &Limits) -> Limiter {
        // Forgetting a circuit must not hand back a full bucket early.
        let refill = |burst: u32, per_min: u32| Duration::from_secs((burst as u64 * 60).div_ceil(per_min.max(1) as u64));
        let forget = IDLE_FORGET
            .max(refill(l.challenge_burst, l.challenge_per_minute))
            .max(refill(l.circuit_burst, l.circuit_per_minute));
        Limiter {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                last_purge: Instant::now(),
            }),
            limits: CircuitLimits {
                conns: l.conn_per_circuit,
                challenge_burst: l.challenge_burst as f32,
                challenge_per_sec: l.challenge_per_sec(),
                page_burst: l.circuit_burst as f32,
                page_per_sec: l.circuit_per_sec(),
                forget,
            },
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// How many circuits are remembered: for the metrics.
    pub fn tracked(&self) -> usize {
        self.lock().map.len()
    }

    /// Reserves a connection slot for the circuit. None = limit exceeded.
    pub fn enter(&self, circuit: u32) -> Option<ConnSlot<'_>> {
        let now = Instant::now();
        let mut g = self.lock();
        let e = g.entry(circuit, now, &self.limits)?;
        if e.active >= self.limits.conns {
            return None;
        }
        e.active += 1;
        Some(ConnSlot {
            lim: self,
            circuit,
        })
    }

    /// Consumes one permit to generate a challenge. false = too many.
    pub fn take(&self, circuit: u32) -> bool {
        self.take_at(Instant::now(), circuit)
    }

    fn take_at(&self, now: Instant, circuit: u32) -> bool {
        let mut g = self.lock();
        match g.entry(circuit, now, &self.limits) {
            Some(e) => e.challenges.take(now, self.limits.challenge_burst, self.limits.challenge_per_sec),
            None => false,
        }
    }

    /// Consumes one permit to serve a site page. false = too many.
    pub fn take_page(&self, circuit: u32) -> bool {
        self.take_page_at(Instant::now(), circuit)
    }

    fn take_page_at(&self, now: Instant, circuit: u32) -> bool {
        let mut g = self.lock();
        match g.entry(circuit, now, &self.limits) {
            Some(e) => e.pages.take(now, self.limits.page_burst, self.limits.page_per_sec),
            None => false,
        }
    }
}

// ------------------------------------------------------------ memory budget

/// Request and response bytes buffered at once, across all connections. Every
/// forwarded request and its response are held in memory (see upstream.rs);
/// without a global bound, a few visitors with a valid pass fetching large
/// files in parallel could exhaust the process's memory. Over the budget, the
/// visitor gets a 503 instead.
pub const MAX_BUFFERED: usize = 128 * 1024 * 1024;
/// The most one Tor circuit may hold of that budget. Without it, one circuit's
/// 8 connections, each holding a large response for a slow reader, could take
/// half the budget. 24 MiB fits one maximal response (8 MiB, counted twice
/// while it is re-framed) next to a page's ordinary assets.
pub const MAX_BUFFERED_PER_CIRCUIT: usize = 24 * 1024 * 1024;
/// The most one pass may hold, whatever circuits it is used from (a pass is not
/// bound to a circuit). Filling the whole budget then takes at least
/// MAX_BUFFERED / MAX_BUFFERED_PER_PASS passes, each a solved CAPTCHA.
pub const MAX_BUFFERED_PER_PASS: usize = 32 * 1024 * 1024;

/// Who a reservation is charged to, besides the global budget.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Owner {
    Circuit(u32),
    Pass([u8; 16]),
}

struct MemInner {
    used: usize,
    /// Bytes held per owner; an owner holding nothing has no entry, so the map
    /// never holds more entries than there are live reservations (x2).
    per: HashMap<Owner, usize>,
}

/// A shared byte budget, with a share per circuit and per pass. Reservations
/// give their bytes back when dropped.
pub struct Memory {
    inner: Mutex<MemInner>,
    max: usize,
    max_circuit: usize,
    max_pass: usize,
}

impl Default for Memory {
    fn default() -> Self {
        Self::with_shares(MAX_BUFFERED, MAX_BUFFERED_PER_CIRCUIT, MAX_BUFFERED_PER_PASS)
    }
}

impl Memory {
    /// A budget of `max` bytes with the default per-circuit and per-pass shares.
    pub fn new(max: usize) -> Memory {
        Self::with_shares(max, MAX_BUFFERED_PER_CIRCUIT, MAX_BUFFERED_PER_PASS)
    }

    /// The configured budget and shares.
    pub fn from_limits(l: &Limits) -> Memory {
        Self::with_shares(l.memory, l.memory_per_circuit, l.memory_per_pass)
    }

    pub fn with_shares(max: usize, max_circuit: usize, max_pass: usize) -> Memory {
        Memory {
            inner: Mutex::new(MemInner { used: 0, per: HashMap::new() }),
            max,
            max_circuit,
            max_pass,
        }
    }

    fn lock(&self) -> MutexGuard<'_, MemInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn cap(&self, o: &Owner) -> usize {
        match o {
            Owner::Circuit(_) => self.max_circuit,
            Owner::Pass(_) => self.max_pass,
        }
    }

    /// Reserves `n` bytes charged to the global budget only. None = over budget.
    pub fn reserve(&self, n: usize) -> Option<Reservation<'_>> {
        self.reserve_for(&[], n)
    }

    /// Reserves `n` bytes charged to the global budget and to each owner's
    /// share. None = some limit would be exceeded.
    pub fn reserve_for(&self, owners: &[Owner], n: usize) -> Option<Reservation<'_>> {
        let mut r = Reservation { mem: self, bytes: 0, owners: owners.to_vec() };
        if r.grow(n) {
            Some(r)
        } else {
            None
        }
    }

    /// Bytes currently reserved.
    pub fn used(&self) -> usize {
        self.lock().used
    }

    /// Bytes currently held by one owner.
    pub fn used_by(&self, o: Owner) -> usize {
        self.lock().per.get(&o).copied().unwrap_or(0)
    }

    fn release(&self, owners: &[Owner], n: usize) {
        if n == 0 {
            return;
        }
        let mut g = self.lock();
        g.used = g.used.saturating_sub(n);
        for o in owners {
            if let Some(v) = g.per.get_mut(o) {
                *v = v.saturating_sub(n);
                if *v == 0 {
                    g.per.remove(o);
                }
            }
        }
    }
}

/// Bytes held from a `Memory` budget; released on drop.
pub struct Reservation<'a> {
    mem: &'a Memory,
    bytes: usize,
    owners: Vec<Owner>,
}

impl Reservation<'_> {
    /// Adds `n` bytes to the reservation. false = over the global budget or an
    /// owner's share (nothing added).
    pub fn grow(&mut self, n: usize) -> bool {
        if n == 0 {
            return true;
        }
        let mem = self.mem;
        let mut g = mem.lock();
        let fits = |held: usize, cap: usize| held.checked_add(n).is_some_and(|t| t <= cap);
        if !fits(g.used, mem.max) {
            return false;
        }
        for o in &self.owners {
            if !fits(g.per.get(o).copied().unwrap_or(0), mem.cap(o)) {
                return false;
            }
        }
        g.used += n;
        for o in &self.owners {
            *g.per.entry(*o).or_insert(0) += n;
        }
        self.bytes += n;
        true
    }

    /// Bytes this reservation holds.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Gives back everything above `n` bytes.
    pub fn shrink_to(&mut self, n: usize) {
        if n < self.bytes {
            self.mem.release(&self.owners, self.bytes - n);
            self.bytes = n;
        }
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.mem.release(&self.owners, self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_budget_is_shared_and_released() {
        let m = Memory::new(100);
        let mut a = m.reserve(60).expect("fits");
        assert!(m.reserve(41).is_none(), "over budget");
        let b = m.reserve(40).expect("exactly fits");
        assert_eq!(m.used(), 100);
        assert!(!a.grow(1));
        drop(b);
        assert!(a.grow(30));
        a.shrink_to(10);
        assert_eq!(m.used(), 10);
        drop(a);
        assert_eq!(m.used(), 0);
        assert!(m.reserve(usize::MAX).is_none(), "no overflow");
    }

    #[test]
    fn circuit_and_pass_shares_cap_one_owner() {
        let m = Memory::with_shares(1000, 100, 150);
        let (c1, c2, p) = (Owner::Circuit(1), Owner::Circuit(2), Owner::Pass([7; 16]));
        let a = m.reserve_for(&[c1, p], 100).expect("fits the circuit share");
        assert!(m.reserve_for(&[c1], 1).is_none(), "circuit 1 is at its share");
        // the same pass from another circuit: limited by the pass share
        let b = m.reserve_for(&[c2, p], 50).expect("pass has 50 left");
        assert!(m.reserve_for(&[c2, p], 1).is_none(), "pass is at its share");
        // another pass on circuit 2 is fine
        let c = m.reserve_for(&[c2, Owner::Pass([8; 16])], 50).expect("other owners are unaffected");
        assert_eq!((m.used(), m.used_by(c1), m.used_by(c2), m.used_by(p)), (200, 100, 100, 150));
        drop((a, b, c));
        assert_eq!((m.used(), m.used_by(c1), m.used_by(p)), (0, 0, 0));
        assert!(m.lock().per.is_empty(), "no entry is kept for owners holding nothing");
    }

    #[test]
    fn connection_limit_per_circuit() {
        let l = Limiter::new();
        let mut slots = Vec::new();
        for _ in 0..MAX_CONN_PER_CIRCUIT {
            slots.push(l.enter(7).expect("should fit"));
        }
        assert!(l.enter(7).is_none(), "limit was exceeded");
        // another circuit is not affected
        assert!(l.enter(8).is_some());
        // closing one makes room again
        slots.pop();
        assert!(l.enter(7).is_some());
    }

    #[test]
    fn burst_and_refill() {
        let l = Limiter::new();
        let t0 = Instant::now();
        for _ in 0..CHALLENGE_BURST as usize {
            assert!(l.take_at(t0, 1));
        }
        assert!(!l.take_at(t0, 1), "the burst should run out");
        // another circuit has its own bucket
        assert!(l.take_at(t0, 2));
        // after 6 s there is 1 new permit, and only 1
        let t1 = t0 + Duration::from_secs(6) + Duration::from_millis(50);
        assert!(l.take_at(t1, 1));
        assert!(!l.take_at(t1, 1));
        // after a long time, at most the burst
        let t2 = t1 + Duration::from_secs(3600);
        for _ in 0..CHALLENGE_BURST as usize {
            assert!(l.take_at(t2, 1));
        }
        assert!(!l.take_at(t2, 1));
    }

    #[test]
    fn page_bucket_burst_and_refill() {
        let l = Limiter::new();
        let t0 = Instant::now();
        for _ in 0..CIRCUIT_PAGE_BURST as usize {
            assert!(l.take_page_at(t0, 1));
        }
        assert!(!l.take_page_at(t0, 1), "the page burst should run out");
        // 1 s later (1.5 tokens refilled): exactly one more request
        let t1 = t0 + Duration::from_secs(1) + Duration::from_millis(50);
        assert!(l.take_page_at(t1, 1));
        assert!(!l.take_page_at(t1, 1));
        // other circuits are unaffected
        assert!(l.take_page_at(t1, 2));
    }

    #[test]
    fn page_and_challenge_buckets_are_independent() {
        let l = Limiter::new();
        let t0 = Instant::now();
        for _ in 0..CIRCUIT_PAGE_BURST as usize {
            assert!(l.take_page_at(t0, 5));
        }
        assert!(!l.take_page_at(t0, 5));
        // pages exhausted, challenges untouched (the visitor can still re-verify)
        for _ in 0..CHALLENGE_BURST as usize {
            assert!(l.take_at(t0, 5));
        }
        assert!(!l.take_at(t0, 5));
    }

    #[test]
    fn bucket_ignores_a_clock_going_backwards() {
        let t0 = Instant::now() + Duration::from_secs(10);
        let mut b = Bucket::full(1.0, t0);
        assert!(b.take(t0, 1.0, 1.0));
        // an earlier instant must neither refill nor rewind `last`
        assert!(!b.take(t0 - Duration::from_secs(5), 1.0, 1.0));
        assert!(!b.take(t0, 1.0, 1.0));
        assert!(b.take(t0 + Duration::from_millis(1100), 1.0, 1.0));
    }

}
