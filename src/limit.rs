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
//!    hammering the site with several passes; see main.rs for what happens
//!    when it runs out).
//!
//! To take the service down, an attacker needs many circuits, and every new
//! circuit goes through tor's defenses (PoW included).
//! Policy: when in doubt, deny (fail-closed).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
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
// Contract between the two page limits, checked at compile time: with a single
// pass, the per-pass bucket (store.rs) is the one that trips first.
const _: () = assert!(CIRCUIT_PAGE_BURST > crate::store::PASS_BURST);
const _: () = assert!(CIRCUIT_PAGE_REFILL_PER_SEC > crate::store::PASS_REFILL_PER_SEC);
/// Maximum number of circuits remembered (bounded memory).
const MAX_ENTRIES: usize = 50_000;
/// A circuit idle for this long is forgotten. Must be at least the time any
/// bucket needs to refill completely, or forgetting would hand back a full
/// bucket early: challenges 60 s, pages 60 s (90 / 1.5). 600 s covers both.
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

impl Inner {
    fn purge(&mut self, now: Instant) {
        match now.checked_duration_since(self.last_purge) {
            Some(d) if d >= PURGE_EVERY => {}
            _ => return,
        }
        self.last_purge = now;
        self.map.retain(|_, e| {
            e.active > 0 || now.checked_duration_since(e.last).is_none_or(|d| d < IDLE_FORGET)
        });
    }

    /// The circuit's entry, created if there is room. None if the map is full.
    fn entry(&mut self, c: u32, now: Instant) -> Option<&mut Entry> {
        if !self.map.contains_key(&c) {
            if self.map.len() >= MAX_ENTRIES {
                self.purge(now);
                if self.map.len() >= MAX_ENTRIES {
                    return None;
                }
            }
            self.map.insert(
                c,
                Entry {
                    active: 0,
                    challenges: Bucket::full(CHALLENGE_BURST, now),
                    pages: Bucket::full(CIRCUIT_PAGE_BURST, now),
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
    pub fn new() -> Limiter {
        Limiter {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                last_purge: Instant::now(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reserves a connection slot for the circuit. None = limit exceeded.
    pub fn enter(&self, circuit: u32) -> Option<ConnSlot<'_>> {
        let now = Instant::now();
        let mut g = self.lock();
        let e = g.entry(circuit, now)?;
        if e.active >= MAX_CONN_PER_CIRCUIT {
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
        match g.entry(circuit, now) {
            Some(e) => e.challenges.take(now, CHALLENGE_BURST, CHALLENGE_REFILL_PER_SEC),
            None => false,
        }
    }

    /// Consumes one permit to serve a site page. false = too many.
    pub fn take_page(&self, circuit: u32) -> bool {
        self.take_page_at(Instant::now(), circuit)
    }

    fn take_page_at(&self, now: Instant, circuit: u32) -> bool {
        let mut g = self.lock();
        match g.entry(circuit, now) {
            Some(e) => e.pages.take(now, CIRCUIT_PAGE_BURST, CIRCUIT_PAGE_REFILL_PER_SEC),
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

/// A shared byte budget. Reservations give their bytes back when dropped.
pub struct Memory {
    used: AtomicUsize,
    max: usize,
}

impl Default for Memory {
    fn default() -> Self {
        Self::new(MAX_BUFFERED)
    }
}

impl Memory {
    pub fn new(max: usize) -> Memory {
        Memory { used: AtomicUsize::new(0), max }
    }

    /// Reserves `n` bytes. None = the budget would be exceeded.
    pub fn reserve(&self, n: usize) -> Option<Reservation<'_>> {
        let mut r = Reservation { mem: self, bytes: 0 };
        if r.grow(n) {
            Some(r)
        } else {
            None
        }
    }

    /// Bytes currently reserved.
    pub fn used(&self) -> usize {
        self.used.load(Ordering::SeqCst)
    }
}

/// Bytes held from a `Memory` budget; released on drop.
pub struct Reservation<'a> {
    mem: &'a Memory,
    bytes: usize,
}

impl Reservation<'_> {
    /// Adds `n` bytes to the reservation. false = over budget (nothing added).
    pub fn grow(&mut self, n: usize) -> bool {
        let ok = self
            .mem
            .used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |u| {
                u.checked_add(n).filter(|&t| t <= self.mem.max)
            })
            .is_ok();
        if ok {
            self.bytes += n;
        }
        ok
    }

    /// Gives back everything above `n` bytes.
    pub fn shrink_to(&mut self, n: usize) {
        if n < self.bytes {
            self.mem.used.fetch_sub(self.bytes - n, Ordering::SeqCst);
            self.bytes = n;
        }
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.mem.used.fetch_sub(self.bytes, Ordering::SeqCst);
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
