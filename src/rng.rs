//! Minimal CSPRNG backed by /dev/urandom (the kernel). No dependencies.
//!
//! Fail-closed policy: if the kernel cannot provide entropy, the thread
//! panics. It never falls back to a weak or predictable generator.

use std::fs::File;
use std::io::Read;

const BUF_LEN: usize = 4096;

pub struct Rng {
    src: File,
    buf: [u8; BUF_LEN],
    pos: usize,
}

impl Rng {
    // No `Default`: it would open /dev/urandom and could panic, and a panicking
    // `Default::default()` is a worse surprise than calling `Rng::new()`.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Rng {
        let src = File::open("/dev/urandom").expect("could not open /dev/urandom");
        Rng {
            src,
            buf: [0u8; BUF_LEN],
            pos: BUF_LEN, // "empty" buffer: filled on first use
        }
    }

    fn refill(&mut self) {
        self.src
            .read_exact(&mut self.buf)
            .expect("failed to read /dev/urandom");
        self.pos = 0;
    }

    pub fn byte(&mut self) -> u8 {
        if self.pos >= BUF_LEN {
            self.refill();
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        b
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut v = 0u32;
        for _ in 0..4 {
            v = (v << 8) | self.byte() as u32;
        }
        v
    }

    /// Uniform integer in [0, n) without modulo bias (rejection sampling).
    pub fn below(&mut self, n: u32) -> u32 {
        assert!(n > 0);
        // Largest multiple of n that fits in u32: every value < limit is uniform.
        let limit = u32::MAX - (u32::MAX % n);
        loop {
            let v = self.next_u32();
            if v < limit {
                return v % n;
            }
        }
    }

    /// Uniform f32 in [0, 1) with 24 bits of precision.
    pub fn unit(&mut self) -> f32 {
        (self.next_u32() >> 8) as f32 / 16_777_216.0
    }

    /// Uniform f32 in [lo, hi).
    pub fn range(&mut self, lo: f32, hi: f32) -> f32 {
        lo + self.unit() * (hi - lo)
    }

    /// 128 random bits (tokens).
    pub fn token(&mut self) -> [u8; 16] {
        let mut t = [0u8; 16];
        for b in t.iter_mut() {
            *b = self.byte();
        }
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_stays_in_range() {
        let mut r = Rng::new();
        for _ in 0..10_000 {
            assert!(r.below(7) < 7);
        }
        assert_eq!(r.below(1), 0);
    }

    #[test]
    fn unit_is_in_0_1() {
        let mut r = Rng::new();
        for _ in 0..10_000 {
            let u = r.unit();
            assert!((0.0..1.0).contains(&u));
        }
    }

    #[test]
    fn tokens_differ() {
        let mut r = Rng::new();
        assert_ne!(r.token(), r.token());
    }

    #[test]
    fn crosses_the_buffer_boundary() {
        let mut r = Rng::new();
        for _ in 0..(BUF_LEN * 3 + 5) {
            r.byte();
        }
    }
}
