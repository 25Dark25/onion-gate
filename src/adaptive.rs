//! Adaptive mode (`captcha = adaptive`): no CAPTCHA while the gate is calm,
//! the CAPTCHA for everyone new as soon as it looks attacked.
//!
//! While calm, a visitor without a pass gets a **free pass** (a 303 to the same
//! URL with the cookie) instead of a challenge. A free pass is an ordinary
//! pass in every other way: the same request budget, lifetime and memory share,
//! and getting one costs a challenge permit of the visitor's circuit, like a
//! challenge image would. A pass that spends its budget, or whose circuit
//! spends its own, leads to the CAPTCHA, never to a new free pass. Free passes
//! may fill at most half the pass store.
//!
//! The monitor looks at the last minute every few seconds. The gate goes
//! **under attack** when any of these holds:
//!  - more than `adaptive_new_per_minute` arrivals (requests for the site
//!    without a valid pass);
//!  - more than 30 rate-limit answers (429);
//!  - more than 10 backend failures (connect or timeout);
//!  - more than half of `max_conn` connections open, or more than half of the
//!    `memory` budget in use;
//!  - the operator's `adaptive_force_file` exists.
//!
//! Going under attack revokes every free pass at once: from then on, everyone
//! without a solved pass gets the CAPTCHA. Solved passes are never revoked by
//! a mode change. The gate goes back to calm only after `adaptive_hold`
//! without any of the signals (hysteresis: an attacker cannot make it flap).
//!
//! Without the PROXY line there are no circuits, so a free pass would cost
//! nothing: the configuration refuses adaptive mode without `proxy_protocol`.

use crate::config::Limits;
use crate::App;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How often the monitor looks, and how far back.
pub const TICK: Duration = Duration::from_secs(5);
const WINDOW: Duration = Duration::from_secs(60);
/// Fixed thresholds (per minute) for the secondary signals.
const MAX_429_PER_MINUTE: u64 = 30;
const MAX_BACKEND_ERRORS_PER_MINUTE: u64 = 10;

/// What the monitor reads: counters (cumulative) and gauges (now).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Snapshot {
    pub arrivals: u64,
    pub rate_limited: u64,
    pub backend_errors: u64,
    pub conn_open: u64,
    pub conn_max: u64,
    pub memory_used: u64,
    pub memory_max: u64,
    /// The operator's force file exists.
    pub forced: bool,
}

/// A change of mode, with the reason when it is an attack.
#[derive(Debug, PartialEq)]
pub enum Change {
    Attack(String),
    Calm,
}

struct Monitor {
    samples: VecDeque<(Instant, Snapshot)>,
    /// The last time any signal held.
    last_signal: Option<Instant>,
}

pub struct Adaptive {
    enabled: bool,
    attack: AtomicBool,
    monitor: Mutex<Monitor>,
    new_per_minute: u64,
    hold: Duration,
    force_file: Option<PathBuf>,
}

impl Adaptive {
    pub fn new(l: &Limits) -> Adaptive {
        Adaptive {
            enabled: l.adaptive,
            attack: AtomicBool::new(false),
            monitor: Mutex::new(Monitor { samples: VecDeque::new(), last_signal: None }),
            new_per_minute: l.adaptive_new_per_minute as u64,
            hold: l.adaptive_hold,
            force_file: (!l.adaptive_force_file.is_empty()).then(|| PathBuf::from(&l.adaptive_force_file)),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Calm: visitors without a pass get a free one instead of a challenge.
    pub fn calm(&self) -> bool {
        self.enabled && !self.attack.load(Ordering::Relaxed)
    }

    /// One look at the last minute. Pure apart from the state it keeps, so it
    /// can be driven with any clock.
    pub fn tick(&self, now: Instant, snap: Snapshot) -> Option<Change> {
        if !self.enabled {
            return None;
        }
        let mut m = self.monitor.lock().unwrap_or_else(|e| e.into_inner());
        m.samples.push_back((now, snap));
        // Keep the newest sample that is at least WINDOW old as the base.
        while m.samples.len() > 2 && now.saturating_duration_since(m.samples[1].0) >= WINDOW {
            m.samples.pop_front();
        }
        let base = m.samples[0].1;
        let d = |cur: u64, old: u64| cur.saturating_sub(old);

        let mut reasons = Vec::new();
        let arrivals = d(snap.arrivals, base.arrivals);
        if arrivals > self.new_per_minute {
            reasons.push(format!("{} arrivals in a minute (adaptive_new_per_minute = {})", arrivals, self.new_per_minute));
        }
        let limited = d(snap.rate_limited, base.rate_limited);
        if limited > MAX_429_PER_MINUTE {
            reasons.push(format!("{} rate-limit answers in a minute", limited));
        }
        let errors = d(snap.backend_errors, base.backend_errors);
        if errors > MAX_BACKEND_ERRORS_PER_MINUTE {
            reasons.push(format!("{} backend failures in a minute", errors));
        }
        if snap.conn_open * 2 > snap.conn_max {
            reasons.push(format!("{} of {} connections open", snap.conn_open, snap.conn_max));
        }
        if snap.memory_used * 2 > snap.memory_max {
            reasons.push(format!("{} of {} buffered bytes in use", snap.memory_used, snap.memory_max));
        }
        if snap.forced {
            reasons.push("the force file exists".to_string());
        }

        let attacked = self.attack.load(Ordering::Relaxed);
        if !reasons.is_empty() {
            m.last_signal = Some(now);
            if !attacked {
                self.attack.store(true, Ordering::Relaxed);
                return Some(Change::Attack(reasons.join("; ")));
            }
        } else if attacked && m.last_signal.is_none_or(|t| now.saturating_duration_since(t) >= self.hold) {
            self.attack.store(false, Ordering::Relaxed);
            return Some(Change::Calm);
        }
        None
    }
}

/// The monitor's view of the gate right now.
pub fn snapshot(app: &App) -> Snapshot {
    let m = &app.metrics;
    Snapshot {
        arrivals: m.arrivals.get(),
        rate_limited: m.limited_connections.get() + m.limited_challenges.get(),
        backend_errors: m.upstream_connect.get() + m.upstream_timeout.get(),
        conn_open: m.conn_open.get(),
        conn_max: app.limits.max_conn as u64,
        memory_used: app.memory.used() as u64,
        memory_max: app.limits.memory as u64,
        forced: app.adaptive.force_file.as_ref().is_some_and(|f| f.exists()),
    }
}

/// One step of the monitor: look, and act on a change.
pub fn step(app: &App, now: Instant) -> Option<Change> {
    let change = app.adaptive.tick(now, snapshot(app))?;
    app.metrics.mode_changes.inc();
    match &change {
        Change::Attack(why) => {
            let revoked = app.store.revoke_free_passes();
            eprintln!("onion-gate: under attack, CAPTCHA for everyone new ({}); {} free passes revoked", why, revoked);
        }
        Change::Calm => eprintln!("onion-gate: calm again, free passes for new visitors"),
    }
    Some(change)
}

/// The monitor thread (adaptive mode only).
pub fn run(app: &App) {
    loop {
        std::thread::sleep(TICK);
        step(app, Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adaptive(new_per_minute: u32, hold_secs: u64) -> Adaptive {
        Adaptive::new(&Limits {
            adaptive: true,
            adaptive_new_per_minute: new_per_minute,
            adaptive_hold: Duration::from_secs(hold_secs),
            ..Limits::default()
        })
    }

    fn snap(arrivals: u64) -> Snapshot {
        Snapshot { arrivals, conn_max: 512, memory_max: 1000, ..Snapshot::default() }
    }

    #[test]
    fn calm_until_arrivals_exceed_the_threshold_within_a_minute() {
        let a = adaptive(60, 600);
        let t0 = Instant::now();
        assert!(a.calm());
        // 60 arrivals spread over two minutes: never more than 60 in one.
        for i in 0..=24 {
            let t = t0 + TICK * i;
            assert_eq!(a.tick(t, snap(i as u64 * 5 / 2)), None, "tick {}", i);
        }
        assert!(a.calm());
        // 61 more within a minute: attack.
        let t = t0 + TICK * 30;
        assert!(matches!(a.tick(t, snap(60 + 61)), Some(Change::Attack(_))));
        assert!(!a.calm());
    }

    #[test]
    fn stays_under_attack_for_the_hold_then_calms() {
        let a = adaptive(10, 900);
        let t0 = Instant::now();
        a.tick(t0, snap(0));
        assert!(matches!(a.tick(t0 + TICK, snap(50)), Some(Change::Attack(_))));
        // No new arrivals from now on. The burst stays in the one-minute window
        // (still a signal) until t0 + 60 s; the 15-minute hold runs from there.
        let last_signal = t0 + Duration::from_secs(60);
        let mut t = t0 + TICK;
        while t + TICK < last_signal + Duration::from_secs(900) {
            t += TICK;
            assert_eq!(a.tick(t, snap(50)), None, "at {:?}", t - t0);
            assert!(!a.calm(), "too early to calm down");
        }
        t += TICK;
        assert_eq!(a.tick(t, snap(50)), Some(Change::Calm), "at {:?}", t - t0);
        assert!(a.calm());
    }

    #[test]
    fn a_signal_during_the_hold_restarts_it() {
        let a = adaptive(10, 300);
        let t0 = Instant::now();
        a.tick(t0, snap(0));
        assert!(a.tick(t0 + TICK, snap(50)).is_some());
        let mut s = snap(50);
        s.forced = true;
        assert_eq!(a.tick(t0 + Duration::from_secs(250), s), None, "still under attack");
        assert_eq!(a.tick(t0 + Duration::from_secs(400), snap(50)), None, "hold restarted at 250 s");
        assert_eq!(a.tick(t0 + Duration::from_secs(551), snap(50)), Some(Change::Calm));
    }

    #[test]
    fn every_signal_triggers() {
        let base = snap(0);
        let cases: Vec<(&str, Snapshot)> = vec![
            ("429s", Snapshot { rate_limited: 31, ..base }),
            ("backend", Snapshot { backend_errors: 11, ..base }),
            ("connections", Snapshot { conn_open: 257, ..base }),
            ("memory", Snapshot { memory_used: 501, ..base }),
            ("force file", Snapshot { forced: true, ..base }),
        ];
        for (name, s) in cases {
            let a = adaptive(1000, 600);
            let t0 = Instant::now();
            assert_eq!(a.tick(t0, base), None);
            assert!(matches!(a.tick(t0 + TICK, s), Some(Change::Attack(_))), "{} did not trigger", name);
        }
    }

    #[test]
    fn disabled_never_changes() {
        let a = Adaptive::new(&Limits::default());
        assert!(!a.calm(), "always mode: never calm (always the CAPTCHA)");
        let s = Snapshot { forced: true, ..snap(1_000_000) };
        assert_eq!(a.tick(Instant::now(), s), None);
    }
}
