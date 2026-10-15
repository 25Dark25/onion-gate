//! Aggregate metrics, served on a separate loopback port (`metrics_port`) in
//! the Prometheus text format: `curl http://127.0.0.1:PORT/metrics`.
//!
//! Only counters and totals: how many challenges, passes, forwarded requests,
//! limits hit, errors; how full the stores and the memory budget are. Never a
//! circuit identifier, a path, a cookie, a header or the time of any single
//! request, and nothing is written anywhere. The counters only say how busy
//! the gate is; they are also what an operator watches to see an attack coming
//! (challenges and 429s climbing, memory filling, the backend slowing down).
//!
//! The endpoint listens on 127.0.0.1 only, like the gate. Anyone who can reach
//! it can already reach the gate itself, so it adds no exposure beyond the
//! aggregate numbers. Keep it off the onion: tor must not point at this port.

use crate::App;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

/// A counter or gauge. Relaxed ordering: they are statistics, not locks.
#[derive(Default)]
pub struct Counter(AtomicU64);

impl Counter {
    pub fn inc(&self) {
        self.0.fetch_add(1, Relaxed);
    }
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Relaxed);
    }
    pub fn dec(&self) {
        self.0.fetch_sub(1, Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Relaxed)
    }
}

/// Every counter the gate keeps.
pub struct Metrics {
    started: Instant,
    /// Connections accepted, refused for `max_conn`, and open right now.
    pub conn_accepted: Counter,
    pub conn_refused: Counter,
    pub conn_open: Counter,
    /// Connections closed for a missing or malformed PROXY line.
    pub proxy_rejected: Counter,
    /// Requests the parser refused (4xx before any routing).
    pub bad_requests: Counter,
    /// 429s: a circuit over its connections, or over its challenge images.
    pub limited_connections: Counter,
    pub limited_challenges: Counter,
    /// Challenge images generated.
    pub challenges: Counter,
    /// Verifications: wrong or expired, a round passed, the CAPTCHA passed
    /// (= passes issued).
    pub verify_failed: Counter,
    pub verify_next_round: Counter,
    pub verify_passed: Counter,
    /// Passes revoked: their own budget spent, or their circuit's.
    pub revoked_pass_budget: Counter,
    pub revoked_circuit_budget: Counter,
    /// A store was full (503).
    pub store_full: Counter,
    /// The memory budget was spent (503).
    pub memory_busy: Counter,
    /// Requests forwarded and answered, and the forwarding failures by kind.
    pub forwarded: Counter,
    pub upstream_connect: Counter,
    pub upstream_timeout: Counter,
    pub upstream_bad_response: Counter,
    pub upstream_too_large: Counter,
    /// Time spent waiting for the backend, in microseconds, over all forwards.
    pub upstream_micros: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics {
            started: Instant::now(),
            conn_accepted: Counter::default(),
            conn_refused: Counter::default(),
            conn_open: Counter::default(),
            proxy_rejected: Counter::default(),
            bad_requests: Counter::default(),
            limited_connections: Counter::default(),
            limited_challenges: Counter::default(),
            challenges: Counter::default(),
            verify_failed: Counter::default(),
            verify_next_round: Counter::default(),
            verify_passed: Counter::default(),
            revoked_pass_budget: Counter::default(),
            revoked_circuit_budget: Counter::default(),
            store_full: Counter::default(),
            memory_busy: Counter::default(),
            forwarded: Counter::default(),
            upstream_connect: Counter::default(),
            upstream_timeout: Counter::default(),
            upstream_bad_response: Counter::default(),
            upstream_too_large: Counter::default(),
            upstream_micros: Counter::default(),
        }
    }
}

/// Writes one metric family: HELP, TYPE and its samples.
fn family(out: &mut String, name: &str, kind: &str, help: &str, samples: &[(&str, u64)]) {
    out.push_str(&format!("# HELP onion_gate_{} {}\n# TYPE onion_gate_{} {}\n", name, help, name, kind));
    for (labels, v) in samples {
        out.push_str(&format!("onion_gate_{}{} {}\n", name, labels, v));
    }
}

/// The metrics page, in the Prometheus text exposition format (0.0.4).
pub fn render(app: &App) -> String {
    let m = &app.metrics;
    let (challenges_pending, passes_live) = app.store.sizes();
    let mut o = String::with_capacity(4096);
    family(&mut o, "info", "gauge", "Version of onion-gate (always 1).", &[(
        &format!("{{version=\"{}\"}}", env!("CARGO_PKG_VERSION")),
        1,
    )]);
    family(&mut o, "uptime_seconds", "gauge", "Seconds since the gate started.", &[("", m.started.elapsed().as_secs())]);
    family(&mut o, "connections_total", "counter", "Connections accepted, or refused because max_conn were open.", &[
        ("{result=\"accepted\"}", m.conn_accepted.get()),
        ("{result=\"refused_max_conn\"}", m.conn_refused.get()),
    ]);
    family(&mut o, "connections_open", "gauge", "Connections open right now.", &[("", m.conn_open.get())]);
    family(&mut o, "proxy_line_rejected_total", "counter", "Connections closed for a missing or malformed PROXY line.", &[("", m.proxy_rejected.get())]);
    family(&mut o, "bad_requests_total", "counter", "Requests refused by the HTTP parser (4xx).", &[("", m.bad_requests.get())]);
    family(&mut o, "rate_limited_total", "counter", "429 answers, by the per-circuit limit that was hit.", &[
        ("{limit=\"conn_per_circuit\"}", m.limited_connections.get()),
        ("{limit=\"challenge\"}", m.limited_challenges.get()),
    ]);
    family(&mut o, "challenges_total", "counter", "Challenge images generated.", &[("", m.challenges.get())]);
    family(&mut o, "verifications_total", "counter", "CAPTCHA answers, by outcome (passed = passes issued).", &[
        ("{result=\"failed\"}", m.verify_failed.get()),
        ("{result=\"next_round\"}", m.verify_next_round.get()),
        ("{result=\"passed\"}", m.verify_passed.get()),
    ]);
    family(&mut o, "passes_revoked_total", "counter", "Passes revoked for spending a request budget.", &[
        ("{budget=\"pass\"}", m.revoked_pass_budget.get()),
        ("{budget=\"circuit\"}", m.revoked_circuit_budget.get()),
    ]);
    family(&mut o, "forwarded_total", "counter", "Requests forwarded to the backend and answered.", &[("", m.forwarded.get())]);
    family(&mut o, "upstream_errors_total", "counter", "Requests the backend did not answer usably, by kind.", &[
        ("{kind=\"connect\"}", m.upstream_connect.get()),
        ("{kind=\"timeout\"}", m.upstream_timeout.get()),
        ("{kind=\"bad_response\"}", m.upstream_bad_response.get()),
        ("{kind=\"too_large\"}", m.upstream_too_large.get()),
    ]);
    family(&mut o, "upstream_seconds_total", "counter", "Time spent waiting for the backend, over all forwarded requests.", &[]);
    o.push_str(&format!("onion_gate_upstream_seconds_total {:.6}\n", m.upstream_micros.get() as f64 / 1e6));
    family(&mut o, "busy_total", "counter", "503 answers, by the resource that was full.", &[
        ("{resource=\"memory\"}", m.memory_busy.get()),
        ("{resource=\"store\"}", m.store_full.get()),
    ]);
    family(&mut o, "challenges_pending", "gauge", "Challenges issued and not yet answered or expired.", &[("", challenges_pending as u64)]);
    family(&mut o, "passes_live", "gauge", "Passes held in memory (some may have expired since the last purge).", &[("", passes_live as u64)]);
    family(&mut o, "circuits_tracked", "gauge", "Tor circuits the limiter remembers.", &[("", app.limiter.tracked() as u64)]);
    family(&mut o, "memory_bytes", "gauge", "Bytes of bodies buffered now, and the budget.", &[
        ("{kind=\"used\"}", app.memory.used() as u64),
        ("{kind=\"limit\"}", app.limits.memory as u64),
    ]);
    o
}

const READ_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_REQUEST: usize = 4096;

/// Serves `GET /metrics`, one connection at a time: the page is small, and a
/// local client that stalls only delays the next scrape, never the gate.
pub fn serve(listener: TcpListener, app: &App) {
    for mut s in listener.incoming().flatten() {
        answer(&mut s, app);
    }
}

fn answer(s: &mut TcpStream, app: &App) {
    let _ = s.set_read_timeout(Some(READ_TIMEOUT));
    let _ = s.set_write_timeout(Some(READ_TIMEOUT));
    let deadline = Instant::now() + READ_TIMEOUT;
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        if buf.len() > MAX_REQUEST || Instant::now() > deadline {
            return;
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let line = buf.split(|&b| b == b'\r').next().unwrap_or(&[]);
    let mut parts = line.split(|&b| b == b' ');
    let (method, target) = (parts.next().unwrap_or(&[]), parts.next().unwrap_or(&[]));
    let path = target.split(|&b| b == b'?').next().unwrap_or(&[]);
    let (status, body) = if method == b"GET" && path == b"/metrics" {
        ("200 OK", render(app))
    } else {
        ("404 Not Found", "Not found. The metrics are at /metrics.\n".to_string())
    };
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        status,
        body.len()
    );
    let _ = s.write_all(head.as_bytes()).and_then(|_| s.write_all(body.as_bytes()));
    let _ = s.shutdown(Shutdown::Both);
}
