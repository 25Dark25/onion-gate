//! Run-time configuration: a `key = value` file and/or `--key=value` flags.
//!
//! Every setting has a default (the values the gate always had), so the only
//! required one is `upstream`. Flags override the file. Keys are the same in
//! both places; `-` and `_` are interchangeable (`--pass-idle` = `pass_idle`).
//!
//! Values are human-readable:
//!  - durations: `45s`, `30m`, `2h` (a bare number is seconds);
//!  - sizes: `512K`, `8M`, `1G` (binary multiples; a bare number is bytes);
//!  - rates: requests per minute, whole numbers;
//!  - booleans: `yes`/`no` (also `true`/`false`, `on`/`off`, `1`/`0`).
//!
//! The listen address is not configurable on purpose: onion-gate listens on
//! 127.0.0.1 only. The upstream must resolve to loopback (checked at start).

use std::time::Duration;

/// The tunable limits. The defaults are the values documented in the README.
#[derive(Clone, Debug, PartialEq)]
pub struct Limits {
    /// Consecutive CAPTCHA rounds required for a pass.
    pub rounds: u8,
    /// How long a challenge image stays valid (the page's time bar).
    pub challenge_ttl: Duration,
    /// A pass unused for this long expires.
    pub pass_idle: Duration,
    /// A pass expires this long after it was issued, however active.
    pub pass_max: Duration,
    /// Requests per pass: burst, and sustained rate per minute.
    pub pass_burst: u32,
    pub pass_per_minute: u32,
    /// Forwarded requests per Tor circuit: burst, and rate per minute.
    pub circuit_burst: u32,
    pub circuit_per_minute: u32,
    /// Challenge images per Tor circuit: burst, and rate per minute.
    pub challenge_burst: u32,
    pub challenge_per_minute: u32,
    /// Simultaneous connections per Tor circuit, and in total.
    pub conn_per_circuit: u16,
    pub max_conn: usize,
    /// Largest request body forwarded, and largest backend response relayed.
    pub max_body: usize,
    pub max_response: usize,
    /// How long the backend may take to answer (and to accept the request).
    pub upstream_timeout: Duration,
    /// Bytes buffered at once: in total, per circuit, per pass.
    pub memory: usize,
    pub memory_per_circuit: usize,
    pub memory_per_pass: usize,
}

impl Default for Limits {
    /// The documented defaults, taken from the constants in each module.
    fn default() -> Limits {
        use crate::{http, limit, store, upstream};
        let per_minute = |per_sec: f32| (per_sec * 60.0).round() as u32;
        Limits {
            rounds: crate::ROUNDS,
            challenge_ttl: store::CHALLENGE_TTL,
            pass_idle: store::PASS_IDLE,
            pass_max: store::PASS_MAX,
            pass_burst: store::PASS_BURST as u32,
            pass_per_minute: per_minute(store::PASS_REFILL_PER_SEC),
            circuit_burst: limit::CIRCUIT_PAGE_BURST as u32,
            circuit_per_minute: per_minute(limit::CIRCUIT_PAGE_REFILL_PER_SEC),
            challenge_burst: limit::CHALLENGE_BURST as u32,
            challenge_per_minute: per_minute(limit::CHALLENGE_REFILL_PER_SEC),
            conn_per_circuit: limit::MAX_CONN_PER_CIRCUIT,
            max_conn: DEFAULT_MAX_CONN,
            max_body: http::DEFAULT_MAX_BODY,
            max_response: upstream::MAX_RESPONSE,
            upstream_timeout: upstream::IO_TIMEOUT,
            memory: limit::MAX_BUFFERED,
            memory_per_circuit: limit::MAX_BUFFERED_PER_CIRCUIT,
            memory_per_pass: limit::MAX_BUFFERED_PER_PASS,
        }
    }
}

/// Simultaneous connections in total (one thread each); extra ones are closed.
pub const DEFAULT_MAX_CONN: usize = 512;

impl Limits {
    pub fn pass_per_sec(&self) -> f32 {
        self.pass_per_minute as f32 / 60.0
    }
    pub fn circuit_per_sec(&self) -> f32 {
        self.circuit_per_minute as f32 / 60.0
    }
    pub fn challenge_per_sec(&self) -> f32 {
        self.challenge_per_minute as f32 / 60.0
    }

    /// Every rule a working configuration must follow, as messages.
    pub fn problems(&self) -> Vec<String> {
        let mut p = Vec::new();
        let mut need = |ok: bool, msg: &str| {
            if !ok {
                p.push(msg.to_string());
            }
        };
        need((1..=5).contains(&self.rounds), "rounds must be 1 to 5");
        need(
            (10..=300).contains(&self.challenge_ttl.as_secs()),
            "challenge_ttl must be 10s to 5m (Tor Browser needs time; a long one helps solvers)",
        );
        need(self.pass_idle >= Duration::from_secs(60), "pass_idle must be at least 1m");
        need(self.pass_max >= self.pass_idle, "pass_max must be at least pass_idle");
        need(self.pass_max <= Duration::from_secs(7 * 24 * 3600), "pass_max must be at most 7 days");
        for (v, name) in [
            (self.pass_burst, "pass_burst"),
            (self.pass_per_minute, "pass_per_minute"),
            (self.circuit_burst, "circuit_burst"),
            (self.circuit_per_minute, "circuit_per_minute"),
            (self.challenge_burst, "challenge_burst"),
            (self.challenge_per_minute, "challenge_per_minute"),
        ] {
            need((1..=100_000).contains(&v), &format!("{} must be 1 to 100000", name));
        }
        // With one pass on a circuit, the pass's budget must be the one that
        // trips (and revokes the pass); otherwise an honest visitor is cut by
        // the circuit limit first.
        need(
            self.circuit_burst > self.pass_burst && self.circuit_per_minute > self.pass_per_minute,
            "circuit_burst and circuit_per_minute must be larger than pass_burst and pass_per_minute",
        );
        need(
            (1..=1000).contains(&self.conn_per_circuit),
            "conn_per_circuit must be 1 to 1000",
        );
        need(
            self.max_conn >= self.conn_per_circuit as usize && self.max_conn <= 20_000,
            "max_conn must be at least conn_per_circuit and at most 20000",
        );
        need(self.max_body >= 1024, "max_body must be at least 1K");
        need(self.max_response >= 1024, "max_response must be at least 1K");
        need(
            (1..=600).contains(&self.upstream_timeout.as_secs()),
            "upstream_timeout must be 1s to 10m",
        );
        need(
            self.memory_per_circuit <= self.memory_per_pass && self.memory_per_pass < self.memory,
            "memory shares must satisfy memory_per_circuit <= memory_per_pass < memory",
        );
        // Bodies and responses are counted twice while they are copied: the
        // largest allowed one must fit in a circuit's share, or it could never
        // be delivered.
        need(
            self.memory_per_circuit / 2 >= self.max_response.max(self.max_body),
            "memory_per_circuit must be at least twice max_response and max_body",
        );
        p
    }
}

/// Everything the binary needs to run.
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// Port on 127.0.0.1.
    pub port: u16,
    /// The backend, `host:port`; must resolve to loopback.
    pub upstream: String,
    /// Read tor's PROXY line on every connection (per-circuit limits).
    pub proxy_protocol: bool,
    /// Port on 127.0.0.1 for the metrics page; 0 = off.
    pub metrics_port: u16,
    pub limits: Limits,
}

/// What the command line asks for.
#[derive(Debug, PartialEq)]
pub enum Action {
    Run(Config),
    /// `--print-config`: print the effective configuration and exit.
    Print(Config),
    /// `--check`: validate (and try the backend), then exit.
    Check(Config),
    Help,
    Version,
}

/// (key, help), in the order `--print-config` writes them.
pub const KEYS: &[(&str, &str)] = &[
    ("port", "Port to listen on. onion-gate listens on 127.0.0.1 only."),
    ("upstream", "The backend to protect, host:port. Must resolve to loopback. Required."),
    ("proxy_protocol", "Read tor's PROXY line (HiddenServiceExportCircuitID haproxy). Needed for per-circuit limits: use yes behind tor."),
    ("metrics_port", "Port on 127.0.0.1 for aggregate metrics (GET /metrics, Prometheus text). 0 = off. Never point tor at it."),
    ("rounds", "CAPTCHA rounds in a row needed for a pass (1-5)."),
    ("challenge_ttl", "How long a challenge image is valid; the page shows a bar for it."),
    ("pass_idle", "A pass unused for this long expires."),
    ("pass_max", "A pass expires this long after it was issued, however active."),
    ("pass_burst", "Requests one pass may make in a burst. Every request counts, assets included."),
    ("pass_per_minute", "Sustained requests per minute per pass. Spending the budget revokes the pass."),
    ("circuit_burst", "Forwarded requests one Tor circuit may make in a burst. Must exceed pass_burst."),
    ("circuit_per_minute", "Sustained forwarded requests per minute per circuit. Must exceed pass_per_minute."),
    ("challenge_burst", "Challenge images one circuit may get in a burst (each costs CPU)."),
    ("challenge_per_minute", "Sustained challenge images per minute per circuit."),
    ("conn_per_circuit", "Simultaneous connections per circuit."),
    ("max_conn", "Simultaneous connections in total."),
    ("max_body", "Largest request body forwarded (with a valid pass)."),
    ("max_response", "Largest backend response relayed; larger ones are a 502."),
    ("upstream_timeout", "How long the backend may take to answer."),
    ("memory", "Request and response bytes buffered at once, in total. Over it: 503."),
    ("memory_per_circuit", "The most one circuit may hold of memory. At least 2 x max_response."),
    ("memory_per_pass", "The most one pass may hold of memory."),
];

impl Config {
    fn empty() -> Config {
        Config {
            port: 8088,
            upstream: String::new(),
            proxy_protocol: false,
            metrics_port: 0,
            limits: Limits::default(),
        }
    }

    /// Sets one key from its text value.
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        let key = key.trim().to_ascii_lowercase().replace('-', "_");
        let v = value.trim();
        let l = &mut self.limits;
        let bad = |what: &str| format!("{}: {:?} is not {}", key, v, what);
        match key.as_str() {
            "port" => self.port = v.parse().ok().filter(|&p| p != 0).ok_or_else(|| bad("a port (1-65535)"))?,
            "upstream" => {
                if v.is_empty() || v.contains(char::is_whitespace) {
                    return Err(bad("host:port"));
                }
                self.upstream = v.to_string();
            }
            "proxy_protocol" => self.proxy_protocol = boolean(v).ok_or_else(|| bad("yes or no"))?,
            "metrics_port" => self.metrics_port = v.parse().map_err(|_| bad("a port, or 0 for off"))?,
            "rounds" => l.rounds = v.parse().map_err(|_| bad("a number"))?,
            "challenge_ttl" => l.challenge_ttl = duration(v).ok_or_else(|| bad("a duration (30s, 5m)"))?,
            "pass_idle" => l.pass_idle = duration(v).ok_or_else(|| bad("a duration (30s, 5m, 2h)"))?,
            "pass_max" => l.pass_max = duration(v).ok_or_else(|| bad("a duration (30s, 5m, 2h)"))?,
            "pass_burst" => l.pass_burst = v.parse().map_err(|_| bad("a whole number"))?,
            "pass_per_minute" => l.pass_per_minute = v.parse().map_err(|_| bad("a whole number"))?,
            "circuit_burst" => l.circuit_burst = v.parse().map_err(|_| bad("a whole number"))?,
            "circuit_per_minute" => l.circuit_per_minute = v.parse().map_err(|_| bad("a whole number"))?,
            "challenge_burst" => l.challenge_burst = v.parse().map_err(|_| bad("a whole number"))?,
            "challenge_per_minute" => l.challenge_per_minute = v.parse().map_err(|_| bad("a whole number"))?,
            "conn_per_circuit" => l.conn_per_circuit = v.parse().map_err(|_| bad("a whole number"))?,
            "max_conn" => l.max_conn = v.parse().map_err(|_| bad("a whole number"))?,
            "max_body" => l.max_body = size(v).ok_or_else(|| bad("a size (64K, 1M)"))?,
            "max_response" => l.max_response = size(v).ok_or_else(|| bad("a size (64K, 8M)"))?,
            "upstream_timeout" => l.upstream_timeout = duration(v).ok_or_else(|| bad("a duration (30s)"))?,
            "memory" => l.memory = size(v).ok_or_else(|| bad("a size (128M)"))?,
            "memory_per_circuit" => l.memory_per_circuit = size(v).ok_or_else(|| bad("a size (24M)"))?,
            "memory_per_pass" => l.memory_per_pass = size(v).ok_or_else(|| bad("a size (32M)"))?,
            _ => return Err(format!("unknown setting {:?} (see --help)", key)),
        }
        Ok(())
    }

    /// The value of one key, written the way the file takes it.
    fn get(&self, key: &str) -> String {
        let l = &self.limits;
        match key {
            "port" => self.port.to_string(),
            "upstream" => self.upstream.clone(),
            "proxy_protocol" => (if self.proxy_protocol { "yes" } else { "no" }).to_string(),
            "metrics_port" => self.metrics_port.to_string(),
            "rounds" => l.rounds.to_string(),
            "challenge_ttl" => show_duration(l.challenge_ttl),
            "pass_idle" => show_duration(l.pass_idle),
            "pass_max" => show_duration(l.pass_max),
            "pass_burst" => l.pass_burst.to_string(),
            "pass_per_minute" => l.pass_per_minute.to_string(),
            "circuit_burst" => l.circuit_burst.to_string(),
            "circuit_per_minute" => l.circuit_per_minute.to_string(),
            "challenge_burst" => l.challenge_burst.to_string(),
            "challenge_per_minute" => l.challenge_per_minute.to_string(),
            "conn_per_circuit" => l.conn_per_circuit.to_string(),
            "max_conn" => l.max_conn.to_string(),
            "max_body" => show_size(l.max_body),
            "max_response" => show_size(l.max_response),
            "upstream_timeout" => show_duration(l.upstream_timeout),
            "memory" => show_size(l.memory),
            "memory_per_circuit" => show_size(l.memory_per_circuit),
            "memory_per_pass" => show_size(l.memory_per_pass),
            _ => unreachable!("every key in KEYS has a value"),
        }
    }

    /// Applies a configuration file's text. `name` is used in messages.
    pub fn apply_file(&mut self, name: &str, text: &str) -> Result<(), String> {
        let mut seen: Vec<String> = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = |e: String| format!("{}:{}: {}", name, i + 1, e);
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| at(format!("expected `key = value`, found {:?}", line)))?;
            let key = k.trim().to_ascii_lowercase().replace('-', "_");
            if seen.contains(&key) {
                return Err(at(format!("{} is set twice", key)));
            }
            self.set(&key, v).map_err(at)?;
            seen.push(key);
        }
        Ok(())
    }

    /// The effective configuration as a file, with every key and its help.
    pub fn to_file(&self) -> String {
        let mut s = String::from(
            "# onion-gate configuration. Every key is optional except upstream; a\n\
             # missing key takes its default. Durations: 30s, 5m, 2h. Sizes: 64K, 8M.\n\
             # Rates are requests per minute.\n",
        );
        for (key, help) in KEYS {
            s.push('\n');
            s.push_str("# ");
            s.push_str(help);
            s.push('\n');
            let v = self.get(key);
            if *key == "upstream" && v.is_empty() {
                s.push_str("upstream = 127.0.0.1:3000\n");
            } else {
                s.push_str(&format!("{} = {}\n", key, v));
            }
        }
        s
    }

    /// Every problem with this configuration (empty = good).
    pub fn problems(&self) -> Vec<String> {
        let mut p = Vec::new();
        if self.upstream.is_empty() {
            p.push("upstream is required: the backend to protect, e.g. upstream = 127.0.0.1:3000".to_string());
        }
        if self.metrics_port != 0 && self.metrics_port == self.port {
            p.push("metrics_port must differ from port".to_string());
        }
        p.extend(self.limits.problems());
        p
    }
}

/// Parses the command line (without the program name). `read` loads a file
/// (injected so tests need no files).
pub fn from_args<I, F>(args: I, read: F) -> Result<Action, String>
where
    I: IntoIterator<Item = String>,
    F: Fn(&str) -> Result<String, String>,
{
    let args: Vec<String> = args.into_iter().collect();
    let mut cfg = Config::empty();
    let mut mode = 0u8; // 0 run, 1 print, 2 check

    // The file first, so that flags override it wherever they appear.
    let files: Vec<&str> = args.iter().filter_map(|a| a.strip_prefix("--config=")).collect();
    match files.as_slice() {
        [] => {}
        [path] => {
            let text = read(path)?;
            cfg.apply_file(path, &text)?;
        }
        _ => return Err("--config given more than once".to_string()),
    }

    let mut port_seen = false;
    let mut flag_keys: Vec<String> = Vec::new();
    for a in &args {
        match a.as_str() {
            "-h" | "--help" => return Ok(Action::Help),
            "-V" | "--version" => return Ok(Action::Version),
            "--print-config" => mode = 1,
            "--check" => mode = 2,
            "--proxy-protocol" => cfg.proxy_protocol = true,
            _ if a.starts_with("--config=") => {}
            _ => {
                if let Some(kv) = a.strip_prefix("--") {
                    let (k, v) = kv
                        .split_once('=')
                        .ok_or_else(|| format!("{}: expected --key=value", a))?;
                    let key = k.to_ascii_lowercase().replace('-', "_");
                    if flag_keys.contains(&key) {
                        return Err(format!("--{} given more than once", k));
                    }
                    cfg.set(&key, v)?;
                    flag_keys.push(key);
                } else if !port_seen && a.bytes().all(|b| b.is_ascii_digit()) {
                    // A bare number is the port (the original command line).
                    cfg.set("port", a)?;
                    port_seen = true;
                } else {
                    return Err(format!("unexpected argument: {}", a));
                }
            }
        }
    }
    Ok(match mode {
        1 => Action::Print(cfg),
        2 => Action::Check(cfg),
        _ => Action::Run(cfg),
    })
}

fn boolean(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" | "1" => Some(true),
        "no" | "false" | "off" | "0" => Some(false),
        _ => None,
    }
}

/// `45s`, `30m`, `2h`, or a bare number of seconds.
fn duration(v: &str) -> Option<Duration> {
    let (num, mul) = match v.as_bytes().last()? {
        b's' => (&v[..v.len() - 1], 1),
        b'm' => (&v[..v.len() - 1], 60),
        b'h' => (&v[..v.len() - 1], 3600),
        b'd' => (&v[..v.len() - 1], 86_400),
        _ => (v, 1),
    };
    let n: u64 = whole(num)?;
    n.checked_mul(mul).map(Duration::from_secs)
}

/// `512K`, `8M`, `1G` (binary), or a bare number of bytes.
fn size(v: &str) -> Option<usize> {
    let (num, mul) = match v.as_bytes().last()?.to_ascii_uppercase() {
        b'K' => (&v[..v.len() - 1], 1usize << 10),
        b'M' => (&v[..v.len() - 1], 1 << 20),
        b'G' => (&v[..v.len() - 1], 1 << 30),
        b'B' => (&v[..v.len() - 1], 1),
        _ => (v, 1),
    };
    let n: usize = whole(num)?;
    n.checked_mul(mul)
}

/// Digits only (no sign, no spaces inside).
fn whole<T: std::str::FromStr>(s: &str) -> Option<T> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn show_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s != 0 && s % 3600 == 0 {
        format!("{}h", s / 3600)
    } else if s != 0 && s % 60 == 0 {
        format!("{}m", s / 60)
    } else {
        format!("{}s", s)
    }
}

fn show_size(n: usize) -> String {
    if n != 0 && n % (1 << 30) == 0 {
        format!("{}G", n >> 30)
    } else if n != 0 && n % (1 << 20) == 0 {
        format!("{}M", n >> 20)
    } else if n != 0 && n % (1 << 10) == 0 {
        format!("{}K", n >> 10)
    } else {
        n.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Result<Action, String> {
        from_args(a.iter().map(|s| s.to_string()), |p| Err(format!("no file {}", p)))
    }

    fn with_file(a: &[&str], text: &'static str) -> Result<Action, String> {
        from_args(a.iter().map(|s| s.to_string()), move |_| Ok(text.to_string()))
    }

    fn run(a: Result<Action, String>) -> Config {
        match a {
            Ok(Action::Run(c)) => c,
            other => panic!("not a run: {:?}", other),
        }
    }

    #[test]
    fn the_original_command_line_still_works() {
        let c = run(args(&["9000", "--upstream=127.0.0.1:3000", "--proxy-protocol", "--max-body=2048"]));
        assert_eq!(c.port, 9000);
        assert_eq!(c.upstream, "127.0.0.1:3000");
        assert!(c.proxy_protocol);
        assert_eq!(c.limits.max_body, 2048);
        assert!(c.problems().is_empty(), "{:?}", c.problems());
    }

    #[test]
    fn defaults_are_valid_and_upstream_is_required() {
        let c = run(args(&[]));
        assert_eq!(c.port, 8088);
        assert!(!c.proxy_protocol);
        assert_eq!(c.limits, Limits::default());
        assert!(Limits::default().problems().is_empty());
        assert_eq!(c.problems().len(), 1, "only upstream is missing");
    }

    #[test]
    fn defaults_are_the_documented_values() {
        let l = Limits::default();
        assert_eq!((l.rounds, l.challenge_ttl.as_secs()), (2, 30));
        assert_eq!((l.pass_idle.as_secs(), l.pass_max.as_secs()), (1800, 7200));
        assert_eq!((l.pass_burst, l.pass_per_minute), (60, 60));
        assert_eq!((l.circuit_burst, l.circuit_per_minute), (90, 90));
        assert_eq!((l.challenge_burst, l.challenge_per_minute), (10, 10));
        assert_eq!((l.conn_per_circuit, l.max_conn), (8, 512));
        assert_eq!((l.max_body, l.max_response), (1 << 20, 8 << 20));
        assert_eq!(l.upstream_timeout.as_secs(), 30);
        assert_eq!((l.memory, l.memory_per_circuit, l.memory_per_pass), (128 << 20, 24 << 20, 32 << 20));
    }

    #[test]
    fn units_parse() {
        assert_eq!(duration("45s"), Some(Duration::from_secs(45)));
        assert_eq!(duration("30m"), Some(Duration::from_secs(1800)));
        assert_eq!(duration("2h"), Some(Duration::from_secs(7200)));
        assert_eq!(duration("90"), Some(Duration::from_secs(90)));
        assert_eq!(size("512K"), Some(512 * 1024));
        assert_eq!(size("8m"), Some(8 << 20));
        assert_eq!(size("1G"), Some(1 << 30));
        assert_eq!(size("1000"), Some(1000));
        for bad in ["", "s", "-1s", "1.5m", "1 m", "1x", "99999999999999999999h"] {
            assert_eq!(duration(bad), None, "{:?}", bad);
        }
        for bad in ["", "K", "-1K", "1.5M", "1 M", "1T", "99999999999999999999G"] {
            assert_eq!(size(bad), None, "{:?}", bad);
        }
    }

    #[test]
    fn file_then_flags_override() {
        let text = "# comment\nupstream = 127.0.0.1:3000\n\nproxy-protocol = yes\npass_idle = 10m\nrounds=3\n";
        let c = run(with_file(&["--config=/x", "--rounds=1"], text));
        assert_eq!(c.upstream, "127.0.0.1:3000");
        assert!(c.proxy_protocol);
        assert_eq!(c.limits.pass_idle, Duration::from_secs(600));
        assert_eq!(c.limits.rounds, 1, "the flag wins over the file");
    }

    #[test]
    fn file_errors_name_the_line() {
        let e = with_file(&["--config=gate.conf"], "upstream = 127.0.0.1:1\nbogus = 1\n").unwrap_err();
        assert!(e.starts_with("gate.conf:2:") && e.contains("unknown setting"), "{}", e);
        let e = with_file(&["--config=gate.conf"], "rounds = 2\nrounds = 3\n").unwrap_err();
        assert!(e.contains(":2:") && e.contains("twice"), "{}", e);
        let e = with_file(&["--config=gate.conf"], "pass_idle = soon\n").unwrap_err();
        assert!(e.contains(":1:") && e.contains("pass_idle"), "{}", e);
        let e = with_file(&["--config=gate.conf"], "just words\n").unwrap_err();
        assert!(e.contains("key = value"), "{}", e);
    }

    #[test]
    fn bad_command_lines_are_refused() {
        assert!(args(&["--upstream=a", "--upstream=b"]).is_err(), "a key twice");
        assert!(args(&["--config=a", "--config=b"]).is_err(), "two files");
        assert!(args(&["99", "88"]).is_err(), "one port");
        assert!(args(&["0"]).is_err(), "port 0");
        assert!(args(&["--max-body=0x10"]).is_err());
        assert!(args(&["--bogus=1"]).is_err());
        assert!(args(&["--rounds"]).is_err(), "a value is needed");
        assert!(args(&["stray"]).is_err());
        assert_eq!(args(&["--help"]), Ok(Action::Help));
        assert_eq!(args(&["--version"]), Ok(Action::Version));
        assert!(matches!(args(&["--upstream=127.0.0.1:1", "--check"]), Ok(Action::Check(_))));
        assert!(matches!(args(&["--print-config"]), Ok(Action::Print(_))));
    }

    #[test]
    fn rules_are_enforced() {
        let bad = |f: fn(&mut Limits)| {
            let mut l = Limits::default();
            f(&mut l);
            assert!(!l.problems().is_empty(), "{:?} accepted", l);
        };
        bad(|l| l.rounds = 0);
        bad(|l| l.rounds = 6);
        bad(|l| l.challenge_ttl = Duration::from_secs(5));
        bad(|l| l.pass_idle = Duration::from_secs(10));
        bad(|l| l.pass_max = Duration::from_secs(60));
        bad(|l| l.circuit_burst = 60);
        bad(|l| l.circuit_per_minute = 30);
        bad(|l| l.challenge_per_minute = 0);
        bad(|l| l.conn_per_circuit = 0);
        bad(|l| l.max_conn = 4);
        bad(|l| l.max_body = 10);
        bad(|l| l.upstream_timeout = Duration::ZERO);
        bad(|l| l.memory_per_pass = l.memory);
        bad(|l| l.memory_per_circuit = l.memory_per_pass + 1);
        bad(|l| l.max_response = 16 << 20); // twice that exceeds the 24M circuit share
    }

    #[test]
    fn print_config_round_trips() {
        let mut c = run(args(&["--upstream=127.0.0.1:3000", "--proxy-protocol", "--pass-idle=45s", "--max-body=1500"]));
        let text = c.to_file();
        for (key, _) in KEYS {
            assert!(text.contains(&format!("\n{} = ", key)), "{} missing", key);
        }
        let mut back = Config::empty();
        back.apply_file("printed", &text).unwrap();
        assert_eq!(back, c);
        // and an empty upstream prints as a usable example
        c.upstream.clear();
        assert!(c.to_file().contains("upstream = 127.0.0.1:3000"));
    }

    #[test]
    fn the_example_file_is_valid_and_matches_the_defaults() {
        let mut c = Config::empty();
        c.apply_file("deploy/onion-gate.conf", include_str!("../deploy/onion-gate.conf")).unwrap();
        assert!(c.problems().is_empty(), "{:?}", c.problems());
        assert_eq!(c.limits, Limits::default(), "regenerate it with --print-config");
        assert!(c.proxy_protocol && c.upstream == "127.0.0.1:3000" && c.port == 8088);
    }

    #[test]
    fn every_key_can_be_set_and_read() {
        let mut c = Config::empty();
        for (key, _) in KEYS {
            let v = c.get(key);
            let v = if v.is_empty() { "127.0.0.1:1".to_string() } else { v };
            c.set(key, &v).unwrap_or_else(|e| panic!("{}: {}", key, e));
        }
    }
}
