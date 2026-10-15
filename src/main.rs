//! onion-gate binary: read the configuration, build the shared state, and run
//! the accept loop. All the gate logic lives in the library (`lib.rs`), so the
//! integration tests exercise exactly the same code path.

#![forbid(unsafe_code)]

use onion_gate::config::{self, Action, Config, KEYS};
use onion_gate::upstream::Upstream;
use onion_gate::{adaptive, metrics, serve_connection, App, COOKIE};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const STACK_SIZE: usize = 512 * 1024;

const USAGE: &str = "\
usage: onion-gate [--config=FILE] [--KEY=VALUE ...] [--check | --print-config]

  --config=FILE    read settings from FILE (lines of `key = value`, # comments)
  --KEY=VALUE      set one setting; flags override the file
  --proxy-protocol same as --proxy-protocol=yes
  --check          check the configuration and the backend, then exit
  --print-config   print the effective configuration (a ready-to-edit file)
  --help, --version

The only required setting is upstream. Behind tor, also set proxy_protocol.
Example: onion-gate --upstream=127.0.0.1:3000 --proxy-protocol";

/// The gate listens on 127.0.0.1:`port` only, so that is the one upstream
/// address that would loop back into it.
fn points_at_self(addrs: &[SocketAddr], port: u16) -> bool {
    addrs.iter().any(|a| a.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST) && a.port() == port)
}

/// Every problem with the configuration, including the upstream address.
/// Returns the resolved upstream when there is none.
fn validate(cfg: &Config) -> Result<Upstream, Vec<String>> {
    let mut problems = cfg.problems();
    let mut upstream = None;
    if !cfg.upstream.is_empty() {
        match Upstream::new(&cfg.upstream, COOKIE) {
            Ok(u) if cfg.metrics_port != 0 && points_at_self(u.addrs(), cfg.metrics_port) => problems.push(format!(
                "upstream {} is onion-gate's metrics port; point it at the backend",
                cfg.upstream
            )),
            Ok(u) if points_at_self(u.addrs(), cfg.port) => problems.push(format!(
                "upstream {} is onion-gate's own address; point it at the backend",
                cfg.upstream
            )),
            Ok(u) => upstream = Some(u),
            Err(e) => problems.push(format!("upstream = {}", e)),
        }
    }
    match upstream {
        Some(u) if problems.is_empty() => Ok(u),
        _ => Err(problems),
    }
}

fn fail(problems: &[String]) -> ! {
    for p in problems {
        eprintln!("onion-gate: {}", p);
    }
    eprintln!("(onion-gate --help lists the settings; --print-config shows the defaults)");
    std::process::exit(2);
}

fn help() {
    println!("{}\n\nSettings (file key, or --key=value; - and _ are the same):", USAGE);
    let defaults = Config {
        port: 8088,
        upstream: String::new(),
        proxy_protocol: false,
        metrics_port: 0,
        limits: Default::default(),
    }
    .to_file();
    for (key, text) in KEYS {
        let default = defaults
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{} = ", key)))
            .unwrap_or("");
        let default = if *key == "upstream" { "(required)" } else { default };
        println!("  {:<22}{:<12}{}", key, default, text);
    }
}

fn main() {
    let read = |path: &str| std::fs::read_to_string(path).map_err(|e| format!("--config={}: {}", path, e));
    let action = match config::from_args(std::env::args().skip(1), read) {
        Ok(a) => a,
        Err(e) => fail(&[e]),
    };
    let cfg = match action {
        Action::Help => return help(),
        Action::Version => return println!("onion-gate {}", env!("CARGO_PKG_VERSION")),
        Action::Print(cfg) => return print!("{}", cfg.to_file()),
        Action::Check(cfg) => return check(&cfg),
        Action::Run(cfg) => cfg,
    };
    let upstream = validate(&cfg).unwrap_or_else(|p| fail(&p));

    // The listen IP is deliberately NOT configurable: loopback only. Tor (or a
    // front such as another proxy) connects to it locally.
    let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, cfg.port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("onion-gate: could not listen on 127.0.0.1:{}: {}", cfg.port, e);
            std::process::exit(1);
        }
    };
    let l = &cfg.limits;
    eprintln!(
        "onion-gate {} listening on 127.0.0.1:{} -> upstream {} (proxy-protocol: {}, rounds: {}, max-body: {} bytes)",
        env!("CARGO_PKG_VERSION"),
        cfg.port,
        cfg.upstream,
        if cfg.proxy_protocol { "yes" } else { "no" },
        l.rounds,
        l.max_body
    );
    if !cfg.proxy_protocol {
        eprintln!(
            "warning: without proxy_protocol there are no per-circuit limits: challenge \
             generation is unlimited and only the per-pass budget applies. Use it behind tor \
             with HiddenServiceExportCircuitID haproxy"
        );
    }

    let max_conn = l.max_conn as u64;
    let metrics_listener = match cfg.metrics_port {
        0 => None,
        p => match TcpListener::bind((Ipv4Addr::LOCALHOST, p)) {
            Ok(m) => Some(m),
            Err(e) => {
                eprintln!("onion-gate: could not listen on 127.0.0.1:{} (metrics_port): {}", p, e);
                std::process::exit(1);
            }
        },
    };
    let app = Arc::new(App::new(upstream, cfg.proxy_protocol, cfg.limits));
    if app.adaptive.enabled() {
        eprintln!("captcha: adaptive (free passes while calm; the CAPTCHA for everyone new under attack)");
        let a = Arc::clone(&app);
        thread::spawn(move || adaptive::run(&a));
    }
    if let Some(m) = metrics_listener {
        eprintln!("metrics on http://127.0.0.1:{}/metrics", cfg.metrics_port);
        let a = Arc::clone(&app);
        thread::spawn(move || metrics::serve(m, &a));
    }

    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(_) => {
                thread::sleep(Duration::from_millis(20)); // e.g. EMFILE: do not spin hot
                continue;
            }
        };
        let m = &app.metrics;
        if m.conn_open.get() >= max_conn {
            m.conn_refused.inc();
            drop(stream);
            continue;
        }
        m.conn_open.inc();
        m.conn_accepted.inc();
        let a = Arc::clone(&app);
        let spawned = thread::Builder::new().stack_size(STACK_SIZE).spawn(move || {
            let _open = OpenConn(&a);
            let mut stream = stream;
            serve_connection(&mut stream, &a);
        });
        if spawned.is_err() {
            m.conn_open.dec();
        }
    }
}

/// Counts the connection as open until its thread ends, however it ends.
struct OpenConn<'a>(&'a App);
impl Drop for OpenConn<'_> {
    fn drop(&mut self) {
        self.0.metrics.conn_open.dec();
    }
}

/// `--check`: the configuration is valid, and is the backend answering?
/// Exit 0 when it can run (a backend that is down is only a warning: it may
/// start after the gate), 2 when the configuration is wrong.
fn check(cfg: &Config) {
    let upstream = validate(cfg).unwrap_or_else(|p| fail(&p));
    println!("configuration: OK");
    let up = upstream
        .addrs()
        .iter()
        .any(|a| TcpStream::connect_timeout(a, Duration::from_secs(2)).is_ok());
    if up {
        println!("backend {}: accepting connections", cfg.upstream);
    } else {
        println!("warning: backend {}: not accepting connections (yet?)", cfg.upstream);
    }
    if !cfg.proxy_protocol {
        println!("warning: proxy_protocol is off: fine for a local test, not behind tor");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(args: &[&str]) -> Config {
        match config::from_args(args.iter().map(|s| s.to_string()), |_| Err("no files".into())) {
            Ok(Action::Run(c)) => c,
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn upstream_on_the_gate_itself_is_detected() {
        let a: Vec<SocketAddr> = vec!["127.0.0.1:8088".parse().unwrap()];
        assert!(points_at_self(&a, 8088));
        assert!(!points_at_self(&a, 9000));
        let v6: Vec<SocketAddr> = vec!["[::1]:8088".parse().unwrap()];
        assert!(!points_at_self(&v6, 8088), "the gate does not listen on ::1");
    }

    #[test]
    fn validation_collects_every_problem() {
        let p = validate(&cfg(&["--upstream=127.0.0.1:8088"])).err().unwrap();
        assert!(p.iter().any(|m| m.contains("own address")), "{:?}", p);
        let p = validate(&cfg(&["--upstream=10.0.0.1:80", "--rounds=9"])).err().unwrap();
        assert_eq!(p.len(), 2, "{:?}", p);
        assert!(validate(&cfg(&["--upstream=127.0.0.1:3000"])).is_ok());
        assert!(validate(&cfg(&[])).is_err(), "upstream is required");
    }
}
