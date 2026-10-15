//! onion-gate binary: parse the flags, build the shared state, and run the
//! accept loop. All the gate logic lives in the library (`lib.rs`), so the
//! integration tests exercise exactly the same code path.

#![forbid(unsafe_code)]

use onion_gate::http::DEFAULT_MAX_BODY;
use onion_gate::upstream::Upstream;
use onion_gate::{limit::Limiter, limit::Memory, serve_connection, store::Store, App, COOKIE};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const DEFAULT_PORT: u16 = 8088;
/// Maximum simultaneous connections overall; extra ones are simply closed.
const MAX_CONN: usize = 512;
const STACK_SIZE: usize = 512 * 1024;

static ACTIVE: AtomicUsize = AtomicUsize::new(0);

struct Config {
    port: u16,
    proxy: bool,
    upstream: String,
    max_body: usize,
}

fn parse_args<I: Iterator<Item = String>>(args: I) -> Result<Config, String> {
    let mut port: Option<u16> = None;
    let mut proxy = false;
    let mut upstream: Option<String> = None;
    let mut max_body: Option<usize> = None;
    for a in args {
        if a == "--proxy-protocol" {
            proxy = true;
        } else if let Some(v) = a.strip_prefix("--upstream=") {
            if upstream.is_some() || v.is_empty() {
                return Err(format!("invalid argument: {} (a host:port, once)", a));
            }
            upstream = Some(v.to_string());
        } else if let Some(v) = a.strip_prefix("--max-body=") {
            match v.parse::<usize>() {
                Ok(n) if max_body.is_none() && n > 0 => max_body = Some(n),
                _ => return Err(format!("invalid argument: {} (a positive byte count, once)", a)),
            }
        } else if port.is_none() {
            match a.parse::<u16>() {
                Ok(p) if p != 0 => port = Some(p),
                _ => return Err(format!("invalid argument: {}", a)),
            }
        } else {
            return Err(format!("unexpected argument: {}", a));
        }
    }
    let upstream = upstream.ok_or("missing --upstream=HOST:PORT (the backend to protect)")?;
    Ok(Config {
        port: port.unwrap_or(DEFAULT_PORT),
        proxy,
        upstream,
        max_body: max_body.unwrap_or(DEFAULT_MAX_BODY),
    })
}

struct ConnGuard;
impl Drop for ConnGuard {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

fn main() {
    let cfg = match parse_args(std::env::args().skip(1)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            eprintln!(
                "usage: onion-gate [port] --upstream=HOST:PORT [--proxy-protocol] [--max-body=BYTES]   (default port {})",
                DEFAULT_PORT
            );
            std::process::exit(2);
        }
    };

    let upstream = match Upstream::new(&cfg.upstream, COOKIE) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("--upstream: {}", e);
            std::process::exit(1);
        }
    };

    // The listen IP is deliberately NOT configurable: loopback only. Tor (or a
    // front such as another proxy) connects to it locally.
    let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, cfg.port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("could not listen on 127.0.0.1:{}: {}", cfg.port, e);
            std::process::exit(1);
        }
    };
    eprintln!(
        "onion-gate listening on 127.0.0.1:{} -> upstream {} (proxy-protocol: {}, max-body: {} bytes)",
        cfg.port,
        cfg.upstream,
        if cfg.proxy { "yes" } else { "no" },
        cfg.max_body
    );

    let app = Arc::new(App {
        store: Store::new(),
        limiter: Limiter::new(),
        upstream,
        proxy: cfg.proxy,
        max_body: cfg.max_body,
        memory: Memory::default(),
    });

    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(_) => {
                thread::sleep(Duration::from_millis(20)); // e.g. EMFILE: do not spin hot
                continue;
            }
        };
        if ACTIVE.fetch_add(1, Ordering::SeqCst) >= MAX_CONN {
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
            drop(stream);
            continue;
        }
        let a = Arc::clone(&app);
        let spawned = thread::Builder::new().stack_size(STACK_SIZE).spawn(move || {
            let _guard = ConnGuard;
            let mut stream = stream;
            serve_connection(&mut stream, &a);
        });
        if spawned.is_err() {
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(args: &[&str]) -> Result<Config, String> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn upstream_is_required() {
        assert!(a(&["8088"]).is_err());
        assert!(a(&["--upstream=127.0.0.1:3000"]).is_ok());
    }

    #[test]
    fn parses_all_flags() {
        let c = a(&["9000", "--upstream=127.0.0.1:3000", "--proxy-protocol", "--max-body=2048"]).unwrap();
        assert_eq!(c.port, 9000);
        assert!(c.proxy);
        assert_eq!(c.upstream, "127.0.0.1:3000");
        assert_eq!(c.max_body, 2048);
    }

    #[test]
    fn defaults_and_rejections() {
        let c = a(&["--upstream=127.0.0.1:3000"]).unwrap();
        assert_eq!(c.port, DEFAULT_PORT);
        assert!(!c.proxy);
        assert_eq!(c.max_body, DEFAULT_MAX_BODY);
        assert!(a(&["0", "--upstream=x:1"]).is_err(), "port 0 rejected");
        assert!(a(&["--upstream=a", "--upstream=b"]).is_err(), "upstream once");
        assert!(a(&["--max-body=0", "--upstream=x:1"]).is_err(), "max-body > 0");
        assert!(a(&["99", "88", "--upstream=x:1"]).is_err(), "one port");
    }
}
