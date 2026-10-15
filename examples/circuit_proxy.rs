//! Stands in for tor in local tests: accepts plain connections (from a browser
//! or curl) and passes them to onion-gate with a PROXY v1 line in front, the way
//! tor does with `HiddenServiceExportCircuitID haproxy`. Not for production.
//!
//!     cargo run --example circuit_proxy -- LISTEN_PORT GATE_PORT [--circuit=N]
//!
//! Every connection carries the same circuit identifier N (default 1), as all
//! of one Tor Browser tab's requests share a circuit. Run several instances on
//! different ports with different N to play several visitors.
//!
//! The line has tor's shape, `PROXY TCP6 fc00:dead:beef:4dad::HHHH:LLLL ::1 ...`,
//! with the circuit identifier in the low 32 bits of the source address.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::thread;

fn usage() -> ! {
    eprintln!("usage: circuit_proxy LISTEN_PORT GATE_PORT [--circuit=N]   (N: 0..=4294967295, default 1)");
    std::process::exit(2);
}

fn port(a: Option<String>) -> u16 {
    match a.map(|a| a.parse::<u16>()) {
        Some(Ok(p)) if p != 0 => p,
        _ => usage(),
    }
}

/// The PROXY v1 line tor would send for `circuit`.
fn proxy_line(circuit: u32, dst_port: u16) -> String {
    format!(
        "PROXY TCP6 fc00:dead:beef:4dad::{:x}:{:x} ::1 {} {}\r\n",
        circuit >> 16,
        circuit & 0xFFFF,
        dst_port,
        dst_port
    )
}

/// Copies `from` into `to` until EOF, then half-closes `to`.
fn pump(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

fn main() {
    let mut args = std::env::args().skip(1);
    let listen = port(args.next());
    let gate = port(args.next());
    let mut circuit: u32 = 1;
    for a in args {
        match a.strip_prefix("--circuit=").map(|v| v.parse::<u32>()) {
            Some(Ok(n)) => circuit = n,
            _ => usage(),
        }
    }

    let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, listen)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("could not listen on 127.0.0.1:{}: {}", listen, e);
            std::process::exit(1);
        }
    };
    eprintln!(
        "circuit proxy: 127.0.0.1:{} -> onion-gate 127.0.0.1:{} as circuit {}",
        listen, gate, circuit
    );
    for client in listener.incoming().flatten() {
        thread::spawn(move || {
            let mut upstream = match TcpStream::connect((Ipv4Addr::LOCALHOST, gate)) {
                Ok(u) => u,
                Err(_) => return,
            };
            if upstream.write_all(proxy_line(circuit, listen).as_bytes()).is_err() {
                return;
            }
            let (c2, u2) = match (client.try_clone(), upstream.try_clone()) {
                (Ok(c), Ok(u)) => (c, u),
                _ => return,
            };
            let back = thread::spawn(move || pump(u2, c2));
            pump(client, upstream);
            let _ = back.join();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gate_reads_back_the_circuit() {
        for c in [0u32, 1, 0xFFFF, 0x1_0000, 0xDEAD_BEEF, u32::MAX] {
            let line = proxy_line(c, 80);
            assert!(line.len() <= 107, "PROXY v1 lines are at most 107 bytes");
            let parsed = onion_gate::http::parse_proxy(line.trim_end_matches("\r\n"));
            assert_eq!(parsed, Some(c), "{:?}", line);
        }
    }
}
