//! A small loopback backend for trying onion-gate by hand. Not for production.
//!
//!     cargo run --example test_backend -- [port]        (default 3000)
//!
//! Every page it serves is something a real site does that the gate must relay
//! correctly. Pages:
//!
//!   /                 HTML page with a stylesheet and 20 images (21 sub-requests)
//!   /style.css        the stylesheet
//!   /img/N.png        a small PNG (any N)
//!   /form             a form that posts to /echo
//!   /echo             the method, target, headers and body this backend received
//!   /cookie           sets a backend cookie (it must reach /echo afterwards)
//!   /redirect         302 to /
//!   /big?kib=N        N KiB of text (at most 16384), for the response cap
//!   /chunked          a chunked response
//!   /slow?s=N         answers after N seconds (at most 120), for the I/O timeout
//!   anything else     404
//!
//! Like the gate, it is std only and listens on 127.0.0.1 only.

use onion_gate::png;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

const MAX_HEAD: usize = 64 * 1024;
const MAX_BODY: usize = 16 * 1024 * 1024;
const MAX_BIG_KIB: usize = 16 * 1024;
const MAX_SLOW_SECS: u64 = 120;
const IMAGES: usize = 20;

fn main() {
    let port: u16 = match std::env::args().nth(1) {
        None => 3000,
        Some(a) => match a.parse() {
            Ok(p) if p != 0 => p,
            _ => {
                eprintln!("usage: test_backend [port]   (default 3000)");
                std::process::exit(2);
            }
        },
    };
    let listener = match TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("could not listen on 127.0.0.1:{}: {}", port, e);
            std::process::exit(1);
        }
    };
    eprintln!("test backend listening on 127.0.0.1:{}", port);
    for mut s in listener.incoming().flatten() {
        thread::spawn(move || {
            s.set_read_timeout(Some(Duration::from_secs(30))).ok();
            s.set_write_timeout(Some(Duration::from_secs(30))).ok();
            if let Some((head, body)) = read_request(&mut s) {
                let resp = respond(&head, &body);
                let _ = s.write_all(&resp);
            }
        });
    }
}

/// Reads one request: the head and a Content-Length body. None on anything odd.
fn read_request(s: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(he) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..he]).into_owned();
            let len = header(&head, "content-length").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
            if len > MAX_BODY {
                return None;
            }
            while buf.len() < he + 4 + len {
                let n = s.read(&mut chunk).ok()?;
                if n == 0 {
                    return None;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            return Some((head, buf[he + 4..he + 4 + len].to_vec()));
        }
        if buf.len() > MAX_HEAD {
            return None;
        }
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// The first value of header `name` (lowercase) in `head`.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name) {
            Some(v.trim())
        } else {
            None
        }
    })
}

/// The value of `key` in a query string.
fn query_get<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn response(status: &str, ctype: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n",
        status,
        ctype,
        body.len(),
        extra
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

fn html(title: &str, inner: &str) -> Vec<u8> {
    let page = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>{}</title>\n\
         <link rel=\"stylesheet\" href=\"/style.css\">\n</head>\n<body>\n<h1>{}</h1>\n{}\n\
         <p><a href=\"/\">home</a> · <a href=\"/form\">form</a> · <a href=\"/echo\">echo</a> · \
         <a href=\"/cookie\">cookie</a> · <a href=\"/big?kib=1024\">1 MiB</a> · \
         <a href=\"/chunked\">chunked</a> · <a href=\"/redirect\">redirect</a></p>\n</body>\n</html>\n",
        title, title, inner
    );
    response("200 OK", "text/html; charset=utf-8", "", page.as_bytes())
}

/// A 16x16 1-bit PNG: a checkerboard whose phase depends on `n`, so every
/// image URL is a distinct resource.
fn image(n: usize) -> Vec<u8> {
    let mut raw = Vec::with_capacity(16 * 3);
    for y in 0..16 {
        raw.push(0); // filter: none
        let row: u16 = if (y / 4 + n) % 2 == 0 { 0xF0F0 } else { 0x0F0F };
        raw.extend_from_slice(&row.to_be_bytes());
    }
    png::encode(16, 16, 1, 0, &raw)
}

fn respond(head: &str, body: &[u8]) -> Vec<u8> {
    let mut first = head.lines().next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("");
    let target = first.next().unwrap_or("/");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));

    match path {
        "/" => {
            let mut imgs = String::new();
            for i in 0..IMAGES {
                imgs.push_str(&format!("<img src=\"/img/{}.png\" width=\"32\" height=\"32\" alt=\"{}\">\n", i, i));
            }
            html(
                "onion-gate test backend",
                &format!(
                    "<p>If you can read this, the gate let you through. This page loads a \
                     stylesheet and {} images: {} requests in all, each charged to the pass and \
                     circuit budgets.</p>\n<p class=\"ok\">The stylesheet loaded if this line is green.</p>\n{}",
                    IMAGES,
                    IMAGES + 2,
                    imgs
                ),
            )
        }
        "/style.css" => response(
            "200 OK",
            "text/css",
            "",
            b"body{font:16px/1.5 sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}\
              .ok{color:#080;font-weight:bold}img{margin:2px;image-rendering:pixelated}\
              pre{white-space:pre-wrap;word-break:break-all;background:#eee;padding:.5rem}\n",
        ),
        p if p.starts_with("/img/") && p.ends_with(".png") => {
            let n = p["/img/".len()..p.len() - 4].parse::<usize>().unwrap_or(0);
            response("200 OK", "image/png", "Cache-Control: no-store\r\n", &image(n))
        }
        "/form" => html(
            "Form",
            "<form method=\"post\" action=\"/echo\">\n<p><textarea name=\"text\" rows=\"6\" cols=\"50\">\
             Ünïcödé, &amp; symbols = + %</textarea></p>\n<p><button>Send</button></p>\n</form>",
        ),
        "/echo" => html(
            "Echo",
            &format!(
                "<p>What this backend received. Check that there is no <code>onion_gate_pass</code> \
                 cookie and no <code>X-Forwarded-*</code>, <code>Forwarded</code> or <code>X-Real-IP</code> \
                 header.</p>\n<pre>{}\n\n{} body bytes:\n{}</pre>",
                escape(head),
                body.len(),
                escape(&String::from_utf8_lossy(body))
            ),
        ),
        "/cookie" => {
            let mut r = html("Cookie", "<p>Set the cookie <code>backend_test=1</code>. Open <a href=\"/echo\">echo</a>: it must be there.</p>");
            let at = r.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0) + 2;
            r.splice(at..at, b"Set-Cookie: backend_test=1; Path=/; HttpOnly; SameSite=Lax\r\n".iter().copied());
            r
        }
        "/redirect" => response("302 Found", "text/plain", "Location: /\r\n", b"to /\n"),
        "/big" => {
            let kib = query_get(query, "kib").and_then(|v| v.parse::<usize>().ok()).unwrap_or(1024).min(MAX_BIG_KIB);
            let line = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde\n"; // 64 bytes
            let mut b = Vec::with_capacity(kib * 1024);
            while b.len() < kib * 1024 {
                b.extend_from_slice(line);
            }
            response("200 OK", "text/plain", "", &b)
        }
        "/chunked" => {
            let mut r = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
            for i in 0..10 {
                let part = format!("chunk {} of 10\n", i + 1);
                r.extend_from_slice(format!("{:x}\r\n{}\r\n", part.len(), part).as_bytes());
            }
            r.extend_from_slice(b"0\r\n\r\n");
            r
        }
        "/slow" => {
            let secs = query_get(query, "s").and_then(|v| v.parse::<u64>().ok()).unwrap_or(5).min(MAX_SLOW_SECS);
            thread::sleep(Duration::from_secs(secs));
            html("Slow", &format!("<p>Answered after {} s.</p>", secs))
        }
        _ if method == "HEAD" || method == "GET" || method == "POST" => {
            response("404 Not Found", "text/plain", "", b"backend: not found\n")
        }
        _ => response("405 Method Not Allowed", "text/plain", "Allow: GET, HEAD, POST\r\n", b"backend: method not allowed\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(r: &[u8]) -> String {
        String::from_utf8_lossy(r).into_owned()
    }

    #[test]
    fn home_links_every_image() {
        let r = text(&respond("GET / HTTP/1.1", b""));
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n"));
        assert_eq!(r.matches("<img ").count(), IMAGES);
    }

    #[test]
    fn echo_escapes_what_it_reflects() {
        let r = text(&respond("POST /echo HTTP/1.1\r\nX-Test: <b>", b"<script>"));
        assert!(r.contains("&lt;b&gt;") && r.contains("&lt;script&gt;"));
        assert!(!r.contains("<script>") && !r.contains("<b>"));
    }

    #[test]
    fn big_is_capped_and_sized() {
        let r = respond("GET /big?kib=3 HTTP/1.1", b"");
        let he = r.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        assert_eq!(r.len() - he - 4, 3 * 1024);
        assert!(text(&r).contains("Content-Length: 3072\r\n"));
    }

    #[test]
    fn cookie_header_lands_in_the_head() {
        let r = text(&respond("GET /cookie HTTP/1.1", b""));
        let (head, _) = r.split_once("\r\n\r\n").unwrap();
        assert!(head.contains("\r\nSet-Cookie: backend_test=1;"));
    }

    #[test]
    fn images_are_valid_pngs() {
        let p = image(3);
        assert_eq!(&p[..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        assert_ne!(image(0), image(1));
    }
}
