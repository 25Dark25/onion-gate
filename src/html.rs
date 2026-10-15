//! HTML templates. No JavaScript, no external resources.
//!
//! HTML of the CAPTCHA page and of the gate's generic error messages.
//!
//! IMPORTANT (security): no function in this module includes client-controlled
//! data. Only server-generated values (the token: 32 hex chars, the base64
//! image) and static messages are inserted. That is why nothing needs escaping
//! and reflected XSS is impossible. The return path after the CAPTCHA is NOT in
//! the page: it lives server-side, bound to the challenge token (store.rs).

use crate::captcha::{H, W};
use std::time::Duration;

const HEAD: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Verification required</title>
<link rel="icon" href="data:,">
<style>
body{font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;max-width:21rem;margin:2rem auto;padding:0 1rem;color:#dcdfdb;background:#1a1d21;color-scheme:dark}
a{color:#8cc2a8}
.c{display:block;width:300px;height:300px;margin:.75rem 0;padding:0;border:0;border-radius:4px;cursor:crosshair;filter:invert(.88)}
.m{color:#e8a598}
.s{color:#9aa2a7;font-size:.875rem}
.b{width:300px;height:6px;background:#343a40;border-radius:3px;overflow:hidden;margin:.75rem 0 0}
.b i{display:block;height:100%;background:#8cc2a8}
@keyframes d{from{width:100%}to{width:0}}
</style>
</head>
<body>
<main>
"#;

const TAIL: &str = "</main>\n</body>\n</html>\n";

/// Challenge page. `notice` is STATIC text (may be "").
/// `ttl` is how long the challenge is valid: the time bar empties over it.
pub fn challenge(png_b64: &str, token_hex: &str, round: u8, rounds: u8, notice: &str, ttl: Duration) -> String {
    let mut s = String::with_capacity(png_b64.len() + 1536);
    s.push_str(HEAD);
    s.push_str("<p><b>Click the broken circle.</b> (");
    s.push_str(&round.to_string());
    s.push('/');
    s.push_str(&rounds.to_string());
    s.push_str(")</p>\n");
    if !notice.is_empty() {
        s.push_str("<p class=\"m\">");
        s.push_str(notice);
        s.push_str("</p>\n");
    }
    // Time-left bar: CSS only (no JS), empties over the challenge's lifetime.
    s.push_str("<div class=\"b\"><i style=\"animation:d ");
    s.push_str(&ttl.as_secs().to_string());
    s.push_str("s linear forwards\"></i></div>\n");
    // <input type="image"> submits c.x and c.y (click coordinates in CSS px,
    // relative to the image's top-left corner). No border or padding and a
    // fixed size, so the coordinates are never offset.
    // The action is absolute, so this page works whatever URL it is served at.
    s.push_str("<form method=\"post\" action=\"/__gate/verify\">\n");
    s.push_str("<input type=\"hidden\" name=\"t\" value=\"");
    s.push_str(token_hex);
    s.push_str("\">\n");
    s.push_str("<input class=\"c\" type=\"image\" name=\"c\" width=\"");
    s.push_str(&W.to_string());
    s.push_str("\" height=\"");
    s.push_str(&H.to_string());
    s.push_str("\" alt=\"CAPTCHA\" src=\"data:image/png;base64,");
    s.push_str(png_b64);
    s.push_str("\">\n</form>\n");
    s.push_str(TAIL);
    s
}

/// Generic message (errors). `text` must be static / server-generated.
pub fn message(text: &str) -> String {
    let mut s = String::from(HEAD);
    s.push_str("<p class=\"m\">");
    s.push_str(text);
    s.push_str("</p>\n<p class=\"s\"><a href=\"/__gate/\">Try again</a></p>\n");
    s.push_str(TAIL);
    s
}

/// Standard base64 with padding (RFC 4648).
pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b0 = c[0] as u32;
        let b1 = if c.len() > 1 { c[1] as u32 } else { 0 };
        let b2 = if c.len() > 2 { c[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_high_bytes() {
        assert_eq!(base64(&[0xFF, 0xFF, 0xFF]), "////");
        assert_eq!(base64(&[0xFB, 0xEF, 0xBE]), "++++");
    }

    #[test]
    fn challenge_page_has_what_it_needs_and_nothing_external() {
        let p = challenge("QUJD", "00112233445566778899aabbccddeeff", 1, 2, "", Duration::from_secs(30));
        assert!(p.contains("<html lang=\"en\">"));
        assert!(p.contains("name=\"t\" value=\"00112233445566778899aabbccddeeff\""));
        assert!(p.contains("type=\"image\" name=\"c\""));
        assert!(p.contains("src=\"data:image/png;base64,QUJD\""));
        assert!(p.contains("method=\"post\" action=\"/__gate/verify\""));
        assert!(p.contains("<link rel=\"icon\" href=\"data:,\">"));
        assert!(!p.contains("<script"));
        assert!(!p.contains("http://") && !p.contains("https://"));
        assert!(p.contains("(1/2)"));
        // CSS time bar, no visible number of seconds
        assert!(p.contains("<i style=\"animation:d 30s linear forwards\">"));
        assert!(!p.contains("Expires"));
        // the return path is never in the form
        assert!(!p.contains("name=\"next\"") && !p.contains("name=\"r\""));
    }

    #[test]
    fn notice_only_appears_when_given() {
        assert!(!challenge("A", "t", 1, 1, "", Duration::from_secs(30)).contains("class=\"m\""));
        assert!(challenge("A", "t", 1, 1, "Wrong", Duration::from_secs(30)).contains("<p class=\"m\">Wrong</p>"));
    }
}
