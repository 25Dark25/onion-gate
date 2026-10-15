# Testing onion-gate

Three layers, from cheapest to most realistic:

1. **`cargo test`** — unit tests, end-to-end tests over loopback sockets
   (`tests/flow.rs`) and a small fuzzer over the parsers (`src/fuzz.rs`, see
   [Fuzzing](#fuzzing)). The end-to-end tests solve the CAPTCHA by reading the
   server's own state, so they cover the whole flow, including forwarding and
   the budgets.
2. **The local harness** (`scripts/harness.sh`) — the real binaries as separate
   processes, a test backend, and curl or a browser. No tor needed.
3. **Tor Browser at the Safest level** against a real `.onion` — the only test
   of what a visitor actually sees. This one is manual: see the
   [checklist](#tor-browser-checklist).

## The local harness

Requirements: a Unix system, Rust (as for building), bash and curl 8.2 or later
(for `--haproxy-clientip`). Everything is built from this repository; nothing
is downloaded.

Two example programs make it work. They are std only, like the gate, and are
not meant for production:

- `examples/test_backend.rs` — a small backend with pages that exercise what
  the gate must relay: a page with 21 sub-requests, a form, an echo of what the
  backend received (headers and body), a backend cookie, a redirect, a large
  and a chunked response, and a slow one. The list is at the top of the file.
- `examples/circuit_proxy.rs` — plays tor's part for a browser: it passes each
  connection on to the gate with a PROXY v1 line carrying a fixed circuit
  identifier, as tor does with `HiddenServiceExportCircuitID haproxy`.

### `scripts/harness.sh check`

Builds, starts a backend and a gate (with `--proxy-protocol` and metrics) on
ports 13001, 18089 and 18099, runs the checks below with curl, and stops
everything. CI runs it on Linux.

- without a pass, every path is the challenge (`200`), with nothing of the
  backend in it;
- security headers on the challenge (`Cache-Control: no-store`, the CSP,
  `Connection: close`) and no `<script>`;
- `HEAD` gets headers and no body;
- the `/__gate/` namespace: `404` for unknown paths, `405` with `Allow: POST`
  for `GET /__gate/verify`;
- a bogus token, a wrong click and a replayed token all get the same generic
  failure, and none gets a pass;
- a malformed or unknown pass cookie gets the challenge and is cleared;
- a connection without the PROXY line is closed without an answer;
- per circuit: 10 challenges in a burst, then `429` with `Retry-After`, while
  another circuit is still served;
- per circuit: 8 connections held open, the 9th gets `429`; it is served again
  once they close;
- the metrics (on port 18099) counted the challenges, failures, 429s and the
  missing PROXY line above, show no path, and serve nothing but `/metrics`;
- the binary refuses a non-loopback upstream, an upstream on its own port, and
  unknown flags.

What it does **not** cover, because curl cannot pass the CAPTCHA: everything
behind a valid pass. That is covered by `tests/flow.rs`, by `pass` below and by
the browser checklist.

### `scripts/harness.sh up` and `pass`

`up` starts a stack for a browser and keeps it running until Ctrl-C:

| What | Address |
| --- | --- |
| test backend, direct (for comparison only) | `http://127.0.0.1:13000/` |
| onion-gate, with `--proxy-protocol` | `127.0.0.1:18088` |
| visitor on circuit 1 | `http://127.0.0.1:18080/` |
| visitor on circuit 2 | `http://127.0.0.1:18081/` |

Open a visitor address in a browser with JavaScript disabled, pass the
CAPTCHA, copy the value of the `onion_gate_pass` cookie (developer tools →
Storage) and run, in another terminal:

```bash
scripts/harness.sh pass <cookie value>          # checks behind the gate
scripts/harness.sh pass <cookie value> --spend  # ...then spends the pass's budget (revokes it)
```

`pass` checks that: the backend is reached; it does not see the pass cookie
but does see the others; it sees none of `X-Forwarded-*`, `Forwarded`,
`X-Real-IP`, `True-Client-IP`, `X_Forwarded_For`, `Proxy`; a `POST` body
arrives intact; chunked, 1 MiB and redirect responses are relayed; a response
over the 8 MiB cap is a `502`; `/__gate/` is never forwarded, even with a pass.
With `--spend`, it then makes requests until the budget runs out and checks
that the pass is revoked and its cookie cleared.

`HARNESS_RELEASE=1` uses the release build; `BACKEND_PORT`, `GATE_PORT` and
`BROWSER_PORT` change the ports of `up` and `pass`.

Tor Browser cannot use the `127.0.0.1` addresses: it sends everything through
tor, so loopback addresses are not reachable from it. For Tor Browser, put the
stack behind a real onion service.

## Fuzzing

The parsers are what a visitor (and a backend) can feed arbitrary bytes to, so
they are fuzzed against **properties**, not just for crashes. The targets are
in `src/fuzz.rs`:

| Target | Input | Property |
| --- | --- | --- |
| `request` | a request head | what the parser accepts is well-formed, and the request the gate would forward is accepted by the same strict parser, framed exactly (no byte left over for a second request), with one `Host` and `Connection: close`, and without the pass cookie, client-identity or hop-by-hop headers (the list is written out in the target, not taken from the code it checks) |
| `response` | a backend response | the re-framed response has no control bytes in any line (no response splitting), a valid status line, one `Content-Length` and no `Transfer-Encoding`, a body of exactly that length, and re-framing it again changes nothing |
| `chunks` | a chunked body | walking it as it arrives, in pieces, gives the same result and bytes as walking it whole |
| `proxy_line`, `cookies`, `return_path` | a PROXY line, a `Cookie` value, a request target | no panic; the pass cookie never survives `cookie_without`; the return path is never an open redirect |

### In `cargo test`

A deterministic, std-only mutation fuzzer runs every target 20 000 times on
each `cargo test` (well under a second). It has no coverage feedback, so it is
a regression net, not a substitute for the real thing. To run it longer or with
other random choices:

```bash
FUZZ_ITERS=3000000 FUZZ_SEED=7 cargo test --release --lib fuzz
```

A failure prints the target, the seed and the input.

### With libFuzzer (outside the repository)

The `fuzzing` feature exposes the same targets to a coverage-guided fuzzer. It
adds no dependency to onion-gate: the fuzzer crate lives in a directory of its
own, outside this repository, and depends on onion-gate by path. With
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (it needs a nightly
toolchain):

```bash
mkdir -p ~/og-fuzz/fuzz_targets && cd ~/og-fuzz
cat > Cargo.toml <<'TOML'
[package]
name = "og-fuzz"
version = "0.0.0"
edition = "2021"
publish = false

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
onion-gate = { path = "/path/to/onion-gate", features = ["fuzzing"] }

[workspace]
TOML
for t in request response chunks proxy_line cookies return_path; do
  printf '#![no_main]\nlibfuzzer_sys::fuzz_target!(|data: &[u8]| onion_gate::fuzz::%s(data));\n' "$t" > "fuzz_targets/$t.rs"
  printf '\n[[bin]]\nname = "%s"\npath = "fuzz_targets/%s.rs"\ntest = false\ndoc = false\nbench = false\n' "$t" "$t" >> Cargo.toml
done
cargo +nightly fuzz run --fuzz-dir . request -- -max_total_time=900
```

For `response` and `chunks`, the first byte of each input is not part of the
message: it selects a HEAD request (odd) or the size of the pieces.

### What fuzzing has found

- A backend status code outside 100–599 (`000`, `999`) was relayed to the
  visitor as an invalid status line (`HTTP/1.1 0 OK`); it is now a `502`.
  Found by the in-repo fuzzer in under a second.
- libFuzzer found that a backend header literally named `close` is relayed and
  then, on a second pass, removed as hop-by-hop (named by the gate's own
  `Connection: close`). Harmless; the property was adjusted and the input kept
  as a seed.

The properties were checked by breaking the code on purpose (mutation
testing): eight realistic defects — forwarding `X-Forwarded-*`, a header named
in `Connection` or the pass cookie, an off-by-one `Content-Length`, accepting
`Transfer-Encoding` or two `Host` headers, relaying control bytes, and an
off-by-one in the chunk-size line cap — were each caught by `cargo test`.

## Tor Browser checklist

This is the test that matters, and it is manual. It needs tor on the machine
that runs the stack, and Tor Browser anywhere.

### Setup

1. Start the stack: `scripts/harness.sh up` (gate on `127.0.0.1:18088`).
2. Run a throwaway onion service pointing at it. A minimal `torrc` for that:

   ```
   DataDirectory /tmp/og-tor/data
   HiddenServiceDir /tmp/og-tor/hs
   HiddenServicePort 80 127.0.0.1:18088
   HiddenServiceExportCircuitID haproxy
   SocksPort 0
   ```

   ```bash
   mkdir -p -m 700 /tmp/og-tor/data /tmp/og-tor/hs
   tor -f /path/to/that/torrc
   cat /tmp/og-tor/hs/hostname        # the .onion to open
   ```

3. In Tor Browser: Settings → Privacy & Security → Security Level → **Safest**.
   Check that JavaScript is really off: the shield icon in the toolbar says
   Safest.
4. Write down: the onion-gate commit, `tor --version`, the Tor Browser version,
   the operating system, and the zoom level if it is not 100%.

The `pass` checks work against this stack too, with a cookie copied from Tor
Browser.

### Checks

Mark each one pass or fail, with a note for anything unexpected. Every
failure is worth a report with what you saw.

| # | Do | Expect |
| --- | --- | --- |
| 1 | Open `http://<onion>/form?x=1` | The CAPTCHA page, at that address (no redirect): text, a 300×300 image that renders, a time bar that empties in 30 s. Nothing of the test backend |
| 2 | Click a plain (unbroken) ring | "Wrong or expired. Try this new image.", a new image, round 1/2 again |
| 3 | Click the broken ring twice (two rounds) | After round 1: "Correct. One more." and round 2/2. After round 2: you land on `/form?x=1`, the backend's form |
| 4 | Load `/` | "the gate let you through", the green line (stylesheet) and all 20 images |
| 5 | Submit the form on `/form` | The echo page shows the text intact (accents and symbols included), no `onion_gate_pass` in `Cookie`, no `X-Forwarded-*`, `Forwarded` or `X-Real-IP` |
| 6 | Open `/cookie`, then `/echo` | `backend_test=1` is in the echo's `Cookie` |
| 7 | Open `/redirect` | You end up on `/` |
| 8 | Open `/chunked` and `/big?kib=1024` | Ten "chunk N of 10" lines; 1 MiB of text |
| 9 | Open `/big?kib=9000` | The gate's error page ("The site behind the gate did not respond"), not a broken download |
| 10 | Open `/slow?s=40` | After about 30 s, the gate's error page (`504`) |
| 11 | On a new challenge (open the site in a New Identity), wait for the bar to empty plus 10 s, then click the broken ring | "Wrong or expired", a new image |
| 12 | On a challenge, move to the image with Tab and press Enter (no mouse) | "Wrong or expired": a keyboard submit sends no useful point. This records a known accessibility limit, not a bug |
| 13 | Zoom to 133% (Ctrl +) and pass the CAPTCHA | The clicks land where you click: a correct click is accepted |
| 14 | With a pass, hold F5 on `/` for a while | Eventually: the CAPTCHA with "Too many requests in a short time. Please verify again." Solving it gives a new pass |
| 15 | New Tor circuit for this site (Ctrl+Shift+L), then reload | Still passes: the pass is not tied to a circuit |
| 16 | New Identity, then open the site | The CAPTCHA again (the cookie is gone) |
| 17 | Restart the stack (Ctrl-C, `up` again), reload | The CAPTCHA again: passes do not survive a restart |
| 18 | Open `/` in 10 tabs at once | Note what happens: some requests may get the "Too many requests from your connection" page (8 connections per circuit) |
| 19 | Fail the CAPTCHA quickly, over and over | After about 10 images in a minute: "Too many requests from your connection. Wait a minute." (10 challenge images per circuit in a burst, 1 more every 6 s) |
| 20 | Try the page on a narrow window (letterboxing) and with the dark/light theme | Text is readable; the image fits and keeps its 300×300 size |

Items 1, 3, 12, 13 and 20 are about what only a real browser shows (image
rendering, click coordinates, layout); the rest are also covered by the
automated tests and are here to confirm that tor and Tor Browser do not change
the behavior.
