# onion-gate

[![tests](https://github.com/25Dark25/onion-gate/actions/workflows/test.yml/badge.svg)](https://github.com/25Dark25/onion-gate/actions/workflows/test.yml)

A no-JavaScript CAPTCHA **gate** and **reverse proxy** that sits in front of any
local web backend. Nothing behind it is reachable until the visitor passes a
"click the broken circle" challenge; once they do, their requests are forwarded
to your backend and per-Tor-circuit limits throttle abuse.

Written in Rust with **only the standard library — zero dependencies**. It works
in Tor Browser at the *Safest* level (no JavaScript at all), listens on
`127.0.0.1` only, and makes exactly one kind of outbound connection: to the
loopback backend you point it at.

> **Status / honesty note.** This project was extracted and adapted from a larger
> codebase **with the help of an AI assistant (Claude)**. It has **not** had an
> independent security audit. The CAPTCHA stops bots that do not target it and
> cheap floods; it does **not** stop a solver written for it (a classical one
> passes about 35 % of the time, see
> [docs/CAPTCHA-STRENGTH.md](docs/CAPTCHA-STRENGTH.md)), a trained model or a
> human solver farm. Read [Limitations](#limitations) before relying on it. Use
> it as a speed bump and a rate-limiter, not as a wall.

## What it is for

A hidden service (or any site you can run a local backend for) gets hammered by
bots, scrapers and cheap floods. onion-gate makes every visitor pass a small
image CAPTCHA once per session before any request reaches your backend, and caps
how fast a single Tor circuit can hit you. Your backend can be anything —
nginx, Caddy, a Python/Go/Node app, another Rust binary — as long as it listens
on loopback.

## How it works

```
Tor Browser ──.onion──▶ tor ──PROXY line──▶ onion-gate (127.0.0.1) ──▶ your backend (127.0.0.1)
                                                 │
                                       no valid pass? serve a CAPTCHA
                                       valid pass?    forward the request
```

1. A visitor requests any path without a valid pass. The response is a challenge
   page served **in place** (HTTP `200` at the same URL, no redirect — saves a
   round trip over Tor). The path they asked for is remembered **server-side**,
   bound to the challenge token.
2. The challenge is a 300×300 PNG generated in memory (thin rings, one with a
   gap, plus distortion), embedded as a `data:` URI inside an
   `<input type="image">`. Clicking it posts the click coordinates.
3. The server validates the click in the undistorted image space. The token is
   **single-use** (deleted on the first attempt) and expires after 30 s
   (+5 s grace for Tor latency). A CSS-only bar shows the time left.
4. **Two rounds** are required. A wrong click restarts with a fresh image,
   keeping the path the visitor was going to.
5. On success the server sets a session cookie (`onion_gate_pass`) and `303`s the
   visitor back to the path they originally asked for (query string included).
6. With a valid pass, every request is **forwarded to your backend** and the
   response relayed back. Each request renews the pass and is charged to two
   budgets: the pass's and the Tor circuit's. If either runs out, the pass is
   revoked and the visitor gets a challenge again.

Without a valid pass, the answer to **any** path is a challenge — including paths
that do not exist — so the gate reveals nothing about your backend until the
CAPTCHA is passed.

### The gate's own namespace

onion-gate reserves the path prefix **`/__gate/`** for itself (the challenge form
posts to `/__gate/verify`). Your backend must not use that prefix; everything
else is forwarded untouched.

### What the backend sees

Forwarded requests keep their method, path, query and headers, **except**:

- hop-by-hop headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`,
  `Upgrade`, …) are dropped;
- the `onion_gate_pass` cookie is stripped from the `Cookie` header (other
  cookies pass through);
- headers that claim to describe the client or an earlier proxy are dropped:
  `Forwarded`, every `X-Forwarded-*`, `X-Real-IP`, `X-Client-IP`,
  `True-Client-IP` and similar, plus `Proxy` (httpoxy). onion-gate is the first
  hop and connects from loopback, so a backend that trusts these from a local
  proxy would otherwise believe whatever the visitor wrote. Names are matched
  with `_` read as `-`, as CGI and PHP do;
- `Content-Length` is recomputed (and sent as `0` for an empty `POST`, `PUT`
  or `PATCH`) and `Connection: close` is forced.

onion-gate **adds nothing** about the visitor — no `X-Forwarded-For`, no client
address. The backend learns only what the request itself carried. That is
deliberate: the whole point is that the visitor stays anonymous.

## Requirements

- A Unix-like system (Linux, macOS, BSD): randomness comes from `/dev/urandom`,
  and the build refuses other targets. Windows is not supported.
- Rust 1.82+ (`cargo`), std only — no crates to download.
- A backend that listens on a loopback address (`127.0.0.1` or `::1`).
- For per-circuit limits: tor with `HiddenServiceExportCircuitID haproxy`
  (see [`deploy/torrc.example`](deploy/torrc.example)). Without it the gate still
  works, but can only apply the per-pass limit: challenge generation (CPU) is
  then unlimited, so run without `--proxy-protocol` for local tests only (the
  binary warns at startup).

## Build and run

```bash
cargo build --release --offline      # produces target/release/onion-gate
cargo test  --offline                 # run the test suite
```

Run it in front of a backend on `127.0.0.1:3000`:

```bash
# local testing (plain HTTP, no PROXY line, no per-circuit limits):
./target/release/onion-gate 8088 --upstream=127.0.0.1:3000

# production behind tor (tor sends the PROXY line):
./target/release/onion-gate 8088 --proxy-protocol --upstream=127.0.0.1:3000
```

Flags:

| Flag | Meaning |
| --- | --- |
| `[port]` | Port to listen on (loopback only). Default `8088`. |
| `--upstream=HOST:PORT` | **Required.** The backend to protect. Must resolve to loopback, and not to onion-gate's own port. |
| `--proxy-protocol` | Require tor's PROXY v1 line on every connection (production). |
| `--max-body=BYTES` | Cap on request body size (default 1 MiB). |

Then open the `.onion` (or `http://127.0.0.1:8088` for a local test) in Tor
Browser: you get the CAPTCHA first, and your site after.

## Download and verify a release

Releases are on the [Releases page](https://github.com/25Dark25/onion-gate/releases). Each one contains the source zip, a detached OpenPGP signature (`.asc`) and the SHA-256 of the zip in the release notes. There are no prebuilt binaries: verify the zip, then build it with `cargo build --release --offline`.

**PGP key fingerprint:** `A7FC EDEA D7E6 C343 7312  284A 442D A687 E0FF 73EE`

- Published at keys.openpgp.org: <https://keys.openpgp.org/vks/v1/by-fingerprint/A7FCEDEAD7E6C3437312284A442DA687E0FF73EE>
- Also on GitHub: <https://github.com/25Dark25.gpg>

```bash
# Linux / macOS
curl -sSL https://github.com/25Dark25.gpg | gpg --import
# Windows (PowerShell), to verify the download before copying it to a Unix host
Invoke-WebRequest https://github.com/25Dark25.gpg -OutFile 25Dark25.gpg; gpg --import 25Dark25.gpg

gpg --fingerprint A7FCEDEAD7E6C3437312284A442DA687E0FF73EE   # must match the fingerprint above
gpg --verify onion-gate-0.1.0.zip.asc onion-gate-0.1.0.zip     # use the file names of the release you downloaded
```

`gpg` will report a good signature and also warn that the key is not certified; that is expected. What matters is that the fingerprint is the same in several independent places (this README, the release notes and keys.openpgp.org). A valid signature shows the file was published by whoever controls that key, not who that person is.

To check the hash: `sha256sum onion-gate-0.1.0.zip` (Linux), `shasum -a 256 onion-gate-0.1.0.zip` (macOS) or `Get-FileHash onion-gate-0.1.0.zip -Algorithm SHA256` (PowerShell), and compare it with the release notes.

## Putting it in front of any server

onion-gate speaks plain HTTP/1.1 to one loopback backend. Point `--upstream` at
whatever already serves your site:

- **nginx / Caddy / Apache** — have them listen on, say, `127.0.0.1:3000` and run
  `onion-gate 8088 --proxy-protocol --upstream=127.0.0.1:3000`. Point tor's
  `HiddenServicePort` at `127.0.0.1:8088` instead of at the web server.
- **An app server** (Gunicorn, Node, a Go/Rust binary, …) — same idea: bind the
  app to loopback and give its address to `--upstream`.
- **Static files** — serve them with any tiny static server on loopback and put
  onion-gate in front.

The only change to your existing stack is that tor (or whatever faces the world)
now talks to onion-gate, and onion-gate talks to your old entry point. Your
backend does not need to know onion-gate exists, with one rule: **do not use the
`/__gate/` path prefix**, and expect no keep-alive (one request per connection).

A minimal hardened systemd unit is in
[`deploy/onion-gate.service`](deploy/onion-gate.service).

## Tunable constants (and where)

All limits are plain constants — change them and rebuild. No config file.

**Every request counts against the budgets, assets included.** With no
keep-alive, a page with 20 images, stylesheets and scripts is 21 requests and 21
connections. The defaults fit roughly three such pages a minute per visitor
with room for bursts. A heavier site needs larger budgets; a site that inlines
its assets can use much tighter ones (one request per page) and catch scrapers
sooner. Keep the circuit budget looser than the pass budget — the build checks
it.

| What | Default | Where |
| --- | --- | --- |
| CAPTCHA rounds | 2 | `ROUNDS` in `src/lib.rs` |
| Pass cookie name | `onion_gate_pass` | `COOKIE` in `src/lib.rs` |
| Gate path prefix | `/__gate/` | `GATE_PREFIX`, `VERIFY_PATH` in `src/lib.rs` |
| Challenge expiry / grace | 30 s / 5 s | `CHALLENGE_TTL`, `GRACE` in `src/store.rs` |
| Pass idle / hard lifetime | 30 min / 2 h | `PASS_IDLE`, `PASS_MAX` in `src/store.rs` |
| Pass request budget | 60 burst, 1 / s | `PASS_BURST`, `PASS_REFILL_PER_SEC` in `src/store.rs` |
| Circuit request budget | 90 burst, 1.5 / s | `CIRCUIT_PAGE_BURST`, `CIRCUIT_PAGE_REFILL_PER_SEC` in `src/limit.rs` |
| Challenge permits / circuit | 10 burst, 1 / 6 s | `CHALLENGE_BURST`, `CHALLENGE_REFILL_PER_SEC` in `src/limit.rs` |
| Connections / circuit | 8 | `MAX_CONN_PER_CIRCUIT` in `src/limit.rs` |
| Total connections | 512 | `MAX_CONN` in `src/main.rs` |
| Request body cap | 1 MiB | `--max-body`, default `DEFAULT_MAX_BODY` in `src/http.rs` |
| Request head / target cap | 16 KiB / 2 KiB | `MAX_HEAD`, `MAX_TARGET` in `src/http.rs` |
| Read deadlines (head / body) | 8 s / 60 s | `READ_DEADLINE`, `BODY_DEADLINE` in `src/http.rs` |
| Upstream response cap / timeouts | 8 MiB / 5 s connect, 30 s I/O | top of `src/upstream.rs` |
| Buffered bytes: all / per circuit / per pass | 128 / 24 / 32 MiB | `MAX_BUFFERED`, `MAX_BUFFERED_PER_CIRCUIT`, `MAX_BUFFERED_PER_PASS` in `src/limit.rs` |
| Time to deliver one response | 30 s + size at 16 KiB/s, at most 300 s | `SEND_GRACE`, `MIN_SEND_RATE`, `SEND_DEADLINE` in `src/http.rs` |
| Image difficulty | — | constants at the top of `src/captcha.rs` |
| CAPTCHA page text and style | — | `src/html.rs` |

## Project layout

```
src/lib.rs       the gate: routing, the challenge/verify flow, forwarding, return-path safety
src/main.rs      the binary: flags, loopback bind, accept loop
src/captcha.rs   challenge drawing, distortion, click validation
src/store.rs     single-use challenge tokens, session passes and their budget
src/limit.rs     per-Tor-circuit limits (connections, challenges, pages) and the token bucket
src/http.rs      minimal strict HTTP/1.1 parsing, the PROXY line, response writing
src/upstream.rs  the reverse proxy: forward to the loopback backend, relay the response
src/html.rs      the CAPTCHA page and error pages, base64
src/png.rs       PNG encoder
src/rng.rs       randomness from /dev/urandom
src/fuzz.rs      fuzz targets for the parsers (tests, and the `fuzzing` feature for libFuzzer)
tests/flow.rs    end-to-end tests over real sockets (gate, forwarding, limits, no open redirect)
examples/        local test harness: a test backend and a stand-in for tor's PROXY line
scripts/         harness.sh: automated checks against the real binaries, and a stack for a browser
docs/TESTING.md  how to test: cargo test, the harness, and the Tor Browser (Safest) checklist
docs/CAPTCHA-STRENGTH.md  the CAPTCHA measured against a reference solver
deploy/          example torrc and a hardened systemd unit
.github/         CI (tests on Linux and macOS, MSRV and stable) and Dependabot
```

## Security properties

Guarantees (as far as the code goes):

- **Gate:** no backend content — and no hint of which paths exist — without a
  valid pass.
- **Single-use tokens** with strict expiry; the same generic message for every
  failure, always with a new image (no oracle).
- **No open redirect:** the post-CAPTCHA return path is sanitized to a
  same-origin absolute path and stored server-side, never taken from a header
  the client controls.
- **Strict HTTP:** one request per connection, `Connection: close`, no keep-alive
  or pipelining (no request smuggling), chunked request bodies rejected, header
  names must be tokens, exactly one `Host` (HTTP/1.1), size and time limits
  throughout.
- **Loopback only:** listens on `127.0.0.1`; the upstream must be loopback too.
- **No visitor data added** to forwarded requests; the pass cookie is stripped.
- **Bounded memory** in every store and for all buffered bodies together (with
  a share per circuit and per pass), and no request body buffered (beyond
  1 KiB) for a visitor without a valid pass.

## Limitations

Be honest with yourself about what this is:

- **Not resistant to a solver written for it.** A classical reference solver,
  with no machine learning, clicks the right ring in 59 % of rounds, so it
  obtains a pass about 35 % of the time (measured on 2000 challenges, see
  [docs/CAPTCHA-STRENGTH.md](docs/CAPTCHA-STRENGTH.md)). A model trained on this
  generator's unlimited labelled output would likely do better, and anyone can
  pay people to click. The CAPTCHA raises the cost of automation, it does not
  make it impossible: against a solver, the per-pass and per-circuit budgets
  are what hold, and against many circuits, tor's proof-of-work.
- **No independent audit.** The code was written with AI help and reviewed by its
  author only. Read it before you trust it.
- **Passes are transferable.** A pass is a bearer cookie, not bound to a circuit;
  its budget and lifetime limit how much a shared pass is worth, no more.
- **Whole request/response buffered in memory**, each capped, and all of them
  together capped by a global budget (`MAX_BUFFERED`, 128 MiB): past it,
  forwarded requests get `503` until memory is freed, instead of the process
  running out of memory. No streaming, no WebSockets (`101 Switching
  Protocols` is refused), no HTTP/2, no large uploads/downloads beyond the
  caps. Raise `--max-body`, the response cap and the budget if you need more,
  at a memory cost.
- **Slow readers hold their response, within limits.** A visitor with a valid
  pass who reads very slowly keeps its buffered response until it is delivered
  or its deadline passes: 30 s plus the time to send it at 16 KiB/s, at most
  300 s. One circuit can hold at most 24 MiB of the budget this way and one
  pass at most 32 MiB, so filling the whole 128 MiB takes at least 6 circuits
  and 4 passes (8 solved CAPTCHAs); while it lasts, other forwarded requests
  get `503`. The responses are buffered rather than streamed on purpose:
  streaming would hand the slow reader to your backend instead, tying up its
  workers (the classic slow-client problem a buffering proxy exists to absorb).
  A site that serves large files to untrusted visitors should lower the
  response cap or serve them elsewhere.
- **Strict about the backend too.** A response with a `Transfer-Encoding` other
  than plain `chunked`, conflicting `Content-Length`s, a header name that is not
  a token, or control bytes or non-UTF-8 bytes in the status line or a header is
  answered with `502` rather than relayed.
- **A sub-request without a pass gets the challenge page.** If a pass expires
  while a page is loading, an image or stylesheet request receives HTML instead
  and shows as broken until the next navigation, which shows the CAPTCHA.
- **Without a valid pass, a request body over 1 KiB is never read** (so nobody
  can make the gate buffer uploads before passing the CAPTCHA). If a pass
  expires while the visitor is uploading a large form, the browser may show a
  connection error instead of the challenge; reloading the page shows it.
- **One backend, loopback only.** No load balancing, no TLS termination, no
  virtual hosts. Put those in your backend or in front of tor.
- **Network-level DoS** is tor's job (its PoW and introduction defenses) plus the
  per-circuit limits here, not the CAPTCHA's.
- **The warrant-canary, payments, catalog and everything e-commerce** from the
  original project are intentionally **not** here. This is only the gate.

## Development

This project was developed with the help of Claude (Anthropic) and directed, tested and published by its author. Treat it like any unaudited security code: read `src/`, run the tests, and judge it by what can be verified rather than by who wrote it.

```bash
cargo test --offline                              # unit + end-to-end tests, and a short fuzz run
cargo clippy --offline --all-targets -- -D warnings
cargo build --release --offline
scripts/harness.sh check                          # the real binaries over sockets (needs curl >= 8.2)
```

CI runs the same on Linux and macOS with Rust 1.82 (the minimum supported version) and the latest stable (the harness on Linux only), and fails if the crate gains any dependency. [docs/TESTING.md](docs/TESTING.md) explains the harness and has the manual checklist for Tor Browser at the Safest level.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE). Do what you like; no warranty.
