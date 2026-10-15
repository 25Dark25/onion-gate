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
  then unlimited, so run without `proxy_protocol` for local tests only (the
  binary warns at startup).

## Quick start

From a source checkout (or a verified release, see below) to a protected
`.onion`, assuming your site already runs on the same machine:

1. **Build** (no crates to download):

   ```bash
   cargo build --release --offline
   sudo cp target/release/onion-gate /usr/local/bin/
   ```

2. **Keep your backend on loopback.** Make nginx, Caddy or your app listen on
   `127.0.0.1:3000` (any loopback port), not on a public address.

3. **Configure onion-gate.** Copy the example and set `upstream` to that
   address; every other setting has a working default:

   ```bash
   sudo mkdir -p /etc/onion-gate
   sudo cp deploy/onion-gate.conf /etc/onion-gate/onion-gate.conf
   sudoedit /etc/onion-gate/onion-gate.conf          # upstream = 127.0.0.1:3000
   onion-gate --config=/etc/onion-gate/onion-gate.conf --check
   ```

4. **Point tor at onion-gate**, not at the backend, and let it send the circuit
   identifier (full example with tor's own defenses:
   [`deploy/torrc.example`](deploy/torrc.example)):

   ```
   HiddenServicePort 80 127.0.0.1:8088
   HiddenServiceExportCircuitID haproxy
   HiddenServicePoWDefensesEnabled 1
   ```

5. **Run it** with the hardened systemd unit, and reload tor:

   ```bash
   sudo cp deploy/onion-gate.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now onion-gate
   sudo systemctl reload tor
   ```

Open the `.onion` in Tor Browser: you get the CAPTCHA first, and your site
after. To try it locally first, without tor or a backend of your own,
`scripts/harness.sh up` starts a test backend and the gate (see
[docs/TESTING.md](docs/TESTING.md)).

Your backend needs no changes, with two rules: **do not use the `/__gate/`
path prefix** (the gate's own), and expect one request per connection (no
keep-alive). It will see no visitor address and no `X-Forwarded-*` headers; see
[What the backend sees](#what-the-backend-sees).

## Configuration

Every setting can go in the file (`key = value`) or on the command line
(`--key=value`, which overrides the file); `-` and `_` are interchangeable. Only
`upstream` is required.

```bash
onion-gate --help                          # every setting, its default and what it does
onion-gate --print-config [...]            # the effective configuration, as a ready-to-edit file
onion-gate --config=FILE --check           # validate (and see if the backend answers), then exit
onion-gate --upstream=127.0.0.1:3000 --proxy-protocol    # no file needed
```

Values are human-readable: durations `45s`, `30m`, `2h`; sizes `512K`, `8M`;
rates in requests per minute. A configuration that breaks a rule (a circuit
budget tighter than a pass budget, a response cap that no memory share can
hold, ...) is refused at start with every problem listed. The listen address
is not a setting: onion-gate only ever listens on `127.0.0.1`.

**Every request counts against the budgets, assets included.** With no
keep-alive, a page with 20 images, stylesheets and scripts is 21 requests and 21
connections. The defaults fit roughly three such pages a minute per visitor
with room for bursts. A heavier site needs larger budgets; a site that inlines
its assets can use much tighter ones (one request per page) and catch scrapers
sooner. The circuit budget must stay looser than the pass budget.

| Setting | Default | What it does |
| --- | --- | --- |
| `port` | 8088 | Port on 127.0.0.1 |
| `upstream` | — (required) | The backend, `host:port`, on loopback |
| `proxy_protocol` | no | Read tor's PROXY line: per-circuit limits. **Use `yes` behind tor** |
| `metrics_port` | 0 (off) | Port on 127.0.0.1 for aggregate [metrics](#metrics) |
| `captcha` | always | `always`, or `adaptive`: no CAPTCHA while calm, see [Adaptive mode](#adaptive-mode) |
| `adaptive_new_per_minute` | 60 | Adaptive: arrivals per minute that mean an attack |
| `adaptive_hold` | 15m | Adaptive: time without any signal before calming down |
| `adaptive_force_file` | (none) | Adaptive: while this file exists, the CAPTCHA is on for everyone new |
| `rounds` | 2 | CAPTCHA rounds in a row for a pass (1–5) |
| `challenge_ttl` | 30s | How long a challenge image is valid (+5 s grace for Tor latency) |
| `pass_idle` / `pass_max` | 30m / 2h | A pass expires when unused this long / this long after it was issued |
| `pass_burst` / `pass_per_minute` | 60 / 60 | Requests per pass; spending them revokes the pass |
| `circuit_burst` / `circuit_per_minute` | 90 / 90 | Forwarded requests per Tor circuit |
| `challenge_burst` / `challenge_per_minute` | 10 / 10 | Challenge images per circuit (each costs CPU) |
| `conn_per_circuit` / `max_conn` | 8 / 512 | Simultaneous connections per circuit / in total |
| `max_body` / `max_response` | 1M / 8M | Largest request body forwarded / backend response relayed |
| `upstream_timeout` | 30s | How long the backend may take to answer |
| `memory` / `memory_per_circuit` / `memory_per_pass` | 128M / 24M / 32M | Bytes buffered at once: total, and the most one circuit / one pass may hold |

Fixed in the code on purpose (protocol hardening, not tuning):

| What | Value | Where |
| --- | --- | --- |
| Pass cookie name / gate path prefix | `onion_gate_pass` / `/__gate/` | `COOKIE`, `GATE_PREFIX` in `src/lib.rs` |
| Request head / target cap | 16 KiB / 2 KiB | `MAX_HEAD`, `MAX_TARGET` in `src/http.rs` |
| Read deadlines (head / body) | 8 s / 60 s | `READ_DEADLINE`, `BODY_DEADLINE` in `src/http.rs` |
| Backend connect timeout | 5 s | `CONNECT_TIMEOUT` in `src/upstream.rs` |
| Time to deliver one response | 30 s + size at 16 KiB/s, at most 300 s | `SEND_GRACE`, `MIN_SEND_RATE`, `SEND_DEADLINE` in `src/http.rs` |
| Image difficulty | — | constants at the top of `src/captcha.rs` |
| CAPTCHA page text and style | — | `src/html.rs` |

## Adaptive mode

With `captcha = adaptive` (it needs `proxy_protocol = yes`), visitors only see
the CAPTCHA when the gate looks attacked:

- **Calm:** a visitor without a pass gets a **free pass** — a `303` back to the
  same URL with the pass cookie — and goes straight to the site. A free pass
  has the same request budget, lifetime and memory share as a solved one, and
  getting one costs a challenge permit of the circuit (10 in a burst, 10 a
  minute), like an image would. A pass that spends its budget gets the
  CAPTCHA, never a new free pass. Free passes may fill at most half the pass
  store.
- **Under attack:** every free pass is revoked at once, and everyone without a
  solved pass gets the CAPTCHA, exactly as with `captcha = always`. Solved
  passes are never revoked by a mode change.

Every 5 seconds the gate looks at the last minute. It goes under attack when
any of these holds: more than `adaptive_new_per_minute` arrivals (requests for
the site without a valid pass); more than 30 rate-limit answers; more than 10
backend failures; more than half of `max_conn` or of `memory` in use; or the
`adaptive_force_file` exists. It calms down only after `adaptive_hold` with
none of them, so an attacker cannot make it flap. Every change is printed to
standard error (with its reason, never visitor data) and counted in the
metrics.

To force the CAPTCHA by hand, create the file; to let the gate decide again,
delete it. The gate only checks that it exists, so any path it can read works,
for example next to the configuration (it survives restarts there):

```
adaptive_force_file = /etc/onion-gate/under-attack
```
```bash
sudo touch /etc/onion-gate/under-attack   # CAPTCHA for everyone new, within 5 s
sudo rm /etc/onion-gate/under-attack      # back to automatic (calm after adaptive_hold)
```

**What it gives up, on purpose:** while calm, anyone reaches your site without
a CAPTCHA, bots included, limited only by the per-pass and per-circuit
budgets. Choose it when friction for real visitors matters more than keeping
bots off between attacks; keep `captcha = always` when the CAPTCHA itself is
the point (scrapers, spam, account creation).

## Metrics

With `metrics_port` set, onion-gate serves aggregate counters at
`http://127.0.0.1:PORT/metrics`, in the Prometheus text format: read them with
`curl`, or point Prometheus (or anything that reads that format) at them.

```bash
onion-gate --config=/etc/onion-gate/onion-gate.conf --metrics-port=9180
curl -s http://127.0.0.1:9180/metrics | grep -v '^#'
```

| Metric | What it counts |
| --- | --- |
| `onion_gate_challenges_total` | Challenge images generated |
| `onion_gate_arrivals_total` | Requests for the site without a valid pass (new visitors, expired passes, bots) |
| `onion_gate_free_passes_total` | Passes issued without a CAPTCHA (adaptive, calm) |
| `onion_gate_mode`, `onion_gate_mode_changes_total` | 0 = adaptive and calm, 1 = adaptive and under attack, 2 = `captcha = always`; changes |
| `onion_gate_verifications_total{result}` | CAPTCHA answers: `failed`, `next_round`, `passed` (= passes issued) |
| `onion_gate_rate_limited_total{limit}` | 429s: `conn_per_circuit`, `challenge` |
| `onion_gate_passes_revoked_total{budget}` | Passes revoked for spending the `pass` or the `circuit` budget |
| `onion_gate_forwarded_total` | Requests forwarded and answered |
| `onion_gate_upstream_errors_total{kind}` | Backend failures: `connect`, `timeout`, `bad_response`, `too_large` |
| `onion_gate_upstream_seconds_total` | Time spent waiting for the backend (divide by forwarded for the mean) |
| `onion_gate_busy_total{resource}` | 503s: `memory` budget or a `store` full |
| `onion_gate_bad_requests_total`, `onion_gate_proxy_line_rejected_total` | Requests the parser refused; connections without a valid PROXY line |
| `onion_gate_connections_total{result}`, `onion_gate_connections_open` | Connections accepted or refused for `max_conn`; open now |
| `onion_gate_challenges_pending`, `onion_gate_passes_live`, `onion_gate_circuits_tracked` | How full the stores are |
| `onion_gate_memory_bytes{kind}` | Buffered bytes `used`, and the `limit` |
| `onion_gate_uptime_seconds`, `onion_gate_info{version}` | Since when, and which version |

**No visitor data, by design:** only totals. Never a circuit identifier, a
path, a cookie, a header or the time of any one request, and nothing is
written to disk. The endpoint listens on `127.0.0.1` only and answers one
scrape at a time; never point tor at it. (Dumping the counters on a Unix
signal is not offered: the standard library cannot catch signals without
`unsafe` code, which this crate forbids.)

What an attack looks like in them: `challenges_total` and
`rate_limited_total{limit="challenge"}` climbing fast with few
`verifications_total{result="passed"}`; `circuits_tracked` growing (many
circuits: tor's proof-of-work is the answer); `busy_total` or
`memory_bytes{kind="used"}` near the limit; `upstream_seconds_total` rising
faster than `forwarded_total` (the backend is struggling).

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

onion-gate speaks plain HTTP/1.1 to one loopback backend. Point `upstream` at
whatever already serves your site:

- **nginx / Caddy / Apache** — have them listen on, say, `127.0.0.1:3000`, set
  `upstream = 127.0.0.1:3000`, and point tor's `HiddenServicePort` at
  onion-gate (`127.0.0.1:8088`) instead of at the web server.
- **An app server** (Gunicorn, Node, a Go/Rust binary, …) — same idea: bind the
  app to loopback and give its address to `upstream`.
- **Static files** — serve them with any tiny static server on loopback and put
  onion-gate in front.

The only change to your existing stack is that tor now talks to onion-gate, and
onion-gate talks to your old entry point. Remember that the backend sees no
visitor address: anything it did per IP (rate limits, logs) now sees
`127.0.0.1` for everyone, which is the point.

## Project layout

```
src/lib.rs       the gate: routing, the challenge/verify flow, forwarding, return-path safety
src/main.rs      the binary: configuration, --check/--print-config, loopback bind, accept loop
src/config.rs    settings: defaults, the file and flag parser, validation
src/metrics.rs   aggregate counters and the loopback /metrics endpoint
src/adaptive.rs  adaptive mode: the attack monitor, free passes while calm
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
deploy/          example configuration, torrc and a hardened systemd unit
.github/         CI (tests on Linux and macOS, MSRV and stable) and Dependabot
```

## Security properties

Guarantees (as far as the code goes):

- **Gate:** no backend content — and no hint of which paths exist — without a
  valid pass. With `captcha = always` (the default) a pass means a solved
  CAPTCHA; with `captcha = adaptive`, while calm, it does not (see
  [Adaptive mode](#adaptive-mode)).
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
  together capped by a global budget (`memory`, 128 MiB by default): past it,
  forwarded requests get `503` until memory is freed, instead of the process
  running out of memory. No streaming, no WebSockets (`101 Switching
  Protocols` is refused), no HTTP/2, no large uploads/downloads beyond the
  caps. Raise `max_body`, `max_response` and the `memory` settings if you need
  more, at a memory cost.
- **Slow readers hold their response, within limits.** A visitor with a valid
  pass who reads very slowly keeps its buffered response until it is delivered
  or its deadline passes: 30 s plus the time to send it at 16 KiB/s, at most
  300 s. With the defaults, one circuit can hold at most 24 MiB of the budget
  this way and one pass at most 32 MiB, so filling the whole 128 MiB takes at
  least 6 circuits and 4 passes (8 solved CAPTCHAs); while it lasts, other forwarded requests
  get `503`. The responses are buffered rather than streamed on purpose:
  streaming would hand the slow reader to your backend instead, tying up its
  workers (the classic slow-client problem a buffering proxy exists to absorb).
  A site that serves large files to untrusted visitors should lower
  `max_response` or serve them elsewhere.
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
