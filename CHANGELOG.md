# Changelog

All notable changes to this project are listed here. Versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

### Changed

- A request for a sub-resource (an image, a stylesheet...) without a valid
  pass gets a bare `403` instead of the challenge page: no image is drawn and
  no challenge permit is spent. Detected by `Sec-Fetch-Dest`, or an `Accept`
  that leads with a non-HTML type; in doubt, the challenge as before. New
  metric `onion_gate_subresources_refused_total`.

## [0.1.0] - 2026-10-16

First release.

### Added

- The gate: a no-JavaScript "click the broken circle" CAPTCHA (2 rounds by
  default) that works in Tor Browser at the Safest level. Single-use tokens
  with strict expiry, one generic failure message (no oracle), and the return
  path kept server-side (no open redirect).
- A reverse proxy to one loopback backend: strict HTTP/1.1 parsing, one request
  per connection, hop-by-hop, client-identity and `X-Forwarded-*` headers and
  the pass cookie stripped, responses re-framed with their own length.
  Requests and responses are buffered, not streamed.
- Limits per pass and per Tor circuit (from tor's PROXY line,
  `HiddenServiceExportCircuitID haproxy`): request budgets, challenge permits
  and connections; a global memory budget with per-circuit and per-pass
  shares; a delivery deadline scaled to the response size.
- Configuration by file and flags, validated at start (`--check`,
  `--print-config`, `--help`), and examples in `deploy/`: configuration, torrc
  and a hardened systemd unit.
- Adaptive mode (`captcha = adaptive`, off by default): no CAPTCHA while calm,
  the CAPTCHA for everyone new under attack.
- Aggregate metrics on a separate loopback port (`metrics_port`, off by
  default), with no visitor data.
- Tests: unit, end-to-end over sockets, property-based fuzz targets (also
  usable with libFuzzer through the `fuzzing` feature), a local harness and a
  Tor Browser checklist (`docs/TESTING.md`).
- A measurement of the CAPTCHA against a reference solver
  (`docs/CAPTCHA-STRENGTH.md`): a classical solver passes about 35 % of the time.

### Security

- Not independently audited. Standard library only (zero dependencies),
  `#![forbid(unsafe_code)]`, listens on 127.0.0.1 only. Read the README's
  Limitations and SECURITY.md before relying on it.

[0.1.0]: https://github.com/25Dark25/onion-gate/releases/tag/v0.1.0
