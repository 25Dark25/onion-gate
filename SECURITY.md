# Security policy

## Reporting a vulnerability

Use **Security → Advisories → Report a vulnerability** on the repository page (GitHub private vulnerability reporting). Please do not open a public issue for security problems. Include the version or commit, the configuration (the output of `onion-gate --print-config` with your flags or `--config` file), steps to reproduce and the impact.

## In scope

- Reaching the backend without a valid pass, or learning anything about it (which paths exist, its responses, its headers) before passing the CAPTCHA.
- Reusing a challenge token, a click outside the target being accepted, or any response that reveals why an attempt failed (an oracle).
- An open redirect through the return path after the CAPTCHA.
- Request smuggling or header injection toward the backend, or response splitting toward the visitor.
- The pass cookie, or anything identifying the visitor, reaching the backend.
- Getting around the per-pass or per-circuit limits from a single circuit, or unbounded memory or CPU use caused by one circuit.
- onion-gate listening on anything but `127.0.0.1`, or connecting to a non-loopback upstream.
- Misleading claims in the code or documentation.

## Out of scope

- Solving the CAPTCHA automatically (a classical solver already passes about 35 % of the time, see [docs/CAPTCHA-STRENGTH.md](docs/CAPTCHA-STRENGTH.md)), with a model trained on this generator, or with paid human solvers. This is a documented limitation: the gate raises the cost of automation, it does not prevent it. A solver that gets around the per-pass or per-circuit **limits** is in scope.
- Floods from many Tor circuits at once. That is tor's job (proof-of-work and introduction defenses); the per-circuit limits here only bound what each circuit can do.
- Sharing or reselling a valid pass. Passes are bearer cookies by design; their budget and lifetime are the only limit.
- Vulnerabilities in the backend behind the gate, in tor, or in the operating system.

## Status

The project has not had an independent audit. Only the latest release is supported.
