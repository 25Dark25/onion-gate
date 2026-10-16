# How strong is the CAPTCHA?

A measurement against a reference solver, so the README's claims rest on a
number rather than on how the images look. The short answer: **a classical
solver written without any machine learning passes about three rounds in five,
and a full two-round CAPTCHA about one time in three.** The CAPTCHA is not
what stops a determined bot; the per-pass and per-circuit budgets are.

## Result

Measured on 2026-10-15 at commit `65b78be`, on 2000 fresh challenges that
were **not** used to tune the solver:

| | Per round | Two rounds (a pass) |
| --- | --- | --- |
| Random click | 1.9 % (380 / 20 000) | ~0.04 % |
| Reference solver | **59.0 %** (1180 / 2000; 95 % CI 56.8–61.1 %) | **~35 %** (p², rounds are independent) |

The solver needs about 85 ms of CPU per image on one core; generating the image
took about 3.6 ms in the same build (`opt-level = 3`; the gate's release
profile optimizes for size, so it may be somewhat slower there).

## Method

The solver sees only the PNG a visitor receives. The challenge's secret is
used only to score the click, with the gate's own `captcha::is_hit`, so a
"hit" means exactly what it means to the gate.

It is classical image processing, a few hundred lines, no training data:

1. Decode the PNG to a black/white map.
2. Circular Hough transform over the radii the generator uses, widened for the
   distortion; keep the strongest, mutually distant centers.
3. For each candidate, fit an ellipse to the ink near it (the distortion turns
   circles into roughly elliptical shapes) and measure, around it, the longest
   arc with no continuous stroke.
4. Reject candidates that are not ring-shaped, that coincide with a whole ring
   already found, or whose longest gap is out of the plausible range.
5. Among the rest, prefer a long single gap, dense ink elsewhere, and an
   **empty** gap sector: a real cut ends cleanly, while the arcs that the wavy
   wires and crossing rings form (the generator's decoys, which work: they
   were the main cause of misses) have ink running through it.
6. Click the center of the chosen ring. Any click inside the broken ring
   counts, so the center is a safe target.

The weights were tuned on separate batches of a few hundred images, then
frozen before the final measurement. The solver is kept out of this
repository on purpose: publishing a working attack tuned to this generator
helps attackers more than it helps operators, and the number above is what an
operator needs.

## What this means

- **This is a lower bound on what an attacker can do.** It is one afternoon's
  classical solver. Anyone can generate unlimited labelled images with this
  generator (it is open source), so a trained model would very likely do
  better. Paid human solvers do better still.
- **What the CAPTCHA still does:** it stops anything that does not target this
  gate specifically (generic scrapers, crawlers, scripts that only follow
  links), and it makes every pass cost an attacker some engineering and CPU.
- **What actually limits a solver-equipped bot is the budgets.** One pass
  costs it about 5–6 challenge images on average (`(1 + p) / p²` verifications
  plus the first image). A circuit gets 10 images in a burst and one more every
  6 s, so it can obtain about one pass every 35 s, and one pass is worth up to
  1 request per second for up to 2 hours. A single circuit is therefore held to
  its page budget (90 in a burst, 1.5 per second) whatever its CAPTCHA skill.
  More circuits mean more of everything: that is what tor's proof-of-work
  defense is for.
- **Making the images harder is a weak lever.** It costs real visitors as much
  as it costs solvers, and a generator whose code is public loses an arms race
  against a model trained on its own output. A third round (`rounds = 3`) would
  cut this solver's pass rate to about 21 % at the price of one more click for
  everyone; how much it costs humans has not been measured yet.

## Reproducing

The library exposes everything needed: `captcha::generate` returns the PNG and
the secret, `captcha::is_hit` scores a click, and `Warp::invert` gives the
screen position of the answer. A solver can live in a separate crate that
depends on this one by path; it needs nothing else. `cargo test dump_samples --
--ignored` (with `DUMP_DIR` and `DUMP_N`) writes sample images with their
answers.
