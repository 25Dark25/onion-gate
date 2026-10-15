//! "Click the broken circle" challenge generation.
//!
//! The image is 1 bit/pixel (black on white): ~12 KB PNG, no JS.
//! Everything that decides the challenge's position/shape comes from /dev/urandom.
//!
//! Layers (bottom to top), designed to make automatic segmentation harder:
//!   1. "under" wire               (rings cut through it with a white halo)
//!   2. random scratches
//!   3. rings, which MAY cross each other; every ring drawn later sits
//!      "on top" (a white halo breaks the strokes it crosses)
//!   4. scratches across the rim of randomly chosen rings (never tied to the gap)
//!   5. clustered dot texture (value noise, cloud-like)
//!   6. "over" wire                (with a white halo)
//!   7. non-linear DISTORTION of the whole image (grid-like sine warp)
//!   8. salt-and-pepper noise + frame
//!
//! VALIDATION: the secret is stored in the UNDISTORTED image space (ring
//! center + warp parameters). The user's click, which arrives in distorted
//! image coordinates, is mapped back to source space with the same
//! displacement function and compared there. Nothing needs inverting.

use crate::png;
use crate::rng::Rng;
use std::f32::consts::{PI, TAU};

pub const W: usize = 300;
pub const H: usize = 300;

/// Rings per image (17 whole + 1 broken). Blind guess = 1/N_CIRCLES per round.
const N_CIRCLES: usize = 18;
/// Radius (center line) of each ring: R_MIN..=R_MAX px.
const R_MIN: u32 = 14;
const R_MAX: u32 = 26;
/// Stroke width in px (thin).
const THICK: f32 = 1.0;
/// Center-to-edge margin. MUST exceed the warp's maximum displacement (8 px).
const MARGIN: f32 = 10.0;
/// White halo (px) around each stroke: creates the "on top" look.
const HALO: f32 = 1.5;
/// Extra tolerance (px) around the stroke that still counts as a "hit".
pub const HIT_PAD: f32 = 2.5;
/// Noise scratches (short 1 px segments).
const N_SCRATCHES: usize = 6;
/// Scratches across the rim of random rings (all rings equally likely).
const N_RIM_SCRATCHES: usize = 8;
/// Final salt-and-pepper noise: a pixel flips if byte < NOISE (4/256 ~ 1.6 %).
const NOISE: u8 = 4;
/// Texture: value-noise lattice (TEX_GRID x TEX_GRID nodes, TEX_CELL px cells).
/// (TEX_GRID - 1) * TEX_CELL must exceed W and H.
const TEX_GRID: usize = 11;
const TEX_CELL: f32 = 30.0;
/// Dot density = TEX_BASE + TEX_GAIN * n^2, with n in [0,1].
const TEX_BASE: f32 = 0.002;
const TEX_GAIN: f32 = 0.03;
/// White halo (px) of an "over" wire.
const WIRE_HALO: f32 = 2.0;
/// Bilinear coverage threshold when warping (0.4 keeps a 1 px stroke from breaking).
const WARP_THR: f32 = 0.4;

struct Circle {
    x: f32,
    y: f32,
    /// radius of the ring's center line
    r: f32,
}

// ------------------------------------------------------------------ warp

/// Grid-like sine distortion (smooth displacement field):
///   dx(x,y) = A1*sin(k1*y + f1) + A2*sin(k2*x + f2)
///   dy(x,y) = B1*sin(k3*x + f3) + B2*sin(k4*y + f4)
/// Amplitudes 2..4 px, wavelengths 100..180 px => displacement <= 8 px and
/// derivative <= 0.25 per term, so the mapping is injective and no stroke
/// gets squashed or folded.
/// Output pixel (x, y) takes its value from source (x + dx, y + dy).
#[derive(Clone, Copy)]
pub struct Warp {
    p: [f32; 12],
}

impl Warp {
    /// No distortion (zero amplitudes).
    #[cfg(test)]
    pub fn identity() -> Warp {
        Warp { p: [0.0; 12] }
    }

    fn random(rng: &mut Rng) -> Warp {
        let mut p = [0.0f32; 12];
        for g in 0..4 {
            p[g * 3] = rng.range(2.0, 4.0); // amplitude
            p[g * 3 + 1] = TAU / rng.range(100.0, 180.0); // wavenumber
            p[g * 3 + 2] = rng.range(0.0, TAU); // phase
        }
        Warp { p }
    }

    fn fx_y(&self, y: f32) -> f32 {
        self.p[0] * (self.p[1] * y + self.p[2]).sin()
    }
    fn fx_x(&self, x: f32) -> f32 {
        self.p[3] * (self.p[4] * x + self.p[5]).sin()
    }
    fn fy_x(&self, x: f32) -> f32 {
        self.p[6] * (self.p[7] * x + self.p[8]).sin()
    }
    fn fy_y(&self, y: f32) -> f32 {
        self.p[9] * (self.p[10] * y + self.p[11]).sin()
    }

    /// Point (x, y) of the DISTORTED image -> the source point that drew it.
    pub fn apply(&self, x: f32, y: f32) -> (f32, f32) {
        (
            x + self.fx_y(y) + self.fx_x(x),
            y + self.fy_x(x) + self.fy_y(y),
        )
    }

    /// The distorted-image (screen) point that corresponds to source point
    /// (cx, cy): the point a solver must click. Fixed-point iteration (a
    /// contraction, so it converges). Used by tests and external harnesses.
    pub fn invert(&self, cx: f32, cy: f32) -> (f32, f32) {
        let (mut x, mut y) = (cx, cy);
        for _ in 0..40 {
            let (sx, sy) = self.apply(x, y);
            x = cx - (sx - x);
            y = cy - (sy - y);
        }
        (x, y)
    }
}

fn sample(src: &[u8], x: i32, y: i32) -> f32 {
    if x < 0 || y < 0 || x >= W as i32 || y >= H as i32 {
        0.0
    } else {
        src[y as usize * W + x as usize] as f32
    }
}

/// Applies the warp to the whole image (bilinear sampling + threshold).
fn warp_image(src: &[u8], w: &Warp) -> Vec<u8> {
    // Each term depends on x only or y only: precompute per column/row.
    let mut col_dx = [0.0f32; W];
    let mut col_dy = [0.0f32; W];
    let mut row_dx = [0.0f32; H];
    let mut row_dy = [0.0f32; H];
    for x in 0..W {
        let c = x as f32 + 0.5;
        col_dx[x] = w.fx_x(c);
        col_dy[x] = w.fy_x(c);
    }
    for y in 0..H {
        let c = y as f32 + 0.5;
        row_dx[y] = w.fx_y(c);
        row_dy[y] = w.fy_y(c);
    }

    let mut out = vec![0u8; W * H];
    for y in 0..H {
        for x in 0..W {
            let sx = x as f32 + 0.5 + row_dx[y] + col_dx[x];
            let sy = y as f32 + 0.5 + col_dy[x] + row_dy[y];
            let fx = sx - 0.5;
            let fy = sy - 0.5;
            let x0f = fx.floor();
            let y0f = fy.floor();
            let wx = fx - x0f;
            let wy = fy - y0f;
            let x0 = x0f as i32;
            let y0 = y0f as i32;
            let v = sample(src, x0, y0) * (1.0 - wx) * (1.0 - wy)
                + sample(src, x0 + 1, y0) * wx * (1.0 - wy)
                + sample(src, x0, y0 + 1) * (1.0 - wx) * wy
                + sample(src, x0 + 1, y0 + 1) * wx * wy;
            if v >= WARP_THR {
                out[y * W + x] = 1;
            }
        }
    }
    out
}

// ------------------------------------------------------------ challenge

/// What the server remembers in order to validate the click.
#[derive(Clone, Copy)]
pub struct Secret {
    /// Center of the broken ring IN SOURCE SPACE (undistorted).
    pub cx: f32,
    pub cy: f32,
    /// Hit radius: outer radius of the stroke + HIT_PAD.
    pub hit_r: f32,
    pub warp: Warp,
}

pub struct Challenge {
    /// PNG ready to serve.
    pub png: Vec<u8>,
    pub secret: Secret,
}

pub fn generate(rng: &mut Rng) -> Challenge {
    let circles = place_circles(rng);
    let broken = rng.below(circles.len() as u32) as usize;
    let (theta, half) = pick_gap(&circles, broken, rng);
    let b = &circles[broken];

    let mut ink = vec![0u8; W * H];

    // 1) wire underneath
    let under = make_wire(rng);
    stamp(&mut ink, &under, 0.5, 1);

    // 2) scratches
    for _ in 0..N_SCRATCHES {
        scratch(&mut ink, rng);
    }

    // 3) rings; the chosen one gets the gap
    for (i, c) in circles.iter().enumerate() {
        let gap = if i == broken { Some((theta, half)) } else { None };
        draw_ring(&mut ink, c, gap);
    }

    // 4) scratches across the rims of random rings. NOT tied to the gap:
    //    a mark on the broken ring only would give the answer away.
    for _ in 0..N_RIM_SCRATCHES {
        let c = &circles[rng.below(circles.len() as u32) as usize];
        rim_scratch(&mut ink, c, rng);
    }

    // 5) clustered dot texture
    texture(&mut ink, rng);

    // 6) wire on top, with halo
    let over = make_wire(rng);
    stamp(&mut ink, &over, WIRE_HALO, 0);
    stamp(&mut ink, &over, 0.5, 1);

    // 7) non-linear distortion of everything above
    let warp = Warp::random(rng);
    let mut img = warp_image(&ink, &warp);

    // 8) salt-and-pepper noise (on the final image) and frame
    for px in img.iter_mut() {
        if rng.byte() < NOISE {
            *px ^= 1;
        }
    }
    frame(&mut img);

    let raw = pack_1bit(&img);
    Challenge {
        png: png::encode(W as u32, H as u32, 1, 0, &raw),
        secret: Secret {
            cx: b.x,
            cy: b.y,
            hit_r: b.r + THICK / 2.0 + HIT_PAD,
            warp,
        },
    }
}

/// Does the click (x, y), in displayed-image coordinates, land inside the
/// broken ring? Any odd value => false.
pub fn is_hit(s: &Secret, x: f32, y: f32) -> bool {
    if !(x.is_finite() && y.is_finite()) {
        return false;
    }
    if x < 0.0 || y < 0.0 || x >= W as f32 || y >= H as f32 {
        return false;
    }
    let (sx, sy) = s.warp.apply(x, y);
    let dx = sx - s.cx;
    let dy = sy - s.cy;
    dx * dx + dy * dy <= s.hit_r * s.hit_r
}

// ---------------------------------------------------------------- drawing

/// Two rings are compatible if they are apart (>= 5 px between strokes) or
/// cross "cleanly": neither tangent, nor nearly concentric, nor nearly stacked.
fn pair_ok(a: &Circle, b: &Circle) -> bool {
    let dx = a.x - b.x;
    let dy = a.y - b.y;
    let d = (dx * dx + dy * dy).sqrt();
    let (r1, r2) = (a.r, b.r);
    if d >= r1 + r2 + THICK + 5.0 {
        return true;
    }
    d <= r1 + r2 - 6.0 && d >= (r1 - r2).abs() + 6.0 && d >= 0.65 * (r1 + r2)
}

/// Rejection sampling; if they do not fit (probability ~0) it starts over.
fn place_circles(rng: &mut Rng) -> Vec<Circle> {
    loop {
        let mut v: Vec<Circle> = Vec::with_capacity(N_CIRCLES);
        let mut tries = 0u32;
        while v.len() < N_CIRCLES && tries < 600 {
            tries += 1;
            let r = (R_MIN + rng.below(R_MAX - R_MIN + 1)) as f32;
            let m = r + THICK / 2.0 + MARGIN;
            let cand = Circle {
                x: rng.range(m, W as f32 - m),
                y: rng.range(m, H as f32 - m),
                r,
            };
            if v.iter().all(|o| pair_ok(&cand, o)) {
                v.push(cand);
            }
        }
        if v.len() == N_CIRCLES {
            return v;
        }
    }
}

/// Smallest angular difference between two angles, in [0, PI].
fn ang_diff(a: f32, b: f32) -> f32 {
    let d = (a - b).abs() % TAU;
    if d > PI {
        TAU - d
    } else {
        d
    }
}

/// Angles (on ring `b`) where other rings cross it.
fn intersection_angles(circles: &[Circle], b: usize) -> Vec<f32> {
    let c = &circles[b];
    let mut out = Vec::new();
    for (j, o) in circles.iter().enumerate() {
        if j == b {
            continue;
        }
        let dx = o.x - c.x;
        let dy = o.y - c.y;
        let d = (dx * dx + dy * dy).sqrt();
        if (c.r - o.r).abs() < d && d < c.r + o.r {
            let a = dy.atan2(dx);
            let cosv = ((c.r * c.r + d * d - o.r * o.r) / (2.0 * c.r * d)).clamp(-1.0, 1.0);
            let al = cosv.acos();
            out.push(a + al);
            out.push(a - al);
        }
    }
    out
}

/// Angular clearance (rad) between the gap (theta, half) and the nearest crossing.
fn gap_clearance(angs: &[f32], theta: f32, half: f32) -> f32 {
    let mut clear = 9.9f32;
    for &a in angs.iter() {
        let v = ang_diff(a, theta) - half;
        if v < clear {
            clear = v;
        }
    }
    clear
}

/// Picks the gap (center angle, half-width 30-42 degrees) so that no other ring
/// crosses the cut (if one did, a person would see the gap "bridged" by another
/// circle and could not decide). At most 64 attempts; if none is clean, the
/// one with the most clearance is used.
fn pick_gap(circles: &[Circle], b: usize, rng: &mut Rng) -> (f32, f32) {
    let angs = intersection_angles(circles, b);
    let need = 6.0 / circles[b].r; // 6 px of arc
    let mut best = (f32::MIN, 0.0f32, 0.0f32);
    for _ in 0..64 {
        let th = rng.range(0.0, TAU);
        let hw = rng.range(30.0f32.to_radians(), 42.0f32.to_radians());
        let clear = gap_clearance(&angs, th, hw);
        if clear >= need {
            return (th, hw);
        }
        if clear > best.0 {
            best = (clear, th, hw);
        }
    }
    (best.1, best.2)
}

/// Draws the ring. Pixels within THICK/2 of the circumference become ink; those
/// in the next band (HALO) are ERASED, so a ring drawn later "covers" whatever
/// it crosses. Nothing is touched inside the gap.
fn draw_ring(ink: &mut [u8], c: &Circle, gap: Option<(f32, f32)>) {
    let ext = (c.r + THICK / 2.0 + HALO + 1.0).ceil() as i32;
    let cxi = c.x as i32;
    let cyi = c.y as i32;
    for py in (cyi - ext)..=(cyi + ext) {
        for px in (cxi - ext)..=(cxi + ext) {
            if px < 0 || py < 0 || px >= W as i32 || py >= H as i32 {
                continue;
            }
            let dx = px as f32 + 0.5 - c.x;
            let dy = py as f32 + 0.5 - c.y;
            let dist = ((dx * dx + dy * dy).sqrt() - c.r).abs();
            if dist > THICK / 2.0 + HALO {
                continue;
            }
            if let Some((theta, half)) = gap {
                if ang_diff(dy.atan2(dx), theta) < half {
                    continue;
                }
            }
            ink[py as usize * W + px as usize] = if dist <= THICK / 2.0 { 1 } else { 0 };
        }
    }
}

/// 1 px segment: `len` px from (x0, y0) along the unit direction (dx, dy).
fn line(ink: &mut [u8], x0: f32, y0: f32, dx: f32, dy: f32, len: f32) {
    let mut s = 0.0f32;
    while s <= len {
        // `as i32` saturates, no UB; bounds are checked by hand.
        let px = (x0 + s * dx) as i32;
        let py = (y0 + s * dy) as i32;
        if px >= 0 && py >= 0 && (px as usize) < W && (py as usize) < H {
            ink[py as usize * W + px as usize] = 1;
        }
        s += 0.5;
    }
}

fn scratch(ink: &mut [u8], rng: &mut Rng) {
    let x0 = rng.range(0.0, W as f32);
    let y0 = rng.range(0.0, H as f32);
    let phi = rng.range(0.0, TAU);
    let len = rng.range(14.0, 36.0);
    line(ink, x0, y0, phi.cos(), phi.sin(), len);
}

/// A short segment crossing the ring's rim at a random angle.
fn rim_scratch(ink: &mut [u8], c: &Circle, rng: &mut Rng) {
    let a = rng.range(0.0, TAU);
    let px = c.x + c.r * a.cos();
    let py = c.y + c.r * a.sin();
    let phi = a + rng.range(-0.6, 0.6);
    let len = rng.range(12.0, 22.0);
    let (dx, dy) = (phi.cos(), phi.sin());
    line(ink, px - len / 2.0 * dx, py - len / 2.0 * dy, dx, dy, len);
}

/// Wavy curve crossing the whole canvas (horizontal or vertical).
fn make_wire(rng: &mut Rng) -> Vec<(f32, f32)> {
    let vert = rng.below(2) == 1;
    let y0 = rng.range(30.0, 270.0);
    let slope = rng.range(-0.4, 0.4);
    let amp = rng.range(8.0, 22.0);
    let lam = rng.range(70.0, 140.0);
    let ph = rng.range(0.0, TAU);
    let mut pts = Vec::with_capacity(2 * W + 1);
    let mut u = 0.0f32;
    while u <= W as f32 {
        let v = y0 + slope * (u - 150.0) + amp * (TAU * u / lam + ph).sin();
        pts.push(if vert { (v, u) } else { (u, v) });
        u += 0.5;
    }
    pts
}

/// Stamps a disc of radius `rad` with value `val` at every point of the curve.
fn stamp(ink: &mut [u8], pts: &[(f32, f32)], rad: f32, val: u8) {
    let k = rad.ceil() as i32;
    for &(x, y) in pts {
        let xi = x as i32;
        let yi = y as i32;
        for oy in -k..=k {
            for ox in -k..=k {
                if (ox * ox + oy * oy) as f32 <= rad * rad {
                    let px = xi + ox;
                    let py = yi + oy;
                    if px >= 0 && py >= 0 && px < W as i32 && py < H as i32 {
                        ink[py as usize * W + px as usize] = val;
                    }
                }
            }
        }
    }
}

/// Clustered dots: density varies smoothly (smoothed bilinear value noise),
/// forming "clouds" instead of uniform dots. Only adds ink.
fn texture(ink: &mut [u8], rng: &mut Rng) {
    let mut lat = [[0.0f32; TEX_GRID]; TEX_GRID];
    for row in lat.iter_mut() {
        for v in row.iter_mut() {
            *v = rng.unit();
        }
    }
    for y in 0..H {
        for x in 0..W {
            let gx = (x as f32 + 0.5) / TEX_CELL;
            let gy = (y as f32 + 0.5) / TEX_CELL;
            // <= 9 because 299.5 / 30 < 10, so i0 + 1 <= 10 < TEX_GRID
            let i0 = (gx as usize).min(TEX_GRID - 2);
            let j0 = (gy as usize).min(TEX_GRID - 2);
            let fx = gx - i0 as f32;
            let fy = gy - j0 as f32;
            let sx = fx * fx * (3.0 - 2.0 * fx);
            let sy = fy * fy * (3.0 - 2.0 * fy);
            let n = lat[j0][i0] * (1.0 - sx) * (1.0 - sy)
                + lat[j0][i0 + 1] * sx * (1.0 - sy)
                + lat[j0 + 1][i0] * (1.0 - sx) * sy
                + lat[j0 + 1][i0 + 1] * sx * sy;
            let dens = TEX_BASE + TEX_GAIN * n * n;
            if rng.unit() < dens {
                ink[y * W + x] = 1;
            }
        }
    }
}

fn frame(ink: &mut [u8]) {
    for x in 0..W {
        ink[x] = 1;
        ink[(H - 1) * W + x] = 1;
    }
    for y in 0..H {
        ink[y * W] = 1;
        ink[y * W + W - 1] = 1;
    }
}

/// Packs into 1-bit grayscale PNG rows (1 = white, MSB = leftmost pixel).
/// Each row is prefixed with its filter byte (0 = None).
fn pack_1bit(ink: &[u8]) -> Vec<u8> {
    let bytes_per_row = W.div_ceil(8);
    let mut raw = Vec::with_capacity((bytes_per_row + 1) * H);
    for y in 0..H {
        raw.push(0);
        for bx in 0..bytes_per_row {
            let mut byte = 0u8;
            for bit in 0..8 {
                let x = bx * 8 + bit;
                let white = x >= W || ink[y * W + x] == 0;
                byte = (byte << 1) | white as u8;
            }
            raw.push(byte);
        }
    }
    raw
}

/// Tests only: generates a challenge and also returns the image as pixels
/// (to dump samples or measure solvers).
#[cfg(test)]
pub fn generate_with_pixels(rng: &mut Rng) -> (Challenge, Vec<u8>) {
    let ch = generate(rng);
    let px = decode_1bit_stored(&ch.png);
    (ch, px)
}

/// Tests only: decodes the PNG this module produces (1 bit, stored blocks).
#[cfg(test)]
fn decode_1bit_stored(png: &[u8]) -> Vec<u8> {
    // signature(8) + IHDR(4+4+13+4) + IDAT length(4) + "IDAT"(4) + zlib header(2)
    let mut i = 8 + 25 + 8 + 2;
    let mut raw = Vec::new();
    loop {
        let last = png[i] & 1 == 1;
        let len = u16::from_le_bytes([png[i + 1], png[i + 2]]) as usize;
        raw.extend_from_slice(&png[i + 5..i + 5 + len]);
        i += 5 + len;
        if last {
            break;
        }
    }
    let bpr = W.div_ceil(8);
    let mut ink = vec![0u8; W * H];
    for y in 0..H {
        let row = &raw[y * (bpr + 1) + 1..(y + 1) * (bpr + 1)];
        for x in 0..W {
            let white = (row[x / 8] >> (7 - x % 8)) & 1 == 1;
            ink[y * W + x] = if white { 0 } else { 1 };
        }
    }
    ink
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sec(cx: f32, cy: f32, r: f32) -> Secret {
        Secret {
            cx,
            cy,
            hit_r: r,
            warp: Warp::identity(),
        }
    }

    #[test]
    fn placement_follows_the_rules() {
        let mut rng = Rng::new();
        for _ in 0..200 {
            let cs = place_circles(&mut rng);
            assert_eq!(cs.len(), N_CIRCLES);
            for (i, a) in cs.iter().enumerate() {
                // enough margin for the warp (<= 8 px) to keep them on the canvas
                let m = a.r + THICK / 2.0 + MARGIN - 1e-3;
                assert!(a.x >= m && a.x <= W as f32 - m);
                assert!(a.y >= m && a.y <= H as f32 - m);
                for b in cs.iter().skip(i + 1) {
                    assert!(pair_ok(a, b));
                }
            }
        }
    }

    #[test]
    fn crossings_but_no_tangencies() {
        let mut rng = Rng::new();
        let mut crossings = 0;
        for _ in 0..100 {
            let cs = place_circles(&mut rng);
            for (i, a) in cs.iter().enumerate() {
                for b in cs.iter().skip(i + 1) {
                    let d = ((a.x - b.x).powi(2) + (a.y - b.y).powi(2)).sqrt();
                    // never nearly tangent from outside
                    assert!(d >= a.r + b.r + THICK + 5.0 - 1e-3 || d <= a.r + b.r - 6.0 + 1e-3);
                    if d < a.r + b.r {
                        crossings += 1;
                        // nor nearly tangent from inside
                        assert!(d >= (a.r - b.r).abs() + 6.0 - 1e-3);
                    }
                }
            }
        }
        assert!(crossings > 100, "almost no overlaps: {}", crossings);
    }

    #[test]
    fn gap_is_almost_always_free_of_crossings() {
        let mut rng = Rng::new();
        let mut clean = 0;
        let total = 400;
        for _ in 0..total {
            let cs = place_circles(&mut rng);
            let b = rng.below(cs.len() as u32) as usize;
            let (th, hw) = pick_gap(&cs, b, &mut rng);
            assert!((0.0..TAU).contains(&th));
            assert!(hw >= 30.0f32.to_radians() - 1e-4 && hw <= 42.0f32.to_radians() + 1e-4);
            let angs = intersection_angles(&cs, b);
            if gap_clearance(&angs, th, hw) >= 6.0 / cs[b].r - 1e-5 {
                clean += 1;
            }
        }
        assert!(clean * 100 >= total * 95, "clean gaps: {}/{}", clean, total);
    }

    #[test]
    fn identity_warp_moves_nothing() {
        let w = Warp::identity();
        assert_eq!(w.apply(12.5, 99.0), (12.5, 99.0));
    }

    #[test]
    fn warp_is_bounded() {
        let mut rng = Rng::new();
        for _ in 0..20 {
            let w = Warp::random(&mut rng);
            for _ in 0..200 {
                let x = rng.range(0.0, W as f32);
                let y = rng.range(0.0, H as f32);
                let (sx, sy) = w.apply(x, y);
                assert!((sx - x).abs() <= 8.001 && (sy - y).abs() <= 8.001);
            }
        }
    }

    #[test]
    fn warp_invert_is_inverse_of_apply() {
        let mut rng = Rng::new();
        for _ in 0..50 {
            let w = Warp::random(&mut rng);
            let (cx, cy) = (rng.range(30.0, 270.0), rng.range(30.0, 270.0));
            let (px, py) = w.invert(cx, cy);
            let (sx, sy) = w.apply(px, py);
            assert!((sx - cx).abs() < 0.01 && (sy - cy).abs() < 0.01);
        }
    }

    #[test]
    fn is_hit_geometry_without_warp() {
        let s = sec(100.0, 100.0, 20.0);
        assert!(is_hit(&s, 100.0, 100.0));
        assert!(is_hit(&s, 119.9, 100.0));
        assert!(!is_hit(&s, 120.1, 100.0));
        // corner (0,0): what a browser sends when the <input> is activated with Enter
        assert!(!is_hit(&s, 0.0, 0.0));
        assert!(!is_hit(&s, f32::NAN, 10.0));
        assert!(!is_hit(&s, f32::INFINITY, 10.0));
        assert!(!is_hit(&s, -1.0, 10.0));
        assert!(!is_hit(&s, W as f32, 10.0));
        assert!(!is_hit(&s, 10.0, H as f32 + 5.0));
    }

    #[test]
    fn is_hit_with_warp_validates_in_source_space() {
        let mut rng = Rng::new();
        for _ in 0..50 {
            let w = Warp::random(&mut rng);
            let s = Secret {
                cx: 150.0,
                cy: 140.0,
                hit_r: 20.0,
                warp: w,
            };
            let (px, py) = w.invert(150.0, 140.0);
            assert!(is_hit(&s, px, py), "the drawn center does not hit");
            // 40 px away on screen (>= 28 px in source, derivative <= 0.5) misses
            assert!(!is_hit(&s, px + 40.0, py));
            assert!(!is_hit(&s, px, py - 40.0));
        }
    }

    #[test]
    fn challenge_is_a_png_and_center_hits() {
        let mut rng = Rng::new();
        for _ in 0..30 {
            let (ch, px) = generate_with_pixels(&mut rng);
            assert_eq!(&ch.png[..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
            assert!(ch.png.len() < 20_000, "unexpectedly large PNG");
            assert_eq!(px.len(), W * H);
            let s = &ch.secret;
            let (x, y) = s.warp.invert(s.cx, s.cy);
            assert!(x > 0.0 && x < W as f32 && y > 0.0 && y < H as f32);
            assert!(is_hit(s, x, y));
            assert!(!is_hit(s, 0.0, 0.0));
        }
    }

    /// The broken ring must show ink along almost all of its circumference
    /// except the gap: checks that the warp does not break the 1 px stroke.
    #[test]
    fn stroke_survives_the_warp() {
        let mut rng = Rng::new();
        for _ in 0..20 {
            let (ch, px) = generate_with_pixels(&mut rng);
            let s = &ch.secret;
            let r = s.hit_r - HIT_PAD - THICK / 2.0;
            let mut inked = 0;
            let n = 180;
            for k in 0..n {
                let a = TAU * k as f32 / n as f32;
                let (x, y) = s.warp.invert(s.cx + r * a.cos(), s.cy + r * a.sin());
                let (xi, yi) = (x as i32, y as i32);
                let mut found = false;
                for oy in -1..=1 {
                    for ox in -1..=1 {
                        let (qx, qy) = (xi + ox, yi + oy);
                        if qx >= 0 && qy >= 0 && qx < W as i32 && qy < H as i32 && px[qy as usize * W + qx as usize] == 1 {
                            found = true;
                        }
                    }
                }
                if found {
                    inked += 1;
                }
            }
            // gap <= 84 degrees (23 %) + crossing halos: >= 60 % must stay inked
            assert!(inked * 100 >= n * 60, "broken stroke: {}/{}", inked, n);
        }
    }

    #[test]
    fn ang_diff_wraps_correctly() {
        assert!((ang_diff(0.1, TAU - 0.1) - 0.2).abs() < 1e-4);
        assert!((ang_diff(-PI + 0.1, PI - 0.1) - 0.2).abs() < 1e-4);
        assert!(ang_diff(1.0, 1.0) < 1e-6);
    }

    #[test]
    fn pack_1bit_has_expected_size() {
        let ink = vec![0u8; W * H];
        let raw = pack_1bit(&ink);
        assert_eq!(raw.len(), (W.div_ceil(8) + 1) * H);
        // blank row: filter 0 + 0xFF bytes (the padding is white too)
        assert_eq!(raw[0], 0);
        assert!(raw[1..=W.div_ceil(8)].iter().all(|&b| b == 0xFF));
    }

    /// Run with:  DUMP_DIR=/path cargo test dump_samples -- --ignored
    /// Writes DUMP_N (default 6) real PNGs plus a file with each one's answer.
    #[test]
    #[ignore]
    fn dump_samples() {
        let dir = std::env::var("DUMP_DIR").unwrap_or_else(|_| ".".into());
        let mut rng = Rng::new();
        let count: usize = std::env::var("DUMP_N").ok().and_then(|v| v.parse().ok()).unwrap_or(6);
        let mut answers = String::new();
        for i in 0..count {
            let ch = generate(&mut rng);
            std::fs::write(format!("{}/sample_{}.png", dir, i), &ch.png).unwrap();
            let s = &ch.secret;
            let (x, y) = s.warp.invert(s.cx, s.cy);
            answers.push_str(&format!("{} {:.1} {:.1} {:.1}\n", i, x, y, s.hit_r));
        }
        std::fs::write(format!("{}/answers.txt", dir), answers).unwrap();
    }
}
