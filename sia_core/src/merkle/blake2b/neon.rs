//! AArch64 NEON backend. NEON registers hold two `u64`, so a group of four
//! lanes is a pair of `uint64x2_t`.

use core::arch::aarch64::*;

use super::{INIT, MAX_LANES, SIGMA, build_msg, store_out};

const N: usize = 4;

/// Byte-shuffle table that rotates each 64-bit lane right by `rb` bytes.
const fn rot_ctrl(rb: usize) -> [u8; 16] {
    let mut c = [0u8; 16];
    let mut p = 0;
    while p < 16 {
        let word = p / 8;
        c[p] = (word * 8 + (p % 8 + rb) % 8) as u8;
        p += 1;
    }
    c
}

const CTRL16: [u8; 16] = rot_ctrl(2);
const CTRL24: [u8; 16] = rot_ctrl(3);

#[derive(Clone, Copy)]
struct U64x4(uint64x2_t, uint64x2_t);

#[inline(always)]
unsafe fn tbl(v: uint64x2_t, ctrl: &[u8; 16]) -> uint64x2_t {
    let idx = vld1q_u8(ctrl.as_ptr());
    vreinterpretq_u64_u8(vqtbl1q_u8(vreinterpretq_u8_u64(v), idx))
}

impl U64x4 {
    #[inline(always)]
    unsafe fn splat(x: u64) -> Self {
        U64x4(vdupq_n_u64(x), vdupq_n_u64(x))
    }

    #[inline(always)]
    unsafe fn load(p: *const u64) -> Self {
        U64x4(vld1q_u64(p), vld1q_u64(p.add(2)))
    }

    #[inline(always)]
    unsafe fn store(self, p: *mut u64) {
        vst1q_u64(p, self.0);
        vst1q_u64(p.add(2), self.1);
    }

    #[inline(always)]
    unsafe fn add(self, b: Self) -> Self {
        U64x4(vaddq_u64(self.0, b.0), vaddq_u64(self.1, b.1))
    }

    #[inline(always)]
    unsafe fn xor(self, b: Self) -> Self {
        U64x4(veorq_u64(self.0, b.0), veorq_u64(self.1, b.1))
    }

    #[inline(always)]
    unsafe fn rotr16(self) -> Self {
        U64x4(tbl(self.0, &CTRL16), tbl(self.1, &CTRL16))
    }

    #[inline(always)]
    unsafe fn rotr24(self) -> Self {
        U64x4(tbl(self.0, &CTRL24), tbl(self.1, &CTRL24))
    }

    #[inline(always)]
    unsafe fn rotr32(self) -> Self {
        // ror 32 = swap the 32-bit halves of each lane
        let rev = |v| vreinterpretq_u64_u32(vrev64q_u32(vreinterpretq_u32_u64(v)));
        U64x4(rev(self.0), rev(self.1))
    }

    #[inline(always)]
    unsafe fn rotr63(self) -> Self {
        let rotl1 = |v| vorrq_u64(vshrq_n_u64::<63>(v), vshlq_n_u64::<1>(v));
        U64x4(rotl1(self.0), rotl1(self.1))
    }
}

#[inline(always)]
unsafe fn g(
    a: U64x4,
    b: U64x4,
    c: U64x4,
    d: U64x4,
    mx: U64x4,
    my: U64x4,
) -> (U64x4, U64x4, U64x4, U64x4) {
    let a = a.add(b).add(mx);
    let d = d.xor(a).rotr32();
    let c = c.add(d);
    let b = b.xor(c).rotr24();
    let a = a.add(b).add(my);
    let d = d.xor(a).rotr16();
    let c = c.add(d);
    let b = b.xor(c).rotr63();
    (a, b, c, d)
}

/// Hashes up to `N` blocks; a partial batch leaves the unused lanes zero.
#[target_feature(enable = "neon")]
unsafe fn hash_batch(out: &mut [[u8; 32]], blocks: &[[u8; 64]], prefix: u8) {
    let mut buf = [0u64; 16 * MAX_LANES];
    build_msg::<N>(blocks, prefix, &mut buf);

    let mut m = [U64x4::splat(0); 16];
    for (j, w) in m.iter_mut().enumerate() {
        *w = U64x4::load(buf.as_ptr().add(j * N));
    }
    let mut v = [U64x4::splat(0); 16];
    for (i, w) in v.iter_mut().enumerate() {
        *w = U64x4::splat(INIT[i]);
    }

    for s in &SIGMA {
        macro_rules! mix {
            ($a:literal, $b:literal, $c:literal, $d:literal, $x:literal, $y:literal) => {{
                let (ra, rb, rc, rd) = g(v[$a], v[$b], v[$c], v[$d], m[s[$x]], m[s[$y]]);
                v[$a] = ra;
                v[$b] = rb;
                v[$c] = rc;
                v[$d] = rd;
            }};
        }
        mix!(0, 4, 8, 12, 0, 1);
        mix!(1, 5, 9, 13, 2, 3);
        mix!(2, 6, 10, 14, 4, 5);
        mix!(3, 7, 11, 15, 6, 7);
        mix!(0, 5, 10, 15, 8, 9);
        mix!(1, 6, 11, 12, 10, 11);
        mix!(2, 7, 8, 13, 12, 13);
        mix!(3, 4, 9, 14, 14, 15);
    }

    let mut ow = [0u64; 4 * MAX_LANES];
    for i in 0..4 {
        v[i].xor(v[i + 8])
            .xor(U64x4::splat(INIT[i]))
            .store(ow.as_mut_ptr().add(i * N));
    }
    store_out::<N>(&ow, out);
}

#[target_feature(enable = "neon")]
pub(super) unsafe fn hash_blocks(out: &mut [[u8; 32]], blocks: &[[u8; 64]], prefix: u8) {
    for (oc, bc) in out.chunks_mut(N).zip(blocks.chunks(N)) {
        hash_batch(oc, bc, prefix);
    }
}
