//! x86-64 AVX2 backend: a 256-bit register holds four `u64` (one full lane
//! group). Ported from the Go reference's `gen.go`:
//! <https://github.com/SiaFoundation/core/blob/master/blake2b/gen.go>.

use core::arch::x86_64::*;

use super::{INIT, MAX_LANES, SIGMA, build_msg, store_out};

const N: usize = 4;

/// 32-byte `vpshufb` control that rotates each 64-bit lane right by `rb` bytes.
/// `vpshufb` indexes within each 128-bit half, so the 16-byte pattern repeats.
const fn rot_ctrl(rb: usize) -> [u8; 32] {
    let mut c = [0u8; 32];
    let mut p = 0;
    while p < 32 {
        let within = p % 16;
        let word = within / 8;
        c[p] = (word * 8 + (within % 8 + rb) % 8) as u8;
        p += 1;
    }
    c
}

const CTRL16: [u8; 32] = rot_ctrl(2);
const CTRL24: [u8; 32] = rot_ctrl(3);
const CTRL32: [u8; 32] = rot_ctrl(4);

#[inline(always)]
unsafe fn rotr_shuf(v: __m256i, ctrl: &[u8; 32]) -> __m256i {
    _mm256_shuffle_epi8(v, _mm256_loadu_si256(ctrl.as_ptr() as *const __m256i))
}

#[inline(always)]
unsafe fn g(
    a: __m256i,
    b: __m256i,
    c: __m256i,
    d: __m256i,
    mx: __m256i,
    my: __m256i,
) -> (__m256i, __m256i, __m256i, __m256i) {
    let a = _mm256_add_epi64(_mm256_add_epi64(a, b), mx);
    let d = rotr_shuf(_mm256_xor_si256(d, a), &CTRL32);
    let c = _mm256_add_epi64(c, d);
    let b = rotr_shuf(_mm256_xor_si256(b, c), &CTRL24);
    let a = _mm256_add_epi64(_mm256_add_epi64(a, b), my);
    let d = rotr_shuf(_mm256_xor_si256(d, a), &CTRL16);
    let c = _mm256_add_epi64(c, d);
    let bx = _mm256_xor_si256(b, c);
    let b = _mm256_or_si256(_mm256_srli_epi64::<63>(bx), _mm256_slli_epi64::<1>(bx));
    (a, b, c, d)
}

/// Hashes up to `N` blocks; a partial batch leaves the unused lanes zero.
#[target_feature(enable = "avx2")]
unsafe fn hash_batch(out: &mut [[u8; 32]], blocks: &[[u8; 64]], prefix: u8) {
    let mut buf = [0u64; 16 * MAX_LANES];
    build_msg::<N>(blocks, prefix, &mut buf);

    let mut m = [_mm256_setzero_si256(); 16];
    for (j, w) in m.iter_mut().enumerate() {
        *w = _mm256_loadu_si256(buf.as_ptr().add(j * N) as *const __m256i);
    }
    let mut v = [_mm256_setzero_si256(); 16];
    for (i, w) in v.iter_mut().enumerate() {
        *w = _mm256_set1_epi64x(INIT[i] as i64);
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
        let o = _mm256_xor_si256(
            _mm256_xor_si256(v[i], v[i + 8]),
            _mm256_set1_epi64x(INIT[i] as i64),
        );
        _mm256_storeu_si256(ow.as_mut_ptr().add(i * N) as *mut __m256i, o);
    }
    store_out::<N>(&ow, out);
}

#[target_feature(enable = "avx2")]
pub(super) unsafe fn hash_blocks(out: &mut [[u8; 32]], blocks: &[[u8; 64]], prefix: u8) {
    for (oc, bc) in out.chunks_mut(N).zip(blocks.chunks(N)) {
        hash_batch(oc, bc, prefix);
    }
}
