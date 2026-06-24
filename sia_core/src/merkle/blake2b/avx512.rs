//! x86-64 AVX-512F backend. A 512-bit register holds eight `u64`, so one
//! register is a group of eight lanes and rotations use the native `vprorq`.

use core::arch::x86_64::*;

use super::{INIT, MAX_LANES, SIGMA, build_msg, store_out};

const N: usize = 8;

#[inline(always)]
unsafe fn g(
    a: __m512i,
    b: __m512i,
    c: __m512i,
    d: __m512i,
    mx: __m512i,
    my: __m512i,
) -> (__m512i, __m512i, __m512i, __m512i) {
    let a = _mm512_add_epi64(_mm512_add_epi64(a, b), mx);
    let d = _mm512_ror_epi64::<32>(_mm512_xor_si512(d, a));
    let c = _mm512_add_epi64(c, d);
    let b = _mm512_ror_epi64::<24>(_mm512_xor_si512(b, c));
    let a = _mm512_add_epi64(_mm512_add_epi64(a, b), my);
    let d = _mm512_ror_epi64::<16>(_mm512_xor_si512(d, a));
    let c = _mm512_add_epi64(c, d);
    let b = _mm512_ror_epi64::<63>(_mm512_xor_si512(b, c));
    (a, b, c, d)
}

/// Hashes up to `N` blocks; a partial batch leaves the unused lanes zero.
#[target_feature(enable = "avx512f")]
unsafe fn hash_batch(out: &mut [[u8; 32]], blocks: &[[u8; 64]], prefix: u8) {
    let mut buf = [0u64; 16 * MAX_LANES];
    build_msg::<N>(blocks, prefix, &mut buf);

    let mut m = [_mm512_setzero_si512(); 16];
    for (j, w) in m.iter_mut().enumerate() {
        *w = _mm512_loadu_si512(buf.as_ptr().add(j * N) as *const __m512i);
    }
    let mut v = [_mm512_setzero_si512(); 16];
    for (i, w) in v.iter_mut().enumerate() {
        *w = _mm512_set1_epi64(INIT[i] as i64);
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
        let o = _mm512_xor_si512(
            _mm512_xor_si512(v[i], v[i + 8]),
            _mm512_set1_epi64(INIT[i] as i64),
        );
        _mm512_storeu_si512(ow.as_mut_ptr().add(i * N) as *mut __m512i, o);
    }
    store_out::<N>(&ow, out);
}

#[target_feature(enable = "avx512f")]
pub(super) unsafe fn hash_blocks(out: &mut [[u8; 32]], blocks: &[[u8; 64]], prefix: u8) {
    for (oc, bc) in out.chunks_mut(N).zip(blocks.chunks(N)) {
        hash_batch(oc, bc, prefix);
    }
}
