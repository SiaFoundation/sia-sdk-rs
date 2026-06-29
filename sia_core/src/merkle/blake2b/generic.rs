//! Portable scalar backend: one block at a time, also used for batch remainders
//! and the single-hash API.

use super::{INIT, MAX_LANES, SIGMA, build_msg, store_out};

#[inline(always)]
fn g(a: u64, b: u64, c: u64, d: u64, mx: u64, my: u64) -> (u64, u64, u64, u64) {
    let a = a.wrapping_add(b).wrapping_add(mx);
    let d = (d ^ a).rotate_right(32);
    let c = c.wrapping_add(d);
    let b = (b ^ c).rotate_right(24);
    let a = a.wrapping_add(b).wrapping_add(my);
    let d = (d ^ a).rotate_right(16);
    let c = c.wrapping_add(d);
    let b = (b ^ c).rotate_right(63);
    (a, b, c, d)
}

/// Hashes a single block (`prefix ‖ block`).
pub(super) fn hash_block(block: &[u8; 64], prefix: u8) -> [u8; 32] {
    let mut buf = [0u64; 16 * MAX_LANES];
    build_msg::<1>(core::slice::from_ref(block), prefix, &mut buf);
    let mut m = [0u64; 16];
    m.copy_from_slice(&buf[..16]);

    let mut v = INIT;
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
        ow[i] = v[i] ^ v[i + 8] ^ INIT[i];
    }
    let mut out = [[0u8; 32]; 1];
    store_out::<1>(&ow, &mut out);
    out[0]
}

/// Scalar batch; also the dispatch fallback when no SIMD backend is available
/// (so unused on targets that always have one).
#[allow(dead_code)]
pub(super) unsafe fn hash_blocks(out: &mut [[u8; 32]], blocks: &[[u8; 64]], prefix: u8) {
    for (o, b) in out.iter_mut().zip(blocks) {
        *o = hash_block(b, prefix);
    }
}
