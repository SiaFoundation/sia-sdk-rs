//! SIMD-accelerated BLAKE2b-256 specialized for Sia Merkle trees.
//!
//! Every leaf and node hash is `BLAKE2b-256(prefix ‖ 64 bytes)`: a single,
//! final 128-byte block, so the initial state is precomputed and many hashes
//! run in parallel, one per SIMD lane. Each backend implements its own
//! `hash_blocks` kernel; only the constants and the scalar message/output
//! transpose are shared.
//!
//! Reference: <https://github.com/SiaFoundation/core/tree/master/blake2b>. The
//! AVX2 kernel and constants are ported from its `gen.go`:
//! <https://github.com/SiaFoundation/core/blob/master/blake2b/gen.go>.

#![allow(unsafe_op_in_unsafe_fn)]

use std::slice::from_raw_parts;
use std::sync::OnceLock;

mod generic;

#[cfg(target_arch = "x86_64")]
mod avx2;
#[cfg(target_arch = "x86_64")]
mod avx512;
#[cfg(target_arch = "aarch64")]
mod neon;
#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
mod wasm;

#[cfg(test)]
mod tests;

/// The widest backend (AVX-512) hashes 8 blocks at once; scratch buffers are
/// sized for this maximum and narrower backends use a prefix.
const MAX_LANES: usize = 8;

/// Precomputed initial state for a single final 65-byte block with a 32-byte
/// digest: words 0..8 are the chaining value (`IV` xor the parameter block
/// `0x01010020`), words 8..16 are `IV` with the counter `t = 65` (word 12) and
/// final-block flag `!0` (word 14) mixed in. The `initState` from `gen.go`.
const INIT: [u64; 16] = [
    0x6a09e667f2bdc928,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade68290,
    0x9b05688c2b3e6c1f,
    0xe07c265404be4294,
    0x5be0cd19137e2179,
];

/// BLAKE2b message schedule.
const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// Lays out the message words for `N`-wide kernels. The input is `prefix ‖
/// block` (65 bytes), so bytes shift up by one and spill into a 9th word (words
/// 9..16 stay zero). Word `j` for all lanes is contiguous at `msg[j * N..]`.
fn build_msg<const N: usize>(blocks: &[[u8; 64]], prefix: u8, msg: &mut [u64; 16 * MAX_LANES]) {
    msg.fill(0);
    for (lane, block) in blocks.iter().enumerate() {
        let mut wbuf = [0u8; 72];
        wbuf[0] = prefix;
        wbuf[1..65].copy_from_slice(block);
        for j in 0..9 {
            msg[j * N + lane] = u64::from_le_bytes(wbuf[j * 8..j * 8 + 8].try_into().unwrap());
        }
    }
}

/// Transposes the first four state words per lane into contiguous digests.
fn store_out<const N: usize>(ow: &[u64; 4 * MAX_LANES], out: &mut [[u8; 32]]) {
    for (lane, o) in out.iter_mut().enumerate() {
        for w in 0..4 {
            o[w * 8..w * 8 + 8].copy_from_slice(&ow[w * N + lane].to_le_bytes());
        }
    }
}

/// Hashes a batch of any length, chunking internally by the backend's lane
/// width. Callers must ensure the CPU supports the backend's target features.
type HashBlocksFn = unsafe fn(&mut [[u8; 32]], &[[u8; 64]], u8);

#[cfg(target_arch = "x86_64")]
fn detect() -> HashBlocksFn {
    if std::arch::is_x86_feature_detected!("avx512f") {
        avx512::hash_blocks
    } else if std::arch::is_x86_feature_detected!("avx2") {
        avx2::hash_blocks
    } else {
        generic::hash_blocks
    }
}

#[cfg(target_arch = "aarch64")]
fn detect() -> HashBlocksFn {
    // NEON is part of the AArch64 baseline.
    neon::hash_blocks
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
fn detect() -> HashBlocksFn {
    wasm::hash_blocks
}

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    all(target_arch = "wasm32", target_feature = "simd128")
)))]
fn detect() -> HashBlocksFn {
    generic::hash_blocks
}

fn hash_blocks_many(out: &mut [[u8; 32]], blocks: &[[u8; 64]], prefix: u8) {
    static HASH_FN: OnceLock<HashBlocksFn> = OnceLock::new();

    assert_eq!(out.len(), blocks.len());
    let f = *HASH_FN.get_or_init(detect);
    // SAFETY: `detect` only returns a backend whose target features the running
    // CPU has.
    unsafe { f(out, blocks, prefix) };
}

/// Reinterprets a contiguous byte slice as 64-byte blocks.
#[inline]
pub(crate) fn as_blocks(bytes: &[u8]) -> &[[u8; 64]] {
    assert_eq!(bytes.len() % 64, 0);
    // SAFETY: `[u8; 64]` is contiguous with alignment 1 and the length is exact.
    unsafe { from_raw_parts(bytes.as_ptr() as *const [u8; 64], bytes.len() / 64) }
}

// Merkle hash domain-separation prefixes.
pub(crate) const LEAF_PREFIX: u8 = 0;
pub(crate) const NODE_PREFIX: u8 = 1;

/// Computes the Merkle node hash `BLAKE2b-256(0x01 ‖ left ‖ right)`.
pub fn sum_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(left);
    block[32..].copy_from_slice(right);
    generic::hash_block(&block, NODE_PREFIX)
}

/// Computes the Merkle leaf hash of each block into `out`. `out` and `leaves`
/// must have equal length.
pub fn hash_leaves_many(out: &mut [[u8; 32]], leaves: &[[u8; 64]]) {
    hash_blocks_many(out, leaves, LEAF_PREFIX);
}

/// Computes the Merkle node hash of each adjacent pair of children into `out`.
/// `children` must be exactly twice as long as `out`; `out[k]` is the hash of
/// `children[2k] ‖ children[2k + 1]`.
pub fn hash_nodes_many(out: &mut [[u8; 32]], children: &[[u8; 32]]) {
    assert_eq!(children.len(), out.len() * 2);
    // SAFETY: `[u8; 32]` arrays are contiguous, so a pair reinterprets as `[u8; 64]`.
    let pairs = unsafe { from_raw_parts(children.as_ptr() as *const [u8; 64], children.len() / 2) };
    hash_blocks_many(out, pairs, NODE_PREFIX);
}
