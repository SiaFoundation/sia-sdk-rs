use super::*;

/// Reference `BLAKE2b-256(prefix ‖ block)` using the well-tested `blake2b_simd`.
fn reference(block: &[u8; 64], prefix: u8) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new().hash_length(32).to_state();
    state.update(&[prefix]);
    state.update(block);
    let mut out = [0u8; 32];
    out.copy_from_slice(&state.finalize().as_bytes()[..32]);
    out
}

fn random_blocks(seed: u64, n: usize) -> Vec<[u8; 64]> {
    (0..n)
        .map(|i| {
            let mut b = [0u8; 64];
            crate::test_util::fill(seed ^ (i as u64).wrapping_mul(0x100000001b3), &mut b);
            b
        })
        .collect()
}

fn check_backend(name: &str, n: usize, f: HashBlocksFn) {
    let blocks = random_blocks(0xabad1dea, n);
    for prefix in [0u8, 1u8] {
        let mut out = vec![[0u8; 32]; n];
        unsafe { f(&mut out, &blocks, prefix) };
        for (i, o) in out.iter().enumerate() {
            assert_eq!(
                *o,
                reference(&blocks[i], prefix),
                "{name}: lane {i}, prefix {prefix}"
            );
        }
    }
}

#[test]
fn single_block_matches_reference() {
    let blocks = random_blocks(7, 4);
    for b in &blocks {
        assert_eq!(generic::hash_block(b, 0), reference(b, 0));
    }
    // sum_pair packs two child hashes into the 64-byte block, prefix 1.
    let l = [0x11u8; 32];
    let r = [0x22u8; 32];
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(&l);
    block[32..].copy_from_slice(&r);
    assert_eq!(sum_pair(&l, &r), reference(&block, 1));
}

#[test]
fn backends_match_reference() {
    check_backend("scalar", 4, super::generic::hash_blocks);

    #[cfg(target_arch = "aarch64")]
    check_backend("neon", 4, super::neon::hash_blocks);

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            check_backend("avx2", 4, super::avx2::hash_blocks);
        }
        if std::arch::is_x86_feature_detected!("avx512f") {
            check_backend("avx512", 8, super::avx512::hash_blocks);
        }
    }

    #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
    check_backend("wasm", 4, super::wasm::hash_blocks);
}

#[test]
fn bulk_matches_reference() {
    // A non-multiple-of-8 length exercises the dispatched kernel and the scalar
    // remainder on every backend width.
    let leaves = random_blocks(0xc0ffee, 100);
    let mut out = vec![[0u8; 32]; 100];
    hash_leaves_many(&mut out, &leaves);
    for (i, o) in out.iter().enumerate() {
        assert_eq!(*o, reference(&leaves[i], 0), "leaf {i}");
    }

    let children = random_blocks(0xdecaf, 50);
    // Reinterpret the 50 64-byte blocks as 50 child-pairs (100 × 32-byte nodes).
    let nodes: Vec<[u8; 32]> = children
        .iter()
        .flat_map(|b| {
            let mut a = [0u8; 32];
            let mut c = [0u8; 32];
            a.copy_from_slice(&b[..32]);
            c.copy_from_slice(&b[32..]);
            [a, c]
        })
        .collect();
    let mut nout = vec![[0u8; 32]; 50];
    hash_nodes_many(&mut nout, &nodes);
    for (i, o) in nout.iter().enumerate() {
        assert_eq!(*o, reference(&children[i], 1), "node {i}");
    }
}
