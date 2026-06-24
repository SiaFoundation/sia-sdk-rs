//! Deterministic helpers shared across the crate's unit tests.

/// Fills `buf` with a deterministic splitmix64 stream seeded by `seed`.
pub(crate) fn fill(seed: u64, buf: &mut [u8]) {
    let mut x = seed.wrapping_add(0x9e3779b97f4a7c15);
    for chunk in buf.chunks_mut(8) {
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^= z >> 31;
        let bytes = z.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
        x = x.wrapping_add(0x9e3779b97f4a7c15);
    }
}
