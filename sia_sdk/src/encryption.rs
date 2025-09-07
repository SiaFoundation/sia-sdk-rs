use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use rayon::prelude::*;

/// encrypts the provided shards using XChaCha20. To decrypt the shards, call
/// this function again with the same key.
/// NOTE: don't reuse the same key for the same set of shards as it will
/// compromise the security of the encryption. Always use a freshly generated
/// key.
pub fn encrypt_shards(key: &[u8; 32], shard_start: u8, offset: usize, shards: &mut Vec<Vec<u8>>) {
    shards.par_iter_mut().enumerate().for_each(|(i, shard)| {
        encrypt_shard(key, shard_start + i as u8, offset, shard);
    });
}

/// Encrypts a single shard using XChaCha20. To decrypt the shard, call this
/// function again with the same key.
/// NOTE: don't reuse the same key for the same shard as it will compromise the
/// security of the encryption. Always use a freshly generated key.
///
/// For performance reasons, prefer using `encrypt_shards` when encrypting
/// multiple shards.
pub fn encrypt_shard(key: &[u8; 32], index: u8, offset: usize, shard: &mut [u8]) {
    let mut nonce: [u8; 24] = [0u8; 24]; // XChaCha20 nonce size
    nonce[0] = index;
    let mut cipher = XChaCha20::new(key.into(), &nonce.into());
    cipher.seek(offset);
    cipher.apply_keystream(shard);
}

#[cfg(test)]
mod test {
    use rand::RngCore;

    use crate::rhp::SECTOR_SIZE;

    use super::*;

    #[test]
    fn test_encrypt_sector_roundtrip() {
        let key = [1u8; 32];

        let mut sector = vec![0u8; SECTOR_SIZE];
        rand::rng().fill_bytes(&mut sector);

        let original = sector.clone();
        encrypt_shard(&key, 0, 0, &mut sector);
        assert_ne!(sector, original);
        encrypt_shard(&key, 0, 0, &mut sector);
        assert_eq!(sector, original);
    }

    #[test]
    fn test_encrypt_shards() {
        let key = [1u8; 32];
        let mut shards = vec![vec![1, 2, 3], vec![4, 5, 6]];

        // encrypt
        encrypt_shards(&key, 0, 0, &mut shards);
        assert_eq!(shards[0], vec![136, 154, 188]);
        assert_eq!(shards[1], vec![70, 216, 180]);

        // decrypt
        encrypt_shards(&key, 0, 0, &mut shards);
        assert_eq!(shards[0], vec![1, 2, 3]);
        assert_eq!(shards[1], vec![4, 5, 6]);

        // encrypt with offset
        encrypt_shards(&key, 0, 100, &mut shards);
        assert_eq!(shards[0], vec![6, 194, 192]);
        assert_eq!(shards[1], vec![236, 188, 165]);

        // decrypt with offset
        encrypt_shards(&key, 0, 100, &mut shards);
        assert_eq!(shards[0], vec![1, 2, 3]);
        assert_eq!(shards[1], vec![4, 5, 6]);
    }
}
